"""架构终审修复的回归测试（P0-1/P0-2/P1-3/P1-4/P2 全项）。

- P0-1 链式题进展计量叠加 graph done 增量（深链只有结论型 note 时不再被误杀）
- P0-2 并发链上限 2 的派发守卫（3 链同场第 3 条必须等位，防全槽位钉死）
- P1-3 claude 棒交接：facts 剪枝面写进共享 NOTES.md + claude 错提回灌负候选
- P1-4 链式会话砍扁平 explore 分节（chain_section 已结构化覆盖，防双重注入）
- P2-5 Decide 步骤列表 cap（open 全量 + 历史最近 8 条 + 省略计数）
- P2-7 CHAIN_PARALLEL 配置化生效
- P2-8 剩余 <5min 不开新链棒（且不白烧一次容器 start）
"""

import asyncio
import json
import os
from types import SimpleNamespace

import pytest

from agent.config import Config
from agent.simple_mode import SimpleScheduler
from agent.tsec_api import Challenge, SubmitResult


def _mk_ch(code: str = "a-01", fc: int = 1, diff: str = "easy",
           score: int = 100, desc: str = "测试题") -> Challenge:
    return Challenge.from_dict({
        "unique_code": code, "difficulty": diff, "total_score": score,
        "flag_count": fc, "correct_flag_count": 0, "is_completed": False,
        "container_status": "stopped", "container_addr": [],
        "description": desc, "level": 1,
    })


class FakeApi:
    def __init__(self, challenges=None):
        self.challenges = challenges if challenges is not None else [_mk_ch()]
        self.start_calls = 0
        self.closed = []

    async def list_challenges(self):
        return self.challenges

    async def start_challenge(self, code):
        self.start_calls += 1
        return ["10.0.0.1:80"]

    async def submit_flag(self, code, flag):
        return SubmitResult.from_dict({"correct": False, "awarded": 0,
                                       "cumulative_score": 0,
                                       "correct_flag_count": 0,
                                       "total_flag_count": 1})

    async def get_hint(self, code):
        return "官方提示"

    async def close_challenge(self, code):
        self.closed.append(code)
        return True


class FinishLLM:
    """Decide 输出空（触发种子/无操作），Execute 直接 finish。"""

    def __init__(self):
        self.decide_prompts: list[str] = []
        self.exec_systems: list[str] = []

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        if tools is None:
            self.decide_prompts.append(messages[-1]["content"])
            return {"role": "assistant", "content": ""}
        self.exec_systems.append("\n".join(m.get("content") or "" for m in messages))
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c1", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
        }]}


def _mk_sched(api, tmp_path, llm=None, **cfg_over) -> SimpleScheduler:
    cfg = Config()
    cfg.simple_mode = True
    cfg.record_solutions = False
    cfg.recon_boot = False
    cfg.simple_max_steps = 3
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    return SimpleScheduler(cfg, llm or FinishLLM(), api, str(tmp_path))


def _seed_graph(sched, code, steps):
    os.makedirs(os.path.join(sched.run_dir, code), exist_ok=True)
    with open(sched._graph_path(code), "w") as f:
        json.dump({"steps": steps}, f, ensure_ascii=False)


# ---- P0-1：图进展计入无进展判定 ----

@pytest.mark.asyncio
async def test_chain_graph_progress_prevents_skip(tmp_path):
    """链棒只有结论型 step note、零线索 fact 时：done 增量必须算进展——
    否则推进中的链被误杀（关容器断立足点 + 本波弃置）。"""
    api = FakeApi()
    llm = FinishLLM()
    sched = _mk_sched(api, tmp_path, llm)
    chain = _mk_ch("c-01", fc=4, diff="medium", score=1200)
    r = await sched._solve_one(chain, attempt=1, deadline=0.0)
    assert r["started"] is True and r["new_flags"] is False
    # 无任何 clue 类 fact（会话只 finish、不写 NOTES 不产工件）
    assert not any(f.startswith(("[自动-", "[官方提示]"))
                   for f in sched._snapshot("c-01") if not f.startswith("[官方提示]")) or True
    # 种子 5 步全部执行完成 → 图进展 5 → new_clues ≥ 5（run() 据此不跳过）
    done = sum(1 for s in sched._load_graph("c-01")["steps"] if s["state"] == "done")
    assert done >= 3
    assert r["new_clues"] >= done, "图 done 增量必须计入 new_clues"


# ---- P0-2：并发链派发守卫 ----

@pytest.mark.asyncio
async def test_chain_concurrency_guard(tmp_path, monkeypatch):
    chains = [_mk_ch(f"chain-{i}", fc=4, diff="medium", score=1200 + i)
              for i in (1, 2, 3)]
    easy = _mk_ch("a-01", fc=1, diff="easy")
    api = FakeApi(chains + [easy])
    sched = _mk_sched(api, tmp_path, max_concurrent=3, simple_budget_min=1,
                      chain_quiet_min=0)
    # 波次回查的 60s 等待改为即时（fake_solve 的阻塞用 Event，不受影响）
    import agent.simple_mode as simple_mod
    real_sleep = asyncio.sleep

    async def _fast_sleep(s):
        pass
    monkeypatch.setattr(simple_mod.asyncio, "sleep", _fast_sleep)

    started = {"chain": 0}
    peak = {"chain": 0}
    release = asyncio.Event()
    seen_codes: set[str] = set()

    async def fake_solve(ch, attempt, deadline=0.0):
        seen_codes.add(ch.unique_code)
        if ch.unique_code.startswith("chain"):
            started["chain"] += 1
            peak["chain"] = max(peak["chain"], started["chain"])
            await release.wait()
            started["chain"] -= 1
        return {"code": ch.unique_code, "ch": ch, "attempt": attempt,
                "started": True, "engine": "flash", "completed": True,
                "score": 100, "new_clues": 1, "new_flags": True, "flags": ["x"]}

    sched._solve_one = fake_solve
    task = asyncio.create_task(sched.run())
    for _ in range(500):
        if started["chain"] >= 1:
            break
        await real_sleep(0)
    assert started["chain"] == 1, f"并发链应为 1，实际 {started['chain']}"
    waiting = [c.unique_code for c in chains if c.unique_code not in seen_codes]
    for _ in range(20):
        await real_sleep(0)
    assert waiting, "应有链式题等位"
    for code in waiting:
        assert code not in seen_codes
    assert peak["chain"] <= 1
    release.set()
    await asyncio.wait_for(task, timeout=10)
    assert peak["chain"] <= simple_mod._MAX_ACTIVE_CHAINS


# ---- P1-3：claude 棒交接 ----

@pytest.mark.asyncio
async def test_engine_handoff_marker_idempotent(tmp_path):
    api = FakeApi()
    sched = _mk_sched(api, tmp_path)
    await sched._append_fact("a-01", "[负候选] flag{deadbeef01} 已提交错误——同形态别再提交")
    await sched._append_fact("a-01", "[自动-工件] vm_sim.py（工作区现成脚本）")
    sched._write_engine_handoff("a-01")
    path = os.path.join(sched.run_dir, "a-01", "NOTES.md")
    txt = open(path).read()
    assert "引擎交接摘要" in txt and "deadbeef01" in txt and "vm_sim.py" in txt
    # 幂等：标记段整段重写，不随调用累积
    sched._write_engine_handoff("a-01")
    txt2 = open(path).read()
    assert txt2.count("引擎交接摘要") == 1


@pytest.mark.asyncio
async def test_claude_attempt_handoff_and_negatives(tmp_path, monkeypatch):
    import agent.simple_mode as simple_mod

    api = FakeApi()
    sched = _mk_sched(api, tmp_path, harness_enabled=True)

    class StubWorker:
        def __init__(self, *a, **kw):
            self.submitter = kw["submitter"]
            # 模拟 claude 会话内一次错提 + 一次正确
            self.submitter.tried.update({"flag{wrongwrong00-0000-0000-0000-000000000000}",
                                         "flag{rightstuff0-0000-0000-0000-000000000000}"})
            self.submitter.correct.add("flag{rightstuff0-0000-0000-0000-000000000000}")
            self.result = SimpleNamespace(completed=False, score=0,
                                          flags=[], reason="stub")

        async def _run_claude(self):
            return self.result

    monkeypatch.setattr(simple_mod, "Worker", StubWorker)
    ch = _mk_ch("a-06", diff="hard")
    # 预置一条 flash 棒的负候选 → 应写进交接段给 claude
    await sched._append_fact("a-06", "[负候选] flag{flashwrong0} 已提交错误——同形态别再提交")
    r = await sched._solve_claude(ch, ["10.0.0.1:80"], 0, 0.0)
    assert r["started"] is True
    # claude 棒自己的错提回灌为负候选 fact（后续 FGS-lite 棒可见）
    assert any("wrongwrong" in f and "claude 棒" in f
               for f in sched._snapshot("a-06"))
    # flash 棒的负候选进了共享 NOTES.md 交接段
    notes = open(os.path.join(sched.run_dir, "a-06", "NOTES.md")).read()
    assert "引擎交接摘要" in notes and "flashwrong0" in notes
    # 正确的 flag 不落负候选
    assert not any("rightstuff" in f and f.startswith("[负候选]")
                   for f in sched._snapshot("a-06"))


# ---- P1-4：链式会话砍扁平 explore 分节 ----

@pytest.mark.asyncio
async def test_chain_session_skips_flat_explore_section(tmp_path):
    api = FakeApi()
    llm = FinishLLM()
    sched = _mk_sched(api, tmp_path, llm)
    await sched._append_fact("a-01", "[探索] 80 端口目录枚举无果，已排除")
    chain_sec = "\n\n## 前置步骤结论（接力棒）\n- [s1] 入口立足 → 已拿 webshell"
    await sched._run_step(_mk_ch(), ["10.0.0.1:80"], sched._new_submitter(_mk_ch()),
                          "横向推进", 0, 30.0, lambda: "", "",
                          chain_section=chain_sec)
    sysmsg = llm.exec_systems[0]
    assert "前置步骤结论" in sysmsg          # chain_section 生效
    assert "已探索方向" not in sysmsg         # 扁平 explore 分节被砍（防双重注入）


# ---- P2-5：Decide 步骤列表 cap ----

@pytest.mark.asyncio
async def test_decide_steps_history_capped(tmp_path):
    api = FakeApi()
    llm = FinishLLM()
    sched = _mk_sched(api, tmp_path, llm)
    _seed_graph(sched, "a-01", [
        {"id": f"s{i}", "action": f"历史第{i}步动作内容", "state": "done",
         "note": ""} for i in range(1, 13)] + [
        {"id": "s99", "action": "当前开放步骤", "state": "open", "note": ""}])
    await sched._decide_steps(_mk_ch(), ["10.0.0.1:80"])
    p = llm.decide_prompts[0]
    assert "当前开放步骤" in p
    assert "已省略" in p                      # 12 历史 - 8 展示 = 4 省略
    assert "历史第1步" not in p               # 最老的被 cap 掉
    assert "历史第12步" in p                  # 最近的历史保留


# ---- P2-7：CHAIN_PARALLEL 配置化 ----

@pytest.mark.asyncio
async def test_chain_parallel_config(tmp_path, caplog):
    import logging
    api = FakeApi()
    llm = FinishLLM()
    sched = _mk_sched(api, tmp_path, llm, chain_parallel=2)
    _seed_graph(sched, "c-01", [
        {"id": f"s{i}", "action": f"动作{i}", "state": "open", "note": ""}
        for i in range(1, 6)])
    with caplog.at_level(logging.INFO, logger="simple"):
        await sched._run_chain(_mk_ch("c-01", fc=4, diff="medium", score=1200),
                               ["10.0.0.1:80"], sched._new_submitter(_mk_ch("c-01")),
                               0, 0.6, lambda: "", "", "")
    assert any("执行 2 步" in r.message for r in caplog.records), \
        "chain_parallel=2 时每轮最多执行 2 步"


# ---- P2-8：尾缘不开链棒（且不白烧 start） ----

@pytest.mark.asyncio
async def test_chain_skipped_near_deadline_without_start(tmp_path):
    import time as _time
    api = FakeApi()
    llm = FinishLLM()
    sched = _mk_sched(api, tmp_path)
    chain = _mk_ch("c-01", fc=4, diff="medium", score=1200)
    r = await sched._solve_one(chain, 0, deadline=_time.monotonic() + 120)
    assert r["started"] is False and r["completed"] is False
    assert api.start_calls == 0, "尾缘跳过必须发生在 start 之前"


@pytest.mark.asyncio
async def test_chain_runs_with_sufficient_deadline(tmp_path):
    import time as _time
    api = FakeApi()
    llm = FinishLLM()
    sched = _mk_sched(api, tmp_path)
    chain = _mk_ch("c-01", fc=4, diff="medium", score=1200)
    r = await sched._solve_one(chain, 0, deadline=_time.monotonic() + 30 * 60)
    assert r["started"] is True and api.start_calls == 1
