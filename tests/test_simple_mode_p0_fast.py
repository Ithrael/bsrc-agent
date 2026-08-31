"""P0 快轮转：解出即杀兄弟 / 单 flag 5min / 链 15min 停滞 / 前 90min 禁链 / 关 claude / hint 仅第二波 0 分。"""

import asyncio
import json
import time

import pytest

import agent.simple_mode as simple_mod
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
    def __init__(self, challenges=None, submit_correct=True):
        self.challenges = challenges if challenges is not None else [_mk_ch()]
        self.hint_calls = 0
        self.start_calls = 0
        self.closed: list[str] = []
        self.submit_correct = submit_correct

    async def list_challenges(self):
        return self.challenges

    async def start_challenge(self, code):
        self.start_calls += 1
        return ["10.0.0.1:80"]

    async def submit_flag(self, code, flag):
        return SubmitResult.from_dict({
            "correct": self.submit_correct, "awarded": 100 if self.submit_correct else 0,
            "cumulative_score": 100 if self.submit_correct else 0,
            "correct_flag_count": 1 if self.submit_correct else 0,
            "total_flag_count": 1})

    async def get_hint(self, code):
        self.hint_calls += 1
        return "官方提示"

    async def close_challenge(self, code):
        self.closed.append(code)
        return True


def _mk_sched(api, tmp_path, llm=None, **cfg_over) -> SimpleScheduler:
    cfg = Config()
    cfg.simple_mode = True
    cfg.record_solutions = False
    cfg.recon_boot = False
    cfg.simple_steps_per_round = 2
    cfg.simple_max_steps = 5
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    return SimpleScheduler(cfg, llm, api, str(tmp_path))


def test_step_timeout_single_flag_by_difficulty(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path, llm=None)
    # 单 flag 题按难度分级：easy 8 / medium 15 / hard 20；链式题 15（停滞由 _CHAIN_STAGNATE_S 卡）
    assert sched._step_timeout_min(_mk_ch(fc=1, diff="hard"), 0) == 20
    assert sched._step_timeout_min(_mk_ch(fc=1, diff="easy"), 1) == 8
    assert sched._step_timeout_min(_mk_ch(fc=1, diff="medium"), 0) == 15
    assert sched._step_timeout_min(_mk_ch("b-01", fc=6, diff="hard"), 0) == 15


def test_should_use_claude_always_false(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path, llm=None)
    sched.cfg.harness_enabled = True
    assert sched._should_use_claude(_mk_ch(diff="hard"), 0) is False
    assert sched._should_use_claude(_mk_ch("b-01", fc=4), 0) is False


@pytest.mark.asyncio
async def test_no_hint_on_first_occupancy(tmp_path):
    class FinishLLM:
        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                return {"role": "assistant", "content": "- 方向A"}
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "finish",
                             "arguments": json.dumps({"summary": "已排除"})}
            }]}

    api = FakeApi()
    sched = _mk_sched(api, tmp_path, llm=FinishLLM(), simple_steps_per_round=1)
    await sched._solve_one(_mk_ch("a-06", diff="hard", fc=1), 0)
    assert api.hint_calls == 0


@pytest.mark.asyncio
async def test_hint_on_second_wave_still_zero(tmp_path):
    class FinishLLM:
        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                return {"role": "assistant", "content": "- 方向A"}
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "finish",
                             "arguments": json.dumps({"summary": "已排除"})}
            }]}

    api = FakeApi(submit_correct=False)
    sched = _mk_sched(api, tmp_path, llm=FinishLLM(), simple_steps_per_round=1)
    ch = _mk_ch("a-05", diff="easy")
    await sched._solve_one(ch, 0)
    assert api.hint_calls == 0
    await sched._solve_one(ch, 1)
    assert api.hint_calls == 1


@pytest.mark.asyncio
async def test_no_hint_if_already_has_flags(tmp_path):
    class FinishLLM:
        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                return {"role": "assistant", "content": "- 方向A"}
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "finish",
                             "arguments": json.dumps({"summary": "已排除"})}
            }]}

    api = FakeApi()
    sched = _mk_sched(api, tmp_path, llm=FinishLLM(), simple_steps_per_round=1)
    ch = _mk_ch("b-02", fc=6, diff="hard")
    ch.correct_flag_count = 2
    sched._seen_attempt.add("b-02")
    await sched._solve_one(ch, 1)
    assert api.hint_calls == 0


@pytest.mark.asyncio
async def test_cancel_siblings_when_flag_complete(tmp_path):
    """一条 step 交对 flag 后，慢的兄弟 step 必须被 cancel，不能把槽占满窗口。"""
    flag = "flag{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"

    class MixedLLM:
        def __init__(self):
            self.slow_entered = asyncio.Event()
            self.slow_cancelled = False

        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            blob = " ".join(str(m.get("content") or "") for m in messages)
            if tools is None:
                return {"role": "assistant", "content": "- fast\n- slow"}
            if "当前步骤: slow" in blob:
                self.slow_entered.set()
                try:
                    await asyncio.sleep(3)
                except asyncio.CancelledError:
                    self.slow_cancelled = True
                    raise
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "submit_flag",
                             "arguments": json.dumps({"flag": flag})}
            }]}

    api = FakeApi()
    llm = MixedLLM()
    sched = _mk_sched(api, tmp_path, llm=llm, simple_steps_per_round=2)
    t0 = time.monotonic()
    r = await sched._solve_one(_mk_ch(), 0)
    elapsed = time.monotonic() - t0
    assert r["completed"] is True
    assert elapsed < 1.5, f"解出后应立刻放槽，实际 {elapsed:.1f}s"


@pytest.mark.asyncio
async def test_chain_quiet_blocks_dispatch(tmp_path, monkeypatch):
    chain = _mk_ch("b-01", fc=4, diff="medium", score=1200)
    easy = _mk_ch("a-01", fc=1, diff="easy")
    api = FakeApi(challenges=[chain, easy])
    sched = _mk_sched(api, tmp_path, llm=None, max_concurrent=3,
                      simple_budget_min=1, chain_quiet_min=90, endgame_min=0)
    clock_t = {"t": time.monotonic()}

    def fake_mono():
        return clock_t["t"]

    async def _fast_sleep(s):
        clock_t["t"] += float(s)

    monkeypatch.setattr(simple_mod.time, "monotonic", fake_mono)
    monkeypatch.setattr(simple_mod.asyncio, "sleep", _fast_sleep)
    seen = []

    async def fake_solve(ch, attempt, deadline=0.0):
        seen.append(ch.unique_code)
        return {"code": ch.unique_code, "ch": ch, "attempt": attempt,
                "started": True, "engine": "flash", "completed": True,
                "score": 100, "new_clues": 1, "new_flags": True, "flags": ["x"]}

    sched._solve_one = fake_solve
    await asyncio.wait_for(sched.run(), timeout=5)
    assert "a-01" in seen
    assert "b-01" not in seen


@pytest.mark.asyncio
async def test_max_one_chain_after_quiet(tmp_path, monkeypatch):
    chains = [_mk_ch(f"b-0{i}", fc=4, diff="medium", score=1200) for i in (1, 2)]
    api = FakeApi(challenges=chains)
    sched = _mk_sched(api, tmp_path, llm=None, max_concurrent=3,
                      simple_budget_min=1, chain_quiet_min=0, endgame_min=0)
    clock_t = {"t": time.monotonic()}

    def fake_mono():
        return clock_t["t"]

    async def _fast_sleep(s):
        clock_t["t"] += float(s)

    monkeypatch.setattr(simple_mod.time, "monotonic", fake_mono)
    monkeypatch.setattr(simple_mod.asyncio, "sleep", _fast_sleep)
    release = asyncio.Event()
    live = {"n": 0, "peak": 0}

    async def fake_solve(ch, attempt, deadline=0.0):
        live["n"] += 1
        live["peak"] = max(live["peak"], live["n"])
        await release.wait()
        live["n"] -= 1
        return {"code": ch.unique_code, "ch": ch, "attempt": attempt,
                "started": True, "engine": "flash", "completed": True,
                "score": 100, "new_clues": 1, "new_flags": True, "flags": ["x"]}

    sched._solve_one = fake_solve
    task = asyncio.create_task(sched.run())
    for _ in range(200):
        if live["n"] >= 1:
            break
        await asyncio.sleep(0)
    await asyncio.sleep(0.05)
    assert live["peak"] <= 1
    release.set()
    await asyncio.wait_for(task, timeout=5)


def test_seed_web_is_four_not_eight(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path, llm=None)
    seeds = sched._seed_steps_for(_mk_ch("a-01", fc=1, diff="easy"))
    assert 2 <= len(seeds) <= 4
    assert not any("/v1/models" in s for s in seeds)


def test_seed_cve_starts_with_fingerprint(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path, llm=None)
    seeds = sched._seed_steps_for(_mk_ch("c-07", fc=1, diff="easy"))
    assert "指纹" in seeds[0]
    assert not any("/v1/models" in s for s in seeds)


def test_seed_pwn_not_web(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path, llm=None)
    seeds = sched._seed_steps_for(_mk_ch("f1-02", fc=1, diff="medium",
                                        desc="二进制逆向挑战"))
    assert any("逆向" in s or "checksec" in s or "gdb" in s for s in seeds)
    assert not any("JS 源码" in s or "SQLi" in s for s in seeds)


def test_chain_parallel_matches_24_paths(tmp_path):
    cfg = Config()
    assert cfg.chain_parallel == 8
    assert cfg.simple_steps_per_round == 4
    assert cfg.simple_max_steps == 8


@pytest.mark.asyncio
async def test_frozen_system_and_facts_yaml_user(tmp_path):
    class RecLLM:
        def __init__(self):
            self.systems = []
            self.users = []

        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                return {"role": "assistant", "content": ""}
            self.systems.append(messages[0]["content"])
            self.users.append(messages[1]["content"])
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "finish",
                             "arguments": json.dumps({"summary": "已排除"})}
            }]}

    llm = RecLLM()
    api = FakeApi()
    sched = _mk_sched(api, tmp_path, llm=llm, simple_steps_per_round=2)
    await sched._run_step(_mk_ch(), ["10.0.0.1:80"], sched._new_submitter(_mk_ch()),
                          "指纹与协议", 0, 30.0, lambda: "", "")
    await sched._run_step(_mk_ch(), ["10.0.0.1:80"], sched._new_submitter(_mk_ch()),
                          "另一方向", 1, 30.0, lambda: "", "")
    assert llm.systems[0] == llm.systems[1] == simple_mod.SIMPLE_SYSTEM
    assert "当前步骤:" not in llm.systems[0]
    assert llm.users[0].startswith("facts:")
    assert "当前步骤: 指纹与协议" in llm.users[0]
    assert "当前步骤: 另一方向" in llm.users[1]


@pytest.mark.asyncio
async def test_empty_graph_skips_first_decide(tmp_path):
    """空图首占位：不下 Decide，题型种子直接 Execute。"""

    class RecLLM:
        def __init__(self):
            self.kinds = []
            self.first_step = ""

        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            self.kinds.append("decide" if tools is None else "exec")
            if tools is None:
                return {"role": "assistant", "content":
                        "ADD should_not_be_first_intent"}
            if not self.first_step:
                blob = " ".join(str(m.get("content") or "") for m in messages)
                if "当前步骤:" in blob:
                    self.first_step = blob.split("当前步骤:", 1)[1][:80]
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "finish",
                             "arguments": json.dumps({"summary": "已排除"})}
            }]}

    llm = RecLLM()
    sched = _mk_sched(FakeApi(), tmp_path, llm=llm, simple_steps_per_round=2)
    ch = _mk_ch("a-01")
    seeds = sched._seed_steps_for(ch)
    await sched._run_chain(ch, ["10.0.0.1:80"], sched._new_submitter(ch),
                           0, 4.0, lambda: "", "", "")
    assert llm.kinds, "应至少跑 Execute"
    assert llm.kinds[0] == "exec"
    assert "should_not_be_first_intent" not in llm.first_step
    assert any(s[:24] in llm.first_step for s in seeds)
    g = sched._load_graph("a-01")
    seeded = [s for s in g["steps"] if s.get("added") == "seed"]
    assert seeded and any(s["state"] == "done" for s in seeded)


@pytest.mark.asyncio
async def test_execute_session_capped_at_2min(tmp_path):
    """5min 占用内单 Execute ≤120s，才能跑 2-3 轮 FGS。"""
    recorded = []

    async def fake_run_step(ch, addrs, submitter, direction, step_no, timeout_s,
                            hint_cb, retry_note, sol_section="", **kw):
        recorded.append(timeout_s)
        return "已排除：本方向无入口"

    class Dummy:
        async def chat(self, *a, **kw):
            return {"role": "assistant", "content": ""}

    sched = _mk_sched(FakeApi(), tmp_path, llm=Dummy())
    sched._run_step = fake_run_step
    ch = _mk_ch("a-01")
    await sched._run_chain(ch, ["10.0.0.1:80"], sched._new_submitter(ch),
                           0, 300.0, lambda: "", "", "")
    assert recorded
    assert all(t <= simple_mod._EXECUTE_SESS_S for t in recorded)
    assert recorded[0] == simple_mod._EXECUTE_SESS_S


@pytest.mark.asyncio
async def test_facts_yaml_keeps_clues_not_finish_junk(tmp_path):
    class MixLLM:
        def __init__(self):
            self.n = 0

        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                return {"role": "assistant", "content": ""}
            self.n += 1
            if self.n == 1:
                return {"role": "assistant", "content": "", "tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": {"name": "finish",
                                 "arguments": json.dumps(
                                     {"summary": "已排除：弱口令，因全 401"})}
                }]}
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c2", "type": "function",
                "function": {"name": "finish",
                             "arguments": json.dumps({"summary": "收束无新发现"})}
            }]}

    llm = MixLLM()
    sched = _mk_sched(FakeApi(), tmp_path, llm=llm, simple_steps_per_round=2)
    ch = _mk_ch()
    sub = sched._new_submitter(ch)
    await sched._run_step(ch, ["10.0.0.1:80"], sub, "弱口令", 0, 30.0, lambda: "", "")
    await sched._run_step(ch, ["10.0.0.1:80"], sub, "另一方向", 1, 30.0, lambda: "", "")
    facts = sched._snapshot("a-01")
    assert any("已排除" in f and "弱口令" in f for f in facts)
    assert not any("收束无新发现" in f for f in facts)
    yaml = sched._facts_yaml(ch, ["10.0.0.1:80"], facts + ["[普通摘要] 不该出现"])
    assert "已排除" in yaml
    assert "不该出现" not in yaml
    assert "收束无新发现" not in yaml


def test_persist_fact_predicate():
    assert simple_mod._persist_fact("[自动-凭证] admin:123")
    assert simple_mod._persist_fact("[自动-工件] x.py（工作区现成脚本）")
    assert simple_mod._persist_fact("[官方提示] 看 /admin")
    assert simple_mod._persist_fact("[负候选] flag{x} 已提交错误")
    assert simple_mod._persist_fact("[弱口令] 已排除：全 401")
    assert not simple_mod._persist_fact("[弱口令] 收束无新发现")
    assert not simple_mod._persist_fact("[自动-笔记] 一堆过程")
    assert not simple_mod._persist_fact("[方向] 3 步未 finish（flag 进度 0/1）")
