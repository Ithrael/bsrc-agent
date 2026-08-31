"""复眼（Compound Eye）架构组件测试：负事实回灌 / 风险税 / 差分注入 /
事件驱动 Decide / 停滞换面 / 工件登记 / 链式题 claude 耗尽升级。

设计依据（榜首 97.14 run 12662 日志复盘，全部通用机制、零题目知识）：
- f2-05：8 次错提全是兄弟会话重复推导的近失 → 负事实回灌 + 工件登记
- b-02：图记得对路选错（chisel 隧道）→ Decide 风险税（信封内优先）
- 每轮全量 Decide 是 token 大头 → 事件驱动节流
- 单图兔子洞（keystream 爆破 3 分钟无果）→ 停滞强制换攻击面
"""

import asyncio
import json
import os

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
    def __init__(self, challenges=None, submit_correct=True):
        self.challenges = challenges if challenges is not None else [_mk_ch()]
        self.submit_correct = submit_correct
        self.hint_calls = 0

    async def list_challenges(self):
        return self.challenges

    async def start_challenge(self, code):
        return ["10.0.0.1:80"]

    async def submit_flag(self, code, flag):
        return SubmitResult.from_dict({
            "correct": self.submit_correct, "awarded": 300 if self.submit_correct else 0,
            "cumulative_score": 300 if self.submit_correct else 0,
            "correct_flag_count": 1 if self.submit_correct else 0,
            "total_flag_count": 1})

    async def get_hint(self, code):
        self.hint_calls += 1
        return "官方提示"

    async def close_challenge(self, code):
        return True


class RecordingLLM:
    """按调用形态分流：tools=None 是 Decide/规划，带 tools 是 Execute 会话。
    记录全部调用的 prompt / model / tools 形态供断言。"""

    def __init__(self, decide_out="", exec_calls=None):
        self.decide_out = decide_out
        self.exec_calls = exec_calls or []   # 每次 Execute 会话依次弹出的 tool_calls
        self.decide_prompts: list[str] = []
        self.decide_models: list[str] = []
        self.exec_systems: list[str] = []

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        if tools is None:
            self.decide_prompts.append(messages[-1]["content"])
            self.decide_models.append(model)
            return {"role": "assistant", "content": self.decide_out}
        self.exec_systems.append("\n".join(m.get("content") or "" for m in messages))
        if self.exec_calls:
            return {"role": "assistant", "content": "", "tool_calls": self.exec_calls.pop(0)}
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c9", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
        }]}


def _finish_call(cid="c1"):
    return {"id": cid, "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}}


def _mk_sched(api, tmp_path, llm, **cfg_over) -> SimpleScheduler:
    cfg = Config()
    cfg.simple_mode = True
    cfg.record_solutions = False
    cfg.recon_boot = False
    cfg.simple_max_steps = 3
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    return SimpleScheduler(cfg, llm, api, str(tmp_path))


def _seed_graph(sched, code, steps):
    os.makedirs(os.path.join(sched.run_dir, code), exist_ok=True)
    with open(sched._graph_path(code), "w") as f:
        json.dump({"steps": steps}, f, ensure_ascii=False)


# ---- P1：负事实回灌 ----

@pytest.mark.asyncio
async def test_negative_fact_on_wrong_submit(tmp_path):
    api = FakeApi(submit_correct=False)
    llm = RecordingLLM()
    sched = _mk_sched(api, tmp_path, llm)
    ch = _mk_ch()
    sub = sched._new_submitter(ch)
    out = await sched._submit(ch, sub, "flag{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}")
    assert "负结果" in out
    facts = sched._snapshot("a-01")
    assert any(f.startswith("[负候选]") and "flag{aaaaaaaa" in f for f in facts)


@pytest.mark.asyncio
async def test_negative_facts_section_injected_into_step(tmp_path):
    """负候选进 prompt 的独立分节（剪枝面显式可见）。"""
    api = FakeApi(submit_correct=True)
    llm = RecordingLLM(exec_calls=[[_finish_call()]])
    sched = _mk_sched(api, tmp_path, llm)
    await sched._append_fact("a-01", "[负候选] flag{deadbeef} 已提交错误——同形态别再提交")
    await sched._run_step(_mk_ch(), ["10.0.0.1:80"], sched._new_submitter(_mk_ch()),
                          "方向A", 0, 30.0, lambda: "", "")
    sysmsg = llm.exec_systems[0]
    assert "负候选" in sysmsg and "deadbeef" in sysmsg


# ---- P1：工件登记 ----

@pytest.mark.asyncio
async def test_artifact_script_registered_as_fact(tmp_path):
    api = FakeApi()
    write_call = {"id": "c1", "type": "function", "function": {
        "name": "write_file", "arguments": json.dumps(
            {"path": "exploit_gen.py", "content": "print('cand gen')\n"})}}
    llm = RecordingLLM(exec_calls=[[write_call], [_finish_call("c2")]])
    sched = _mk_sched(api, tmp_path, llm)
    await sched._run_step(_mk_ch(), ["10.0.0.1:80"], sched._new_submitter(_mk_ch()),
                          "方向A", 0, 30.0, lambda: "", "")
    assert any(f.startswith("[自动-工件]") and "exploit_gen.py" in f
               for f in sched._snapshot("a-01"))


# ---- P3：Decide flash 决策 + 风险税 ----

@pytest.mark.asyncio
async def test_decide_uses_flash_and_risk_tax(tmp_path):
    api = FakeApi()
    llm = RecordingLLM(decide_out="ADD 用已控 webshell 直连内网 10.0.0.2 取备份包")
    sched = _mk_sched(api, tmp_path, llm, llm_model_hard="pro-model")
    await sched._decide_steps(_mk_ch(), ["10.0.0.1:80"])
    # Decide 直接用默认 flash（不传 model），即使配了 LLM_MODEL_HARD 也不用——
    # 13842 实测 pro 走 OpenAI 通道 content 近 100% 空返回，强模型决策层形同虚设
    assert llm.decide_models == [""]
    assert "信封内" in llm.decide_prompts[0] and "反向隧道" in llm.decide_prompts[0]
    # ADD 解析入图
    g = sched._load_graph("a-01")
    assert any(s["state"] == "open" and "webshell" in s["action"] for s in g["steps"])


@pytest.mark.asyncio
async def test_decide_force_explore_directive(tmp_path):
    api = FakeApi()
    llm = RecordingLLM(decide_out="")
    sched = _mk_sched(api, tmp_path, llm)
    await sched._decide_steps(_mk_ch(), ["10.0.0.1:80"], force_explore=True)
    assert "换攻击面" in llm.decide_prompts[0]


# ---- P2：差分注入（步骤上下文） ----

@pytest.mark.asyncio
async def test_chain_section_injects_context(tmp_path):
    api = FakeApi()
    llm = RecordingLLM()
    sched = _mk_sched(api, tmp_path, llm)
    _seed_graph(sched, "a-01", [
        {"id": "s1", "action": "入口立足", "state": "done", "note": "拿到 webshell uid=33"},
        {"id": "s2", "action": "横向取备份包", "state": "open", "note": ""},
        {"id": "s3", "action": "反向隧道穿透", "state": "dropped", "note": "隧道不通"},
    ])
    section = sched._chain_section("a-01", sched._load_graph("a-01"), "s2")
    assert "前置步骤结论" in section and "webshell uid=33" in section
    assert "并行兄弟" not in section          # 唯一 open 是自己，不列兄弟
    assert "已废弃路径" in section and "隧道不通" in section


@pytest.mark.asyncio
async def test_run_chain_step_context_reaches_session(tmp_path):
    api = FakeApi()
    llm = RecordingLLM()   # decide 空输出不改图；Execute 直接 finish
    sched = _mk_sched(api, tmp_path, llm)
    _seed_graph(sched, "a-01", [
        {"id": "s1", "action": "入口立足", "state": "done", "note": "admin 弱口令已拿"},
        {"id": "s2", "action": "内网横向", "state": "open", "note": ""},
    ])
    sub = sched._new_submitter(_mk_ch())
    await sched._run_chain(_mk_ch(), ["10.0.0.1:80"], sub, 0,
                           2.0, lambda: "", "", "")
    assert llm.exec_systems, "Execute 会话应被执行"
    assert "前置步骤结论" in llm.exec_systems[0] and "admin 弱口令已拿" in llm.exec_systems[0]


# ---- P3：事件驱动 Decide（节流谓词）+ 停滞换面 ----

def test_need_decide_predicate():
    nd = SimpleScheduler._need_decide
    assert nd(decided=False, open_cnt=0, clue_delta=0, stagnant=False)   # occupancy 尚未 Decide
    assert nd(decided=True, open_cnt=0, clue_delta=0, stagnant=False)    # 没活必排
    assert nd(decided=True, open_cnt=3, clue_delta=2, stagnant=False)    # 世界大变必排
    assert nd(decided=True, open_cnt=3, clue_delta=0, stagnant=True)     # 停滞必排（换面）
    # 节流：还有活干、世界没大变、没停滞 → 不排（砍掉榜首式每轮全量重排的串行税）
    assert not nd(decided=True, open_cnt=3, clue_delta=1, stagnant=False)
    assert not nd(decided=True, open_cnt=3, clue_delta=0, stagnant=False)


@pytest.mark.asyncio
async def test_run_chain_stagnation_forces_explore(tmp_path):
    """一轮无新 flag 无新线索 → 下一轮 Decide 带换攻击面指令。"""
    api = FakeApi(submit_correct=False)

    class StagnantLLM(RecordingLLM):
        def __init__(self):
            super().__init__()
            self.exec_rounds = 0

        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                self.decide_prompts.append(messages[-1]["content"])
                return {"role": "assistant", "content":
                        "ADD 继续深挖当前入口（对 80 端口做全目录枚举）"}
            # Execute：发一条 shell（无产出）再耗尽步数 → 「N 步未 finish」→ step 保持 open
            self.exec_rounds += 1
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": f"c{self.exec_rounds}", "type": "function",
                "function": {"name": "shell",
                             "arguments": json.dumps({"command": "true"})}}]}

    llm = StagnantLLM()
    sched = _mk_sched(api, tmp_path, llm, simple_max_steps=2)
    sub = sched._new_submitter(_mk_ch())
    await sched._run_chain(_mk_ch(), ["10.0.0.1:80"], sub, 0,
                           1.5, lambda: "", "", "")
    assert len(llm.decide_prompts) >= 1, "停滞应触发 Decide"
    assert any("换攻击面" in p for p in llm.decide_prompts), \
        "停滞后的 Decide 必须带换攻击面指令"


# ---- P3：链式题 claude 耗尽升级 FGS-lite ----

@pytest.mark.asyncio
async def test_chain_escalates_to_fgs_after_claude_budget(tmp_path):
    api = FakeApi()
    llm = RecordingLLM()
    sched = _mk_sched(api, tmp_path, llm, harness_enabled=True,
                      simple_claude_attempts=2)
    called = {"claude": False, "chain": False}

    async def fake_claude(*a, **kw):
        called["claude"] = True
        raise AssertionError("claude 不应被调用（预算耗尽）")

    async def fake_chain(ch, addrs, submitter, attempt, budget_s, hint_cb,
                         retry_note, sol_section):
        called["chain"] = True
        return 0

    sched._solve_claude = fake_claude
    sched._run_chain = fake_chain
    ch = _mk_ch("b-09", fc=4, diff="hard", score=1800)
    await sched._solve_one(ch, attempt=2, deadline=0.0)
    assert called["chain"] is True and called["claude"] is False


@pytest.mark.asyncio
async def test_chain_before_claude_budget_still_claude(tmp_path):
    """P0：simple_mode 全程 flash，hard 链也不再走 claude。"""
    api = FakeApi()
    llm = RecordingLLM()
    sched = _mk_sched(api, tmp_path, llm, harness_enabled=True,
                      simple_claude_attempts=2)
    called = {"claude": False, "chain": False}

    async def fake_claude(*a, **kw):
        called["claude"] = True
        raise AssertionError("claude 不应被调用")

    async def fake_chain(*a, **kw):
        called["chain"] = True
        return 0

    sched._solve_claude = fake_claude
    sched._run_chain = fake_chain
    ch = _mk_ch("b-09", fc=4, diff="hard", score=1800)
    await sched._solve_one(ch, attempt=0, deadline=0.0)
    assert called["claude"] is False and called["chain"] is True
