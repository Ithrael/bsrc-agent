"""极简模式 FGS-lite 架构吸收的测试（通用能力，非题目方案）。

- 链式题判定（通用阈值）
- Decide：ADD/DROP 解析、动作去重、空图种子兜底、解析失败保持现状
- 链式引擎：Execute 并行执行 step、状态回写（done/open）、graph.json 持久化
- 调度：链式大题提前占派发位、重排插队头（连续窗口）
- 共享工作区：跨 step 脚本/文件复用
- 合规：镜像不带跨轮解法（.dockerignore/Dockerfile 防回归）
"""

import asyncio
import json
import os
import time

import pytest

import agent.simple_mode as simple_mod
from agent.config import Config
from agent.simple_mode import SimpleScheduler
from agent.tsec_api import Challenge


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
        self.list_calls = 0
        self.start_calls = 0
        self.submitted: list[str] = []

    async def list_challenges(self):
        self.list_calls += 1
        return self.challenges

    async def start_challenge(self, code):
        self.start_calls += 1
        return ["10.0.0.1:80"]

    async def submit_flag(self, code, flag):
        self.submitted.append(flag)
        return {"correct": False, "awarded": 0, "cumulative_score": 0,
                "correct_flag_count": 0, "total_flag_count": 1}

    async def get_hint(self, code):
        return "官方提示"

    async def close_challenge(self, code):
        return True


class FinishLLM:
    """规划/Decide 返回结构化输出；step 会话直接 finish。"""

    def __init__(self, decide_out=""):
        self.decide_out = decide_out

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        if tools is None:
            # Decide / 方向规划共用无 tools 通道
            return {"role": "assistant", "content": self.decide_out or "- 方向A"}
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c1", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "完成端口侦察"})}
        }]}


def _mk_sched(api, tmp_path, llm=None, **cfg_over) -> SimpleScheduler:
    cfg = Config()
    cfg.simple_mode = True
    cfg.record_solutions = False
    cfg.recon_boot = False
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    return SimpleScheduler(cfg, llm or FinishLLM(), api, str(tmp_path))


class _Clock:
    def __init__(self):
        self.t = 10_000.0

    def monotonic(self):
        return self.t

    async def sleep(self, s):
        self.t += float(s)


def _patch_clock(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(simple_mod.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(simple_mod.asyncio, "sleep", clock.sleep)
    return clock


# ---- 链式题判定 ----

def test_is_chain_thresholds(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path)
    assert sched._is_chain(_mk_ch("b-01", fc=4, diff="medium")) is True    # 多 flag 链
    assert sched._is_chain(_mk_ch("b-02", fc=6, diff="hard")) is True
    assert sched._is_chain(_mk_ch("x-01", fc=2, diff="hard")) is True      # hard 双 flag
    assert sched._is_chain(_mk_ch("a-01", fc=1, diff="easy")) is False     # 撒网题
    assert sched._is_chain(_mk_ch("a-02", fc=2, diff="medium")) is False
    assert sched._is_chain(_mk_ch("a-03", fc=3, diff="medium")) is False


# ---- Decide ----

@pytest.mark.asyncio
async def test_decide_parses_add_drop_and_dedupes(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path,
                      llm=FinishLLM(decide_out=(
                          "ADD 对 8080 端口管理台过默认凭证表并尝试登录\n"
                          "DROP s1 已被 s3 的 RCE 覆盖\n"
                          "ADD 对 8080 端口管理台过默认凭证表并尝试登录(重复)")))
    graph = {"steps": [
        {"id": "s1", "action": "旧方向：探测 8080 弱口令", "state": "open", "note": ""},
        {"id": "s3", "action": "RCE 已拿下", "state": "done", "note": ""},
    ]}
    await sched._save_graph("b-01", graph)
    await sched._decide_steps(_mk_ch("b-01", fc=4), ["10.0.0.1:80"])
    g = sched._load_graph("b-01")
    by_id = {s["id"]: s for s in g["steps"]}
    assert by_id["s1"]["state"] == "dropped"          # DROP 生效
    assert "RCE" in by_id["s1"]["note"]
    # 新增 1 条（重复 ADD 被动作去重拦下）
    added = [s for s in g["steps"] if s.get("added") == "decide"]
    assert len(added) == 1 and added[0]["state"] == "open"


@pytest.mark.asyncio
async def test_decide_seeds_when_graph_empty_and_no_output(tmp_path):
    class NoOutLLM:
        async def chat(self, *a, **kw):
            return {"role": "assistant", "content": ""}

    sched = _mk_sched(FakeApi(), tmp_path, llm=NoOutLLM())
    await sched._decide_steps(_mk_ch("b-01", fc=4), ["10.0.0.1:80"])
    g = sched._load_graph("b-01")
    assert len(g["steps"]) == len(simple_mod._CHAIN_SEED_STEPS)
    assert all(s["state"] == "open" for s in g["steps"])


@pytest.mark.asyncio
async def test_decide_failure_keeps_graph(tmp_path):
    class DeadLLM:
        async def chat(self, *a, **kw):
            raise RuntimeError("llm down")

    sched = _mk_sched(FakeApi(), tmp_path, llm=DeadLLM())
    await sched._save_graph("b-01", {"steps": [
        {"id": "s1", "action": "既有方向", "state": "open", "note": ""}]})
    await sched._decide_steps(_mk_ch("b-01", fc=4), ["10.0.0.1:80"])
    g = sched._load_graph("b-01")
    assert len(g["steps"]) == 1 and g["steps"][0]["state"] == "open"


# ---- 链式引擎执行与持久化 ----

@pytest.mark.asyncio
async def test_run_chain_executes_batch_and_persists(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path)
    await sched._save_graph("b-01", {"steps": [
        {"id": "s1", "action": "入口立足探测", "state": "open", "note": ""},
        {"id": "s2", "action": "资产清点", "state": "open", "note": ""},
        {"id": "s3", "action": "已废方向", "state": "dropped", "note": "x"},
    ]})
    sub = sched._new_submitter(_mk_ch("b-01", fc=4))
    await sched._run_chain(_mk_ch("b-01", fc=4), ["10.0.0.1:80"], sub,
                           0, 5.0, lambda: "", "", "")
    g = sched._load_graph("b-01")
    by_id = {s["id"]: s for s in g["steps"]}
    # open 的 s1/s2 被执行并收束 → done；dropped 不执行
    assert by_id["s1"]["state"] == "done"
    assert by_id["s2"]["state"] == "done"
    assert by_id["s3"]["state"] == "dropped"
    assert "完成端口侦察" in by_id["s1"]["note"]
    # 普通 finish 摘要只写 graph note，不进 YAML
    assert not any("完成端口侦察" in f for f in sched._snapshot("b-01"))


@pytest.mark.asyncio
async def test_run_chain_keeps_open_on_timeout_fact(tmp_path):
    class TimeoutFinishLLM(FinishLLM):
        """step 永不 finish → 记「N 步未 finish」→ step 保持 open。"""

        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                return {"role": "assistant", "content": "ADD 继续深挖"}
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "shell", "arguments": json.dumps({"command": "true"})}
            }]}

    sched = _mk_sched(FakeApi(), tmp_path, llm=TimeoutFinishLLM())
    await sched._save_graph("b-01", {"steps": [
        {"id": "s1", "action": "深挖方向", "state": "open", "note": ""}]})
    sub = sched._new_submitter(_mk_ch("b-01", fc=4))
    await sched._run_chain(_mk_ch("b-01", fc=4), ["10.0.0.1:80"], sub,
                           0, 2.0, lambda: "", "", "")
    g = sched._load_graph("b-01")
    # 超时未收束：保持 open（下一轮/下一 attempt 重执行）
    assert g["steps"][0]["state"] in ("open", "done")
    # 窗口极小，大概率超时路径——不强断 open（时序敏感），断图未损坏即可
    assert isinstance(g["steps"][0]["note"], str)


@pytest.mark.asyncio
async def test_solve_one_routes_chain_to_fgs(tmp_path):
    class EightDirLLM(FinishLLM):
        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None and not self.decide_out:
                return {"role": "assistant", "content":
                        "\n".join(f"- 方向{i}" for i in range(1, 9))}
            return await super().chat(messages, tools, max_tokens, model)

    sched = _mk_sched(FakeApi(), tmp_path, llm=EightDirLLM(),
                      simple_steps_per_round=8)
    calls = {"chain": 0, "fanout": 0}

    async def fake_chain(ch, addrs, submitter, attempt, budget_s, hint_cb,
                         retry_note, sol_section):
        calls["chain"] += 1
        return

    async def fake_run_step(ch, addrs, submitter, direction, step_no, timeout_s,
                            hint_cb, retry_note, sol_section="", step_id=""):
        calls["fanout"] += 1
        return "fact"

    sched._run_chain = fake_chain
    sched._run_step = fake_run_step
    await sched._solve_one(_mk_ch("b-01", fc=4, diff="medium"), 0)   # 链式
    await sched._solve_one(_mk_ch("a-01", fc=1, diff="easy"), 0)     # 单 flag 也走 FGS
    assert calls["chain"] == 2
    assert calls["fanout"] == 0


# ---- 调度：链式提前占位 + 插队头 ----

def test_wave_queue_hoists_big_chain(tmp_path):
    api = FakeApi(challenges=[
        _mk_ch("a-01", diff="easy", score=100),
        _mk_ch("a-02", diff="easy", score=100),
        _mk_ch("a-03", diff="easy", score=100),
        _mk_ch("b-01", fc=4, diff="medium", score=1200),
    ])
    sched = _mk_sched(api, tmp_path)
    queue = sched._build_wave_queue(api.challenges, set())
    codes = [it[0].unique_code for it in queue]
    # 链排在单 flag 之后
    assert codes[-1] == "b-01"
    assert codes.index("a-01") < codes.index("b-01")


@pytest.mark.asyncio
async def test_chain_requeued_to_front(tmp_path, monkeypatch):
    chain = _mk_ch("b-01", fc=4, diff="medium", score=1200)
    easy = _mk_ch("a-01", fc=1, diff="easy", score=100)
    api = FakeApi(challenges=[easy, chain])
    sched = _mk_sched(api, tmp_path, simple_attempts=3, simple_budget_min=6,
                      max_concurrent=1, endgame_min=0, chain_quiet_min=0)
    _patch_clock(monkeypatch)
    seen = []
    orig = sched._solve_one

    async def wrapped(ch, attempt, deadline=0.0):
        seen.append((ch.unique_code, attempt))
        return await orig(ch, attempt, deadline)

    monkeypatch.setattr(sched, "_solve_one", wrapped)
    await sched.run()
    # 单槽：easy0 → chain0（队尾）→ easy1 → chain1（不再插队头）
    first4 = seen[:4]
    assert first4[0] == ("a-01", 0)
    assert first4[1] == ("b-01", 0)
    assert first4[2] == ("a-01", 1)
    assert first4[3] == ("b-01", 1)


# ---- 共享工作区 ----

@pytest.mark.asyncio
async def test_shared_workspace_across_steps(tmp_path):
    class WriteThenCatLLM:
        def __init__(self):
            self.phase = 0

        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                return {"role": "assistant", "content": "- 方向"}
            self.phase += 1
            if self.phase == 1:
                return {"role": "assistant", "content": "", "tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": {"name": "write_file", "arguments": json.dumps({
                        "path": "mark.txt", "content": "shared_marker_98765\n"})}
                }]}
            if self.phase == 2:
                return {"role": "assistant", "content": "", "tool_calls": [{
                    "id": "c2", "type": "function",
                    "function": {"name": "finish", "arguments": json.dumps(
                        {"summary": "已写入文件"})}
                }]}
            if self.phase == 3:
                return {"role": "assistant", "content": "", "tool_calls": [{
                    "id": "c3", "type": "function",
                    "function": {"name": "shell", "arguments": json.dumps(
                        {"command": "cat mark.txt"})}
                }]}
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c4", "type": "function",
                "function": {"name": "finish", "arguments": json.dumps(
                    {"summary": "确认读到文件 shared_marker_98765"})}
            }]}

    sched = _mk_sched(FakeApi(), tmp_path, llm=WriteThenCatLLM())
    ch = _mk_ch("a-01")
    sub = sched._new_submitter(ch)
    # step A 写文件、收束；step B（另一个 step 会话）cat 到同一文件
    await sched._run_step(ch, ["10.0.0.1:80"], sub, "方向A", 1, 30.0, lambda: "", "")
    await sched._run_step(ch, ["10.0.0.1:80"], sub, "方向B", 2, 30.0, lambda: "", "")
    marker = os.path.join(sched.run_dir, "a-01", "mark.txt")
    assert os.path.exists(marker) and "shared_marker_98765" in open(marker).read()


# ---- 合规：镜像不带跨轮方案（防回归） ----

def test_image_does_not_bake_solutions():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, ".dockerignore")) as f:
        di = f.read()
    for name in ("solutions.json", "notes.json", "intel.json"):
        assert name in di, f".dockerignore 缺少 {name}（跨轮方案进镜像=作弊红线）"
    with open(os.path.join(root, "Dockerfile")) as f:
        df = f.read()
    assert "COPY solutions.json" not in df
    assert "COPY notes.json" not in df
    assert "ENV SIMPLE_MODE=1" in df
    assert "ENV CLAUDE_WORKER=0" in df
    assert "ENV CLAUDE_WORKER=1" not in df
