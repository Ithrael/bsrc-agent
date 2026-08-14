import asyncio
import json
import time

import pytest

from agent.config import Config
from agent.tsec_api import Challenge, TsecClient
from agent.worker import Worker
from tests.mock_server import TOKEN, make_server


class FakeLLM:
    """脚本化的假 LLM：第一轮 echo 出 flag（测自动捕获），第二轮 finish。"""

    def __init__(self):
        self.n = 0

    async def chat(self, messages, tools=None):
        self.n += 1
        if self.n == 1:
            return {"role": "assistant", "content": "先侦察", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "shell", "arguments": json.dumps({"command": "echo 得到 flag{mock-1} 了"})},
            }]}
        return {"role": "assistant", "content": "做完了", "tool_calls": [{
            "id": "c2", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "done"})},
        }]}


@pytest.mark.asyncio
async def test_worker_auto_capture_and_finish(tmp_path):
    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")
    addrs = await api.start_challenge(ch.unique_code)

    cfg = Config()
    cfg.challenge_timeout_min = 5
    cfg.recon_boot = False  # mock 目标在 127.0.0.1 随机端口，预侦察无意义且拖慢测试
    cfg.record_solutions = False  # 不把 mock 题写进真实 solutions.json
    w = Worker(cfg, FakeLLM(), api, ch, addrs, str(tmp_path / "mock_web_01"),
               deadline=time.monotonic() + 600)
    res = await w.run()
    assert res.completed
    assert res.score == 100
    assert res.flags == ["flag{mock-1}"]
    await api.close()


@pytest.mark.asyncio
async def test_state_md_tracks_flag_progress(tmp_path):
    """STATE.md 自动维护 FACTS：初始骨架 + flag 进度行。"""
    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")
    addrs = await api.start_challenge(ch.unique_code)

    cfg = Config()
    cfg.challenge_timeout_min = 5
    cfg.recon_boot = False
    cfg.record_solutions = False
    w = Worker(cfg, FakeLLM(), api, ch, addrs, str(tmp_path / "mock_web_01"),
               deadline=time.monotonic() + 600)
    res = await w.run()
    assert res.completed
    state = (tmp_path / "mock_web_01" / "STATE.md").read_text()
    assert "## FACTS" in state
    assert "- flag 进度: 1/1" in state
    await api.close()
    srv.shutdown()


@pytest.mark.asyncio
async def test_hint_persisted_to_notes(tmp_path, monkeypatch):
    """hint 自动落盘 notes.json（下轮复现不再扣分）；已有专家复盘时不覆盖。"""
    monkeypatch.setattr("agent.worker.notes_lib_path", lambda: str(tmp_path / "notes.json"))
    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")
    cfg = Config()
    cfg.hint_policy = "free"
    w = Worker.__new__(Worker)
    w.cfg = cfg
    w.api = api
    w.ch = ch
    w._hint_used = False
    w.started = time.monotonic() - 600
    r = await w._hint_cb()
    assert "试试 /flag" in r
    saved = json.load(open(tmp_path / "notes.json"))
    assert "官方 hint" in saved["mock_web_01"]
    # 已有专家复盘：不覆盖
    with open(tmp_path / "notes.json", "w") as f:
        json.dump({"mock_web_01": "人工复盘内容"}, f, ensure_ascii=False)
    w._hint_used = False
    await w._hint_cb()
    saved = json.load(open(tmp_path / "notes.json"))
    assert saved["mock_web_01"] == "人工复盘内容"
    await api.close()
    srv.shutdown()
    srv.shutdown()


def test_scaled_max_steps_scales_with_flag_count():
    cfg = Config()
    w = Worker.__new__(Worker)
    w.cfg = cfg
    w.ch = Challenge.from_dict({"unique_code": "b-01", "flag_count": 4})
    # 第二轮（默认 ROUND=2）不设步数熔断：解开题目为终极目标
    assert w._scaled_max_steps() == float("inf")
    # 第一轮（ROUND=1）收紧到 round1_max_steps：覆盖优先快速过手
    cfg.round_num = 1
    assert w._scaled_max_steps() == float(cfg.round1_max_steps)


class DegradingLLM:
    """第一次抛 400（上下文超长），第二次正常返回。"""

    def __init__(self):
        self.calls = 0
        self.last_n = 0

    async def chat(self, messages, tools=None):
        self.calls += 1
        self.last_n = len(messages)
        if self.calls == 1:
            raise RuntimeError("LLM 400: context too long")
        return {"role": "assistant", "content": "ok"}


@pytest.mark.asyncio
async def test_chat_degrades_context_then_retries():
    cfg = Config()
    w = Worker.__new__(Worker)
    w.cfg = cfg
    w.ch = Challenge.from_dict({"unique_code": "b-02", "flag_count": 6})
    w.llm = DegradingLLM()
    messages = ([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
                + [{"role": "assistant", "content": str(i)} for i in range(12)])
    out = await w._chat(messages, [])
    assert out["content"] == "ok"
    assert w.llm.calls == 2
    assert w.llm.last_n < len(messages)


@pytest.mark.asyncio
async def test_chat_reraises_non_context_error():
    cfg = Config()
    w = Worker.__new__(Worker)
    w.cfg = cfg
    w.ch = Challenge.from_dict({"unique_code": "b-02"})
    w.llm = DegradingLLM()
    w.llm.calls = 0

    async def fail(messages, tools=None):
        raise RuntimeError("LLM 鉴权失败 401")

    w.llm.chat = fail
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    with pytest.raises(RuntimeError):
        await w._chat(messages, [])


@pytest.mark.asyncio
async def test_submit_cb_rejects_non_flag_format():
    """P3：tsec{...} 等非 flag{...} 格式直接拒绝，不打平台；记入 tried 防重复尝试。"""
    from agent.flagger import FlagSubmitter
    calls = []

    class _NoCall:
        async def submit_flag(self, *a, **k):
            calls.append(1)
            raise RuntimeError("unreachable")

    w = Worker.__new__(Worker)
    w.submitter = FlagSubmitter("x-01", 1)
    w.api = _NoCall()
    from agent.tsec_api import Challenge
    w.ch = Challenge.from_dict({"unique_code": "x-01", "description": "", "difficulty": "easy",
                                "level": 1, "total_score": 100, "flag_count": 1,
                                "correct_flag_count": 0, "is_completed": False,
                                "container_status": "stopped", "container_addr": []})
    r = await w._submit_cb("tsec{fake-guess}")
    assert "格式拒绝" in r
    assert calls == []                       # 平台未被调用
    assert "tsec{fake-guess}" in w.submitter.tried
    # flag{...} 格式通过校验（会尝试打平台，这里平台是 _NoCall → 验证走到了提交路径）
    with pytest.raises(RuntimeError, match="unreachable"):
        await w._submit_cb("flag{real-flag}")
