"""harness 攻坚测试：fake 后端（shell 脚本）模拟外部 agent CLI，验证解析/回调/静态选择/动态升级。"""
import json
import time

import pytest

from agent.config import Config
from agent.harness import run_harness
from agent.tsec_api import Challenge, TsecClient
from agent.worker import Worker
from tests.mock_server import TOKEN, make_server


def _fake_backend(tmp_path, lines: list[str]) -> str:
    """假 harness CLI：按行输出 NDJSON 后退出（stdin 不读，与真实 CLI 的 stream 输出对齐）。"""
    p = tmp_path / "fake-harness.sh"
    p.write_text("#!/bin/bash\n" + "\n".join(f"echo '{l}'" for l in lines) + "\n")
    p.chmod(0o755)
    return str(p)


@pytest.mark.asyncio
async def test_run_harness_parses_jsonl(tmp_path):
    """事件流解析：最终文本提取（codex/claude 两种格式）+ on_text 回调。"""
    cfg = Config()
    cfg.harness_backend = _fake_backend(tmp_path, [
        '{"type":"item.started"}',
        '{"type":"item.completed","item":{"text":"找到 flag{fake-h1} 了"}}',
        '{"type":"result","result":"done"}',
    ])
    seen = []
    res = await run_harness(cfg, "prompt", str(tmp_path), 60, on_text=seen.append)
    assert res.events == 3
    assert res.output_text == "done"          # claude 格式 result 事件覆盖 codex 文本
    assert "flag{fake-h1}" in res.collected   # 事件流含 bash/文本内容
    assert len(seen) == 3


@pytest.mark.asyncio
async def test_run_harness_flag_collection(tmp_path):
    """flagger 挂接：harness 输出流里的 flag 通过回调收集（后续统一异步提交）。"""
    from agent.flagger import extract_flags
    cfg = Config()
    cfg.harness_backend = _fake_backend(tmp_path, [
        '{"type":"item.completed","item":{"text":"shell 输出: flag{fake-h2}"}}',
    ])
    flags = []
    res = await run_harness(cfg, "p", str(tmp_path), 60,
                            on_text=lambda t: flags.extend(extract_flags(t)))
    assert "flag{fake-h2}" in flags


def _ch(code="x-01", difficulty="hard", score=500, flags=1):
    return Challenge.from_dict({
        "unique_code": code, "description": "", "difficulty": difficulty,
        "level": 1, "total_score": score, "flag_count": flags,
        "correct_flag_count": 0, "is_completed": False,
        "container_status": "stopped", "container_addr": [],
    })


def test_should_use_harness_logic(monkeypatch):
    """静态选择：第 2 轮 partial/hard 无解法题走 harness，completed/easy/第 1 轮不走。"""
    import agent.scheduler as sched
    from agent.scheduler import Scheduler
    cfg = Config()
    cfg.harness_enabled = True
    cfg.round_num = 2
    s = Scheduler.__new__(Scheduler)
    s.cfg = cfg
    monkeypatch.setattr(sched, "_LIB", {"b-02": {"partial": True}})
    assert s._should_use_harness(_ch("b-02"))
    monkeypatch.setattr(sched, "_LIB", {"b-01": {"completed": True}})
    assert not s._should_use_harness(_ch("b-01"))
    monkeypatch.setattr(sched, "_LIB", {})
    assert s._should_use_harness(_ch("c-09", difficulty="hard"))
    assert not s._should_use_harness(_ch("a-01", difficulty="easy"))
    cfg.round_num = 1
    assert not s._should_use_harness(_ch("b-02"))
    cfg.round_num = 2
    cfg.harness_enabled = False
    assert not s._should_use_harness(_ch("b-02"))


class NoFlagLLM:
    """永不产出 flag 的假 LLM：驱动 worker 走到 12 步无进展 → 触发 harness 升级。"""

    def __init__(self):
        self.n = 0

    async def chat(self, messages, tools=None):
        self.n += 1
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": f"c{self.n}", "type": "function",
            "function": {"name": "shell", "arguments": json.dumps(
                {"command": "echo nothing"})},
        }]}

    def stats(self):
        return f"fake calls={self.n}"


@pytest.mark.asyncio
async def test_worker_harness_upgrade_submits_flag(tmp_path):
    """动态升级端到端：12 步无 flag → fake harness 接手 → 其输出中的 flag 自动提交 → 完成。"""
    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")
    addrs = await api.start_challenge(ch.unique_code)
    cfg = Config()
    cfg.challenge_timeout_min = 5
    cfg.recon_boot = False
    cfg.record_solutions = False
    cfg.harness_enabled = True
    cfg.harness_backend = _fake_backend(tmp_path, [
        '{"type":"item.completed","item":{"text":"拿到 flag{mock-1} 了"}}',
    ])
    w = Worker(cfg, NoFlagLLM(), api, ch, addrs, str(tmp_path / "mock_web_01"),
               deadline=time.monotonic() + 600)
    w.harness_upgrade_after_s = 0  # 测试不等 4 分钟
    res = await w.run()
    assert res.completed, res.reason
    assert res.score == 100
    assert res.flags == ["flag{mock-1}"]
    # harness 复盘落盘
    assert (tmp_path / "mock_web_01" / "harness-transcript.jsonl").exists()
    await api.close()
    srv.shutdown()
