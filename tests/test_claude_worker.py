"""claude code 直接解题模式（CLAUDE_WORKER=1）测试：fake claude CLI 模拟 stream-json 输出，
验证 prompt 打包、submit_flag.sh 生成、flag 双通道提交、解法落库、无输出超时判定。"""
import json
import time

import pytest

from agent import worker as worker_mod
from agent.config import Config
from agent.tsec_api import Challenge, TsecClient
from agent.worker import Worker
from tests.mock_server import TOKEN, make_server


def _fake_claude(tmp_path, lines: list[str]) -> str:
    """假 claude CLI：逐行输出 stream-json 事件后退出。"""
    p = tmp_path / "fake-claude.sh"
    p.write_text("#!/bin/bash\n" + "\n".join(f"echo '{l}'" for l in lines) + "\n")
    p.chmod(0o755)
    return str(p)


@pytest.mark.asyncio
async def test_claude_worker_solves_and_submits(tmp_path, monkeypatch):
    """claude 输出流含 flag → 双通道提交成功、completed、解法落库、submit_flag.sh 生成。"""
    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")
    addrs = await api.start_challenge(ch.unique_code)

    # 解法库重定向到 tmp_path，防污染真实 solutions.json
    sol_path = tmp_path / "solutions.json"
    sol_path.write_text("{}")
    notes_path = tmp_path / "notes.json"
    notes_path.write_text("{}")
    monkeypatch.setattr(worker_mod, "solution_lib_path", lambda: str(sol_path))
    monkeypatch.setattr(worker_mod, "notes_lib_path", lambda: str(notes_path))

    cfg = Config()
    cfg.claude_worker = True
    cfg.harness_backend = _fake_claude(tmp_path, [
        '{"type":"system","subtype":"init","session_id":"s1"}',
        '{"type":"assistant","message":{"content":[{"type":"text","text":"shell 输出发现 flag{mock-1}"}]}}',
        '{"type":"result","result":"solved mock_web_01"}',
    ])
    cfg.recon_boot = False
    cfg.record_solutions = True

    ws = tmp_path / "ws"
    w = Worker(cfg, object(), api, ch, addrs, str(ws), deadline=time.monotonic() + 600)
    res = await w.run()

    assert res.completed
    assert res.score == 100
    assert res.flags == ["flag{mock-1}"]
    assert res.reason == "all flags captured"
    # submit_flag.sh 生成且内容含本题 unique_code
    sh = (ws / "submit_flag.sh").read_text()
    assert "mock_web_01" in sh and "BENCHMARK_TOKEN" in sh
    # 解法落库：completed + note
    lib = json.loads(sol_path.read_text())
    assert lib["mock_web_01"]["completed"] is True
    assert "solved mock_web_01" in lib["mock_web_01"]["note"]
    await api.close()


@pytest.mark.asyncio
async def test_claude_worker_pair_split(tmp_path, monkeypatch):
    """P0 分治：flag≥3 的题 spawn 3 个 claude（入口/横向/提权收尾），三条线 flag 合并提交。"""
    srv = make_server()
    srv.state.update({
        "mock_pair_01": {
            "unique_code": "mock_pair_01",
            "description": "mock：三 flag 大题（触发分治）",
            "difficulty": "hard",
            "level": 1,
            "total_score": 1200,
            "flag_count": 3,
            "correct_flag_count": 0,
            "is_completed": False,
            "container_status": "stopped",
            "container_addr": [],
            "_flags": ["flag{p-1}", "flag{p-2}", "flag{p-3}"],
        },
    })
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_pair_01")
    addrs = await api.start_challenge(ch.unique_code)

    sol_path = tmp_path / "solutions.json"
    sol_path.write_text("{}")
    notes_path = tmp_path / "notes.json"
    notes_path.write_text("{}")
    monkeypatch.setattr(worker_mod, "solution_lib_path", lambda: str(sol_path))
    monkeypatch.setattr(worker_mod, "notes_lib_path", lambda: str(notes_path))

    # fake claude：读 stdin 按分工提示区分 A/B/C 线，各自输出对应 flag；调用次数落盘
    calls_log = tmp_path / "calls.log"
    p = tmp_path / "fake-claude.sh"
    p.write_text("#!/bin/bash\n"
                 f"echo call >> {calls_log}\n"
                 "prompt=$(cat)\n"
                 "if echo \"$prompt\" | grep -q '提权与收尾'; then\n"
                 "  echo '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"提权 flag{p-3}\"}]}}'\n"
                 "  echo '{\"type\":\"result\",\"result\":\"C done\"}'\n"
                 "elif echo \"$prompt\" | grep -q '内网横向'; then\n"
                 "  echo '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"横向 flag{p-2}\"}]}}'\n"
                 "  echo '{\"type\":\"result\",\"result\":\"B done\"}'\n"
                 "else\n"
                 "  echo '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"入口 flag{p-1}\"}]}}'\n"
                 "  echo '{\"type\":\"result\",\"result\":\"A done\"}'\n"
                 "fi\n")
    p.chmod(0o755)

    cfg = Config()
    cfg.claude_worker = True
    cfg.harness_backend = str(p)
    cfg.recon_boot = False
    cfg.record_solutions = False

    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws"),
               deadline=time.monotonic() + 600)
    res = await w.run()

    assert res.completed, res.reason
    assert res.score == 1200
    assert sorted(res.flags) == ["flag{p-1}", "flag{p-2}", "flag{p-3}"]
    assert calls_log.read_text().strip().splitlines() == ["call", "call", "call"]  # 三个进程都跑过
    await api.close()


@pytest.mark.asyncio
async def test_claude_worker_quick_retry(tmp_path, monkeypatch):
    """快速重跑：claude 提前退出（有输出但没拿全 flag）→ 当场断点重跑一次拿全。"""
    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")
    addrs = await api.start_challenge(ch.unique_code)

    sol_path = tmp_path / "solutions.json"
    sol_path.write_text("{}")
    notes_path = tmp_path / "notes.json"
    notes_path.write_text("{}")
    monkeypatch.setattr(worker_mod, "solution_lib_path", lambda: str(sol_path))
    monkeypatch.setattr(worker_mod, "notes_lib_path", lambda: str(notes_path))

    # 第 1 次调用：正常退出但没拿 flag（"gave up"）；第 2 次（重跑）：输出 flag
    calls_log = tmp_path / "calls.log"
    p = tmp_path / "fake-claude.sh"
    p.write_text("#!/bin/bash\n"
                 f"n=$(wc -l < {calls_log} 2>/dev/null || echo 0)\n"
                 f"echo call >> {calls_log}\n"
                 "if [ \"$n\" -eq 0 ]; then\n"
                 "  echo '{\"type\":\"result\",\"result\":\"gave up\"}'\n"
                 "else\n"
                 "  echo '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"断点续跑拿到 flag{mock-1}\"}]}}'\n"
                 "  echo '{\"type\":\"result\",\"result\":\"solved on retry\"}'\n"
                 "fi\n")
    p.chmod(0o755)

    cfg = Config()
    cfg.claude_worker = True
    cfg.harness_backend = str(p)
    cfg.recon_boot = False
    cfg.record_solutions = False

    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws"),
               deadline=time.monotonic() + 600)
    res = await w.run()

    assert res.completed, res.reason
    assert res.flags == ["flag{mock-1}"]
    assert calls_log.read_text().strip().splitlines() == ["call", "call"]  # 首跑 + 重跑
    await api.close()


@pytest.mark.asyncio
async def test_claude_worker_no_output(tmp_path):
    """claude 无任何输出（模拟超时被杀）→ 不误报完成，解法不落库。"""
    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")
    addrs = await api.start_challenge(ch.unique_code)

    cfg = Config()
    cfg.claude_worker = True
    cfg.harness_backend = _fake_claude(tmp_path, [])  # 无输出直接退出
    cfg.recon_boot = False
    cfg.record_solutions = False

    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws2"),
               deadline=time.monotonic() + 600)
    res = await w.run()
    assert not res.completed
    assert res.score == 0
    assert res.reason == "claude no output (timeout?)"
    await api.close()
