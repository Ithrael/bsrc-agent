"""claude code 直接解题模式（CLAUDE_WORKER=1）测试：fake claude CLI 模拟 stream-json 输出，
验证 prompt 打包、submit_flag.sh 生成、flag 双通道提交、解法落库、无输出超时判定。"""
import json
import os
import time
from pathlib import Path

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
        '{"type":"assistant","message":{"content":[{"type":"text","text":"shell 输出发现 flag{mock_flag_01}"}]}}',
        '{"type":"result","result":"solved mock_web_01"}',
    ])
    cfg.recon_boot = False
    cfg.record_solutions = True

    ws = tmp_path / "ws"
    w = Worker(cfg, object(), api, ch, addrs, str(ws), deadline=time.monotonic() + 600)
    res = await w.run()

    assert res.completed
    assert res.score == 100
    assert res.flags == ["flag{mock_flag_01}"]
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
    """P0 分治（主进程 + Task 子 agent 架构）：flag 3-4 的题 spawn 1 个主 claude 进程，
    主 prompt 含子 agent 方向表（入口/横向/提权收尾/独立侦察/CVE/云逃逸），flag 由主进程提交。"""
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
            "_flags": ["flag{p_line_01}", "flag{p_line_02}", "flag{p_line_03}"],
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

    # fake claude：单主进程，输出三个 flag + 断言 prompt 含主控指令
    calls_log = tmp_path / "calls.log"
    p = tmp_path / "fake-claude.sh"
    p.write_text("#!/bin/bash\n"
                 f"echo call >> {calls_log}\n"
                 "prompt=$(cat)\n"
                 "echo \"$prompt\" > /tmp/master_prompt.txt\n"
                 "echo '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"flag{p_line_01} flag{p_line_02} flag{p_line_03}\"}]}}'\n"
                 "echo '{\"type\":\"result\",\"result\":\"master done\"}'\n")
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
    assert sorted(res.flags) == ["flag{p_line_01}", "flag{p_line_02}", "flag{p_line_03}"]
    lines = calls_log.read_text().strip().splitlines()
    assert len(lines) == 1, f"单主进程只跑一次: {lines}"
    # 主 prompt 含主控指令与子 agent 方向表
    master = Path("/tmp/master_prompt.txt").read_text()
    assert "主控 agent" in master and "Task" in master
    for kw in ("入口面", "内网横向", "提权与收尾", "独立侦察", "CVE 专攻", "云与逃逸"):
        assert kw in master, f"子 agent 方向缺失: {kw}"
    # 防踩：子 agent 约定目录已创建
    ws = tmp_path / "ws"
    assert (ws / "line_A").is_dir() and (ws / "line_F").is_dir()
    # 防踩：共享文件软链进各 line 目录（cd line_X 后相对路径追加/提交仍落共享文件，
    # f54063c 重构误删、2026-08-24 review 恢复）
    for name in ("NOTES.md", "STATE.md", "RELAY.md", "submit_flag.sh"):
        ln = ws / "line_A" / name
        assert ln.is_symlink(), f"line_A/{name} 应为软链"
        assert ln.resolve() == (ws / name).resolve()
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
                 "  echo '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"断点续跑拿到 flag{mock_flag_01}\"}]}}'\n"
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
    assert res.flags == ["flag{mock_flag_01}"]
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


# ---- 第 2 次任务新逻辑（2026-08-16 冲 20000 配置）----

@pytest.mark.asyncio
async def test_medium_round2_timeout_25min():
    """题数最大化：medium 首轮 12min（快速轮转），重试轮 25min（run 12231 复盘回滚）。"""
    w = Worker.__new__(Worker)
    w.cfg = Config()
    w.attempt = 1
    w.ch = Challenge.from_dict({"unique_code": "bctf-02", "flag_count": 1,
                                "total_score": 400, "difficulty": "medium"})
    # 有断点（RELAY 有内容）才给满预算 25min
    import tempfile
    d = tempfile.mkdtemp()
    w.ws = d
    w.notes_path = os.path.join(d, "NOTES.md")
    with open(os.path.join(d, "RELAY.md"), "w") as f:
        f.write("# 接力块\n已达成原语: 拿到后台凭证\n")
    assert w._scaled_timeout_s() == 25 * 60
    # 首轮快速轮转 12min
    w.attempt = 0
    assert w._scaled_timeout_s() == 12 * 60


def test_medium_retry_no_progress_degrades():
    """medium retry 无断点降为 10min 快验轮（预算分级）。"""
    import tempfile
    w = Worker.__new__(Worker)
    w.cfg = Config()
    w.ch = Challenge.from_dict({"unique_code": "bctf-02", "flag_count": 1,
                                "total_score": 400, "difficulty": "medium"})
    w.attempt = 1
    d = tempfile.mkdtemp()
    w.ws = d
    w.notes_path = os.path.join(d, "NOTES.md")
    assert w._scaled_timeout_s() == 15 * 60          # 无 RELAY → 快验（12936 复盘 10→15min）
    with open(os.path.join(d, "RELAY.md"), "w") as f:
        f.write("# 接力块\n已证死路: SQLi — 预编译\n")
    assert w._scaled_timeout_s() == 25 * 60          # 有断点 → 满预算


@pytest.mark.asyncio
async def test_medium_round2_uses_hard_model(tmp_path, monkeypatch):
    """effort 分级：medium/hard 全程 max；easy 首轮不开（快扫）、二轮开（12464 pro reasoning=0 教训）。"""
    import agent.harness as harness_mod

    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")
    ch = Challenge.from_dict({"unique_code": "bctf-02", "flag_count": 1,
                              "total_score": 400, "difficulty": "medium",
                              "description": ch.description, "level": 1,
                              "correct_flag_count": 0, "is_completed": False,
                              "container_status": "stopped", "container_addr": []})
    addrs = await api.start_challenge("mock_web_01")
    addrs = ["127.0.0.1:80"]

    calls: list[dict] = []

    async def fake_run_harness(cfg, prompt, cwd, timeout_s, on_text=None,
                               token_budget=0, model="", effort="", stop_event=None):
        calls.append({"model": model, "effort": effort, "timeout_s": timeout_s})
        from agent.harness import HarnessResult
        r = HarnessResult()
        r.events = 0
        return r

    monkeypatch.setattr(harness_mod, "run_harness", fake_run_harness)

    sol_path = tmp_path / "solutions.json"
    sol_path.write_text("{}")
    notes_path = tmp_path / "notes.json"
    notes_path.write_text("{}")
    monkeypatch.setattr(worker_mod, "solution_lib_path", lambda: str(sol_path))
    monkeypatch.setattr(worker_mod, "notes_lib_path", lambda: str(notes_path))

    cfg = Config()
    cfg.claude_worker = True
    cfg.llm_model = "deepseek-v4-flash"
    cfg.llm_model_hard = "deepseek-v4-pro"
    cfg.recon_boot = False
    cfg.record_solutions = False

    # 首轮（attempt=0）：flash 模型、effort max 全量生效
    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws1"),
               deadline=time.monotonic() + 600, attempt=0)
    await w._run_claude()
    assert calls[0]["model"] == ""
    assert calls[0]["effort"] == "max"

    # 二轮（attempt=1）：pro + effort max
    w2 = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws2"),
                deadline=time.monotonic() + 600, attempt=1)
    await w2._run_claude()
    assert calls[-1]["model"] == "deepseek-v4-pro"
    assert calls[-1]["effort"] == "max"

    # easy 二轮（attempt=1）同样换 pro + effort max（用户决策：一轮没解决的都用 pro）
    ch_easy = Challenge.from_dict({"unique_code": "bctf-07", "flag_count": 1,
                                   "total_score": 250, "difficulty": "easy",
                                   "description": None, "level": 1,
                                   "correct_flag_count": 0, "is_completed": False,
                                   "container_status": "stopped", "container_addr": []})
    w3 = Worker(cfg, object(), api, ch_easy, addrs, str(tmp_path / "ws3"),
                deadline=time.monotonic() + 600, attempt=1)
    await w3._run_claude()
    assert calls[-1]["model"] == "deepseek-v4-pro"
    assert calls[-1]["effort"] == "max"
    # easy 首轮：flash 且不开 effort（快扫吞吐优先）；二轮才开 max 深挖
    w4 = Worker(cfg, object(), api, ch_easy, addrs, str(tmp_path / "ws4"),
                deadline=time.monotonic() + 600, attempt=0)
    await w4._run_claude()
    assert calls[-1]["model"] == ""
    assert calls[-1]["effort"] == ""
    await api.close()


@pytest.mark.asyncio
async def test_auto_hint_skips_when_notes_has_hint(tmp_path, monkeypatch):
    """notes.json 已有 [官方 hint]（上轮拉过）→ _auto_hint 返回空且不再调平台 API（防重复扣分）。"""
    notes_path = tmp_path / "notes.json"
    notes_path.write_text(json.dumps({"bctf-25": "[官方 hint] 数据查询功能"}))
    monkeypatch.setattr(worker_mod, "notes_lib_path", lambda: str(notes_path))

    w = Worker.__new__(Worker)
    w.cfg = Config()
    w.ch = Challenge.from_dict({"unique_code": "bctf-25", "flag_count": 1,
                                "total_score": 960, "difficulty": "hard"})
    w._hint_used = False
    w._hint_auto = False

    class FakeApi:
        def __init__(self):
            self.calls = 0

        async def get_hint(self, code):
            self.calls += 1
            return "should-not-be-called"

    fake = FakeApi()
    w.api = fake
    out = await w._auto_hint()
    assert out == ""
    assert fake.calls == 0
    assert w._hint_used  # 标记已用，本轮不再拉


# ---- 10585 复盘优化（2026-08-16）----

@pytest.mark.asyncio
async def test_repro_challenge_skips_hard_model(tmp_path, monkeypatch):
    """优化1：复现题（有完整解法）不上 pro——即使 hard 难度也走 flash 短时复现通道。"""
    import agent.harness as harness_mod

    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")
    ch = Challenge.from_dict({"unique_code": "mock_web_01", "flag_count": 1,
                              "total_score": 500, "difficulty": "hard",
                              "description": ch.description, "level": 1,
                              "correct_flag_count": 0, "is_completed": False,
                              "container_status": "stopped", "container_addr": []})
    addrs = await api.start_challenge("mock_web_01")
    addrs = ["127.0.0.1:80"]

    calls: list[dict] = []

    async def fake_run_harness(cfg, prompt, cwd, timeout_s, on_text=None,
                               token_budget=0, model="", effort="", stop_event=None):
        calls.append({"model": model, "effort": effort, "timeout_s": timeout_s,
                      "token_budget": token_budget})
        from agent.harness import HarnessResult
        r = HarnessResult()
        r.events = 0
        return r

    monkeypatch.setattr(harness_mod, "run_harness", fake_run_harness)

    # 解法库写入 completed 解法 → has_completed_sol=True
    sol_path = tmp_path / "solutions.json"
    # Claude 解法记录可能只有 note，没有裸 LLM 的 steps；仍应走短复现路径。
    sol_path.write_text(json.dumps({"mock_web_01": {"completed": True,
                                                    "note": "复现：/flag 直接读"}}))
    notes_path = tmp_path / "notes.json"
    notes_path.write_text("{}")
    monkeypatch.setattr(worker_mod, "solution_lib_path", lambda: str(sol_path))
    monkeypatch.setattr(worker_mod, "notes_lib_path", lambda: str(notes_path))

    cfg = Config()
    cfg.claude_worker = True
    cfg.llm_model = "deepseek-v4-flash"
    cfg.llm_model_hard = "deepseek-v4-pro"
    cfg.recon_boot = False
    cfg.record_solutions = False

    # hard 复现题 attempt=0：不换 pro（flash 走短复现），effort 仍全量 max
    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws1"),
               deadline=time.monotonic() + 600, attempt=0)
    await w._run_claude()
    assert calls[0]["model"] == ""
    assert calls[0]["effort"] == "max"
    # 优化4：复现题止损——单 flag 题 5min 超时 + token 熔断 clamp 50 万
    assert calls[0]["timeout_s"] == 5 * 60
    # 默认 -1：6 小时冲刺不设置 Claude 会话 token 熔断
    assert calls[0]["token_budget"] == 0
    await api.close()


@pytest.mark.asyncio
async def test_repro_multi_flag_timeout_10min(tmp_path, monkeypatch):
    """优化4：多 flag 复现题 10min 止损（b 系列复现比单 flag 稍长，但远小于 15min）。"""
    import agent.harness as harness_mod

    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = Challenge.from_dict({"unique_code": "mock_pair_01", "flag_count": 4,
                              "total_score": 1200, "difficulty": "medium",
                              "description": None, "level": 1,
                              "correct_flag_count": 0, "is_completed": False,
                              "container_status": "stopped", "container_addr": []})
    addrs = ["127.0.0.1:80"]

    calls: list[dict] = []

    async def fake_run_harness(cfg, prompt, cwd, timeout_s, on_text=None,
                               token_budget=0, model="", effort="", stop_event=None):
        calls.append({"timeout_s": timeout_s, "token_budget": token_budget})
        from agent.harness import HarnessResult
        r = HarnessResult()
        r.events = 0
        return r

    monkeypatch.setattr(harness_mod, "run_harness", fake_run_harness)

    sol_path = tmp_path / "solutions.json"
    sol_path.write_text(json.dumps({"mock_pair_01": {"completed": True,
                                                "note": "复现"}}))
    notes_path = tmp_path / "notes.json"
    notes_path.write_text("{}")
    monkeypatch.setattr(worker_mod, "solution_lib_path", lambda: str(sol_path))
    monkeypatch.setattr(worker_mod, "notes_lib_path", lambda: str(notes_path))

    cfg = Config()
    cfg.claude_worker = True
    cfg.recon_boot = False
    cfg.record_solutions = False

    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws1"),
               deadline=time.monotonic() + 600, attempt=0)
    await w._run_claude()
    assert calls[0]["timeout_s"] == 10 * 60
    assert calls[0]["token_budget"] == 0
    await api.close()


# ---- advisor brief（Heimdall observer→advisor 模式，retry 轮定向指令）----

class _FakeLLM:
    """记录 model 覆盖参数的假 LLM 客户端。"""

    def __init__(self, reply="1. 进度：已有入口凭证，缺 2 面 flag\n2. 方向：先打 /admin"):
        self.reply = reply
        self.calls: list[dict] = []

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        self.calls.append({"model": model, "n": len(messages),
                           "max_tokens": max_tokens,
                           "prompt": messages[0]["content"]})
        return {"role": "assistant", "content": self.reply}


def _brief_worker(tmp_path, addrs=("10.0.0.5:80",), attempt=1):
    w = Worker.__new__(Worker)
    w.cfg = Config()
    w.cfg.llm_model = "flash"
    w.cfg.llm_model_hard = "pro"
    w.ch = Challenge.from_dict({"unique_code": "bctf-31", "flag_count": 3,
                                "correct_flag_count": 1, "total_score": 1200,
                                "difficulty": "hard"})
    w.addrs = list(addrs)
    w.attempt = attempt
    w.ws = str(tmp_path)
    w.notes_path = str(tmp_path / "NOTES.md")
    w.state_path = str(tmp_path / "STATE.md")
    w.transcripts = []
    return w


@pytest.mark.asyncio
async def test_advisor_brief_uses_hard_model_and_reads_progress(tmp_path):
    """retry 轮 advisor 用强模型单次调用，读 RELAY/NOTES/STATE，产出定向指令文本。"""
    w = _brief_worker(tmp_path)
    (tmp_path / "RELAY.md").write_text(
        "已达成原语: SSRF→内网 10.0.0.5:8080 可达\n"
        "已证死路: SQLi — 参数全程 PDO 预编译\n"
        "下一步: 用 SSRF 打内网 redis\n")
    (tmp_path / "NOTES.md").write_text(
        "# bctf-31 笔记\n\n目标: 10.0.0.5:80\n\n- 拿到 admin/admin，后台 /admin 有上传点\n")
    (tmp_path / "STATE.md").write_text("## FACTS\n- flag 进度: 1/3\n## ELIMINATED\n- SQLi 不存在\n")
    llm = _FakeLLM()
    w.llm = llm
    brief = await w._advisor_brief()
    assert "指挥官 brief" in brief
    assert "admin" in brief  # brief 内容透传
    assert len(llm.calls) == 1  # 单次调用
    assert llm.calls[0]["model"] == "pro"  # 强模型
    p = llm.calls[0]["prompt"]
    assert "ELIMINATED" in p  # 进度进入 advisor 输入
    assert "10.0.0.5:80" in p
    assert "SSRF→内网" in p  # RELAY.md 接力块注入
    assert "批评者" in p  # critic 对抗审查要求（ASTRA 模式）


def test_claude_prompt_requires_relay_blocks(tmp_path):
    """行动纪律包含接力块强制落盘规则；攻击面清单把 RELAY.md 列为最优先读取。"""
    w = _brief_worker(tmp_path)
    ch = w.ch
    prompt = w._build_claude_prompt(ch, {}, {}, False, [], "", "")
    assert "RELAY.md" in prompt
    assert "已达成原语" in prompt and "已证死路" in prompt and "下一步" in prompt
    assert "没落盘的进展等于没发生" in prompt
    # RELAY.md 排在攻击面清单首位
    assert prompt.index("RELAY.md（接力块") < prompt.index("NOTES.md（已有发现）")


@pytest.mark.asyncio
async def test_advisor_brief_skips_when_no_progress(tmp_path):
    """空工作区（首轮即崩）没有可分析进度：不发起 LLM 调用。"""
    w = _brief_worker(tmp_path)
    llm = _FakeLLM()
    w.llm = llm
    assert await w._advisor_brief() == ""
    assert llm.calls == []


@pytest.mark.asyncio
async def test_advisor_brief_llm_failure_returns_empty(tmp_path):
    """advisor 调用失败不影响解题：返回空串。"""
    w = _brief_worker(tmp_path)
    (tmp_path / "NOTES.md").write_text("目标: 10.0.0.5:80\n- 有进展")
    (tmp_path / "STATE.md").write_text("## FACTS\n- x")

    class _Boom:
        async def chat(self, *a, **kw):
            raise RuntimeError("gateway down")

    w.llm = _Boom()
    assert await w._advisor_brief() == ""


# ---- 容器轮换检测（Heimdall instance_rotated 元数据对齐） ----

def test_rotation_notice_detects_addr_change(tmp_path):
    """NOTES 记录的旧地址 ≠ 当前地址：返回警告 + 追加新地址记录行（幂等）。"""
    w = _brief_worker(tmp_path, addrs=("10.0.0.9:80",))
    (tmp_path / "NOTES.md").write_text("# 笔记\n\n目标: 10.0.0.5:80\n\n- 已拿凭证\n")
    rot = w._rotation_notice()
    assert "容器已轮换" in rot
    assert "10.0.0.5:80" in rot and "10.0.0.9:80" in rot
    # 幂等：已追加新地址记录，再次构建不再告警
    assert w._rotation_notice() == ""
    content = (tmp_path / "NOTES.md").read_text()
    assert "[调度器] 本次目标地址: 10.0.0.9:80" in content
    # 地址记录行不含旧地址（防下次解析误判）
    line = [l for l in content.splitlines() if l.startswith("[调度器] 本次目标地址")][0]
    assert "10.0.0.5" not in line


def test_rotation_notice_no_change_returns_empty(tmp_path):
    w = _brief_worker(tmp_path, addrs=("10.0.0.5:80",))
    (tmp_path / "NOTES.md").write_text("# 笔记\n\n目标: 10.0.0.5:80\n")
    assert w._rotation_notice() == ""


def test_rotation_notice_injected_into_claude_prompt(tmp_path):
    """_build_claude_prompt 包含轮换警告块。"""
    w = _brief_worker(tmp_path, addrs=("10.0.0.9:80",))
    (tmp_path / "NOTES.md").write_text("# 笔记\n\n目标: 10.0.0.5:80\n")
    w._rotation_text = w._rotation_notice()
    ch = w.ch
    prompt = w._build_claude_prompt(ch, {}, {}, False, [], "", "")
    assert "容器已轮换" in prompt
    assert "10.0.0.9:80" in prompt


# ---- 2026-08-24 review 修复：子 agent 架构闭环加固 ----


@pytest.mark.asyncio
async def test_early_stop_on_completion(tmp_path, monkeypatch):
    """完成早停：drain 通道提交最后一面 flag → 完成事件杀主进程组，
    不等它 sleep 60 自己结束/超时（槽位时间是稀缺资源）。"""
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

    # fake claude：先吐 flag 再 sleep 60（不触发完成早停就会跑满 60s）
    p = tmp_path / "fake-claude.sh"
    p.write_text("#!/bin/bash\n"
                 "echo '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"text\","
                 "\"text\":\"found flag{mock_flag_01}\"}]}}'\n"
                 "sleep 60\n"
                 "echo '{\"type\":\"result\",\"result\":\"never reached\"}'\n")
    p.chmod(0o755)

    cfg = Config()
    cfg.claude_worker = True
    cfg.harness_backend = str(p)
    cfg.recon_boot = False
    cfg.record_solutions = False
    monkeypatch.setattr(Worker, "_drain_interval_s", 0.2)

    t0 = time.monotonic()
    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws"),
               deadline=time.monotonic() + 600)
    res = await w.run()
    elapsed = time.monotonic() - t0

    assert res.completed
    assert res.flags == ["flag{mock_flag_01}"]
    assert elapsed < 30, f"完成事件应提前杀掉主进程，实际跑了 {elapsed:.1f}s"
    await api.close()


@pytest.mark.asyncio
async def test_state_md_submitted_flag_settled(tmp_path, monkeypatch):
    """子 agent 内部提交兜底：flag 只登记在 STATE.md（submit_flag.sh 成功后写入的行），
    主进程事件流从未出现该值（Task 子 agent 输出不进主流）→ 收尾扫描登记行补记账。"""
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

    # fake claude：模拟子 agent 已在内部经 submit_flag.sh 提交成功（STATE.md 有登记行），
    # 主进程流只输出不含 flag 的总结
    p = tmp_path / "fake-claude.sh"
    p.write_text("#!/bin/bash\n"
                 "echo '- flag 已正确提交: flag{mock_flag_01}' >> STATE.md\n"
                 "echo '{\"type\":\"result\",\"result\":\"sub-agent submitted internally\"}'\n")
    p.chmod(0o755)

    cfg = Config()
    cfg.claude_worker = True
    cfg.harness_backend = str(p)
    cfg.recon_boot = False
    cfg.record_solutions = False

    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws"),
               deadline=time.monotonic() + 600)
    res = await w.run()

    assert res.completed, "STATE.md 登记行应兜底记账完成判定"
    assert res.flags == ["flag{mock_flag_01}"]
    assert res.score == 100
    await api.close()


def test_record_claude_solution_guards(tmp_path, monkeypatch):
    """解法库落库纪律（对齐裸 LLM 版）：快速失败不落库；partial 不降级已有
    completed；partial 标记补写（scheduler 断点优先通道依赖）。"""
    from agent.harness import HarnessResult

    sol_path = tmp_path / "solutions.json"
    monkeypatch.setattr(worker_mod, "solution_lib_path", lambda: str(sol_path))

    def _worker():
        w = Worker.__new__(Worker)
        w.cfg = Config()
        w.cfg.record_solutions = True
        w.ch = Challenge.from_dict({"unique_code": "mock_web_01", "flag_count": 1,
                                    "total_score": 100, "difficulty": "easy"})
        w.result = worker_mod.WorkerResult()
        return w

    res = HarnessResult()
    res.output_text = "gave up"
    w = _worker()

    # 场景 1：已有 completed 记录 + 本轮快速失败（<8min）→ 完全不落库
    sol_path.write_text(json.dumps(
        {"mock_web_01": {"completed": True, "note": "已验证解法"}}))
    w.result.completed = False
    w.result.elapsed_min = 2.0
    w._record_claude_solution(res)
    lib = json.loads(sol_path.read_text())
    assert lib["mock_web_01"] == {"completed": True, "note": "已验证解法"}

    # 场景 2：本轮超时失败（≥8min partial）→ 已有 completed 不降级覆盖
    w.result.elapsed_min = 12.0
    w._record_claude_solution(res)
    lib = json.loads(sol_path.read_text())
    assert lib["mock_web_01"]["completed"] is True

    # 场景 3：无已有记录 + 超时失败 → 落 partial=True（断点通道可识别）
    sol_path.write_text("{}")
    w._record_claude_solution(res)
    lib = json.loads(sol_path.read_text())
    assert lib["mock_web_01"]["completed"] is False
    assert lib["mock_web_01"]["partial"] is True

    # 场景 4：解出 → completed=True 且清 partial
    w.result.completed = True
    w._record_claude_solution(res)
    lib = json.loads(sol_path.read_text())
    assert lib["mock_web_01"]["completed"] is True
    assert lib["mock_web_01"]["partial"] is False


# ---- ClawGod 保险（2026-08-24：缓存 env + 启动冒烟降级 + 运行时健康守卫）----


def test_claude_env_sets_attribution_header():
    """缓存保险：_claude_env 显式设 CLAUDE_CODE_ATTRIBUTION_HEADER=0——
    ClawGod 补丁的原生 env 等价物，patch 静默失效时缓存命中仍保得住。"""
    from agent.harness import _claude_env
    cfg = Config()
    env = _claude_env(cfg)
    assert env["CLAUDE_CODE_ATTRIBUTION_HEADER"] == "0"
    assert env["ANTHROPIC_BASE_URL"]
    assert "ANTHROPIC_API_KEY" not in env  # 避免与 AUTH_TOKEN 冲突


@pytest.mark.asyncio
async def test_smoke_claude_detects_broken_and_healthy(monkeypatch):
    """启动冒烟：rc!=0 或无 stream 输出判死（--version 正常但 -p 秒退的
    patch 断裂场景）；rc=0 且有 JSON 输出判活。"""
    from agent import main as main_mod

    class _Proc:
        def __init__(self, rc, out):
            self.returncode = rc
            self._out = out

        async def communicate(self):
            return self._out, b""

    cfg = Config()

    async def fake_exec_fail(*a, **kw):
        return _Proc(1, b"clawgod: bun runtime not found")

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec_fail)
    assert await main_mod._smoke_claude(cfg) is False

    async def fake_exec_ok(*a, **kw):
        return _Proc(0, b'{"type":"system","subtype":"init"}\n{"type":"result","result":"OK"}\n')

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec_ok)
    assert await main_mod._smoke_claude(cfg) is True


def test_scheduler_claude_health_guard():
    """运行时守卫：连续 6 次崩溃/无输出全局降级裸 LLM；任何正常输出清零计数。"""
    from agent.scheduler import Scheduler

    sched = Scheduler.__new__(Scheduler)
    sched.cfg = Config()
    sched.cfg.claude_worker = True
    sched.cfg.harness_enabled = True
    sched._claude_fail_streak = 0

    def _res(reason):
        r = worker_mod.WorkerResult()
        r.reason = reason
        return r

    for i in range(5):
        sched._track_claude_health(_res("crash: FileNotFoundError: claude"))
        assert sched.cfg.claude_worker, f"5 次内不误杀（第 {i + 1} 次）"
    sched._track_claude_health(_res("claude no output (timeout?)"))
    assert not sched.cfg.claude_worker
    assert not sched.cfg.harness_enabled

    # 恢复场景：计数接近阈值时一次正常输出清零
    sched.cfg.claude_worker = True
    sched.cfg.harness_enabled = True
    sched._claude_fail_streak = 5
    sched._track_claude_health(_res("claude done"))
    assert sched._claude_fail_streak == 0
    assert sched.cfg.claude_worker


# ---- hint 时机提前（Cairn_X 148-hint 复盘：hard/多 flag 首轮即带 hint 开工） ----

def _hint_worker(difficulty="hard", flag_count=4, policy="free"):
    w = Worker.__new__(Worker)
    w.cfg = Config()
    w.cfg.hint_policy = policy
    w.ch = Challenge.from_dict({"unique_code": "b-02", "flag_count": flag_count,
                                "total_score": 1200, "difficulty": difficulty})
    w.attempt = 0
    return w


def test_hint_upfront_hard_free():
    # run 12610 复盘：hard 单 flag 首轮带 hint 全面 -10%（a-01 500→450 等 7 题）
    # 且无速度收益——回到 12464 首轮硬解、retry 再拉的满分策略
    assert not _hint_worker("hard", 1)._should_hint_upfront()
    assert _hint_worker("medium", 2)._should_hint_upfront()        # 多 flag 题保留 upfront
    assert _hint_worker("hard", 4)._should_hint_upfront()          # 多 flag 大题（b 系列）


def test_hint_upfront_excluded():
    assert not _hint_worker("easy", 1)._should_hint_upfront()      # flash 能解，不浪费 10%
    assert not _hint_worker("medium", 1)._should_hint_upfront()
    assert not _hint_worker("hard", 4, policy="stuck")._should_hint_upfront()  # stuck 策略不首轮拉


# ---- CLAIM/EVIDENCE 提交纪律（hxbai 69 flag 仅 4 错提） ----

def test_claude_prompt_has_claim_evidence_discipline(tmp_path):
    """行动纪律含 CLAIM/EVIDENCE 条款：证据来自工具输出才提交。"""
    w = _brief_worker(tmp_path)
    prompt = w._build_claude_prompt(w.ch, {}, {}, False, [], "", "")
    assert "CLAIM/EVIDENCE" in prompt
    assert "RAW EVIDENCE" in prompt or "证据" in prompt
    assert "禁止提交" in prompt


def test_submit_flag_sh_requires_evidence():
    """生成的 submit_flag.sh 第 1 次提交起要求证据参数（<6 字符拒绝），NOTES 已记来源可豁免。"""
    src = open("agent/worker.py").read()
    assert "EVID=" in src and "${#EVID} -lt 6" in src    # 证据长度闸门
    assert "grep -Fq" in src and "NOTES.md" in src       # 来源已记录豁免
    assert "[证据拒绝]" in src
    assert "CLAIM/EVIDENCE 提交纪律" in src              # prompt 行动纪律同步


# ---- 已购 hint 置顶（每次轮转免费复用，重复调 API 会重复扣 10%） ----

def test_hint_hoisted_to_top_of_prompt(tmp_path):
    """notes.json 里的官方 hint 提升为独立置顶段，排在解法库记录之前。"""
    w = _brief_worker(tmp_path)
    notes = {"bctf-31": "[官方 hint] 关注 JWT Header 里的 kid 字段与管理面板规则执行逻辑。"}
    prompt = w._build_claude_prompt(w.ch, {}, notes, False, [], "", "")
    assert "官方提示（已购" in prompt
    assert "kid 字段" in prompt
    assert "先按此验证，再扩展" in prompt
    # 置顶段在解法库记录段之前
    if "解法库记录" in prompt:
        assert prompt.index("官方提示（已购") < prompt.index("解法库记录")


def test_no_progress_not_requeued():
    """scheduler._finish：no_progress 原因不进常规 retry 队列（末尾回查轮仍可回挖）。"""
    import asyncio
    from agent.scheduler import Scheduler
    from agent.tsec_api import Challenge

    async def run():
        sch = Scheduler.__new__(Scheduler)
        sch.cfg = Config()
        sch.cfg.retry_unsolved = True
        sch.api = None
        sch.done = {}
        sch.retry_queue = []
        async def fake_close(code):
            return True
        sch._close_safely = fake_close
        ch = Challenge.from_dict({"unique_code": "f2-05", "flag_count": 1,
                                  "total_score": 400, "difficulty": "hard"})
        from agent.worker import WorkerResult
        res = WorkerResult()
        res.completed = False
        res.reason = "no_progress: attempt 2 无 flag 无断点，退出轮转（末尾回查轮可回挖）"
        await sch._finish(ch, res)
        assert sch.retry_queue == [], "no_progress 不应进入常规 retry"
        res2 = WorkerResult()
        res2.completed = False
        res2.reason = "claude done"
        await sch._finish(ch, res2)
        assert sch.retry_queue == [ch], "普通失败仍应进入 retry"
    asyncio.run(run())


# ---- 多阶段渗透基建（HOSTS.md 台账 + 通用 post-exploitation 工具，run 12464 渗透 60.71 复盘） ----

def test_hosts_ledger_discipline_in_prompt(tmp_path):
    """行动纪律含 HOSTS.md 台账维护；攻击面清单把台账列入先读顺序。"""
    w = _brief_worker(tmp_path)
    prompt = w._build_claude_prompt(w.ch, {}, {}, False, [], "", "")
    assert "HOSTS.md 资产台账" in prompt
    assert prompt.index("HOSTS.md（资产台账") < prompt.index("NOTES.md（已有发现）")


def test_killchain_tooling_scripts_exist():
    """镜像内置的通用 post-exploitation 脚本存在且 bash 语法合法。"""
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for name in ("flag_sweep.sh", "creds_replay.sh"):
        p = os.path.join(root, "tools", name)
        assert os.path.exists(p), name
        r = subprocess.run(["bash", "-n", p], capture_output=True)
        assert r.returncode == 0, f"{name}: {r.stderr.decode()[:100]}"


def test_subagent_shared_files_include_hosts_ledger():
    """子 agent 软链共享文件含 HOSTS.md；Dockerfile 烤进工具与 chisel。"""
    src = open("agent/worker.py").read()
    assert '"RELAY.md", "HOSTS.md", "submit_flag.sh"' in src
    dk = open("Dockerfile").read()
    assert "chisel" in dk
    assert "COPY tools/flag_sweep.sh tools/creds_replay.sh /opt/tools/" in dk


# ---- 闭环修复回归（2026-08-26）：hint 去重 / HOSTS 速览 / harness 解法落库 ----

@pytest.mark.asyncio
async def test_hint_cb_reuses_cached_hint(tmp_path, monkeypatch):
    """notes.json 已有官方 hint 时 get_hint 工具直接复用缓存，不再打 hint API
    （重复查看重复扣 10%）。"""
    from agent.config import Config
    notes_p = tmp_path / "notes.json"
    notes_p.write_text(json.dumps({"a-01": "[官方 hint] 从 SQL 注入入手，users 表有 flag"}))
    monkeypatch.setattr(worker_mod, "notes_lib_path", lambda: str(notes_p))

    class BoomApi:
        async def get_hint(self, code):
            raise AssertionError("已缓存 hint 不应再打 API")

    w = Worker.__new__(Worker)
    w.cfg = Config()          # hint_policy 默认 free
    w.api = BoomApi()
    w.ch = Challenge.from_dict({"unique_code": "a-01", "flag_count": 1,
                                "total_score": 500, "difficulty": "easy"})
    w.started = time.monotonic()
    w._hint_used = False
    out = await w._hint_cb()
    assert "从 SQL 注入入手" in out
    assert "免费复用" in out
    assert w._hint_used


@pytest.mark.asyncio
async def test_workspace_digest_includes_hosts_ledger(tmp_path):
    """续跑轮工作区速览必须带 HOSTS.md 资产台账（多 flag 续跑最关键交接）。"""
    ws = tmp_path
    (ws / "NOTES.md").write_text("# 笔记\n- 入口在 8080")
    (ws / "STATE.md").write_text("## FACTS\n- flag 进度: 1/3")
    (ws / "RELAY.md").write_text("# 接力块\n已达成原语: RCE")
    (ws / "HOSTS.md").write_text("# 资产台账\n- web-1 | 8080/nginx | admin:123 | flag1 已拿")
    w = Worker.__new__(Worker)
    w.ws = str(ws)
    w.notes_path = str(ws / "NOTES.md")
    w.state_path = str(ws / "STATE.md")
    digest = await w._workspace_digest()
    assert "HOSTS.md" in digest
    assert "web-1 | 8080/nginx" in digest
    assert "RELAY.md" in digest and "STATE.md" in digest


def test_record_harness_solution(tmp_path, monkeypatch):
    """静态 harness 路径解法落库：completed/partial 写 solutions.json；
    partial 不降级覆盖 completed；<8min 失败不落库。"""
    from agent.worker import record_harness_solution
    sol_p = tmp_path / "solutions.json"
    sol_p.write_text("{}")
    monkeypatch.setattr(worker_mod, "solution_lib_path", lambda: str(sol_p))

    record_harness_solution("x-01", "RCE via CVE", completed=True, elapsed_min=20.0)
    lib = json.loads(sol_p.read_text())
    assert lib["x-01"]["completed"] is True
    assert "RCE via CVE" in lib["x-01"]["note"]

    record_harness_solution("x-01", "failed retry", completed=False, elapsed_min=15.0)
    lib = json.loads(sol_p.read_text())
    assert lib["x-01"]["completed"] is True          # 不降级覆盖
    assert "RCE via CVE" in lib["x-01"]["note"]

    record_harness_solution("x-02", "quick fail", completed=False, elapsed_min=3.0)
    lib = json.loads(sol_p.read_text())
    assert "x-02" not in lib                         # 短命失败不落库


# ---- 2026-08-27 修复回归：证据统一 / STATE 进度早停 / 分类 playbook / events.jsonl ----

@pytest.mark.asyncio
async def test_submit_flag_sh_real_execution(tmp_path):
    """真实执行 submit_flag.sh（不是只 grep 源码）：无证据被证据闸门拒绝（exit≠0）；
    带证据提交成功并登记 STATE.md「flag 已正确提交」+「flag 进度: 1/1」。
    从 line 子目录执行（13174 实测场景：claude bash 换目录跑，相对路径拼错）——
    修复后 .flag_lock/.flag_wrong/STATE.md 仍落在工作区根。"""
    import subprocess
    srv = make_server()
    host, port = srv.server_address
    ch = Challenge.from_dict({"unique_code": "mock_web_01", "flag_count": 1,
                              "total_score": 100, "difficulty": "easy"})
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "NOTES.md").write_text("# notes\n")
    (ws / "STATE.md").write_text("# state\n## FACTS\n- flag 进度: 0/1\n")
    sh = ws / "submit_flag.sh"
    sh.write_text(worker_mod._submit_flag_script(ch, str(ws)))
    sh.chmod(0o755)
    sub = ws / "line_A"
    sub.mkdir()
    env = {"BENCHMARK_BASE_URL": f"http://{host}:{port}",
           "BENCHMARK_TOKEN": TOKEN,
           "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    # 无证据 → 闸门拒绝，不打平台（mock 的 correct 计数不变）
    r1 = subprocess.run(["bash", str(sh), "flag{mock_flag_01}"],
                        cwd=sub, env=env, capture_output=True, text=True)
    assert r1.returncode != 0
    assert "证据拒绝" in r1.stdout
    # 带证据 → 成功 + STATE.md 双行登记（进度行是 Python drain 完成判定的输入）
    r2 = subprocess.run(["bash", str(sh), "flag{mock_flag_01}", "cat /flag 第一行输出"],
                        cwd=sub, env=env, capture_output=True, text=True)
    assert r2.returncode == 0, r2.stdout
    assert '"correct": true' in r2.stdout
    state = (ws / "STATE.md").read_text()
    assert "flag 已正确提交: flag{mock_flag_01}" in state
    assert "flag 进度: 1/1" in state
    assert (ws / ".flag_wrong").read_text().strip() == "0"
    await TsecClient(f"http://{host}:{port}", TOKEN).close()


def test_submit_flag_script_embeds_absolute_paths():
    """脚本内嵌的共享文件路径必须绝对化（13174 实测 bug：RUN_DIR 相对路径 +
    claude bash 换目录执行 → .flag_lock/STATE.md 写到不存在的深层路径，
    flock/连错计数/显式通道完成判定全失效）。"""
    ch = Challenge.from_dict({"unique_code": "x-01", "flag_count": 1,
                              "total_score": 100, "difficulty": "easy"})
    src = worker_mod._submit_flag_script(ch, "runs/20260827-125035/f1-05")
    abs_ws = os.path.abspath("runs/20260827-125035/f1-05")
    assert f">{abs_ws}/.flag_lock" in src
    assert f"> {abs_ws}/.flag_wrong" in src       # echo 0 > path（带空格）
    assert f">> {abs_ws}/STATE.md" in src
    assert f"cat {abs_ws}/.flag_wrong" in src


@pytest.mark.asyncio
async def test_submit_flag_sh_no_evidence_does_not_submit(tmp_path):
    """证据闸门拒绝时不产生任何平台请求：mock correct 计数保持 0（省一次必错请求）。"""
    import subprocess
    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = Challenge.from_dict({"unique_code": "mock_web_01", "flag_count": 1,
                              "total_score": 100, "difficulty": "easy"})
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "NOTES.md").write_text("# notes\n")
    (ws / "STATE.md").write_text("# state\n")
    sh = ws / "submit_flag.sh"
    sh.write_text(worker_mod._submit_flag_script(ch, str(ws)))
    sh.chmod(0o755)
    env = {"BENCHMARK_BASE_URL": f"http://{host}:{port}",
           "BENCHMARK_TOKEN": TOKEN,
           "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    r = subprocess.run(["bash", str(sh), "flag{mock_flag_01}"],
                       cwd=ws, env=env, capture_output=True, text=True)
    assert r.returncode != 0
    challenges = await api.list_challenges()
    c = next(x for x in challenges if x.unique_code == "mock_web_01")
    assert c.correct_flag_count == 0
    await api.close()


@pytest.mark.asyncio
async def test_state_progress_completes_and_stops_early(tmp_path, monkeypatch):
    """修复 3 核心场景：子 agent 经 submit_flag.sh 提交最后一面（STATE.md 进度行
    1/1），主进程事件流从未出现该 flag → drain 读进度行置完成事件杀主进程，
    不等到它 sleep 60 自己退出。"""
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

    # fake claude：模拟子 agent 已提交成功（STATE.md 有进度行 + 登记行），
    # 主进程流只输出不含 flag 的总结，随后 sleep 60
    p = tmp_path / "fake-claude.sh"
    p.write_text("#!/bin/bash\n"
                 "echo '## FACTS' >> STATE.md\n"
                 "echo \"- flag 已正确提交: flag{mock_flag_01} ($(date +%H:%M:%S))\" >> STATE.md\n"
                 "echo \"- flag 进度: 1/1 ($(date +%H:%M:%S))\" >> STATE.md\n"
                 "echo '{\"type\":\"result\",\"result\":\"sub-agent submitted internally\"}'\n"
                 "sleep 60\n")
    p.chmod(0o755)

    cfg = Config()
    cfg.claude_worker = True
    cfg.harness_backend = str(p)
    cfg.recon_boot = False
    cfg.record_solutions = False
    monkeypatch.setattr(Worker, "_drain_interval_s", 0.2)

    t0 = time.monotonic()
    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws"),
               deadline=time.monotonic() + 600)
    res = await w.run()
    elapsed = time.monotonic() - t0

    assert res.completed, res.reason
    assert res.flags == ["flag{mock_flag_01}"]
    assert elapsed < 30, f"drain 应读 STATE 进度提前杀主进程，实际跑了 {elapsed:.1f}s"
    await api.close()


def test_state_flag_progress_parses_latest(tmp_path):
    """STATE.md 进度行只认本 attempt 开始后写入的（带时间戳）：上轮残留行与
    无时间戳初始行不做完成判定（flag 每轮重新生成，上轮 3/4 ≠ 本轮 3/4）。"""
    w = Worker.__new__(Worker)
    w.state_path = str(tmp_path / "STATE.md")
    w._started_wall = time.time() - 60          # 本 attempt 60 秒前开始
    now = time.strftime("%H:%M:%S")
    (tmp_path / "STATE.md").write_text(
        "## FACTS\n"
        "- flag 进度: 3/4 (10:00:00)\n"          # 上轮残留（时间戳更早）：跳过
        f"- flag 进度: 2/4 ({now})\n"
        "- flag 进度: 1/4\n")                    # 无时间戳（初始行）：跳过
    assert w._state_flag_progress() == (2, 4)
    # 只有残留行：返回 None（不误触发完成/不虚增计数）
    (tmp_path / "STATE.md").write_text(
        "## FACTS\n- flag 进度: 3/4 (10:00:00)\n- flag 进度: 1/4\n")
    assert w._state_flag_progress() is None


@pytest.mark.asyncio
async def test_subagent_instruction_requires_evidence(tmp_path, monkeypatch):
    """子 agent 指令与脚本用法一致：必须带 RAW EVIDENCE 参数（此前只写
    ./submit_flag.sh <flag>，会被脚本证据闸门直接拒绝）。"""
    srv = make_server()
    srv.state.update({
        "mock_pair_02": {
            "unique_code": "mock_pair_02",
            "description": "mock：三 flag（触发分治）",
            "difficulty": "hard",
            "level": 1,
            "total_score": 1200,
            "flag_count": 3,
            "correct_flag_count": 0,
            "is_completed": False,
            "container_status": "stopped",
            "container_addr": [],
            "_flags": ["flag{p_02a}", "flag{p_02b}", "flag{p_02c}"],
        },
    })
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_pair_02")
    addrs = await api.start_challenge(ch.unique_code)

    sol_path = tmp_path / "solutions.json"
    sol_path.write_text("{}")
    notes_path = tmp_path / "notes.json"
    notes_path.write_text("{}")
    monkeypatch.setattr(worker_mod, "solution_lib_path", lambda: str(sol_path))
    monkeypatch.setattr(worker_mod, "notes_lib_path", lambda: str(notes_path))

    prompt_file = tmp_path / "master_prompt.txt"
    p = tmp_path / "fake-claude.sh"
    p.write_text("#!/bin/bash\n"
                 "cat > " + str(prompt_file) + "\n"
                 "echo '{\"type\":\"result\",\"result\":\"no flag\"}'\n")
    p.chmod(0o755)

    cfg = Config()
    cfg.claude_worker = True
    cfg.harness_backend = str(p)
    cfg.recon_boot = False
    cfg.record_solutions = False

    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws"),
               deadline=time.monotonic() + 600)
    await w.run()

    master = prompt_file.read_text()
    assert "./submit_flag.sh <flag> '<RAW EVIDENCE" in master
    assert "`./submit_flag.sh <flag>` 提交" not in master   # 旧裸用法已移除
    await api.close()


def test_claude_prompt_injects_category_playbook(tmp_path):
    """修复 5：生产路径复用分类 playbook——b 系列注入多阶段渗透速查、
    f 系列注入二进制逆向速查（且不再塞偏 Web 的攻击面清单）。"""
    w = _brief_worker(tmp_path)
    ch_b = Challenge.from_dict({"unique_code": "b-02", "flag_count": 6,
                                "correct_flag_count": 0, "total_score": 1200,
                                "difficulty": "hard"})
    p_b = w._build_claude_prompt(ch_b, {}, {}, False, [], "", "")
    assert "多阶段渗透速查" in p_b
    assert "攻击面清单" in p_b          # b 系列是 Web 多阶段：保留清单
    ch_f = Challenge.from_dict({"unique_code": "f2-05", "flag_count": 1,
                                "correct_flag_count": 0, "total_score": 400,
                                "difficulty": "hard"})
    p_f = w._build_claude_prompt(ch_f, {}, {}, False, [], "", "")
    assert "二进制逆向" in p_f
    assert "攻击面清单" not in p_f      # 非 Web 类删除无关段落（注册矩阵等纯噪音）


def test_claude_prompt_exec_env_distinction(tmp_path):
    """修复 5：明确区分解题容器 shell 与目标环境执行；云元数据/直读命令标注从目标发起。"""
    w = _brief_worker(tmp_path)
    ch = Challenge.from_dict({"unique_code": "a-01", "flag_count": 1,
                              "correct_flag_count": 0, "total_score": 500,
                              "difficulty": "easy"})
    p = w._build_claude_prompt(ch, {}, {}, False, [], "", "")
    assert "解题容器" in p and "不是目标" in p
    assert "从**目标环境** curl" in p or "从**目标环境**" in p
    # 云环境必查条目带「从目标发起」标注
    assert "从目标发起，不是解题容器" in p


def test_load_events_aggregates(tmp_path):
    """events.jsonl 聚合：attempts/completed/p50（只统计解出的耗时）/solve_prob。"""
    from agent.scheduler import _load_events
    (tmp_path / "events.jsonl").write_text("\n".join(json.dumps(e) for e in [
        {"challenge": "b-02", "completed": True, "elapsed_min": 20.0, "score": 1},
        {"challenge": "b-02", "completed": True, "elapsed_min": 30.0, "score": 1},
        {"challenge": "b-02", "completed": True, "elapsed_min": 10.0, "score": 1},
        {"challenge": "b-02", "completed": False, "elapsed_min": 15.0, "score": 0},
        {"challenge": "x-99", "completed": False, "elapsed_min": 12.0, "score": 0},
    ]) + "\n")
    st = _load_events(str(tmp_path))
    assert st["b-02"]["attempts"] == 4
    assert st["b-02"]["completed"] == 3
    assert st["b-02"]["p50"] == 20.0      # 解出耗时中位数（10/20/30）
    assert st["b-02"]["solve_prob"] == 0.75
    assert st["x-99"]["solve_prob"] == 0.0 and st["x-99"]["p50"] is None
    assert _load_events(str(tmp_path / "missing")) == {}


def test_priority_learns_from_events(tmp_path):
    """修复 6：实测高解出率的剩一面题提到断点档；多轮零解题降权；
    P50 耗时替换难度估算。"""
    from agent.scheduler import _priority
    ch1 = Challenge.from_dict({"unique_code": "x-01", "flag_count": 2,
                               "correct_flag_count": 1, "total_score": 500,
                               "difficulty": "medium"})
    ch2 = Challenge.from_dict({"unique_code": "x-02", "flag_count": 1,
                               "correct_flag_count": 0, "total_score": 500,
                               "difficulty": "medium"})
    base1 = _priority(ch1, 2)
    high = {"x-01": {"attempts": 4, "completed": 3, "p50": 8.0, "solve_prob": 0.75}}
    p1 = _priority(ch1, 2, high)
    assert p1 // 1000 == 1               # 高解出率剩一面 ≈ 断点档
    assert p1 < base1                    # 且比无实测数据时更靠前
    zero = {"x-02": {"attempts": 3, "completed": 0, "p50": None, "solve_prob": 0.0}}
    base2 = _priority(ch2, 2)
    p2 = _priority(ch2, 2, zero)
    assert p2 // 1000 == base2 // 1000 + 4   # 多轮零解降权
    # P50 进入 est 分量
    p3 = _priority(ch2, 2, {"x-02": {"attempts": 1, "completed": 1, "p50": 3.0, "solve_prob": 1.0}})
    assert p3 % 1000 == 3.0


def test_finish_records_events(tmp_path):
    """_finish 落一行 events.jsonl（challenge/attempt/meta 全量字段），聚合随刷新。"""
    import asyncio
    from agent.scheduler import Scheduler

    async def run():
        sch = Scheduler.__new__(Scheduler)
        sch.cfg = Config()
        sch.cfg.retry_unsolved = True
        sch.run_dir = str(tmp_path)
        sch._events = {}
        sch._attempts = {"x-01": 1}
        sch._dead = set()
        sch.done = {}
        sch.retry_queue = []

        async def fake_close(code):
            return True
        sch._close_safely = fake_close
        ch = Challenge.from_dict({"unique_code": "x-01", "flag_count": 1,
                                  "correct_flag_count": 0, "total_score": 100,
                                  "difficulty": "easy"})
        res = worker_mod.WorkerResult()
        res.completed = True
        res.score = 100
        res.flags = ["flag{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"]
        res.reason = "all flags captured"
        res.elapsed_min = 3.2
        res.meta = {"model": "deepseek-v4-flash", "fan_out": 6, "tokens": 12345,
                    "first_flag_s": 42.0, "primitives": 2}
        await sch._finish(ch, res)
        assert sch._events["x-01"]["solve_prob"] == 1.0
        lines = (tmp_path / "events.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        ev = json.loads(lines[0])
        assert ev["challenge"] == "x-01" and ev["attempt"] == 1
        assert ev["model"] == "deepseek-v4-flash" and ev["fan_out"] == 6
        assert ev["first_flag_s"] == 42.0 and ev["completed"] is True
    asyncio.run(run())


def test_run_meta_fields(tmp_path):
    """_run_meta：模型/fan-out/token/首 flag 秒数/原语计数齐全（events.jsonl 输入）。"""
    w = Worker.__new__(Worker)
    w.cfg = Config()
    w._used_model = "deepseek-v4-pro"
    w._fan_out = 8
    w._tokens_used = 999
    w._started_wall = time.time() - 120
    w.state_path = str(tmp_path / "STATE.md")
    now = time.strftime("%H:%M:%S")
    (tmp_path / "STATE.md").write_text(
        f"## FACTS\n- flag 已正确提交: flag{{x}} ({now})\n- flag 进度: 1/4\n")
    w.ws = str(tmp_path)
    (tmp_path / "RELAY.md").write_text(
        "# 接力块\n已达成原语: RCE\n已达成原语: 无\n已达成原语: 拿到 admin 凭据\n")
    meta = w._run_meta()
    assert meta["model"] == "deepseek-v4-pro"
    assert meta["fan_out"] == 8 and meta["tokens"] == 999
    assert meta["first_flag_s"] is not None and meta["first_flag_s"] > 0
    assert meta["primitives"] == 2      # 「无」占位行不算
