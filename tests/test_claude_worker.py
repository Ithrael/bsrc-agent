"""claude code 直接解题模式（CLAUDE_WORKER=1）测试：fake claude CLI 模拟 stream-json 输出，
验证 prompt 打包、submit_flag.sh 生成、flag 双通道提交、解法落库、无输出超时判定。"""
import json
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
    w.first_attempt = False
    w.attempt = 1
    w.ch = Challenge.from_dict({"unique_code": "bctf-02", "flag_count": 1,
                                "total_score": 400, "difficulty": "medium"})
    assert w._scaled_timeout_s() == 25 * 60
    # 首轮快速轮转 12min
    w.attempt = 0
    w.first_attempt = True
    assert w._scaled_timeout_s() == 12 * 60


@pytest.mark.asyncio
async def test_medium_round2_uses_hard_model(tmp_path, monkeypatch):
    """medium 二轮（attempt=1）claude 会话用 LLM_MODEL_HARD + effort；首轮用 flash 无 effort。"""
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
                               token_budget=0, model="", effort=""):
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

    # 首轮（attempt=0）：flash、无 effort
    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws1"),
               deadline=time.monotonic() + 600, attempt=0)
    await w._run_claude()
    assert calls[0]["model"] == ""
    assert calls[0]["effort"] == ""

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
    # easy 首轮仍 flash
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
                               token_budget=0, model="", effort=""):
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

    # hard 复现题 attempt=0：不换 pro（无 hard_model/effort）
    w = Worker(cfg, object(), api, ch, addrs, str(tmp_path / "ws1"),
               deadline=time.monotonic() + 600, attempt=0)
    await w._run_claude()
    assert calls[0]["model"] == ""
    assert calls[0]["effort"] == ""
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
                               token_budget=0, model="", effort=""):
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
