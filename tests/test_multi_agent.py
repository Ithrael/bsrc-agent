"""多 agent 并行解题改造的专项回归测试（T1-T4，2026-08-28）。

- T1 资源看门狗：load/mem 连续 2 次超阈 → 紧张态（不配双主 + STATE 注入减线），恢复解除
- T1 卡面催线：多 flag 题进度停在 0<N<T ≥15min → RELAY.md 注入加线指令（20min 冷却）
- T1 drain 5s：完成早停感知延迟从 20s 降到 5s
- T2 分区双主：claude 模式大题 flag≥4 配双主；[ZONE:web/intranet] 裁剪 Task 线组
- T3 副线：hard/多 flag 非复现题配裸 LLM 副线（force_raw_llm 绕过 claude 路径）
- T3 模型分层：hard 单 flag 撒网 A/H 线用 pro
- T4 线效归因：STATE.md「## 线效」解析进 events meta
- T4 intel 回写：蒸馏输出的「跨题方法论」行自动落 intel.json.new
"""
import asyncio
import json
import time

import pytest

from agent.config import Config
from agent.scheduler import Scheduler
from agent.tsec_api import Challenge, TsecClient
from tests.mock_server import TOKEN, make_server
from tests.test_scheduler_e2e import FakeLLM


def _ch(code, flag_count, score, difficulty="hard", correct=0):
    return Challenge.from_dict({
        "unique_code": code, "description": "mock", "difficulty": difficulty,
        "level": 1, "total_score": score, "flag_count": flag_count,
        "correct_flag_count": correct, "is_completed": False,
        "container_status": "stopped", "container_addr": [],
    })


# ---- T1：资源看门狗 ----

class _TightWorker:
    """看门狗注入 STATE.md 的最小 worker 替身。"""

    def __init__(self, ws):
        self.state_path = f"{ws}/STATE.md"


def _watchdog_sched(tmp_path):
    cfg = Config()
    sched = Scheduler(cfg, FakeLLM(), _NoopApi(), str(tmp_path))
    ws = tmp_path / "zone-1"
    ws.mkdir()
    (ws / "STATE.md").write_text("# 状态\n\n## FACTS\n- flag 进度: 0/1\n")
    sched.active_workers = {"zone-1": [_TightWorker(str(ws))]}
    return sched, ws


class _NoopApi:
    async def list_challenges(self):
        return []

    async def get_hint(self, code):
        return None

    async def submit_flag(self, code, flag):
        from agent.tsec_api import SubmitResult
        return SubmitResult(False, 0, 0, 0, 1, None)


def test_resource_tick_tight_then_release(tmp_path):
    """连续 2 次高 load → 紧张态 + STATE 注入减线指令；恢复 2 次 → 解除。"""
    sched, ws = _watchdog_sched(tmp_path)
    sched._resource_tick(7.0, 8000)
    assert not sched.cfg.resource_tight, "1 次不触发（防瞬时抖动）"
    sched._resource_tick(9.0, 8000)
    assert sched.cfg.resource_tight
    injected = (ws / "STATE.md").read_text()
    assert "子 agent 数量控制在 3 以内" in injected
    # 紧张态下不配双主
    ch = _ch("b-01", 6, 1800)
    sched.cfg.claude_worker = True
    assert not sched._should_pair(ch)
    sched._resource_tick(1.0, 12000)
    assert sched.cfg.resource_tight, "恢复也要连续 2 次"
    sched._resource_tick(1.0, 12000)
    assert not sched.cfg.resource_tight
    assert "资源已恢复" in (ws / "STATE.md").read_text()
    assert sched._should_pair(ch), "恢复后大题重新可配双主"


def test_resource_tick_ignores_non_linux(tmp_path):
    """load/mem 双 None（非 Linux 读不到 /proc）：不动作。"""
    sched, _ = _watchdog_sched(tmp_path)
    sched._resource_tick(None, None)
    sched._resource_tick(None, None)
    assert not sched.cfg.resource_tight


# ---- T1：卡面催线 ----

class _StuckWorker:
    def __init__(self, cc, total):
        class _S:
            correct_count = cc
            expected_flags = total
        self.submitter = _S()


def test_refanout_injects_relay_on_stuck_surface(tmp_path):
    """进度停在 2/4 超 5min → RELAY.md 注入横向专班指令；8min 冷却内不重复。"""
    cfg = Config()
    sched = Scheduler(cfg, FakeLLM(), _NoopApi(), str(tmp_path))
    ws = tmp_path / "b-02"
    ws.mkdir()
    (ws / "RELAY.md").write_text("# 接力块\n")
    sched.active_workers = {"b-02": [_StuckWorker(2, 4)]}
    now = time.monotonic()
    # 首次采样：记录基线（2, now），未到 5min 不注入
    sched._refanout_stuck_surfaces(now - 6 * 60 + 60)   # 基线比这更晚即可
    sched._surface_stuck["b-02"] = (2, now - 6 * 60)    # 直接预置停 6min
    sched._refanout_stuck_surfaces(now)
    relay = (ws / "RELAY.md").read_text()
    assert "横向专班" in relay, "卡面 5min 应注入横向专班指令"
    # 冷却内再触发：不重复注入
    sched._refanout_stuck_surfaces(now + 60)
    assert (ws / "RELAY.md").read_text().count("横向专班") == 1
    # 进度推进到全拿：不再催
    sched.active_workers = {"b-02": [_StuckWorker(4, 4)]}
    sched._refanout_stuck_surfaces(now + 1200)
    assert (ws / "RELAY.md").read_text().count("横向专班") == 1


# ---- T1：drain 间隔 ----

def test_drain_interval_tightened():
    """drain 20s→5s：完成早停（STATE 进度→drain→杀进程组）感知延迟锁定。"""
    from agent.worker import Worker
    assert Worker._drain_interval_s == 5


# ---- T2：分区双主 ----

def test_should_pair_claude_zone_matrix(tmp_path):
    """claude 模式：flag≥4 且（≥1200 分或二轮起）才配双主；资源紧张/复现题不配。"""
    cfg = Config()
    cfg.claude_worker = True
    sched = Scheduler(cfg, FakeLLM(), _NoopApi(), str(tmp_path))
    assert not sched._should_pair(_ch("s-1", 3, 1800)), "flag<4 不配"
    assert not sched._should_pair(_ch("s-2", 6, 800, difficulty="medium")), "低分首轮不配"
    assert sched._should_pair(_ch("b-02", 6, 1800)), "6 面 1800 分大题配双主"
    sched._attempts["b-09"] = 1
    assert sched._should_pair(_ch("b-09", 4, 1000)), "二轮起 4 面也配"
    cfg.resource_tight = True
    assert not sched._should_pair(_ch("b-02", 6, 1800)), "资源紧张不配"


@pytest.mark.asyncio
async def test_zone_trims_line_keys_and_prompt(tmp_path, monkeypatch):
    """[ZONE:web] 裁剪 Task 线组（只建 line_A/D/E）且分区文案进 prompt。"""
    import agent.harness as harness_mod
    import agent.worker as worker_mod

    prompts: list[str] = []

    async def fake_run_harness(cfg, prompt, cwd, timeout_s, on_text=None,
                               token_budget=0, model="", effort="", stop_event=None, resume_session_id=""):
        prompts.append(prompt)
        from agent.harness import HarnessResult
        r = HarnessResult()
        r.events = 3
        r.output_text = "done"
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
    cfg.recon_boot = False
    cfg.record_solutions = False
    ch = _ch("b-02", 6, 1800)
    from agent.worker import Worker
    ws = tmp_path / "worker-A"
    w = Worker(cfg, object(), _NoopApi(), ch, ["127.0.0.1:80"], str(ws),
               deadline=time.monotonic() + 600, attempt=0,
               role_extra="[ZONE:web]\n## 分区双主（你是 A 主：入口与 Web 面方向组）\n共享文件约定。")
    assert w._zone_role_text.startswith("\n## 分区双主"), "ZONE 机器标记不进 prompt"
    await w._run_claude()
    assert "分区双主" in prompts[0], "分区角色文案应拼进 claude prompt"
    # 线目录裁剪：A 主分区只建 ADE 三条线（line_B 属于 B 主分区）
    lines = sorted(p.name for p in ws.iterdir() if p.name.startswith("line_"))
    assert lines == ["line_A", "line_D", "line_E"], f"A 主分区应只建 ADE 线，实际 {lines}"


# ---- T3：副线 ----

def test_should_second_brain_matrix(tmp_path):
    cfg = Config()
    cfg.claude_worker = True
    sched = Scheduler(cfg, FakeLLM(), _NoopApi(), str(tmp_path))
    assert sched._should_second_brain(_ch("h-1", 1, 500)), "hard 非复现配副线"
    assert sched._should_second_brain(_ch("m-1", 3, 800, difficulty="medium")), "多 flag 配副线"
    assert not sched._should_second_brain(_ch("e-1", 1, 200, difficulty="easy")), \
        "easy 单 flag 不配（主线足够，副线纯烧 token）"
    cfg.resource_tight = True
    assert not sched._should_second_brain(_ch("h-1", 1, 500)), "资源紧张不配"
    cfg.resource_tight = False
    import agent.scheduler as sm
    orig = sm._LIB
    try:
        sm._LIB = {"h-1": {"completed": True}}
        assert not sched._should_second_brain(_ch("h-1", 1, 500)), "复现题不配"
    finally:
        sm._LIB = orig


@pytest.mark.asyncio
async def test_force_raw_llm_bypasses_claude_path(tmp_path, monkeypatch):
    """force_raw_llm=True 时 run() 走裸 LLM 循环（副线/降级兜底的关键开关），
    即便全局 cfg.claude_worker=True。"""
    from agent.worker import Worker

    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    cfg = Config()
    cfg.claude_worker = True
    cfg.recon_boot = False
    cfg.record_solutions = False
    ch = next(c for c in await api.list_challenges() if c.unique_code == "mock_web_01")

    called = {"claude": False}

    async def _no_claude(self):
        called["claude"] = True
        raise AssertionError("force_raw_llm 的 worker 不应走 _run_claude")

    monkeypatch.setattr(Worker, "_run_claude", _no_claude)
    w = Worker(cfg, FakeLLM(), api, ch, ["127.0.0.1:80"], str(tmp_path / "brain"),
               deadline=time.monotonic() + 120, force_raw_llm=True)
    res = await w.run()
    assert not called["claude"]
    assert res.completed, "副线裸循环应正常解题（FakeLLM echo flag）"
    await api.close()
    srv.shutdown()


# ---- T3：模型分层 ----

@pytest.mark.asyncio
async def test_hard_solo_fanout_uses_pro_on_AH_lines(tmp_path, monkeypatch):
    """hard 单 flag 撒网：A/H 线（CVE 检索/综合深挖）用 pro，其余探路线 flash。"""
    import agent.harness as harness_mod
    import agent.worker as worker_mod

    prompts: list[str] = []

    async def fake_run_harness(cfg, prompt, cwd, timeout_s, on_text=None,
                               token_budget=0, model="", effort="", stop_event=None, resume_session_id=""):
        prompts.append(prompt)
        from agent.harness import HarnessResult
        r = HarnessResult()
        r.events = 3
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
    cfg.llm_model_hard = "deepseek-v4-pro"
    cfg.recon_boot = False
    cfg.record_solutions = False
    from agent.worker import Worker
    ch = _ch("f-05", 1, 600, difficulty="hard")
    w = Worker(cfg, object(), _NoopApi(), ch, ["127.0.0.1:80"], str(tmp_path / "ws"),
               deadline=time.monotonic() + 600, attempt=0)
    await w._run_claude()
    assert "[A线]（CVE 检索）与 [H线]（综合深挖）两条用 deepseek-v4-pro" in prompts[0], \
        "hard 单 flag 撒网应分层指定 A/H 线用 pro"


# ---- T4：线效归因 + intel 回写 ----

def test_line_stats_parses_state(tmp_path):
    from agent.worker import Worker
    ch = _ch("b-01", 4, 1200)
    w = Worker(Config(), object(), _NoopApi(), ch, ["127.0.0.1:80"],
               str(tmp_path), deadline=time.monotonic() + 60)
    (tmp_path / "STATE.md").write_text(
        "# 状态\n\n## FACTS\n- flag 进度: 2/4\n\n## 线效\n- [A] flag:1\n- [C] flag:0\n"
        "- [G] flag:1\n\n## ELIMINATED\n- x\n\n## 线效\n- [A] flag:1\n")
    assert w._line_stats() == {"A": 2, "C": 0, "G": 1}, "同线多块累加，0 也记录"
    assert w._run_meta()["lines"] == {"A": 2, "C": 0, "G": 1}


@pytest.mark.asyncio
async def test_distill_intel_writes_tip(tmp_path, monkeypatch):
    """「跨题方法论」有效内容回写 intel.json.new；「无」占位不写。"""
    import agent.worker as worker_mod
    intel_path = tmp_path / "intel.json"
    monkeypatch.setattr(worker_mod, "intel_lib_path", lambda: str(intel_path))
    ch = _ch("a-03", 1, 300)
    w = worker_mod.Worker(Config(), object(), _NoopApi(), ch, ["127.0.0.1:80"],
                          str(tmp_path / "ws"), deadline=time.monotonic() + 60)
    w._distill_intel("已达成原语: 无\n跨题方法论: 平台所有题的 flag 都在 /challenge/flagN.txt 直读")
    lines = (tmp_path / "intel.json.new").read_text().strip().splitlines()
    assert len(lines) == 1 and "/challenge/flagN.txt" in lines[0]
    key = json.loads(lines[0])
    assert "实测-a-03" in next(iter(key))
    # 占位不写
    w._distill_intel("跨题方法论: 无")
    assert len((tmp_path / "intel.json.new").read_text().strip().splitlines()) == 1
