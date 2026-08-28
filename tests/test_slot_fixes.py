"""P0/P1 槽位与吞吐修复的专项回归测试（2026-08-28）。

- P0-1 空槽回查：pending/retry 双空 + 任务在跑时，平台回查把可回挖题带回补空槽
- P0-2 attempt 计数：409/start 失败轮转不消耗重试预算，容器就绪后才自增
- P0-3 endgame 放行：快赢耗尽后放行最优候选，预算封顶 min(15, 剩余窗口)
- P0-4 冷却唤醒：只看 pending 内题的到期戳，陈旧条目不拖长空转睡眠
- P1-5 events 跨轮合并：第 2 轮开局即带第 1 轮实测排序
- P1-6 停滞抢占：零 flag 零新 FACTS 的在跑窗口被 cancel 轮转，有进展不动
- P1-7 close 短超时：单次 10s 不进重试链
"""
import asyncio
import json
import time

import httpx
import pytest

from agent.config import Config
from agent.scheduler import Scheduler, _load_cross_run_events, _load_events
from agent.tsec_api import ApiError, Challenge, TsecClient
from tests.mock_server import TOKEN, make_server
from tests.test_scheduler_e2e import FakeLLM, _extra_challenge


# ---- P0-2：attempt 计数不因 409/start 失败轮转而消耗 ----

class _Start409Api:
    """list 正常、start 恒 409 invalid_state（平台实例满）。"""

    def __init__(self, code="att-1"):
        self.code = code

    async def list_challenges(self):
        return [Challenge.from_dict({"unique_code": self.code, "flag_count": 1,
                                     "difficulty": "easy", "total_score": 100})]

    async def start_challenge(self, code):
        raise ApiError(409, "invalid_state", "当前活跃的题目实例数已达到上限")

    async def close_challenge(self, code):
        return True


@pytest.mark.asyncio
async def test_attempt_not_consumed_on_409_requeue(tmp_path):
    """409 轮转只重排不计数：此前派发时自增，被弹两次的题首次真实运行就带
    attempt≥2（白拉 hint 扣 10%、错换 pro、45min 窗口错降 15min 快验）。"""
    cfg = Config()
    api = _Start409Api()
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    ch = (await api.list_challenges())[0]
    for _ in range(3):                       # 连续三次 409 弹回
        await sched._run_one(ch)
    assert sched._attempts == {}, f"409 轮转不应消耗 attempt，实际 {sched._attempts}"
    assert sched.pending and sched.pending[-1].unique_code == "att-1"


@pytest.mark.asyncio
async def test_attempt_increments_only_after_container_ready(tmp_path, monkeypatch):
    """容器就绪后自增且只自增一次；cancel（停滞抢占）路径同样结算进 retry。"""
    from agent import scheduler as sched_mod
    from agent.worker import WorkerResult

    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    cfg = Config()
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    ch = (await api.list_challenges())[0]

    class _StubWorker:
        def __init__(self, *a, **kw):
            self.result = WorkerResult()
            self.started = time.monotonic()

            class _S:
                correct = set()
                score = 0
                completed = False
            self.submitter = _S()

        async def run(self):
            await asyncio.sleep(3600)
            return self.result

    async def fake_start_flow(ch):
        return ["127.0.0.1:31337"], False

    monkeypatch.setattr(sched_mod, "Worker", _StubWorker)
    monkeypatch.setattr(sched, "_start_flow", fake_start_flow)
    t = asyncio.create_task(sched._run_one(ch))
    await asyncio.sleep(0.3)
    assert sched._attempts == {ch.unique_code: 1}, "就绪后自增恰好一次"
    t.cancel()
    await t                                     # 吞掉取消：正常结束不抛
    assert not t.cancelled()
    assert [c.unique_code for c in sched.retry_queue] == [ch.unique_code], \
        "抢占取消要落断点进 retry，题不能丢"
    assert srv.state[ch.unique_code]["container_status"] == "stopped", \
        "取消路径必须 close，防平台槽位泄漏"
    await api.close()
    srv.shutdown()


# ---- P0-1：空槽回查（pending/retry 双空 + 任务在跑） ----

@pytest.mark.asyncio
async def test_idle_slot_platform_recheck_while_task_running(tmp_path, monkeypatch):
    """其余题 no_progress（不进 retry）+ 长任务占槽：空槽靠平台回查立即补位，
    不等长任务自然结束（旧逻辑回查只在无任务时触发，空槽空转整个窗口）。"""
    from agent.worker import WorkerResult

    srv = make_server()
    srv.state = {
        "mock_slow_01": _extra_challenge("mock_slow_01", "flag{mock_slow_01}"),
        "mock_re_01": _extra_challenge("mock_re_01", "flag{mock_re_01}"),
    }
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    cfg = Config()
    cfg.stagnate_boost_min = 0      # 关掉掉速检测，只验证空槽回查路径
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))

    marks = {"slow_1st_end": None, "re_2nd_start": None}
    calls = {"slow": 0, "re": 0}

    async def fake_run_one(ch, budget_cap_min=0.0):
        if ch.unique_code == "mock_slow_01":
            calls["slow"] += 1
            if calls["slow"] == 1:
                await asyncio.sleep(2.5)            # 长任务占住槽位
                marks["slow_1st_end"] = time.monotonic()
                done = False                        # 首轮 no_progress：不进 retry
            else:
                done = True
        else:
            calls["re"] += 1
            if calls["re"] == 1:
                done = False                        # 首轮 no_progress
            else:
                marks["re_2nd_start"] = time.monotonic()
                done = True
        r = WorkerResult()
        r.completed = done
        r.reason = "all flags captured" if done else "no_progress: attempt 0 无 flag 无断点"
        if done:
            await sched.api.submit_flag(ch.unique_code, "flag{mock_slow_01}"
                                        if ch.unique_code == "mock_slow_01" else "flag{mock_re_01}")
            r.score = ch.total_score
        await sched._finish(ch, r)

    monkeypatch.setattr(sched, "_run_one", fake_run_one)
    await sched.run()
    try:
        assert calls == {"slow": 2, "re": 2}, calls
        assert marks["re_2nd_start"] is not None and marks["slow_1st_end"] is not None
        assert marks["re_2nd_start"] < marks["slow_1st_end"], (
            "re 的第 2 次 attempt 应在 slow 首轮运行期间由空槽回查拉起，"
            f"实际 re_2nd={marks['re_2nd_start']:.2f} slow_1st_end={marks['slow_1st_end']:.2f}")
    finally:
        await api.close()
        srv.shutdown()


# ---- P0-3：endgame 快赢耗尽后放行最优候选（预算封顶） ----

@pytest.mark.asyncio
async def test_endgame_tail_relax_dispatches_capped(tmp_path, monkeypatch):
    """尾段快赢先走原预算；全被门拦时不空槽——放行最优候选，预算封顶
    min(15, 剩余名义窗口)，快赢题（剩一面）cap=0。"""
    from agent.worker import WorkerResult

    srv = make_server()
    srv.state = {
        "mock_quick_01": {
            "unique_code": "mock_quick_01", "description": "剩一面快赢",
            "difficulty": "easy", "level": 1, "total_score": 400,
            "flag_count": 2, "correct_flag_count": 1, "is_completed": False,
            "container_status": "stopped", "container_addr": [],
            "_flags": ["flag{q1}", "flag{q2}"],
        },
        "mock_big_01": {
            "unique_code": "mock_big_01", "description": "被门拦的大题",
            "difficulty": "hard", "level": 1, "total_score": 1800,
            "flag_count": 3, "correct_flag_count": 0, "is_completed": False,
            "container_status": "stopped", "container_addr": [],
            "_flags": ["flag{b1}", "flag{b2}", "flag{b3}"],
        },
    }
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    cfg = Config()
    cfg.stagnate_boost_min = 0
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    sched._t0 = time.monotonic() - 300 * 60     # 345min 窗口已过 300min：进 endgame

    order: list[str] = []
    caps: dict[str, float] = {}

    async def fake_run_one(ch, budget_cap_min=0.0):
        order.append(ch.unique_code)
        caps[ch.unique_code] = budget_cap_min
        for fl in srv.state[ch.unique_code]["_flags"]:
            await sched.api.submit_flag(ch.unique_code, fl)
        r = WorkerResult()
        r.completed = True
        r.score = ch.total_score
        r.reason = "all flags captured"
        await sched._finish(ch, r)

    monkeypatch.setattr(sched, "_run_one", fake_run_one)
    await sched.run()
    try:
        assert order[0] == "mock_quick_01", "快赢题仍优先放行"
        assert set(order) == {"mock_quick_01", "mock_big_01"}, order
        assert caps["mock_quick_01"] == 0.0, "快赢题不封顶"
        assert caps["mock_big_01"] == 15.0, f"尾段兜底放行应封顶 15min，实际 {caps['mock_big_01']}"
    finally:
        await api.close()
        srv.shutdown()


# ---- P0-4：冷却唤醒只看 pending 内的到期戳 ----

def test_next_backoff_wakeup_filters_stale_entries():
    sch = Scheduler.__new__(Scheduler)
    sch.pending = [Challenge.from_dict({"unique_code": "p-1", "flag_count": 1})]
    now = time.monotonic()
    sch._start_backoff = {"p-1": now + 5, "finished-9": now + 120}  # 后者为陈旧条目
    assert sch._next_backoff_wakeup(now) == now + 5


# ---- P1-5：events.jsonl 跨轮合并 ----

def _write_events(d, rows):
    import os
    d.mkdir(parents=True, exist_ok=True)
    with open(d / "events.jsonl", "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def test_load_cross_run_events_merges_siblings(tmp_path):
    runs = tmp_path / "runs"
    _write_events(runs / "20260827-010101", [
        {"challenge": "x-01", "completed": True, "elapsed_min": 3.0},
        {"challenge": "y-01", "completed": False},
        {"challenge": "y-01", "completed": False},
    ])
    _write_events(runs / "20260828-020202", [
        {"challenge": "y-01", "completed": True, "elapsed_min": 5.0},
    ])
    stats = _load_cross_run_events(str(runs / "20260828-020202"))
    assert stats["x-01"]["attempts"] == 1 and stats["x-01"]["solve_prob"] == 1.0
    assert stats["y-01"]["attempts"] == 3 and abs(stats["y-01"]["solve_prob"] - 1 / 3) < 1e-9
    # 单轮版仍只读自身
    single = _load_events(str(runs / "20260828-020202"))
    assert single["y-01"]["attempts"] == 1


def test_load_cross_run_events_skips_custom_run_dir(tmp_path):
    """非时间戳命名的 run_dir（测试 tmp/RUN_DIR 自定义）按字面单轮处理。"""
    d = tmp_path / "custom-run"
    _write_events(d, [{"challenge": "z-01", "completed": True, "elapsed_min": 2.0}])
    sibling = tmp_path / "20260828-030303"
    _write_events(sibling, [{"challenge": "z-01", "completed": False}])
    stats = _load_cross_run_events(str(d))
    assert stats["z-01"]["attempts"] == 1 and stats["z-01"]["solve_prob"] == 1.0


# ---- P1-6：停滞抢占 ----

class _PreemptWorker:
    """最小 Worker 替身：submitter/_state_counts 供调度器采样。"""

    def __init__(self, flags=0, facts=0, completed=False):
        class _S:
            correct = {f"flag{{i{i}}}" for i in range(flags)}
            score = 0
        _S.completed = completed
        self.submitter = _S()
        self._facts = facts

    def _state_counts(self):
        return self._facts, 0


@pytest.mark.asyncio
async def test_stagnate_preempt_cancels_flat_attempt(tmp_path):
    """全局停滞 + 零 flag 零新 FACTS 持续 ≥2×boost 窗口 → cancel 轮转；
    有新事实的窗口不动；10min 频率上限内不连环抢。"""
    from tests.test_scheduler_e2e import _FakeApi, _ch

    cfg = Config()
    cfg.stagnate_boost_min = 12            # 抢占阈值 24min
    api = _FakeApi([_ch("flat-1", 1, 300), _ch("prog-1", 1, 300)])
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    sched._last_total_flags = 0            # 防 0>-1 被记为「有增长」

    flat_task = asyncio.create_task(asyncio.sleep(60))
    prog_task = asyncio.create_task(asyncio.sleep(60))
    sched.running = {"flat-1": flat_task, "prog-1": prog_task}
    sched.active_workers = {
        "flat-1": [_PreemptWorker(flags=0, facts=1)],   # 1 条 FACTS 但不再新增
        "prog-1": [_PreemptWorker(flags=1, facts=4)],
    }
    now = time.monotonic()
    sched._stagnate_sample = {
        "flat-1": (now - 25 * 60, 0, 1),   # 25min 无变化 ≥ 24min 阈值
        "prog-1": (now, 1, 4),             # 刚有新 flag/FACTS
    }
    sched._last_progress_ts = now - 30 * 60

    await sched._stagnate_check()
    await asyncio.sleep(0)                 # 让 cancel 送达
    assert flat_task.cancelled(), "零产出的在跑窗口应被抢占轮转"
    assert not prog_task.cancelled(), "有新事实的窗口不误杀"

    # 频率上限：10min 内重建的 flat 窗口不再被抢
    flat_task2 = asyncio.create_task(asyncio.sleep(60))
    sched.running["flat-1"] = flat_task2
    sched._stagnate_sample["flat-1"] = (time.monotonic() - 30 * 60, 0, 1)
    await sched._stagnate_check()
    await asyncio.sleep(0)
    assert not flat_task2.cancelled()
    flat_task2.cancel()
    prog_task.cancel()


# ---- P1-7：close 单次短超时 ----

class _CountingClient:
    def __init__(self, exc):
        self.calls = 0
        self._exc = exc

    async def request(self, method, path, **kw):
        self.calls += 1
        raise self._exc


@pytest.mark.asyncio
async def test_close_challenge_single_attempt():
    """close 是 fire-and-forget：单次 10s 不进 4×30s 重试链（防题目槽被占 ~4min）。"""
    c = TsecClient("http://127.0.0.1:1", "t")
    fake = _CountingClient(httpx.TimeoutException("boom"))
    c._client = fake
    with pytest.raises(ApiError):
        await c.close_challenge("x")
    assert fake.calls == 1
