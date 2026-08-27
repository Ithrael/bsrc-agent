import json
import re
import time

import pytest

from agent.config import Config
from agent.scheduler import Scheduler
from agent.tsec_api import TsecClient
from tests.mock_server import TOKEN, make_server


class FakeLLM:
    """无状态：从 system prompt 抓题目代码，echo 该题全部 mock flag（真实 LLMClient 也是无状态的）。"""

    FLAGS = {
        "mock_web_01": ["flag{mock_flag_01}"],
        "mock_bin_01": ["flag{mock_flag_2a}", "flag{mock_flag_2b}"],
        "mock_web_02": ["flag{mock_flag_02}"],
        "mock_web_03": ["flag{mock_flag_03}"],
        "mock_pair_01": ["flag{p_line_01}", "flag{p_line_02}", "flag{p_line_03}"],
    }

    def __init__(self):
        self.n = 0

    async def chat(self, messages, tools=None):
        self.n += 1
        has_tool_result = any(m.get("role") == "tool" for m in messages)
        if not has_tool_result:
            # 模拟侦察输出中直接出现本题全部 mock flag（自动捕获路径）
            code = "mock_web_01"
            for m in messages:
                if m.get("role") == "system":
                    mm = re.search(r"题目代码：(\S+)", m.get("content") or "")
                    if mm:
                        code = mm.group(1)
                    break
            flags = " 以及 ".join(self.FLAGS.get(code, []))
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "shell", "arguments": json.dumps(
                    {"command": f"echo '找到 {flags}'"})},
            }]}
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c2", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "ok"})},
        }]}

    def stats(self):
        return f"fake calls={self.n}"


@pytest.mark.asyncio
async def test_scheduler_end_to_end(tmp_path):
    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    cfg = Config()
    cfg.max_concurrent = 3
    cfg.recon_boot = False  # mock 目标在 127.0.0.1 随机端口，预侦察无意义且拖慢测试
    cfg.record_solutions = False  # 不把 mock 题写进真实 solutions.json
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    sched.deadline = time.monotonic() + 300
    done = await sched.run()
    assert len(done) == 2
    assert all(v["completed"] for v in done.values())
    assert sum(v["score"] for v in done.values()) == 600
    await api.close()
    srv.shutdown()


def _extra_challenge(code: str, flag: str, score: int = 100) -> dict:
    return {
        "unique_code": code,
        "description": f"mock：并发测试题 {code}",
        "difficulty": "easy",
        "level": 1,
        "total_score": score,
        "flag_count": 1,
        "correct_flag_count": 0,
        "is_completed": False,
        "container_status": "stopped",
        "container_addr": [],
        "_flags": [flag],
    }


@pytest.mark.asyncio
async def test_fixed_concurrency_no_convergence(tmp_path):
    """并发写死：409 不降级（run 10048 复盘 effective_max 收敛致后半程单线程）。

    409 时题轮转队尾 + 冷却重试；所有题最终都跑完（无一判死）；
    start 调用次数有界（冷却机制防空转）。
    """
    srv = make_server(instance_limit=2)
    srv.state.update({
        "mock_web_02": _extra_challenge("mock_web_02", "flag{mock_flag_02}"),
        "mock_web_03": _extra_challenge("mock_web_03", "flag{mock_flag_03}"),
    })
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    cfg = Config()
    cfg.max_concurrent = 3
    cfg.recon_boot = False
    cfg.record_solutions = False
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    sched.deadline = time.monotonic() + 300
    sched.start_backoff_s = 1  # 缩短 409 冷却，加速测试
    done = await sched.run()
    try:
        assert sched.effective_max == 3, f"并发写死不降级，实际 {sched.effective_max}"
        assert len(done) == 4, done
        assert all(v["completed"] for v in done.values()), done
        assert srv.start_calls < 30, f"start 调用应有界，实际 {srv.start_calls}"
    finally:
        await api.close()
        srv.shutdown()


@pytest.mark.asyncio
async def test_paired_workers(tmp_path):
    """大题双 worker：1000 分 3-flag 题触发配对，1 个容器 2 条线，共享 flag 进度。"""
    srv = make_server()
    srv.state.update({
        "mock_pair_01": {
            "unique_code": "mock_pair_01",
            "description": "mock：三 flag 大题（触发双 worker）",
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
    cfg = Config()
    cfg.max_concurrent = 3
    cfg.pair_workers = True
    cfg.recon_boot = False
    cfg.record_solutions = False
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    sched.deadline = time.monotonic() + 300
    done = await sched.run()
    try:
        assert len(done) == 3, done
        assert all(v["completed"] for v in done.values()), done
        pair = done["mock_pair_01"]
        assert pair["score"] == 1200, pair
        # 双 worker 只占 1 个容器槽：start 恰好 3 次（每题一次）
        assert srv.start_calls == 3, f"start 调用应为 3，实际 {srv.start_calls}"
        ws = tmp_path / "mock_pair_01"
        assert (ws / "worker-A" / "transcript.jsonl").exists()
        assert (ws / "worker-B" / "transcript.jsonl").exists()
        assert (ws / "NOTES.md").exists()  # 共享笔记
        merged = json.loads((ws / "RESULT.json").read_text())
        assert merged["paired"] and merged["score"] == 1200
    finally:
        await api.close()
        srv.shutdown()


@pytest.mark.asyncio
async def test_no_pair_when_solution_exists(tmp_path):
    """解法库有 completed 解法的题不配对（直接复现更快）。"""
    srv = make_server()
    srv.state.update({
        "mock_pair_01": {
            "unique_code": "mock_pair_01",
            "description": "mock：三 flag 大题",
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
    cfg = Config()
    cfg.max_concurrent = 3
    cfg.pair_workers = True
    cfg.recon_boot = False
    cfg.record_solutions = False
    # 直接往 scheduler 的解法库视图里塞 completed 记录（不污染真实 solutions.json）
    from agent import scheduler as sched_mod
    sched_mod._LIB["mock_pair_01"] = {"completed": True, "steps": ["echo x"]}
    try:
        sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
        sched.deadline = time.monotonic() + 300
        done = await sched.run()
        try:
            assert all(v["completed"] for v in done.values()), done
            ws = tmp_path / "mock_pair_01"
            assert not (ws / "worker-B").exists(), "有 completed 解法不应配对"
        finally:
            await api.close()
            srv.shutdown()
    finally:
        sched_mod._LIB.pop("mock_pair_01", None)


class _FakeApi:
    """只实现 list_challenges 的假平台：correct_flag_count 由测试直接控制。"""

    def __init__(self, challenges: list[dict]):
        self.challenges = challenges

    async def list_challenges(self):
        from agent.tsec_api import Challenge
        return [Challenge.from_dict(c) for c in self.challenges]


def _ch(code: str, flag_count: int, score: int, correct: int = 0) -> dict:
    return {
        "unique_code": code, "description": "mock", "difficulty": "hard",
        "level": 1, "total_score": score, "flag_count": flag_count,
        "correct_flag_count": correct, "is_completed": False,
        "container_status": "stopped", "container_addr": [],
    }


@pytest.mark.asyncio
async def test_stagnate_check_boost_and_cooldown(tmp_path):
    """掉速检测：有增长不触发；无进展超阈值插队多 flag 题；20min 冷却防重复。"""
    cfg = Config()
    cfg.stagnate_boost_min = 30
    api = _FakeApi([_ch("b_02", 6, 1800), _ch("a_05", 1, 300)])
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    challenges = await api.list_challenges()
    sched.pending = [c for c in challenges if c.unique_code == "a_05"]
    sched.retry_queue = [c for c in challenges if c.unique_code == "b_02"]

    # 场景 1：平台有新 flag 增长 → 刷新进度时间戳，不插队
    api.challenges[1]["correct_flag_count"] = 1  # a_05 涨一面
    sched._last_progress_ts = time.monotonic() - 31 * 60
    await sched._stagnate_check()
    assert sched.pending[0].unique_code == "a_05", "有增长不应插队"
    assert time.monotonic() - sched._last_progress_ts < 5, "增长应刷新进度时间戳"

    # 场景 2：31 分钟无进展 → b_02（6 面 1800 分）插到队头，retry 清空
    sched._last_progress_ts = time.monotonic() - 31 * 60
    await sched._stagnate_check()
    assert sched.pending[0].unique_code == "b_02"
    assert sched.pending[0].flag_count == 6
    assert sched.retry_queue == []

    # 场景 3：冷却期内再查不重复插队（b_02 已在队头，冷却 return 不动队列）
    sched._last_progress_ts = time.monotonic() - 31 * 60
    sched.retry_queue = [c for c in challenges if c.unique_code == "b_02"]
    await sched._stagnate_check()
    assert sched.pending[0].unique_code == "b_02"
    assert len(sched.pending) == 2  # b_02 队头 + a_05 原题
    assert len(sched.retry_queue) == 1  # 冷却 return，重新塞的 b_02 未被处理


@pytest.mark.asyncio
async def test_stagnate_check_disabled(tmp_path):
    """STAGNATE_BOOST_MIN=0 时掉速检测关闭：不插队。"""
    cfg = Config()
    cfg.stagnate_boost_min = 0
    api = _FakeApi([_ch("b_02", 6, 1800)])
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    challenges = await api.list_challenges()
    sched.pending = []
    sched.retry_queue = list(challenges)
    sched._last_progress_ts = time.monotonic() - 31 * 60
    await sched._stagnate_check()
    assert sched.pending == []
    assert len(sched.retry_queue) == 1


# ---- endgame 收尾纪律（12464 复盘：尾段不开新硬题，只打快赢） ----

def _sched_for_endgame(global_budget_min=345, endgame_min=45, elapsed_min=0):
    import time as _t
    from agent.scheduler import Scheduler
    sch = Scheduler.__new__(Scheduler)
    sch.cfg = Config()
    sch.cfg.global_budget_min = global_budget_min
    sch.cfg.endgame_min = endgame_min
    sch._t0 = _t.monotonic() - elapsed_min * 60
    sch._endgame_logged = False
    return sch


def test_in_endgame_threshold():
    """345min 窗口、45min 收尾：299min 未进入，300min（=345-45）进入。"""
    assert not _sched_for_endgame(elapsed_min=299)._in_endgame()
    assert _sched_for_endgame(elapsed_min=300)._in_endgame()


def test_endgame_ok_quick_wins_only():
    """快赢=只剩一面或有完整解法；新多 flag 硬题不放行。"""
    from agent.tsec_api import Challenge
    sch = _sched_for_endgame()
    one_left = Challenge.from_dict({"unique_code": "x-1", "flag_count": 4,
                                    "correct_flag_count": 3, "difficulty": "hard"})
    assert sch._endgame_ok(one_left)                      # 剩一面
    fresh_big = Challenge.from_dict({"unique_code": "x-2", "flag_count": 6,
                                     "correct_flag_count": 0, "difficulty": "hard"})
    assert not sch._endgame_ok(fresh_big)                 # 新 6 flag 硬题
    import agent.scheduler as sm
    orig = sm._LIB
    try:
        sm._LIB = {"x-2": {"completed": True}}
        assert sch._endgame_ok(fresh_big)                 # 有完整解法可复现
    finally:
        sm._LIB = orig


def test_fscan_wired_in_image_and_playbook():
    """fscan 进镜像 + playbook 阶段门/多 flag 清单接入（通用工具，无题目先验）。"""
    dk = open("Dockerfile").read()
    assert "COPY tools/bin/fscan /usr/local/bin/fscan" in dk
    pb = open("agent/prompts.py").read()
    assert "fscan -h" in pb
    wk = open("agent/worker.py").read()
    assert wk.count("fscan") >= 2


# ---- 闭环修复回归（2026-08-26）：钉子题判死 / 回查兜底 / endgame retry 晋升 ----

@pytest.mark.asyncio
async def test_nail_dead_and_false_kill(tmp_path, monkeypatch):
    """钉子题判死入 _dead 且不进 retry；平台已有部分 flag 的题不误杀（进 retry）。"""
    from agent.worker import WorkerResult
    import agent.scheduler as sched_mod

    srv = make_server()
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    notes_p = tmp_path / "notes.json"
    notes_p.write_text(json.dumps({"mock_web_01": "[官方 hint] 试 SQL 注入",
                                   "mock_bin_01": "[官方 hint] 看协议"}))
    monkeypatch.setattr(sched_mod, "notes_lib_path", lambda: str(notes_p))
    cfg = Config()
    cfg.record_solutions = False
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    challenges = {c.unique_code: c for c in await api.list_challenges()}

    def _zero_result():
        r = WorkerResult()
        r.completed = False
        r.score = 0
        r.flags = []
        r.reason = "claude done"
        r.elapsed_min = 5.0
        return r

    # 场景 1：hint 已看 + 第 3 次调度 + 平台 0 flag → 判死，不进 retry
    sched._attempts["mock_web_01"] = 2
    await sched._finish(challenges["mock_web_01"], _zero_result())
    assert "mock_web_01" in sched._dead
    assert sched.retry_queue == []

    # 场景 2：平台已有 1/2 flag（本轮没新增）→ 不误杀，进 retry 续跑
    srv.state["mock_bin_01"]["correct_flag_count"] = 1
    fresh = {c.unique_code: c for c in await api.list_challenges()}
    sched._attempts["mock_bin_01"] = 2
    await sched._finish(fresh["mock_bin_01"], _zero_result())
    assert "mock_bin_01" not in sched._dead
    assert [c.unique_code for c in sched.retry_queue] == ["mock_bin_01"]
    await api.close()
    srv.shutdown()


@pytest.mark.asyncio
async def test_platform_recheck_dead_last_resort(tmp_path):
    """回查过滤钉子题；只剩钉子题时兜底回挖（其他题全解了就试试死题）。"""
    cfg = Config()
    api = _FakeApi([_ch("dead-1", 1, 500), _ch("alive-1", 1, 300)])
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))
    sched._dead.add("dead-1")
    assert await sched._platform_recheck()
    assert [c.unique_code for c in sched.pending] == ["alive-1"]      # 钉子题被滤掉
    # alive-1 也解完 → 只剩钉子题，兜底回挖
    api.challenges[1]["is_completed"] = True
    assert await sched._platform_recheck()
    assert [c.unique_code for c in sched.pending] == ["dead-1"]
    # 全部解开 → 退出信号
    api.challenges[0]["is_completed"] = True
    assert not await sched._platform_recheck()


def test_endgame_promotes_retry_over_blocked_pending(tmp_path):
    """收尾段 retry 快赢不被 pending 里的拦截题饿死（尾段全系统空转修复）。"""
    from agent.tsec_api import Challenge
    blocked = Challenge.from_dict({"unique_code": "big-1", "flag_count": 6,
                                   "correct_flag_count": 0, "difficulty": "hard"})
    quick = Challenge.from_dict({"unique_code": "one-1", "flag_count": 4,
                                 "correct_flag_count": 3, "difficulty": "hard"})
    sch = _sched_for_endgame(elapsed_min=300)   # 进入 endgame
    sch.pending = [blocked]
    sch.retry_queue = [quick]
    sch._promote_retry_in_endgame()
    assert sch.pending[0].unique_code == "one-1"      # 快赢排到拦截题前面
    assert sch.retry_queue == []
    # 非 endgame 不动（retry 等 pending 清空的既有语义保留）
    sch2 = _sched_for_endgame(elapsed_min=100)
    sch2.pending = [blocked]
    sch2.retry_queue = [quick]
    sch2._promote_retry_in_endgame()
    assert sch2.pending == [blocked] and sch2.retry_queue == [quick]


def test_claude_health_tracks_harness_path():
    """静态 harness 路径崩溃同样计入健康度 streak，达阈值降级。"""
    from agent.worker import WorkerResult
    sch = Scheduler.__new__(Scheduler)
    sch.cfg = Config()
    sch.cfg.claude_worker = False
    sch.cfg.harness_enabled = True
    sch._claude_fail_streak = 0
    r = WorkerResult()
    r.reason = "harness crash"
    for _ in range(6):
        sch._track_claude_health(r)
    assert not sch.cfg.harness_enabled          # 连续崩溃触发全局降级
    assert not sch.cfg.claude_worker


# ---- 槽位空转修复（13174 实测：pending 空 + 任务在跑时 retry 永不拉起） ----

@pytest.mark.asyncio
async def test_pull_retry_into_pending_filters_completed(tmp_path):
    """retry 并入：平台快照过滤已完成题、按优先级排序、清空 retry 队列。"""
    from agent.scheduler import Scheduler
    from agent.tsec_api import Challenge

    ch_a = Challenge.from_dict({"unique_code": "rr-1", "flag_count": 1,
                                "total_score": 500, "difficulty": "easy"})
    ch_b = Challenge.from_dict({"unique_code": "rr-2", "flag_count": 1,
                                "total_score": 100, "difficulty": "easy"})

    class FakeApi:
        async def list_challenges(self):
            done = Challenge.from_dict({"unique_code": "rr-2", "flag_count": 1,
                                        "correct_flag_count": 1, "total_score": 100,
                                        "difficulty": "easy", "is_completed": True})
            alive = Challenge.from_dict({"unique_code": "rr-1", "flag_count": 1,
                                         "correct_flag_count": 0, "total_score": 500,
                                         "difficulty": "easy", "is_completed": False})
            return [done, alive]

    sch = Scheduler.__new__(Scheduler)
    sch.cfg = Config()
    sch.cfg.round_num = 2
    sch.run_dir = str(tmp_path)
    sch.api = FakeApi()
    sch._events = {}
    sch.pending = []
    sch.retry_queue = [ch_a, ch_b]
    assert await sch._pull_retry_into_pending() is True
    assert [c.unique_code for c in sch.pending] == ["rr-1"]   # rr-2 平台已完成被滤掉
    assert sch.retry_queue == []
    # retry 空：直接返回 False 不发请求
    assert await sch._pull_retry_into_pending() is False


@pytest.mark.asyncio
async def test_no_idle_slots_retry_dispatched_while_task_running(tmp_path, monkeypatch):
    """槽位空转修复核心场景：pending 空 + 长任务占着槽位时，retry 队列立即补空槽——
    fail 题的第 2 次 attempt 必须发生在 slow 题结束之前（旧逻辑要等全部任务
    结束才拉 retry，空槽空转 8s 到 slow 跑完）。"""
    import asyncio

    from agent.worker import WorkerResult

    srv = make_server()
    # 只留 slow + fail 两题（默认 mock_web_01/bin 平台侧永不完成会死循环）
    srv.state = {
        "mock_slow_01": _extra_challenge("mock_slow_01", "flag{mock_slow_01}"),
        "mock_fail_01": _extra_challenge("mock_fail_01", "flag{mock_fail_01}"),
    }
    host, port = srv.server_address
    api = TsecClient(f"http://{host}:{port}", TOKEN)
    cfg = Config()
    cfg.max_concurrent = 3
    cfg.recon_boot = False
    cfg.record_solutions = False
    cfg.stagnate_boost_min = 0   # 关掉掉速插队：只验证空槽补位路径本身
    sched = Scheduler(cfg, FakeLLM(), api, str(tmp_path))

    calls = {"slow": 0, "fail": []}
    slow_ended: list[float] = []

    async def fake_run_one(ch, attempt=0):
        if ch.unique_code == "mock_slow_01":
            calls["slow"] += 1
            await asyncio.sleep(8)          # 长任务占住 1 个槽位
            slow_ended.append(time.monotonic())
            done_slow = calls["slow"] >= 2  # 第 2 次 attempt 才算完成
        elif ch.unique_code == "mock_fail_01":
            calls["fail"].append(time.monotonic())
            done_slow = False
        else:
            done_slow = True                # 其他 mock 题立即完成
        flag = {"mock_slow_01": "flag{mock_slow_01}",
                "mock_fail_01": "flag{mock_fail_01}"}.get(ch.unique_code, "")
        if ch.unique_code == "mock_fail_01":
            r = WorkerResult()
            r.completed = len(calls["fail"]) >= 3   # 第 3 次 attempt 才算完成
        else:
            r = WorkerResult()
            r.completed = done_slow
        if r.completed:
            if flag:
                await sched.api.submit_flag(ch.unique_code, flag)  # 平台侧入账（终局退出条件）
            r.score = ch.total_score
            r.flags = [flag] if flag else []
            r.reason = "all flags captured"
        else:
            r.reason = "claude done"
        await sched._finish(ch, r)

    monkeypatch.setattr(sched, "_run_one", fake_run_one)
    done = await sched.run()
    try:
        assert calls["slow"] == 2, f"slow 首轮失败 + retry 完成，实际 {calls['slow']}"
        assert len(calls["fail"]) == 3, f"fail 3 次 attempt 后完成，实际 {calls['fail']}"
        # 核心断言：fail 的第 2 次 attempt（空槽补位）发生在 slow 结束之前
        assert calls["fail"][1] < slow_ended[0], (
            f"空槽应在 slow 运行期间被 retry 补位：fail_att2={calls['fail'][1]:.1f} "
            f"slow_end={slow_ended[0]:.1f}（旧逻辑空转 8s）")
        assert done["mock_slow_01"]["completed"]
        assert done["mock_fail_01"]["completed"]
    finally:
        await api.close()
        srv.shutdown()
