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
    assert "shadow1ng/fscan" in dk
    pb = open("agent/prompts.py").read()
    assert "fscan -h" in pb
    wk = open("agent/worker.py").read()
    assert wk.count("fscan") >= 2
