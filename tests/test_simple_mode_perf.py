"""极简模式提速优化的测试。

- 优化 2：共享启动侦察（后台 recon → [自动-侦察] fact；复现题/已有侦察跳过）
- 优化 3：同轮多 tool_calls 并行执行（不同 shell 会话并行，同 session 串行）
- 优化 4：无进展 attempt 跳过（无新 flag 无新线索 → 本波不再重排）
- 优化 5：复现题优先派发 + 复现题不走 claude
- 优化 6：free 策略下 flash 退化的 hard/多 flag 题 attempt 0 主动拉 hint
- 优化 7：收尾段快赢排序（剩 1 面 > 低难度 > 高分）
- 优化 8：attempt≥1 方向 step 数减半
"""

import asyncio
import json
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
        self.hint_calls = 0
        self.submitted: list[str] = []

    async def list_challenges(self):
        self.list_calls += 1
        return self.challenges

    async def start_challenge(self, code):
        self.start_calls += 1
        return ["10.0.0.1:80"]

    async def submit_flag(self, code, flag):
        self.submitted.append(flag)
        return {"correct": True, "awarded": 100, "cumulative_score": 100,
                "correct_flag_count": len(self.submitted), "total_flag_count": 1}

    async def get_hint(self, code):
        self.hint_calls += 1
        return "官方提示"

    async def close_challenge(self, code):
        return True


class FinishLLM:
    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        if tools is None:
            return {"role": "assistant", "content": "- 方向A"}
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c1", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
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


def _patch_lib(monkeypatch, tmp_path, lib: dict):
    p = tmp_path / "solutions.json"
    p.write_text(json.dumps(lib, ensure_ascii=False))
    monkeypatch.setattr(simple_mod, "solution_lib_path", lambda: str(p))
    return p


# ---- 优化 2：共享启动侦察 ----

@pytest.mark.asyncio
async def test_bg_recon_appends_fact(tmp_path, monkeypatch):
    calls = []

    async def fake_recon(addrs, ws, budget_s=75):
        calls.append((addrs, ws))
        return "开放端口: 80(http), 8080(http)\n组件: ComfyUI 0.2"

    monkeypatch.setattr(simple_mod, "recon_targets", fake_recon)
    sched = _mk_sched(FakeApi(), tmp_path)
    sched.cfg.recon_boot = True
    await sched._solve_one(_mk_ch(), 0)
    await asyncio.gather(*list(sched._bg_tasks)) if sched._bg_tasks else None
    assert calls, "recon 应被调用"
    assert any(f.startswith("[自动-侦察]") and "ComfyUI" in f
               for f in sched._snapshot("a-01"))


@pytest.mark.asyncio
async def test_bg_recon_report_dropped_if_container_closed(tmp_path, monkeypatch):
    """快解场景：attempt 在侦察完成前结束并 close 容器——对已关容器扫出的
    「无开放端口」废报告不得落 fact（会毒化后续 attempt 的「别重新探测」）。"""

    async def slow_recon(addrs, ws, budget_s=75):
        await asyncio.sleep(0.3)     # 慢于整个 attempt
        return "无开放端口（容器已关时的废报告）"

    monkeypatch.setattr(simple_mod, "recon_targets", slow_recon)
    sched = _mk_sched(FakeApi(), tmp_path)
    sched.cfg.recon_boot = True
    await sched._solve_one(_mk_ch(), 0)
    await asyncio.gather(*list(sched._bg_tasks)) if sched._bg_tasks else None
    assert not any(f.startswith("[自动-侦察]") for f in sched._snapshot("a-01"))


@pytest.mark.asyncio
async def test_bg_recon_skipped_for_reproduce_and_cached(tmp_path, monkeypatch):
    calls = []

    async def fake_recon(addrs, ws, budget_s=75):
        calls.append(addrs)
        return "报告"

    monkeypatch.setattr(simple_mod, "recon_targets", fake_recon)
    sched = _mk_sched(FakeApi(), tmp_path)
    sched.cfg.recon_boot = True
    # 复现题（有完整解法）跳过
    _patch_lib(monkeypatch, tmp_path,
               {"a-01": {"completed": True, "note": "curl /flag"}})
    await sched._solve_one(_mk_ch(), 0)
    await asyncio.gather(*list(sched._bg_tasks)) if sched._bg_tasks else None
    assert calls == []
    # 已有侦察 fact 的题（attempt 1 复用）不重跑
    monkeypatch.setattr(simple_mod, "solution_lib_path", lambda: "/nonexistent.json")
    await sched._append_fact("a-01", "[自动-侦察] 上一轮报告")
    await sched._solve_one(_mk_ch(), 1)
    await asyncio.gather(*list(sched._bg_tasks)) if sched._bg_tasks else None
    assert calls == []


# ---- 优化 3：多 tool_calls 并行 ----

class TwoShellThenFinishLLM:
    """第 1 轮并行发 2 条不同 session 的 sleep 命令；第 2 轮 finish。"""

    def __init__(self):
        self.round = 0

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        if tools is None:
            return {"role": "assistant", "content": "- 方向A"}
        self.round += 1
        if self.round == 1:
            return {"role": "assistant", "content": "", "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "shell", "arguments": json.dumps(
                    {"command": "sleep 0.6; echo A", "session": "sa"})}},
                {"id": "c2", "type": "function", "function": {"name": "shell", "arguments": json.dumps(
                    {"command": "sleep 0.6; echo B", "session": "sb"})}},
            ]}
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c3", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
        }]}


@pytest.mark.asyncio
async def test_parallel_tool_calls_faster_than_serial(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path, llm=TwoShellThenFinishLLM(),
                      simple_steps_per_round=1)
    t0 = time.monotonic()
    await sched._run_step(_mk_ch(), ["10.0.0.1:80"], sched._new_submitter(_mk_ch()),
                          "方向A", 0, 60.0, lambda: "", "")
    elapsed = time.monotonic() - t0
    # 串行 ≥1.2s（两条 0.6s sleep），并行 ≈0.6-0.7s；阈值 1.0s 留足余量
    assert elapsed < 1.0, f"两条 shell 应并行执行，实际耗时 {elapsed:.2f}s"


# ---- 优化 4：无进展 attempt 跳过 ----

@pytest.mark.asyncio
async def test_no_progress_attempt_skipped_in_wave(tmp_path, monkeypatch):
    # FinishLLM 永不提交：attempt 0 探索 → attempt 1（拉 hint 但 clue 基线在其后
    # 取样，不算进展）无新线索 → attempt 2 被跳过。simple_attempts=3 验证跳过生效
    api = FakeApi()
    sched = _mk_sched(api, tmp_path, simple_steps_per_round=1, simple_attempts=3,
                      simple_budget_min=2)
    _patch_clock(monkeypatch)
    seen = []
    orig = sched._solve_one

    async def wrapped(ch, attempt, deadline=0.0):
        seen.append(attempt)
        return await orig(ch, attempt, deadline)

    monkeypatch.setattr(sched, "_solve_one", wrapped)
    await sched.run()
    assert seen == [0, 1, 0, 1], f"每波应只跑 attempt 0/1（第 3 次被跳过），实际 {seen}"


@pytest.mark.asyncio
async def test_new_clues_reset_skip(tmp_path):
    # 有新线索的 attempt 正常重排：step 输出里出现新凭证
    class CredShellLLM:
        def __init__(self):
            self.first = True

        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                return {"role": "assistant", "content": "- 方向A"}
            if self.first:
                self.first = False
                return {"role": "assistant", "content": "", "tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": {"name": "shell", "arguments": json.dumps(
                        {"command": "echo 'password=S3cret99x'"})}
                }]}
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c2", "type": "function",
                "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
            }]}

    sched = _mk_sched(FakeApi(), tmp_path, llm=CredShellLLM(), simple_steps_per_round=1)
    r = await sched._solve_one(_mk_ch(), 0)
    assert r["engine"] == "flash"
    assert r["new_clues"] >= 1      # 凭证被自动提取 → 有进展
    assert r["new_flags"] is False


# ---- 优化 5：复现题优先 + 不走 claude ----

def test_should_use_claude_false_for_reproduce(tmp_path, monkeypatch):
    _patch_lib(monkeypatch, tmp_path,
               {"b-01": {"completed": True, "note": "复现步骤"}})
    sched = _mk_sched(FakeApi(), tmp_path)
    sched.cfg.harness_enabled = True
    # 多 flag + 有完整解法 → flash 复现通道，不 spawn claude
    assert sched._should_use_claude(_mk_ch("b-01", fc=4, diff="hard")) is False
    assert sched._should_use_claude(_mk_ch("b-02", fc=4, diff="hard")) is False


@pytest.mark.asyncio
async def test_wave_queue_reproduce_first(tmp_path, monkeypatch):
    _patch_lib(monkeypatch, tmp_path,
               {"h-01": {"completed": True, "note": "复现步骤"}})
    api = FakeApi(challenges=[_mk_ch("a-01", diff="easy"), _mk_ch("h-01", diff="hard")])
    sched = _mk_sched(api, tmp_path)
    queue = sched._build_wave_queue(api.challenges, set())
    assert queue[0][0].unique_code == "h-01"   # 复现 hard 排在无解法 easy 前
    assert queue[1][0].unique_code == "a-01"


# ---- 优化 6：hard/多 flag flash 首轮拉 hint ----

@pytest.mark.asyncio
async def test_hint_upfront_for_hard_flash_attempt0(tmp_path):
    """P0：首轮（含 hard）不拉 hint；第二波仍 0 分才买。"""
    api = FakeApi()
    sched = _mk_sched(api, tmp_path, simple_steps_per_round=1)
    await sched._solve_one(_mk_ch("a-06", diff="hard"), 0)
    assert api.hint_calls == 0
    api2 = FakeApi()
    sched2 = _mk_sched(api2, tmp_path, simple_steps_per_round=1)
    await sched2._solve_one(_mk_ch("a-01", diff="easy"), 0)
    assert api2.hint_calls == 0


@pytest.mark.asyncio
async def test_no_hint_upfront_under_stuck(tmp_path):
    api = FakeApi()
    sched = _mk_sched(api, tmp_path, hint_policy="stuck", simple_steps_per_round=1)
    await sched._solve_one(_mk_ch("a-06", diff="hard"), 0)
    assert api.hint_calls == 0


# ---- 优化 7：收尾段快赢排序 ----

def test_endgame_resort_prioritizes_one_flag_left(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path)
    hard_left2 = _mk_ch("b-01", fc=3, diff="hard", score=600)
    hard_left2.correct_flag_count = 1     # 剩 2 面
    easy_left1 = _mk_ch("a-02", diff="easy", score=200)   # 单 flag 剩 1 面
    med_left1 = _mk_ch("c-01", fc=2, diff="medium", score=300)
    med_left1.correct_flag_count = 1     # 剩 1 面
    queue = [(hard_left2, 1), (easy_left1, 0), (med_left1, 0)]
    # 剩余 30min（< endgame 45min）触发重排
    sched._endgame_resort(queue, 30 * 60)
    codes = [it[0].unique_code for it in queue]
    # 剩 1 面的题排前（easy 先于 medium），剩 2 面的 hard 最后
    assert codes == ["a-02", "c-01", "b-01"]
    # 非收尾段不重排
    queue2 = [(hard_left2, 1), (easy_left1, 0)]
    sched._endgame_resort(queue2, 60 * 60)
    assert queue2[0][0].unique_code == "b-01"


# ---- 优化 8：attempt≥1 step 数减半 ----

@pytest.mark.asyncio
async def test_steps_halved_on_retry(tmp_path):
    """全题 FGS：attempt 0/1 都走 _run_chain，不再按 attempt 减半撒网。"""
    counts = []

    async def fake_chain(ch, addrs, submitter, attempt, budget_s, hint_cb,
                         retry_note, sol_section):
        counts.append(attempt)
        return 0

    sched = _mk_sched(FakeApi(), tmp_path, simple_steps_per_round=8)
    sched._run_chain = fake_chain
    await sched._solve_one(_mk_ch(), 0)
    await sched._solve_one(_mk_ch(), 1)
    assert counts == [0, 1]
