"""极简模式冒烟测试：mock 平台 API，验证各种异常场景下不崩溃。

三次托管跑崩溃的回归测试：
- 13494: _submit 返回 SubmitResult → extract_flags TypeError
- 13497: close_challenge 网络异常 → run() 的 t.result() 崩溃
- 13506: start_challenge 网络失败 → 空 addr 瞎跑白费一轮
"""

import asyncio
import json

import pytest

from agent.config import Config
from agent.flagger import FlagSubmitter
from agent.simple_mode import SimpleScheduler
from agent.tsec_api import ApiError, Challenge, SubmitResult


def _mk_ch(code: str = "a-01", fc: int = 1, diff: str = "easy", score: int = 100) -> Challenge:
    return Challenge.from_dict({
        "unique_code": code, "difficulty": diff, "total_score": score,
        "flag_count": fc, "correct_flag_count": 0, "is_completed": False,
        "container_status": "stopped", "container_addr": [],
        "description": "测试题", "level": 1,
    })


class FakeApi:
    """可配置异常场景的 mock 平台 API。"""

    def __init__(self, challenges=None, start_fail=0, submit_fail=False,
                 close_fail=False, hint_fail=False):
        self.challenges = challenges or [_mk_ch()]
        self.start_fail = start_fail
        self.start_calls = 0
        self.submit_fail = submit_fail
        self.close_fail = close_fail
        self.hint_fail = hint_fail
        self.submitted: list[str] = []
        self.closed: list[str] = []

    async def list_challenges(self):
        return self.challenges

    async def start_challenge(self, code):
        self.start_calls += 1
        if self.start_calls <= self.start_fail:
            raise ApiError(0, "network", "")  # 模拟 13506 的 network 异常
        return ["10.0.0.1:80"]

    async def submit_flag(self, code, flag):
        if self.submit_fail:
            raise ApiError(0, "network", "")
        self.submitted.append(flag)
        return SubmitResult.from_dict({"correct": True, "awarded": 100,
                                       "cumulative_score": 100,
                                       "correct_flag_count": 1,
                                       "total_flag_count": 1})

    async def get_hint(self, code):
        if self.hint_fail:
            raise ApiError(0, "network", "")
        return "官方提示"

    async def close_challenge(self, code):
        if self.close_fail:
            raise ApiError(0, "network", "")
        self.closed.append(code)
        return True


class FakeLLM:
    """方向规划（无 tools）返回固定方向；step 执行（有 tools）返回 finish 快速收束。"""

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        if tools is None:
            # 方向规划：返回「- 方向」列表
            return {"role": "assistant", "content": "- 方向A\n- 方向B\n- 方向C"}
        # step 执行：直接 finish 收束，不执行 shell（快速、不依赖环境）
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c1", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "测试收束"})}
        }]}


def _mk_sched(api, tmp_path) -> SimpleScheduler:
    cfg = Config()
    cfg.simple_mode = True
    cfg.simple_steps_per_round = 3  # 减少 step 数，加速测试
    return SimpleScheduler(cfg, FakeLLM(), api, str(tmp_path))


# ---- start 失败重试（13506 回归）----
@pytest.mark.asyncio
async def test_addrs_start_failure_retries_then_succeeds(tmp_path):
    api = FakeApi(start_fail=2)
    sched = _mk_sched(api, tmp_path)
    addrs = await sched._addrs(_mk_ch())
    assert addrs == ["10.0.0.1:80"]
    assert api.start_calls == 3  # 前 2 次失败，第 3 次成功


@pytest.mark.asyncio
async def test_addrs_start_all_fail_returns_empty(tmp_path):
    api = FakeApi(start_fail=99)
    sched = _mk_sched(api, tmp_path)
    assert await sched._addrs(_mk_ch()) == []


# ---- start 失败跳过本轮（13506 回归）----
@pytest.mark.asyncio
async def test_solve_one_start_fail_skips(tmp_path):
    api = FakeApi(start_fail=99)
    sched = _mk_sched(api, tmp_path)
    r = await sched._solve_one(_mk_ch(), 0)
    assert r["completed"] is False
    assert r["flags"] == []
    assert api.start_calls >= 3  # 重试过 3 次


# ---- submit 网络异常兜底（13497 回归）----
@pytest.mark.asyncio
async def test_submit_network_error_returns_string(tmp_path):
    api = FakeApi(submit_fail=True)
    sched = _mk_sched(api, tmp_path)
    ch = _mk_ch()
    sub = FlagSubmitter(ch.unique_code, ch.flag_count, 0, wrong_cap=10)
    out = await sched._submit(ch, sub, "flag{test}")
    assert isinstance(out, str)  # 返回字符串，不是抛异常
    assert "失败" in out


# ---- close 网络异常兜底（13497 回归）----
@pytest.mark.asyncio
async def test_close_network_error_no_crash(tmp_path):
    api = FakeApi(close_fail=True)
    sched = _mk_sched(api, tmp_path)
    r = await sched._solve_one(_mk_ch(), 0)  # close 在 _solve_one 结尾，close 失败应不崩溃
    assert r["completed"] is False


# ---- hint 网络异常兜底 ----
@pytest.mark.asyncio
async def test_hint_network_error_returns_string(tmp_path):
    api = FakeApi(hint_fail=True)
    sched = _mk_sched(api, tmp_path)
    out = await sched._hint(_mk_ch(), 1)  # attempt=1 才拉 hint
    assert isinstance(out, str)


# ---- 完整 _solve_one 正常流程不崩溃（submit 返回 SubmitResult 的 str 兜底回归）----
@pytest.mark.asyncio
async def test_solve_one_full_flow_no_crash(tmp_path):
    api = FakeApi()
    sched = _mk_sched(api, tmp_path)
    r = await sched._solve_one(_mk_ch(), 0)
    assert r["completed"] is False  # FakeLLM 只 finish 不 submit，未完成属正常
    assert api.closed  # close 被调用
