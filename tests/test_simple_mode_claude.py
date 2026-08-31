"""极简模式 claude 攻坚与方向规划修复的单元测试。

覆盖 13536 复盘的两处根因：
- 方向规划回退到通用 Web 8 方向 → pwn 题被打成 Web 题（应按题型选方向集）
- hard/pwn/多 flag 题应切 claude harness，easy/medium 单 flag 继续 flash
"""

import pytest

from agent.config import Config
from agent.simple_mode import (
    SimpleScheduler, _parse_direction_lines, _DIRECTIONS_BY_PB, STEP_DIRECTIONS,
)
from agent.tsec_api import Challenge


def _mk_ch(code: str = "a-01", fc: int = 1, diff: str = "easy",
           score: int = 100, desc: str = "测试题") -> Challenge:
    return Challenge.from_dict({
        "unique_code": code, "difficulty": diff, "total_score": score,
        "flag_count": fc, "correct_flag_count": 0, "is_completed": False,
        "container_status": "stopped", "container_addr": [],
        "description": desc, "level": 1,
    })


def _mk_sched(tmp_path) -> SimpleScheduler:
    cfg = Config()
    cfg.simple_mode = True
    cfg.harness_enabled = True
    return SimpleScheduler(cfg, None, None, str(tmp_path))


# ---- 方向规划解析（13536 根因：只认「- 」前缀导致解析空回退）----
def test_parse_direction_lines_accepts_dash():
    assert _parse_direction_lines("- A\n- B\n- C") == ["A", "B", "C"]


def test_parse_direction_lines_accepts_numbered_and_star():
    assert _parse_direction_lines("1. A\n2) B\n* C") == ["A", "B", "C"]


def test_parse_direction_lines_ignores_blank_and_noise():
    assert _parse_direction_lines("- A\n\n   \n- B") == ["A", "B"]


# ---- 回退方向按题型（13536 根因：pwn 题回退到 Web 8 方向）----
def test_fallback_directions_pwn_not_web(tmp_path):
    sched = _mk_sched(tmp_path)
    dirs = sched._fallback_directions(_mk_ch(code="f1-02", diff="medium"), 8)
    # pwn 题不应回退到「信息泄露 JS 源码」这类 Web 方向
    assert not any("JS 源码" in d or "SQLi" in d for d in dirs)
    assert any("逆向" in d or "pwn" in d or "内存安全" in d or "协议分析" in d for d in dirs)


def test_fallback_directions_web_falls_back_to_step_directions(tmp_path):
    sched = _mk_sched(tmp_path)
    dirs = sched._fallback_directions(_mk_ch(code="a-06", diff="hard"), 8)
    assert dirs == list(STEP_DIRECTIONS)[:8]


# ---- claude 切换判断 ----
def test_should_use_claude_hard(tmp_path):
    sched = _mk_sched(tmp_path)
    assert sched._should_use_claude(_mk_ch(code="a-06", diff="hard")) is False


def test_should_use_claude_binary_escalation(tmp_path):
    """P0：simple_mode 全程 flash，二进制也不再升级 claude。"""
    sched = _mk_sched(tmp_path)
    ch = _mk_ch(code="f1-02", diff="medium")
    assert sched._should_use_claude(ch, attempt=0) is False
    assert sched._should_use_claude(ch, attempt=1) is False


def test_should_use_claude_multiflag(tmp_path):
    sched = _mk_sched(tmp_path)
    assert sched._should_use_claude(_mk_ch(code="b-01", fc=4, diff="medium")) is False


def test_should_use_claude_easy_single_flag_no(tmp_path):
    sched = _mk_sched(tmp_path)
    assert sched._should_use_claude(_mk_ch(code="a-01", fc=1, diff="easy")) is False


def test_should_use_claude_disabled_when_harness_off(tmp_path):
    cfg = Config()
    cfg.simple_mode = True
    cfg.harness_enabled = False
    sched = SimpleScheduler(cfg, None, None, str(tmp_path))
    assert sched._should_use_claude(_mk_ch(code="a-06", diff="hard")) is False


# ---- A-E 五个闭环修复的回归测试 ----

class _FakeApi:
    """记录 start/close/hint 调用，submit 可配置返回正确 flag。"""

    def __init__(self):
        self.start_calls = 0
        self.closed: list[str] = []
        self.hint_calls = 0
        self.submit_correct = True

    async def list_challenges(self):
        return []

    async def start_challenge(self, code):
        self.start_calls += 1
        return ["10.0.0.1:80"]

    async def submit_flag(self, code, flag):
        from agent.tsec_api import SubmitResult
        return SubmitResult.from_dict({"correct": self.submit_correct, "awarded": 100,
                                       "cumulative_score": 100,
                                       "correct_flag_count": 1,
                                       "total_flag_count": 1})

    async def get_hint(self, code):
        self.hint_calls += 1
        return "官方提示"

    async def close_challenge(self, code):
        self.closed.append(code)
        return True


class _SubmitLLM:
    """方向规划返回 1 个方向；step 执行先 submit_flag 一次再 finish。"""

    def __init__(self):
        self.submitted = False

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        import json
        if tools is None:
            return {"role": "assistant", "content": "- 方向A"}
        if not self.submitted:
            self.submitted = True
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "submit_flag",
                             "arguments": json.dumps({"flag": "flag{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"})}
            }]}
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c2", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
        }]}


def _mk_full_sched(api, tmp_path) -> SimpleScheduler:
    cfg = Config()
    cfg.simple_mode = True
    cfg.harness_enabled = True
    cfg.simple_steps_per_round = 1
    cfg.simple_max_steps = 5
    cfg.record_solutions = False    # 防测试污染真实解法库
    cfg.recon_boot = False          # 测试不起真实 nmap 侦察
    return SimpleScheduler(cfg, _SubmitLLM(), api, str(tmp_path))


@pytest.mark.asyncio
async def test_close_challenge_invalidates_snapshot(tmp_path):
    """E：close 后 ch 快照打回 stopped，下次 attempt 强制重新 start。"""
    api = _FakeApi()
    sched = _mk_full_sched(api, tmp_path)
    ch = _mk_ch()
    ch.container_status = "available"
    ch.container_addr = ["10.0.0.1:80"]
    await sched._close_challenge(ch)
    assert ch.container_status == "stopped"
    assert ch.container_addr == []
    assert api.closed == [ch.unique_code]


@pytest.mark.asyncio
async def test_hint_pulled_proactively_on_retry(tmp_path):
    """D：attempt>=1 主动拉官方提示（8 step 开跑前都能看到）。"""
    api = _FakeApi()
    sched = _mk_full_sched(api, tmp_path)
    await sched._solve_one(_mk_ch(), 1, 0.0)
    assert api.hint_calls == 1  # 主动拉一次


@pytest.mark.asyncio
async def test_solve_one_writes_back_progress(tmp_path):
    """A：解出 flag 后 ch.correct_flag_count 被写回（跨 attempt 进度不丢）。"""
    api = _FakeApi()
    sched = _mk_full_sched(api, tmp_path)
    ch = _mk_ch()  # correct_flag_count 初始 0
    r = await sched._solve_one(ch, 0, 0.0)
    assert ch.correct_flag_count == 1  # submit 正确后写回
    assert r["completed"] is True
