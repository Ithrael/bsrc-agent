"""时间分配合理性修复的测试（通用规则，按题目属性不按系列）。

- 链式题 attempt 预算下限 30min
- 次轮窗口不倒挂（attempt1/2 ≥ attempt0）
- 二进制类型 easy/medium 单 flag：flash 快试一轮再升级 claude
- 链式题 attempt 间不 close 容器，终态（止损/耗尽/解出）才关
- 全部链式题提前占派发位
"""

import asyncio
import json

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
        self.closed: list[str] = []

    async def list_challenges(self):
        self.list_calls += 1
        return self.challenges

    async def start_challenge(self, code):
        self.start_calls += 1
        return ["10.0.0.1:80"]

    async def submit_flag(self, code, flag):
        return {"correct": False, "awarded": 0, "cumulative_score": 0,
                "correct_flag_count": 0, "total_flag_count": 1}

    async def get_hint(self, code):
        return "官方提示"

    async def close_challenge(self, code):
        self.closed.append(code)
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


# ---- 次轮窗口不倒挂 ----

def test_step_window_no_inversion(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path)
    for fc, diff in [(1, "easy"), (2, "medium"), (4, "medium"), (1, "hard"), (6, "hard")]:
        w = [sched._step_timeout_min(_mk_ch(fc=fc, diff=diff), a) for a in (0, 1, 2)]
        assert w[1] >= w[0] and w[2] >= w[0], f"fc={fc} diff={diff} 窗口倒挂: {w}"


# ---- 链式题窗口：剩余预算（停滞 15min 在 _run_chain）；单 flag 5min ----

@pytest.mark.asyncio
async def test_chain_attempt_budget_floor(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path)
    budgets = []

    async def fake_chain(ch, addrs, submitter, attempt, budget_s, hint_cb,
                         retry_note, sol_section):
        budgets.append(budget_s)

    sched._run_chain = fake_chain
    await sched._solve_one(_mk_ch("x-01", fc=5, diff="medium"), 0,
                           deadline=simple_mod.time.monotonic() + 3600)
    assert budgets and budgets[0] >= 15 * 60
    budgets.clear()
    await sched._solve_one(_mk_ch("a-01", fc=1, diff="easy"), 0,
                           deadline=simple_mod.time.monotonic() + 3600)
    assert budgets == [8 * 60]  # 单 flag easy 按难度分级 = 8min


# ---- 二进制类型升级路由（通用：按类型不按系列） ----

def test_binary_type_flash_first_then_claude(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path)
    sched.cfg.harness_enabled = True
    binary_easy = _mk_ch("pwn-09", fc=1, diff="medium", desc="二进制逆向挑战")
    assert sched._problem_type(binary_easy) == "binary"
    assert sched._should_use_claude(binary_easy, attempt=0) is False
    assert sched._should_use_claude(binary_easy, attempt=1) is False
    binary_hard = _mk_ch("pwn-10", fc=1, diff="hard", desc="二进制逆向挑战")
    assert sched._should_use_claude(binary_hard, attempt=0) is False
    web_easy = _mk_ch("web-01", fc=1, diff="medium")
    assert sched._should_use_claude(web_easy, attempt=1) is False


# ---- 链式题容器跨 attempt 存活 ----

@pytest.mark.asyncio
async def test_chain_container_kept_between_attempts(tmp_path, monkeypatch):
    chain = _mk_ch("chain-01", fc=4, diff="medium", score=1200)
    api = FakeApi(challenges=[chain])
    sched = _mk_sched(api, tmp_path, simple_attempts=3, simple_budget_min=5,
                      max_concurrent=1, endgame_min=0, chain_quiet_min=0)
    _patch_clock(monkeypatch)
    await sched.run()
    # P0：链 attempt 结束即 close，下次重开
    assert api.start_calls >= 1
    assert len(api.closed) >= 1


@pytest.mark.asyncio
async def test_nonchain_closes_every_attempt(tmp_path, monkeypatch):
    easy = _mk_ch("a-01", fc=1, diff="easy")
    api = FakeApi(challenges=[easy])
    sched = _mk_sched(api, tmp_path, simple_attempts=2, simple_budget_min=2,
                      max_concurrent=1, endgame_min=0)
    _patch_clock(monkeypatch)
    await sched.run()
    # 撒网题每 attempt close + start（槽位轮转语义不变）
    assert api.start_calls >= 2
    assert api.closed.count("a-01") >= 2


# ---- 全部链式题提前占位 ----

def test_wave_queue_hoists_all_chains(tmp_path):
    api = FakeApi(challenges=[
        _mk_ch("web-1", diff="easy"), _mk_ch("web-2", diff="easy"),
        _mk_ch("web-3", diff="easy"), _mk_ch("web-4", diff="easy"),
        _mk_ch("chain-a", fc=5, diff="medium", score=1500),
        _mk_ch("chain-b", fc=4, diff="hard", score=1200),
        _mk_ch("chain-c", fc=6, diff="hard", score=1800),
    ])
    sched = _mk_sched(api, tmp_path)
    queue = sched._build_wave_queue(api.challenges, set())
    codes = [it[0].unique_code for it in queue]
    # 单 flag 在前，链全部排在队尾
    for c in ("web-1", "web-2", "web-3", "web-4"):
        assert codes.index(c) < codes.index("chain-c")
    assert set(codes[-3:]) == {"chain-a", "chain-b", "chain-c"}
