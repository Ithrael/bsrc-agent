"""极简模式第二轮闭环修复的测试（P0-P2 全量）。

- P0-1 波次回查：一波 attempt 耗尽后回查平台开下一波，预算不闲置
- P0-2 start 失败不消耗 attempt（started=False 同 attempt 重排 + 波内连败熔断 + 跨波重置）
- P0-3 flash 路径解法库闭环（注入 + 复现题止损 + 回写不降级 + partial 门槛）
- P1-4 409 duplicate 识别与进度校准
- P1-6 step 会话上下文裁剪（保头截尾 + 孤儿 tool 剔除）
- P1-7 deadline 封顶 flash step 超时
- P2-8 NOTES.md 写盘但不进 YAML
- P2-9 跨方向新事实 step 内注入
- P2-10 HINT_POLICY=stuck 不主动拉
- P2-11 wrong_total 跨 attempt 累计
- P2-12 方向解析无前缀行兜底
- P2-13 flag_count=0 跳过
"""

import asyncio
import json
import os
import time

import pytest

import agent.simple_mode as simple_mod
from agent.config import Config
from agent.simple_mode import SimpleScheduler, _parse_direction_lines
from agent.tsec_api import ApiError, Challenge, SubmitResult


def _mk_ch(code: str = "a-01", fc: int = 1, diff: str = "easy",
           score: int = 100, desc: str = "测试题") -> Challenge:
    return Challenge.from_dict({
        "unique_code": code, "difficulty": diff, "total_score": score,
        "flag_count": fc, "correct_flag_count": 0, "is_completed": False,
        "container_status": "stopped", "container_addr": [],
        "description": desc, "level": 1,
    })


class FakeApi:
    def __init__(self, challenges=None, start_fail=0, submit_correct=True):
        self.challenges = challenges if challenges is not None else [_mk_ch()]
        self.start_fail = start_fail
        self.start_calls = 0
        self.list_calls = 0
        self.submit_correct = submit_correct
        self.submitted: list[str] = []
        self.hint_calls = 0

    async def list_challenges(self):
        self.list_calls += 1
        return self.challenges

    async def start_challenge(self, code):
        self.start_calls += 1
        if self.start_calls <= self.start_fail:
            raise ApiError(0, "network", "")
        return ["10.0.0.1:80"]

    async def submit_flag(self, code, flag):
        if not self.submit_correct:
            return SubmitResult.from_dict({"correct": False, "awarded": 0,
                                           "cumulative_score": 0,
                                           "correct_flag_count": 0,
                                           "total_flag_count": 1})
        self.submitted.append(flag)
        return SubmitResult.from_dict({"correct": True, "awarded": 100,
                                       "cumulative_score": 100,
                                       "correct_flag_count": len(self.submitted),
                                       "total_flag_count": 1})

    async def get_hint(self, code):
        self.hint_calls += 1
        return "官方提示"

    async def close_challenge(self, code):
        return True


class FinishLLM:
    """规划返回 1 个方向；step 直接 finish 收束。"""

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        if tools is None:
            return {"role": "assistant", "content": "- 方向A"}
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c1", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
        }]}


class SubmitThenFinishLLM:
    """先 submit_flag 一次再 finish。"""

    def __init__(self, flag="flag{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"):
        self.flag = flag
        self.submitted = False

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        if tools is None:
            return {"role": "assistant", "content": "- 方向A"}
        if not self.submitted:
            self.submitted = True
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "submit_flag", "arguments": json.dumps({"flag": self.flag})}
            }]}
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c2", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
        }]}


def _mk_sched(api, tmp_path, llm=None, **cfg_over) -> SimpleScheduler:
    cfg = Config()
    cfg.simple_mode = True
    cfg.record_solutions = False
    cfg.recon_boot = False       # 测试不起真实 nmap 侦察
    for k, v in cfg_over.items():
        setattr(cfg, k, v)
    return SimpleScheduler(cfg, llm or FinishLLM(), api, str(tmp_path))


class _Clock:
    """假时钟：sleep 直接推进时钟（run() 波次循环不真等 60s）。"""

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


# ---- P2-12 方向解析无前缀行兜底 ----

def test_parse_direction_lines_bare_lines_fallback():
    dirs = _parse_direction_lines(
        "好的，规划如下：\n先打 CVE 检索面（nuclei 模板直接利用）\n再做认证越权面（默认凭证加 JWT 伪造）")
    assert dirs == ["先打 CVE 检索面（nuclei 模板直接利用）", "再做认证越权面（默认凭证加 JWT 伪造）"]


def test_parse_direction_lines_prefixed_wins_over_bare():
    assert _parse_direction_lines("- A\n这里有一条不带前缀但足够长的方向描述文本") == ["A"]


# ---- P1-4 duplicate 识别 ----

@pytest.mark.asyncio
async def test_submit_duplicate_records_correct(tmp_path):
    class DupApi(FakeApi):
        async def submit_flag(self, code, flag):
            raise ApiError(409, "duplicate", "flag already submitted")

    sched = _mk_sched(DupApi(), tmp_path)
    ch = _mk_ch()
    sub = sched._new_submitter(ch)
    out = await sched._submit(ch, sub, "flag{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}")
    assert out.startswith("[duplicate]")
    assert sub.correct_count == 1  # duplicate 校准本地进度
    assert len(sub.correct) == 1


# ---- P2-11 wrong_total 跨 attempt 累计 ----

@pytest.mark.asyncio
async def test_wrong_total_carried_across_attempts(tmp_path):
    api = FakeApi(submit_correct=False)
    sched = _mk_sched(api, tmp_path,
                      llm=SubmitThenFinishLLM("flag{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}"),
                      simple_steps_per_round=1)
    await sched._solve_one(_mk_ch(), 0)
    assert sched._wrong_total.get("a-01") == 1
    nxt = sched._new_submitter(_mk_ch())
    assert nxt.wrong_total == 1  # 新 attempt 继承错提额度（auto 通道熔断不重置）


# ---- P1-6 上下文裁剪 ----

def _big_msg(role, content, **kw):
    m = {"role": role, "content": content}
    m.update(kw)
    return m


def test_trim_messages_truncates_and_drops_orphan_tool(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path, context_char_budget=1_300)
    messages = [
        _big_msg("system", "S" * 200),
        _big_msg("user", "U" * 200),
        _big_msg("assistant", "", tool_calls=[
            {"id": "t1", "type": "function",
             "function": {"name": "shell", "arguments": "{}"}}]),
        _big_msg("tool", "X" * 5_000, tool_call_id="t1"),   # 超预算被截
        _big_msg("assistant", "done"),
    ]
    out = sched._trim_messages(messages)
    assert out[0]["role"] == "system" and out[1]["role"] == "user"  # 保头
    assert any("截断" in m.get("content", "") for m in out)          # 截断通知
    assert not any(m.get("role") == "tool" for m in out)             # 孤儿 tool 一并剔除
    assert out[-1]["content"] == "done"                              # 最新消息保留


def test_trim_messages_noop_under_budget(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path, context_char_budget=90_000)
    messages = [_big_msg("system", "S" * 100), _big_msg("user", "U" * 100)]
    assert sched._trim_messages(messages) is messages


# ---- P2-10 stuck 不主动拉 hint ----

@pytest.mark.asyncio
async def test_hint_stuck_no_proactive_pull(tmp_path):
    api = FakeApi()
    sched = _mk_sched(api, tmp_path, hint_policy="stuck")
    out = await sched._hint(_mk_ch(), 1, proactive=True)
    assert out == "" and api.hint_calls == 0
    # 模型自觉卡住调 get_hint（非 proactive）仍可拉
    out = await sched._hint(_mk_ch(), 1)
    assert api.hint_calls == 1
    assert any(f.startswith("[官方提示]") for f in sched._snapshot("a-01"))


@pytest.mark.asyncio
async def test_hint_free_proactive_timing_is_caller_decided(tmp_path):
    """proactive 拉取时机由调用方决定（次轮普遍拉 / hard 多 flag 首轮拉）；
    模型工具调用（非 proactive）首轮仍拒绝。"""
    api = FakeApi()
    sched = _mk_sched(api, tmp_path, hint_policy="free")
    # 非 proactive（模型 get_hint）attempt 0：拒绝，不扣分
    out = await sched._hint(_mk_ch(), 0)
    assert "首轮" in out and api.hint_calls == 0
    # proactive attempt 0（free）：拉（时机由调用方决定，_hint 不再挡）
    out = await sched._hint(_mk_ch(), 0, proactive=True)
    assert api.hint_calls == 1
    assert any(f.startswith("[官方提示]") for f in sched._snapshot("a-01"))


# ---- P0-3 解法库注入 / 止损 / 回写 ----

def _patch_lib(monkeypatch, tmp_path, lib: dict):
    p = tmp_path / "solutions.json"
    p.write_text(json.dumps(lib, ensure_ascii=False))
    monkeypatch.setattr(simple_mod, "solution_lib_path", lambda: str(p))
    return p


def _patch_notes(monkeypatch, tmp_path, notes: dict | None = None):
    p = tmp_path / "notes.json"
    p.write_text(json.dumps(notes or {}, ensure_ascii=False))
    monkeypatch.setattr(simple_mod, "notes_lib_path", lambda: str(p))
    return p


def test_solution_section_injects_and_flags_full(tmp_path, monkeypatch):
    _patch_lib(monkeypatch, tmp_path,
               {"a-01": {"completed": True, "note": "curl /flag 直读", "steps": ["curl http://x/flag"]}})
    _patch_notes(monkeypatch, tmp_path, {"a-01": "后台 admin/admin"})
    sched = _mk_sched(FakeApi(), tmp_path)
    section, has_full = sched._solution_section(_mk_ch("a-01"))
    assert has_full is True
    assert "解法库" in section and "curl /flag 直读" in section and "admin/admin" in section


def test_record_simple_solution_completed_and_no_downgrade(tmp_path, monkeypatch):
    p = _patch_lib(monkeypatch, tmp_path, {})
    sched = _mk_sched(FakeApi(), tmp_path)
    sched.cfg.record_solutions = True
    sched._record_simple_solution(_mk_ch(), ["fact-1", "fact-2"], True, 2.0)
    lib = json.loads(p.read_text())
    assert lib["a-01"]["completed"] is True and "fact-1" in lib["a-01"]["note"]
    # partial 不降级 completed
    sched._record_simple_solution(_mk_ch(), ["worse"], False, 10.0)
    lib = json.loads(p.read_text())
    assert lib["a-01"]["completed"] is True
    # 快速失败不落库
    _patch_lib(monkeypatch, tmp_path, {})
    sched._record_simple_solution(_mk_ch("b-01"), [], False, 0.5)
    assert "b-01" not in json.loads(p.read_text())


@pytest.mark.asyncio
async def test_solve_one_injects_solution_and_caps_timeout(tmp_path, monkeypatch):
    _patch_lib(monkeypatch, tmp_path,
               {"a-01": {"completed": True, "note": "curl /flag 直读"}})
    _patch_notes(monkeypatch, tmp_path, {})
    sched = _mk_sched(FakeApi(), tmp_path, simple_steps_per_round=1)
    recorded = {}

    async def fake_run_step(ch, addrs, submitter, direction, step_no, timeout_s,
                            hint_cb, retry_note, sol_section="", **kw):
        recorded["timeout_s"] = timeout_s
        recorded["sol_section"] = sol_section
        return "fact"

    monkeypatch.setattr(sched, "_run_step", fake_run_step)
    # deadline 剩 30s：600s 窗口被封顶到 60s 下限；复现题止损 5min 不再收紧
    await sched._solve_one(_mk_ch(), 0, deadline=time.monotonic() + 30)
    assert recorded["timeout_s"] == 60.0
    assert "解法库" in recorded["sol_section"] and "curl /flag 直读" in recorded["sol_section"]


# ---- P2-8 NOTES.md 写盘但不进 YAML（finish 摘要走 graph note）----

class NotesThenFinishLLM:
    def __init__(self):
        self.wrote = False

    async def chat(self, messages, tools=None, max_tokens=None, model=""):
        if tools is None:
            return {"role": "assistant", "content": "- 方向A"}
        if not self.wrote:
            self.wrote = True
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c1", "type": "function",
                "function": {"name": "write_file", "arguments": json.dumps({
                    "path": "NOTES.md",
                    "content": "# 笔记\n- 入口在 /admin 弱口令 admin:123456\n- 数据库 10.0.0.2:3306"})}
            }]}
        return {"role": "assistant", "content": "", "tool_calls": [{
            "id": "c2", "type": "function",
            "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
        }]}


@pytest.mark.asyncio
async def test_solve_one_notes_stay_on_disk_not_yaml(tmp_path):
    sched = _mk_sched(FakeApi(), tmp_path, llm=NotesThenFinishLLM(), simple_steps_per_round=1)
    await sched._solve_one(_mk_ch(), 0)
    facts = sched._snapshot("a-01")
    assert not any(f.startswith("[自动-笔记]") for f in facts)
    notes = open(os.path.join(sched.run_dir, "a-01", "NOTES.md")).read()
    assert "admin:123456" in notes


# ---- P2-9 跨方向新事实 step 内注入 ----

@pytest.mark.asyncio
async def test_run_step_injects_cross_direction_facts(tmp_path):
    class TwoRoundLLM:
        """第 1 轮落一条兄弟线索 fact + shell 占位；第 2 轮 finish 前检查注入。"""

        def __init__(self, sched):
            self.sched = sched
            self.calls_with_tools = 0
            self.saw_injection = False

        async def chat(self, messages, tools=None, max_tokens=None, model=""):
            if tools is None:
                return {"role": "assistant", "content": "- 方向A"}
            self.calls_with_tools += 1
            if self.calls_with_tools == 1:
                await self.sched._append_fact("a-01", "[自动-凭证] password=P@ssw0rd1")
                return {"role": "assistant", "content": "", "tool_calls": [{
                    "id": "c1", "type": "function",
                    "function": {"name": "shell",
                                 "arguments": json.dumps({"command": "true"})}
                }]}
            self.saw_injection = any("跨方向新事实" in m.get("content", "")
                                     for m in messages)
            return {"role": "assistant", "content": "", "tool_calls": [{
                "id": "c2", "type": "function",
                "function": {"name": "finish", "arguments": json.dumps({"summary": "已排除"})}
            }]}

    sched = _mk_sched(FakeApi(), tmp_path, simple_steps_per_round=1)
    llm = TwoRoundLLM(sched)
    sched.llm = llm
    await sched._run_step(_mk_ch(), ["10.0.0.1:80"], sched._new_submitter(_mk_ch()),
                          "方向A", 0, 60.0, lambda: "", "")
    assert llm.saw_injection is True


# ---- P0-1 / P0-2 / P2-13 run() 主循环 ----

@pytest.mark.asyncio
async def test_run_skips_zero_flag_and_completed(tmp_path):
    zero = _mk_ch("z-01", fc=0)
    done = _mk_ch("d-01")
    done.is_completed = True
    api = FakeApi(challenges=[zero, done])
    sched = _mk_sched(api, tmp_path)
    await sched.run()
    assert api.start_calls == 0  # 两题都被过滤，不 start


@pytest.mark.asyncio
async def test_run_start_fail_same_attempt_requeue(tmp_path, monkeypatch):
    api = FakeApi(start_fail=3)  # 第一个 _solve_one 的 3 次 start 全失败
    sched = _mk_sched(api, tmp_path, llm=SubmitThenFinishLLM(), simple_steps_per_round=1)
    _patch_clock(monkeypatch)
    seen = []
    orig = sched._solve_one

    async def wrapped(ch, attempt, deadline=0.0):
        seen.append(attempt)
        return await orig(ch, attempt, deadline)

    monkeypatch.setattr(sched, "_solve_one", wrapped)
    await sched.run()
    assert seen == [0, 0]        # start 失败不消耗 attempt
    assert api.submitted         # 第二次真正跑并解出


@pytest.mark.asyncio
async def test_run_start_fail_wave_cap_and_reset(tmp_path, monkeypatch):
    # 12 次 start 全失败：波 1 内同 attempt 重排 3 次后弃置（4 次 _solve_one），
    # 波 2 重置连败计数，第 13 次 start 成功 → 解出收工
    api = FakeApi(start_fail=12)
    sched = _mk_sched(api, tmp_path, llm=SubmitThenFinishLLM(), simple_steps_per_round=1)
    _patch_clock(monkeypatch)
    seen = []
    orig = sched._solve_one

    async def wrapped(ch, attempt, deadline=0.0):
        seen.append(attempt)
        return await orig(ch, attempt, deadline)

    monkeypatch.setattr(sched, "_solve_one", wrapped)
    await sched.run()
    assert seen == [0, 0, 0, 0, 0]   # 波1 4 次（3 重排 + 弃置阈值）+ 波2 成功 1 次
    assert api.submitted


@pytest.mark.asyncio
async def test_run_wave_requery_until_budget(tmp_path, monkeypatch):
    # 永远解不出（finish 无提交）：每波 2 attempt，波间回查平台，预算耗尽退出
    api = FakeApi()
    sched = _mk_sched(api, tmp_path, llm=FinishLLM(), simple_steps_per_round=1,
                      simple_attempts=2, simple_budget_min=2)  # 假时钟 120s
    _patch_clock(monkeypatch)
    seen = []
    orig = sched._solve_one

    async def wrapped(ch, attempt, deadline=0.0):
        seen.append(attempt)
        return await orig(ch, attempt, deadline)

    monkeypatch.setattr(sched, "_solve_one", wrapped)
    await sched.run()
    assert seen == [0, 1, 0, 1]      # 两波 × 2 attempt
    assert api.list_calls >= 3       # 初始 + 波间回查
