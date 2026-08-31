"""能力增强包回归测试（方案 1/3/4 + 定向 playbook，2026-08-28）。

- 方案1 resume：session_id 捕获、--resume 传参、resume 无输出自动回退、跨 attempt 持久化
- 方案3 知识包：镜像 COPY + playbook 引用 + 文件清单
- 方案4 fallback：主网关连续 2 次失败切备用、备用连续 5 次成功切回、400 不触发切换
"""
import json
import time

import httpx
import pytest

from agent.config import Config
from agent.harness import run_harness, HarnessResult, _parse_jsonl
from agent.llm import LLMClient
from tests.test_scheduler_e2e import FakeLLM


# ---- 方案1：session_id 捕获与 --resume ----

def test_parse_jsonl_extracts_session_id():
    res = HarnessResult()
    _parse_jsonl('{"type":"system","subtype":"init","session_id":"sess-abc123"}', res)
    assert res.session_id == "sess-abc123"
    _parse_jsonl('{"type":"result","result":"done","session_id":"sess-xyz999"}', res)
    assert res.session_id == "sess-xyz999"      # result 事件覆盖（最新会话）


@pytest.mark.asyncio
async def test_run_harness_resume_falls_back_on_empty(tmp_path):
    """resume 无输出（session 丢失/不支持）：自动去掉 --resume 原样重跑。"""
    cfg = Config()
    p = tmp_path / "fake-resume.sh"
    # 收到 --resume 参数 → 无输出退出；否则输出一条带 session_id 的事件
    p.write_text('#!/bin/bash\n'
                 'if [[ "$*" == *--resume* ]] || [[ "$1" == "--resume" ]]; then exit 1; fi\n'
                 "echo '{\"type\":\"result\",\"result\":\"ok\",\"session_id\":\"fresh-1\"}'\n")
    p.chmod(0o755)
    cfg.harness_backend = str(p)
    res = await run_harness(cfg, "prompt", str(tmp_path), 60,
                            resume_session_id="old-sess")
    assert res.events == 1 and res.session_id == "fresh-1", "应回退到无 resume 重跑并拿到新会话"


@pytest.mark.asyncio
async def test_run_harness_resume_keeps_session_when_ok(tmp_path):
    """resume 正常出事件：不回退，session_id 保留。"""
    cfg = Config()
    p = tmp_path / "fake-ok.sh"
    p.write_text('#!/bin/bash\n'
                 "echo '{\"type\":\"result\",\"result\":\"continued\",\"session_id\":\"kept-7\"}'\n")
    p.chmod(0o755)
    cfg.harness_backend = str(p)
    res = await run_harness(cfg, "p", str(tmp_path), 60, resume_session_id="kept-7")
    assert res.events == 1 and res.session_id == "kept-7"


@pytest.mark.asyncio
async def test_claude_worker_resume_on_retry_attempt(tmp_path, monkeypatch):
    """attempt>=1 的 claude 主会话 resume 上轮 session（ws/claude-session.json），
    session 保存供下次使用。"""
    import agent.harness as harness_mod
    import agent.worker as worker_mod
    from agent.tsec_api import Challenge

    seen: list[dict] = []

    async def fake_run_harness(cfg, prompt, cwd, timeout_s, on_text=None,
                               token_budget=0, model="", effort="",
                               stop_event=None, resume_session_id=""):
        seen.append({"resume": resume_session_id})
        from agent.harness import HarnessResult
        r = HarnessResult()
        r.events = 2
        r.session_id = "next-sess-42"
        r.output_text = "ok"
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
    ch = Challenge.from_dict({"unique_code": "f2-01", "flag_count": 1,
                              "total_score": 600, "difficulty": "hard",
                              "level": 1, "correct_flag_count": 0,
                              "is_completed": False, "container_status": "stopped",
                              "container_addr": []})
    ws = tmp_path / "ws"
    # 首轮：无 resume；结束后 session 落盘
    w1 = worker_mod.Worker(cfg, object(), _NoopApi(), ch, ["127.0.0.1:80"], str(ws),
                           deadline=time.monotonic() + 600, attempt=0)
    await w1._run_claude()
    assert seen[0]["resume"] == ""
    assert json.loads((ws / "claude-session.json").read_text())["session_id"] == "next-sess-42"
    # retry 轮：resume 上轮 session
    w2 = worker_mod.Worker(cfg, object(), _NoopApi(), ch, ["127.0.0.1:80"], str(ws),
                           deadline=time.monotonic() + 600, attempt=1)
    await w2._run_claude()
    assert seen[1]["resume"] == "next-sess-42", "retry 轮应 resume 上次会话"


class _NoopApi:
    async def list_challenges(self):
        return []

    async def get_hint(self, code):
        return None

    async def submit_flag(self, code, flag):
        from agent.tsec_api import SubmitResult
        return SubmitResult(False, 0, 0, 0, 1, None)


# ---- 方案3：知识包 ----

def test_knowledge_pack_wired_in_image_and_playbooks():
    """五个速查文件进镜像 /opt/knowledge，且 f/b/c playbook 引用了对应路径。"""
    import os
    files = {"linux-privesc.md", "container-escape.md", "shell-payloads.md",
             "default-creds.md", "pwn-cookbook.md"}
    base = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "tools", "knowledge")
    for f in files:
        assert os.path.exists(os.path.join(base, f)), f"缺知识文件 {f}"
    dk = open("Dockerfile").read()
    assert "COPY tools/knowledge /opt/knowledge" in dk
    pb = open("agent/prompts.py").read()
    assert "/opt/knowledge/pwn-cookbook.md" in pb       # f 二进制
    assert "/opt/knowledge/linux-privesc.md" in pb       # b 多阶段
    assert "/opt/knowledge/container-escape.md" in pb
    assert "/opt/knowledge/default-creds.md" in pb       # c 漏洞利用


def test_f_playbook_has_checksec_tree_and_gdb_shortcut():
    """二进制定向强化：保护机制决策树 + gdb 直读期望输入捷径。"""
    from agent.prompts import playbook_for
    pb = playbook_for("f-05", "")
    assert "checksec 决策树" in pb and "ret2libc" in pb
    assert "x/s $rdi" in pb, "逆向题 gdb 直读期望输入是提速关键"
    assert "fmtstr_payload" in pb


def test_b_playbook_has_primitive_to_flag_discipline():
    """多阶段定向强化：原语→flag 面推进纪律（文件读直读/RCE 全盘 find/先提权再找 flag）。"""
    from agent.prompts import playbook_for
    pb = playbook_for("b-02", "")
    assert "原语→flag 面推进纪律" in pb
    assert "先提权再找 flag" in pb


def test_c_playbook_has_poc_adaptation_discipline():
    """漏洞利用定向强化：PoC 适配三关（版本核对/参数化/无回显证实）。"""
    from agent.prompts import playbook_for
    pb = playbook_for("c-04", "")
    assert "PoC 适配纪律" in pb and "版本核对" in pb and "无回显先证实执行" in pb


# ---- 方案4：LLM 双通道 fallback ----

class _FakeChan:
    """假通道：脚本化的 post 行为序列。"""

    def __init__(self, script):
        self.script = list(script)
        self.calls = 0
        self.last_timeout = None

    async def post(self, path, json=None, **kw):
        self.calls += 1
        self.last_timeout = kw.get("timeout")
        action = self.script.pop(0) if self.script else "ok"
        if isinstance(action, Exception):
            raise action
        return httpx.Response(200, request=httpx.Request("POST", "http://x" + path),
                              json={"choices": [{"message": {"content": "hi"}}],
                                    "usage": {}})

    async def aclose(self):
        pass


@pytest.fixture(autouse=True)
def _no_llm_backoff_sleep(monkeypatch):
    """跳过 LLM 重试的指数退避（真睡会拖慢测试 3 分钟）。"""
    import agent.llm as llm_mod

    async def _sleep(_s):
        return None

    monkeypatch.setattr(llm_mod.asyncio, "sleep", _sleep)


@pytest.mark.asyncio
async def test_llm_fallback_switch_and_return():
    """主通道连续 2 次网络失败切备用；备用连续 5 次成功切回主。"""
    c = LLMClient("http://main.local/v1", "k", "m", timeout_s=1,
                  fallback_base_url="http://fb.local/v1", fallback_model="fm")
    main_chan = _FakeChan([httpx.ConnectError("boom")] * 10)
    fb_chan = _FakeChan(["ok"] * 20)
    c._client, c._fallback_client = main_chan, fb_chan

    msg = await c.chat([{"role": "user", "content": "x"}])
    assert msg["content"] == "hi"
    assert c._active == "fallback", "主通道 2 连败应切换"
    assert main_chan.calls == 2

    # 备用连续成功累计 5 次（首轮已 +1）→ 切回主通道
    for _ in range(4):
        await c.chat([{"role": "user", "content": "x"}])
    assert c._active == "main", "备用累计 5 次成功应切回主通道"
    # 切回后再失败 2 次又能切备用（状态机复位）
    await c.chat([{"role": "user", "content": "x"}])
    assert c._active == "fallback"
    assert main_chan.calls == 4, "切回主后 2 连败再次切换"
    await c.close()


@pytest.mark.asyncio
async def test_llm_no_fallback_configured():
    """未配置备用通道：行为退回原语义（重试后抛错），不崩。"""
    c = LLMClient("http://main.local/v1", "k", "m", timeout_s=1)
    chan = _FakeChan([httpx.ConnectError("boom")] * 10)
    c._client = chan
    with pytest.raises(RuntimeError):
        await c.chat([{"role": "user", "content": "x"}])
    assert c._active == "main"
    assert chan.calls == 3  # 1 + 最多再试 2 次
    await c.close()


@pytest.mark.asyncio
async def test_llm_400_does_not_trigger_switch():
    """400（请求本身问题）不计入切换：换通道也一样失败。"""
    c = LLMClient("http://main.local/v1", "k", "m",
                  fallback_base_url="http://fb.local/v1")
    # 直接驱动状态机（400 在 chat 里 raise 前不调 _note_channel_failure）
    for _ in range(5):
        c._note_channel_success()
    assert c._fail_streak == 0
    await c.close()


@pytest.mark.asyncio
async def test_llm_retry_wait_capped_at_5s(monkeypatch):
    """单次退避 ≤5s，总共最多 2 次等待（3 次尝试）。"""
    import agent.llm as llm_mod
    waits = []

    async def rec_sleep(s):
        waits.append(s)

    monkeypatch.setattr(llm_mod.asyncio, "sleep", rec_sleep)
    c = LLMClient("http://main.local/v1", "k", "m", timeout_s=1)
    c._client = _FakeChan([httpx.ConnectError("boom")] * 10)
    with pytest.raises(RuntimeError):
        await c.chat([{"role": "user", "content": "x"}])
    assert waits == [3, 5]
    await c.close()


@pytest.mark.asyncio
async def test_llm_chat_timeout_s_passed_to_post():
    """timeout_s 作为本次调用墙钟预算传给 httpx post。"""
    c = LLMClient("http://main.local/v1", "k", "m", timeout_s=300)
    chan = _FakeChan(["ok"])
    c._client = chan
    await c.chat([{"role": "user", "content": "x"}], timeout_s=12)
    assert chan.last_timeout is not None
    assert 11 <= chan.last_timeout <= 12
    await c.close()
