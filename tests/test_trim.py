from agent.config import Config
from agent.worker import Worker


def _mk_worker(budget: int) -> Worker:
    cfg = Config()
    cfg.context_char_budget = budget
    return Worker.__new__(Worker) | None


def _assistant_with_calls(ids):
    return {"role": "assistant", "content": "",
            "tool_calls": [{"id": i, "type": "function", "function": {"name": "shell", "arguments": "{}"}} for i in ids]}


def _tool(cid, text):
    return {"role": "tool", "tool_call_id": cid, "content": text}


def test_trim_drops_orphan_tool_messages():
    cfg = Config()
    cfg.context_char_budget = 500
    w = Worker.__new__(Worker)
    w.cfg = cfg
    messages = [
        {"role": "system", "content": "s" * 50},
        {"role": "user", "content": "u" * 50},
        _assistant_with_calls(["a1", "a2"]),
        _tool("a1", "x" * 200),   # 将被截掉的 assistant 的孤儿 tool
        _tool("a2", "y" * 200),
        _assistant_with_calls(["b1"]),
        _tool("b1", "z" * 100),
        {"role": "assistant", "content": "final"},
    ]
    out = w._trim(messages)
    # 尾部不得出现孤儿 tool（其 assistant 不在保留集内）
    kept_call_ids = {c["id"] for m in out if m.get("role") == "assistant"
                     for c in (m.get("tool_calls") or [])}
    for m in out:
        if m.get("role") == "tool":
            assert m["tool_call_id"] in kept_call_ids, f"孤儿 tool: {m['tool_call_id']}"
    assert out[0]["role"] == "system" and out[1]["role"] == "user"


def test_trim_noop_when_small():
    cfg = Config()
    cfg.context_char_budget = 10_000
    w = Worker.__new__(Worker)
    w.cfg = cfg
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    assert w._trim(messages) == messages


def test_trim_aggressive_keeps_head_and_tail():
    w = Worker.__new__(Worker)
    messages = ([{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
                + [_assistant_with_calls([f"id{i}"]) for i in range(10)])
    out = w._trim_aggressive(messages)
    assert out[0]["role"] == "system" and out[1]["role"] == "user"
    assert len(out) < len(messages)


def test_trim_aggressive_noop_when_short():
    w = Worker.__new__(Worker)
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
    assert w._trim_aggressive(messages) == messages


def test_trim_notice_contains_state_summary(tmp_path):
    """截断通知含自动状态摘要：flag 进度 + STATE.md + 最近 shell 命令（不再只让 LLM 自己读笔记）。"""
    from agent.flagger import FlagSubmitter
    cfg = Config()
    cfg.context_char_budget = 200
    w = Worker.__new__(Worker)
    w.cfg = cfg
    w.submitter = FlagSubmitter("a-01", 2)
    w.submitter.record("flag{a}", True, 100)
    w.state_path = str(tmp_path / "STATE.md")
    with open(w.state_path, "w") as f:
        f.write("## FACTS\n- 端口 80/tcp open（http）\n")
    tail = [
        {"role": "assistant", "content": "",
         "tool_calls": [{"id": "x1", "type": "function",
                         "function": {"name": "shell", "arguments": '{"command": "curl -s http://10.0.0.1/admin"}'}}]},
        {"role": "tool", "tool_call_id": "x1", "content": "ok"},
    ]
    notice = w._build_truncate_notice(tail)
    assert "1/2" in notice["content"]          # flag 进度
    assert "端口 80/tcp open" in notice["content"]  # STATE.md 的 FACTS
    assert "curl -s http://10.0.0.1/admin" in notice["content"]  # 最近命令
    assert "NOTES.md" in notice["content"]
