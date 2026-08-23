#!/usr/bin/env python3
"""从平台 LLM 会话数据提取每题解法，重建 solutions.json（跨轮复用）。

用法：
  TOKEN=<jwt> python3 tools/fetch_sessions.py <run_id> [output.json]

流程：拉会话列表 → 逐会话拉详情（steps 分页）→ 题号从 user prompt
（「编号: b-01」）提取 → 解法摘要取最后一条 assistant 文本 → 输出 solutions.json。
"""
import json
import os
import re
import sys

import httpx

BASE = "https://tsecbench.zc.tencent.com/api/v1"
TOKEN = os.environ.get("TOKEN", "")
# 题号格式：v1 的 a-01/b-02/e1-03 与百度活动集的 bctf-04（多字母前缀）
CODE_RE = re.compile(r"(?i)(?:编号|challenge|unique_code)[:：\s]+([a-z][a-z0-9]*-[0-9]{2,3})\b")
REDACT_RE = re.compile(r"flag\{[^}]{1,120}\}")

if not TOKEN:
    print("需要 JWT：TOKEN=eyJ... python3 tools/fetch_sessions.py 9489", file=sys.stderr)
    sys.exit(1)


def api(client: httpx.Client, path: str, **params) -> dict:
    r = client.get(f"{BASE}{path}", params=params,
                   headers={"authorization": f"Bearer {TOKEN}"})
    r.raise_for_status()
    return r.json()


def extract_texts(detail: dict, role: str) -> list[str]:
    """从会话详情 steps 提取指定 role 的文本（跳过 thinking）。"""
    out = []
    for st in detail.get("steps") or []:
        for it in st.get("items") or []:
            if it.get("role") != role:
                continue
            if it.get("kind") == "thinking":
                continue
            t = (it.get("text") or "").strip()
            if t:
                out.append(t)
    return out


def _dicts(value):
    """递归遍历状态/事件中的 dict，兼容平台不同版本的嵌套字段。"""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _dicts(child)


def _progress(d: dict) -> tuple[int | None, int | None]:
    """提取平台进度；没有同时拿到当前数和总数时返回 (None, None)。"""
    current_keys = ("correct_flag_count", "correct_flags", "answered_flag_count")
    total_keys = ("total_flag_count", "flag_count", "total_flags")
    current = next((d.get(k) for k in current_keys if isinstance(d.get(k), int)), None)
    total = next((d.get(k) for k in total_keys if isinstance(d.get(k), int)), None)
    if current is None or total is None or total <= 0:
        return None, None
    return current, total


def _code(d: dict) -> str:
    return str(d.get("challenge_code") or d.get("unique_code") or d.get("code") or "").lower()


def main():
    run_id = sys.argv[1] if len(sys.argv) > 1 else "9489"
    out = sys.argv[2] if len(sys.argv) > 2 else "solutions.json"
    client = httpx.Client(timeout=60)

    # 1. 会话列表（分页拿全）
    sessions = []
    page = 1
    while True:
        j = api(client, f"/runs/{run_id}/llm/sessions", page=page, page_size=50)
        items = j.get("items") or []
        sessions.extend(items)
        total_pages = (j.get("pagination") or {}).get("total_pages") or 0
        if page >= total_pages or not items:
            break
        page += 1
    print(f"会话总数: {len(sessions)}")

    # 2. 逐会话拉详情，提取题号 + 最后 assistant 文本
    lib = {}
    session_flag_counts: dict[str, int] = {}
    for i, s in enumerate(sessions):
        sid = s.get("session_id")
        frm = s.get("range_first_captured_at") or s.get("first_captured_at") or ""
        to = s.get("range_last_captured_at") or s.get("last_active_at") or ""
        if not sid or not frm or not to:
            continue
        # 详情分页拿全
        all_texts_user: list[str] = []
        all_texts_assistant: list[str] = []
        p = 1
        try:
            while True:
                j = api(client, f"/runs/{run_id}/llm/sessions/{sid}",
                        **{"from": frm, "to": to, "page": p, "page_size": 50})
                all_texts_user.extend(extract_texts(j, "user"))
                all_texts_assistant.extend(extract_texts(j, "assistant"))
                pg = j.get("pagination") or {}
                if p >= (pg.get("total_pages") or 1) or not (j.get("steps")):
                    break
                p += 1
        except Exception as e:
            print(f"  [{i}] 会话 {sid} 拉取失败: {e}")
            continue
        # 题号：user prompt 里「编号: b-01」
        codes = sorted(set(m.group(1).lower()
                           for t in all_texts_user for m in CODE_RE.finditer(t)))
        if not codes:
            # 兜底：assistant 文本里的 [x-xx] / Challenge x-xx
            codes = sorted(set(m.group(1).lower()
                               for t in all_texts_assistant
                               for m in re.finditer(r"(?i)(?:challenge\s+|\[)([a-z][a-z0-9]*-[0-9]{2,3})\b", t)))
        if not codes:
            continue
        # Claude 初始 prompt 会带「flag 数量: N」，作为事件缺少 total_flag_count
        # 时的最后一个辅助证据（仍要求 answer_correct 的去重索引达到 N）。
        for code in codes:
            for t in all_texts_user:
                m = re.search(r"(?i)flag\s*数量\s*[:：]\s*(\d+)", t)
                if m:
                    session_flag_counts[code] = max(session_flag_counts.get(code, 0), int(m.group(1)))
                    break
        if not all_texts_assistant:
            continue
        # note 取法：从后往前拼 assistant 文本直到 ≥2000 字符——claude 在提交成功后
        # 的收尾段里有完整解法总结（最后一条单句只有 "Flag submitted..."，解法在前几段）
        parts: list[str] = []
        total = 0
        for t in reversed(all_texts_assistant):
            if t in parts:
                continue  # 会话内重复文本（重跑/分治线互相引用）去重
            parts.append(t)
            total += len(t)
            if total >= 2000:
                break
        note = REDACT_RE.sub("flag{REDACTED}", "\n\n".join(reversed(parts)))[-3000:]
        # completed 判定：note 里出现提交成功信号（否则是超时/未解的 partial）。
        # 信号从宽：断点重跑/分治线也会提及首轮提交成功（duplicate），漏判代价
        # 是走短时复现通道，有「复现失败 12 步→harness 重探索」兜底，利大于弊。
        ok = bool(re.search(r"(?i)(correct|awarded|duplicate|1/1)", note))
        for code in codes:
            cur = lib.get(code)
            if (cur is None or ok > cur.get("completed", False)
                    or (ok == cur.get("completed", False)
                        and len(note) > len(cur.get("note") or ""))):
                lib[code] = {
                    "note": note,
                    "completed": ok,
                    "elapsed_min": 0.0,
                }
        print(f"  [{i}] 会话 {sid} → {codes}（note {len(note)} 字符, completed={ok}）")

    # 3. 平台事件校正：单个 answer_correct 只代表拿到一面，不能直接把多 flag
    # 题标成 completed。只有事件/状态明确给出全量进度，或去重后的 flag index 达到
    # 题目总面数，才允许标记完成；否则保留为 partial，避免下一轮跳过剩余 flag。
    try:
        ev = api(client, f"/runs/{run_id}/status")
        answered = set()
        completed = set()
        indices: dict[str, set[int]] = {}
        for event in (ev.get("run_events") or []):
            for e in _dicts(event):
                code = _code(e)
                if e.get("operation_type") != "answer_correct" or not code:
                    continue
                answered.add(code)
                current, total = _progress(e)
                if e.get("completed") is True or e.get("is_completed") is True \
                        or e.get("all_flags_correct") is True \
                        or (current is not None and total is not None and current >= total):
                    completed.add(code)
                idx = e.get("matched_flag_index")
                if isinstance(idx, int):
                    indices.setdefault(code, set()).add(idx)
        # 有些状态版本把最终题目进度放在 run status 的 challenges 列表里，
        # 不属于 run_events，统一扫描一次。
        for d in _dicts(ev):
            code = _code(d)
            if not code:
                continue
            current, total = _progress(d)
            if d.get("is_completed") is True or d.get("completed") is True \
                    or (current is not None and total is not None and current >= total):
                completed.add(code)
        for code, seen in indices.items():
            expected = session_flag_counts.get(code)
            if expected and len(seen) >= expected:
                completed.add(code)
        fixed = 0
        for code in completed:
            if code in lib and not lib[code]["completed"]:
                lib[code]["completed"] = True
                fixed += 1
        for code in list(lib):
            if lib[code]["completed"] and code not in completed:
                # 只要该 run 有该题的 answer_correct 事件却没有全量证据，
                # 必须降为 partial；否则最危险的误判仍会把多 flag 题跳过。
                if code in answered:
                    lib[code]["completed"] = False
                    lib[code]["partial"] = True
                    fixed += 1
        print(f"平台事件校正: {len(answered)} 题有正确事件，{len(completed)} 题确认全通，修正 {fixed} 题")
    except Exception as e:
        print(f"平台事件校正失败（跳过）: {e}")

    with open(out, "w") as f:
        json.dump(lib, f, ensure_ascii=False, indent=2)
    print(f"重建 {len(lib)} 题解法 -> {out}")


if __name__ == "__main__":
    main()
