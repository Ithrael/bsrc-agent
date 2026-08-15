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
CODE_RE = re.compile(r"(?i)(?:编号|challenge|unique_code)[:：\s]+([a-z]\d?-\d{2})\b")
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
                               for m in re.finditer(r"(?i)(?:challenge\s+|\[)([a-z]\d?-\d{2})\b", t)))
        if not codes:
            continue
        last = all_texts_assistant[-1] if all_texts_assistant else ""
        if not last:
            continue
        note = REDACT_RE.sub("flag{REDACTED}", last)[-3000:]
        for code in codes:
            if code not in lib or len(note) > len(lib[code].get("note") or ""):
                lib[code] = {
                    "note": note,
                    "completed": True,
                    "elapsed_min": 0.0,
                }
        print(f"  [{i}] 会话 {sid} → {codes}（assistant 尾文本 {len(last)} 字符）")

    with open(out, "w") as f:
        json.dump(lib, f, ensure_ascii=False, indent=2)
    print(f"重建 {len(lib)} 题解法 -> {out}")


if __name__ == "__main__":
    main()
