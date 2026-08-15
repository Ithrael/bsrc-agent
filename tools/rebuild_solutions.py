#!/usr/bin/env python3
"""从平台运行日志重建 solutions.json（跨轮解法复用）。

worker 在 claude 模式把解法 note 分块打到 stdout（[SOLNOTE] 标签），
托管容器销毁后 solutions.json 丢失；赛后把平台日志保存为文本：

    grep '\[SOLNOTE\]' run.log | python3 tools/rebuild_solutions.py solutions.json

重建的 entry 结构与 _record_claude_solution 一致（note/completed/elapsed_min），
下一轮 docker build 时 COPY 进镜像即可让已解题直接复现。
"""
import json
import re
import sys


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "solutions.json"
    entries: dict[str, dict] = {}
    pat = re.compile(r"\[SOLNOTE\]\s+(\S+)\|(\w+)\|(\d+)\|(.*)$")
    for line in sys.stdin:
        m = pat.search(line)
        if not m:
            continue
        code, tag, idx, chunk = m.group(1), m.group(2), int(m.group(3)), m.group(4)
        e = entries.setdefault(code, {"chunks": {}, "tag": tag})
        e["chunks"][idx] = chunk
        e["tag"] = tag  # 最后一笔决定 tag
    lib = {}
    for code, e in sorted(entries.items()):
        note = "".join(e["chunks"][i] for i in sorted(e["chunks"]))
        lib[code] = {"note": note, "completed": e["tag"] == "SOLVED", "elapsed_min": 0.0}
    with open(out, "w") as f:
        json.dump(lib, f, ensure_ascii=False, indent=2)
    print(f"重建 {len(lib)} 题解法 -> {out}")


if __name__ == "__main__":
    main()
