#!/usr/bin/env python3
"""构建离线漏洞库索引 poc-index.json（Docker 构建期运行；本地开发可手动跑）。

运行时精确查索引（O(1)），替代每个 Agent 在几百 MB 文档里递归 find/grep：
  components: 组件/技术名（小写）→ vulhub 目录/README、PayloadsAllTheThings 目录
  cves:       CVE 编号（小写）→ PoC-in-GitHub JSON、nuclei 模板、vulhub CVE 子目录

用法: python3 build_poc_index.py [pocs_root] [nuclei_root] [out_path]
"""
from __future__ import annotations

import json
import os
import re
import sys

_CVE_NAME = re.compile(r"^(cve-\d{4}-\d{4,7})$", re.I)
_MAX_PATHS = 8  # 每个条目最多索引的路径数（vulhub 一个组件目录可含几十个 CVE 子目录）


def _add(mapping: dict[str, list[str]], key: str, path: str):
    lst = mapping.setdefault(key, [])
    if path not in lst and len(lst) < _MAX_PATHS:
        lst.append(path)


def build_index(pocs_root: str, nuclei_root: str) -> dict:
    components: dict[str, list[str]] = {}
    cves: dict[str, list[str]] = {}

    # vulhub：组件目录（含 README 利用链）+ CVE 子目录
    vulhub = os.path.join(pocs_root, "vulhub")
    if os.path.isdir(vulhub):
        for name in sorted(os.listdir(vulhub)):
            comp_dir = os.path.join(vulhub, name)
            if not os.path.isdir(comp_dir) or name.startswith("."):
                continue
            key = name.lower()
            _add(components, key, comp_dir)
            for f in sorted(os.listdir(comp_dir)):
                if f.lower().startswith("readme") and f.lower().endswith(".md"):
                    _add(components, key, os.path.join(comp_dir, f))
            for sub in sorted(os.listdir(comp_dir)):
                if _CVE_NAME.match(sub):
                    _add(cves, sub.lower(), os.path.join(comp_dir, sub))

    # PoC-in-GitHub：<year>/CVE-XXXX-XXXX.json
    pocgh = os.path.join(pocs_root, "PoC-in-GitHub")
    if os.path.isdir(pocgh):
        for year in sorted(os.listdir(pocgh)):
            year_dir = os.path.join(pocgh, year)
            if not os.path.isdir(year_dir):
                continue
            for f in sorted(os.listdir(year_dir)):
                m = re.match(r"^(cve-\d{4}-\d{4,7})\.json$", f, re.I)
                if m:
                    _add(cves, m.group(1).lower(), os.path.join(year_dir, f))

    # nuclei 模板：任意深度的 CVE-*.yaml
    if os.path.isdir(nuclei_root):
        for root, dirs, files in os.walk(nuclei_root):
            dirs[:] = [d for d in dirs if d != ".git"]
            for f in files:
                m = re.match(r"^(cve-\d{4}-\d{4,7})\.ya?ml$", f, re.I)
                if m:
                    _add(cves, m.group(1).lower(), os.path.join(root, f))

    # PayloadsAllTheThings：技术目录（SQL Injection 等）——运行时按关键词命中即给目录
    pat = os.path.join(pocs_root, "PayloadsAllTheThings")
    if os.path.isdir(pat):
        for name in sorted(os.listdir(pat)):
            d = os.path.join(pat, name)
            if os.path.isdir(d) and not name.startswith("."):
                _add(components, name.lower(), d)

    return {"components": components, "cves": cves}


def main() -> int:
    pocs_root = sys.argv[1] if len(sys.argv) > 1 else "/opt/pocs"
    nuclei_root = sys.argv[2] if len(sys.argv) > 2 else "/opt/nuclei-templates"
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(pocs_root, "poc-index.json")
    idx = build_index(pocs_root, nuclei_root)
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(idx, f, ensure_ascii=False, separators=(",", ":"))
    os.replace(tmp, out)
    print(f"poc-index.json: {len(idx['components'])} components, {len(idx['cves'])} cves -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
