"""flag 自动捕获：扫描所有工具输出里的 flag 模式，去重后自动提交。

答错无惩罚（平台幂等、duplicate 只针对已正确的 flag），所以宁可错杀不可放过。
"""
from __future__ import annotations

import logging
import re

log = logging.getLogger("flagger")

# 常见 flag 形态：flag{...} / FLAG{...} / flag-uuid / key{...} / tsec{...} 等。
# 平台已知全为 flag{uuid} 形态，宽模式只为兜底未知命名；错提无惩罚。
_PATTERNS = [
    re.compile(r"(?i)\bflag\{[^\s}]{1,300}\}"),
    re.compile(r"(?i)\bkey\{[^\s}]{1,300}\}"),
    re.compile(r"(?i)\b(?:tsec|tsrc|ctf|bsrc|hack)\{[^\s}]{1,300}\}"),
    re.compile(r"\bflag-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
    # 全大写前缀兜底（TSEC{...}、SECRET{...} 等）；不用小写前缀，避免误抓 JS 对象字面量
    re.compile(r"\b[A-Z][A-Z0-9_]{2,}\{[^}\s]{8,300}\}"),
]


def extract_flags(text: str) -> list[str]:
    found: list[str] = []
    for pat in _PATTERNS:
        for m in pat.finditer(text or ""):
            f = m.group(0)
            if f not in found:
                found.append(f)
    return found


class FlagSubmitter:
    """每题一个：记录已提交/已正确的 flag，避免重复提交。"""

    def __init__(self, unique_code: str, expected_flags: int):
        self.unique_code = unique_code
        self.expected_flags = expected_flags
        self.tried: set[str] = set()
        self.correct: set[str] = set()
        self.score = 0

    @property
    def completed(self) -> bool:
        return len(self.correct) >= self.expected_flags

    def should_try(self, flag: str) -> bool:
        flag = flag.strip()
        return bool(flag) and flag not in self.tried

    def record(self, flag: str, correct: bool, awarded: int):
        self.tried.add(flag)
        if correct:
            self.correct.add(flag)
            self.score += awarded
