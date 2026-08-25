"""flag 自动捕获：扫描所有工具输出里的 flag 模式，去重后自动提交。

答错无惩罚（平台幂等、duplicate 只针对已正确的 flag），但错提仍烧提交请求、
污染事件流（run 10282 实测 111 次错提 vs 榜首 2 次）——提取保持宽模式，
提交前统一过 plausible_flag 格式闸门。
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


# 提交闸门：平台 flag 实测两形态——flag{UUID}（主流）/ flag{leetspeak}（f 系列二进制题）。
# UUID 形态天然严格；leetspeak 内部要求含数字（真 flag 如 x73a_f31st3l 混数字，
# 模型瞎编的纯英文短语 flag{this_is_flag} 无数字），再叠加常见占位词黑名单。
_PLAUSIBLE = re.compile(
    r"(?i)^flag-(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
    r"|^flag\{([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-z_]{8,64})\}$")
_JUNK_INNER = {"flag", "test", "xxx", "example", "placeholder", "sample",
               "dummy", "your_flag", "here", "todo", "redacted", "censored",
               "mock", "fake", "guess", "example_flag", "the_flag", "found"}


def plausible_flag(flag: str) -> bool:
    """提交前格式闸门：所有提交通道（LLM 工具/harness 输出捕获/调度器直连）统一过这里。

    拒绝占位符、纯英文短语瞎编、其他前缀（KEY{...}/TSEC{...} 等提取兜底形态）。
    提取可以宽（错提无惩罚），提交必须严（省请求、降噪音）。"""
    f = (flag or "").strip()
    m = _PLAUSIBLE.match(f)
    if not m:
        return False
    inner = (m.group(1) or "").lower()
    if not inner:
        return True  # flag-<uuid> 裸形态（UUID 严格，不可能误伤）
    if "-" in inner:
        return True  # flag{uuid} 形态
    if inner in _JUNK_INNER:
        return False
    # leetspeak 形态：真 flag 混数字（leet 本义），纯字母短语按瞎编处理
    return any(c.isdigit() for c in inner)


class FlagSubmitter:
    """每题一个：记录已提交/已正确的 flag，避免重复提交。

    ``correct_count`` 以平台返回的进度为准。重试同一题时，之前已正确的
    flag 值本身不可从平台反查，不能只依赖本地 ``correct`` 集合判断完成。

    错提熔断（run 12464 复盘：145 次错提全部绕过 submit_flag.sh 闸门——
    输出捕获通道直接调 API，f2-05 盲猜 75 次、c-02 答对了还错 23 次）：
    ``auto=True`` 的自动通道（正则捕获）累计错提 ≥ wrong_cap 次后关闭；
    显式通道（LLM 的 submit_flag 工具调用）不熔断——c-02 错 23 次仍解出，
    说明正确 flag 可能出现在多次错误之后，不能一刀切。
    """

    def __init__(self, unique_code: str, expected_flags: int,
                 initial_correct_count: int = 0, wrong_cap: int = 10):
        self.unique_code = unique_code
        self.expected_flags = expected_flags
        self.tried: set[str] = set()
        self.correct: set[str] = set()
        self.score = 0
        self.correct_count = max(0, min(expected_flags, initial_correct_count))
        self.wrong_streak = 0  # 连续提交错误计数（run 12019 复盘：f2-05 连错 10 次盲猜）
        self.wrong_total = 0   # 累计错提（auto 通道熔断用，不因正确提交清零）
        self.wrong_cap = wrong_cap

    @property
    def completed(self) -> bool:
        return self.correct_count >= self.expected_flags

    def should_try(self, flag: str, auto: bool = False) -> bool:
        flag = flag.strip()
        # auto 通道熔断：正则捕获流错提打满 cap，说明输出里全是垃圾候选
        if auto and self.wrong_total >= self.wrong_cap:
            return False
        # 格式闸门收口在 should_try：所有提交通道（含调度器 harness worker 的
        # api.submit_flag 直连）都先问 should_try，垃圾候选在这里统一拦截。
        return bool(flag) and flag not in self.tried and plausible_flag(flag)

    def record(self, flag: str, correct: bool, awarded: int,
               correct_count: int | None = None):
        self.tried.add(flag)
        if correct:
            self.wrong_streak = 0
            if flag not in self.correct:
                self.correct.add(flag)
                self.score += awarded
            self.correct_count = max(
                self.correct_count,
                len(self.correct),
                min(self.expected_flags, correct_count or 0),
            )
        else:
            self.wrong_streak += 1
            self.wrong_total += 1
