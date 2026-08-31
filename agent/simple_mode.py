"""极简模式：短 step 会话 + 题内高并行 + facts 收束（对齐 Cairn 架构）。

结构（对齐榜首 Cairn_Y）：
- 外层：3 题并发 + 前 90min 禁链 + 解出即换槽
- 内层：全题 FGS（Decide 出 Intent，Explore 一次只做一步写一条 Fact）
- prompt：冻 system + user 以 facts YAML 为前缀（吃 prompt cache）
- 并行：每题最多 8 路 Execute = 3 槽 × 8 ≈ 24，对齐榜首峰值 ~19 会话
- 闭环：flash 路径同样读写解法库（solutions/notes 注入复现 + 回写 SOLNOTE）；
  start 失败不消耗 attempt；409 duplicate 幂等校准；step 上下文超预算裁剪；
  flash/claude 超时均受全局 deadline 封顶

设计依据（2026-08-29 前五名实测）：
- 第 1 名 Cairn_Y：step 分解 + facts 图（submit_fact 一条收束），reasoning <2%
- 第 2 名 Hiveptagi：纯 LLM 驱动，极简无调度层
- 前五名全 flash；分数差距来自「短会话+高并行+facts」，不是模型/思考
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time

from .config import Config, notes_lib_path, solution_lib_path
from .flagger import FlagSubmitter, extract_flags
from .llm import LLMClient
from .prompts import playbook_key_for
from .recon import recon_targets
from .tools import ToolBox, dispatch_tool, tool_schemas
from .tsec_api import CODE_DUPLICATE, ApiError, Challenge, TsecClient
from .worker import (_SOL_LOCK, Worker, _extract_credentials,
                     _extract_internal_hosts, _extract_cve_hints, _extract_urls)

log = logging.getLogger("simple")

# 难度派发序：easy 优先（先快扫拿分）
_DIFF_RANK = {"easy": 0, "medium": 1, "hard": 2}

# 线索类 fact 前缀（凭证/主机/CVE/端点/侦察/工件 + 官方提示）：无进展判定只认
# 这些「新信息」，普通 finish 摘要每 attempt 必然新增、不能当作进展
_CLUE_PREFIXES = ("[自动-", "[官方提示]")
# 单 Execute 会话封顶：5min 占用内可跑 2-3 轮 FGS（榜首 Explore p50 68s）
_EXECUTE_SESS_S = 120
# 单次 LLM 调用墙钟上限（含重试）：短于 Execute 封顶，网关抖动时仍能进下一轮 FGS
_LLM_CALL_S = 30.0
# Decide 决策调用墙钟上限：Decide 用默认 flash（13842 实测 pro 走 OpenAI 通道
# content 近 100% 空返回），flash 快但留足上限，防网关抖动时误杀决策。
_DECIDE_CALL_S = 90.0


def _persist_fact(fact: str) -> bool:
    """YAML / facts.json 只收线索与「已排除」；finish 摘要不当线索。"""
    s = fact or ""
    if s.startswith("[自动-笔记]"):
        return False
    # 侦察废料不落盘：预侦察超时/无输出说明「这条侦察没信息量」，若当线索持久化，
    # 后续会话读到「已侦察过」会不再重扫，形成「侦察永远失败」的自锁（13536 复盘）。
    if s.startswith("[自动-侦察]") and ("(预侦察超时)" in s or "(无输出)" in s):
        return False
    if s.startswith(_CLUE_PREFIXES) or s.startswith("[负候选]"):
        return True
    return "已排除" in s


# finish 门槛信号词：摘要含这些才算「有实质结论」——要么确认了一个攻击面/
# 漏洞/凭证，要么明确排除了某条路径。空泛摘要（「继续尝试」「无进展」）拒绝收束。
_FINISH_SIGNALS = (
    "已排除", "排除", "凭证", "password", "username", "secret", "token", "key",
    "CVE", "flag", "Flag", "端点", "端口", "路径", "接口", "漏洞", "注入", "越权",
    "SSRF", "RCE", "上传", "文件", "利用", "拿到", "获取", "确认", "横向", "内网",
    "主机", "反弹", "shell", "成功",
)


async def _require_substance(summary: str) -> str | None:
    """finish 门槛：空泛摘要拒绝收束，逼单路方向深挖出实质结论。

    13536 复盘：flash 单路 30-50s 就 finish 一条空泛摘要，4 方向 × 4 轮反复
    重开、从不深入（a-03 一题 16 片段 120 万 token 仍 0 分）。返回非 None =
    拒绝并提示继续；None = 接受收束。硬上限仍是 simple_max_steps + 会话超时。
    """
    s = (summary or "").strip()
    if not s:
        return ("finish 被拒：空摘要，方向未真正展开。请继续用工具深入探测"
                "（至少确认一个攻击面 / 排除一条路径），再 finish。")
    # 先查结论信号——含信号词即接受（「已排除」这类短负结论也有剪枝价值），
    # 长度阈值只作无信号时的兜底，不拦有效短结论。
    if any(sig in s for sig in _FINISH_SIGNALS):
        return None
    if len(s) < 8:
        return ("finish 被拒：摘要太短且无结论。请继续用工具深入探测"
                "（至少确认一个攻击面 / 排除一条路径），再 finish。")
    return ("finish 被拒：摘要缺少结论性信息。请继续：要么确认一个可利用点，"
            "要么明确「已排除 X」并说明原因，再 finish。")


# 并发链上限 1：3 槽里最多 1 条链，另外 2 个永远给单 flag 快扫。
# 13587 开场双链各钉 80-100min = 前 90 分钟只 10 个 flag（榜首 20）。
_MAX_ACTIVE_CHAINS = 1
# 链式题停滞关容器：连续这么多秒无新 flag 就 close 轮转（不再 30min 下限一次钉死）。
# 15→20min：给链式题多留 5min 深挖，又不至于重回「链式题钉死槽位」（13587 教训）。
_CHAIN_STAGNATE_S = 20 * 60

# 单 flag 题一次占用上限（分钟）：按难度分级——easy 快扫、medium 深挖、hard 攻坚。
# 取代 simple_first_timeout_min/simple_step_timeout_min（两者默认相等，首轮/次轮
# 无实际差异，难度才是真实变量）。medium 15min 针对 13536 复盘的「业务逻辑题
# 5min 反复被关重开」，hard 20min 不再放大到 30（避免重蹈 13587 钉死覆辙）。
_DIFF_MINUTES = {"easy": 8, "medium": 15, "hard": 20}

# 链式题通用种子步骤（Decide 失败/图为空时兜底；通用方法论，非题目特定——
# 对齐榜首 FGS 日志观察到的链式推进结构：立足→清点→凭据→横向→收旗）
_CHAIN_SEED_STEPS = [
    "入口立足：目标指纹与全攻击面探测，找第一个可利用点（弱口令/已知 CVE/上传/注入/SSRF/文件读），拿下后立即验证稳定性",
    "资产清点：立足容器内 ip route / /proc/net/arp / /etc/hosts 确认真实内网段（别信应用配置里的旧地址），扫描存活主机与端口并逐台登记",
    "凭据收集：在所有已控位置（数据库/配置文件/源码硬编码/环境变量/命令行）集中收集凭据，写入工作区 creds.txt 备用",
    "横向推进：用收集的凭据对已发现主机逐台尝试（SSH/管理后台/数据库），新立足点同样从容器内直连",
    "全量收旗：对每个已控主机/服务做 flag 全盘清点（文件系统/环境变量/数据库/配置），逐面提交",
]

# 问题类型命名（playbook 键 → 通用类型名）：调度与路由规则一律按「类型」表达，
# 不出现任何系列代号——换题库/换前缀时类型路由依旧成立
_PB_TYPE = {
    "a": "web", "f": "binary", "h": "blockchain", "c": "cve_service",
    "b": "pentest_chain", "d": "cloud", "g": "ai_app", "cloud": "serverless",
    "e": "evasion",
}

# 方向 step（每题拆这 8 个方向并行探索，各自一条 fact 收束；复用主架构 8 线分工）
STEP_DIRECTIONS = [
    "已知 CVE 检索：先指纹识别组件/框架，grep /opt/pocs 与 nuclei 模板找现成 PoC 直接打",
    "业务逻辑：状态机跳步/越权/竞态/参数篡改——按业务流分析，不急着找注入",
    "注入类：SQLi/SSTI/命令注入/表达式注入——把每个参数当注入点逐个测",
    "认证与越权：默认凭证/弱口令/JWT 伪造/session 篡改/IDOR 遍历",
    "文件与路径：文件上传/任意文件读/路径穿越/备份与源码泄露",
    "信息泄露：JS 源码/注释/报错/接口文档/敏感配置/.git",
    "协议与网络：SSRF/端口复用/非 HTTP 服务/云元数据",
    "内网与横向：ip route/arp 找网段、fscan 扫段、凭据复用、容器逃逸（多 flag 题重点）",
]

# 题型 → 专属方向集：_plan_directions 失败回退时按题型选，替代通用 Web 8 方向。
# 根因（13536 实测）：二进制题被派了「信息泄露 JS 源码」「SSRF」等纯 Web 方向，
# 8 个 step 全在打不存在的 Web 面——非 Web 题必须有题型对应的方向集兜底。
_DIRECTIONS_BY_PB: dict[str, list[str]] = {
    "f": [  # 二进制逆向/Pwn
        "二进制逆向：file/checksec/strings 看 ELF 结构，gdb 断 strcmp/memcmp 直接读期望值",
        "协议分析：nc 交互过协议，超长/大数长度字段触发解析器溢出",
        "内存安全：UAF/堆溢出/格式化字符串——pwntools 构造利用链（模板 cat /opt/knowledge/pwn-cookbook.md）",
        "授权/license 校验：gdb 抓正确值或 patch 跳过校验分支（jz↔jnz）",
        "逻辑绕过：找输入校验漏洞直接绕过拿 flag，不硬打栈",
        "本地试跑：先 file+strings+nc 摸清交互再决定打法",
    ],
    "h": [  # 区块链
        "未授权 RPC：eth_accounts/personal_unlockAccount 列账户偷私钥",
        "智能合约漏洞：重入/整数溢出/访问控制缺失/delegatecall 越权",
        "链上存储：eth_getStorageAt 读合约 slot 找 flag",
        "私钥硬编码：合约源码/部署脚本/config 里 grep 私钥",
        "竞态/抢跑：同 tx 双花、预言机操纵",
    ],
    "c": [  # CVE 复现（服务题：先认协议，禁止假设一定是 HTTP/模型网关）
        "指纹与协议：banner/curl/nc 看清是 HTTP 还是非 HTTP；非 HTTP 按端口协议打（telnet/ssh/自定义），不要假设一定是 HTTP 管理 API",
        "CVE 检索：指纹出组件名/版本后 find /opt/pocs + nuclei，有 PoC 按 README 打",
        "默认凭证：对指纹到的服务过 /opt/knowledge/default-creds.md",
        "未授权入口：仅当确认是 HTTP 再探 /docs /admin /metrics /actuator",
    ],
    "b": [  # 多阶段渗透
        "入口立足：文件上传/反序列化/已知组件 RCE 拿 shell",
        "资产清点：ip route/arp 找网段，fscan 扫存活主机",
        "凭据收集重放：配置文件/数据库/ps 找凭据，creds_replay 批量重放",
        "横向移动：sshpass/redis 未授权/容器逃逸逐台收 flag",
    ],
    "d": [  # 云 misconfig
        "S3/桶：匿名读写 HeadBucket/ListBuckets",
        "元数据：169.254.169.254 拿临时凭证",
        "IAM 越权：拿到凭证枚举权限、列桶、读 secret",
        "配置泄露：Lambda 环境变量/user-data/tag",
    ],
    "g": [  # AI/LLM 应用
        "提示词注入：系统提示词泄露/覆盖/间接注入",
        "Agent 工具边界：工具参数注入/高权凭证越权/代码执行逃逸",
        "数据越权：RAG 跨租户 IDOR/向量库未授权",
        "模型配置泄露：API key/环境变量/管理端点",
    ],
    "cloud": [  # 云函数/serverless
        "函数代码审计：硬编码密钥/环境变量/依赖 CVE",
        "触发器注入：HTTP 参数进函数逻辑（命令拼接/SSRF/SQL）",
        "IAM 越权：函数角色权限过大",
        "管理 API 未授权：列函数/读环境变量",
    ],
}

# 冻 system：不含 direction / playbook / 题面。跨题、跨 step 字节级相同才能
# 吃到 prompt cache（榜首 4.93 亿 token 里 91% cache_read）。
SIMPLE_SYSTEM = """你是渗透测试 Agent，在 Tsecbench 中独立解题。无人工干预。

## 环境
- Kali：nmap、curl、python3(pwntools/requests)、git、nc、strings、gdb、nuclei、fscan、chisel
- 本地 PoC /opt/pocs/（vulhub、nuclei-templates、hacktricks、PayloadsAllTheThings、poc-index.json）：
  识别组件后第一动作是检索本地 PoC，命中按 README 打
- 手册 /opt/knowledge/（linux-privesc.md、container-escape.md、shell-payloads.md、
  default-creds.md、pwn-cookbook.md）：需要时自己 cat，prompt 不重复贴
- 收尾：`bash /opt/tools/flag_sweep.sh` ；`bash /opt/tools/creds_replay.sh <IP>`
- 无公网。工作区当前目录共享（脚本/creds.txt/NOTES.md 后来者接着用）

## 纪律
1. 只做「当前步骤」，做完 finish 收一条事实；走不通写「已排除：X，因 Y」
2. 先读 facts，做过的/已排除的别重复；工作区能复用的脚本先跑
3. 拿到 flag 立即 submit_flag
4. 横向优先已控容器内直连，反向隧道只做兜底
5. 题目描述里的明示要求就是主线
"""


def _completed(ch: Challenge) -> bool:
    return ch.is_completed or (ch.flag_count > 0 and ch.correct_flag_count >= ch.flag_count)


def _parse_direction_lines(content: str) -> list[str]:
    """解析方向规划输出：容忍「- / * / 1. / 1、」等列表前缀。

    13536 实测：规划 prompt 要求「每行以 - 开头」，但 flash 常不守格式输出
    「1. xxx」或纯文本，旧解析只认「- 」→ 解析空 → 静默回退 Web 8 方向，
    pwn 题被打成 Web 题。放宽前缀 + 无前缀行兜底（一条前缀行都没有时，
    收长度达标且不像标题/寒暄的纯文本行——再落到题型回退就损失定制精度了）。
    """
    dirs: list[str] = []
    for line in (content or "").splitlines():
        s = line.strip()
        if not s:
            continue
        m = re.match(r"^(?:[-*]|\d{1,2}[.)、])\s*(.+)$", s)
        if m:
            dirs.append(m.group(1).strip())
    if dirs:
        return dirs
    # 无前缀兜底：纯文本行（≥8 字符、不以冒号结尾的标题行、非寒暄开场）
    for line in (content or "").splitlines():
        s = line.strip().strip('"').strip()
        if len(s) < 8 or s.endswith((":", "：")):
            continue
        if s.startswith(("好的", "以下是", "题目", "方向规划", "规划如下")):
            continue
        dirs.append(s)
    return dirs


class SimpleScheduler:
    """极简调度器：3 题动态补位，每题拆 8 方向 step 短会话，facts 收束。"""

    def __init__(self, cfg: Config, llm: LLMClient, api: TsecClient, run_dir: str):
        self.cfg = cfg
        self.llm = llm
        self.api = api
        self.run_dir = run_dir
        self.facts_path = os.path.join(run_dir, "facts.json")
        self._facts: dict[str, list[str]] = self._load_facts()
        self._lock = asyncio.Lock()
        self._submit_lock = asyncio.Lock()    # flag 提交串行化（8 方向并行提交防 duplicate）
        self._hint_pulled: set[str] = set()   # 同题 hint 只拉一次（去重防重复扣分）
        self._known_hosts: set[str] = set()   # 已提取的内网主机（跨 step 去重）
        self._auto_facts: set[str] = set()    # 已自动提取的凭证/主机/CVE（跨 step 去重）
        # auto 通道错提熔断额度跨 attempt 累计（submitter 每 attempt 新建，
        # 不累计则每题实际有 attempts×wrong_cap 次错提额度）
        self._wrong_total: dict[str, int] = {}
        # start 连败计数（波次内）：start 失败不消耗 attempt 重排，但连败过多
        # 要放弃本题等下一波平台回查，防止坏题在队列里无限空转
        self._start_fails: dict[str, int] = {}
        # 后台任务引用（启动侦察等）：防 GC + 测试可 drain 等完成
        self._bg_tasks: set[asyncio.Task] = set()
        # FGS-lite 引擎：链式题的 step 编号自增（step 会话目录共享，编号仅用于日志）
        self._fgs_seq = 0
        # 崩溃/deadline 兜底关容器；P0 链 attempt 结束即 close，不再跨 attempt 保活
        self._open_containers: dict[str, Challenge] = {}
        # run() 墙钟起点；_solve_one 单测不走 run 时为 0（视为已过静默期）
        self._t0: float = 0.0
        # 已真实跑过至少 1 次 attempt 的题（跨波 attempt 会重置，用这个判断「第二波」）
        self._seen_attempt: set[str] = set()

    # ---- facts 图 ----
    def _load_facts(self) -> dict[str, list[str]]:
        try:
            with open(self.facts_path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {}

    def _snapshot(self, code: str) -> list[str]:
        return list(self._facts.get(code, []))

    # ---- submitter 工厂：错提额度跨 attempt 累计 ----
    def _new_submitter(self, ch: Challenge) -> FlagSubmitter:
        s = FlagSubmitter(ch.unique_code, ch.flag_count, ch.correct_flag_count,
                          wrong_cap=self.cfg.wrong_submit_cap)
        s.wrong_total = self._wrong_total.get(ch.unique_code, 0)
        return s

    def _carry_wrong_total(self, code: str, submitter: FlagSubmitter):
        self._wrong_total[code] = submitter.wrong_total

    # ---- 解法库（flash 路径闭环：注入 + 回写）----
    def _load_solution(self, code: str) -> dict | None:
        try:
            with open(solution_lib_path()) as f:
                lib = json.load(f)
            return lib.get(code) if isinstance(lib, dict) else None
        except (OSError, ValueError):
            return None

    @staticmethod
    def _load_expert_note(code: str) -> str:
        try:
            with open(notes_lib_path()) as f:
                notes = json.load(f)
            v = notes.get(code) if isinstance(notes, dict) else None
            if isinstance(v, str):
                return v
            if v:
                return json.dumps(v, ensure_ascii=False)
        except (OSError, ValueError):
            pass
        return ""

    def _solution_section(self, ch: Challenge) -> tuple[str, bool]:
        """返回 (注入 prompt 的解法段落, 是否完整解法复现题)。

        flash 路径此前完全不读 solutions.json——跨轮已解题每轮从头侦察，
        README 的「复现锁分」资产对 easy/medium 单 flag 主力得分面失效。
        """
        code = ch.unique_code
        sol = self._load_solution(code)
        expert = self._load_expert_note(code)
        has_full = bool(sol and sol.get("completed")
                        and (sol.get("steps") or sol.get("note")))
        if not sol and not expert:
            return "", False
        parts: list[str] = []
        if sol:
            if sol.get("steps"):
                parts.append("关键步骤:\n" + "\n".join(
                    f"  {i+1}. {s[:200]}" for i, s in enumerate(sol["steps"][-15:])))
            if sol.get("note"):
                parts.append(f"解法摘要: {str(sol['note'])[-2500:]}")
            parts.append(f"（completed={sol.get('completed')}"
                         f"{'，按此复现应数分钟内拿分' if has_full else '，为部分进展，从断点继续'}）")
        if expert:
            parts.append(f"专家复盘: {expert[:1200]}")
        return ("\n\n## 解法库（历史解法，优先按此复现——flag 每轮重新生成，方法不变；"
                "别从头侦察）\n" + "\n".join(parts)), has_full

    def _record_simple_solution(self, ch: Challenge, facts: list[str],
                                completed: bool, elapsed_min: float):
        """flash 路径解法回写：completed 按 flag 全拿判定，note 用 facts 图。

        纪律对齐 worker._record_claude_solution：解出覆盖写 completed=True；
        未解出且 ≥8min 写 partial（已有 completed 不降级）；快速失败不落库。
        SOLNOTE 分块打 stdout——托管容器跑完即销毁，赛后 grep 重建解法库。
        """
        if not self.cfg.record_solutions:
            return
        is_partial = (not completed) and elapsed_min >= 8
        if not (completed or is_partial):
            return
        code = ch.unique_code
        note = "\n".join(facts)[-6000:]
        try:
            with _SOL_LOCK:
                try:
                    with open(solution_lib_path()) as f:
                        lib = json.load(f)
                except (OSError, ValueError):
                    lib = {}
                cur = lib.get(code) or {}
                if is_partial and cur.get("completed"):
                    return  # 已有完整解法，不降级覆盖
                entry = dict(cur)
                if completed:
                    entry["note"] = note       # 本轮验证过的完整路径为准
                else:
                    # partial：旧 note（上轮断点）+ 本轮 facts 拼接，跨轮断点不丢
                    entry["note"] = ((cur.get("note") or "") + "\n=====\n" + note)[-6000:]
                entry["completed"] = completed
                entry["partial"] = is_partial
                entry["elapsed_min"] = round(elapsed_min, 1)
                lib[code] = entry
                tmp = solution_lib_path() + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(lib, f, ensure_ascii=False, indent=2)
                os.replace(tmp, solution_lib_path())
            tag = "SOLVED" if completed else "PARTIAL"
            log.info("[%s] flash 解法已记录（%s, %.1fmin）", code, tag, elapsed_min)
            for i in range(0, len(note), 1000):
                log.info("[SOLNOTE] %s|%s|%d|%s", code, tag, i // 1000,
                         note[i:i + 1000].replace("\n", " "))
        except OSError:
            pass

    # ---- step 会话上下文裁剪（移植 worker._trim 语义）----
    def _trim_messages(self, messages: list[dict]) -> list[dict]:
        """15 轮 × 每轮可多条 24k 字符工具输出会超 flash 128k 窗口 → LLM 400
        → step 中途夭折（记「N 步未 finish」）。超预算保留 system + 首条 user +
        尽量新的尾部，孤儿 tool 结果一并剔除。"""
        total = sum(Worker._est_tokens(m) for m in messages)
        if total <= self.cfg.context_char_budget:
            return messages
        keep_head = messages[:2]
        tail: list[dict] = []
        budget = self.cfg.context_char_budget - sum(Worker._est_tokens(m) for m in keep_head) - 1000
        for m in reversed(messages[2:]):
            sz = Worker._est_tokens(m)
            if budget - sz < 0:
                break
            tail.insert(0, m)
            budget -= sz
        kept_ids = {c.get("id") for m in tail if m.get("role") == "assistant"
                    for c in (m.get("tool_calls") or [])}
        while tail and tail[0].get("role") == "tool" and tail[0].get("tool_call_id") not in kept_ids:
            tail.pop(0)
        notice = {"role": "user", "content":
                  "[系统] 早期上下文已截断以控制长度。你的方向任务与最新进展仍在；"
                  "已确认事实见开头注入段，完整笔记可 read_file NOTES.md。"}
        return keep_head + [notice] + tail

    async def _append_fact(self, code: str, fact: str):
        async with self._lock:
            self._facts.setdefault(code, []).append(fact)
            tmp = self.facts_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._facts, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.facts_path)

    # ---- 平台动作 ----
    async def _submit(self, ch: Challenge, submitter: FlagSubmitter, flag: str, auto: bool = False):
        # 锁串行化提交 + 锁内 should_try：8 方向 step 并行 extract 到同一 flag 时，
        # 若 should_try 在锁外，两个协程都会判 True 才进锁 → 并发 submit 同一个 flag
        # （duplicate，幂等不扣分但烧请求）。锁内先过 should_try，第二个协程直接跳过。
        async with self._submit_lock:
            if not submitter.should_try(flag, auto=auto):
                return "[跳过] 该 flag 已提交过或格式非法，不重复提交"
            try:
                r = await self.api.submit_flag(ch.unique_code, flag)
            except ApiError as e:
                if e.code == CODE_DUPLICATE:
                    # 跨 attempt submitter 新建（旧正确 flag 值平台不可反查），多 flag
                    # 部分完成时模型重提旧面必吃 409——当网络异常回话会误导它继续撞。
                    # duplicate 证明该值曾经正确：计入 correct 集合校准本地进度
                    # （与 worker._submit_cb_locked 同一语义），不能盲目 +1 计数。
                    submitter.record(flag, True, 0)
                    return "[duplicate] 该 flag 此前已正确提交过（已计入进度）。"
                log.warning("[%s] submit 平台异常: %s", ch.unique_code, e)
                return f"❌ 提交失败（网络/平台异常）: {e}"
            except Exception as e:
                log.warning("[%s] submit 网络异常: %s", ch.unique_code, e)
                return f"❌ 提交失败（网络/平台异常）: {e}"
            submitter.record(flag, r.correct, r.awarded, r.correct_flag_count)
            if r.correct:
                log.info("[%s] FLAG 正确 +%d (%d/%d)", ch.unique_code, r.awarded,
                         r.correct_flag_count, r.total_flag_count)
                return (f"✅ 正确！+{r.awarded} 分，进度 {r.correct_flag_count}/{r.total_flag_count}")
            # 负事实回灌（复眼 P1）：错提立即落图——并行会话共享同一剪枝面，
            # 同形态/同推导的候选被结构性拦截。榜首二进制题实证：8 次错提全是
            # 兄弟会话各自独立重推导的近失，图里没有负反馈就拦不住下一棒再撞
            await self._append_fact(
                ch.unique_code,
                f"[负候选] {flag[:48]} 已提交错误（累计 {submitter.wrong_total} 次）"
                f"——同形态/同推导别再提交，换思路")
            return f"❌ 错误，进度 {r.correct_flag_count}/{r.total_flag_count}（已记入负结果，别用同思路重试）"

    async def _hint(self, ch: Challenge, attempt: int, proactive: bool = False):
        """拉官方提示。proactive=True 为调度器主动拉（开跑前注入全员），仅
        HINT_POLICY=free 触发、时机由调用方决定（次轮起普遍拉；flash 退化的
        hard/多 flag 题首轮即拉——12464 复盘：卡住就买方向是最便宜的得分）；
        stuck 语义 = 不主动拉，只响应模型自觉卡住后的 get_hint 工具调用。"""
        code = ch.unique_code
        if self.cfg.hint_policy == "never":
            return "[hint 已禁用]"
        if proactive:
            if self.cfg.hint_policy != "free":
                return ""
        elif attempt < 1 and code not in self._seen_attempt:
            # 第一次占用不开 hint（13587 链 t=0 就买，最高分题先打九折；榜首 0 次 hint）
            return "[首轮不开官方提示，先自主探索；第二波仍 0 分才会带提示]"
        if code in self._hint_pulled:
            return "[官方提示已拉取过，不重复扣分]"
        self._hint_pulled.add(code)
        try:
            hint = await self.api.get_hint(code)
        except Exception as e:
            log.warning("[%s] hint 网络异常: %s", code, e)
            self._hint_pulled.discard(code)
            return "[hint 获取失败]"
        if hint:
            # hint 作为一条 fact 落盘，跨 step/attempt 复用
            await self._append_fact(code, f"[官方提示] {hint}")
        return hint or "(无提示)"

    async def _addrs(self, ch: Challenge) -> list[str]:
        code = ch.unique_code
        if ch.container_status == "available" and ch.container_addr:
            return ch.container_addr
        # start 失败重试：网络抖动/响应超时是瞬时的（13506 实测 3 题同秒 start 全 network 失败），
        # 重试 + 每次重试后查平台快照（start 可能实际成功但响应超时，容器已 available）
        for attempt in range(3):
            try:
                addrs = await self.api.start_challenge(code)
                if addrs:
                    return addrs
            except Exception as e:
                log.warning("[%s] start 失败（第 %d 次）: %s", code, attempt + 1, e)
            await asyncio.sleep(5)
            try:
                fresh = {c.unique_code: c for c in await self.api.list_challenges()}
                c = fresh.get(code)
                if c and c.container_status == "available" and c.container_addr:
                    log.info("[%s] start 响应超时但容器已就绪，复用 addr", code)
                    return c.container_addr
            except Exception:
                pass
        return []

    async def _close_challenge(self, ch: Challenge):
        """close 容器 + 失效 ch 快照。

        失效是 E 修复的关键：ch 来自 run 开头的 list_challenges 快照，close 后
        若不改 container_status，下一次 attempt 的 _addrs 会因快照仍是 available
        而直接返回已关闭的 addr，白打一轮。close 后把快照打回 stopped，强制下次
        attempt 重新 start。
        """
        try:
            await self.api.close_challenge(ch.unique_code)
        except Exception as e:
            log.warning("[%s] close 失败（忽略，不影响解题）: %s", ch.unique_code, e)
        ch.container_status = "stopped"
        ch.container_addr = []

    async def _close_if_open(self, ch: Challenge):
        """关闭链式题跨 attempt 存活的容器（终态调用：解出/attempt 耗尽/止损）。"""
        if ch.unique_code in self._open_containers:
            await self._close_challenge(ch)
            self._open_containers.pop(ch.unique_code, None)

    async def _cleanup_open_containers(self):
        """run() 退出前兜底关闭所有存活容器（deadline 中断等路径）。"""
        for code, ch in list(self._open_containers.items()):
            await self._close_challenge(ch)
        self._open_containers.clear()

    async def _gather_until_solved(self, submitter: FlagSubmitter, coros: list):
        """并行跑 step；任一拿全 flag 立即 cancel 兄弟会话，立刻让槽。

        13587 收尾 36 分钟 8 方向 gather 等到死：easy 0 分仍占满 3 槽。
        """
        tasks = [asyncio.create_task(c) for c in coros]
        out: list[str] = [""] * len(tasks)
        pending: set[asyncio.Task] = set(tasks)
        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    idx = tasks.index(t)
                    if t.cancelled():
                        continue
                    try:
                        out[idx] = t.result() or ""
                    except asyncio.CancelledError:
                        pass
                    except Exception as e:
                        out[idx] = f"[step异常: {type(e).__name__}: {e}]"
                if submitter.completed and pending:
                    for t in pending:
                        t.cancel()
                    await asyncio.gather(*pending, return_exceptions=True)
                    break
        finally:
            leftover = [t for t in tasks if not t.done()]
            for t in leftover:
                t.cancel()
            if leftover:
                await asyncio.gather(*leftover, return_exceptions=True)
        return out

    async def _llm_chat(self, messages: list[dict], tools: list | None = None,
                        max_tokens: int | None = None, model: str = "",
                        timeout_s: float | None = None) -> dict:
        """转发 llm.chat；测试 fake 不接 timeout_s 时降级。"""
        kw: dict = {}
        if tools is not None:
            kw["tools"] = tools
        if max_tokens is not None:
            kw["max_tokens"] = max_tokens
        if model:
            kw["model"] = model
        if timeout_s is not None:
            kw["timeout_s"] = timeout_s
        try:
            return await self.llm.chat(messages, **kw)
        except TypeError:
            kw.pop("timeout_s", None)
            return await self.llm.chat(messages, **kw)

    # ---- 单 step 短会话 ----
    async def _run_step(self, ch: Challenge, addrs: list[str], submitter: FlagSubmitter,
                        direction: str, step_no: int, timeout_s: float,
                        hint_cb, retry_note: str, sol_section: str = "",
                        step_id: str = "", chain_section: str = ""):
        code = ch.unique_code
        # 工作区全题共享（会话上下文独立、文件共享）：一个 step 写的 exploit 脚本/
        # 笔记，兄弟 step 与后续 attempt 直接复用（榜首日志观察：后置步骤直接复用
        # 前置步骤建成的攻击脚本——能力累积在文件里，不累积在上下文里）
        ws = os.path.join(self.run_dir, code)
        box = ToolBox(ws, submit_cb=lambda f: self._submit(ch, submitter, f),
                      hint_cb=hint_cb, finish_cb=_require_substance)

        facts = self._snapshot(code)
        user = (
            self._facts_yaml(ch, addrs, facts)
            + f"\n\n当前步骤: {direction}"
            + (retry_note or "")
            + (sol_section or "")
            + (chain_section or "")
            + f"\nflag 进度 {submitter.correct_count}/{ch.flag_count}"
            + "\n开始探索，结束用 finish 收束一条事实。"
        )
        messages = [
            {"role": "system", "content": SIMPLE_SYSTEM},
            {"role": "user", "content": user},
        ]
        # 跨方向新事实注入水位：开跑时已注入的 facts 不再重复注入
        injected_facts = set(facts)

        fact = ""
        extracted: set[str] = set()   # 本次 step 自动提取的线索（step 结束统一落盘）
        steps = 0
        started = time.monotonic()
        tools = tool_schemas()
        # 同轮多条工具调用并行执行（移植 worker 模式）：不同 shell 会话/文件工具
        # 互不依赖，同 session 用锁排队（持久会话语义）——串行时一轮 3 条 shell
        # = 3×60s，并行 = max(60s)，15 轮步数预算不被延迟吃掉
        session_locks: dict[str, asyncio.Lock] = {}

        async def _exec_one(call: dict) -> tuple[str, dict, str]:
            fn = call.get("function") or {}
            name = fn.get("name", "")
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            if name == "shell":
                sess_name = args.get("session", "main")
                lock = session_locks.setdefault(sess_name, asyncio.Lock())
                async with lock:
                    return name, args, await dispatch_tool(box, name, args)
            return name, args, await dispatch_tool(box, name, args)

        try:
            while steps < self.cfg.simple_max_steps and time.monotonic() - started < timeout_s:
                if submitter.completed:
                    break
                # 跨方向新事实注入：早收束 step 的线索（凭证/主机/hint）让在跑
                # step 当轮看到——多 flag 链式题不能全靠 attempt 间接力
                fresh = [f for f in self._snapshot(code) if f not in injected_facts]
                if fresh:
                    injected_facts.update(fresh)
                    prio = [f for f in fresh if f.startswith(_CLUE_PREFIXES)] or fresh
                    messages.append({"role": "user", "content":
                                     "【跨方向新事实】（别的方向刚确认，直接复用，别重新探测）\n"
                                     + "\n".join(f"- {f}" for f in prio[-8:])})
                # 上下文裁剪：长会话超预算先截旧工具输出，防 LLM 400 中途夭折
                messages = self._trim_messages(messages)
                remain = timeout_s - (time.monotonic() - started)
                if remain <= 0:
                    break
                try:
                    msg = await self._llm_chat(messages, tools,
                                               timeout_s=min(_LLM_CALL_S, remain))
                except Exception as e:
                    log.warning("[%s] LLM 调用失败: %s", code, e)
                    break
                messages.append(msg)
                steps += 1
                calls = msg.get("tool_calls") or []
                if not calls:
                    if msg.get("content"):
                        fact = msg["content"][:2000]
                    messages.append({"role": "user", "content":
                        "请继续用工具行动；若已拿全 flag 或本方向穷尽，调用 finish 收束。"})
                    continue
                outs = await asyncio.gather(*(_exec_one(c) for c in calls),
                                            return_exceptions=True)
                for call, res in zip(calls, outs):
                    if isinstance(res, BaseException):
                        name, args, out = "?", {}, f"[工具执行异常: {type(res).__name__}: {res}]"
                    else:
                        name, args, out = res
                    out = out if isinstance(out, str) else str(out)  # 防御：工具输出必须是字符串
                    for fl in extract_flags(out):
                        # should_try 已在 _submit 锁内（防并发 duplicate），这里直接提交
                        await self._submit(ch, submitter, fl, auto=True)
                    # 自动提取线索（不依赖 LLM finish summary）：凭证/内网主机/CVE/端点
                    for cred in _extract_credentials(out):
                        label = f"[自动-凭证] {cred}"
                        if label not in self._auto_facts:
                            self._auto_facts.add(label)
                            extracted.add(label)
                    for ip in _extract_internal_hosts(out, self._known_hosts):
                        self._known_hosts.add(ip)
                        label = f"[自动-内网主机] {ip}"
                        if label not in self._auto_facts:
                            self._auto_facts.add(label)
                            extracted.add(label)
                    for cve in _extract_cve_hints(out):
                        label = f"[自动-CVE] {cve}"
                        if label not in self._auto_facts:
                            self._auto_facts.add(label)
                            extracted.add(label)
                    for url in _extract_urls(out, self._known_hosts):
                        label = f"[自动-端点] {url}"
                        if label not in self._auto_facts:
                            self._auto_facts.add(label)
                            extracted.add(label)
                    if name == "finish":
                        fact = (args.get("summary") or "")[:2000]
                    messages.append({"role": "tool", "tool_call_id": call.get("id", ""),
                                     "content": out})
                if box.finished or submitter.completed:
                    break
        finally:
            await box.destroy()

        # 自动提取的线索先落盘（不依赖 LLM finish summary）
        for f in extracted:
            await self._append_fact(code, f)
        # 工件登记（复眼 P1）：会话期间新增/修改的脚本与 PoC 落一条 fact——共享
        # 工作区里「有什么可复用的工具」必须进图，否则兄弟会话不知道去跑现成
        # 脚本而重新推导（榜首二进制题复盘：候选生成器没登记，兄弟会话重复推导 8 次错提）
        try:
            arts = []
            for fn in sorted(os.listdir(ws)):
                if not fn.endswith((".py", ".sh")):
                    continue
                p = os.path.join(ws, fn)
                if os.path.getmtime(p) >= started - 5 and fn not in ("run_local.sh",):
                    arts.append(fn)
            for fn in arts[:6]:
                label = f"[自动-工件] {fn}（工作区现成脚本，先看/先跑它再自己写）"
                if label not in self._auto_facts:
                    self._auto_facts.add(label)
                    await self._append_fact(code, label)
        except OSError:
            pass
        # finish 摘要只回 graph.json step note（调用方 _run_chain 写 note）；
        # YAML 只收线索 / 「已排除」，普通「收束」不当线索（否则每 step 刷屏打穿 cache）
        if not fact:
            fact = f"[{direction[:60]}] {steps} 步未 finish（flag 进度 {submitter.correct_count}/{ch.flag_count}）"
        else:
            fact = f"[{direction[:60]}] {fact}"
        if _persist_fact(fact):
            await self._append_fact(code, fact)
        return fact

    # ---- step 时长分级（映射主架构 _scaled_timeout_s 的分级精神） ----
    def _step_timeout_min(self, ch: Challenge, attempt: int) -> int:
        """一次占用上限：链式题单步窗口 15min（无新 flag 的停滞关容器由
        _run_chain 再卡一层，_CHAIN_STAGNATE_S=20min）；单 flag 题按难度分级
        _DIFF_MINUTES（easy 8 / medium 15 / hard 20）。"""
        if self._is_chain(ch):
            return 15
        return _DIFF_MINUTES.get(ch.difficulty, 15)

    def _fallback_directions(self, ch: Challenge, n: int) -> list[str]:
        """方向规划失败时的题型兜底：按 playbook 选题型专属方向集。

        通用 Web 8 方向对非 Web 题（pwn f / 区块链 h / CVE 服务 c / 云 d 等）是纯噪音，
        回退也得回退到「题型对」的方向，而不是回退到 Web 通用方向。
        """
        pb = playbook_key_for(ch.unique_code, ch.description or "")
        dirs = _DIRECTIONS_BY_PB.get(pb) or STEP_DIRECTIONS
        return list(dirs)[:n]

    # ---- 方向动态规划（LLM 读题目 + facts，动态决定下一步方向，替代静态 8 方向） ----
    async def _plan_directions(self, ch: Challenge, addrs: list[str], facts: list[str], n: int) -> list[str]:
        facts_block = "\n".join(f"- {f}" for f in facts[-24:]) or "(无)"
        prompt = (
            f"你是渗透测试调度员，根据题目信息精准规划探索方向。\n\n"
            f"题目：{ch.unique_code}\n描述：{ch.description or '(无)'}\n"
            f"难度：{ch.difficulty}，{ch.flag_count} 面 flag，目标：{', '.join(addrs) or '(未知)'}\n\n"
            f"已确认事实（之前探索的结论，别重复已排除的）：\n{facts_block}\n\n"
            f"先判断题型（Web 漏洞 / 二进制逆向 / 云 misconfig / 多阶段渗透 / 开源 CVE 复现），"
            f"再针对性规划 {n} 个方向。每个方向必须具体可执行（含目标端口/组件名/CVE 编号/参数），"
            f"禁止泛泛的「侦察」「探测」。互不重叠。输出格式：每行一个，以「- 」开头，不要其他内容。"
        )
        try:
            msg = await self._llm_chat([{"role": "user", "content": prompt}],
                                       max_tokens=1200, timeout_s=_LLM_CALL_S)
            content = msg.get("content") or ""
        except Exception as e:
            log.error("[%s] 方向规划调用失败，按题型回退: %s", ch.unique_code, e)
            return self._fallback_directions(ch, n)
        dirs = _parse_direction_lines(content)
        if not dirs:
            log.error("[%s] 方向规划输出无法解析（%r），按题型回退", ch.unique_code, content[:120])
            return self._fallback_directions(ch, n)
        return dirs[:n]

    def _problem_type(self, ch: Challenge) -> str:
        """通用问题类型（web/二进制/区块链/CVE 服务/云/AI 应用/多阶段渗透/规避）。"""
        return _PB_TYPE.get(playbook_key_for(ch.unique_code, ch.description or ""), "web")

    def _seed_steps_for(self, ch: Challenge) -> list[str]:
        """空图种子 Intent：链用立足→收旗；单 flag 用题型方向集截断。
        默认 4 条（simple_steps_per_round），不是 Web 8 分类。"""
        if self._is_chain(ch):
            return list(_CHAIN_SEED_STEPS)
        pb = playbook_key_for(ch.unique_code, ch.description or "")
        dirs = _DIRECTIONS_BY_PB.get(pb) or STEP_DIRECTIONS
        n = max(2, min(len(dirs), self.cfg.simple_steps_per_round))
        return list(dirs)[:n]

    def _facts_yaml(self, ch: Challenge, addrs: list[str], facts: list[str]) -> str:
        """榜首会话形态：user 以 facts YAML 开头。origin 不含进度（进度变了
        会把整段 cache 前缀打穿）。"""
        origin = (
            f"编号: {ch.unique_code}\n"
            f"描述: {ch.description or '(无)'}\n"
            f"目标: {', '.join(addrs) or '(无)'}\n"
            f"难度: {ch.difficulty}，共 {ch.flag_count} 面 flag"
        )
        lines = ["facts:", "  - id: fact_origin", "    title: 题目信息", "    content: |"]
        for ln in origin.splitlines():
            lines.append("      " + ln)
        kept = [f for f in facts if _persist_fact(f)][-24:]
        for i, f in enumerate(kept, 1):
            content = " ".join(str(f).split())[:400]
            lines.append(f"  - id: f{i}")
            lines.append(f"    content: {json.dumps(content, ensure_ascii=False)}")
        return "\n".join(lines)

    def _should_use_claude(self, ch: Challenge, attempt: int = 0) -> bool:
        """P0：simple_mode 全程 flash。榜首 62/63 全 flash；13587 的 pro/claude
        占 25% token、长会话把槽钉死，解出题数反而更少。"""
        return False

    def _has_full_solution(self, code: str) -> bool:
        sol = self._load_solution(code)
        return bool(sol and sol.get("completed")
                    and (sol.get("steps") or sol.get("note")))

    # ---- FGS-lite：链式题的持久 Step 图 + 增量 Decide（吸收榜首架构，通用） ----
    # 观察（榜首 97.14 分 run 日志）：长链题靠 Fact-Goal-Step 图外化状态——Execute
    # 短会话只做一个 step（干净上下文防腐化），Decide 在事实变化后从干净上下文
    # 重排（新增/废弃带原因），step 依赖事实推进到第 20+ 步仍不丢链。我们此前
    # 的「每 attempt 重撒 8 个一次性方向」在链式题上第 3 步就断链。
    @staticmethod
    def _is_chain(ch: Challenge) -> bool:
        """链式题判定（通用阈值）：多 flag 是链式渗透（入口→内网→逐台收），
        hard 双 flag 同理。单 flag 同样走 FGS，只是种子 Intent 用题型方向集。"""
        return ch.flag_count >= 4 or (ch.flag_count >= 2 and ch.difficulty == "hard")

    def _parallel_cap(self, ch: Challenge) -> int:
        """单题并行 Execute 路数上限：链式题用 chain_parallel（多面横向铺开），
        单 flag 题收敛到 simple_steps_per_round——8 路对单 flag medium Web 题是
        撒网浪费（13536 复盘：8 方向盲打互相重复，token 全耗在无差别枚举）。"""
        if self._is_chain(ch):
            return self.cfg.chain_parallel
        return min(self.cfg.simple_steps_per_round, self.cfg.chain_parallel)

    async def _ensure_seed_graph(self, ch: Challenge) -> bool:
        """空图写入题型种子 Intent。已有步骤则不动。返回是否新写入。"""
        code = ch.unique_code
        graph = self._load_graph(code)
        if graph["steps"]:
            return False
        seeds = self._seed_steps_for(ch)
        graph["steps"] = [{"id": f"s{i+1}", "action": a, "state": "open",
                           "note": "", "added": "seed"}
                          for i, a in enumerate(seeds)]
        await self._save_graph(code, graph)
        return True

    def _graph_path(self, code: str) -> str:
        return os.path.join(self.run_dir, code, "graph.json")

    def _load_graph(self, code: str) -> dict:
        try:
            with open(self._graph_path(code)) as f:
                g = json.load(f)
            if isinstance(g, dict) and isinstance(g.get("steps"), list):
                return g
        except (OSError, ValueError):
            pass
        return {"steps": []}

    async def _save_graph(self, code: str, graph: dict):
        async with self._lock:
            os.makedirs(os.path.dirname(self._graph_path(code)), exist_ok=True)
            tmp = self._graph_path(code) + ".tmp"
            with open(tmp, "w") as f:
                json.dump(graph, f, ensure_ascii=False, indent=1)
            os.replace(tmp, self._graph_path(code))

    async def _decide_steps(self, ch: Challenge, addrs: list[str],
                            force_explore: bool = False, timeout_s: float = _DECIDE_CALL_S):
        """Decide（干净上下文，1 次调用）：读题 + facts + 现有 steps →
        新增 ADD / 废弃 DROP（带原因）/ 隐含保留。解析失败保持现状。

        复眼改造：
        - flash 决策（Decide 直接用默认 flash 模型）：13842 实测 pro 走 OpenAI
          通道 Decide 时 content 几乎 100% 空返回（13806 同病根），强模型决策层
          形同虚设还白烧 90s 空等——不如 flash 单次到位；
        - 风险排序税（信封内优先）：榜首多 flag 链式题实证死因——图记得对、路选错，
          有全部事实却选了「经反向隧道」这条脆弱路径；
        - force_explore（停滞触发）：主线连续无新事实时强制 ADD 换攻击面步骤，
          防单图陷入兔子洞（单一爆破路线长时间无果的实测教训）。
        """
        code = ch.unique_code
        graph = self._load_graph(code)
        facts = self._snapshot(code)
        neg = [f for f in facts if f.startswith("[负候选]") or "已排除" in f
               or "不可利用" in f or "失效" in f]
        lines = [f"{i+1}. {f[:220]}" for i, f in enumerate(facts[-32:])]
        # 步骤列表有上限：open 全量（最多 chain_parallel 条）+ done/dropped 最近
        # 8 条——20+ 步的深图全量展示会把单次 Decide 推到 10k 字符，历史步的
        # 价值密度远低于 open，用省略计数代替
        hist = [s for s in graph["steps"] if s["state"] != "open"][-8:]
        shown = [s for s in graph["steps"] if s["state"] == "open"] + hist
        omitted = len(graph["steps"]) - len(shown)
        step_lines = [f"- {s['id']} [{s['state']}] {s['action'][:160]}"
                      + (f"（备注: {s.get('note','')[:120]}）" if s.get("note") else "")
                      for s in shown]
        if omitted > 0:
            step_lines.append(f"（另有 {omitted} 条更早的 done/dropped 步骤已省略）")
        prompt = (
            f"你是渗透调度员（Decide）。目标：拿全本题 {ch.flag_count} 面 flag（已 {ch.correct_flag_count} 面）。\n"
            f"题目：{ch.description or '(无)'}\n目标地址：{', '.join(addrs)}\n\n"
            f"已确认事实（[负候选]/「已排除」的别再试）：\n" + "\n".join(lines) + "\n\n"
            f"现有步骤（dropped 的含原因，禁止重复开同类）：\n" + ("\n".join(step_lines) or "(无)") + "\n\n"
            f"依据事实增删步骤。每步必须具体可执行（含目标/端口/凭证/工具），禁止泛泛的「侦察」。\n"
            f"排序原则（风险税）：优先「在已控立足点/已验证凭据/已打通通道上组合原语」的步骤（信封内）；\n"
            f"依赖新建反向隧道/外部监听/出网通道的步骤（信封外）排后，除非信封内无等效路径。\n"
            + ("⚠️ 主线上轮无任何新进展：必须 ADD 至少 1 个换攻击面的步骤（假设当前主线方向全错，从全新入口/协议/凭据视角重开一路）。\n"
               if force_explore else "")
            + f"优先级从上到下；open 步骤最多 {self._parallel_cap(ch)} 个；已被更强原语覆盖的旧步骤立即 DROP。\n"
            f"输出格式（每行一条，别的内容都不要）：\n"
            f"ADD <动作描述>\n"
            f"DROP <step_id> <废弃原因>"
        )
        try:
            msg = await self._llm_chat(
                [{"role": "user", "content": prompt}],
                max_tokens=1500, timeout_s=timeout_s)
            content = msg.get("content") or ""
        except Exception as e:
            log.warning("[%s] Decide 调用失败（沿用现有步骤图）: %s", code, e)
            content = ""
        adds: list[str] = []
        drops: dict[str, str] = {}
        for line in content.splitlines():
            s = line.strip()
            m = re.match(r"^ADD[:\s]+(.{8,})$", s, re.I)
            if m:
                adds.append(m.group(1).strip())
                continue
            m = re.match(r"^DROP[:\s]+(\S+)\s+(.{2,})$", s, re.I)
            if m:
                drops[m.group(1)] = m.group(2).strip()
        if not adds:
            adds = _parse_direction_lines(content)
        if not adds and not drops:
            await self._ensure_seed_graph(ch)
            return
        for st in graph["steps"]:
            if st["id"] in drops:
                st["state"] = "dropped"
                st["note"] = drops[st["id"]][:200]
        # 已有动作去重（含前缀/后缀变体：同义重复的 ADD 不重复入队；对图实时判，
        # 本批先加入的也能拦住后加入的同义重复）
        def _dup(a: str) -> bool:
            return any((st["action"] or "")[:40] in a or a[:40] in (st["action"] or "")
                       for st in graph["steps"])

        nid = max([int(re.sub(r"\D", "", st["id"]) or 0) for st in graph["steps"]] + [0])
        for a in adds:
            if _dup(a):
                continue
            nid += 1
            graph["steps"].append({"id": f"s{nid}", "action": a[:400],
                                   "state": "open", "note": "", "added": "decide"})
        await self._save_graph(code, graph)
        if neg:
            log.info("[%s] Decide 完成（%d 负结果事实已参与决策）", code, len(neg))

    def _write_engine_handoff(self, code: str):
        """跨引擎交接段（P1-3）：claude 棒开跑前，把 facts 图里的负剪枝面 /
        现成工件清单 / 官方提示写进共享 NOTES.md 的标记段（worker 的
        _workspace_digest 会把 NOTES 尾部注入 claude prompt）。幂等：标记段
        整段重写，不随 claude attempt 累积重复。"""
        facts = self._snapshot(code)
        keep = [f for f in facts
                if f.startswith(("[负候选]", "[自动-工件]", "[官方提示]"))]
        if not keep:
            return
        path = os.path.join(self.run_dir, code, "NOTES.md")
        try:
            with open(path, errors="replace") as f:
                txt = f.read()
        except OSError:
            txt = ""
        marker = "## 引擎交接摘要（facts 图自动维护，勿手改）"
        if marker in txt:
            txt = txt.split(marker)[0].rstrip() + "\n\n"
        txt += (marker + "\n"
                + "\n".join(f"- {f[:160]}" for f in keep[-12:]) + "\n")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(txt)
        except OSError as e:
            log.warning("[%s] 引擎交接段写入失败（忽略）: %s", code, e)

    def _chain_section(self, code: str, graph: dict, cur_id: str) -> str:
        """差分注入（复眼 P2）：链式会话的步骤上下文——只给「与本步骤相关的图」
        而非全图硬塞：已完成步骤的结论（前置接力棒）、当前 open 兄弟步骤（防
        重叠）、已废弃步骤及原因（别走死路）。榜首深链日志里后置步骤直接复用前置
        步骤建成的攻击脚本，靠的就是这种「前置结论显式交接」。"""
        done = [s for s in graph["steps"] if s["state"] == "done" and s.get("note")]
        opens = [s for s in graph["steps"] if s["state"] == "open" and s["id"] != cur_id]
        dropped = [s for s in graph["steps"] if s["state"] == "dropped" and s.get("note")]
        parts: list[str] = []
        if done:
            parts.append("## 前置步骤结论（接力棒——先读工作区现成脚本/凭据再动手）\n"
                         + "\n".join(f"- [{s['id']}] {s['action'][:60]} → {s['note'][:140]}"
                                     for s in done[-5:]))
        if opens:
            parts.append("## 并行兄弟步骤（别人在做，别重叠）\n"
                         + "\n".join(f"- [{s['id']}] {s['action'][:100]}" for s in opens[:8]))
        if dropped:
            parts.append("## 已废弃路径（别再走）\n"
                         + "\n".join(f"- [{s['id']}] {s['action'][:60]}（{s['note'][:100]}）"
                                     for s in dropped[-4:]))
        return ("\n\n" + "\n\n".join(parts)) if parts else ""

    @staticmethod
    def _need_decide(decided: bool, open_cnt: int, clue_delta: int,
                     stagnant: bool) -> bool:
        """Decide 触发谓词（事件驱动，替代「每轮全量重排」的串行税）：
        本 occupancy 尚未 Decide；无 open 步骤；新线索 ≥2；停滞（换攻击面）。
        空图首轮不走这里——_run_chain 先写种子再 Execute。其余情况直接执行。"""
        return (not decided) or open_cnt == 0 or clue_delta >= 2 or stagnant

    async def _run_chain(self, ch: Challenge, addrs: list[str], submitter: FlagSubmitter,
                         attempt: int, budget_s: float, hint_cb, retry_note: str,
                         sol_section: str):
        """链式题引擎：Decide（事件驱动重排图）→ Execute（并行 K 个短会话各做
        一个 step）→ 循环至窗口/完成。step 图跨 attempt/波次持久（graph.json）。

        复眼改造（对齐榜首日志复盘的三处结构性缺陷）：
        - 空图首轮跳过 Decide：题型种子直接 Execute（首占位别空转一轮规划）；
          之后仅在「新线索 ≥2 / 无 open 步骤 / 停滞」时 Decide；
        - 停滞检测：一轮既无新 flag 也无新线索 → 下次 Decide 强制 ADD 换攻击面
          步骤（防单图兔子洞：单一爆破路线长时间无果的实测教训）；
        - 步骤上下文注入（差分）：每个 Execute 只看自己的接力棒 + 兄弟概览。
        """
        code = ch.unique_code
        t_end = time.monotonic() + budget_s
        rnd = 0
        K = self._parallel_cap(ch)
        seeded = await self._ensure_seed_graph(ch)
        graph0 = self._load_graph(code)
        done_before = sum(1 for s in graph0["steps"] if s["state"] == "done")
        # 空图已下种子：跳过首轮 Decide，立刻 Execute
        decided = seeded
        clues_at_decide = sum(1 for f in self._snapshot(code) if f.startswith(_CLUE_PREFIXES))
        stagnant = False
        last_flag_at = time.monotonic()
        while time.monotonic() < t_end and not submitter.completed:
            if time.monotonic() - last_flag_at >= _CHAIN_STAGNATE_S:
                log.info("[%s] 链式 %.0fmin 无新 flag，关容器轮转",
                         code, _CHAIN_STAGNATE_S / 60)
                break
            rnd += 1
            graph = self._load_graph(code)
            open_steps = [s for s in graph["steps"] if s["state"] == "open"]
            clues_now = sum(1 for f in self._snapshot(code) if f.startswith(_CLUE_PREFIXES))
            if self._need_decide(decided, len(open_steps),
                                 clues_now - clues_at_decide, stagnant):
                occ_remain = t_end - time.monotonic()
                if occ_remain <= 0:
                    break
                await self._decide_steps(ch, addrs, force_explore=stagnant,
                                         timeout_s=min(_DECIDE_CALL_S, occ_remain))
                decided = True
                clues_at_decide = clues_now
                stagnant = False
                graph = self._load_graph(code)
                open_steps = [s for s in graph["steps"] if s["state"] == "open"]
            if not open_steps:
                log.info("[%s] 步骤图无 open 步骤，链式引擎结束", code)
                break
            batch = open_steps[:K]
            remaining = max(60.0, t_end - time.monotonic())
            sess_s = min(_EXECUTE_SESS_S, remaining)  # 单会话 ≤2min，5min 占用可跑 2-3 轮
            log.info("[%s] 链式第 %d 轮：执行 %d 步 %s", code, rnd, len(batch),
                     [s["id"] for s in batch])
            flags_before = submitter.correct_count
            facts = await self._gather_until_solved(submitter, [
                self._run_step(ch, addrs, submitter, s["action"],
                               self._next_step_no(), sess_s, hint_cb, retry_note,
                               sol_section, step_id=s["id"],
                               chain_section=self._chain_section(code, graph, s["id"]))
                for s in batch])
            # 回写状态：正常收束标 done；超时未收束保持 open（下一轮重执行）。
            # 下一轮 Decide 依据新事实决定 DROP/重开
            g2 = self._load_graph(code)
            for s, fact in zip(batch, facts):
                if not fact or str(fact).startswith("[step异常"):
                    continue
                for st in g2["steps"]:
                    if st["id"] == s["id"] and st["state"] == "open":
                        st["note"] = (fact or "")[:200]
                        if "未 finish" not in (fact or ""):
                            st["state"] = "done"
            await self._save_graph(code, g2)
            if submitter.correct_count > flags_before:
                last_flag_at = time.monotonic()
            # 停滞判定：本轮无新 flag 且无新线索 fact → 下一轮 Decide 强制换面
            clues_after = sum(1 for f in self._snapshot(code) if f.startswith(_CLUE_PREFIXES))
            if submitter.correct_count == flags_before and clues_after <= clues_now:
                stagnant = True
                log.info("[%s] 链式第 %d 轮无新 flag 无新线索，下轮 Decide 强制换攻击面",
                         code, rnd)
        # 图进展增量（P0-1）：深链推进常产出「结论型 step note」而非「线索型 fact」，
        # 无进展判定必须看见图——否则推进中的链被误杀：容器关掉断立足点 + 本波弃置
        done_after = sum(1 for s in self._load_graph(code)["steps"] if s["state"] == "done")
        return done_after - done_before

    def _next_step_no(self) -> int:
        self._fgs_seq += 1
        return self._fgs_seq

    # ---- 波次队列构建与收尾排序 ----
    def _build_wave_queue(self, challenges: list[Challenge],
                          solved: set[str]) -> list[tuple[Challenge, int]]:
        """波次队列：复现题最先（单 run 内记录的解法快速复现），再 easy 优先
        （快扫拿分），同难度按已拿面占比 + 分数。"""
        full_sols = {c.unique_code for c in challenges
                     if self._has_full_solution(c.unique_code)}
        queue = [(c, 0) for c in challenges
                 if c.flag_count >= 1 and not _completed(c)
                 and c.unique_code not in solved]
        queue.sort(key=lambda it: (
            0 if it[0].unique_code in full_sols else 1,
            _DIFF_RANK.get(it[0].difficulty, 3),
            -(it[0].correct_flag_count / max(1, it[0].flag_count)),
            -it[0].total_score))
        # 单 flag 在前、链在后：前 90 分钟 3 槽快扫。13587 把链提到第 3/5/7 位
        # → t=0 双链进场，前 60 分钟只 10 flag（榜首 20）。
        singles = [it for it in queue if not self._is_chain(it[0])]
        chains = [it for it in queue if self._is_chain(it[0])]
        return singles + chains

    def _allow_chain_dispatch(self) -> bool:
        """开跑后 chain_quiet_min 分钟内不派链（默认 90）。"""
        quiet = max(0, self.cfg.chain_quiet_min) * 60
        if quiet <= 0 or self._t0 <= 0:
            return True
        return time.monotonic() - self._t0 >= quiet

    def _endgame_resort(self, queue: list[tuple[Challenge, int]], remaining_s: float):
        """收尾段快赢排序（复用 ENDGAME_MIN，默认 45min）：剩 1 面的多 flag >
        低难度 > 高分——尾段槽位烧在大题第 N 次重试上是 12464 的直接失分源
        （收卷前 25min 还在第三轮攻二进制题）。非收尾段不动排序。"""
        if not queue or remaining_s >= self.cfg.endgame_min * 60:
            return
        queue.sort(key=lambda it: (
            0 if it[0].remaining_flags == 1 else 1,
            _DIFF_RANK.get(it[0].difficulty, 3),
            -it[0].total_score))

    async def _solve_claude(self, ch: Challenge, addrs: list[str], attempt: int,
                            deadline: float) -> dict:
        """复用主架构 claude code 直接解题（Worker._run_claude）：完整 prompt
        （题型 playbook + 端口/CVE 线索 + 行动纪律 + 分治）+ submit_flag.sh 显式
        通道 + 双通道 flag 提交 + 解法落库。裸 LLM 8 方向 step 对 hard/pwn/多 flag
        题能力密度不足，这里整个交给 claude。"""
        code = ch.unique_code
        ws = os.path.join(self.run_dir, code)
        submitter = self._new_submitter(ch)
        # 跨引擎交接（P1-3）：claude 不读 facts.json，但它的工作区摘要会注入共享
        # NOTES.md 尾部——把 flash 棒攒的负剪枝/工件清单/官方提示写进标记段，
        # claude 开局即见「哪些候选已错、哪些脚本能直接跑」
        self._write_engine_handoff(code)
        # B 修复：claude 题按剩余 deadline 封顶单次超时。deadline 只控制 run() 补位，
        # 不约束已开始的 claude 题——尾段剩 5min 时 hard 题仍会跑满 45min 超预算。
        # budget_cap_min 传入 Worker 后 _scaled_timeout_s 会 min(minutes, cap) 收短。
        budget_cap_min = 0.0
        if deadline > 0:
            remaining_min = (deadline - time.monotonic()) / 60
            if remaining_min > 0:
                budget_cap_min = remaining_min
        worker = Worker(self.cfg, self.llm, self.api, ch, addrs, ws, deadline,
                        attempt=attempt, submitter=submitter,
                        budget_cap_min=budget_cap_min)
        try:
            result = await worker._run_claude()
        except Exception as e:
            log.exception("[%s] claude 解题异常（忽略，按未解出处理）", code)
            result = worker.result
            result.reason = f"claude crash: {type(e).__name__}: {e}"
        # claude 棒错提回灌负候选（P1-3）：worker 的提交不走本调度器 _submit，
        # 不补记的话后续 FGS-lite 棒看不见 claude 已撞过的墙（升级路径正好踩这）
        for wf in sorted(worker.submitter.tried - worker.submitter.correct)[:10]:
            await self._append_fact(
                code, f"[负候选] {wf[:48]} 已提交错误（claude 棒）——同形态别再提交")
        if self._is_chain(ch):
            # 链式攻坚题 attempt 间不 close（保立足点），终态由 run() 统一关闭
            self._open_containers[code] = ch
        else:
            await self._close_challenge(ch)
        self._carry_wrong_total(code, worker.submitter)
        # A 修复：把本次 attempt 真实进度写回 ch。否则 attempt 重排时 _solve_claude
        # 用到的 correct_flag_count 还是 run 开头的旧快照——多 flag 题 attempt 0 解出
        # 2/4 面，attempt 1 的 submitter 仍以为 0/4，claude prompt 显示错误进度重打旧面。
        ch.correct_flag_count = max(ch.correct_flag_count, worker.submitter.correct_count)
        return {"code": code, "ch": ch, "attempt": attempt, "started": True,
                "engine": "claude",
                "completed": result.completed, "score": result.score,
                "flags": sorted(result.flags)}

    # ---- 单题：动态方向 step 并行，首轮快速试水 / 次轮带 hint 攻坚 ----
    async def _solve_one(self, ch: Challenge, attempt: int, deadline: float = 0.0) -> dict:
        code = ch.unique_code
        # 尾缘不开新链棒（P2）：剩余 <5min 只够热身，链棒最贵的是开局基建验证——
        # 检查放在 start 之前（不白烧一次容器启动），留给下一波
        if (self._is_chain(ch) and deadline > 0
                and deadline - time.monotonic() < 5 * 60):
            log.info("[%s] 剩余预算不足链棒开局（<5min），跳过本轮", code)
            return {"code": code, "ch": ch, "attempt": attempt, "started": False,
                    "completed": False, "score": 0, "flags": []}
        t0 = time.monotonic()
        addrs = await self._addrs(ch)
        if not addrs:
            # start 失败：跳过本轮（不拿空 addr 瞎跑），重排后下次重试 start。
            # 返回 started=False——run() 据此重排「同 attempt」（不消耗重试预算，
            # 对齐主架构「attempt 只在容器就绪后计数」纪律），连败过多才弃到下波。
            log.warning("[%s] start 失败，跳过本轮（重排后重试）", code)
            return {"code": code, "ch": ch, "attempt": attempt, "started": False,
                    "completed": False, "score": 0, "flags": []}
        # 快照对齐真实状态：start 成功即 available（与 _close_challenge 打回
        # stopped 对称）——后台侦察的存活守卫、后续 _addrs 的复用判断都以此为准
        ch.container_status = "available"
        ch.container_addr = list(addrs)
        self._open_containers[code] = ch   # 异常路径由 run() _close_if_open 兜底
        use_claude = self._should_use_claude(ch, attempt)
        if (use_claude and self._is_chain(ch)
                and attempt >= self.cfg.simple_claude_attempts):
            # 复眼路由升级：链式题 claude attempt 预算耗尽 → 转 FGS-lite flash
            # 引擎续跑（图 + facts 已积累，短会话接力正合适），不再无限重复
            # claude——同一个思路用贵引擎砸第 3 遍，期望收益不如换执行形态
            log.info("[%s] 链式题 claude attempt 预算耗尽，转 FGS-lite 引擎续跑", code)
            use_claude = False
        if use_claude:
            return await self._solve_claude(ch, addrs, attempt, deadline)
        submitter = self._new_submitter(ch)
        entry_correct = ch.correct_flag_count   # 无进展判定基线（flag 面）
        hint_cb = lambda: self._hint(ch, attempt)
        # 解法库提前计算：upfront hint 拉取与启动侦察都以「是否复现题」为前提
        sol_section, has_full_sol = self._solution_section(ch)
        retry_note = ""
        if attempt >= 1 or code in self._seen_attempt:
            retry_note = (f"\n\n⚠️ 这是第 {attempt + 1} 次尝试：下方「已确认事实」是之前探索的结论，"
                          "先从断点继续，别从头侦察，别重复已排除方向。")
        # hint 只给「已经跑过一轮、仍 0 分」的题。开局/已有分的链不准买。
        if (self.cfg.hint_policy == "free" and not has_full_sol
                and ch.correct_flag_count == 0
                and (attempt >= 1 or code in self._seen_attempt)):
            await self._hint(ch, attempt, proactive=True)
        # 无进展判定基线（线索面）：在 hint 拉取之后取样——hint 是本 attempt 的
        # 输入而非产出，不能计为「新进展」（否则每次拉 hint 的 attempt 都免死）
        clue_before = sum(1 for f in self._snapshot(code) if f.startswith(_CLUE_PREFIXES))
        # step 超时按 flag_count + difficulty 分级（多 flag/hard 题更长，链式渗透不被掐断）
        step_timeout_s = self._step_timeout_min(ch, attempt) * 60
        # deadline 封顶：flash 步同样受全局预算约束（此前只有 claude 路径被 cap，
        # 尾段开跑的 3 个 flash 题可在预算外各跑 10-23min，345/360 只有 15min 余量）
        if deadline > 0:
            step_timeout_s = min(step_timeout_s, max(60.0, deadline - time.monotonic()))
        # 完整解法按复现题止损收紧窗口
        if has_full_sol:
            step_timeout_s = min(step_timeout_s,
                                 (5 if ch.flag_count <= 1 else 10) * 60)
        # 共享启动侦察（后台，不阻塞 step）：8 个 step 各自 nmap 同一目标 =
        # 每题 1-3min × 8 份重复扫描；recon ≤75s 出端口/组件/CVE 指纹，完成后
        # 落 fact，在跑 step 经「跨方向新事实」当轮拿到、后续 attempt 全员注入。
        # 复现题跳过（直接复现更快）；已有侦察 fact 的题不重跑
        if (self.cfg.recon_boot and not has_full_sol
                and not any(f.startswith("[自动-侦察]") for f in self._snapshot(code))):
            async def _bg_recon():
                try:
                    report = await recon_targets(addrs, os.path.join(self.run_dir, code))
                except Exception as e:
                    log.warning("[%s] 启动侦察异常（忽略，step 自行侦察兜底）: %s", code, e)
                    return
                # 快解场景 attempt 可能先于侦察结束并 close 容器——对已关容器扫出的
                # 「无开放端口」废报告落 fact 会毒化后续 attempt（「别重新探测」）
                if not report or ch.container_status != "available":
                    return
                await self._append_fact(code, f"[自动-侦察] {report[:3000]}")
            bt = asyncio.create_task(_bg_recon())
            self._bg_tasks.add(bt)
            bt.add_done_callback(self._bg_tasks.discard)
        # 全题 FGS：单 flag 占用 = step_timeout（5min）；链给剩余预算，15min 无新 flag 刹
        if self._is_chain(ch):
            if deadline > 0:
                budget = max(60.0, deadline - time.monotonic())
            else:
                budget = _CHAIN_STAGNATE_S
        else:
            budget = step_timeout_s
        graph_done = (await self._run_chain(ch, addrs, submitter, attempt, budget,
                                            hint_cb, retry_note, sol_section)) or 0
        log.info("[%s] attempt %d 完成，flag %d/%d",
                 code, attempt + 1, submitter.correct_count, ch.flag_count)

        await self._close_challenge(ch)
        self._open_containers.pop(code, None)
        self._seen_attempt.add(code)
        self._carry_wrong_total(code, submitter)
        # A 修复：写回真实进度（flash 单 flag 题解出即 completed 不再重排；未解出
        # correct_count 仍 0，写回无副作用——此处主要兜底多面题的进度快照过期）。
        ch.correct_flag_count = max(ch.correct_flag_count, submitter.correct_count)
        # 解法回写（跨轮资产：下轮注入复现锁分；托管容器销毁前 SOLNOTE 打到 stdout）
        self._record_simple_solution(ch, self._snapshot(code), submitter.completed,
                                     (time.monotonic() - t0) / 60)
        # 无进展计量（run() 据此跳过「无新 flag 无新线索」的后续 attempt）：
        # 只认线索类 fact——finish 摘要每 attempt 必然新增，不算进展；
        # 链式题叠加图进展（done step 增量）：深链推进常只有结论型 note 没有
        # 线索型 fact，不叠加会被误杀（容器关掉断立足点）
        new_clues = (sum(1 for f in self._snapshot(code) if f.startswith(_CLUE_PREFIXES))
                     - clue_before + graph_done)
        return {"code": code, "ch": ch, "attempt": attempt, "started": True,
                "engine": "flash", "new_clues": new_clues,
                "new_flags": submitter.correct_count > entry_correct,
                "completed": submitter.completed, "score": submitter.score,
                "flags": sorted(submitter.correct)}

    # ---- 调度主循环：3 题动态补位 + 波次回查（NEVER_STOP 语义） ----
    async def run(self):
        # 启动 list 带重试（平台冷启动/网络抖动时不至于直接抛异常退出整轮）
        challenges: list[Challenge] = []
        for i in range(3):
            try:
                challenges = await self.api.list_challenges()
                break
            except Exception as e:
                log.warning("题目列表获取失败（第 %d 次）: %s", i + 1, e)
                await asyncio.sleep(5)
        if not challenges:
            log.error("题目列表获取失败，极简模式退出")
            return

        already = sum(c.total_score for c in challenges if _completed(c))

        log.info("极简模式：共 %d 题，已完成 %d（%d 分）；题并发 %d（动态补位），"
                 "每题 %d step，attempt≤%d/波，单 flag 窗口 easy %d/medium %d/hard %dmin，"
                 "队列耗尽回查平台开下一波直至预算耗尽",
                 len(challenges),
                 sum(1 for c in challenges if _completed(c)), already,
                 self.cfg.max_concurrent, self.cfg.simple_steps_per_round,
                 self.cfg.simple_attempts,
                 _DIFF_MINUTES["easy"], _DIFF_MINUTES["medium"], _DIFF_MINUTES["hard"])

        deadline = time.monotonic() + self.cfg.simple_budget_min * 60
        self._t0 = time.monotonic()
        sem = asyncio.Semaphore(self.cfg.max_concurrent)
        solved: set[str] = set()
        wave = 0

        async def _worker(ch, attempt):
            async with sem:
                return await self._solve_one(ch, attempt, deadline)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            wave += 1
            self._start_fails.clear()
            # flag_count=0 的题跳过（submitter 的 0>=0 会立即判 completed 秒过，
            # 白白 start/close 一轮；平台数据异常防御）
            queue = self._build_wave_queue(challenges, solved)
            if not queue:
                log.info("全部题目已解出/已完成（本进程解出 %d 题），极简模式结束", len(solved))
                break
            log.info("—— 第 %d 波：待解 %d 题（累计解出 %d）——", wave, len(queue), len(solved))

            active: dict[asyncio.Task, tuple[str, int]] = {}
            # 并发链上限 1 + 前 90min 静默：3 槽留给单 flag
            active_chains: set[str] = set()
            # 条件带 active：队列空但还有在跑题时继续等结果——否则最后一批任务的
            # 结果不被处理，solved 集漏记（下一波虽有平台 re-list 兜底，日志与
            # 波次统计仍会失真）
            while (queue or active) and time.monotonic() < deadline:
                # 收尾段重排（每轮派发前检查：endgame 可能在本波中途开始）
                self._endgame_resort(queue, deadline - time.monotonic())
                # 动态补位：槽位空出就补下一题（链并发超限时推迟、不占位）
                deferred: list[tuple[Challenge, int]] = []
                while queue and len(active) < self.cfg.max_concurrent:
                    ch, attempt = queue.pop(0)
                    if ch.unique_code in solved:
                        continue
                    if self._is_chain(ch) and (
                            not self._allow_chain_dispatch()
                            or len(active_chains) >= _MAX_ACTIVE_CHAINS):
                        deferred.append((ch, attempt))
                        continue
                    if self._is_chain(ch):
                        active_chains.add(ch.unique_code)
                    t = asyncio.create_task(_worker(ch, attempt))
                    active[t] = (ch.unique_code, attempt)
                if deferred:
                    queue.extend(deferred)   # 队尾：勿堵在队头饿死后面的单 flag
                if not active:
                    break
                done, _ = await asyncio.wait(active.keys(), return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    code, attempt = active.pop(t)
                    active_chains.discard(code)
                    try:
                        r = t.result()
                    except Exception as e:
                        log.error("[%s] 解题异常（忽略，继续调度）: %s", code, e)
                        ch_open = self._open_containers.get(code)
                        if ch_open is not None:
                            await self._close_if_open(ch_open)
                        continue
                    if r["completed"]:
                        solved.add(code)
                        self._start_fails[code] = 0
                        await self._close_if_open(r["ch"])
                        log.info("解出 %s（+%d 分，attempt %d）", code, r["score"], attempt + 1)
                        continue
                    if not r.get("started", True):
                        # start 失败不消耗 attempt（README 纪律：attempt 只在容器
                        # 就绪后计数），同 attempt 重排队尾；波内连败 >3 次弃到下一波
                        fails = self._start_fails.get(code, 0) + 1
                        self._start_fails[code] = fails
                        if fails <= 3:
                            log.warning("[%s] start 失败 %d 次，同 attempt 重排队尾", code, fails)
                            queue.append((r["ch"], attempt))
                        else:
                            log.warning("[%s] start 波内连败 %d 次，本波放弃（下波回查再试）",
                                        code, fails)
                        continue
                    self._start_fails[code] = 0
                    # 无进展止损（仅 flash：claude 的断点在 NOTES/solutions 里，
                    # facts 图看不到，不能用这个判死）：attempt≥1 且无新 flag 无新
                    # 线索 → 后续 attempt 大概率原地重复，本波跳过省槽位时间。
                    if (r.get("engine") == "flash" and attempt >= 1
                            and not r.get("new_flags") and r.get("new_clues", 0) <= 0):
                        log.info("[%s] attempt %d 无新 flag 无新线索，本波跳过剩余 attempt（下波回查再试）",
                                 code, attempt + 1)
                        await self._close_if_open(r["ch"])
                        continue
                    # 未解出重排：claude 题单次 attempt 贵，用 simple_claude_attempts
                    # （默认 2）；flash 题用 simple_attempts（默认 3，按波计）。
                    # 升级路由按下一 attempt 判定（二进制类型 flash 快试未解 →
                    # 下一棒 claude，预算同步切到 claude 档）。
                    # 链式题例外：预算给满 simple_attempts——claude 档耗尽后
                    # （_solve_one 路由升级）继续用 FGS-lite flash 棒，不提前弃题
                    max_attempts = self.cfg.simple_attempts
                    if attempt + 1 < max_attempts:
                        # 一律队尾：链插队头会把快题挤死（13587 B-02 一次 100min）
                        queue.append((r["ch"], attempt + 1))
                    else:
                        # 本波 attempt 用完：链式题此时才关容器（留给下一波重开）
                        await self._close_if_open(r["ch"])

            if active:
                await asyncio.wait(active.keys())
            if time.monotonic() >= deadline:
                break
            # 本波队列耗尽（解出/attempt 用完/start 连败弃置）但预算未用完：
            # 回查平台开下一波——同步最新进度（别题可能已推进），attempt 重新计
            # 数。对齐主架构 NEVER_STOP「队列耗尽后的平台回查轮」，预算不闲置。
            wait_s = min(60.0, max(5.0, deadline - time.monotonic()))
            log.info("第 %d 波结束（累计解出 %d 题）；预算剩 %.0fmin，%.0fs 后回查平台",
                     wave, len(solved), (deadline - time.monotonic()) / 60, wait_s)
            await asyncio.sleep(wait_s)
            try:
                challenges = await self.api.list_challenges()
            except Exception as e:
                log.warning("平台回查失败（沿用旧题表重试下一波）: %s", e)

        await self._cleanup_open_containers()
        log.info("极简模式结束：解出 %d 题，facts 落盘 %s", len(solved), self.facts_path)
