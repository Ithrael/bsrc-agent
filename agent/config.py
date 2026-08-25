"""运行配置：全部走环境变量，容器/本地同一套。

平台注入：BENCHMARK_BASE_URL、BENCHMARK_TOKEN（托管页面上曾显示为 BENCHMAK_TOKEN 拼写变体，做兼容）。
LLM 走 OpenAI 兼容接口；托管模式下 base_url 必须改写为 .tsecbench.gw 网关形式，见 llm.rewrite_gateway_url。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _int(env: str, default: int) -> int:
    v = os.environ.get(env, "").strip()
    try:
        return int(v) if v else default
    except ValueError:
        return default


def solution_lib_path() -> str:
    """solutions.json 路径：优先项目根（agent 包上一级），不存在时回退 cwd。
    避免依赖启动目录，本地/容器/任意 cwd 下都指向同一份解法库。"""
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "solutions.json")
    if not os.path.exists(p) and os.path.exists("solutions.json"):
        return os.path.abspath("solutions.json")
    return p


def notes_lib_path() -> str:
    """notes.json 路径：专家复盘（人工写的高价值提示），与自动记录的 solutions.json 解耦——
    自动记录不会覆盖它，人工复盘不会丢。"""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "notes.json")


def intel_lib_path() -> str:
    """intel.json 路径：跨题共享的全局情报（平台机制、通用攻击面等）。

    与按题的 notes.json/solutions.json 不同：这类发现「解一题、惠全题」，
    每轮跑分只需撞一次，后续题自动复用。"""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "intel.json")


def read_intel() -> dict:
    """读全局情报：intel.json（人工维护 dict）+ intel.json.new（agent 运行中追加的
    JSONL 行，claude 用 bash echo 追加 JSON 行最稳，写坏单行不影响其他）。"""
    import json as _json
    out: dict = {}
    try:
        with open(intel_lib_path()) as f:
            d = _json.load(f)
            if isinstance(d, dict):
                out.update(d)
    except (OSError, ValueError):
        pass
    try:
        with open(intel_lib_path() + ".new") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = _json.loads(line)
                    if isinstance(d, dict):
                        out.update(d)
                except ValueError:
                    pass
    except OSError:
        pass
    return out


@dataclass
class Config:
    # 平台接入
    benchmark_base_url: str = field(default_factory=lambda: os.environ.get("BENCHMARK_BASE_URL", "").rstrip("/"))
    benchmark_token: str = field(default_factory=lambda: os.environ.get("BENCHMARK_TOKEN") or os.environ.get("BENCHMAK_TOKEN", ""))

    # LLM（OpenAI 兼容）
    llm_base_url: str = field(default_factory=lambda: os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1"))
    llm_api_key: str = field(default_factory=lambda: os.environ.get("LLM_API_KEY", ""))
    llm_model: str = field(default_factory=lambda: os.environ.get("LLM_MODEL", "deepseek-v4-flash"))
    # 多模型分工（对标榜首 agent-hehua：flash 主力 + pro 攻坚 + 第三模型兜底）：
    # 非空时 hard 难度的 claude 会话用该模型，其余难度用 llm_model
    llm_model_hard: str = field(default_factory=lambda: os.environ.get("LLM_MODEL_HARD", ""))
    # hard 会话 effort（思考预算）：默认 max（run 10048 hard 题 20min 0 分复盘——
    # 深度不够在瞎转）；置空关闭。easy/medium 不用（flash 秒解，省时省钱）。
    claude_hard_effort: str = field(default_factory=lambda: os.environ.get("CLAUDE_HARD_EFFORT", "max"))
    llm_max_tokens: int = field(default_factory=lambda: _int("LLM_MAX_TOKENS", 8192))
    llm_temperature: float = field(default_factory=lambda: float(os.environ.get("LLM_TEMPERATURE", "0.2")))
    llm_timeout_s: int = field(default_factory=lambda: _int("LLM_TIMEOUT_S", 300))

    # 调度
    # MAX_CONCURRENT 写死为平台上限 3（run 10048 复盘：409 自适应收敛只降不升致
    # 后半程单线程——并发不降级，题轮转队尾等槽位，槽位空出立即补位）。
    max_concurrent: int = field(default_factory=lambda: _int("MAX_CONCURRENT", 3))
    # Agent 级并发：主进程 + Task 子 agent 架构下，每题只有 1 个主 claude 进程
    # （3 题槽位 = 3 主进程），子 agent 在主进程内并行不占 semaphore。
    # 8 = 3 主进程 + 断点重跑/蒸馏等辅助调用的余量（run 12396 实测峰值 9 并发
    # 沙箱稳定，6 升 8 让辅助通道不再挤占主进程额度）。
    max_agent_concurrent: int = field(default_factory=lambda: _int("MAX_AGENT_CONCURRENT", 8))
    # 双 worker 并行：总分≥1000 且 flag≥3 且无完整解法的大题，1 容器 2 条思考线
    # （共享 NOTES.md 与 flag 进度，worker-A 主攻入口面 / worker-B 主攻内网横向）
    pair_workers: bool = field(default_factory=lambda: os.environ.get("PAIR_WORKERS", "1") != "0")
    # 轮次模式：ROUND=1 覆盖优先（短时过手并留断点、不配双 worker）；
    # ROUND=2 收割（按完整解题数/墙钟时间 + 解法库 + 双线/三线攻坚）。
    round_num: int = field(default_factory=lambda: _int("ROUND", 2))

    # harness 攻坚：外部 agent CLI（claude code + ClawGod patch）接手难题。
    # 静态：第 2 轮 partial 未解题/hard 无解法题直接 harness；
    # 动态：复现题 12 步无 flag（复现失败）→ harness 重探索，输出回注裸 LLM 续跑。
    # 默认关：沙箱网关 /anthropic 通道实测通过后第 2 轮再开。
    # codex 已移除（2026-08-14）：ClawGod 自带 CC，codex 冗余。
    harness_enabled: bool = field(default_factory=lambda: os.environ.get("HARNESS", "0") != "0")
    harness_backend: str = field(default_factory=lambda: os.environ.get("HARNESS_BACKEND", "claude"))

    # claude code 直接解题（2026-08-14）：每道题 spawn 一个 claude code（ClawGod 版）完整解题，
    # bsrc-agent 只做调度/3并发/flag 提交/解法库。裸 LLM 循环保留（CLAUDE_WORKER=0 回退，本地调试用）。
    # 容器镜像默认开（Dockerfile ENV），本地 run-local.sh 不设（本地无 claude 二进制）。
    # 该模式下双 worker（pair_workers）自动禁用、harness 升级逻辑不再触发（claude 就是主体）。
    claude_worker: bool = field(default_factory=lambda: os.environ.get("CLAUDE_WORKER", "0") != "0")
    harness_timeout_min: int = field(default_factory=lambda: _int("HARNESS_TIMEOUT_MIN", 15))
    # claude 单题 token 熔断（P1，run 9054 复盘 b-02 单会话烧 920 万 token 仍 0 解）：
    # 0 = 按难度分层自动；>0 = 固定值；<0 = 禁用。6 小时最大解题数量模式默认不熔断。
    # 注意：熔断只统计主进程事件流 usage，Task 子 agent 消耗不计入（低估）；
    # 启用前先实测（详见 Worker._claude_token_budget）。
    claude_token_budget: int = field(default_factory=lambda: _int("CLAUDE_TOKEN_BUDGET", -1))
    # 永不停止：只要平台还有未解出的题就一直跑，全部解开才退出。
    # 单题超时/失败一律临时放弃（状态落库）+ 轮转续跑，不再受全局时限提前掐断。
    # NEVER_STOP=0 时才退回「受 GLOBAL_BUDGET_MIN 约束」的有界模式（调试用）。
    never_stop: bool = field(default_factory=lambda: os.environ.get("NEVER_STOP", "1") != "0")
    global_budget_min: int = field(default_factory=lambda: _int("GLOBAL_BUDGET_MIN", 345))  # 仅 NEVER_STOP=0 时生效
    # 第一轮（ROUND=1）熔断：覆盖优先快速过手，token/步数超限即放弃轮转，把难题留给第二轮攻坚。
    # 第二轮（ROUND=2）不设熔断，以解开题目为终极目标。
    round1_max_steps: int = field(default_factory=lambda: _int("ROUND1_MAX_STEPS", 40))
    round1_token_budget: int = field(default_factory=lambda: _int("ROUND1_TOKEN_BUDGET", 200_000))
    retry_unsolved: bool = field(default_factory=lambda: os.environ.get("RETRY_UNSOLVED", "1") != "0")

    # hint 策略：never / stuck / free。6 小时目标是最大化解题数量，默认直接使用提示。
    hint_policy: str = field(default_factory=lambda: os.environ.get("HINT_POLICY", "free"))
    hint_after_min: int = field(default_factory=lambda: _int("HINT_AFTER_MIN", 8))

    # Cairn 式 explore 切片（run 8900 复盘：单题 30min 长循环死磕 0 分题是最大失分源）：
    # 单段最长分钟数，段边界强制收尾（已确认发现写 NOTES/STATE，模拟 conclude 语义）。
    # 无进展判定：段内无新 flag 且 STATE.md FACTS 无新增 = 无进展段；
    # 连续 STAGNATE_SEGMENTS_HINT 段（默认 2 段=10min）→ 代码自动调 hint 注入（不等 LLM 自觉）；
    # 连续 STAGNATE_SEGMENTS_QUIT 段（默认 3 段=15min）→ 提前放弃轮转，scheduler retry 队列再收割。
    explore_segment_min: int = field(default_factory=lambda: _int("EXPLORE_SEGMENT_MIN", 5))
    stagnate_segments_hint: int = field(default_factory=lambda: _int("STAGNATE_SEGMENTS_HINT", 2))
    stagnate_segments_quit: int = field(default_factory=lambda: _int("STAGNATE_SEGMENTS_QUIT", 3))
    # 全局掉速检测（run 12396 复盘：19:56 b-01/b-03 拿一面后 36 分钟仅 +90 分，
    # 资源全在难啃单 flag 题上，b-02 等 6 面大题无一条线在打）：连续 N 分钟无
    # 新 flag 入账 → 把最高价值的多 flag 未解题强制插队（启动即自动 Task 分治）。
    # 0 = 关闭。
    stagnate_boost_min: int = field(default_factory=lambda: _int("STAGNATE_BOOST_MIN", 20))
    # 错提熔断（run 12464 复盘：145 次错提全走输出捕获通道绕过脚本闸门）：
    # auto 通道（正则捕获）累计错提 ≥ 此值后关闭；显式 submit_flag 不受限。
    wrong_submit_cap: int = field(default_factory=lambda: _int("WRONG_SUBMIT_CAP", 10))
    # 收尾段时长（分钟）：开跑满 GLOBAL_BUDGET_MIN-ENDGAME_MIN 后调度器只放行快赢题
    # （12464 复盘：收卷前 25min 还在第三轮攻 f2-05，尾段槽位全烧在零转化题上）
    endgame_min: int = field(default_factory=lambda: _int("ENDGAME_MIN", 45))

    # 上下文预算：按估算 token 计（CJK 1 字符≈1 token，其余 4 字符≈1 token）。
    # 150k 字符的全中文上下文会逼近 128k token 上限触发 LLM 400（历史 b-02 踩过），
    # 降到 90k 并改用 token 感知估算；仍超限由 worker 的激进降级重试兜底。
    context_char_budget: int = field(default_factory=lambda: _int("CONTEXT_CHAR_BUDGET", 90_000))

    # 启动预侦察：worker 开跑前自动并行 nmap/HTTP 指纹，把结果直接交给 LLM，
    # 省掉每题的 3-5 轮侦察往返。已知解法（completed）的题自动跳过。
    recon_boot: bool = field(default_factory=lambda: os.environ.get("RECON_BOOT", "1") != "0")

    # 解法库回写（completed/partial 记录）。测试/调试时可关（避免污染真实解法库）。
    record_solutions: bool = field(default_factory=lambda: os.environ.get("RECORD_SOLUTIONS", "1") != "0")

    # 运行目录（日志、每题工作区）
    run_dir: str = field(default_factory=lambda: os.environ.get("RUN_DIR", ""))

    # 调试：mock 模式不打真平台
    dry_run: bool = field(default_factory=lambda: os.environ.get("DRY_RUN", "") == "1")

    def validate(self) -> list[str]:
        errs = []
        if not self.benchmark_base_url:
            errs.append("BENCHMARK_BASE_URL 未设置")
        if not self.benchmark_token:
            errs.append("BENCHMARK_TOKEN 未设置")
        if not self.llm_api_key:
            errs.append("LLM_API_KEY 未设置")
        if self.hint_policy not in ("never", "stuck", "free"):
            errs.append(f"HINT_POLICY 非法: {self.hint_policy}")
        if self.max_concurrent < 1:
            errs.append("MAX_CONCURRENT 必须 >= 1")
        if self.max_agent_concurrent < 1:
            errs.append("MAX_AGENT_CONCURRENT 必须 >= 1")
        return errs
