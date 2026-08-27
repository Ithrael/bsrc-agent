"""调度器：3 个题目槽位 + Agent 并发上限 + 优先级队列 + 全局时限。

选题目标是完整解出题数/墙钟时间：优先已知解法和只剩一面 flag 的题，
再处理新单 flag，最后轮转 hard/多 flag 大题。未解出的题在队列尾重排（retry）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time

from .config import Config, notes_lib_path, solution_lib_path
from .flagger import FlagSubmitter
from .llm import LLMClient
from .tsec_api import CODE_INVALID_STATE, ApiError, Challenge, TsecClient
from .worker import Worker, WorkerResult

log = logging.getLogger("scheduler")

_EST_MIN = {"easy": 4, "medium": 10, "hard": 25}
_PLATFORM_MAX_CONCURRENT = 3

# 解法库（solutions.json）：completed=上轮已解出（快速锁分）；partial=上轮有断点（尽早续跑）
_LIB: dict[str, dict] = {}
try:
    with open(solution_lib_path()) as _f:
        _LIB = json.load(_f)
except Exception:
    _LIB = {}


def _reload_lib():
    """运行中重载解法库：本轮的 partial/completed 记录影响 retry 队列排序。"""
    global _LIB
    try:
        with open(solution_lib_path()) as f:
            _LIB = json.load(f)
    except Exception:
        pass


def _challenge_completed(ch: Challenge) -> bool:
    """平台布尔字段与计数字段任一确认全通即可，防止状态快照短暂不同步。"""
    return ch.is_completed or (
        ch.flag_count > 0 and ch.correct_flag_count >= ch.flag_count
    )


def _load_events(run_dir: str) -> dict[str, dict]:
    """读 events.jsonl 聚合成每题统计：attempts / completed / p50（完整解出耗时
    中位数，只统计解出的 attempt）/ solve_prob。损坏/缺失返回空 dict——这是
    增强项不是前置依赖（fix 6：实测数据驱动排序替代部分硬编码阈值）。"""
    stats: dict[str, dict] = {}
    if not run_dir:
        return stats
    try:
        with open(os.path.join(run_dir, "events.jsonl")) as f:
            events = [json.loads(l) for l in f if l.strip()]
    except (OSError, ValueError):
        return stats
    for e in events:
        code = e.get("challenge")
        if not code:
            continue
        st = stats.setdefault(code, {"attempts": 0, "completed": 0, "durations": []})
        st["attempts"] += 1
        if e.get("completed"):
            st["completed"] += 1
            if e.get("elapsed_min"):
                st["durations"].append(float(e["elapsed_min"]))
    for st in stats.values():
        d = sorted(st["durations"])
        st["p50"] = d[len(d) // 2] if d else None
        st["solve_prob"] = st["completed"] / st["attempts"]
    return stats


def _priority(ch: Challenge, round_num: int = 2,
              stats: dict[str, dict] | None = None) -> float:
    """按「完整解出题目数 / 墙钟时间」排序，而不是按分值排序。

    多 flag 题只有全部 flag 都拿到才增加一道已解题，因此剩余一面应显著
    优先于全新的多 flag 大题；同一档内 easy/medium/hard 依次尝试。
    stats（events.jsonl 实测聚合）：P50 完整解出耗时替代难度估算；
    高解出率剩一面题提到断点档；多轮实测零解的题降权。
    """
    info = _LIB.get(ch.unique_code) or {}
    difficulty_rank = {"easy": 0, "medium": 1, "hard": 2}.get(ch.difficulty, 3)
    est = _EST_MIN.get(ch.difficulty, 12)
    if info.get("elapsed_min"):
        est = max(1.0, float(info["elapsed_min"]))

    remaining = ch.remaining_flags
    if info.get("completed"):
        rank = 0                         # 已知解法：优先快速复现
    elif info.get("partial") and remaining <= 1:
        rank = 1                         # 断点只剩最后一面：最高命中率
    elif remaining <= 1:
        rank = 2 + difficulty_rank      # 新的单 flag 题：优先解题数量
    elif info.get("partial"):
        rank = 5 + difficulty_rank      # 有断点但仍多面
    else:
        # 全新多 flag 题最后处理；但高分大题（≥1000 分，b 系列 1200-1800）提前
        # 到与 partial 多面同级（run 12396 复盘：b-02 1800 分从头到尾没启动，
        # 槽位被单 flag 题反复占满，子 agent 无题可派，整段无分治低效期）。
        rank = (5 if ch.total_score >= 1000 else 8) + difficulty_rank

    st = (stats or {}).get(ch.unique_code)
    if st and st.get("attempts"):
        # 实测数据校正（fix 6）：此前每轮 result 直接覆盖 done[code]，无法比较
        # 不同模型/fan-out 的真实收益；events.jsonl 让优先级从数据学习
        if st.get("p50"):
            est = max(1.0, min(est, float(st["p50"])))   # 历史 P50 优于难度估算
        if st.get("solve_prob", 0) >= 0.6 and remaining <= 1:
            rank = 1                     # 实测高解出率的剩一面题 ≈ 断点题
        elif st.get("solve_prob", 0) == 0.0 and st.get("attempts", 0) >= 2:
            rank += 4                    # 多轮实测零解：降权（仍高于全新多面大题）

    if round_num == 1 and not info:
        rank -= 10                       # 保留 ROUND=1 的全题覆盖语义
    return rank * 1000 + est


class Scheduler:
    # 409 轮转后的重试冷却（秒）：防止平台持续拒绝时以 0.6s 频率空转打 start
    start_backoff_s = 30

    def __init__(self, cfg: Config, llm: LLMClient, api: TsecClient, run_dir: str):
        self.cfg = cfg
        self.llm = llm
        self.api = api
        self.run_dir = run_dir
        # 永不停止模式下无全局截止（deadline=∞，worker 永不触发 global deadline），
        # 有界模式退回原语义：GLOBAL_BUDGET_MIN 分钟后收尾。
        self.deadline = float("inf") if cfg.never_stop else time.monotonic() + cfg.global_budget_min * 60
        # 开跑时刻：endgame 判定用（never_stop 下 deadline=∞，但平台 6h 硬窗仍在，
        # 按「名义窗口 - ENDGAME_MIN」触发收尾策略）
        self._t0 = time.monotonic()
        self._endgame_logged = False
        self.pending: list[Challenge] = []
        self.retry_queue: list[Challenge] = []
        self.done: dict[str, dict] = {}
        self.running: dict[str, asyncio.Task] = {}
        # 实测事件统计（events.jsonl 聚合）：选题优先级从历史数据学习
        self._events: dict[str, dict] = _load_events(run_dir) if run_dir else {}
        # 平台题目槽位硬上限为 3；即使环境变量误填更大，也不能把 start 打爆。
        self.effective_max = min(_PLATFORM_MAX_CONCURRENT, max(1, cfg.max_concurrent))
        self._sem = asyncio.Semaphore(self.effective_max)
        # challenge 槽位与 Claude Agent 槽位分离：最多 3 题、默认最多 9 条思考线。
        self._agent_sem = asyncio.Semaphore(cfg.max_agent_concurrent)
        self._start_attempts: dict[str, int] = {}   # start 接口 invalid_state 重试计数
        self._attempts: dict[str, int] = {}         # 选题尝试次数（0=首轮限长超时，≥1=retry 放长）
        self._last_start_ts = 0.0                   # start 限速时间戳
        self.active_workers: dict[str, Worker] = {}
        self._watchdog_stop = False
        # 并发写死 3（平台同时最多 3 题）：409 不降级，题轮转队尾等槽位（run 10048
        # 复盘：409 收敛只降不升致后半程单线程，吞吐损失 2/3——宁可轮转不可塌缩）
        self._start_backoff: dict[str, float] = {}  # 409 轮转的题 -> 可重试时间戳
        # 钉子题（hint 已看 + 多轮 0 flag）判死集合：不进常规 retry、不参与常规回查；
        # 只剩钉子题未解时回查轮仍会回挖（其他题全解了，打死题零机会成本）
        self._dead: set[str] = set()
        self._task_finished = False  # 平台任务已结束（start/close 报 already finished）时置位停止空转
        # claude 运行时健康度：连续崩溃/无输出计数（启动三道闸只防"带病上场"，
        # 这里防运行中恶化——网关策略变化/运行时错误。达标全局降级裸 LLM）
        self._claude_fail_streak = 0
        # 全局掉速检测：harness 的 flag 走 submit_flag.sh 直连，本地感知不到，
        # 以平台 correct_flag_count 总数为准（60s 回查一次）。
        self._last_total_flags = -1          # 上次回查的全局 correct flag 数（-1=未校准）
        self._last_progress_ts = time.monotonic()  # 最近一次 flag 增长的墙钟时间
        self._last_boost_ts = 0.0            # 上次掉速插队时间（20min 冷却防反复插同一题）
        self._last_stagnate_check = 0.0      # 上次掉速检查墙钟时间

    def _in_endgame(self) -> bool:
        """是否进入收尾段：开跑超过「名义窗口 - ENDGAME_MIN」分钟。

        never_stop 下 deadline=∞，但平台 6h 硬窗不变——按 GLOBAL_BUDGET_MIN（默认
        345min）作名义窗口，最后 ENDGAME_MIN（默认 45min）切收尾策略。"""
        return (time.monotonic() - self._t0
                >= (self.cfg.global_budget_min - self.cfg.endgame_min) * 60)

    def _endgame_ok(self, ch: Challenge) -> bool:
        """收尾段快赢题：只剩一面 flag、或有完整解法可短时复现的题。
        新 hard/多 flag 大题不放行（12464 教训：尾段开新硬题=纯烧尾段槽位）。"""
        if ch.remaining_flags <= 1:
            return True
        return bool(_LIB.get(ch.unique_code, {}).get("completed"))

    async def _watchdog(self):
        """容器看门狗：worker 在跑但容器被平台回收时自动重启并更新地址。"""
        while not self._watchdog_stop:
            await asyncio.sleep(45)
            if not self.active_workers:
                continue
            try:
                lst = await self._refresh()
            except ApiError:
                continue
            status = {c.unique_code: c for c in lst}
            for code, workers in list(self.active_workers.items()):
                c = status.get(code)
                if not c or c.container_status == "available":
                    continue
                log.warning("[watchdog] %s 容器状态 %s，worker 仍在跑，尝试重启", code, c.container_status)
                try:
                    addrs = await self._start_throttled(code)
                except ApiError as e:
                    log.warning("[watchdog] %s 重启失败: %s", code, e)
                    continue
                if addrs:
                    if addrs != workers[0].addrs:
                        old_addrs = list(workers[0].addrs)
                        log.warning("[watchdog] %s 新地址 %s（旧 %s），写入 NOTES.md/STATE.md",
                                    code, addrs, old_addrs)
                        # 地址记录行只写新地址（旧地址换行写）：worker 的 _rotation_notice
                        # 按行解析"最后记录的目标"，混写旧地址会导致重复告警
                        try:
                            with open(workers[0].notes_path, "a") as f:
                                f.write(f"\n\n[watchdog] 容器已轮换，新地址: {', '.join(addrs)}\n"
                                        f"（旧地址 {', '.join(old_addrs)} 已失效：旧登录态/cookie/"
                                        "后台任务/半成品连接作废。按 NOTES.md 恢复已发现凭据与路径，"
                                        "对新地址快速重验入口后从断点继续，禁止从头全量侦察。）\n")
                        except OSError:
                            pass
                        try:
                            with open(workers[0].state_path, "a") as f:
                                f.write("## FACTS\n"
                                        f"- 容器已轮换: 当前目标 {', '.join(addrs)}"
                                        f"（旧 {', '.join(old_addrs)} 已失效，登录态需重建）\n")
                        except (OSError, AttributeError):
                            pass
                    for w in workers:
                        w.addrs = addrs
                    log.info("[watchdog] %s 容器已恢复: %s", code, ", ".join(addrs))


    async def _refresh(self) -> list[Challenge]:
        return await self.api.list_challenges()

    async def _stagnate_check(self):
        """全局掉速检测（run 12396 复盘）：连续 N 分钟无新 flag 入账时，把最高
        价值的多 flag 未解题强制插队到 pending 队头——worker 对多 flag 题启动即
        派 Task 子 agent 分治（4-8 线），插队即转分治。flag 计数以平台回查为准
        （harness 的 flag 走 submit_flag.sh 直连，本地 submitter 感知不到）。
        20 分钟冷却防反复插同一题；仅插队不杀在跑任务（不干扰正在解的题）。"""
        if self.cfg.stagnate_boost_min <= 0:
            return
        try:
            challenges = await self._refresh()
        except ApiError:
            return
        total = sum(c.correct_flag_count for c in challenges)
        now = time.monotonic()
        if total > self._last_total_flags:
            self._last_total_flags = total
            self._last_progress_ts = now
            return
        if now - self._last_progress_ts < self.cfg.stagnate_boost_min * 60:
            return
        if now - self._last_boost_ts < 1200:
            return
        # 目标：剩余面最多的多 flag 未解题（b 系列 4-6 面大题），且不在跑/不在冷却
        fresh = {c.unique_code: c for c in challenges}
        candidates = [fresh.get(c.unique_code, c)
                      for c in self.pending + self.retry_queue
                      if fresh.get(c.unique_code, c).remaining_flags >= 2
                      and c.unique_code not in self.active_workers
                      and not _challenge_completed(fresh.get(c.unique_code, c))]
        if not candidates:
            return
        target = max(candidates, key=lambda c: (c.remaining_flags, c.total_score))
        self.pending = [c for c in self.pending if c.unique_code != target.unique_code]
        self.retry_queue = [c for c in self.retry_queue if c.unique_code != target.unique_code]
        self.pending.insert(0, target)
        self._last_boost_ts = now
        log.warning("[stagnate] 连续 %d 分钟无新 flag，强制插队 %s（%d 面剩 %d 分）"
                    "转分治攻坚", self.cfg.stagnate_boost_min, target.unique_code,
                    target.remaining_flags, target.total_score)

    async def _start_throttled(self, code: str) -> list[str]:
        """start 接口限速（相邻调用 ≥0.6s）：平台文档上限 3 题并发，
        MAX_CONCURRENT 调高（百度赛若放宽）时避免瞬间并发 start 触发 invalid_state。"""
        gap = 0.6 - (time.monotonic() - self._last_start_ts)
        if gap > 0:
            await asyncio.sleep(gap)
        self._last_start_ts = time.monotonic()
        return await self.api.start_challenge(code)

    async def _wait_available(self, code: str, timeout_s: int = 300) -> list[str]:
        """start 后轮询直到容器 available 拿到地址。

        轮询间隔 2s（原 5s）：容器启动是每题轮转的固定开销，40 次轮转
        × 平均 3s 增量 ≈ 省 2 分钟；_refresh 是轻量列表接口，2s 频率安全。"""
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout_s:
            try:
                lst = await self._refresh()
            except ApiError:
                await asyncio.sleep(2)
                continue
            for c in lst:
                if c.unique_code == code:
                    if c.container_status == "available" and c.container_addr:
                        return c.container_addr
                    if c.container_status == "stopped" and time.monotonic() - t0 > 30:
                        # 可能被平台回收，尝试重启
                        try:
                            return await self.api.start_challenge(code)
                        except ApiError:
                            pass
                    break
            await asyncio.sleep(2)
        return []

    def _track_claude_health(self, res: WorkerResult):
        """claude 运行时健康度：连续崩溃/无输出达阈值（默认 6 次 ≈ 全槽位两轮
        快速失败）就全局降级裸 LLM 模式。崩溃是秒级的，坏 claude 几分钟内触发；
        单题偶发（容器抖动）有 3 槽位余量不会误杀。任何一次正常输出即清零。
        覆盖 claude_worker 与静态 harness 两条路径（harness 崩溃同样是运行时恶化）。"""
        if not (self.cfg.claude_worker or self.cfg.harness_enabled):
            return
        r = res.reason or ""
        if r.startswith(("crash:", "claude no output", "harness crash",
                         "harness done (0 events)")):
            self._claude_fail_streak += 1
            if self._claude_fail_streak >= 6:
                log.error("claude 连续 %d 次崩溃/无输出（运行中恶化），"
                          "全局降级裸 LLM 模式继续解题", self._claude_fail_streak)
                self.cfg.claude_worker = False
                self.cfg.harness_enabled = False
        else:
            self._claude_fail_streak = 0

    async def _close_safely(self, code: str) -> None:
        """close + 失败重试一次：实例泄漏会占平台槽位（3 上限写死，泄漏=槽位永久少一个）。"""
        try:
            await self.api.close_challenge(code)
            return
        except ApiError as e:
            log.warning("[%s] close 失败: %s", code, e)
        await asyncio.sleep(2)
        try:
            await self.api.close_challenge(code)
        except ApiError as e2:
            log.warning("[%s] close 重试仍失败: %s", code, e2)

    async def _start_flow(self, ch: Challenge) -> tuple[list[str], bool]:
        """启动流程：复用存活容器 → start → 等待就绪。返回 (addrs, requeued)。
        requeued=True 表示题已轮转队尾（409/start 失败/平台结束），调用方直接 return。
        调用方用 8min 保险丝包裹：run 10048 复盘 bctf-05/08 卡在启动阶段 40+ 分钟堵槽。"""
        code = ch.unique_code
        # 先查是否已有活体容器可复用（重跑/平台残留时避免重复 start）
        addrs: list[str] = []
        try:
            for c in await self._refresh():
                if c.unique_code == code and c.container_status == "available" and c.container_addr:
                    addrs = c.container_addr
                    log.info("[%s] 复用存活容器: %s", code, ", ".join(addrs))
                    break
        except ApiError:
            pass
        if not addrs:
            try:
                addrs = await self._start_throttled(code)
            except ApiError as e:
                if e.code == CODE_INVALID_STATE:
                    if "already finished" in (e.message or ""):
                        # 平台任务已结束（时限到/平台终止，run 8629 复盘 16:37 发生）：
                        # 之后所有 start 都会 409，停止空转并退出调度。
                        log.warning("[%s] 平台任务已结束：%s，停止调度", code, e.message)
                        self._task_finished = True
                        self.pending.clear()
                        return [], True
                    # 平台活跃实例数达上限（api-doc §5.2）。并发写死 3（不降级，
                    # run 10048 复盘 effective_max 收敛致后半程单线程、吞吐损失 2/3）：
                    # 题轮转队尾 + 冷却重试，槽位空出后立即补位。
                    log.warning("[%s] start 409（平台实例满，3 槽位），题轮转队尾", code)
                    self._start_backoff[code] = time.monotonic() + self.start_backoff_s
                    self.pending.append(ch)
                    return [], True
                log.error("[%s] start 失败: %s", code, e)
                self.done[code] = {"completed": False, "score": 0, "reason": f"start: {e.code}"}
                # 永不停止：start 失败也冷却轮转重试，不终局丢弃（防单题永久丢失）。
                self._start_backoff[code] = time.monotonic() + self.start_backoff_s
                self.pending.append(ch)
                return [], True
        if not addrs:
            addrs = await self._wait_available(code)
        return addrs, False

    async def _run_one(self, ch: Challenge, attempt: int = 0):
        code = ch.unique_code
        async with self._sem:
            ws = os.path.join(self.run_dir, code)
            os.makedirs(ws, exist_ok=True)
            log.info("[%s] 启动容器 (%s/%d 分, %d flags)", code, ch.difficulty, ch.total_score, ch.flag_count)
            try:
                addrs, requeued = await asyncio.wait_for(self._start_flow(ch), timeout=480)
            except asyncio.TimeoutError:
                log.error("[%s] 启动流程超时（8min 保险丝），放弃本轮", code)
                self.done[code] = {"completed": False, "score": 0, "reason": "start flow timeout"}
                await self._close_safely(code)  # 释放可能残留的容器实例
                self._start_backoff[code] = time.monotonic() + self.start_backoff_s
                self.pending.append(ch)
                return
            if requeued:
                return
            if not addrs:
                log.error("[%s] 容器未就绪，放弃", code)
                self.done[code] = {"completed": False, "score": 0, "reason": "container not ready"}
                await self._close_safely(code)  # start 已成功但未就绪：释放槽位防泄漏
                self._start_backoff[code] = time.monotonic() + self.start_backoff_s
                self.pending.append(ch)
                return
            log.info("[%s] 目标: %s", code, ", ".join(addrs))
            if self._should_use_harness(ch):
                await self._run_harness_worker(ch, addrs, ws)
                return
            if self._should_pair(ch):
                await self._run_paired(ch, addrs, ws)
                return
            worker = Worker(self.cfg, self.llm, self.api, ch, addrs, ws, self.deadline,
                            attempt=attempt, agent_semaphore=self._agent_sem)
            self.active_workers[code] = [worker]
            try:
                res = await worker.run()
            except Exception as e:
                log.exception("[%s] worker 崩溃", code)
                res = worker.result
                res.reason = f"crash: {type(e).__name__}: {e}"
            finally:
                self.active_workers.pop(code, None)
            self._track_claude_health(res)
            await self._finish(ch, res)

    def _should_use_harness(self, ch: Challenge) -> bool:
        """第 2 轮攻坚题直接 harness：第 1 轮没解出的（partial）或无解法的 hard 题。
        completed 复现题裸 LLM 更快更省；easy/medium 裸 LLM 就能解。"""
        if not self.cfg.harness_enabled:
            return False
        if self.cfg.round_num < 2:
            return False
        info = _LIB.get(ch.unique_code, {})
        if info.get("completed"):
            return False
        return bool(info.get("partial")) or ch.difficulty == "hard"

    async def _run_harness_worker(self, ch: Challenge, addrs: list[str], ws: str):
        """单题 harness worker：prompt 注入题目信息 + 解法库/专家复盘 + 工作区约定。"""
        from .flagger import extract_flags
        from .harness import run_harness
        from .worker import _sanitize_step, record_harness_solution
        code = ch.unique_code
        log.info("[%s] harness 直接攻坚（backend=%s）", code, self.cfg.harness_backend)
        notes_path = os.path.join(ws, "NOTES.md")
        state_path = os.path.join(ws, "STATE.md")
        if not os.path.exists(notes_path):
            with open(notes_path, "w") as f:
                f.write(f"# {code} 笔记\n\n目标: {', '.join(addrs)}\n\n")
        if not os.path.exists(state_path):
            with open(state_path, "w") as f:
                f.write("# 结构化状态（FACTS 由代码自动维护；INTENTS/ELIMINATED 由你按约定登记）\n\n"
                        "## FACTS\n"
                        f"- flag 进度: 0/{ch.flag_count}\n")
        # 解法库/专家复盘注入（复用 Worker 的清洗与 notes.json 优先约定）
        sol = _LIB.get(code) or {}
        try:
            with open(notes_lib_path()) as f:
                notes = json.load(f)
        except (OSError, json.JSONDecodeError):
            notes = {}
        inj = ""
        if sol.get("steps") or sol.get("note") or code in notes:
            steps = "\n".join(f"- {_sanitize_step(s, ws)}"
                              for s in sol.get("steps", [])[-15:])[:6000]
            note = (notes.get(code) or sol.get("note") or "")[:2500]
            status = "已解出（上轮）" if sol.get("completed") else "部分进展（上轮未解出）"
            inj = f"\n## 上轮解法记录（{status}，flag 每轮重新生成，方法可参考）\n"
            if note:
                inj += f"专家复盘：\n{note}\n"
            if steps:
                inj += f"关键步骤：\n{steps}\n"
        from .prompts import METATIPS, global_intel, playbook_for
        playbook = playbook_for(code, ch.description or "")
        intel = global_intel()
        prompt = (
            "你是一名顶级自动化渗透测试 Agent，正在 Tsecbench 评测环境中独立解一道安全挑战题。"
            "全程无人工干预，必须自主完成侦察、分析、利用并获取 flag。\n\n"
            f"题目代码：{code}\n难度/分值：{ch.difficulty} / {ch.total_score} 分\n"
            f"描述：{ch.description or '(无描述，全靠侦察)'}\n目标地址：\n"
            + "\n".join(f"- {a}" for a in addrs) + "\n"
            + inj + "\n"
            + (intel + "\n" if intel else "")
            + METATIPS + "\n"
            + playbook + "\n"
            "\n当前工作目录就是你的战场：所有文件/脚本都留在这里；"
            "NOTES.md 写自由笔记，STATE.md 登记结构化状态（## ELIMINATED 记放弃方向）。\n\n"
            "行动纪律：\n"
            "1. 先读 NOTES.md/STATE.md（若有上轮解法记录，直接按记录复现验证，不要从头侦察）。\n"
            "2. 拿到疑似 flag 立即写入 flags.txt（每行一个），同时继续推进。\n"
            "3. 关键发现追加进 NOTES.md；确认放弃的方向记进 STATE.md 的 ## ELIMINATED。\n"
            "4. 禁止长时间盲扫（几万行字典全量爆破），优先理解业务/CVE/默认凭证。\n"
            f"5. 本题共有 {ch.flag_count} 面 flag，多面时每拿到一面都要继续找下一面。\n"
        )
        flags: list[str] = []

        def _on_text(text: str):
            for fl in extract_flags(text):
                if fl not in flags:
                    flags.append(fl)

        submitter = FlagSubmitter(code, ch.flag_count, ch.correct_flag_count,
                                   wrong_cap=self.cfg.wrong_submit_cap)
        h_timeout = min(90, self.cfg.harness_timeout_min * max(1, ch.flag_count)) * 60
        try:
            async with self._agent_sem:
                res = await run_harness(self.cfg, prompt, ws, h_timeout, on_text=_on_text)
        except Exception as e:
            log.exception("[%s] harness worker 崩溃", code)
            res = None
        for flag in flags:
            if submitter.should_try(flag, auto=True):
                try:
                    r = await self.api.submit_flag(code, flag)
                except ApiError as e:
                    if e.code == "duplicate":
                        # duplicate 不能盲目把进度 +1：同题多 Agent 可能同时提交同一面，
                        # 否则会把 2/3 误判为 3/3。后续正常响应会用平台计数校准。
                        submitter.record(flag, True, 0)
                        continue
                    log.warning("[%s] harness flag 提交失败: %s", code, e)
                    continue
                submitter.record(flag, r.correct, r.awarded, r.correct_flag_count)
                if r.correct:
                    log.info("[%s] harness FLAG 正确 +%d (%d/%d)", code, r.awarded,
                             r.correct_flag_count, r.total_flag_count)
        merged = WorkerResult()
        merged.completed = submitter.completed
        merged.score = submitter.score
        merged.flags = sorted(submitter.correct)
        merged.reason = "all flags captured" if merged.completed else \
            ("harness crash" if res is None else f"harness done ({res.events} events)")
        merged.elapsed_min = h_timeout / 60 if not merged.completed else 0
        merged.meta = {"model": f"harness:{self.cfg.harness_backend}",
                       "fan_out": 0,
                       "tokens": res.total_tokens if res else 0}
        try:
            with open(os.path.join(ws, "RESULT.json"), "w") as f:
                json.dump({
                    "unique_code": code, "harness": True,
                    "backend": self.cfg.harness_backend,
                    "completed": merged.completed, "score": merged.score,
                    "flags": merged.flags, "reason": merged.reason,
                }, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
        # 健康度追踪 + 解法落库（闭环补全：harness 崩溃计入降级 streak；
        # completed/partial 写 solutions.json，_LIB/优先级/复现/收尾门才感知得到）
        self._track_claude_health(merged)
        if self.cfg.record_solutions:
            note = ((res.output_text or "") + "\n" + res.digest()) if res else ""
            record_harness_solution(code, note, merged.completed, merged.elapsed_min)
        await self._finish(ch, merged)

    def _should_pair(self, ch: Challenge) -> bool:
        """大题双 worker：总分高、flag 多、无完整解法可复现时，两条思考线共享一个容器。

        复盘：b-02/b-03（1200 分大题）单线 60min 首轮封顶吃满仍只拿 2/6、3/6，
        内网链/多阶段题需要并行探路；有 completed 解法的题直接复现更快，不配。
        """
        if not self.cfg.pair_workers:
            return False
        if self.cfg.claude_worker:
            return False  # claude 直接解题模式：每题一个 claude code 进程已够，双 worker 是裸 LLM 概念
        if self.cfg.round_num == 1:
            return False  # ROUND=1 覆盖优先：双 worker 是攻坚武器，留给第 2 轮
        if ch.total_score < 1000 or ch.flag_count < 3:
            return False
        if _LIB.get(ch.unique_code, {}).get("completed"):
            return False
        return True

    async def _run_paired(self, ch: Challenge, addrs: list[str], ws: str):
        """同一容器跑 2 个 worker：共享 FlagSubmitter（进度/completed 判定）与 NOTES.md，
        工作区隔离（worker-A / worker-B），A 主攻入口面、B 主攻内网/横向。"""
        code = ch.unique_code
        log.info("[%s] 双 worker 并行（%d 分 %d flags）", code, ch.total_score, ch.flag_count)
        submitter = FlagSubmitter(code, ch.flag_count, ch.correct_flag_count,
                                   wrong_cap=self.cfg.wrong_submit_cap)
        completion_event = asyncio.Event()
        notes_path = os.path.join(ws, "NOTES.md")
        if not os.path.exists(notes_path):
            with open(notes_path, "w") as f:
                f.write(f"# {code} 笔记（双 worker 共享）\n\n目标: {', '.join(addrs)}\n\n")
        role_a = ("\n## 并行协作\n"
                  "本题同时有另一个 worker 在解同一目标（共享 ../NOTES.md、../STATE.md 与 flag 进度）。"
                  "你主攻：Web 入口面、认证、已知 CVE、本机 flag 直读。"
                  "关键发现（端点/凭据/payload）用短行 echo 追加进 ../NOTES.md "
                  "（长内容 write_file 到独立文件），开新方向前先读 ../STATE.md 的 FACTS/ELIMINATED 避免重复。")
        role_b = ("\n## 并行协作\n"
                  "本题同时有另一个 worker 在解同一目标（共享 ../NOTES.md、../STATE.md 与 flag 进度）。"
                  "你主攻：内网/横向移动/非 Web 端口/多阶段链后续阶段。"
                  "先 read_file ../STATE.md 与 ../NOTES.md 了解对方进展，只做对方没做的事；"
                  "你的发现同样用短行 echo 追加进 ../NOTES.md，放弃的方向登记进 ../STATE.md 的 ## ELIMINATED。")
        state_path = os.path.join(ws, "STATE.md")
        state_lock = threading.Lock()
        both_transcripts = [os.path.join(ws, "worker-A", "transcript.jsonl"),
                            os.path.join(ws, "worker-B", "transcript.jsonl")]
        w_a = Worker(self.cfg, self.llm, self.api, ch, addrs,
                     os.path.join(ws, "worker-A"), self.deadline,
                     submitter=submitter,
                     notes_path=notes_path, state_path=state_path,
                     state_lock=state_lock, role_extra=role_a,
                     transcripts=both_transcripts, agent_semaphore=self._agent_sem,
                     completion_event=completion_event)
        w_b = Worker(self.cfg, self.llm, self.api, ch, addrs,
                     os.path.join(ws, "worker-B"), self.deadline,
                     submitter=submitter,
                     notes_path=notes_path, state_path=state_path,
                     state_lock=state_lock, role_extra=role_b,
                     transcripts=both_transcripts,
                     write_notes_injection=False, agent_semaphore=self._agent_sem,
                     completion_event=completion_event)  # 解法注入只由 A 写共享笔记
        self.active_workers[code] = [w_a, w_b]
        merged = WorkerResult()
        try:
            tasks = [asyncio.create_task(w_a.run()), asyncio.create_task(w_b.run())]

            async def _cancel_loser_workers():
                await completion_event.wait()
                if submitter.completed:
                    for task in tasks:
                        if not task.done():
                            task.cancel()

            stopper = asyncio.create_task(_cancel_loser_workers())
            try:
                res_a, res_b = await asyncio.gather(*tasks, return_exceptions=True)
            finally:
                stopper.cancel()
            merged.completed = submitter.completed or any(
                r.completed for r in (res_a, res_b) if isinstance(r, WorkerResult))
            merged.score = submitter.score
            merged.flags = sorted(submitter.correct)
            merged.steps = sum(r.steps for r in (res_a, res_b) if isinstance(r, WorkerResult))
            merged.elapsed_min = max(
                (r.elapsed_min for r in (res_a, res_b) if isinstance(r, WorkerResult)),
                default=0.0)
            reasons = []
            for tag, r in (("A", res_a), ("B", res_b)):
                if isinstance(r, WorkerResult):
                    reasons.append(f"{tag}: {r.reason}")
                else:
                    reasons.append(f"{tag}: crash {type(r).__name__}")
            merged.reason = " / ".join(reasons)
            merged.meta = {"model": f"paired:{self.cfg.llm_model}",
                           "fan_out": 2,
                           "tokens": sum((r.meta or {}).get("tokens", 0)
                                         if isinstance(r, WorkerResult) else 0
                                         for r in (res_a, res_b))}
        finally:
            self.active_workers.pop(code, None)
        try:
            with open(os.path.join(ws, "RESULT.json"), "w") as f:
                json.dump({
                    "unique_code": code, "paired": True,
                    "completed": merged.completed, "score": merged.score,
                    "flags": merged.flags, "reason": merged.reason,
                    "steps": merged.steps, "elapsed_min": round(merged.elapsed_min, 1),
                }, f, ensure_ascii=False, indent=2)
        except OSError:
            pass
        await self._finish(ch, merged)

    def _record_event(self, ch: Challenge, res: WorkerResult):
        """append 一行事件到 run_dir/events.jsonl（fix 6）：challenge/attempt/
        模型/fan-out/起止时长/首 flag 时间/原语数/token/最终 flag 数/退出原因。
        用于跨 attempt 比较不同模型、角色与 fan-out 的真实收益；done[code]
        此前每次结果覆盖，无法做这种比较。"""
        run_dir = getattr(self, "run_dir", "")
        if not run_dir:
            return
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "challenge": ch.unique_code,
            "attempt": self._attempts.get(ch.unique_code, 0),
            "difficulty": ch.difficulty,
            "total_score": ch.total_score,
            "flag_count": ch.flag_count,
            "elapsed_min": round(res.elapsed_min, 1),
            "flags_final": len(res.flags or []),
            "completed": bool(res.completed),
            "score": res.score,
            "reason": res.reason,
        }
        rec.update(res.meta or {})
        try:
            os.makedirs(run_dir, exist_ok=True)
            with open(os.path.join(run_dir, "events.jsonl"), "a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self._events = _load_events(run_dir)  # 聚合刷新：下一次排序用最新数据
        except OSError:
            pass

    async def _finish(self, ch: Challenge, res: WorkerResult):
        """收尾：记录 done、关闭容器、未解出进 retry 队列。"""
        code = ch.unique_code
        self._record_event(ch, res)
        self.done[code] = {
            "completed": res.completed, "score": res.score,
            "flags": res.flags, "reason": res.reason,
            "elapsed_min": round(res.elapsed_min, 1),
        }
        log.info("[%s] 结束: %s (+%d 分, %.1f 分钟)", code, res.reason, res.score, res.elapsed_min)
        await self._close_safely(code)
        # no_progress（attempt≥2 无 flag 无断点）不进常规 retry：时间留给有希望的题；
        # 主循环队列耗尽后的平台回查（NEVER_STOP 回查全部未解题）仍会带回它们，
        # 满足「时间没用完就继续挖零进展题」。
        # 钉子题熔断（12641 复盘：7 道钉子题 hint 已看仍 0 分，空转烧槽位——
        # hint 是能力探针，看了还解不出 = 死题）：notes.json 有 [官方 hint] 记录
        # 且 ≥2 次尝试且零 flag → 判死入 _dead（常规 retry 与回查都不再带回；
        # 其他题全解后回查轮仍回挖）。零分判据必须同时看本轮（res.score/flags）
        # 与平台快照（ch.correct_flag_count）：平台已有部分 flag 的题本轮没新增
        # ≠ 死题，只看 res.score 会把 2/6 续跑题误杀。
        nail = False
        attempts = getattr(self, "_attempts", {})  # __new__ 构造的测试实例无此属性
        if (attempts.get(code, 0) >= 2 and res.score == 0 and not res.flags
                and getattr(ch, "correct_flag_count", 0) == 0):
            try:
                with open(notes_lib_path()) as f:
                    nlib = json.load(f)
                nail = (nlib.get(code) or "").startswith("[官方 hint]")
            except (OSError, json.JSONDecodeError):
                pass
        if nail:
            self._dead.add(code)
            log.info("[%s] 钉子题判死（hint 已看 + %d 轮 0 flag），常规轮转不再重试",
                     code, attempts.get(code, 0))
        elif not res.completed and self.cfg.retry_unsolved and "deadline" not in res.reason \
                and not res.reason.startswith("no_progress"):
            self.retry_queue.append(ch)

    def _promote_retry_in_endgame(self):
        """收尾段把 retry 队列并入 pending 队头。endgame 放行门拦下的题会永远
        留在 pending（放行门只跳过不清除），retry→pending 的晋升又只在 pending
        清空后触发——不插队的话最后 ENDGAME_MIN 分钟全系统空转到收卷，retry 里的
        快赢题（剩一面断点续跑）恰恰是尾段最该打的。并入后统一走放行门过滤。"""
        if not (self._in_endgame() and self.pending and self.retry_queue):
            return
        codes_in_pending = {c.unique_code for c in self.pending}
        promo = [c for c in self.retry_queue if c.unique_code not in codes_in_pending]
        self.retry_queue = []
        if promo:
            _reload_lib()
            self.pending = (sorted(promo, key=lambda c: _priority(c, self.cfg.round_num, getattr(self, "_events", {})))
                            + self.pending)

    async def _pull_retry_into_pending(self) -> bool:
        """retry 队列并入 pending（按平台快照过滤已完成题）。返回是否有题可派。

        13174 实测修复：此前只在「pending 空且无任务在跑」时拉取 retry——
        b 系列长预算攻坚期间其余槽位空转 10-30 分钟（历史多轮尾段空窗同源）。
        现在主循环每个 tick（15s）只要有空槽就拉取补位，槽位永不平白空转。"""
        if not self.retry_queue:
            return False
        _reload_lib()  # 本轮的 partial/completed 记录参与重试排序
        try:
            fresh = {c.unique_code: c for c in await self._refresh()}
            retry_todo = [fresh.get(c.unique_code, c) for c in self.retry_queue
                          if not _challenge_completed(fresh.get(c.unique_code, c))]
        except ApiError:
            retry_todo = self.retry_queue
        self.retry_queue = []
        self.pending = sorted(
            retry_todo,
            key=lambda c: _priority(c, self.cfg.round_num, getattr(self, "_events", {})))
        if retry_todo:
            log.info("retry 队列 %d 题并入待解（空槽立即补位）", len(retry_todo))
        return bool(retry_todo)

    async def _platform_recheck(self) -> bool:
        """回查平台把仍未解出的题重新入队。返回 False = 全部解开（可退出）。
        钉子题（_dead）不参与常规回挖；只剩钉子题未解时仍回挖——其他题全解了，
        剩余时间打死题是零机会成本的兜底（时间不用白不用）。"""
        try:
            remaining = [c for c in await self._refresh() if not _challenge_completed(c)]
        except ApiError as e:
            # 拉取失败 ≠ 全部解开：不判空不退出，稍后重试
            log.warning("回查题目失败: %s，60s 后重试", e)
            await asyncio.sleep(60)
            return True
        if not remaining:
            return False
        alive = [c for c in remaining if c.unique_code not in self._dead]
        _reload_lib()
        self.pending = sorted(alive or remaining, key=lambda c: _priority(c, self.cfg.round_num, getattr(self, "_events", {})))
        return True

    async def run(self):
        # 首次拉题：失败不退出（换平台协议可能不适配），循环重试直至成功
        while True:
            try:
                challenges = await self._refresh()
                break
            except ApiError as e:
                log.warning("首次拉取题目失败: %s，30s 后重试", e)
                await asyncio.sleep(30)
        # 清理孤儿容器：available 但既未完成也无 worker 的（历史残留会占 3 槽位）
        for c in challenges:
            if c.container_status == "available" and not _challenge_completed(c) and c.unique_code not in self.active_workers:
                log.warning("关闭孤儿容器 %s（占槽位）", c.unique_code)
                try:
                    await self.api.close_challenge(c.unique_code)
                except ApiError as e:
                    log.warning("关闭失败: %s", e)
        try:
            challenges = await self._refresh()
        except ApiError:
            log.warning("二次拉取失败，用首次结果继续")
        todo = [c for c in challenges if not _challenge_completed(c)]
        already = sum(c.total_score for c in challenges if _challenge_completed(c))
        log.info("共 %d 题，已完成 %d（已有 %d 分），待解 %d", len(challenges),
                 len(challenges) - len(todo), already, len(todo))
        self.pending = sorted(todo, key=lambda c: _priority(c, self.cfg.round_num, getattr(self, "_events", {})))
        wd = asyncio.create_task(self._watchdog())

        tasks: set[asyncio.Task] = set()
        while True:
            if self._task_finished:
                # 平台任务已结束（start 报 already finished）：在跑任务收尾后退出，
                # 不再空转轮转（run 8629 复盘：16:37 后 10+ 分钟无效 409 轮转）。
                log.info("平台任务已结束，停止调度")
                break
            # 掉速检测：60s 节流回查（主循环 15s 一轮，4 轮查一次）
            if time.monotonic() - self._last_stagnate_check >= 60:
                self._last_stagnate_check = time.monotonic()
                await self._stagnate_check()
            if self._in_endgame() and not self._endgame_logged:
                self._endgame_logged = True
                _reload_lib()  # 尾段判定需要最新的 completed 复现状态
                log.info("进入收尾段（剩余 <%dmin）：只放行快赢题（剩一面/完整解法复现）",
                         self.cfg.endgame_min)
            time_left = self.deadline - time.monotonic()
            # 队列耗尽时：先吃 retry（本轮超时未解出、有断点续跑），
            # 再回查平台把仍未被解出的题重新入队。永不停止模式下只有
            # 「平台已无未解题」才退出；有界模式额外受全局 deadline 约束。
            if not self.pending and not tasks:
                if await self._pull_retry_into_pending():
                    continue
                # retry 也空：回查平台。还有未解出的（含 start/容器失败的终局题）就再来一轮。
                if self.cfg.never_stop or time_left > 120:
                    if not await self._platform_recheck():
                        break  # 全部解开
                    continue
                break  # 有界模式时间到

            # 收尾段 retry 快赢优先：endgame 放行门拦下的题占住 pending 时，
            # retry 队列里的剩一面断点续跑题永无出头（见 _promote_retry_in_endgame）
            self._promote_retry_in_endgame()

            # 补充新任务（首轮尝试限长超时；retry 轮预算分级放长）
            # gate 固定 3 并发（平台上限写死）：槽位一空立即补位，不允许空闲。
            # 主循环每 15s 一个 tick，空槽检查天然是这个粒度（无需额外轮询器）。
            skipped = 0
            while (len(tasks) < self.effective_max
                   and (self.cfg.never_stop or time_left > 120)):
                if not self.pending:
                    # 槽位空转修复（13174 实测：b 系列长预算攻坚期间 pending 空、
                    # 其他任务在跑时 retry 队列永不被拉起，空槽空转 10-30 分钟——
                    # 历史多轮「尾段空窗」同源）。pending 空但有空槽就把 retry 拉进来。
                    if not await self._pull_retry_into_pending():
                        break
                ch = self.pending.pop(0)
                wait_until = self._start_backoff.get(ch.unique_code, 0)
                if time.monotonic() < wait_until:
                    self.pending.append(ch)  # 409/失败冷却中，轮转到队尾
                    skipped += 1
                    if skipped >= len(self.pending):
                        break  # 所有待选题都在冷却，等下一轮 15s 循环
                    continue
                # endgame 收尾纪律（12464 复盘：收卷前 25min 还在第三轮攻 f2-05）：
                # 名义窗口只剩 ENDGAME_MIN 时只放行快赢题（只剩一面/有完整解法可复现），
                # 不再开新 hard/多 flag 大题——尾段时间全部给确定性得分
                if self._in_endgame() and not self._endgame_ok(ch):
                    self.pending.append(ch)
                    skipped += 1
                    if skipped >= len(self.pending):
                        break  # 尾段无快赢题：槽位空转至平台收卷（回查轮会持续刷新）
                    continue
                skipped = 0
                n = self._attempts.get(ch.unique_code, 0)
                self._attempts[ch.unique_code] = n + 1
                # attempt=n：0=首轮限长超时快速轮转，retry 轮（n>0）按断点分级放长
                t = asyncio.create_task(self._run_one(ch, attempt=n))
                tasks.add(t)
                t.add_done_callback(tasks.discard)
                time_left = self.deadline - time.monotonic()
            if not tasks:
                # 无在跑任务但还有待选题：只可能是全在 409/失败冷却中。
                # 睡到最近一个冷却到期再排（不 sleep 会空转烧 CPU/API）。
                if self.pending:
                    now = time.monotonic()
                    nxt = min((t for t in self._start_backoff.values() if t > now), default=now)
                    await asyncio.sleep(max(0.5, nxt - now))
                    continue
                await asyncio.sleep(1)  # 兜底：pending/retry 皆空，交由下一轮回查平台
                continue
            await asyncio.wait(tasks, timeout=15, return_when=asyncio.FIRST_COMPLETED)

        # 等待在跑任务收尾（受全局 deadline 约束的 worker 会自行退出）
        if tasks:
            log.info("全局时间到，等待 %d 个任务收尾", len(tasks))
            await asyncio.wait(tasks, timeout=180)
        for t in tasks:
            t.cancel()

        # 总结
        self._watchdog_stop = True
        wd.cancel()
        solved = [k for k, v in self.done.items() if v.get("completed")]
        total_score = sum(v.get("score", 0) for v in self.done.values())
        log.info("=" * 50)
        log.info("本轮解出 %d 题，新增 %d 分", len(solved), total_score)
        log.info("LLM 用量: %s", self.llm.stats())
        failed = {k: v.get("reason", "") for k, v in self.done.items() if not v.get("completed")}
        if failed:
            log.info("未解出: %s", failed)
        return self.done
