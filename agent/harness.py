"""Harness worker：spawn 外部 agent CLI（claude code + ClawGod patch）对单题攻坚。

背景：裸 LLM 循环在"复现失败重探索"和"多阶段大题"上能力密度不足
（b-02 内网链 587 步白跑、c-06 JDWP 现场写 exploit 烧光步数）。
接入外部 harness 作为攻坚大脑：成熟的计划-执行-反思循环 + 长上下文管理。

后端（2026-08-14）：
- claude：Anthropic 格式（api.deepseek.com/anthropic），镜像内由 ClawGod 安装
  （npm 拉 Claude Code → patch → ~/.local/bin/claude 替换 launcher）。
  本地直连实测通过；沙箱网关 /anthropic 路径待实测。SHELL 必须 /bin/bash（zsh 噪音）。
  容器 root 用户禁用 --dangerously-skip-permissions，走预置 /root/.claude/settings.json 白名单。
- codex 已移除（2026-08-14）：ClawGod 自带 CC，codex 冗余，维护成本大于收益。

输出解析：claude --output-format stream-json 是 NDJSON 事件流，
逐行解析 + on_text 同步回调（worker 用回调收集 flag 候选，结束后统一异步提交——
解析循环是同步的，回调里不能 await）。
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import time

log = logging.getLogger("harness")


class HarnessResult:
    def __init__(self):
        self.output_text = ""   # 最终文本输出
        self.collected = ""     # 事件流全部文本（含 bash 输出，复盘落盘用）
        self.events = 0
        self.total_tokens = 0   # assistant 步级 usage 累计（token 熔断用）
        self.session_id = ""    # claude 会话 id（--resume 断点续会话用）

    def digest(self) -> str:
        return self.collected[-6000:]


def _kill_proc(proc) -> None:
    """杀整个进程组（claude 会 fork 子进程跑 bash 工具，只杀主进程会留孤儿占用 stdout 管道）。
    macOS 内核竞态：killpg 与子进程 fork 的窗口可能漏杀孤儿，循环补刀 3 次直到组消失。"""
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    for _ in range(3):
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            return
        time.sleep(0.05)
        try:
            os.killpg(pgid, 0)  # 探测：组还在（含刚 fork 的漏网孤儿）就再杀一轮
        except (ProcessLookupError, PermissionError, OSError):
            return


async def _wait_proc(proc, timeout: float = 5.0) -> None:
    """等进程退出但不依赖 stdout 管道 EOF：killpg 竞态漏杀的孤儿持有管道时
    proc.wait() 会阻塞到孤儿退出（实测 10s+），这里轮询 returncode（child watcher
    在进程退出时即设置，不等管道），最多 timeout 秒。"""
    for _ in range(int(timeout / 0.05)):
        if proc.returncode is not None:
            return
        await asyncio.sleep(0.05)


def _claude_env(cfg, model_override: str = "") -> dict:
    from .llm import anthropic_gateway_url
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)  # 避免与 AUTH_TOKEN 冲突提示
    # Anthropic 端点从域名根派生（LLM_BASE_URL 自带 /v1，直接拼 /anthropic → 404）
    env["ANTHROPIC_BASE_URL"] = anthropic_gateway_url(cfg.llm_base_url)
    env["ANTHROPIC_AUTH_TOKEN"] = cfg.llm_api_key
    # 缓存保险（ClawGod 补丁的等价 env）：x-anthropic-billing-header 会让第三方
    # 网关（DeepSeek 等）的 prompt-cache 命中率归零（实测成本差 5-8 倍）。该变量
    # 是 claude code 原生读取的——显式设置后，即使 ClawGod 某次构建 patch 静默
    # 失效（版本漂移致正则失配），97% 缓存命中也保得住。
    env["CLAUDE_CODE_ATTRIBUTION_HEADER"] = "0"
    model = model_override or cfg.llm_model
    env["ANTHROPIC_MODEL"] = model
    env["ANTHROPIC_DEFAULT_OPUS_MODEL"] = model
    env["ANTHROPIC_DEFAULT_SONNET_MODEL"] = model
    # haiku 槽（含内部杂务调用：标题生成/上下文压缩）固定走便宜主力模型（默认 flash）：
    # - ANTHROPIC_SMALL_FAST_MODEL 不设时，CC 内部调用以 Anthropic haiku 模型名打网关，
    #   DeepSeek 网关把未知名字兜底映射到 deepseek-chat（run 12464：1617 次内部调用
    #   8241 万 token 走了 deepseek-chat）；显式指定后归位 flash
    # - 即使会话主模型是 pro（攻坚），内部杂务也不该烧 pro
    env["ANTHROPIC_SMALL_FAST_MODEL"] = cfg.llm_model
    env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = cfg.llm_model
    env["SHELL"] = "/bin/bash"
    return env


def _claude_cmd(cfg, effort: str = "", model_override: str = "") -> list[str]:
    # 注意：root 用户禁用 --dangerously-skip-permissions；
    # 容器内用预置的 /root/.claude/settings.json 权限白名单放行 Bash/Read/Write 等。
    # --verbose 必须：CC 2.1.232 起 --output-format=stream-json 要求 --verbose（容器实测）。
    # --model 必须用覆盖值：命令行参数优先于 ANTHROPIC_MODEL env（run 10282 复盘：
    # 多模型分工 env 被 --model cfg.llm_model 盖掉，hard 题全程 flash、pro 从未上场）。
    cmd = ["claude", "-p", "-", "--output-format", "stream-json",
           "--verbose", "--model", model_override or cfg.llm_model]
    if effort:
        cmd += ["--effort", effort]
    return cmd


def _parse_jsonl(line: str, res: HarnessResult, on_text=None):
    """解析一行 NDJSON 事件：提取最终文本 + 拼接事件流。
    （同时兼容 codex --json 的 item.completed 格式——解析器保留历史兼容，防切换后端时改动。）"""
    line = line.strip()
    if not line:
        return
    try:
        ev = json.loads(line)
    except json.JSONDecodeError:
        return  # 非 JSON 行（zsh 噪音等）直接丢
    res.events += 1
    # 会话 id（init/system 与 result 事件都带）：断点续会话（--resume）的关键——
    # 超时被杀/提前退出后 resume 同一会话，上下文零丢失（文件重建降级为兜底）
    sid = ev.get("session_id")
    if sid:
        res.session_id = sid
    # token 熔断统计：只累计 assistant 事件的步级 usage（result 事件是总量，重复计入会翻倍）。
    # 按成本加权：cache_read 是缓存命中重读，价格约 input 的 1/10——全额计入会虚高 5 倍
    # 误杀正常题（run 9228 复盘：a-07 正常题 1.9 分钟被 300 万熔断误杀，cache_read 占 97%）。
    if ev.get("type") == "assistant":
        u = (ev.get("message") or {}).get("usage") or ev.get("usage") or {}
        # reasoning/thinking tokens 计入 output 类（effort max 下思考暴涨，防熔断统计失真）
        reasoning = int(u.get("reasoning", 0) or 0) or int(u.get("reasoning_tokens", 0) or 0)
        res.total_tokens += (int(u.get("input_tokens", 0) or 0)
                             + int(u.get("cache_creation_input_tokens", 0) or 0)
                             + int(u.get("output_tokens", 0) or 0)
                             + reasoning
                             + int(u.get("cache_read_input_tokens", 0) or 0) // 10)
    t = ev.get("type")
    item = ev.get("item") or {}
    if t == "item.completed" and item.get("text"):
        res.output_text = item["text"]            # codex 兼容
    if t == "result" and isinstance(ev.get("result"), str):
        res.output_text = ev["result"]            # claude 最终文本
    text = json.dumps(ev, ensure_ascii=False)
    res.collected += text[:2000] + "\n"           # 裁剪防爆内存
    if on_text:
        try:
            on_text(text)                          # 同步回调（只收集，不做 IO）
        except Exception:
            log.exception("harness on_text 回调异常")


async def _run_proc(cmd: list[str], env: dict, prompt: str, cwd: str, timeout_s: int,
                    on_text=None, token_budget: int = 0,
                    stop_event: asyncio.Event | None = None) -> HarnessResult:
    """spawn 一次 claude 进程并读完输出流（run_harness 的执行体）。"""
    res = HarnessResult()
    # 完整命令行入日志（12464 复盘：只打 cmd[0] 时无法事后判断 effort 是否被传上——
    # 全轮 reasoning=0 却查不出哪环丢了 --effort）
    log.info("[harness] 启动: %s（timeout %ds, cwd=%s）", " ".join(cmd), timeout_s, cwd)
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        cwd=cwd, env=env, start_new_session=True)
    try:
        assert proc.stdin and proc.stdout
        try:
            proc.stdin.write(prompt.encode())
            await proc.stdin.drain()
            proc.stdin.close()
        except (BrokenPipeError, ConnectionResetError, OSError):
            # claude 秒退（启动失败/网关抖动/资源紧张）：管道写不进去。
            # 不冒泡成 worker 崩溃（run 10048 bctf-38/03 断点重跑 ConnectionResetError），
            # 返回空结果交由调度轮转，已拿的 flag 不受影响。
            log.warning("[harness] %s 进程提前退出，prompt 写入失败（rc=%s）", cmd[0], proc.returncode)
            await _wait_proc(proc)
            return res
        killed = False

        async def _read_loop():
            nonlocal killed
            # 不用 StreamReader.readline：单行超 64KB（claude 巨长文本事件）会抛
            # ValueError: Separator is found, but chunk is longer than limit
            # （run 10048 bctf-20/bctf-01 崩溃根因）。手动行缓冲无行长限制。
            buf = b""
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    _parse_jsonl(line.decode(errors="replace"), res, on_text)
                    if token_budget and res.total_tokens > token_budget:
                        _kill_proc(proc)
                        killed = True
                        res.collected += "\n[HARNESS TOKEN BUDGET EXCEEDED]\n"
                        log.warning("[harness] %s token 熔断（%d > %d）", cmd[0], res.total_tokens, token_budget)
                        return
            if buf:  # EOF 残留的未换行尾行
                _parse_jsonl(buf.decode(errors="replace"), res, on_text)

        stopper = None
        if stop_event is not None:
            async def _stop_on_complete():
                await stop_event.wait()
                _kill_proc(proc)  # 杀进程组 → stdout EOF → _read_loop 自然退出
                res.collected += "\n[HARNESS STOPPED EARLY]\n"
                log.info("[harness] %s 完成事件触发提前终止（flag 已全部入账）", cmd[0])
            stopper = asyncio.create_task(_stop_on_complete())

        try:
            await asyncio.wait_for(_read_loop(), timeout=timeout_s)
        except asyncio.TimeoutError:
            _kill_proc(proc)
            killed = True
            res.collected += "\n[HARNESS TIMEOUT]\n"
            log.warning("[harness] %s 超时被杀（%ds）", cmd[0], timeout_s)
        finally:
            if stopper is not None:
                stopper.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await stopper
        if killed:
            await _wait_proc(proc)
        else:
            await proc.wait()
    finally:
        if proc.returncode is None:
            _kill_proc(proc)
    log.info("[harness] 结束 rc=%s events=%d tokens=%d", proc.returncode, res.events, res.total_tokens)
    return res


async def run_harness(cfg, prompt: str, cwd: str, timeout_s: int,
                      on_text=None, token_budget: int = 0, model: str = "",
                      effort: str = "", stop_event: asyncio.Event | None = None,
                      resume_session_id: str = "") -> HarnessResult:
    """spawn 外部 agent CLI 跑一次攻坚。backend 支持：
    - "claude"：内置后端（ClawGod 版 claude code）
    - 其他值：当作可执行脚本路径（测试/自定义后端用），参数只有 cwd。
    流式逐行读 stdout（原 communicate 一次性读完）：支持 token 熔断——
    assistant 步级 usage 累计超 token_budget 就 kill（run 9054 复盘 b-02 单会话 920 万 token）。
    model：非空时覆盖该会话的 ANTHROPIC_MODEL（多模型分工：hard 题用更强模型）。
    effort：非空时加 --effort（hard 题 max 思考预算，Claude Code 2.1.231+ 支持）。
    stop_event：外部完成信号（本题 flag 已全部入账）——置位即杀进程组提前收工。
    单主进程 + Task 子 agent 架构下槽位时间是稀缺资源，flag 拿齐后不等模型
    自己收尾/超时（旧多线架构靠 _cancel_loser_workers 做同等事，重构后一度丢失）。
    resume_session_id：非空时 claude --resume 续上一会话——断点重跑/retry 轮
    上下文零丢失（NOTES/RELAY 文件重建从主要手段降级为兜底）。resume 无输出
    （session 丢失/ClawGod 版不支持）时自动去掉 --resume 原样重跑，零风险。"""
    if cfg.harness_backend == "claude":
        env, base_cmd = _claude_env(cfg, model), _claude_cmd(cfg, effort, model)
    else:
        env, base_cmd = dict(os.environ), [cfg.harness_backend]
    cmd = base_cmd
    if resume_session_id:
        cmd = [base_cmd[0], "--resume", resume_session_id] + base_cmd[1:]
    res = await _run_proc(cmd, env, prompt, cwd, timeout_s,
                          on_text, token_budget, stop_event)
    if resume_session_id and res.events == 0:
        log.warning("[harness] --resume %s… 无输出（session 丢失或版本不支持），去掉 resume 重跑",
                    resume_session_id[:16])
        res = await _run_proc(base_cmd, env, prompt, cwd, timeout_s,
                              on_text, token_budget, stop_event)
    return res
