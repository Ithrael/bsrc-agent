"""入口：读环境 → 校验 → 跑调度 → 输出战报。

用法：
  python -m agent            # 正常跑（本地模式需先连靶场 VPN）
  python -m agent --dry-run  # 只校验配置与连通性，不解题
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sys
import time

log = logging.getLogger("main")


async def _probe_anthropic_channel(cfg) -> tuple[int, str]:
    """启动自检：探测 claude 后端依赖的 Anthropic 通道（托管网关 /anthropic 路径此前未实测）。

    与 harness._claude_env 用同一 URL 推导与鉴权，POST 一条最小消息返回 (HTTP 状态码, 摘要)。
    失败时 claude_worker 整轮 0 分（2026-08-14 任务 9030 教训：全题 rc=1），故启动即探测。
    """
    import httpx
    from .llm import anthropic_gateway_url
    url = anthropic_gateway_url(cfg.llm_base_url).rstrip("/") + "/v1/messages"
    payload = {"model": cfg.llm_model, "max_tokens": 1,
               "messages": [{"role": "user", "content": "ping"}]}
    try:
        async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
            r = await client.post(url, json=payload, headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {cfg.llm_api_key}"})
            return r.status_code, (r.text or "")[:120].replace("\n", " ")
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"


async def _smoke_claude(cfg) -> bool:
    """claude 全链路冒烟：spawn 真实 claude -p（一次最小对话，真走一次网关），
    校验 rc==0 且有 stream-json 输出。

    比二进制存在性检查更严：ClawGod patch 断裂（版本漂移）/ bun 丢失 /
    launcher 指向的 cli.cjs 缺失时，`claude --version` 可能仍正常，但 -p 秒退
    127/1——只有实跑能暴露。失败由调用方降级裸 LLM 模式，绝不带着坏 claude 空转。"""
    from .harness import _claude_env
    probe_model = cfg.llm_model_hard or cfg.llm_model
    try:
        proc = await asyncio.create_subprocess_exec(
            "claude", "-p", "回复 OK", "--model", probe_model,
            "--output-format", "stream-json", "--verbose",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            env=_claude_env(cfg, probe_model))
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    except Exception as e:
        log.warning("claude 冒烟异常: %s", e)
        return False
    text = (out or b"").decode(errors="replace")
    if proc.returncode == 0 and '"type"' in text:
        log.info("claude 冒烟 OK（rc=0, %d 字节输出）", len(text))
        return True
    log.warning("claude 冒烟失败 rc=%s，输出前 200 字符: %s",
                proc.returncode, text[:200].replace("\n", " "))
    return False


def _setup_logging(run_dir: str):
    os.makedirs(run_dir, exist_ok=True)
    fmt = "%(asctime)s %(levelname)-5s %(name)s: %(message)s"
    handlers = [logging.StreamHandler(sys.stdout),
                logging.FileHandler(os.path.join(run_dir, "run.log"))] if run_dir else [logging.StreamHandler(sys.stdout)]
    logging.basicConfig(level=logging.INFO, format=fmt, handlers=handlers)
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


async def _amain() -> int:
    from .config import Config
    from .llm import LLMClient
    from .scheduler import Scheduler
    from .tsec_api import TsecClient

    cfg = Config()
    # run_dir 绝对化（2026-08-27 修复）：默认相对路径 runs/... 会让 worker 工作区
    # 也是相对路径，submit_flag.sh 里嵌入的 .flag_lock/.flag_wrong/STATE.md 路径
    # 在 claude bash 换目录执行时拼成不存在的深层路径（13174 实测 flock Bad
    # file descriptor + STATE.md No such file，显式通道完成判定整链失效）
    run_dir = os.path.abspath(cfg.run_dir or os.path.join("runs", time.strftime("%Y%m%d-%H%M%S")))
    _setup_logging(run_dir)
    log = logging.getLogger("main")

    errs = cfg.validate()
    if errs:
        for e in errs:
            log.error("配置错误: %s", e)
        return 2
    log.info("run_dir=%s model=%s base=%s", run_dir, cfg.llm_model, cfg.benchmark_base_url)

    api = TsecClient(cfg.benchmark_base_url, cfg.benchmark_token)
    llm = LLMClient(cfg.llm_base_url, cfg.llm_api_key, cfg.llm_model,
                    cfg.llm_max_tokens, cfg.llm_temperature, cfg.llm_timeout_s,
                    fallback_base_url=cfg.llm_base_url_fallback,
                    fallback_api_key=cfg.llm_api_key_fallback,
                    fallback_model=cfg.llm_model_fallback)
    if cfg.llm_base_url_fallback:
        log.info("LLM 备用通道: %s（主通道连续 3 次网络/5xx 失败自动切换）",
                 cfg.llm_base_url_fallback)
    log.info("LLM endpoint: %s", llm.base_url)
    try:
        # 连通性自检
        try:
            lst = await api.list_challenges()
            log.info("平台连通 OK：%d 题", len(lst))
        except Exception as e:
            # 不退出：换平台协议不适配时，由 scheduler 循环重试 + LLM 读 api-doc.txt 用 platform_api 适配兜底
            log.warning("平台连通自检失败（VPN/凭证/协议问题）: %s。继续启动，运行时自适应。", e)
        try:
            probe = await llm.chat([{"role": "user", "content": "ping，回复 ok"}])
            log.info("LLM 连通 OK: %s", (probe.get("content") or "")[:40])
        except Exception as e:
            log.error("LLM 连通失败（托管模式是否已走 .tsecbench.gw 网关？）: %s", e)
            return 4
        if cfg.simple_mode:
            # 极简模式：跳过 claude worker（直接 LLM 直连全 flash），不依赖 ClawGod/Anthropic 通道
            cfg.claude_worker = False
            cfg.harness_enabled = False
        if cfg.claude_worker:
            # 多模型分工未配置时提示（run 10282 复盘：pro 全程只被调用 1 次——
            # hard 题全靠 flash 单模型，与榜首 2-4 模型分工差距的直接原因）
            if not cfg.llm_model_hard:
                log.warning("LLM_MODEL_HARD 未设置：hard 题/retry 轮将全程使用 %s 单模型。"
                            "建议配置（如 deepseek-v4-pro），否则攻坚能力受限。", cfg.llm_model)
            # claude 可用性三道闸（2026-08-24 加固）：任一失败降级裸 LLM 循环继续解题，
            # 不再退出空转（裸循环走 OpenAI 兼容端点，与 claude 依赖的 Anthropic 通道无关）。
            # 历史教训：ClawGod 安装失败/patch 断裂时镜像仍能构建（"失败不阻断"），
            # 带着 claude_worker=1 上场 = 整轮 6 小时 crash 循环 0 分（run 9030 同类）。
            if cfg.harness_backend == "claude":
                import shutil
                if not shutil.which("claude"):
                    log.error("claude 二进制不存在（ClawGod 安装失败？Dockerfile 构建期 WARNING 被吞）。"
                              "降级裸 LLM 循环（CLAUDE_WORKER=0 等效），继续解题不空转。")
                    cfg.claude_worker = False
                    cfg.harness_enabled = False
            if cfg.claude_worker:
                code, detail = await _probe_anthropic_channel(cfg)
                if not (200 <= code < 300):
                    log.error("claude Anthropic 通道自检失败: HTTP %s %s", code, detail)
                    log.error("claude 模式不可用。降级裸 LLM 循环继续解题（OpenAI 兼容端点已验证连通）。")
                    cfg.claude_worker = False
                    cfg.harness_enabled = False
                else:
                    log.info("claude Anthropic 通道自检 OK: HTTP %s", code)
            if (cfg.claude_worker and cfg.harness_backend == "claude"
                    and not await _smoke_claude(cfg)):
                log.error("claude 冒烟失败（launcher/bun/patched CLI 链路断裂）。"
                          "降级裸 LLM 循环继续解题。")
                cfg.claude_worker = False
                cfg.harness_enabled = False
            if cfg.claude_worker and cfg.claude_hard_effort:
                # effort 探测（run 12464 复盘：探测超时被当失败降级→全轮 pro reasoning=0，
                # 只买到知识没买到思考预算）。三分支判定：
                # - rc==0 → OK；- stderr 明确报 unknown/unrecognized/effort → 真不支持，降级；
                # - 超时/其他错误 → 网关慢，保留 effort（claude 对不支持的能力参数会秒退报错，
                #   不会挂着超时——超时恰恰说明参数被接受了、只是推理慢）。
                from .harness import _claude_env
                probe_model = cfg.llm_model_hard or cfg.llm_model
                stderr_tail = b""
                timed_out = False
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "claude", "-p", "回复 OK", "--effort", cfg.claude_hard_effort,
                        "--model", probe_model,
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
                        env=_claude_env(cfg, probe_model))
                    try:
                        _, stderr_tail = await asyncio.wait_for(proc.communicate(), timeout=90)
                        rc = proc.returncode
                    except asyncio.TimeoutError:
                        timed_out = True
                        rc = -1
                        with contextlib.suppress(ProcessLookupError, OSError):
                            proc.kill()
                except Exception as e:
                    rc = -1
                    log.warning("effort 探测异常: %s", e)
                low = (stderr_tail or b"").lower()[:300]
                if rc == 0:
                    log.info("claude --effort %s 探测 OK（模型 %s）：全量会话（flash/pro）均带 effort",
                             cfg.claude_hard_effort, probe_model)
                elif timed_out:
                    log.warning("claude --effort %s 探测超时（90s，模型 %s）：按网关慢处理，"
                                "保留 effort 不降级（12464 教训：超时≠不支持）",
                                cfg.claude_hard_effort, probe_model)
                elif any(k in low for k in (b"effort", b"unknown", b"unrecognized", b"invalid")):
                    log.warning("claude --effort %s 探测失败 rc=%s（stderr: %s）：真不支持，降级为无 effort",
                                cfg.claude_hard_effort, rc, low[:120])
                    cfg.claude_hard_effort = ""
                else:
                    log.warning("claude --effort %s 探测失败 rc=%s（stderr: %s）：非参数错误，保留 effort",
                                cfg.claude_hard_effort, rc, low[:120] or "(空)")
        if cfg.dry_run or "--dry-run" in sys.argv:
            log.info("dry-run 完成，退出。")
            return 0

        if cfg.simple_mode:
            from .simple_mode import SimpleScheduler
            sched = SimpleScheduler(cfg, llm, api, run_dir)
        else:
            sched = Scheduler(cfg, llm, api, run_dir)
        await sched.run()
        return 0
    finally:
        await api.close()
        await llm.close()


def main():
    raise SystemExit(asyncio.run(_amain()))


if __name__ == "__main__":
    main()
