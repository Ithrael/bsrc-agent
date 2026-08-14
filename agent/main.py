"""入口：读环境 → 校验 → 跑调度 → 输出战报。

用法：
  python -m agent            # 正常跑（本地模式需先连靶场 VPN）
  python -m agent --dry-run  # 只校验配置与连通性，不解题
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import time


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
    run_dir = cfg.run_dir or os.path.join("runs", time.strftime("%Y%m%d-%H%M%S"))
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
                    cfg.llm_max_tokens, cfg.llm_temperature, cfg.llm_timeout_s)
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
        if cfg.claude_worker:
            # claude 直接解题模式下 claude 完全依赖 Anthropic 通道：启动即探测，
            # 不通立刻退出（否则整轮 0 分空转，任务 9030 教训）。
            code, detail = await _probe_anthropic_channel(cfg)
            if not (200 <= code < 300):
                log.error("claude Anthropic 通道自检失败: HTTP %s %s", code, detail)
                log.error("该通道不通时 claude_worker 整轮 0 分。请修复后重传，或设 CLAUDE_WORKER=0 走裸 LLM 循环。")
                return 4
            log.info("claude Anthropic 通道自检 OK: HTTP %s", code)
        if cfg.dry_run or "--dry-run" in sys.argv:
            log.info("dry-run 完成，退出。")
            return 0

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
