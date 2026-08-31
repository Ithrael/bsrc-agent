"""OpenAI 兼容 LLM 客户端。

托管模式网关改写规则（平台文档）：
  1. 域名加 .tsecbench.gw 后缀；2. https 改 http。
  例：https://api.deepseek.com/v1 -> http://api.deepseek.com.tsecbench.gw/v1
本地模式直连即可，设 GATEWAY_REWRITE=0 关闭。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from urllib.parse import urlparse, urlunparse

import httpx

log = logging.getLogger("llm")

# 1 次 + 最多再试 2 次；单次等待 ≤5s。旧值 6 次 × min(60, 2^n*3) ≈ 153s 退避，
# 再加 300s 超时，一次 429 就能把 120s Execute 打成 0 轮 bash。
_MAX_ATTEMPTS = 3
_RETRY_WAIT_CAP_S = 5.0
# 2 连败切备用，留给第 3 次走新通道（总共只有 3 次尝试）
_SWITCH_AFTER = 2


def rewrite_gateway_url(base_url: str) -> str:
    """按平台规则把公网 LLM API 地址改写为托管沙箱内可达的网关地址。

    网关后缀可配：GATEWAY_SUFFIX 环境变量（默认 .tsecbench.gw；换平台时按新平台规则改）。
    """
    if os.environ.get("GATEWAY_REWRITE", "1") == "0":
        return base_url
    suffix = os.environ.get("GATEWAY_SUFFIX", ".tsecbench.gw")
    p = urlparse(base_url)
    host = p.netloc
    if host.endswith(suffix):
        return base_url
    if "." not in host or host.startswith(("10.", "192.168.", "127.", "localhost")):
        return base_url  # 内网/本地地址不改写
    new = p._replace(scheme="http", netloc=host + suffix)
    return urlunparse(new)


def anthropic_gateway_url(base_url: str) -> str:
    """从 OpenAI 兼容 base 派生 claude 后端用的 Anthropic 端点。

    不能直接 base + "/anthropic"：base 自带路径（如 https://api.deepseek.com/v1），
    拼出 /v1/anthropic，claude SDK 再追加 /v1/messages → /v1/anthropic/v1/messages → 404（实测）。
    各厂商 Anthropic 兼容端点路径不同（都先剥离路径到域名根再拼）：
    - DeepSeek：域名根 /anthropic
    - 智谱 GLM：/api/anthropic（13018 实测：/anthropic 404 导致 claude 全挂降级裸 LLM）
    网关改写同样适用。
    """
    p = urlparse(base_url)
    root = urlunparse((p.scheme, p.netloc, "", "", "", ""))
    host = (p.hostname or "").lower()
    path = "/api/anthropic" if "bigmodel.cn" in host else "/anthropic"
    return rewrite_gateway_url(root).rstrip("/") + path


class LLMClient:
    """OpenAI 兼容客户端，支持双通道 fallback（方案4）：主网关连续 2 次网络/5xx
    失败自动切备用网关（LLM_BASE_URL_FALLBACK），备用连续 5 次成功切回主。
    claude 通道已有「降级裸 LLM」保险，这里补上裸循环自身的最后一块：主网关
    抖动期间解题/蒸馏/advisor 不停摆。400/401 不触发切换（请求本身的问题，
    换通道也一样失败）。"""

    def __init__(self, base_url: str, api_key: str, model: str,
                 max_tokens: int = 8192, temperature: float = 0.2, timeout_s: int = 300,
                 fallback_base_url: str = "", fallback_api_key: str = "",
                 fallback_model: str = ""):
        self.base_url = rewrite_gateway_url(base_url).rstrip("/")
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        self.calls = 0
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout_s,
            trust_env=False,  # 沙箱内无公网代理，直连网关
        )
        # 备用通道（空配置=禁用）：状态机 _active ∈ {"main","fallback"}
        self._fallback_base_url = rewrite_gateway_url(fallback_base_url).rstrip("/") \
            if fallback_base_url else ""
        self._fallback_model = fallback_model or model
        self._fallback_client: httpx.AsyncClient | None = None
        if self._fallback_base_url:
            self._fallback_client = httpx.AsyncClient(
                base_url=self._fallback_base_url,
                headers={"Authorization": f"Bearer {fallback_api_key or api_key}"},
                timeout=timeout_s,
                trust_env=False)
        self._active = "main"
        self._fail_streak = 0        # 当前通道连续失败（网络/5xx/429）
        self._fallback_ok_streak = 0 # 备用通道连续成功（够 5 次切回主）

    def _cur(self) -> tuple[httpx.AsyncClient, str]:
        """当前通道 (client, model)。fallback 模型可不同（如主 deepseek 备智谱）。"""
        if self._active == "fallback" and self._fallback_client is not None:
            return self._fallback_client, self._fallback_model
        return self._client, self.model

    def _switch(self, to: str):
        self._active = to
        self._fail_streak = 0
        self._fallback_ok_streak = 0
        url = self._fallback_base_url if to == "fallback" else self.base_url
        log.warning("LLM 通道切换 -> %s（%s）", to, url)

    async def close(self):
        await self._client.aclose()
        if self._fallback_client is not None:
            await self._fallback_client.aclose()

    def _retry_wait(self, attempt: int, deadline: float | None) -> float | None:
        """退避秒数；None = 预算耗尽，停止重试。"""
        wait = min(_RETRY_WAIT_CAP_S, 2 ** attempt * 3)
        if deadline is not None:
            remain = deadline - time.monotonic()
            if remain <= 0.05:
                return None
            wait = min(wait, remain)
        return wait

    async def chat(self, messages: list[dict], tools: list[dict] | None = None,
                   max_tokens: int | None = None, model: str = "",
                   timeout_s: float | None = None) -> dict:
        """返回 message dict：{role, content, tool_calls?}。失败重试后仍抛异常由上层兜底。
        max_tokens 覆盖全局默认（reason 决策等纯 JSON 输出场景收紧输出上限）。
        model 覆盖本次调用的模型（advisor brief 用强模型单次调用，不动全局默认）。
        timeout_s：本次调用（含重试）墙钟预算；None 用客户端默认超时。"""
        payload: dict = {
            "model": model or self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": self.temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        body: dict = {}
        last_exc: Exception | None = None
        deadline = (time.monotonic() + timeout_s) if timeout_s is not None else None
        got = False
        for attempt in range(_MAX_ATTEMPTS):
            remain = (deadline - time.monotonic()) if deadline is not None else None
            if remain is not None and remain <= 0:
                break
            client, chan_model = self._cur()
            post_kw: dict = {}
            if remain is not None:
                post_kw["timeout"] = remain
            try:
                r = await client.post("/chat/completions", json={
                    **payload, "model": model or chan_model}, **post_kw)
                if r.status_code == 400:
                    # 请求非法（上下文超长/结构错误）：重试无意义，带响应体快速失败
                    raise RuntimeError(f"LLM 400: {r.text[:300]}")
                if r.status_code in (401, 403):
                    raise RuntimeError(f"LLM 鉴权失败 {r.status_code}: {r.text[:200]}")
                if r.status_code in (429, 500, 502, 503, 504):
                    last_exc = RuntimeError(f"LLM {r.status_code}")
                    self._note_channel_failure()
                    wait = self._retry_wait(attempt, deadline)
                    log.warning("LLM %s, %.1fs 后重试 (%d/%d)", r.status_code,
                                wait or 0, attempt + 1, _MAX_ATTEMPTS)
                    if wait is None or attempt >= _MAX_ATTEMPTS - 1:
                        break
                    await asyncio.sleep(wait)
                    continue
                r.raise_for_status()
                body = r.json()
                got = True
                break
            except (httpx.TransportError, httpx.TimeoutException) as e:
                last_exc = e
                self._note_channel_failure()
                wait = self._retry_wait(attempt, deadline)
                log.warning("LLM 调用异常 %s, %.1fs 后重试 (%d/%d)", e,
                            wait or 0, attempt + 1, _MAX_ATTEMPTS)
                if wait is None or attempt >= _MAX_ATTEMPTS - 1:
                    break
                await asyncio.sleep(wait)
            except httpx.HTTPStatusError as e:
                last_exc = e
                wait = self._retry_wait(attempt, deadline)
                log.warning("LLM 调用异常 %s, %.1fs 后重试 (%d/%d)", e,
                            wait or 0, attempt + 1, _MAX_ATTEMPTS)
                if wait is None or attempt >= _MAX_ATTEMPTS - 1:
                    break
                await asyncio.sleep(wait)
        if not got:
            raise RuntimeError(f"LLM 调用连续失败: {last_exc}")

        self._note_channel_success()
        self.calls += 1
        usage = body.get("usage") or {}
        self.total_input_tokens += usage.get("prompt_tokens", 0)
        self.total_output_tokens += usage.get("completion_tokens", 0)
        choice = (body.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        return {
            "role": "assistant",
            "content": msg.get("content") or "",
            "tool_calls": msg.get("tool_calls"),
            # 单次调用 token 用量（worker 用于第一轮 token 熔断，消费后 pop 掉，不进上下文/transcript）
            "_usage": {
                "in": usage.get("prompt_tokens", 0),
                "out": usage.get("completion_tokens", 0),
            },
        }

    def _note_channel_failure(self):
        """网络/5xx 失败计数：连续 2 次且备用可用 → 切备用。"""
        self._fallback_ok_streak = 0
        self._fail_streak += 1
        if (self._fail_streak >= _SWITCH_AFTER and self._active == "main"
                and self._fallback_client is not None):
            self._switch("fallback")

    def _note_channel_success(self):
        """成功计数：备用通道连续 5 次成功 → 切回主（主通道通常更快/更便宜）。"""
        if self._active == "main":
            self._fail_streak = 0
            return
        self._fail_streak = 0
        self._fallback_ok_streak += 1
        if self._fallback_ok_streak >= 5:
            self._switch("main")

    def stats(self) -> str:
        return f"calls={self.calls} in={self.total_input_tokens:,} out={self.total_output_tokens:,}"
