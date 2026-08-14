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
from urllib.parse import urlparse, urlunparse

import httpx

log = logging.getLogger("llm")


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
    DeepSeek 等厂商的 Anthropic 兼容端点在域名根 /anthropic，故先剥离路径再拼，网关改写同样适用。
    """
    p = urlparse(base_url)
    root = urlunparse((p.scheme, p.netloc, "", "", "", ""))
    return rewrite_gateway_url(root).rstrip("/") + "/anthropic"


class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str,
                 max_tokens: int = 8192, temperature: float = 0.2, timeout_s: int = 300):
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

    async def close(self):
        await self._client.aclose()

    async def chat(self, messages: list[dict], tools: list[dict] | None = None,
                   max_tokens: int | None = None) -> dict:
        """返回 message dict：{role, content, tool_calls?}。失败重试后仍抛异常由上层兜底。
        max_tokens 覆盖全局默认（reason 决策等纯 JSON 输出场景收紧输出上限）。"""
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": self.temperature,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        body: dict = {}
        last_exc: Exception | None = None
        for attempt in range(6):
            try:
                r = await self._client.post("/chat/completions", json=payload)
                if r.status_code == 400:
                    # 请求非法（上下文超长/结构错误）：重试无意义，带响应体快速失败
                    raise RuntimeError(f"LLM 400: {r.text[:300]}")
                if r.status_code in (401, 403):
                    raise RuntimeError(f"LLM 鉴权失败 {r.status_code}: {r.text[:200]}")
                if r.status_code in (429, 500, 502, 503, 504):
                    wait = min(60, 2 ** attempt * 3)
                    log.warning("LLM %s, %.1fs 后重试 (%d/6)", r.status_code, wait, attempt + 1)
                    await asyncio.sleep(wait)
                    continue
                r.raise_for_status()
                body = r.json()
                break
            except (httpx.TransportError, httpx.TimeoutException, httpx.HTTPStatusError) as e:
                last_exc = e
                wait = min(60, 2 ** attempt * 3)
                log.warning("LLM 调用异常 %s, %.1fs 后重试 (%d/6)", e, wait, attempt + 1)
                await asyncio.sleep(wait)
        else:
            raise RuntimeError(f"LLM 调用连续失败: {last_exc}")

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

    def stats(self) -> str:
        return f"calls={self.calls} in={self.total_input_tokens:,} out={self.total_output_tokens:,}"
