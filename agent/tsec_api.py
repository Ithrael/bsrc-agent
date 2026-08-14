"""平台 Challenges API 客户端（Tsecbench）。

协议（见仓库 api-doc.txt）：
  GET  /openapi/v1/challenges                 题目列表 + 作答进度
  POST /openapi/v1/challenges/start           启动容器拿 container_addr
  GET  /openapi/v1/challenges/hint            提示（扣分）
  POST /openapi/v1/challenges/submit          提交 flag
  POST /openapi/v1/challenges/close           关闭容器
鉴权：请求头 BENCHMARK_TOKEN。同时最多启动 3 题；同一 flag 重复提交返回 409 duplicate。

【换平台适配清单】（如百度靶场：改本文件 + 下方错误码常量即可，上层 worker/scheduler 不动）：
  1. 重写 4 个端点（list/start/hint/submit/close）为新平台协议
  2. 重写 Challenge.from_dict / SubmitResult.from_dict 的字段映射
  3. 必须保留的方法语义（上层依赖）：
     - list_challenges() -> list[Challenge]
       （含 unique_code/difficulty/total_score/flag_count/correct_flag_count/
         is_completed/container_status/container_addr）
     - start_challenge(code) -> container_addr 列表
     - submit_flag(code, flag) -> SubmitResult
       （含 correct/awarded/correct_flag_count/total_flag_count）
     - get_hint(code) -> hint 文本；close_challenge(code) -> bool
  4. 平台机制红利需实测后调整：flagger 的激进提交（错提不罚假设）、
     HINT_POLICY 扣分假设、scheduler 的 409 自适应并发、METATIPS 里的平台经验
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field

import httpx

log = logging.getLogger("tsec_api")

# 平台错误码语义（换平台时改这里；worker/scheduler 按这些码做分支）
CODE_DUPLICATE = "duplicate"          # 已正确提交过的 flag 再次提交
CODE_INVALID_STATE = "invalid_state"  # 并发实例数达上限


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(f"[{status}] {code}: {message}")
        self.status = status
        self.code = code
        self.message = message


@dataclass
class Challenge:
    unique_code: str
    description: str | None
    difficulty: str
    level: int
    total_score: int
    flag_count: int
    correct_flag_count: int
    is_completed: bool
    container_status: str
    container_addr: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "Challenge":
        return cls(
            unique_code=d["unique_code"],
            description=d.get("description"),
            difficulty=d.get("difficulty", "unknown"),
            level=d.get("level", 1),
            total_score=d.get("total_score", 0),
            flag_count=d.get("flag_count", 1),
            correct_flag_count=d.get("correct_flag_count", 0),
            is_completed=d.get("is_completed", False),
            container_status=d.get("container_status", "stopped"),
            container_addr=d.get("container_addr") or [],
        )

    @property
    def remaining_flags(self) -> int:
        return max(0, self.flag_count - self.correct_flag_count)


@dataclass
class SubmitResult:
    correct: bool
    awarded: int
    cumulative_score: int
    correct_flag_count: int
    total_flag_count: int
    matched_flag_index: int | None

    @classmethod
    def from_dict(cls, d: dict) -> "SubmitResult":
        return cls(
            correct=d.get("correct", False),
            awarded=d.get("awarded", 0),
            cumulative_score=d.get("cumulative_score", 0),
            correct_flag_count=d.get("correct_flag_count", 0),
            total_flag_count=d.get("total_flag_count", 0),
            matched_flag_index=d.get("matched_flag_index"),
        )


class TsecClient:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0):
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"BENCHMARK_TOKEN": token},
            timeout=timeout,
            trust_env=False,  # 沙箱内直连，不吃环境代理
        )

    async def close(self):
        await self._client.aclose()

    async def _req(self, method: str, path: str, **kw):
        last_exc: Exception | None = None
        for attempt in range(4):
            try:
                r = await self._client.request(method, path, **kw)
            except (httpx.TransportError, httpx.TimeoutException) as e:
                last_exc = e
                await asyncio.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code >= 500:
                last_exc = ApiError(r.status_code, "server", r.text[:200])
                await asyncio.sleep(1.5 * (attempt + 1))
                continue
            if r.status_code >= 400:
                try:
                    body = r.json()
                    code = body.get("code", "http_error")
                    msg = body.get("message", r.text[:200])
                except json.JSONDecodeError:
                    code, msg = "http_error", r.text[:200]
                raise ApiError(r.status_code, code, msg)
            return r.json()
        raise last_exc if isinstance(last_exc, ApiError) else ApiError(0, "network", str(last_exc))

    async def list_challenges(self) -> list[Challenge]:
        data = await self._req("GET", "/openapi/v1/challenges")
        return [Challenge.from_dict(d) for d in data]

    async def start_challenge(self, unique_code: str) -> list[str]:
        data = await self._req("POST", "/openapi/v1/challenges/start", params={"unique_code": unique_code})
        return data.get("container_addr") or []

    async def get_hint(self, unique_code: str) -> str | None:
        data = await self._req("GET", "/openapi/v1/challenges/hint", params={"unique_code": unique_code})
        return data.get("hint")

    async def submit_flag(self, unique_code: str, flag: str) -> SubmitResult:
        data = await self._req("POST", "/openapi/v1/challenges/submit", json={"unique_code": unique_code, "flag": flag})
        return SubmitResult.from_dict(data)

    async def close_challenge(self, unique_code: str) -> bool:
        data = await self._req("POST", "/openapi/v1/challenges/close", params={"unique_code": unique_code})
        return bool(data.get("closed"))

    async def raw_request(self, method: str, path: str,
                          params: dict | None = None, body: dict | None = None):
        """通用平台请求（LLM 协议适配兜底用）：按 api-doc.txt 直接发请求，返回原始 JSON。

        换平台协议不适配时内置方法会失败；LLM 用 platform_api 工具调本方法按文档自行适配。
        鉴权头 BENCHMARK_TOKEN 由 _req 统一携带。
        """
        kw: dict = {}
        if params:
            kw["params"] = params
        if body is not None:
            kw["json"] = body
        return await self._req(method.upper(), path, **kw)
