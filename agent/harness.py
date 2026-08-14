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
import json
import logging
import os

log = logging.getLogger("harness")


class HarnessResult:
    def __init__(self):
        self.output_text = ""   # 最终文本输出
        self.collected = ""     # 事件流全部文本（含 bash 输出，复盘落盘用）
        self.events = 0

    def digest(self) -> str:
        return self.collected[-6000:]


def _claude_env(cfg) -> dict:
    from .llm import anthropic_gateway_url
    env = dict(os.environ)
    env.pop("ANTHROPIC_API_KEY", None)  # 避免与 AUTH_TOKEN 冲突提示
    # Anthropic 端点从域名根派生（LLM_BASE_URL 自带 /v1，直接拼 /anthropic → 404）
    env["ANTHROPIC_BASE_URL"] = anthropic_gateway_url(cfg.llm_base_url)
    env["ANTHROPIC_AUTH_TOKEN"] = cfg.llm_api_key
    env["ANTHROPIC_MODEL"] = cfg.llm_model
    env["ANTHROPIC_DEFAULT_OPUS_MODEL"] = cfg.llm_model
    env["ANTHROPIC_DEFAULT_SONNET_MODEL"] = cfg.llm_model
    env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = cfg.llm_model
    env["SHELL"] = "/bin/bash"
    return env


def _claude_cmd(cfg) -> list[str]:
    # 注意：root 用户禁用 --dangerously-skip-permissions；
    # 容器内用预置的 /root/.claude/settings.json 权限白名单放行 Bash/Read/Write 等。
    # --verbose 必须：CC 2.1.232 起 --output-format=stream-json 要求 --verbose（容器实测）。
    return ["claude", "-p", "-", "--output-format", "stream-json",
            "--verbose", "--model", cfg.llm_model]


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


async def run_harness(cfg, prompt: str, cwd: str, timeout_s: int,
                      on_text=None) -> HarnessResult:
    """spawn 外部 agent CLI 跑一次攻坚。backend 支持：
    - "claude"：内置后端（ClawGod 版 claude code）
    - 其他值：当作可执行脚本路径（测试/自定义后端用），参数只有 cwd。"""
    if cfg.harness_backend == "claude":
        env, cmd = _claude_env(cfg), _claude_cmd(cfg)
    else:
        env, cmd = dict(os.environ), [cfg.harness_backend]
    res = HarnessResult()
    log.info("[harness] 启动 %s（timeout %ds, cwd=%s）", cmd[0], timeout_s, cwd)
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
        cwd=cwd, env=env)
    try:
        assert proc.stdin
        proc.stdin.write(prompt.encode())
        await proc.stdin.drain()
        proc.stdin.close()
        try:
            out = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            res.collected += "\n[HARNESS TIMEOUT]\n"
            log.warning("[harness] %s 超时被杀（%ds）", cmd[0], timeout_s)
            return res
        text = (out[0] or b"").decode(errors="replace")
        for line in text.splitlines():
            _parse_jsonl(line, res, on_text)
    finally:
        if proc.returncode is None:
            proc.kill()
    log.info("[harness] 结束 rc=%s events=%d", proc.returncode, res.events)
    return res
