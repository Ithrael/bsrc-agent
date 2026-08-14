"""Worker 工具层（meta-tooling）：持久 shell 会话 + 文件读写 + 答题协议工具。

借鉴 Cairn/Terminal-MCP 思路：不给 agent 一堆原子 MCP 工具，而是给一个带会话管理的
持久终端 + 文件读写，让模型自己写脚本组合能力，只有最终结果进入上下文。
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid

from .flagger import extract_flags

log = logging.getLogger("tools")

_END_MARK = "__BSRC_DONE_"
_MAX_OUT = 24_000  # 单次工具返回最大字符，防爆上下文


class ShellSession:
    """一个持久 bash 进程：写入命令 + 结束标记，读取直到标记出现。"""

    def __init__(self, name: str, cwd: str):
        self.name = name
        self.cwd = cwd
        self.proc: asyncio.subprocess.Process | None = None
        self.busy_until = 0.0

    async def ensure(self):
        if self.proc and self.proc.returncode is None:
            return
        env = dict(os.environ)
        env["PS1"] = ""
        env["TERM"] = "dumb"
        # 目标都在靶场内网，代理环境变量只会坏事；托管沙箱本无代理，本地模式需剔除
        for k in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env.pop(k, None)
        # 每题独立 TMPDIR：多 worker 并发时 /tmp 共享会串题（别题 flag 残留会误导）
        tmpdir = os.path.join(self.cwd, ".tmp")
        os.makedirs(tmpdir, exist_ok=True)
        env["TMPDIR"] = tmpdir
        self.proc = await asyncio.create_subprocess_exec(
            "bash", "--norc", "--noprofile",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=self.cwd,
            env=env,
            limit=4 * 1024 * 1024,
        )
        # 初始化：关闭 echo 的提示符干扰。cwd 已由 subprocess 参数设定，
        # 这里用绝对路径 cd 兜底（旧版用相对路径会在非项目根目录启动时报错噪音）
        await self._write("export PS1=; stty -echo 2>/dev/null; cd " + os.path.abspath(self.cwd))

    async def _write(self, cmd: str):
        assert self.proc and self.proc.stdin
        mark = f"{_END_MARK}{uuid.uuid4().hex[:8]}"
        self._mark = mark
        payload = f"{cmd}\necho {mark}$?\n"
        self.proc.stdin.write(payload.encode())
        await self.proc.stdin.drain()

    async def run(self, cmd: str, timeout: int = 60) -> str:
        await self.ensure()
        assert self.proc and self.proc.stdout and self.proc.stdin
        mark = f"{_END_MARK}{uuid.uuid4().hex[:8]}"
        payload = f"{cmd}\necho {mark}$?\n"
        self.proc.stdin.write(payload.encode())
        await self.proc.stdin.drain()

        buf: list[bytes] = []
        size = 0
        deadline = time.monotonic() + timeout
        timed_out = False
        while True:
            remain = deadline - time.monotonic()
            if remain <= 0:
                timed_out = True
                break
            try:
                line = await asyncio.wait_for(self.proc.stdout.readline(), timeout=min(remain, 5.0))
            except asyncio.TimeoutError:
                continue
            if not line:  # EOF：bash 死了
                break
            stripped = line.decode(errors="replace").rstrip("\n")
            if stripped.startswith(_END_MARK):
                if stripped.startswith(mark):
                    break
                continue  # 过期/并发命令的结束标记：丢弃，不进输出
            buf.append(line)
            size += len(line)
            if size > _MAX_OUT * 2:
                break
        text = b"".join(buf).decode(errors="replace")
        # 去掉命令回显行（第一行通常是输入命令本身）
        lines = text.splitlines()
        if lines and lines[0].strip() == cmd.strip()[:200]:
            lines = lines[1:]
        text = "\n".join(lines)
        if len(text) > _MAX_OUT:
            # 截断前先提取全文 flag 候选（超长输出中间截断会丢 flag，提前保住；worker 侧会自动提交）
            flags = extract_flags(text)
            half = _MAX_OUT // 2
            text = text[:half] + f"\n... [截断 {len(text) - _MAX_OUT} 字符] ...\n" + text[-half:]
            if flags:
                text = "【输出含 flag 候选】\n" + "\n".join(flags) + "\n\n" + text
        if timed_out:
            # 发送 Ctrl-C 尝试恢复会话同步
            try:
                self.proc.stdin.write(b"\x03\n")
                await self.proc.stdin.drain()
            except Exception:
                pass
            text += f"\n[TIMEOUT {timeout}s：命令未结束，已发送 Ctrl-C。后台任务请用 nohup ... & 或重定向到文件后轮询]"
        return text or "(无输出)"

    async def destroy(self):
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.kill()
            except ProcessLookupError:
                pass


class ToolBox:
    """每题一个 ToolBox：管理该题的 shell 会话、工作区与答题动作。"""

    def __init__(self, workspace: str, submit_cb=None, hint_cb=None, finish_cb=None,
                 platform_api_cb=None):
        self.workspace = workspace
        os.makedirs(workspace, exist_ok=True)
        self.sessions: dict[str, ShellSession] = {}
        self._submit_cb = submit_cb
        self._hint_cb = hint_cb
        self._finish_cb = finish_cb
        self._platform_api_cb = platform_api_cb
        self.finished = False

    async def shell(self, command: str, session: str = "main", timeout: int = 60) -> str:
        timeout = max(5, min(int(timeout), 600))
        sess = self.sessions.get(session)
        if not sess:
            sess = ShellSession(session, self.workspace)
            self.sessions[session] = sess
        try:
            out = await sess.run(command, timeout)
        except Exception as e:
            # 会话损坏：重建一次
            log.warning("session %s 异常重建: %s", session, e)
            await sess.destroy()
            self.sessions.pop(session, None)
            sess = ShellSession(session, self.workspace)
            self.sessions[session] = sess
            out = await sess.run(command, timeout)
        return out

    def read_file(self, path: str, max_chars: int = 20000) -> str:
        p = self._safe(path)
        try:
            with open(p, errors="replace") as f:
                data = f.read(max_chars + 1)
            if len(data) > max_chars:
                data = data[:max_chars] + f"\n... [截断，文件更大]"
            return data
        except OSError as e:
            return f"[read_file 失败: {e}]"

    def write_file(self, path: str, content: str) -> str:
        p = self._safe(path)
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        if len(content) > 2_000_000:
            return "[write_file 失败: 内容超过 2MB 限制]"
        with open(p, "w") as f:
            f.write(content)
        return f"已写入 {p}（{len(content)} 字符）"

    def _safe(self, path: str) -> str:
        # 允许工作区内的相对/绝对路径；绝对路径放行（容器内本来就是隔离的）
        if os.path.isabs(path):
            return path
        return os.path.join(self.workspace, path)

    async def submit_flag(self, flag: str) -> str:
        if self._submit_cb:
            return await self._submit_cb(flag)
        return "[submit 未配置]"

    async def get_hint(self) -> str:
        if self._hint_cb:
            return await self._hint_cb()
        return "[hint 未配置]"

    async def finish(self, summary: str) -> str:
        # 回调可拒绝提前 finish（如 flag 未拿全）：返回非 None 字符串 = 拒绝并提示继续
        if self._finish_cb:
            reject = await self._finish_cb(summary)
            if reject:
                return reject
        self.finished = True
        return "已结束本题。"

    async def platform_api(self, method: str, path: str, params: str = "", body: str = "") -> str:
        if self._platform_api_cb:
            return await self._platform_api_cb(method, path, params, body)
        return "[platform_api 未配置]"

    async def destroy(self):
        for s in self.sessions.values():
            await s.destroy()
        self.sessions.clear()


def tool_schemas() -> list[dict]:
    """OpenAI function-calling 工具定义。"""
    return [
        {
            "type": "function",
            "function": {
                "name": "shell",
                "description": "在持久 bash 会话中执行命令。会话跨调用保持（cwd、变量、后台进程都在）。"
                "多个命名会话可并行（如一个 nc 监听、一个跑 exploit）。"
                "长任务用 nohup/重定向到文件后台跑，再用后续调用轮询。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "要执行的 bash 命令"},
                        "session": {"type": "string", "description": "会话名，默认 main；不同会话名=不同 shell 进程"},
                        "timeout": {"type": "integer", "description": "秒，默认 60，最大 600"},
                    },
                    "required": ["command"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "读取文件内容（工作区相对路径或绝对路径），大文件会截断。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "max_chars": {"type": "integer", "description": "默认 20000"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "write_file",
                "description": "写文件（exploit 脚本、笔记、词表等）。工作区相对路径或绝对路径。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "submit_flag",
                "description": "提交 flag 判定。返回是否正确及得分。错提交无惩罚，可多次尝试；"
                "已正确提交过的 flag 不要重复提交。本题可能有多面 flag。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "flag": {"type": "string", "description": "完整 flag 字符串，如 flag{...}"},
                    },
                    "required": ["flag"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "get_hint",
                "description": "获取本题官方提示。注意：查看后本题得分按比例扣减，谨慎使用。",
                "parameters": {"type": "object", "properties": {}},
            },
        },
        {
            "type": "function",
            "function": {
                "name": "finish",
                "description": "结束本题（全部 flag 已拿到 / 确认无法继续 / 性价比过低）。",
                "parameters": {
                    "type": "object",
                    "properties": {"summary": {"type": "string", "description": "结论摘要"}},
                    "required": ["summary"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "platform_api",
                "description": "直接调用平台 API（协议适配兜底）：按 api-doc.txt 文档构造请求。"
                "当内置 submit_flag/get_hint 工具失败（换平台协议不适配）时，用本工具按文档自行适配。"
                "鉴权头已自动带上，无需手动加。",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "method": {"type": "string", "description": "GET 或 POST"},
                        "path": {"type": "string", "description": "API 路径，如 /openapi/v1/challenges/submit"},
                        "params": {"type": "string", "description": "URL 查询参数 JSON 字符串（可空串）"},
                        "body": {"type": "string", "description": "请求体 JSON 字符串（可空串）"},
                    },
                    "required": ["method", "path"],
                },
            },
        },
    ]


async def dispatch_tool(box: ToolBox, name: str, args: dict) -> str:
    try:
        if name == "shell":
            if not args.get("command"):
                return "[参数错误] shell 需要 command 字段"
            return await box.shell(args["command"], args.get("session", "main"), args.get("timeout", 60))
        if name == "read_file":
            return box.read_file(args["path"], args.get("max_chars", 20000))
        if name == "write_file":
            return box.write_file(args["path"], args["content"])
        if name == "submit_flag":
            return await box.submit_flag(args["flag"])
        if name == "get_hint":
            return await box.get_hint()
        if name == "finish":
            return await box.finish(args.get("summary", ""))
        if name == "platform_api":
            return await box.platform_api(args.get("method", "GET"), args.get("path", ""),
                                          args.get("params", ""), args.get("body", ""))
        return f"[未知工具: {name}]"
    except Exception as e:
        log.exception("tool %s failed", name)
        return f"[工具 {name} 执行异常: {type(e).__name__}: {e}]"
