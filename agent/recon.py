"""启动预侦察：worker 开跑前并行收集目标指纹，把报告直接交给 LLM。

目标：省掉 LLM 每题的 3-5 轮侦察往返（每轮 shell 15-30s + LLM 思考 10-20s）。
预算 ≤75s/题：nmap 常用端口 + 对 HTTP 端口做首页/敏感路径探测。
已知解法（solutions.json completed）的题不调用本模块，直接复现更快。
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid

log = logging.getLogger("recon")

_HTTP_PORTS = (80, 8080, 8000, 443, 8443, 3000, 5000, 9090, 8888, 8545, 11434)
# nuclei CVE 模板目录：镜像打包到 /opt，本地开发机可用 NUCLEI_TEMPLATES 覆盖（见 run-local.sh）
_NUCLEI_TEMPLATES = os.environ.get("NUCLEI_TEMPLATES", "/opt/nuclei-templates/http/cves")
_MAX_HOSTS = 4          # 多地址题只细查前几个
# 区块链（8545/8546 RPC、9650 Avalanche）与 AI 应用（11434 Ollama、19530 Milvus）端口
_TOP_PORTS = (21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445,
              512, 513, 514, 873, 993, 995, 1080, 1433, 1521, 2049, 2181, 2375,
              2379, 3000, 3306, 3389, 4000, 5000, 5432, 5601, 5672, 5900, 5984,
              6379, 6443, 7001, 7077, 8000, 8001, 8008, 8009, 8042, 8069, 8080,
              8081, 8088, 8090, 8161, 8180, 8200, 8500, 8545, 8546, 8888, 9000,
              9001, 9042, 9090, 9200, 9300, 9418, 9650, 9999, 10000, 11211,
              11434, 15672, 19530, 27017, 28017, 50000, 50070, 50090)


def _parse_hosts(addrs: list[str]) -> list[str]:
    hosts: list[str] = []
    for a in addrs or []:
        h = str(a).strip()
        if not h:
            continue
        if "://" in h:
            h = h.split("://", 1)[1]
        h = h.split("/", 1)[0]
        if ":" in h and h.rsplit(":", 1)[1].isdigit():
            h = h.rsplit(":", 1)[0]
        if h and h not in hosts:
            hosts.append(h)
    return hosts


async def _run_cmd(cmd: str, cwd: str, timeout: int) -> str:
    """独立 ShellSession 跑一条命令（recon 内并发安全：不共享 bash 进程）。"""
    from .tools import ShellSession

    sess = ShellSession(f"recon-{uuid.uuid4().hex[:6]}", cwd)
    try:
        return await asyncio.wait_for(sess.run(cmd, timeout=timeout), timeout=timeout + 15)
    except asyncio.TimeoutError:
        return "(超时)"
    except Exception as e:
        return f"(失败: {type(e).__name__})"
    finally:
        await sess.destroy()


async def _scan_ports(cwd: str, host: str) -> str:
    """nmap 扫描常用端口；nmap 缺失时退化到 python socket 扫 top 端口。"""
    which = await _run_cmd(
        f"command -v nmap >/dev/null 2>&1 && echo yes || echo no", cwd, 10)
    if which.strip() == "yes":
        out = await _run_cmd(
            f"nmap -Pn -sT -T4 --min-rate 3000 -p {','.join(map(str, _TOP_PORTS))} {host} 2>/dev/null | grep -E '^[0-9]+/tcp.*open'",
            cwd, 45,
        )
        if out.strip() and "(超时)" not in out and "(失败" not in out:
            return out.strip()
    # fallback：python socket 连扫（容器内保底）
    ports = ",".join(map(str, _TOP_PORTS))
    script = (
        f"python3 - <<'EOF'\n"
        f"import socket\n"
        f"ports=[{ports}]\n"
        f"open_ports=[]\n"
        f"for p in ports:\n"
        f"    s=socket.socket(); s.settimeout(0.5)\n"
        f"    if s.connect_ex(('{host}',p))==0: open_ports.append(p)\n"
        f"    s.close()\n"
        f"print('open:', open_ports)\n"
        f"EOF"
    )
    return (await _run_cmd(script, cwd, 60)).strip()


async def _http_probe(cwd: str, host: str, port: int) -> str:
    """HTTP 指纹：首页 + 常见敏感路径状态码。"""
    base = f"http://{host}:{port}"
    paths = ("/, /robots.txt, /.git/HEAD, /.env, /admin, /api, /login, /flag, "
             "/challenge/flag.txt, /v1/models, /v1/chat/completions, /docs, /openapi.json")
    cmd = (
        f"curl -s -m 8 -i {base}/ 2>/dev/null | head -25; echo '---STATUS---'; "
        f"for p in {paths}; do "
        f"code=$(curl -s -m 5 -o /dev/null -w '%{{http_code}}' {base}$p 2>/dev/null); "
        f"echo \"$p -> $code\"; done"
    )
    out = await _run_cmd(cmd, cwd, 40)
    if not out or "(超时)" in out or "(失败" in out:
        return ""
    # 全部连接失败（端口未开）的探测没有信息量，直接丢弃
    if "-> 000" in out and "HTTP/" not in out:
        return ""
    return f"[{port}] {out.strip()}"


async def _nuclei_scan(cwd: str, host: str, ports: list[int]) -> str:
    """nuclei CVE 模板扫描：只扫本地 http/cves 目录，命中即精确 CVE 编号（高价值）。

    未装 nuclei（本地调试）静默返回空；命中结果直接进预侦察报告，LLM 据此定位漏洞。
    """
    which = await _run_cmd(
        "command -v nuclei >/dev/null 2>&1 && echo yes || echo no", cwd, 10)
    if which.strip() != "yes":
        return ""
    urls = [f"http://{host}"]  # 默认 80
    for p in ports:
        if p not in (80, 443):
            urls.append(f"http://{host}:{p}")
    uflag = " ".join(f"-u {u}" for u in urls[:4])
    out = await _run_cmd(
        f"nuclei -duc {uflag} -t {_NUCLEI_TEMPLATES} "
        f"-tags rce,sqli,lfi,ssti,ssrf,deserialization,xxe -timeout 5 -rl 150 -c 20 "
        f"-silent -no-color -no-interactsh 2>/dev/null",
        cwd, 50,
    )
    if not out or "(超时)" in out or "(失败" in out:
        return ""
    return f"[nuclei] {out.strip()}"


async def recon_targets(addrs: list[str], workspace: str, budget_s: int = 75) -> str:
    """对目标地址做快速预侦察，返回供 LLM 阅读的报告文本（空串=无信息）。"""
    hosts = _parse_hosts(addrs)
    if not hosts:
        return ""
    hosts = hosts[:_MAX_HOSTS]
    os.makedirs(workspace, exist_ok=True)
    try:
        tasks = [_scan_ports(workspace, h) for h in hosts]
        # HTTP 探测：先查 addr 自带端口，再补常见端口（去重，每 host 最多 4 个）
        port_plan: dict[str, list[int]] = {}
        for a in addrs or []:
            s = str(a)
            if ":" in s and s.rsplit(":", 1)[1].isdigit():
                port_plan.setdefault(s.split(":", 1)[0], []).append(int(s.rsplit(":", 1)[1]))
        for h in hosts:
            ports = port_plan.get(h, [])
            for p in _HTTP_PORTS:
                if p not in ports:
                    ports.append(p)
            port_plan[h] = ports[:4]
        for h, ports in port_plan.items():
            tasks.extend(_http_probe(workspace, h, p) for p in ports)
            tasks.append(_nuclei_scan(workspace, h, ports))

        try:
            results = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), budget_s)
        except asyncio.TimeoutError:
            results = ["(预侦察超时)" for _ in tasks]

        lines: list[str] = []
        for h, r in zip(hosts, results[:len(hosts)]):
            if isinstance(r, Exception):
                r = f"(失败: {type(r).__name__})"
            if str(r).strip() and "(失败" not in str(r) and "(超时)" not in str(r):
                lines.append(f"### {h} 端口扫描\n{str(r).strip()}")
        for r in results[len(hosts):]:
            if isinstance(r, Exception):
                continue
            if str(r).strip() and "(失败" not in str(r):
                lines.append(str(r).strip())
        return "\n\n".join(lines)[:6000]
    except Exception as e:
        log.warning("recon 失败: %s", e)
        return ""
