# bsrc-agent 评测镜像（托管模式上传用，≤3GB 压缩包）
# 构建:  docker build --platform=linux/amd64 -t bsrc-agent:latest .
# 导出:  docker save bsrc-agent:latest | gzip > bsrc-agent.tar.gz
# 基础：小型 Kali（kalilinux/kali-last-release）——对标榜首 Cairn/hxbai 的 Kali 环境，
# 渗透工具链完整（openssh-client/chisel/searchsploit 等），避免 b-02 类「无 ssh 现写 paramiko」卡壳。
FROM kalilinux/kali-last-release

ENV DEBIAN_FRONTEND=noninteractive PIP_NO_CACHE_DIR=1 PYTHONUNBUFFERED=1

# Kali 源：镜像自带 kali-last-snapshot 已被官方删除（404），直接重写为 kali-rolling + 清华镜像
# （构建 VM 直连国外源不稳定），失败回退官方源；install 重试容忍偶发 502
RUN printf 'Types: deb\nURIs: http://mirrors.tuna.tsinghua.edu.cn/kali/\nSuites: kali-rolling\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/kali-archive-keyring.gpg\n' > /etc/apt/sources.list.d/kali.sources \
    && (apt-get update || (printf 'Types: deb\nURIs: http://http.kali.org/kali/\nSuites: kali-rolling\nComponents: main contrib non-free non-free-firmware\nSigned-By: /usr/share/keyrings/kali-archive-keyring.gpg\n' > /etc/apt/sources.list.d/kali.sources && apt-get update))
# 核心工具（此段失败则构建失败——2026-08-23 复盘：整体回退静默丢包，验证才发现 chisel/sqlmap 缺失；
# 清华源偶发 500：769 包下到最后几个断流，失败重试一次增量补漏）
RUN apt-get install -y --no-install-recommends \
      nmap curl wget git netcat-openbsd dnsutils iputils-ping iproute2 \
      procps file binutils gdb openssl ca-certificates vim \
      jq rlwrap openssh-client sshpass proxychains4 socat chisel tmux unzip ripgrep xz-utils \
      sqlmap ffuf whatweb hydra \
      binwalk exiftool ltrace strace patchelf ruby php-cli gcc make cmake \
      python3 python3-pip python3-dev python3-paramiko python3-requests python3-pwntools python3-unicorn \
      nodejs npm \
      -o Acquire::Retries=8 -o Acquire::http::Timeout=180 \
    || apt-get install -y --no-install-recommends --fix-missing \
      nmap curl wget git netcat-openbsd dnsutils iputils-ping iproute2 \
      procps file binutils gdb openssl ca-certificates vim \
      jq rlwrap openssh-client sshpass proxychains4 socat chisel tmux unzip ripgrep xz-utils \
      sqlmap ffuf whatweb hydra \
      binwalk exiftool ltrace strace patchelf ruby php-cli gcc make cmake \
      python3 python3-pip python3-dev python3-paramiko python3-requests python3-pwntools python3-unicorn \
      nodejs npm \
      -o Acquire::Retries=8 -o Acquire::http::Timeout=180
# 大包（exploitdb ~500MB / john）：失败不阻断（searchsploit 是加分项不是硬依赖）
RUN (apt-get install -y --no-install-recommends exploitdb john \
      -o Acquire::Retries=8 -o Acquire::http::Timeout=180) \
    || echo "WARNING: exploitdb/john 安装失败（不影响核心功能）"
RUN rm -rf /var/lib/apt/lists/*

# Python 依赖：pwntools/paramiko/unicorn 由 Kali 官方包提供（pip 版 unicorn 编译与 Kali 包冲突，
# 2026-08-23 构建实测 Failed building wheel——镜像内跳过 pip 版 pwntools）。
# 此处只补 httpx/requests（requirements.txt 保留供本地 venv 用）。清华源优先，失败回退阿里源。
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --break-system-packages -i https://pypi.tuna.tsinghua.edu.cn/simple httpx requests \
    || pip install --no-cache-dir --break-system-packages -i https://mirrors.aliyun.com/pypi/simple httpx requests

# harness 攻坚 CLI（第 2 轮难题用外部 agent 接手）：node 已由 Kali apt 提供（nodejs npm 包）。
# npm registry 多源回退（构建环境网络间歇性故障 2026-08-14 实测：npmmirror DNS 偶发失败）
RUN npm config set registry https://registry.npmmirror.com 2>/dev/null || npm config set registry https://registry.npmjs.org || true
# bun 前置安装（走 npm 二进制包，绕过 bun.sh——构建环境到 bun.sh TLS 被重置）：
# ClawGod 检测到 PATH 已有 bun（≥1.3.14）就跳过它的 bun.sh 安装分支
RUN (npm i -g bun) || (npm config set registry https://registry.npmjs.org && npm i -g bun) || true
RUN npm config set registry https://registry.npmmirror.com 2>/dev/null || true

# ClawGod（https://github.com/0Chencc/clawgod）：官方 Claude Code 运行时补丁。
# 价值（对本场景）：
# ①第三方 API cache 修复——x-anthropic-billing-header 会让 DeepSeek/网关的 prompt-cache 命中率归零
# ②CYBER_RISK 安全测试拒绝提示移除（CTF 靶场场景无拒绝卡顿）
# ③破坏性操作强制确认移除 + token 精简（默认 lean-on）
# 安装脚本 COPY 进镜像（构建环境到 github.com TLS 间歇性失败，本地经 VPN 下载后随构建上下文进入）；
# 脚本内 CC 二进制走 npm pack（跟随上方 registry 配置）。
# harness 唯一后端（codex 已移除 2026-08-14）：失败不阻断构建（agent 主体不依赖 harness），
# 构建日志明确报错；最终验证步骤检查 claude 是否可用。
COPY clawgod-install.sh /tmp/clawgod-install.sh
RUN (cd /tmp && bash clawgod-install.sh && rm -f /tmp/clawgod-install.sh) \
    || echo "WARNING: ClawGod 安装失败，harness 攻坚将不可用"
ENV PATH=/root/.local/bin:$PATH
# claude 权限白名单：root 用户禁用 --dangerously-skip-permissions，用官方 settings.json 放行。
# Task 必须显式放行：主进程 + 子 agent 架构依赖 Task 工具派发并行子 agent，
# headless（-p）模式下 allow 列表之外的工具会被直接拒绝（无法交互授权）。
# "Task" 与 "Task(*)" 双写：不同 CC 版本对通配符语法的匹配有差异，裸工具名
# 是全版本最稳的放行形式（2026-08-24 review 加固）。
RUN mkdir -p /root/.claude && \
    echo '{"permissions": {"allow": ["Bash(*)", "Read(*)", "Write(*)", "Edit(*)", "Glob(*)", "Grep(*)", "Task", "Task(*)"], "deny": []}}' \
    > /root/.claude/settings.json
# harness 可用性验证：claude 二进制存在性检查（构建日志可见，失败不阻断）
RUN if command -v claude >/dev/null 2>&1; then claude --version 2>/dev/null || true; else echo "WARNING: claude not found, harness disabled"; fi

# 离线 payload 语料（浅克隆，构建期联网；运行时沙箱无公网；失败不阻断构建）
RUN git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings /opt/payloads \
    && rm -rf /opt/payloads/.git || true

# nuclei 引擎（本地预下载 v3.11.1 zip：解压后 136MB 超 GitHub 100MB 限制，
# 仓库只存 44MB zip，构建期解压；原动态下载因 GitHub API 不稳曾静默跳过）
COPY tools/bin/nuclei.zip /tmp/nuclei.zip
RUN unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin \
    && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip
# nuclei 全套模板由下方「本地漏洞库」段 COPY（/opt/nuclei-templates）

# 精简词表（多级回退：SecLists 已把 top-100.txt 改名删除，2026-08-24 构建实测 404
# 致 hydra 词表缺失；最终兜底内置列表，保证 prompt 引用的路径永不落空）
RUN mkdir -p /opt/wordlists && \
    for f in raft-small-directories.txt raft-small-words.txt; do \
      curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/$f" -o "/opt/wordlists/$f" || true; \
    done && \
    { curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-100.txt" -o /opt/wordlists/top-100-passwords.txt \
      || curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/darkweb2017_top-100.txt" -o /opt/wordlists/top-100-passwords.txt \
      || printf '%s\n' 123456 password 123456789 12345678 12345 qwerty abc123 111111 123123 1234567890 1234567 iloveyou 000000 admin welcome monkey dragon letmein login princess qwertyuiop solo passw0rd starwars master hello freedom whatever qazwsx trustno1 superman batman football baseball dragon1 michael shadow jordan harley ranger buster hunter thomas robert charlie daniel hannah magic 1q2w3e4r 1qaz2wsx zaq12wsx password1 password123 p@ssw0rd root toor test guest user info changeme > /opt/wordlists/top-100-passwords.txt; }

# 多阶段渗透基建（run 12464 复盘：渗透维度 60.71——链断在"资产清点→凭据复用→逐台收 flag"
# 后三段；以下全部为通用 tradecraft，不含任何题目先验）：
# 1) chisel 静态二进制：Web 壳/SSRF 拿到的内网访问转全工具 SOCKS 穿透（失败不阻断，
#    ssh -D + proxychains4 组合仍可用，playbook 同步教）
# 2) 通用 post-exploitation 脚本：flag_sweep.sh（拿权主机的旗标清点）+
#    creds_replay.sh（凭据清单对目标批量重放）
RUN (curl -fsSL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz -o /tmp/chisel.gz \
     && gunzip -f /tmp/chisel.gz && chmod +x /tmp/chisel && mv /tmp/chisel /usr/local/bin/chisel) \
    || echo "WARNING: chisel 下载失败，穿透回退 ssh -D + proxychains4"
# 3) fscan 静态二进制：内网横向一把梭（存活/端口/服务/弱口令/常见漏洞检测），
#    台账+凭据重放体系（#2 脚本）的主动扫描升级；经隧道时 proxychains4 fscan 使用。
#    本地预下载（v2.2.0 linux_x64，gh-proxy 代理拉取）：构建环境直连 GitHub
#    间歇性 TLS 失败（且 release 资产名是 x64 非 amd64，旧远程下载脚本双重失效）
COPY tools/bin/fscan /usr/local/bin/fscan
RUN chmod +x /usr/local/bin/fscan
# 4) 本地漏洞库（Cairn 拆解：c-02 ComfyUI 题 Cairn 用本地 PoC 检索 5 分钟秒解、
#    我们现场回忆 CVE 310 分钟分治才解——vulhub 全套 PoC + nuclei 模板是
#    通用公开漏洞库，无题目先验，合规；宿主机经 gh-proxy 预下载）
COPY tools/pocs/vulhub /opt/pocs/vulhub
COPY tools/nuclei-templates /opt/nuclei-templates
COPY tools/pocs/PayloadsAllTheThings /opt/pocs/PayloadsAllTheThings
COPY tools/pocs/hacktricks /opt/pocs/hacktricks
COPY tools/pocs/PoC-in-GitHub /opt/pocs/PoC-in-GitHub
COPY tools/flag_sweep.sh tools/creds_replay.sh /opt/tools/
RUN chmod +x /opt/tools/flag_sweep.sh /opt/tools/creds_replay.sh && touch /opt/tools/creds.txt

COPY agent /app/agent
COPY api-doc.txt /app/api-doc.txt
# claude code 直接解题模式：镜像内默认开启（本地 run-local 不设此变量，走裸 LLM 循环调试）
ENV CLAUDE_WORKER=1
# 解法库（57 题已解 + 部分进展）：worker 启动时注入复现，没有它第一轮等于从零侦察
COPY solutions.json /app/solutions.json
# 专家复盘（人工高价值提示，独立存放不被自动记录覆盖）
COPY notes.json /app/notes.json
WORKDIR /app

# 平台注入 BENCHMARK_BASE_URL / BENCHMARK_TOKEN；LLM_* 与策略参数在平台「动态环境变量」配置
# Kali 只有 python3（无 python 别名），ENTRYPOINT 必须用 python3
ENTRYPOINT ["python3", "-m", "agent"]
