#!/bin/bash
# 本地模式跑分入口。
# 前置：1) 已在平台创建本地模式跑分任务，拿到 BENCHMARK_BASE_URL / BENCHMARK_TOKEN / VPN 配置
#       2) 已连接靶场 VPN（否则无法访问题目容器地址）
set -euo pipefail
cd "$(dirname "$0")"

if [ -f .env ]; then
  set -a; source .env; set +a
fi

: "${BENCHMARK_BASE_URL:?请在 .env 配置 BENCHMARK_BASE_URL}"
: "${BENCHMARK_TOKEN:?请在 .env 配置 BENCHMARK_TOKEN}"
: "${LLM_API_KEY:?请在 .env 配置 LLM_API_KEY}"

export GATEWAY_REWRITE=0   # 本地模式直连 LLM，不走托管网关
export LLM_BASE_URL="${LLM_BASE_URL:-https://api.deepseek.com/v1}"
export LLM_MODEL="${LLM_MODEL:-deepseek-v4-flash}"
# nuclei CVE 模板：本地开发机用 $HOME/nuclei-templates（nuclei -update-templates 拉取），镜像用 /opt 打包路径
export NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES:-$HOME/nuclei-templates/http/cves}"

python3 -m agent "$@"
