# bsrc-agent

Tsecbench 自主解题 Agent — BSRC "Agent+" 攻防能力挑战赛靶场参赛系统。

单容器、全自动：启动后自行拉取题目列表、按「完整解出题数 / 墙钟时间」调度（3 题并发上限），逐题渗透解题、自动提交 flag，跑满全局时限。

## 架构

借鉴 Cairn（TCH 黑客松唯一 AK 系统，github.com/oritera/Cairn）的极简 harness 哲学：
**控制面全部在代码，模型只做「prompt in / tool out」**。硬题和多 flag 题按攻击面拆成并行角色线，提交完成后立即收敛。

```
main.py  入口：环境校验 → 连通性自检 → Scheduler
  └─ scheduler.py   选题优先级（解出题数/预估耗时）+ 3 槽并发 + Agent 并发上限 + 全局 deadline
                     + 首轮限长超时 / retry 轮放长 + 未解出重试
       └─ worker.py  单题 Agent 循环：LLM ↔ 工具调用（多 tool_calls 并行执行），自动捕获输出中的 flag
            ├─ recon.py    启动预侦察：nmap + HTTP 指纹并行采集（≤75s），结果直接交给 LLM
            │              （已知解法题跳过，直接复现更快）
            ├─ tools.py    meta-tooling：持久 bash 会话（多命名会话/后台任务）、文件读写、
            │              submit_flag / get_hint（代码层闸门）/ finish
            ├─ prompts.py  极简 system prompt + 六维度速查 playbook（Web/二进制/利用/渗透/云/规避）
            ├─ flagger.py  flag 正则捕获 + 去重（错提无惩罚，宁错杀不放过）
            └─ llm.py      OpenAI 兼容客户端，托管模式自动改写 .tsecbench.gw 网关
```

设计要点（来自对榜首 Cairn_X 跑分数据的复盘 + 本地 12 轮实测复盘）：

- **错提不惩罚**：平台 duplicate 幂等只针对已正确 flag，错提返回 correct:false 无扣分。
  因此所有工具输出都过 flag 正则自动提交（榜首错提 388 次 / 正确 71 次）。
- **hint 扣分**：`HINT_POLICY=free`（默认，6 小时冲刺优先解题数量）；`stuck` 卡住后放行，`never` 完全禁用。
  claude 直接解题模式下 retry 轮/断点重跑自动注入官方提示（扣分约 10%），
  已拿过的 hint 落盘 notes.json 下轮免费复用不重复扣分。
- **解法库（solutions.json）**：
  - 解出的题记录最后 15 条关键 shell 步骤（completed）→ 下轮注入后几分钟内复现锁分
    （实测 a-03 0.7min、b-01 6.4min 拿满 1200 分）；
  - 超时/步数耗尽的题记录部分进展（partial，不覆盖 completed）→ retry 轮从断点续跑，
    不再从零开始（b-02 曾 587 步/150min 白跑）；
  - 注入时自动清洗旧轮次绝对路径（`cd <旧 run 路径> &&` 剥离、路径替换），并同步写入
    NOTES.md（上下文截断后仍可恢复）。
- **超时分级**：按题数最大化快速轮转：hard 首轮/重试/后续为 25/35/40 分钟，medium 为
  20/25 分钟，easy 为 10/15 分钟；有完整解法的复现题单 flag 5 分钟、多 flag 10 分钟止损。
  2 flag 题及 hard 单 flag 题双线并行、flag≥3 题三线分治（各线独立预算）。
- **优先级**：已完成解法优先复现；只剩一面优先于新多 flag 题；同档按难度和预计耗时排序，目标是单位墙钟解出更多题。
- **槽位永不空闲**（平台同时最多 3 题，写死不降级——线上复盘：409 自适应收敛只降不升
  致单线程塌缩）：start 409 轮转队尾冷却 30s 重试；retry 队列空槽即补；
  pending/retry 双空但有任务在跑时节流回查平台（60s，带回题立即派发），
  no_progress/钉子题在空槽面前也是零机会成本的回挖候选；全局停滞
  （STAGNATE_BOOST_MIN 无新 flag）时插队多 flag 大题，并抢占「零 flag 零新
  FACTS 持续 2×窗口」的在跑长窗口（断点已落盘，cancel 结算后 retry 续跑）；
  收尾段快赢优先，快赢耗尽后放行最优候选（单次预算封顶 min(15min, 剩余窗口)）。
- **attempt 只在容器就绪后计数**：409 轮转/start 失败不消耗重试预算——否则被弹
  两次的题首次真实运行就带 attempt≥2（白拉 hint 扣 10%、错换 pro 模型、
  45min 窗口错降 15min 快验）。close 单次 10s 短超时不进重试链（防网络抖动
  把题目槽占住分钟级）；claude 崩溃降级分级：秒级失败（<2min）3 次止损、
  烧满预算的慢失败 6 次防误杀。
- **题内多 agent 并行**：
  - **分区双主（claude 模式）**：flag≥4 且无完整解法的大题（1200+ 分或二轮起）配两个
    claude 主进程——A 主带 Web 入口方向组（入口面/CVE/独立侦察）、B 主带内网横向方向组
    （横向/提权/云逃逸/凭证重放/收尾直读），各自进程内再派 Task 子 agent；共享
    NOTES/STATE/RELAY/HOSTS/submitter 与锁文件，任一主拿全 completion_event 双杀。
    单主进程协调 6-8 线的上下文膨胀与派发间隔是隐性串行点，分区后协调开销也并行。
  - **裸 LLM 副线**：claude 主线同题并行一条廉价裸 LLM 思考线（hard/多 flag 非复现题，
    预算封顶 SECOND_BRAIN_MIN）——claude 网关抖动/健康度降级期间解题不断线（裸循环走
    OpenAI 兼容端点，与 Anthropic 通道互为冗余）+ 冷门角度撞 flag。`SECOND_BRAIN=0` 关闭。
  - **卡面催线**：多 flag 题进度停在 0<N<T 超 15min 时，RELAY.md 自动注入加线指令
    （对卡住的面换角度加派 2 条子 agent 线，20min 冷却）——比停滞抢占温和，不杀进程。
  - **子 agent 模型分层**：hard 单 flag 八线撒网中 A 线（CVE 检索）/H 线（综合深挖）
    用 LLM_MODEL_HARD（吃知识深度），其余探路线 flash 打宽。
  - **资源看门狗**：30s 采样 load/MemAvailable，连续 2 次超阈（load>6 或可用内存<2GB）
    进入紧张态——不配双主/副线、在跑题 STATE.md 注入「子 agent ≤3」；恢复连续 2 次解除。
    多 agent 并行度的安全带（12231 复盘：24 进程吃爆 8核16G）。`RESOURCE_WATCHDOG=0` 关闭。
  - 裸 LLM 模式的原双 worker（PAIR_WORKERS，≥1000 分且 ≥3 flag）保留。
- **结构化状态 STATE.md**（借鉴 Cairn 黑板的轻量裁剪）：FACTS 由代码自动维护（flag 进度、
  nmap 端口），INTENTS/ELIMINATED 由 LLM 按约定登记——防重复探索、防多 flag 漏面，
  上下文截断时状态摘要直接读 STATE.md。自由笔记仍写 NOTES.md，两者分工。
- **两轮赛制（ROUND 模式）**：`ROUND=1` 覆盖优先——没碰过的题优先、短时过手并留断点；
  中间人工调整窗口写 notes.json 专家复盘；`ROUND=2` 复现锁分 + 双线/三线攻坚。
- **claude code 直接解题（CLAUDE_WORKER=1，镜像默认）**：每题 spawn 一个 Claude Code
  （ClawGod 版，接通 DeepSeek 网关）完整解题——原生计划-执行-反思循环 + 长上下文管理；
  多 flag/hard 题同题并行 2/3 条角色线，任一线拿齐全部 flag 立即取消兄弟线；
  bsrc-agent 保留调度/3 题并发/最多 9 Agent/超时分级/flag 双通道提交/解法库。
  裸 LLM 循环（CLAUDE_WORKER=0）保留用于本地调试。
- **claude --resume 断点续会话**：记录每次会话 session_id（ws/claude-session.json），
  断点重跑/retry 轮 `--resume` 续上原会话——上下文零丢失，NOTES/RELAY 文件重建
  从主要手段降级为兜底；resume 无输出（session 丢失/ClawGod 版不支持）自动去掉
  --resume 原样重跑，零风险。`CLAUDE_RESUME=0` 关闭。
- **LLM 双通道 fallback**：`LLM_BASE_URL_FALLBACK` 配备用网关，主通道连续 3 次
  网络/5xx 失败自动切换（key/model 可独立配），备用连续 5 次成功切回主——
  claude 通道已有「降级裸 LLM」保险，这补上裸循环自身的最后一块。
- **离线知识包**（/opt/knowledge，flash 模型的外挂记忆）：`linux-privesc.md`（提权
  决策树）、`container-escape.md`（容器逃逸/云元数据）、`shell-payloads.md`（反弹
  shell/升级 tty/盲打验证/文件传输）、`default-creds.md`（组件默认凭证表）、
  `pwn-cookbook.md`（保护机制决策树 + pwntools 模板）。
- **定向 playbook 强化**：二进制（checksec 决策树/堆/格式化字符串/gdb 直读期望输入）、
  多阶段（原语→flag 面推进纪律：文件读直读、RCE 全盘找、先提权再找 flag）、
  漏洞利用（PoC 适配三关：版本核对/参数化/无回显先证实执行）。
- **状态是资产**：worker 被要求把凭据/端点/已排除方向写进 NOTES.md，上下文超预算截断后可恢复；
  截断预算按 token 估算（CJK 1 字符≈1 token），默认 90k，防全中文长上下文触发 LLM 400。
- **模型选择**：托管沙箱无公网，LLM 只能走白名单网关（`llm.py` 自动做 `.tsecbench.gw` 改写 + https→http）。

## 本地模式（调试，随便跑不计正式次数）

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env   # 填入平台下发的 BENCHMARK_BASE_URL / BENCHMARK_TOKEN 和 LLM_API_KEY
# 连接平台下发的靶场 VPN（否则无法访问题目容器）
./run-local.sh
```

## 托管模式（正式比赛）

```bash
docker build --platform=linux/amd64 -t bsrc-agent:latest .
docker save bsrc-agent:latest | gzip > bsrc-agent.tar.gz   # ≤1GB
```

平台「配置 & 接入」页上传 tar.gz，动态环境变量配置：

| 变量 | 说明 |
|---|---|
| `LLM_BASE_URL` | 白名单内模型 API，如 `https://api.deepseek.com/v1`（镜像内自动改写为网关地址，填公网原地址即可） |
| `LLM_API_KEY` | 对应 key |
| `LLM_MODEL` | 如 `deepseek-v4-flash`（榜单头部全员使用，6 小时时限下吞吐优先） |
| `HINT_POLICY` | `free` 默认（6 小时冲刺）/ `stuck` 卡住后使用 / `never` 禁用（hint 内容自动落盘 notes.json） |
| `ROUND` | 轮次模式：`1` 覆盖优先（短时过手留断点、不配双 worker）/ `2` 默认收割（按完整解题数/墙钟时间、解法库和双线/三线攻坚） |
| `PAIR_WORKERS` | 大题双 worker：claude 模式为分区双主（flag≥4 且 1200+ 分/二轮起，A 主 Web 入口组 / B 主内网横向组）；裸 LLM 模式为总分 ≥1000 且 flag ≥3 的双思考线 |
| `SECOND_BRAIN` | claude 主线同题并行裸 LLM 副线（默认 1，hard/多 flag 非复现题；`SECOND_BRAIN_MIN` 预算默认 10min） |
| `RESOURCE_WATCHDOG` | 资源看门狗（默认 1）：load/mem 连续超阈时不配双主/副线并注入「子 agent ≤3」，恢复自动解除 |
| `CLAUDE_RESUME` | claude 断点续会话（默认 1）：断点重跑/retry 轮 --resume 原会话，失败自动回退新会话 |
| `LLM_BASE_URL_FALLBACK` | 备用 LLM 网关（主通道连续 3 次网络/5xx 失败切换；`LLM_API_KEY_FALLBACK`/`LLM_MODEL_FALLBACK` 可独立配，缺省沿用主配置） |
| `HARNESS` | harness 攻坚开关（默认关，网关实测后第 2 轮再开）：外部 agent CLI 接手难题 |
| `HARNESS_BACKEND` | `claude`（ClawGod 版，唯一后端）/ 脚本路径（测试用）。codex 已移除 |
| `HARNESS_TIMEOUT_MIN` | 单次 harness 攻坚预算，默认 15 |
| `LLM_MODEL_HARD` | 多模型分工：hard 题全程、easy/medium 一轮未解（attempt≥1）用该模型（如 `deepseek-v4-pro`），其余 flash |
| `CLAUDE_HARD_EFFORT` | hard 会话 effort（思考预算），默认 `max`；置空关闭 |
| `MAX_CONCURRENT` | **平台题目槽位上限 3**。start 接口内置 0.6s 限速；409 invalid_state 不降级，题轮转队尾 30s 后重试 |
| `MAX_AGENT_CONCURRENT` | 主 claude 进程全局上限，默认 8（3 题 = 3 主进程 + 断点重跑等辅助调用余量）；Task 子 agent 在主进程内并行，不占此额度 |
| `CLAUDE_TOKEN_BUDGET` | `<0` 禁用 Claude 会话 token 熔断（默认 -1）；6 小时冲刺不因 token 额度提前停题。注意熔断只统计主进程流 usage，子 agent 消耗不计入 |
| 单题预算（非配置项） | 代码按难度/尝试次数决定：hard 25/35/40min、medium 12/25min、easy 8/15min；复现题单 flag 5min、多 flag 10min |
| `GLOBAL_BUDGET_MIN` | 全局预算分钟数，默认 345（时限 360），仅 NEVER_STOP=0 时生效 |

`BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN` 由平台自动注入，无需配置。

## 开发

```bash
.venv/bin/pip install pytest pytest-asyncio
.venv/bin/python -m pytest tests/ -q     # 72 个测试，含 mock 平台端到端
python -m tests.mock_server 8899          # 单独起 mock 平台手动联调
```

## 合规声明

仅用于已授权的评测与比赛环境。禁止对未授权目标使用。
