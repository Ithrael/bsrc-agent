# bsrc-agent

Tsecbench 自主解题 Agent — BSRC "Agent+" 攻防能力挑战赛靶场参赛系统。

单容器、全自动：启动后自行拉取题目列表、按优先级调度（3 题并发上限）、逐题渗透解题、自动提交 flag，跑满全局时限。

## 架构

借鉴 Cairn（TCH 黑客松唯一 AK 系统，github.com/oritera/Cairn）的极简 harness 哲学：
**控制面全部在代码，模型只做「prompt in / tool out」**。不预设攻击流程、不拆角色。

```
main.py  入口：环境校验 → 连通性自检 → Scheduler
  └─ scheduler.py   选题优先级（分值/预估耗时，解法库题加权）+ 3 槽并发 + 全局 deadline
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
- **hint 扣分**：`HINT_POLICY=stuck`（默认）卡住 12 分钟后才放行；`never` 完全禁用。
  实测 hint 只扣约 5%（b-03 满分 1200 用后拿 1140），prompt 鼓励高分题卡住即用。
- **解法库（solutions.json）**：
  - 解出的题记录最后 15 条关键 shell 步骤（completed）→ 下轮注入后几分钟内复现锁分
    （实测 a-03 0.7min、b-01 6.4min 拿满 1200 分）；
  - 超时/步数耗尽的题记录部分进展（partial，不覆盖 completed）→ retry 轮从断点续跑，
    不再从零开始（b-02 曾 587 步/150min 白跑）；
  - 注入时自动清洗旧轮次绝对路径（`cd <旧 run 路径> &&` 剥离、路径替换），并同步写入
    NOTES.md（上下文截断后仍可恢复）。
- **超时分级**：首轮尝试封顶 60 分钟（防 b-02 这类题一次占 150min 堵死 3 个槽位），
  retry 轮按难度×flag 数放宽到 150 分钟。
- **优先级**：解法库 completed 题一律 ×3.0（含 hard），partial 题 ×2.0 尽早续跑。
- **自适应并发**：MAX_CONCURRENT 是探测上限（默认 10）而非写死值——start 收到平台
  409（实例数达上限）时自动收敛到平台实际允许的并发数，409 的题轮转队尾冷却 30s
  重试（不判死、不空转）。换平台（如百度赛放宽上限）无需改配置。
- **题内双 worker**：总分 ≥1000 且 flag ≥3 且无完整解法的大题（b 系列多阶段渗透），
  1 个容器跑 2 条思考线（A 主攻入口面 / B 主攻内网横向），共享 NOTES.md 与 flag 进度
  （共享 submitter 防重复提交、completed 判定同步），解法库记录合并两条线。`PAIR_WORKERS=0` 关闭。
- **结构化状态 STATE.md**（借鉴 Cairn 黑板的轻量裁剪）：FACTS 由代码自动维护（flag 进度、
  nmap 端口），INTENTS/ELIMINATED 由 LLM 按约定登记——防重复探索、防多 flag 漏面，
  上下文截断时状态摘要直接读 STATE.md。自由笔记仍写 NOTES.md，两者分工。
- **两轮赛制（ROUND 模式）**：`ROUND=1` 覆盖优先——没碰过的题 ×5 权重最优先、单题限时
  20min（hard 30min）、不配双 worker，使命是 63 题全部过手 + hint 收割落盘（配合
  `HINT_POLICY=free`）；中间人工调整窗口写 notes.json 专家复盘；`ROUND=2` 复现锁分 +
  双 worker 攻坚。
- **harness 攻坚（静动结合）**：裸 LLM 循环对"复现失败重探索/多阶段大题"能力密度不足，
  接入外部 agent CLI（codex/claude，借鉴 Cairn 的 agent-CLI worker 思路但只用于难题）：
  静态——第 2 轮 partial 未解题/hard 无解法题直接 harness；动态——复现题 12 步无 flag
  （复现失败）→ 打包 NOTES/STATE/最近命令 → harness 接手 → 输出流挂 flagger 自动提交，
  摘要回注裸 LLM 续跑。工作区文件天然交接，非单向门。
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
| `HINT_POLICY` | `never` 冲满分 / `stuck` 默认 / `free` 随意（hint 内容自动落盘 notes.json，下轮复现不再扣分） |
| `ROUND` | 轮次模式：`1` 覆盖优先（无解法记录的题优先、单题限时 20min/hard 30min、不配双 worker，第 1 轮使命是全题过手留解法）/ `2` 默认收割（expected_value + 解法库加权 + 双 worker 攻坚） |
| `PAIR_WORKERS` | 大题双 worker：总分 ≥1000 且 flag ≥3 且无完整解法时，1 容器 2 条思考线（A 入口面 / B 内网横向），共享 STATE.md/NOTES.md/flag 进度 |
| `HARNESS` | harness 攻坚开关（默认关，网关实测后第 2 轮再开）：外部 agent CLI 接手难题 |
| `HARNESS_BACKEND` | `codex` 默认（OpenAI /v1 网关同路已验证）/ `claude`（anthropic 路径，8/16 网关实测后可用）/ 脚本路径（测试用） |
| `HARNESS_TIMEOUT_MIN` | 单次 harness 攻坚预算，默认 15 |
| `MAX_CONCURRENT` | 并发**探测上限**，默认 10（不是写死值）。start 接口内置 0.6s 限速；超平台实例上限的 409 invalid_state 会自动把有效并发收敛到平台实际允许值，该题轮转队尾 30s 后重试，不会打爆平台也不会废题 |
| `CHALLENGE_TIMEOUT_MIN` | 单题超时基准（easy 2/3×、hard 1.5×；首轮封顶 60min，有完整解法的复现题封顶 15min），默认 30 |
| `GLOBAL_BUDGET_MIN` | 全局预算分钟数，默认 345（时限 360） |

`BENCHMARK_BASE_URL` / `BENCHMARK_TOKEN` 由平台自动注入，无需配置。

## 开发

```bash
.venv/bin/pip install pytest pytest-asyncio
.venv/bin/python -m pytest tests/ -q     # 13 个测试，含 mock 平台端到端
python -m tests.mock_server 8899          # 单独起 mock 平台手动联调
```

## 合规声明

仅用于已授权的评测与比赛环境。禁止对未授权目标使用。
