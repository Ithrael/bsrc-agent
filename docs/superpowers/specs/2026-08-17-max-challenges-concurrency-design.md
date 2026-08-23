# 6 小时最大解题数量并发优化设计

## 目标

在约 6 小时的平台窗口内，最大化完整解出的题目数量；分值和 token 成本不是优化目标。平台题目实例并发上限保持 3，单题允许多个 Claude Agent 竞速，但不能因并发导致模型网关雪崩、状态误判或已解题目长期占槽。

## 方案

- 调度优先级改为“预计完整解题概率 / 墙钟耗时”，优先已知解法、只剩一个 flag 的 partial 题、easy/medium 单 flag 题，再处理 hard 和多 flag 题。
- 保持 3 个 challenge 槽位；增加全局 Agent semaphore，默认允许 9 个 Agent（3 题各 3 线），检测到网关限流时可通过环境变量降到 6。
- 未完成且无完整解法的题按角色启动最多三条线：入口、内网/非 Web、提权/收尾；两面 flag 或 hard 单面题至少启动两条线。使用不同模型或角色提示；完成条件触发后取消同题剩余子进程。
- 完整解法只要有 `completed` 且有 `steps`、`note` 或专家笔记即可进入短复现，不要求必须有 shell steps。
- `FlagSubmitter` 继承平台已有的 `correct_flag_count`，提交响应中的平台计数作为完成判据，避免多 flag 重试时本地集合从零开始。
- 会话重建只有在 `correct_flag_count == flag_count` 时标记 completed；单次 `answer_correct` 不足以证明整题完成。
- ROUND=2 关闭 token 熔断；HINT_POLICY=free，以解题数量为目标。

## 完成即取消

同题各 Agent 共享一个完成事件。任一提交路径确认平台计数达到总 flag 数时设置事件；监督任务取消其余 harness，`run_harness` 的进程组清理逻辑负责回收 Claude 及其子进程，随后立即释放 challenge 槽位。

## 状态与隔离

本次先保留现有共享工作区协议，避免引入大规模目录迁移；增加提交锁和完成事件，减少多个 drain 任务的重复提交竞态。Agent 角色和运行结果继续记录到现有 transcript/RESULT 文件，便于后续按 Agent 统计命中率。

## 验证标准

1. 单题多线中一条线拿全 flag 后，其他进程被取消且调度器能马上补充下一题。
2. 已完成但只有 note 的解法不再执行新题三线侦察。
3. 2/3 flag 的题重试后拿到最后一面时立即判定完成。
4. 单 flag 正确提交不能把多 flag 题误标 completed。
5. 现有测试全部通过，并新增上述行为的单元/端到端测试。
