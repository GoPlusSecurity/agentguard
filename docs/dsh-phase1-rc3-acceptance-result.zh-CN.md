# AgentGuard for DSH `phase1-rc3` 定向验收报告

- **测试时间**：2026-08-19 03:00–03:05（JST）
- **Git HEAD**：`557f73a`（包含 `2337e26` fail-closed 修复、`bf64fdd` baseline 冻结及验收文档提交）
- **scannerVersion**：`1.1.29-beta.0`
- **phase**：`phase1-rc3`
- **rulesBaseline**：`2337e266cf78f82e8d07f5555f7cc760b6ddc830`
- **初始 runtime mode**：`protect`
- **最终 runtime mode**：`protect`
- **总结论**：**PASS**

| 用例 | 结果 | 关键结构化证据 | 与预期差异 |
|---|---|---|---|
| UAT-RC3-01 版本与完整扫描 | PASS | 四个工具齐全；scanner 为 AgentGuard for DSH `1.1.29-beta.0` / `phase1-rc3` / baseline `2337e266...`；safe-theme coverage `{3,3,0,complete:true}`；LOW / safe-to-try / routine | 无 |
| UAT-RC3-02 超大文件 fail-closed | PASS | `lib/client.js` 为 2,726,803 bytes；coverage `{15,14,1,complete:false}`；`oversized:1`；包含 `DSH_SCAN_INCOMPLETE`；repository/runtime/review 均为 high；expert-review-required；无 safe-to-try | 无 |
| UAT-RC3-03 批量传播 | PASS | total 2 / succeeded 2 / failed 0 / incomplete 1；riskCounts low 1 + high 1；摘要明确存在一个 incomplete scan | 无 |
| UAT-RC3-04 protect 可见性 | PASS | `configuredMode: protect`；`preExecuteProtectionActive: true`；`configuredPostResponseMode: block-malicious`；摘要明确 pre-execute enforcement active | 无 |
| UAT-RC3-05 observe 与恢复 | PASS | observe 时 `configuredMode: observe`、`preExecuteProtectionActive: false`；摘要明确仅评估和审计；恢复后 protect enforcement active | 无 |
| UAT-RC3-06 最终稳定状态 | PASS | HTTP 200；配置与 summary 均恢复 protect；无遗留修改；未安装或执行扫描目标 | 无 |

## 覆盖率证据

- safe-theme：discovered 3 / scanned 3 / skipped 0 / complete `true`
- dsh-deep-whale：discovered 15 / scanned 14 / skipped 1 / complete `false`
- skippedByReason：fileLimit 0 / oversized 1 / unreadable 0
- `DSH_SCAN_INCOMPLETE`：存在
- 不完整目标最终 repository/runtime risk：high / high
- 不完整目标最终 recommendation：expert-review-required

## 状态可见性证据

- protect：`configuredMode: protect` / `preExecuteProtectionActive: true` / `configuredPostResponseMode: block-malicious`
- observe：`configuredMode: observe` / `preExecuteProtectionActive: false` / `configuredPostResponseMode: block-malicious`
- 恢复后：`configuredMode: protect` / `preExecuteProtectionActive: true` / HTTP 200

## 问题与建议

1. 两个定向验收目标均已达成：扫描不完整时 fail closed；observe/protect 当前状态明确可见。
2. 非阻塞观察：observe 的 `modelSummary` 没有重复显示 post-response mode，但结构化字段 `configuredPostResponseMode` 正确返回 `block-malicious`，配置全程未被改变。
3. `launchctl kickstart` 会短暂中断当前 DSH 会话，属于本地服务重启的预期行为。

## 结论

`phase1-rc3` 六项定向验收全部通过，最终状态已恢复为 protect，可继续维护者审阅与合并流程。
