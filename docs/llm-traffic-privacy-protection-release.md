# LLM 流量隐私保护：发布与迁移说明

本文对应 Task 11 的 AgentGuard 侧发布验收。它描述 AgentGuard 的统一 evaluator、五个宿主 adapter 的能力分级，以及升级时必须保留的降级语义；不要求修改任何宿主源码或运行宿主上游测试。

## 发布前验收

在 AgentGuard 仓库和安装产物中运行：

```bash
npm run build
npm test
npm run test:dsh-package
python -m pytest plugins/hermes/tests -q
```

`src/tests/fixtures/runtime-conformance.ts` 是跨宿主标准 fixture。相同的 endpoint、credential、payload、PII 和 lifecycle facts 必须得到相同的 reason、risk score 和 decision；adapter 只负责把宿主可见性映射成 `coverageLevel`、`canBlockCurrentAction` 与 `missingFacts`。

## 覆盖矩阵

统一 fixture 覆盖：本地 endpoint、官方 provider、已知聚合商、未知 relay、高危 endpoint；普通请求、tool-loop 第二次请求、retry、fallback、辅助模型、流式响应、embedding 和 file upload。

宿主缺少最终 endpoint、credential 或完整 payload 时，相关规则必须是 `partial`/`observe_only`/`unsupported`，不能转成 allow。只有宿主实际提供 blocking lifecycle 时才执行 protect；observer 事件只记录 `observed` 或 `would_block`。

## 升级与回滚

1. 先在 `observe_only` 模式运行一轮，检查 Cloud 审计中的宿主、lifecycle、coverage、enforcement 和 `missingFacts`，确认未知事实没有被默认值填充。
2. 逐个宿主只对已标记为 `blocking` 的生命周期启用 protect；保持旧 policy cache 兼容，缺失 `schemaVersion` 按 v1 读取。
3. 发布后保留本地 policy cache、audit spool 和安装器生成的官方 hook 配置，以便离线回滚到上一版本。
4. 回滚时恢复 AgentGuard 包和对应 adapter 配置，不修改宿主源码；恢复后再次运行 conformance fixture 与离线保护测试。

## 安全边界声明

插件和本地 evaluator 不能约束恶意进程内代码直接打开 socket、绕过 adapter 或自行发起网络请求。高威胁部署必须叠加容器、沙箱、OS 网络策略或出站防火墙；AgentGuard 的 coverage 和 Dashboard 不能把这类缺口显示为已阻断。

Cloud 断开、超时或策略拉取失败时，已支持的本地 blocking 行为保持不变；observer-only 事件只保留本地审计和明确的覆盖缺口。
