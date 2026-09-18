# AgentGuard LLM 出站隐私保护实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 只修改 AgentGuard，在其中落地个人隐私规则 1–19，并通过 OpenClaw、deepseek-harness（DSH）、Hermes、Codex 和 Claude Code 已公开的生命周期接口提供最大可实现保护；对宿主没有暴露的模型流量事实明确标记为 `unknown`、`observe_only` 或 `unsupported`，不宣称已完整拦截真实模型 API 流量。

**Architecture:** AgentGuard 提供统一的端点分级、PII 检测、运行时决策、脱敏审计、审批协议和宿主能力模型；每个 adapter 只消费对应 Agent 已公开的生命周期事件，并把实际可见字段标准化。AgentGuard 不修改或 patch 任何宿主源码。完整 prompt 和响应只在本机内存中参与判定，AgentGuard Cloud 只下发策略并接收脱敏元数据与覆盖状态。

**Tech Stack:** TypeScript/Node.js（AgentGuard）、Python（AgentGuard Hermes 插件）、Codex 原生 `hooks.json`、Claude Code 原生 settings hooks、各宿主已有插件/Hook 生命周期、AgentGuard Cloud policy/audit API。

**Spec:** 原始需求为 `/Users/jeff/Downloads/AgentGuard 个人隐私保护规则集.md`；平台现有接入文档见 [OpenClaw](./openclaw.md)、[DSH](./dsh.md)、[Hermes](./hermes.md)、[Claude Code](./claude-code.md) 和 [隐私边界](./privacy-boundary.md)。

## Global Constraints

- 本地规则在未连接 Cloud 时必须仍然可用；Cloud 不得成为本地 `block` 的可用性依赖。
- 只允许修改 AgentGuard 仓库及 AgentGuard 安装到目标项目/用户目录的插件、Hook 和配置；禁止修改、patch、fork 或要求发布 OpenClaw、DSH、Hermes、Codex、Claude Code 源码。
- 不得依赖尚不存在的宿主生命周期；adapter 必须兼容宿主当前公开接口，并对能力缺口显式降级。
- 原始 prompt、文件内容、模型响应、Authorization header 和 API key 不得上传 Cloud。
- API key 只允许生成 `credentialKind`、`credentialPresent` 等事实；不得进入 hook payload、日志或审批文案。
- 宿主公开逐请求事件时，每次 retry、fallback、provider 切换和 endpoint 切换都必须重新检查；宿主未公开时标记为 `unsupported`，不得声称已经复核。
- 对 T3/T4 端点的强阻断只有在宿主于发送前公开最终 endpoint 时才能成立；只有 run 级或工具级事件时，仅能提供预防性配置保护和审计。
- 规则证据必须先脱敏再写入 `~/.agentguard/audit.jsonl`，Cloud 同步只能处理已脱敏事件。
- AgentGuard 能控制的 `require_approval`、解析错误和 evaluator 错误应默认拒绝；如果宿主规定 Hook 超时/崩溃后继续执行，则必须标为 fail-open 能力缺口并告警，不能宣称 AgentGuard 可以覆盖宿主行为。
- 宿主内 hook 是纵深防御，不是对恶意插件或任意进程内代码的隔离边界；高威胁部署仍需 OS/容器级网络出口控制。
- 首批按宿主实际公开能力覆盖 chat completions、responses、messages；embeddings、provider file upload 和辅助模型调用如果没有公开生命周期，必须显示为 `unsupported`。
- 不引入本地模型代理、透明网络代理或流量劫持作为补偿路径。

---

## 1. 当前会话结论

### 1.1 原始需求分成三层

1. **静态 PII 扫描（规则 1–10）**：发现代码、配置、数据文件中硬编码的身份证、银行卡、生物识别、医疗、轨迹、通讯录、手机号、邮箱和批量个人数据。
2. **静态中转站风险（规则 11–13）**：发现模型 endpoint 覆盖、用户 key 转发和安装脚本静默改写 agent 配置。
3. **运行时模型流量保护（规则 14–19）**：在模型请求实际发出前检查 endpoint、PII、凭据和批量 workspace 数据，在模型响应驱动工具执行前检查响应投毒。

前两层可以完全由 AgentGuard 实现。第三层的上限取决于宿主当前已经公开的模型调用生命周期；本计划不要求宿主新增接口，缺失能力按 `partial/observe_only/unsupported` 处理。

完整规则清单：

| # | Rule ID | 类型 | 核心目标 |
| --- | --- | --- | --- |
| 1 | `PII_NATIONAL_ID` | 静态 | 身份证、护照、SSN 等证件号 |
| 2 | `PII_BANK_ACCOUNT` | 静态 | 银行卡、信用卡、IBAN、收款账户 |
| 3 | `PII_BIOMETRIC` | 静态 | 人脸、指纹、声纹、虹膜、基因数据 |
| 4 | `PII_MINOR_DATA` | 静态 | 不满 14 周岁未成年人数据 |
| 5 | `PII_HEALTH_RECORD` | 静态 | 病历、诊断、处方和检验数据 |
| 6 | `PII_LOCATION_TRACE` | 静态 | 连续精准定位和行踪轨迹 |
| 7 | `PII_CONTACT_DUMP` | 静态 | 批量通讯录或客户名单 |
| 8 | `PII_PHONE_NUMBER` | 静态 | 中国手机号和 E.164 号码 |
| 9 | `PII_EMAIL_ADDRESS` | 静态 | 个人邮箱地址 |
| 10 | `PII_HARDCODED_DATASET` | 静态 | 多类 PII 共现的内联数据集 |
| 11 | `LLM_ENDPOINT_OVERRIDE` | 静态 | 模型 base URL 指向非官方域名 |
| 12 | `RELAY_KEY_FORWARDING` | 静态 | 用户模型 key 被转发到第三方 host |
| 13 | `RELAY_INSTALL_SCRIPT` | 静态 | 安装脚本静默改写 agent endpoint |
| 14 | `UNTRUSTED_LLM_ENDPOINT` | 运行时 | 模型请求发往 T3/T4 endpoint |
| 15 | `PII_EGRESS` | 运行时 | 模型 payload 携带个人信息出站 |
| 16 | `LLM_ENDPOINT_HIJACK` | 运行时 | shell/file write 劫持模型 endpoint |
| 17 | `RELAY_RESPONSE_TAMPERING` | 运行时 | 中转响应注入 tool call、命令或未知包 |
| 18 | `LLM_KEY_TO_UNKNOWN_HOST` | 运行时 | 模型凭据被送往未知或高危 host |
| 19 | `WORKSPACE_BULK_EGRESS` | 运行时 | 大体积、多文件 workspace 数据出站 |

### 1.2 五个宿主在“不修改上游”约束下的能力

| 宿主 | 可使用的现有接口 | AgentGuard 可实现能力 | 主要缺口 | 覆盖级别 |
| --- | --- | --- | --- | --- |
| DSH | `llm/stream` waterfall | 在 `next()` 前检查并短路语义请求；可包装 stream 检查响应和 tool call；覆盖通过统一 LLM service 发起的辅助调用 | 看不到 adapter 最终 URL、认证事实和精确序列化字节数；直接绕过 service 的调用不可见 | `partial`，五者中最高 |
| Hermes | `pre_llm_call`、`pre_api_request`、`post_api_request`、`pre_tool_call` | 观察主循环请求/响应；通过 `pre_tool_call` 阻止响应诱导的危险工具执行 | API hook 返回值不控制调用且异常被吞；system/tools 不完整；辅助 SDK 调用可绕过；不能阻断模型出站 | 模型流量 `observe_only`，工具层 `partial` |
| OpenClaw | `before_agent_run`、`before_model_resolve`、`before_prompt_build`、`llm_input/output`、`model_call_started/ended`、tool hooks | 在 run 级阻断初始输入；观察模型语义与调用统计；阻止危险工具和 endpoint 配置修改 | 没有公开的逐模型请求决策 gate；retry、fallback、辅助调用和最终 transport facts 不完整 | 模型流量 `observe_only/partial`，run/tool 层可阻断 |
| Codex | `UserPromptSubmit`、`PreToolUse`、`PermissionRequest`、`PostToolUse`、compact hooks | 拒绝用户 prompt 和受支持的本地工具调用；过滤工具结果；保护 endpoint 配置 | 没有逐模型请求/响应 Hook，看不到最终 endpoint、credential 和完整 payload；托管工具可能绕过 | prompt/tool `partial`，模型流量 `unsupported` |
| Claude Code | `UserPromptSubmit`、`UserPromptExpansion`、`PreToolUse`、`PostToolUse`/`PostToolUseFailure`、`PostToolBatch`、`ConfigChange`、`PreModelSwitch`、`MessageDisplay`、`Stop` 等 | 拒绝用户 prompt/命令展开/工具；原位替换成功工具输出；在下一模型调用前检查整批 tool results；阻止部分配置和模型切换 | 没有逐模型 HTTP 请求 gate；失败工具输出不能原位替换；`@file` 注入绕过 `PreToolUse`；看不到最终 endpoint/credential/完整 payload；自动 fallback 覆盖不完整；显示层 Hook 不改变 transcript | prompt/tool/context `partial`，模型 transport `unsupported` |

推荐交付顺序：**AgentGuard 公共能力与 capability model → DSH adapter → Claude Code adapter → Hermes adapter → OpenClaw adapter → Codex adapter → Cloud 管理面**。先用 DSH 验证可阻断的语义请求协议，再利用 Claude Code 较丰富的工具/上下文 Hook 验证分阶段保护，其他 adapter 按实际生命周期降级，不能为了统一表面能力而伪造缺失事实。

### 1.3 “运行时规则看不到真正模型 API 流量”的根因

现有 AgentGuard 主要拦截 shell、文件、browser、network tool。模型 provider 的 SDK 调用通常由宿主内部直接发出，不经过这些 tool hook。因此仅检查：

- 用户输入；
- 会话开始；
- shell 中的 `curl`；
- tool call；

都不能证明最终发给模型的 payload、endpoint 和 credential 组合是安全的。真正的安全门必须位于“provider、endpoint、credential 和最终请求已经确定，但 socket/SDK 请求尚未发送”的边界。

### 1.4 Codex 原生 Hook 调研结论

评估范围为本机 `codex-cli 0.148.0-alpha.15`、CLI 生成的 App Server schema，以及 [Codex Hooks 官方文档](https://learn.chatgpt.com/zh-Hans/docs/hooks)。本机安装目录只有可执行文件，没有完整 Codex 源码，因此以下结论以公开接口和本机可观测行为为准。

Codex 当前公开的生命周期事件包括：

- 会话：`SessionStart`、`SessionEnd`、`Interrupt`；
- 用户和轮次：`UserPromptSubmit`、`Stop`；
- 工具：`PreToolUse`、`PermissionRequest`、`PostToolUse`；
- 上下文压缩：`PreCompact`、`PostCompact`；
- 子智能体：`SubagentStart`、`SubagentStop`。

这些 Hook 中不存在 `before_model_request`、`after_model_response`、provider retry/fallback 或最终 HTTP transport 事件。App Server 的 `turn/started`、`item/started`、`item/completed` 等通知是状态观察/控制面，也不是模型请求发送前的同步安全门。

#### 1.4.1 可用能力

| Hook | AgentGuard 用途 | 能否同步阻断 | 关键限制 |
| --- | --- | --- | --- |
| `UserPromptSubmit` | 检查用户本轮直接提交的 prompt，命中 PII/API key 时拒绝或警告 | 可以，返回 `decision: "block"` 或退出码 `2` | 只包含原始用户 prompt，不包含 system/developer、历史消息、工具结果、附件、compact 后上下文和 retry 请求 |
| `PreToolUse` | 检查 shell、`apply_patch`、MCP 和大多数本地函数工具；阻止读取敏感文件、修改 endpoint、危险外发 | 可以，返回 `permissionDecision: "deny"`；也可改写受支持的输入 | 托管工具（例如 WebSearch）不经过此路径；部分专用工具可选择绕过；不是模型 transport gate |
| `PermissionRequest` | 对 Codex 已经准备发起的 shell、文件或受管网络审批作 allow/deny | 可以 | 只有 Codex 原本就要审批时才触发，不能为普通动作主动创建审批 |
| `PostToolUse` | 扫描工具结果并阻止原始结果继续交给模型 | 只能阻止后续消费 | 工具副作用已经发生，不能回滚；仍看不到最终模型请求 |
| `PreCompact` / `PostCompact` | 记录压缩发生、做审计或补充上下文策略 | 不适合作为模型流量 gate | 看不到压缩后最终发送的完整语义 payload |
| `Stop` | 轮次结束时做审计或验证 | 不能阻止已经发生的模型调用 | 只能影响轮次是否继续，不能拒绝或撤销既有模型响应 |

必须使用同步 Hook；`async: true` 的后台 Hook 不能阻止、批准或改写触发它的动作。Hook 输出不得带回原始 PII、API key 或完整工具结果，因为过长输出可能溢写到本机临时文件。

#### 1.4.2 对规则 14–19 的覆盖边界

| 规则 | Codex 原生 Hook 可实现部分 | 无法实现部分 | 覆盖结论 |
| --- | --- | --- | --- |
| `UNTRUSTED_LLM_ENDPOINT` | `PreToolUse` 可阻止 shell/文件工具把配置改到未知 endpoint | 无法读取每次模型调用最终解析出的 endpoint，也无法检查内部 fallback | 部分 |
| `PII_EGRESS` | `UserPromptSubmit` 可检查用户直接粘贴的 PII；`PostToolUse` 可阻止敏感工具结果继续进入上下文 | 无法检查最终请求中的 system、历史、附件、压缩上下文和内部生成内容 | 部分 |
| `LLM_ENDPOINT_HIJACK` | `PreToolUse` 可阻止受支持工具修改 `.codex/config.toml`、环境变量或 shell 启动配置 | 非 Hook 路径修改以及下一次请求的实际 endpoint 无法复核 | 部分，是原生 Hook 最适合覆盖的运行时规则 |
| `RELAY_RESPONSE_TAMPERING` | 恶意响应最终生成受支持的本地工具调用时，`PreToolUse` 可做最后一道拦截 | 没有模型响应进入 Agent 前的 Hook；正文和托管工具不受完整控制 | 部分 |
| `LLM_KEY_TO_UNKNOWN_HOST` | 可阻止明显读取 key 后调用 `curl`/MCP 的工具行为 | 看不到 Codex 内部模型请求的 destination 与 Authorization 组合 | 不满足模型流量要求 |
| `WORKSPACE_BULK_EGRESS` | 可按单次文件读取、命令或 MCP 参数做路径/大小启发式检查 | 无法计算最终组装请求的总字节数、文件数和附件大小 | 不满足模型流量要求 |

因此，Codex 原生 Hook 方案的准确定位是：**保护用户直接输入和本地工具边界，降低 endpoint 劫持、敏感文件读取及响应诱导工具执行的风险；不提供真实模型 API 流量的完整可见性或阻断保证。**

### 1.5 Claude Code 原生 Hook 调研结论

评估依据为 2026-09-16 抓取的 [Claude Code Hooks reference](https://code.claude.com/docs/en/hooks) 和 [Permissions 文档](https://code.claude.com/docs/en/permissions)，以及 AgentGuard 当前 Claude Code installer/adapter。本机未安装 `claude` CLI，无法记录本机版本或做真实进程验证，因此实施前必须在声明的最低支持版本上运行 fixtures。部分新事件有明确版本要求，例如 `PreModelSwitch`/`PostModelSwitch` 需要 Claude Code `2.1.251+`。

Claude Code 没有 `before_model_request`、`after_model_response` 或能暴露最终 HTTP destination/Authorization 的 Hook，但现有工具和上下文生命周期比 Codex 更完整：

| Hook | AgentGuard 可实现能力 | 能否同步阻断/改写 | 关键限制 |
| --- | --- | --- | --- |
| `UserPromptSubmit` | 在 Claude 处理用户输入前扫描 PII、API key 和大段数据 | 可用 `decision: "block"` 或退出码 `2` 阻断 | 只看到当前用户 prompt，不包含 system、历史、工具结果和最终组装 payload；不能原位替换 prompt |
| `UserPromptExpansion` | 在 slash command、自定义 command/skill 或 MCP prompt 展开前按命令名、参数和来源执行 allow/block 策略 | 可阻止本次展开 | Hook 输入是原始 invocation 及命令元数据，不保证包含展开后的完整 prompt；只能按命令策略或可见参数判断，不能把它当成最终 payload 扫描 |
| `PreToolUse` | 检查 Bash/PowerShell、Read/Write/Edit、Web、MCP 等工具输入 | 可 `allow/deny/ask/defer`，也可 `updatedInput`；`deny` 在权限规则前生效 | 不是模型 transport gate；`@file` 引用在构建 prompt 时直接注入内容，不触发此 Hook；多个并行工具的 Hook 彼此独立，不能在读取前聚合批量总量；command Hook 超时默认不阻断工具 |
| `PermissionRequest` | 在 Claude Code 准备显示工具审批时代理 allow/deny | 可 allow/deny | 只有本来需要审批的工具才触发；普通工具策略应使用 `PreToolUse` |
| `PostToolUse` | 扫描工具结果，在进入下一模型上下文前做脱敏 | 可用 `updatedToolOutput` 替换结果 | 工具副作用已经发生；单纯返回 `decision: "block"` 不会隐藏原始输出，必须生成匹配该工具输出 schema 的替换值 |
| `PostToolUseFailure` | 扫描失败类型和可见错误，记录敏感失败路径 | 不能替换或阻止失败结果，只能追加 context | 命令 stderr、异常文本等仍可能含 PII；能否由同批 `PostToolBatch` 捕获并阻止下一模型调用必须按目标版本验证，未验证前标为 `partial/unsupported` |
| `PostToolBatch` | 在下一模型请求前检查整批 tool calls 及模型将看到的序列化 `tool_response`，统计本批文件/字节/PII | 可阻止 agentic loop 进入下一模型调用 | 只覆盖当前工具批次，不包含 system/history/用户输入组成的完整 payload；不能证明 resume 后旧结果不会再次进入上下文 |
| `ConfigChange` | 审计并阻止 Claude settings/skill 配置在当前 session 生效 | 除 `policy_settings` 外可阻断生效 | Hook 在文件变化后触发，不负责回滚磁盘内容；server-managed settings 不触发；下次新 session 仍需重新检查磁盘配置 |
| `PreModelSwitch` | 检查用户或 SDK 请求的目标 model，并基于 `context_tokens` 识别大上下文重发 | 可 `allow/deny/ask` | 看不到 endpoint/credential；不覆盖 Claude Code 自动 fallback；自定义 gateway model 仍只有 model id |
| `PostModelSwitch` | 观察 session model 改变及部分自动 fallback | 不能阻断 | 不覆盖 fallback chain 中仅服务单个 turn、但未改变 session model 的临时替换 |
| `MessageDisplay` | 扫描/替换用户界面显示的 assistant 文本 | 只能替换显示内容 | 不改变 transcript 或 Claude 内部所见内容；超时/失败显示原文；tool-call-only response 不触发 |
| `Stop` / `SubagentStop` | 检查最终 assistant 文本并要求继续工作 | 可阻止“停止” | 模型响应已经生成并可能已经显示；不是响应进入工具循环前的安全门，不能撤销既有输出 |
| `InstructionsLoaded` / compact hooks | 观察指令文件加载并控制部分 compact 行为 | 指令加载本身不能阻断；`PreCompact` 可阻止压缩 | 看不到每次最终请求的完整上下文；不能依赖 transcript 格式重建稳定的发送前 gate |

必须使用本地同步 `type: "command"` Hook。`type: "http"` 会把 Hook 输入发送到网络端点，`type: "prompt"`/`type: "agent"` 会额外调用模型，不适合作为处理原始隐私数据的默认安全边界；`async: true` 也不能承担同步阻断。

#### 1.5.1 对规则 14–19 的覆盖边界

| 规则 | Claude Code 原生 Hook 可实现部分 | 无法实现部分 | 覆盖结论 |
| --- | --- | --- | --- |
| `UNTRUSTED_LLM_ENDPOINT` | `PreToolUse` 可阻止工具修改 endpoint；`ConfigChange` 可检查新 settings 并阻止其在当前 session 生效 | 没有每次模型请求的最终 endpoint；环境变量、自动 fallback、gateway 内部路由和下一 session 实际 destination 不可确认 | 模型 transport `unsupported`，配置保护 `partial` |
| `PII_EGRESS` | `UserPromptSubmit` 阻断直接输入；`UserPromptExpansion` 可阻止不受信任的 command/skill/MCP prompt；`PreToolUse` 阻止常规敏感文件读取；`PostToolUse.updatedToolOutput` 脱敏结果；`PostToolBatch` 在下一模型调用前做整批检查 | 看不到 system、完整 history、缓存内容、所有附件及最终组装 payload；`@file` 注入绕过 `PreToolUse`，只有预先配置的精确 `Read` deny 路径可补偿 | `partial`，但工具结果路径覆盖明显优于仅有 pre-tool 的宿主 |
| `LLM_ENDPOINT_HIJACK` | `PreToolUse` 阻止 Bash/Write/Edit 修改；`ConfigChange` 阻止部分 settings 生效；`PreModelSwitch` 控制显式 model switch | policy/server-managed 设置、外部持久化修改、自动 fallback 和最终 endpoint 仍不可控 | `partial` |
| `RELAY_RESPONSE_TAMPERING` | 模型产生危险工具调用时由 `PreToolUse` 拒绝或审批；`Stop`/`MessageDisplay` 可观察文本风险 | 没有原始模型响应进入 Agent 前的 Hook；显示替换不影响 transcript；无法验证 relay 签名或来源 | 工具执行保护 `partial`，响应完整性 `unsupported` |
| `LLM_KEY_TO_UNKNOWN_HOST` | 可阻止显式 Bash/Web/MCP 工具把可见 key 发往未知 host | 看不到 Claude Code 内部模型 HTTP destination 与 Authorization 组合 | 模型 transport `unsupported` |
| `WORKSPACE_BULK_EGRESS` | `PreToolUse` 做常规单次读取控制；`PostToolBatch` 聚合本批文件路径和 serialized results；`PostToolUse` 可替换大结果 | 无法计算包含历史/system/cache/附件的最终 request bytes；并行读取在执行前无法统一聚合；`@file` 注入不产生可聚合的 tool batch | `partial` |

结论：**仅修改 AgentGuard 时，Claude Code 能提供很强的 prompt/tool/context 分阶段保护，尤其适合阻止敏感文件进入下一次模型调用；但仍不能满足最终模型 endpoint、credential 和完整 payload 的 transport 级规则。**

#### 1.5.2 AgentGuard 当前实现差距

现有 `agentguard init --agent claude-code` 只生成 `PreToolUse`，匹配 Bash、Read、Write/Edit/MultiEdit 和 WebFetch/WebSearch。现有 `require_approval → permissionDecision: "ask"` 与 Claude Code 协议兼容，但仍有以下缺口：

- 没有安装 `UserPromptSubmit`、`UserPromptExpansion`、`PostToolUse`、`PostToolUseFailure`、`PostToolBatch`、`ConfigChange`、`PreModelSwitch`、`PostModelSwitch` 和 `Stop`。
- 没有通用 MCP matcher，也没有 PowerShell 等新增/平台特定工具覆盖。
- 没有处理 `@file` 绕过 `PreToolUse` 的路径；若组织明确配置敏感路径，只能通过精确合并 Claude Code `Read` deny 权限规则补偿，不能用宽泛 deny 伪装成完整 payload 保护。
- 没有实现 `updatedToolOutput`，因此工具结果中的 PII 不能在进入模型前原位脱敏。
- `.claude/settings.local.json` 已存在时默认直接跳过，使用 `--force` 又会整体覆盖，尚未结构化合并用户已有 settings/hooks。
- Hook command 使用 `./.claude/hooks/...` 相对路径；Claude Code 改变 cwd 后可能失效，应改用 `${CLAUDE_PROJECT_DIR}` 或安装时解析的稳定路径。
- adapter 仍以 Pre/Post tool 二分法建模，无法表达 prompt、prompt-expansion、batch、config、model-switch、display 和 stop 等阶段，也没有 coverage/enforcement status。

---

## 2. 统一运行时协议

五个 adapter 应映射到同一个 AgentGuard 本地协议，避免复制隐私规则；统一的是事件和能力描述，不是假设所有宿主都拥有相同生命周期。

### 2.1 能力与事件

建议在 `src/runtime/types.ts` 增加宿主能力描述和可选的 `llm_request`、`llm_response` action type：

```ts
type CoverageLevel = 'full' | 'partial' | 'observe_only' | 'unsupported';
type EnforcementStatus = 'enforced' | 'would_block' | 'observed' | 'unsupported';

interface AgentLifecycleCapabilities {
  userPrompt: 'blocking' | 'observe_only' | 'none';
  promptExpansion: 'blocking' | 'observe_only' | 'none';
  modelRequest: 'blocking' | 'observe_only' | 'none';
  modelResponse: 'blocking' | 'observe_only' | 'none';
  preTool: 'blocking' | 'observe_only' | 'none';
  postTool: 'blocking' | 'observe_only' | 'none';
  toolOutputRewrite: boolean;
  postToolBatch: 'blocking' | 'observe_only' | 'none';
  configChange: 'blocking' | 'observe_only' | 'none';
  modelSwitch: 'blocking' | 'observe_only' | 'none';
  assistantDisplay: 'rewrite_display_only' | 'observe_only' | 'none';
  finalDestination: boolean;
  credentialFacts: boolean;
  exactPayloadBytes: boolean;
  retryAndFallback: boolean;
  auxiliaryModelCalls: boolean;
}

interface LlmEgressRequestMetadata {
  requestId: string;
  parentRequestId?: string;
  sessionId: string;
  purpose: 'conversation' | 'compaction' | 'title' | 'vision' |
    'embedding' | 'file_upload' | 'plugin' | 'other';
  lifecycleStage: 'user_prompt' | 'prompt_expansion' | 'run_start' | 'model_request' |
    'model_response' | 'pre_tool' | 'post_tool' | 'post_tool_batch' |
    'config_change' | 'model_switch' | 'assistant_display' | 'stop';
  canBlockCurrentAction: boolean;
  provider?: string;
  model?: string;
  apiMode?: string;
  attempt?: number;
  isRetry?: boolean;
  isFallback?: boolean;
  destination?: {
    scheme?: string;
    host?: string;
    port?: number;
    path?: string;
    service?: string;
    region?: string;
  };
  credentialKind: 'api_key' | 'oauth' | 'aws' | 'ambient' | 'none' | 'unknown';
  credentialPresent: boolean | 'unknown';
  payloadBytes?: number;
  attachmentBytes?: number;
  messageCount?: number;
  filePathCount?: number;
}
```

每个 adapter 静态声明 `AgentLifecycleCapabilities`，事件再携带本次实际的 `canBlockCurrentAction`。不可见字段使用 `undefined` 或 `unknown`，不得从默认 provider、环境变量名称或历史事件推断为本次真实网络事实。

宿主 Hook 已提供的语义 payload 作为本地、只读、短生命周期输入交给 evaluator，但不得放进持久化 metadata。审计事件只保存脱敏摘要、计数、覆盖级别和缺失事实。

### 2.2 生命周期语义

```text
宿主触发现有生命周期事件
        ↓
AgentGuard adapter 标准化“可见事实 + 缺失事实 + 是否可阻断”
        ↓
本地 evaluator 对当前事件可判定的规则求值
        ↓
blocking hook: allow / warn / require_approval / block
`observe_only` hook: audit / warn（不得声称已阻断模型调用）
        ↓
pre-tool hook 对危险执行动作提供最后一道阻断
```

要求：

- `canBlockCurrentAction=true` 时才允许返回有强制语义的 `require_approval` 或 `block`；否则决策必须标为 `observe_only`，同时通过后续 `pre_tool` 尽可能阻止危险执行。
- evaluator 保留策略原始决策，adapter 另外记录实际 `enforcementStatus`；例如 observer 命中 `block` 时记录 `policyDecision=block`、`enforcementStatus=would_block`，不能把两者折叠成“已阻断”。
- `warn` 不阻断，但必须记录脱敏审计。
- 只有 DSH `llm/stream` 这类现有 blocking seam 才能在模型语义请求发送前短路；其他宿主不得把 run-start、observer 或 tool hook 命名为 `before_model_request`。
- 如果现有 response hook 不能阻止响应继续流转，AgentGuard 只记录响应风险；当响应产生本地工具调用时，再由 blocking `pre_tool` 执行实际阻断。
- retry/fallback 只有在宿主为每次尝试发出可区分事件时才关联；否则 capability 标为 `false`。
- 多个 adapter 使用同一规则 evaluator，但每条审计必须保留 `agentHost`、`lifecycleStage`、`coverageLevel` 和 `missingFacts`。

### 2.3 端点分级

在 `src/runtime/llm-endpoints.ts` 建立唯一分级实现：

| Tier | 含义 | 默认处置 |
| --- | --- | --- |
| T0 | localhost、loopback、`.local`、Ollama、LM Studio | endpoint `allow`，PII `allow` |
| T1 | 模型厂商官方端点 | endpoint `allow`，PII `warn` |
| T2 | Azure OpenAI、Bedrock、Vertex AI、OpenRouter 等可审计云/聚合商 | endpoint `allow`，PII `warn` |
| T3 | 未知、自建、中转端点 | endpoint/PII `require_approval` |
| T4 | blocked domain、高危 TLD、IP 字面量、短链等 | `block` |

用户配置的 `trustedLlmEndpoints` 可将私有部署提升到受信范围，但不能覆盖 `blockedDomains`。

### 2.4 规则 14–19 的标准输入、决策和降级

| 规则 | 完整判断所需事实 | 事实齐全时的默认决策 | 事实缺失时的处理 |
| --- | --- | --- | --- |
| `UNTRUSTED_LLM_ENDPOINT` | 最终 destination + API path/service + tier | T3 `require_approval`，T4 `block` | 标为 `unsupported`；仍可通过配置写入和显式网络工具检测预防 endpoint 劫持 |
| `PII_EGRESS` | 即将发送的完整语义 payload + tier | T0 `allow`；T1/T2 `warn`；T3 `require_approval`；T4 `block` | 只扫描 hook 可见部分并标为 `partial`；不得写成“本次请求无 PII” |
| `LLM_ENDPOINT_HIJACK` | shell/file write 对 endpoint 配置的修改 | T3 `require_approval`，T4 `block` | 只要有 blocking pre-tool 就执行；宿主内部或外部修改标为不可见 |
| `RELAY_RESPONSE_TAMPERING` | 完整响应、来源 tier、tool calls/命令/包名 | T3/T4 `require_approval` | response observer 只审计；blocking pre-tool 阻止最终危险动作，覆盖标为 `partial` |
| `LLM_KEY_TO_UNKNOWN_HOST` | `credentialPresent`/`credentialKind` + 最终 destination | T3/T4 `block` | `credentialPresent` 或 destination 任一未知即标为 `unsupported`，不得推断 allow |
| `WORKSPACE_BULK_EGRESS` | 最终 payload bytes、附件 bytes、多文件路径特征、tier | T0–T2 `warn`；T3 `require_approval`；T4 `block` | 对可见文件读取/工具参数做启发式检测并标为 `partial`；不能计算最终总量时不产生完整结论 |

---

## 3. 分阶段实施

### Task 1：冻结策略语义和数据边界

**Files:**

- Modify: `src/runtime/types.ts`
- Modify: `src/runtime/policy.ts`
- Modify: `docs/privacy-boundary.md`
- Test: `src/tests/runtime-cloud.test.ts`

**Produces:** 版本化的本地请求/响应事件、宿主 capability、endpoint tier、审批和 Cloud 脱敏契约。

- [x] 将 `llm_request`、`llm_response` 加入 `RuntimeActionType`，检查所有 action type switch 和序列化路径。
- [x] 增加 `AgentLifecycleCapabilities`、`CoverageLevel`、`EnforcementStatus`、`canBlockCurrentAction` 和 `missingFacts`，由每个 adapter 显式声明。
- [x] 给 `EffectiveRuntimePolicy.network` 增加 `untrustedLlmEndpoint`、`trustedLlmEndpoints`，增加 `privacy.piiEgressTrusted`、`privacy.piiEgressUntrusted`、`privacy.enabledCategories`、`privacy.bulkEgressBytes`、`privacy.bulkAttachmentBytes`、`privacy.bulkFilePathCount`。
- [x] 规定 credential metadata 只包含类型和存在性，禁止 key、Authorization 值和可逆摘要。
- [x] 规定 `payloadBytes` 是 UTF-8 序列化请求体字节数；无法取得时使用 `undefined`，不得用字符数伪装成精确字节数。
- [x] 规定审批超时、非交互宿主和安全 gate 异常的 fail-closed 行为。
- [x] 为旧 Cloud policy 缺少新字段时的默认值写兼容性测试。

**Acceptance:** 老 policy cache 可继续加载；本地默认 policy 在无 Cloud 时能对规则 14–19 给出确定决策或明确的 `partial/observe_only/unsupported`，不会因字段缺失输出误导性的 `allow`。

### Task 2：实现静态 PII 规则 1–10

**Files:**

- Create: `src/scanner/rules/privacy.ts`
- Modify: `src/scanner/rules/index.ts`
- Modify: `src/types/scanner.ts`
- Modify: `src/scanner/index.ts`
- Test: `src/tests/scanner.test.ts`
- Test fixtures: `src/tests/fixtures/privacy/`

- [x] 增加 10 个 `PII_*` RiskTag，并为每个 tag 注册规则。
- [x] 实现中国身份证 mod-11-2、银行卡 Luhn、IBAN mod-97 等 validator。
- [x] 所有普通 PII 使用“字段名 + 值”双要素；裸数字不得命中。
- [x] 实现测试卡、`example.com`、faker/test/noreply 特征排除。
- [x] 对 `test`、`fixtures`、`examples`、`mock` 路径降一级，而不是完全忽略。
- [x] `PII_CONTACT_DUMP` 至少 20 条手机号或 email 才命中。
- [x] `PII_HARDCODED_DATASET` 至少三类 PII 在同一结构共现才命中。
- [x] 更新 scanner summary，使隐私命中不再落入通用安全描述。

**Acceptance:** 每条规则至少有真阳性、误报抑制和路径降级测试；测试证据不包含完整 PII 原值。

### Task 3：实现端点分级和静态中转站规则 11–13

**Files:**

- Create: `src/runtime/llm-endpoints.ts`
- Create: `src/scanner/rules/llm-relay.ts`
- Modify: `src/scanner/rules/index.ts`
- Modify: `src/types/scanner.ts`
- Test: `src/tests/llm-endpoints.test.ts`
- Test: `src/tests/scanner.test.ts`

- [x] 实现 URL 规范化：大小写、默认端口、IPv4/IPv6、punycode、尾点、userinfo、重定向目标。
- [x] 固定分级优先级：先识别 loopback/T0，再判断普通 IP 字面量为 T4，避免 `127.0.0.1` 和 `::1` 被误封。
- [x] 建立 T0–T4 官方默认列表，并允许 policy 添加私有可信端点。
- [x] 实现 `LLM_ENDPOINT_OVERRIDE`，覆盖 OpenAI、Anthropic、Gemini 等常见 base URL 变量和 agent 配置格式。
- [x] 实现 `RELAY_KEY_FORWARDING`，要求 credential 读取与第三方网络目标在局部窗口内共现。
- [x] 实现 `RELAY_INSTALL_SCRIPT`，覆盖 shell rc 和 OpenClaw、DSH、Hermes、Codex、Claude Code 的模型配置文件。
- [x] 对 host suffix 做标签边界匹配，防止 `api.openai.com.attacker.test` 被误判为官方域名。

**Acceptance:** T0–T4 表驱动测试通过；伪造官方后缀、IP、短链和自定义端口均有负向或高危测试。

### Task 4：实现本地运行时隐私 evaluator 和脱敏

**Files:**

- Create: `src/runtime/privacy.ts`
- Modify: `src/runtime/evaluator.ts`
- Modify: `src/runtime/redaction.ts`
- Modify: `src/runtime/audit.ts`
- Modify: `src/runtime/protect.ts`
- Test: `src/tests/runtime-cloud.test.ts`
- Create: `src/tests/runtime-privacy.test.ts`

- [x] 在 `customPolicyReasons` 中生成规则 14–19 的 reason。
- [x] 在 `policyDecisionFor` 中显式映射所有新 reason，禁止依赖 fallback `warn`。
- [x] 确保 PII reason severity 至少为 `medium`，避免被低于 20 分的 auto-allow 静默放行。
- [x] 将 PII 检测拆成可复用的纯本地函数，静态 scanner 和运行时 body scanner 共用 validator。
- [x] evidence 只输出 PII 类型、计数和掩码；禁止保留完整命中值。
- [x] 扩展 `REDACTION_PATTERNS`，覆盖所有新增 PII 类型并保留 credential 兜底脱敏。
- [x] 对 body、附件和文件路径分别计数，避免单纯依赖 `bodyPreview` 截断结果。
- [x] 对 request/response 用同一 `requestId` 关联审计，但不把原始 payload 写盘。

**Acceptance:** 六条运行时规则均有事实齐全和事实缺失测试，覆盖 allow/warn/approval/block 以及 `partial/observe_only/unsupported`；本地 audit 和模拟 Cloud payload 中搜索不到测试 PII/API key 原值。

### Task 5：适配 DSH 现有 `llm/stream` 生命周期

**AgentGuard files:**

- Modify: `src/dsh/plugin.ts`
- Create: `src/dsh/llm-privacy.ts`
- Modify: `dsh.cordis.patch.yml`
- Test: `src/tests/dsh-plugin.test.ts`
- Create: `src/tests/dsh-llm-privacy.test.ts`
- Extend: `scripts/test-dsh-plugin-e2e.mjs`

DSH 源码只作为生命周期契约的只读评估依据，不产生任何修改、patch 或发布要求。

- [x] 在 AgentGuard DSH 插件中注册 `llm/stream` waterfall listener。
- [x] 声明 DSH capability：`modelRequest=blocking`；最终 destination、credential facts、精确 payload bytes 为不可用；辅助调用是否覆盖取决于是否经过 `ctx.llm.stream()`。
- [x] 从 `GenerateOptions` 读取实际可用的 system、messages、tools、images、provider 和 model，构造本地 `llm_request`；不存在的 purpose、attempt、endpoint 字段保持 `unknown`。
- [x] 在调用 `next()` 前执行 AgentGuard；`block` 返回规范错误 stream，`require_approval` 走 DSH 原生 `approval/request`。
- [x] 包装下游 stream，检测可见的 tool call、命令和包名；只有 wrapper 能在 DSH 消费前可靠短路时才将 response capability 标为 `blocking`，否则标为 `observe_only`。
- [x] 用集成测试验证 conversation、compaction、session title 等已知消费者是否经过 `ctx.llm.stream()`；未经过者记录为 adapter capability 缺口，而不是修改 DSH。
- [x] 对规则 14、18、19 输出缺失的 transport facts；禁止根据 provider 名称猜测实际 endpoint 或 key 是否存在。

**Acceptance:** 所有经过现有 `llm/stream` 的调用都能在语义请求阶段得到一致决策；最终 URL、认证事实、精确字节数、adapter 内 retry/fallback 和任何直接 SDK 调用明确标为 `unsupported`，不宣称 DSH 已完整覆盖规则 14–19。

### Task 6：适配 Hermes 现有插件生命周期

**AgentGuard files:**

- Modify: `plugins/hermes/plugin.py`
- Modify: `plugins/hermes/bridge.py`
- Add tests: `plugins/hermes/tests/test_llm_request.py`
- Add tests: `plugins/hermes/tests/test_llm_response.py`
- Modify: `docs/hermes.md`

Hermes 源码只作为生命周期契约的只读评估依据，不产生任何修改、patch 或发布要求。现有能力边界如下：

- `pre_llm_call` 每个 user turn 只触发一次，不是每个模型请求。
- `pre_api_request` 虽按主循环每次 API call 触发，但返回值被忽略、异常被吞掉。
- 它只传 `request_messages`；Anthropic 的 system 和 tools 已被拆到 `api_kwargs` 其他字段。
- `call_llm()`、`async_call_llm()`、title、compression、iteration summary 和部分 trajectory 路径直接调用 provider client，绕过该 hook。
- `post_api_request` 能观察主响应，但不能阻断；`transform_llm_output` 又在整个 tool loop 结束后才触发。

- [x] 注册现有 `pre_llm_call`、`pre_api_request`、`post_api_request` 和 `pre_tool_call`，不得引用不存在的 request/response gate。
- [x] 声明 Hermes capability：主循环模型请求/响应为 `observe_only`，`pre_tool_call` 为 `blocking`；辅助模型、完整 system/tools、retry/fallback 和 transport facts 为不完整或不可用。
- [x] 将 `pre_api_request` 可见的 messages/provider/model/base URL 映射到 `llm_request`，但固定 `canBlockCurrentAction=false`；即使本地 evaluator 返回 block，也只能记录违规和警告，不能报告“已阻断”。
- [x] 将 `post_api_request` 映射到 `llm_response` observer；发现响应投毒后记录关联风险，实际工具执行仍由 `pre_tool_call` 阻断。
- [x] 保留 `pre_tool_call` 作为 endpoint 劫持和响应投毒后的最后一道执行拦截。
- [x] 不为每次大型 prompt 启动一个 Node 子进程；由 AgentGuard 提供本地常驻 daemon + Unix socket，Windows 使用 named pipe 或 loopback authenticated IPC。
- [x] IPC 只允许当前用户访问，设置请求上限、超时和 fail-closed 策略。
- [x] 对 title、compression、iteration summary、trajectory 等已知 bypass 输出 `unsupported` capability，不尝试 monkey patch Hermes 内部对象。

**Acceptance:** Hermes 主循环可见模型事件进入脱敏审计，危险本地工具在 `pre_tool_call` 被阻断；模型请求本身、辅助 LLM 调用和原始模型响应明确为 `observe_only/unsupported`，不得宣称 T3 endpoint 已在发送前阻断。

### Task 7：适配 OpenClaw 现有插件生命周期

**AgentGuard files:**

- Modify: `src/adapters/openclaw-plugin.ts`
- Modify: `src/adapters/openclaw.ts`
- Test: `src/tests/adapter.test.ts`
- Modify: `docs/openclaw.md`

OpenClaw 源码只作为生命周期契约的只读评估依据，不产生任何修改、patch 或发布要求。现有能力边界如下：

- `before_agent_run` 只在一次 agent run 前看到初始 prompt/history，不覆盖每个模型调用、工具回合和 retry。
- `before_model_resolve` 可以覆盖 provider/model，`before_prompt_build` 可以修改 prompt context，但它们不是逐模型请求的安全决策 gate。
- `llm_input` 可见 run 级 provider/model/system/prompt/history/tools，`llm_output` 可见部分响应，但两者都是 observer，不能承担同步阻断。
- `model_call_started`/`model_call_ended` 可提供 call id、provider/model 和部分字节统计，但偏诊断且没有最终 endpoint/credential。
- provider `wrapStreamFn` 的确位于每次调用附近，但当前由 provider owner 使用，不是所有插件都能注册的全局安全链。

- [x] 注册现有 `before_agent_run` 作为 run 级 blocking gate，扫描本轮 prompt、加载的 history 和 system prompt；明确它不是每次模型调用 gate。
- [x] 注册现有 `llm_input`/`llm_output` 和 `model_call_started`/`model_call_ended` 作为 observer，并通过 runId/callId 尽可能关联审计。
- [x] 只记录 Hook 实际提供的 provider/model、语义内容和字节统计；endpoint、credential、retry/fallback 无事件证据时保持 `unknown`。
- [x] 注册 `before_tool_call`/`after_tool_call`，阻止危险命令、敏感文件读取、endpoint 配置修改和响应投毒后的执行动作。
- [x] 对 `before_tool_call` 的 `requireApproval` 使用 OpenClaw 已有审批返回结构；`before_agent_run` 只有 pass/block，不伪造 approval。
- [x] 不注册或占用 provider 私有 `wrapStreamFn`，不 monkey patch provider runtime。
- [x] 对主 run、第二轮 tool loop、compaction、retry/fallback 和辅助调用分别做黑盒覆盖测试，未触发公开 Hook 的路径记录为 `unsupported`。

**Acceptance:** 初始 run 和受支持工具调用可以被现有 gate 阻断，公开 LLM/diagnostic observer 进入脱敏审计；逐模型请求、最终 endpoint/credential、内部 retry/fallback 和未触发公开 Hook 的辅助调用明确为 `observe_only/unsupported`。

### Task 8：使用 Codex 原生 Hook 落地有限覆盖

**AgentGuard files:**

- Modify: `src/installers.ts`
- Modify: `src/runtime/protect.ts`
- Modify: `docs/codex.md`
- Test: `src/tests/installers.test.ts`
- Add tests: `src/tests/codex-hooks.test.ts`

**Codex files generated into the target project:**

- Create or merge: `.codex/hooks.json`
- Create: `.codex/hooks/agentguard-user-prompt.sh`
- Create: `.codex/hooks/agentguard-pre-tool.sh`
- Create: `.codex/hooks/agentguard-post-tool.sh`

#### 8.1 修正现有集成方式

当前 `agentguard init --agent codex` 生成 `.codex/skills/agentguard/SKILL.md` 和 `.codex/agentguard-hook.json`，后者不是 Codex 官方 Hook 的加载文件；Skill 也依赖模型自觉调用 `agentguard protect`，不能作为强制执行机制。

- [x] 改为生成或安全合并官方 `<repo>/.codex/hooks.json`；不要覆盖用户已有 Hook。
- [x] 保留 Skill 作为使用说明，但不得把 Skill 描述成安全边界。
- [x] 安装后提示用户通过 `/hooks` 审查并信任新增 Hook；在未信任前，Codex 会跳过项目 Hook。
- [x] 记录受支持的最低 Codex 版本，并在初始化时检查 `hooks` feature 是否可用。
- [x] Hook command 使用 Git 根目录或安装时解析出的稳定绝对路径，不能假设 Codex 总从仓库根目录启动。

#### 8.2 Hook 映射

- [x] `UserPromptSubmit`：将 `prompt` 映射成只在本机处理的 `user_prompt`/隐私检查事件；`block` 输出 `{ "decision": "block", "reason": "<脱敏原因>" }` 或使用退出码 `2`；`warn` 只返回简短 `systemMessage`。
- [x] `PreToolUse`：按 `tool_name` 和 `tool_input` 映射为 `shell`、`file_read`、`file_write`、`network`、`mcp_tool`；AgentGuard `block` 和不能原生审批的 `require_approval` 都返回官方 `permissionDecision: "deny"`。
- [x] `PostToolUse`：扫描敏感工具结果；命中阻断规则时阻止原始结果继续交给模型，但明确它不能撤销已产生的副作用。
- [x] `PermissionRequest`：只处理 Codex 已经触发的审批。AgentGuard 可以 deny 或 allow，但不能使用它为普通动作主动发起审批。
- [x] `PreCompact`/`PostCompact`：只记录脱敏元数据和策略状态，不把 transcript 或 compact 内容送到 Cloud。
- [x] 所有安全 Hook 必须同步运行；禁止设置 `async: true`。

#### 8.3 决策与失败语义

- [x] 删除或停止输出 Codex 专用 `{ "decision": "confirm" }`；这不是当前官方 `PreToolUse` 决策格式。
- [x] 不输出 `permissionDecision: "ask"`。当前 Codex 会把它视为不受支持的字段、报告 Hook 失败并继续工具调用。
- [x] `require_approval` 首版采取 fail-closed：拒绝当前工具调用，返回 action id 和脱敏说明，要求用户显式批准后重试；审批命令本身仍需防止 Agent 自行执行。
- [x] AgentGuard wrapper 对可捕获的 JSON 解析失败或 evaluator 错误以退出码 `2` 拒绝；宿主强制终止 Hook、进程未能返回退出码等情况按 Codex 实际语义记录，不得笼统宣称超时 fail-closed。
- [x] 不读取或解析 `transcript_path` 来重建最终模型请求；官方明确该记录格式不是稳定 Hook 接口，且即使读取也不能获得可靠的发送前阻断点。
- [x] Hook stdout/stderr 只返回规则 ID、风险级别、action id 和脱敏原因，避免 Codex 的长输出溢写机制把敏感内容落盘。

#### 8.4 Codex 专属验收

- [x] 用户 prompt 命中 API key、证件号等策略时，模型请求开始前被 `UserPromptSubmit` 拒绝。
- [x] Bash、`apply_patch`、MCP 和已确认支持的本地函数工具均经过 `PreToolUse`；危险调用在工具执行前被拒绝。
- [x] endpoint 配置修改、敏感文件批量读取和显式 `curl` 外发有正向与误报抑制测试。
- [x] `PostToolUse` 能阻止敏感结果继续进入下一次模型请求，但测试明确验证原工具副作用不会被误报为已撤销。
- [x] 已有 `.codex/hooks.json` 被结构化合并且重复执行 init 幂等。
- [x] 未信任 Hook、托管 WebSearch、专用工具绕过和 Codex 内部模型调用被列为已知缺口，不计入“受保护”统计。
- [x] 规则 14–19 的报告区分 `full`、`partial`、`observe_only`、`unsupported`，不得把 prompt/tool 命中率包装成模型 API 流量覆盖率。

**Acceptance:** Codex 的用户输入和受支持本地工具路径可以被官方同步 Hook 检查并拒绝；文档、CLI 状态和审计明确显示其有限覆盖，不宣称能够观察或阻断最终模型 endpoint、credential、完整 payload 或原始模型响应。

### Task 9：扩展 Claude Code 原生 Hook 适配

**AgentGuard files:**

- Modify: `src/installers.ts`
- Modify: `src/adapters/types.ts`
- Modify: `src/adapters/claude-code.ts`
- Modify: `src/runtime/types.ts`
- Modify: `src/runtime/protect.ts`
- Modify: `docs/claude-code.md`
- Modify: `src/tests/installer.test.ts`
- Modify: `src/tests/adapter.test.ts`
- Modify: `src/tests/integration.test.ts`
- Add tests: `src/tests/claude-code-lifecycle.test.ts`

**Claude Code files generated or merged into the target project:**

- Create or merge: `.claude/settings.local.json`
- Create/update: `.claude/hooks/agentguard-protect.sh`
- Optional Windows equivalent: `.claude/hooks/agentguard-protect.ps1`

Claude Code 源码和 CLI 不属于修改范围。AgentGuard 只安装官方 settings Hook，并根据宿主版本声明实际 capability。

#### 9.1 安装器与版本能力

- [x] 将 `.claude/settings.local.json` 改为结构化、幂等合并；保留用户已有 settings 和同事件其他 Hook，禁止 `--force` 整体覆盖未知配置。
- [x] Hook command 使用 `${CLAUDE_PROJECT_DIR}` 或稳定绝对路径，避免 `/cd` 或从子目录启动后相对路径失效。
- [x] 记录 `claude --version`；对有明确最低版本的事件做 version gate，例如 `PreModelSwitch`/`PostModelSwitch` 只在 `2.1.251+` 注册。
- [x] 安装后输出实际启用事件、未满足版本要求的事件和覆盖矩阵；CLI 不存在时仍可生成模板，但状态必须标为 `unverified`。
- [x] 默认只生成本地同步 `type: "command"` Hook；禁止把原始 prompt/tool result 发送到 `http`、`prompt`、`agent` 或外部 MCP Hook。

#### 9.2 生命周期映射

- [x] `UserPromptSubmit`：映射为 `user_prompt`，扫描当前 prompt；`block` 返回顶层 `{ "decision": "block", "reason": "<脱敏原因>" }`。
- [x] `UserPromptExpansion`：映射为 `prompt_expansion`，根据 `expansion_type`、`command_name`、`command_args` 和 `command_source` 阻止不受信任的 slash/custom command、skill 或 MCP prompt 展开；不得声称扫描了 Hook 未提供的展开后完整正文。
- [x] `PreToolUse`：统一处理 Bash/PowerShell、Read、Write/Edit、Web、MCP 和未知工具；按 `tool_name`/`tool_input` 动态映射，避免只依赖安装器写死的少量 matcher。
- [x] `@file` 不触发 `PreToolUse`：仅当 AgentGuard policy 明确列出敏感路径时，幂等合并对应的精确 Claude Code `Read` deny 权限规则；未配置的 `@file` 路径标记为 `unsupported`，禁止生成覆盖整个 workspace 的宽泛 deny。
- [x] `require_approval` 继续使用 Claude Code 原生 `permissionDecision: "ask"`；非交互场景和无审批 UI 时按 Claude Code 实际行为测试并记录。
- [x] `PostToolUse`：扫描 `tool_response`；对有稳定 schema 的内置/MCP 工具使用 `updatedToolOutput` 替换为脱敏结果。顶层 `decision: "block"` 不能替代脱敏，因为 Claude 仍会看到原始输出。
- [x] `PostToolUseFailure`：只映射失败类型、脱敏错误摘要和 coverage；该事件没有输出替换或阻断能力，不得把附加 context 记为脱敏成功。
- [x] `PostToolBatch`：映射为 `post_tool_batch`，对模型即将看到的 serialized results 计算本批 PII、文件路径数和字节数；命中阻断策略时在下一模型调用前结束 agentic loop。
- [x] `ConfigChange`：读取 `source`/`file_path`，扫描新配置是否加入未知 endpoint、key forwarding 或危险 permission；对可阻断来源拒绝当前 session 应用，并明确不会自动回滚磁盘内容。
- [x] `PreModelSwitch`：读取 `from_model`、`to_model`、`source` 和 `context_tokens`；阻止不允许的显式 model switch 或对大上下文重发请求审批，但不把 model id 当作 endpoint。
- [x] `PostModelSwitch`：只审计自动/session model 变化；未触发事件的一次性 fallback 标为 `unsupported`。
- [x] `MessageDisplay` 和 `Stop`：用于响应文本观察及可选的显示层脱敏；固定 `canBlockCurrentAction=false` 或 `display_only`，不得声称修改了 transcript、模型响应或已发生的工具行为。
- [x] `InstructionsLoaded`、`PreCompact`、`PostCompact`：只记录脱敏元数据和 coverage，不解析不稳定 transcript 来伪造最终模型 payload。

#### 9.3 决策、性能和失败语义

- [x] 对可捕获的 adapter/JSON/evaluator 错误，blocking Hook wrapper 使用退出码 `2`；observer 错误只记录 `SECURITY_GATE_ERROR`。
- [x] Claude Code 的 `UserPromptSubmit`、`PreToolUse` 等 command Hook 超时/失败可能继续原动作；将该行为标为 host fail-open 缺口，配置合理超时并监控，不能在文档中宣称 timeout fail-closed。
- [x] `PostToolUse.updatedToolOutput` 只对有 fixture 验证的输出 schema 启用；未知 schema 不做破坏性猜测，转由 `PostToolBatch` 阻止下一次模型调用并标为 `partial`。
- [x] 并行 `PreToolUse` Hook 不共享可靠的批次前状态；批量读取阈值在 `PostToolBatch` 聚合，审计同时标明“读取已发生、当前模型续接已阻止”。旧结果仍可能保留在 transcript，恢复会话后的再次发送必须标为未保证。
- [x] Hook 输出只含规则 ID、掩码、计数和 action id；不把原始 PII、API key 或大型 tool result 写入 stdout/stderr、audit 或 Cloud。

#### 9.4 Claude Code 专属验收

- [x] 用户 prompt 命中 PII/API key 时，在 Claude 处理前被拒绝，且不会进入本轮模型处理。
- [x] direct slash/custom command、skill 和 MCP prompt 的展开路径触发 `UserPromptExpansion`；不受信任命令按元数据被阻止，测试不假设 Hook 可见展开后正文。
- [x] Bash、PowerShell、Read、Write/Edit、Web、MCP 和未知工具均有 matcher/动态映射测试；危险调用在执行前 deny/ask。
- [x] `@sensitive-file` 在 policy 已配置精确路径时由合并后的 `Read` deny 规则阻止；未配置路径的 fixture 明确报告 `unsupported`，不计入 PreToolUse 保护率。
- [x] 已验证 schema 的敏感 tool result 被 `updatedToolOutput` 替换，下一模型调用 fixture 中不再包含原值。
- [x] 失败工具的 stderr/异常含 PII 时，fixture 验证该目标版本的 `PostToolBatch.tool_response` 是否包含失败结果并能阻止下一模型调用；若不包含，则该路径报告 `unsupported`。
- [x] 并行读取多个敏感文件时，`PostToolBatch` 在下一模型调用前阻断，并报告本批文件数和脱敏字节数。
- [x] endpoint settings 通过 Agent 工具修改时由 `PreToolUse` 拦截；外部修改时 `ConfigChange` 阻止当前 session 应用，同时明确磁盘文件未回滚。
- [x] 显式 model switch 能 deny/ask；自动 fallback 只审计或标为 `unsupported`，不会误报为已阻断。
- [x] `MessageDisplay` 替换只计为 `display_only`；原 transcript 和 Stop 内容保持不受其影响的测试证据。
- [x] 安装器对已有 settings 做幂等合并；从子目录启动和 `/cd` 后 Hook 仍能找到 AgentGuard 脚本。
- [x] 每个 Hook fixture 同时断言 policy decision、实际 enforcement status、coverage level 和 missing facts。

**Acceptance:** Claude Code 的当前 prompt、命令展开元数据、受支持工具、已验证 tool output 和本批 tool results 可以由原生同步 Hook 检查、阻断或脱敏；配置和显式 model switch 可获得部分保护。`@file` 仅在有精确 `Read` deny 策略时获得路径级补偿。最终模型 endpoint、credential、完整 payload、自动/临时 fallback、未配置的 `@file` 注入和原始模型响应仍明确标为 `partial/unsupported`。

### Task 10：AgentGuard Cloud 配套改造

Cloud 不是本地执行前置条件，但需要支持集中策略和审计。

**Cloud policy API:**

- [ ] 支持 `network.untrustedLlmEndpoint` 和 `network.trustedLlmEndpoints`。
- [ ] 支持 `privacy.piiEgressTrusted`、`privacy.piiEgressUntrusted` 和 `privacy.enabledCategories`。
- [ ] policy schema 增加版本和向后兼容默认值，旧客户端忽略新字段，新客户端能消费旧 policy。
- [ ] trusted endpoint 的组织配置必须经过域名规范化，且不能覆盖全局 blocked domain。

**Cloud audit API/UI:**

- [ ] 接收 `agentHost`、`lifecycleStage`、`coverageLevel`、`enforcementStatus`、`canBlockCurrentAction`、`missingFacts`，以及 Hook 实际提供的 endpoint tier、provider、model、purpose、payload size、PII 类别/数量、credential kind、reason、decision 和 requestId。
- [ ] 服务端再次拒绝或脱敏疑似 prompt、Authorization、API key 和 PII 原值。
- [ ] Dashboard 支持按宿主、覆盖级别、生命周期阶段、endpoint tier、reason code、decision 和 purpose 筛选。
- [ ] 只在宿主事件确实提供 retry/fallback 关联时展示，不展示原始 prompt/response，也不使用默认值填充未知事实。
- [ ] 为规则 14–19 增加趋势和告警，但不允许通过审计接口反推出具体个人数据。

**Acceptance:** 断开 Cloud 后本地保护不变；Cloud 抓包/测试 fixture 中没有 prompt、key 或完整 PII；Dashboard 能区分已阻断、仅观察、部分覆盖和不支持。

### Task 11：跨宿主测试、发布和迁移

**AgentGuard verification:**

```bash
npm run build
npm test
npm run test:dsh-package
python -m pytest plugins/hermes/tests -q
```

不运行或要求修改后的 DSH、Hermes、OpenClaw、Codex、Claude Code 上游测试。宿主源码只读分析和官方契约可以指导 fixtures；所有实现验证都在 AgentGuard 仓库及其安装产物中完成。

- [ ] 建立统一 evaluator conformance fixture：相同事实输入必须得到相同 reason、risk score 和 decision。
- [ ] 为五个 adapter 分别建立 lifecycle fixture，验证事件字段、`canBlockCurrentAction`、capability 和 `missingFacts` 映射。
- [ ] 建立本地、官方远端、已知聚合商、未知中转、高危端点五类 evaluator fixture；只有 adapter 能提供 endpoint 时才把它作为宿主集成覆盖。
- [ ] 对普通请求、tool-loop 第二次请求、retry、fallback、辅助模型、流式响应、embedding 和 file upload 分别断言 `full/partial/observe_only/unsupported`，而不是假设都可拦截。
- [ ] 验证在 destination 与 credential facts 都可见时，未知 endpoint + key 即使 payload 无 PII 仍然 `block`；任一事实不可见时返回 `unsupported`，而不是 `allow`。
- [ ] 验证 PII 规则失败或 Cloud 离线不会让本地 `block` 变成 allow。
- [ ] 先用 `observe_only` feature flag 收集误报，再逐 adapter 只对标记为 `blocking` 的生命周期启用 protect。
- [ ] 发布说明明确：插件无法约束恶意进程内代码直接开 socket；高威胁场景需要容器/OS 网络策略。

---

## 4. 跨宿主验收矩阵

在“不修改宿主源码、不使用代理”的约束下，没有一个宿主能完整提供规则 14–19 所需的全部 transport facts。验收必须按实际能力进行：

| 规则 | DSH | Hermes | OpenClaw | Codex | Claude Code |
| --- | --- | --- | --- | --- | --- |
| 14 `UNTRUSTED_LLM_ENDPOINT` | 最终 endpoint 不可见：`unsupported`；配置/显式网络工具可做预防 | 主循环 base URL 可能可见但不可阻断：`observe_only/partial`；辅助调用 `unsupported` | 最终 endpoint 不可见：`unsupported`；配置修改可拦截 | 模型 endpoint 不可见：`unsupported`；配置修改可拦截 | 模型 endpoint 不可见：`unsupported`；`PreToolUse`/`ConfigChange` 配置保护为 `partial` |
| 15 `PII_EGRESS` | 对 `llm/stream` 可见语义 payload 可发送前阻断：`partial` | 主循环可见 messages 仅审计：`observe_only/partial` | 初始 run 可阻断，`llm_input` 仅观察：`partial` | 用户 prompt 与工具结果可阻断：`partial` | prompt 可阻断，tool output 可替换，batch 可在下次模型调用前停止：`partial` |
| 16 `LLM_ENDPOINT_HIJACK` | 受支持 tool/file hook 可阻断：`partial` | `pre_tool_call` 可阻断：`partial` | `before_tool_call` 可阻断并审批：`partial` | `PreToolUse` 可阻断：`partial` | `PreToolUse`、`ConfigChange`、`PreModelSwitch` 可阻断部分劫持：`partial` |
| 17 `RELAY_RESPONSE_TAMPERING` | stream wrapper 能覆盖的响应及最终工具调用：`partial` | 响应仅观察，`pre_tool_call` 阻断执行：`partial` | `llm_output` 观察，`before_tool_call` 阻断执行：`partial` | 没有原始响应 Hook，`PreToolUse` 阻断执行：`partial` | 原始响应完整性 `unsupported`；危险 tool 执行由 `PreToolUse` 阻断：`partial` |
| 18 `LLM_KEY_TO_UNKNOWN_HOST` | 模型 transport credential/destination 组合不可见：`unsupported` | 模型 transport 不可阻断且事实不完整：`unsupported` | credential/destination 不可见：`unsupported` | credential/destination 不可见：`unsupported` | 内部模型 transport 不可见：`unsupported`；显式工具外发可拦截 |
| 19 `WORKSPACE_BULK_EGRESS` | 可检查语义 payload，但缺精确最终字节数：`partial` | 只检查可见 messages/tool actions：`observe_only/partial` | run/tool/diagnostic 字段可启发式检查：`partial` | prompt 和本地工具可启发式检查：`partial` | `PostToolBatch` 可聚合本批结果，但缺最终 request bytes/history：`partial` |

共同验收不变量：

| 场景 | 预期 |
| --- | --- |
| Hook 提供完整 endpoint、credential 和 payload facts | 按 T0–T4 与规则策略给出 allow/warn/approval/block |
| 某条规则必需事实缺失 | 返回 `partial` 或 `unsupported`，不得返回“检查通过” |
| observer 发现本应 block 的风险 | 记录 `would_block`/风险原因；不得声称请求已被阻断 |
| 危险响应最终产生受支持工具调用 | blocking pre-tool 在执行前拒绝或审批 |
| tool 修改模型 base URL 到 T3/T4 | 在现有 blocking tool hook 中拒绝或审批；不承诺下一模型请求能再次复核 |
| retry/fallback 没有独立事件 | 标记 `retryAndFallback=false`，不生成虚假的二次检查审计 |
| title/compaction/vision 没有经过公开 Hook | 标记 `unsupported`，不纳入保护率分母或成功数 |
| Cloud 超时或断网 | 已支持的本地 blocking 行为不失效 |
| blocking hook 的审批界面不可用 | `require_approval` 按 deny 处理 |

---

## 5. 仍需产品/架构明确的细节及推荐默认值

这些问题不阻塞前四个 AgentGuard 基础任务，但必须在任一 adapter 对其 blocking 生命周期启用 protect 前冻结。

| 问题 | 推荐默认值 |
| --- | --- |
| T1/T2 的 PII 是否只 warn | 保持原需求：`warn`；组织策略可升级，不允许低于本地强制下限 |
| 用户能否批准 key 发往 T3 | 不能；规则 18 固定 `block` |
| T3 响应投毒是否整体缓冲 | 仅 DSH stream wrapper 在现有接口允许时缓冲；其他宿主依赖 response observer + blocking pre-tool，不声称阻断正文 |
| bulk threshold | 默认 `(payloadBytes >= 1 MiB 且 filePathCount >= 20) 或 attachmentBytes >= 5 MiB`；三个阈值均由 policy 可调 |
| trusted private endpoint 的配置权 | 个人部署可本地配置；组织托管设备由 Cloud policy 管理 |
| approval 的有效期 | 默认仅当前可阻断 action；没有 request gate 时不得创建“模型请求已批准”的误导性记录 |
| hook 故障 | AgentGuard 可捕获的 blocking-hook 错误 fail-closed；宿主超时/崩溃语义按 capability 记录；observer 失败只记录 `SECURITY_GATE_ERROR` 和覆盖缺口 |
| Claude Code Hook 超时 | 官方 command Hook（包括 `UserPromptSubmit`、`PreToolUse`）超时/失败可能继续原动作；标为 host fail-open，Dashboard/CLI 必须显式告警，不能用 AgentGuard 配置掩盖 |
| Claude Code tool output 脱敏 | 仅对有 schema fixture 的工具启用 `updatedToolOutput`；未知工具由 `PostToolBatch` 阻止续接并标为 `partial` |
| Claude Code `@file` 注入 | 只对 policy 明确配置的敏感路径合并精确 `Read` deny；其余路径标为 `unsupported`，不以宽泛 deny 代替最终 payload 检查 |
| prompt 是否传 AgentGuard 子进程 | 不使用一次一进程；只通过受限本机 IPC 交给常驻 evaluator |
| embeddings/file upload | 对公开生命周期覆盖的宿主执行测试；其余标记 `unsupported`，而不是假装已覆盖 |

---

## 6. 发布里程碑

1. **M0：规则基础**——规则 1–13、endpoint tier、PII 脱敏和 policy schema 完成。
2. **M1：本地运行时内核**——规则 14–19、capability model 和缺失事实语义可对标准化 fixture 正确决策，Cloud 非必需。
3. **M2：DSH adapter**——用现有 `llm/stream` 实现可阻断的语义请求保护，transport 缺口显式降级。
4. **M3：Claude Code adapter**——扩展现有 PreToolUse 集成，增加 prompt、prompt expansion、tool output、batch、config 和 model-switch 生命周期，并显式处理 `@file` 绕过边界。
5. **M4：Hermes adapter**——接入现有观察型 API hooks 和 blocking `pre_tool_call`，辅助调用缺口显式降级。
6. **M5：OpenClaw adapter**——接入现有 run gate、LLM observers、diagnostic events 和 tool gate，不要求新增上游 Hook。
7. **M6：Codex 原生 Hook**——用官方 Hook 完成用户 prompt 与本地工具层保护，并在产品状态中标注规则 14–19 的部分覆盖/不支持项。
8. **M7：Cloud 管理面**——策略下发、脱敏审计、Dashboard 和组织级 endpoint 管理。
9. **M8：能力分级发布**——完成 evaluator conformance、adapter fixture、误报观测和回滚演练后，只对各宿主已有 blocking 生命周期开启 protect。

每个里程碑均可独立发布和回滚。全部里程碑只修改 AgentGuard；宿主升级导致生命周期变化时，只更新相应 adapter 和 capability 声明。

---

## 7. 源码评估依据

评估日期：2026-09-16。

以下宿主源码仅用于只读确认公开生命周期、事件字段和调用覆盖，不属于实施修改范围。

- AgentGuard：commit `14370b767a7f1847459fcfdaafcaaa841126112e`。
- DSH：commit `b150a551b8d465e31e418e1b2eaf5e79bbb7d28e`，版本 `0.1.1-rc.2`。
- Hermes：commit `64202200a6043b685750e16107067971446f8818`，版本 `0.15.1`。
- OpenClaw：本地源码版本 `2026.5.26`；本地目录没有 Git metadata，因此未记录 commit SHA。
- Codex：本机 `codex-cli 0.148.0-alpha.15`；安装包只包含可执行文件，未获得完整源码 commit，因此使用本机 CLI/schema 和官方公开 Hook 契约评估。
- Claude Code：本机未安装 `claude` CLI，未进行版本/运行时实测；使用 2026-09-16 抓取的官方 Hook/permissions 契约评估，实施前需在目标最低版本验证。

关键证据：

- OpenClaw `src/plugins/hooks.ts`、`src/plugins/hook-types.ts`、`src/plugins/hook-before-agent-start.types.ts`：现有 `before_agent_run` gate、prompt/model hooks、观察型 LLM hooks、model-call diagnostics 和 tool gates。
- OpenClaw `src/agents/pi-embedded-runner/run/attempt.ts`：`llm_input/output` 及 stream wrapper 链的实际接线位置。
- DSH `packages/llm/llm/src/index.ts`：`llm/stream` waterfall 的统一调用入口。
- DSH `packages/compaction/compaction-basic/README.md`：compaction 也通过 `ctx.llm.stream()`，可被同一 hook 拦截。
- Hermes `agent/conversation_loop.py`：主循环的 `pre_api_request`/`post_api_request`。
- Hermes `agent/auxiliary_client.py`：辅助模型调用的直接 SDK 路径。
- Hermes `hermes_cli/plugins.py`：`pre_api_request`/`post_api_request` 的返回值不影响模型请求执行。
- Hermes `SECURITY.md`：OS 级隔离是对抗恶意 LLM 的唯一正式安全边界。
- Codex [Hooks 官方文档](https://learn.chatgpt.com/zh-Hans/docs/hooks)：生命周期事件、信任模型、tool hook 覆盖范围和决策格式；官方文档同时明确工具 Hook 不是完整强制执行边界。
- AgentGuard `src/installers.ts`：现有 Codex 初始化只生成 Skill 和非官方 `.codex/agentguard-hook.json` 模板。
- AgentGuard `src/runtime/protect.ts`：现有 Codex `confirm` 输出需要改为官方 Hook 决策，并对无法原生发起审批的场景 fail-closed。
- Claude Code [Hooks reference](https://code.claude.com/docs/en/hooks)：`UserPromptSubmit`、`UserPromptExpansion`、成功/失败 tool hooks、`PostToolBatch`、`ConfigChange`、model-switch、display/stop 事件、`@file` 绕过及其阻断/改写语义。
- Claude Code [Permissions](https://code.claude.com/docs/en/permissions)：`PreToolUse` 在权限提示前运行、deny/ask/allow 的优先级和工具阻断边界。
- AgentGuard `src/installers.ts`、`src/adapters/claude-code.ts`、`src/runtime/protect.ts`：当前 Claude Code 仅安装 PreToolUse，且 adapter/installer 尚未覆盖新的 prompt、prompt-expansion、batch、config、model-switch 和 tool-output rewrite 生命周期。

## 8. 完成定义

在当前约束下，完成定义是“AgentGuard 侧兼容和能力分级保护已实现”，不能表述为“五个 Agent 的真实模型 API 流量均已完整保护”。只有同时满足以下条件才能宣称完成：

- 所有代码和安装产物修改都位于 AgentGuard；没有宿主 patch、fork、monkey patch 或上游发布依赖。
- 规则 1–19 均已进入 AgentGuard 类型、scanner/evaluator、policy mapping、脱敏和测试。
- 每个 adapter 静态声明生命周期 capability，并为每次事件输出 `lifecycleStage`、`canBlockCurrentAction`、`coverageLevel` 和 `missingFacts`。
- 相同事实输入经过统一 evaluator 产生相同 reason、risk score 和 decision；不同宿主只因可见事实和阻断能力不同而降级。
- DSH 只对经过现有 `llm/stream` 的语义请求声明 blocking；最终 endpoint、credential、精确 payload bytes、内部 retry/fallback 和绕过 service 的调用明确为缺口。
- Hermes 的模型 API hooks 明确标为 `observe_only`，辅助模型调用明确标为不完整；`pre_tool_call` 对受支持危险执行提供实际阻断。
- OpenClaw 只对 `before_agent_run` 和 `before_tool_call` 等现有 gate 声明 blocking；LLM hooks/diagnostics 标为 observer，最终 transport facts保持 unknown。
- Codex 的 `UserPromptSubmit`、`PreToolUse`、`PermissionRequest`、`PostToolUse` 使用官方配置和返回协议；模型 transport 标为 unsupported，且不使用不受支持的 `permissionDecision: "ask"`。
- Claude Code 的 prompt/prompt-expansion/tool/output/batch/config/model-switch Hook 使用官方返回协议；`updatedToolOutput` 只对验证过的 schema 启用，`MessageDisplay` 只计为 display-only，`@file` 绕过、Hook 超时 fail-open 和 model transport 缺口明确展示。
- adapter fixture 对普通调用、tool loop、辅助调用、compaction、retry/fallback、embedding 和 file upload 逐项给出实际覆盖状态；未触发公开生命周期的路径不得计为受保护。
- observer 发现高风险时只记录 `would_block`，不得生成“已阻断”审计；危险响应产生受支持工具调用时由 blocking pre-tool 提供最后一道执行保护。
- 本地离线保护可用，Cloud 从未接收原始 prompt、响应、key 或完整 PII，并能正确展示 `partial/observe_only/unsupported`。
- 文档和产品界面明确说明：在不修改宿主源码且不使用网络代理的前提下，规则 14、18 以及部分 15、17、19 无法获得完整模型 transport 级保证。

如果产品仍要求“每次模型请求在 socket 发送前检查最终 endpoint、credential 和完整 payload”，则该目标与本计划约束不相容；只能等待宿主未来公开相应 blocking lifecycle，再更新 AgentGuard adapter。
