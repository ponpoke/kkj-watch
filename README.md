# kkj-watch — 変更検知エンジン(x402レジストリ+官公需入札)

> **Change detection for machines — two free feeds + x402-paid evidence.**
> 1. **x402 registry watch**: every change in the x402 Bazaar registry (23k+ resources) — `price_changed`, `payto_changed` (receiving-address change: verify before paying), `schema_changed`, listings/delistings. Free: `/x402/changes` (filter `?type=`), `/x402/resources?q=`, `/x402/sample-change`. Paid: `/paid/x402/history/{id}` ($0.01, full SHA-256 audit trail).
> 2. **Japanese procurement watch**: corrections, deadline changes, document replacements. Free: `/events` (filter `?tag=`), `/cases?query=`, `/sample-diff`, `/agent.json`. Paid (x402): `/paid/requirements/{key}` ($0.02, cached), `/paid/analyze-now/{key}` ($0.30, fresh LLM).

## Provenance伝播レイヤー（第5類型: 使われるほど原典へ辿られる）

Hotmailのフッターは剥がせたが、本システムの**署名付きproofは価値と識別子が不可分**（識別子を消すと検証が壊れる）＝剥離不能な出所。全データ応答に `provenance`/`cite_as` ブロック（witness・canonical_url・license・署名root）を埋め込み、出所を保持する下流エージェントが原典（我々）へ機械的に辿れる終点を運ぶ。

- 帰属ライセンス: データは **CC-BY-4.0** で自由利用可（AIエージェント・モデル学習含む）、**出所の保持が条件**。無料の対価は帰属
- 恒久identity: `GET /.well-known/witness`（公開鍵・正典URL・cite_asテンプレ・公開roots）
- 付与先: `/x402/trust`・`/x402/trust-feed`・`/paid/x402/attest`・`/witness/proof`・エンティティページ(JSON-LD `license`/`citation`/`sameAs`)・バッジJSON
- 署名proof/attestationは `witness`+`attribution` を同梱し、識別子を消すと検証不成立（=非剥離）

## プログラマティックGEO: resource毎の公開リファレンスページ

`GET /x402/e/{id}` = 監視中x402エンドポイント1件ごとの公開ページ。検索エンジン/LLMに取り込まれ「is this x402 endpoint OK to pay?」の答えになる情報surfaceを、営業ゼロ・限界費用ゼロで所有する狙い。各ページはresource固有の実観測(観測verdict・価格・payTo/価格変更履歴・GETプローブ結果・スナップショット数・署名アテステーション状況)を必ず含み、JSON-LD・canonical・バッジ/ x402guardスニペット・trust-feed/attestationリンクを備える。

品質・安全の制約:
- `sitemap-x402.xml` に載せるのは **trust_scoreあり かつ 実プローブ済み** のresourceのみ(全23kは載せない)。未検証は `noindex` かつ sitemap非掲載。
- 表現は一貫して **observed trust / risk indicator / not a guarantee**。「safe」とは書かない。
- `/stats` の `usage.surfaces` で `/x402/e/` `/badge/` `/x402/claim/` `/paid/x402/attest/` `/witness/anchor` へのアクセスを面ごとに分けて計測。

## Signed existence proof(cryptographic timestamp witness)

任意データの「時刻Tに存在した」を、**中身を明かさずに**証明する層。既存の日次署名ハッシュチェーンに相乗り。**受け取るのはsha256(64桁hex)のみ・原文/契約書/ログ/個人情報/秘密情報は一切受け取らず保存しない。** 法的公証ではなく tamper-evident hash-chain anchor。

```
POST /witness/anchor  {"sha256":"<64-hex>"}   # 小さな無料枠/IP・超過はx402 $0.005
GET  /witness/proof/{sha256}                   # 署名付きMerkle包含証明(未封入はpending)
GET  /witness                                  # 説明・privacy・料金
python -m kkj.attest prove-hash <sha256>       # ローカル検証
```

スパム対策として無料枠は小さく(既定5/日/IP)、超過分はx402有料anchor。x402が廃れても「自分の行為を証明したい」という需要は残るため、Trust Indexの外側へ広げる長期の軸。

## Trust バッジ(売り手向け・#3) と Trust フィード(発見層向け・#2)

**売り手**は、自分のx402エンドポイントの観測Trustを README/サイトに貼れます(被リンク＝流入):

```markdown
[![x402 trust](https://5.75.142.199.sslip.io/badge/x402/{id}.svg)](https://5.75.142.199.sslip.io/x402/trust/{id})
```

- 貼り付けスニペット: `GET /x402/claim/{id}`（markdown/html/shields.io の3形式）
- バッジ本体: `GET /badge/x402/{id}.svg`（`.json` は shields.io endpoint 互換）
- payTo不一致は自動で赤 `payTo mismatch` 表示。署名アテステーションがあれば `✓`

**発見層(x402scan/Bazaar/explorer)** は、公開フィードを取り込んで各resource横にTrustを表示できます:

```
GET /x402/trust-feed.json     # 全件(resource, trust_score, grade, payto_status, badge_url, detail_url, attestation_root)
GET /x402/trust-feed.ndjson   # 1行1レコード(ストリーム取り込み向け)
```

いずれも「観測ベースのリスク指標であって安全保証ではない」旨を含み、日次署名rootに裏付けられます。

## x402guard — 支払い直前の安全チェックを1行で(クライアント側ミドルウェア)

エージェントに新しい習慣を求めず、**既存の支払い呼び出しをラップするだけ**で、payTo乗っ取り・価格改竄・低信頼・掲載消失を pay 前に検知して止める、ゼロ依存(標準ライブラリのみ)の安全レイヤー。`x402guard/` を参照。

```python
from x402guard import safe_pay
data = safe_pay(url, pay=lambda: my_x402_client.get(url))  # 危険ならX402Blockedで支払い前に停止
```

裏側は本リポジトリの x402 Trust Index(日次Ed25519署名ハッシュチェーンrootに裏付け)。「見に来てもらうAPI」ではなく「支払い経路に入り込む安全レイヤー」。詳細: [x402guard/README.md](x402guard/README.md)

## x402レジストリ変更検知(第2プロダクト)

x402エコシステムのBazaarレジストリ(公開discovery API)を毎時同期し、掲載リソースの**価格・受取アドレス(payTo)・スキーマ・掲載状態**の変化を検知する。エージェントが「支払う直前に、キャッシュ済みの支払い条件が変わっていないか」を$0以下のコストで確認できるレイヤー。

安全設計: 監視対象は**レジストリの掲載内容のみ**。掲載されている23k超の外部エンドポイントには一切アクセスしない(SSRF・迷惑クロール・任意URL登録のリスクを構造的に排除)。通信先は `api.cdp.coinbase.com` 固定。

```sh
python -m kkj.x402watch sync    # レジストリ同期(systemdタイマーで毎時)
python -m kkj.x402watch stats   # 蓄積状況
```

### Observed trust score, backed by daily signed hash-chain roots

Trust Index は「現在スコア」ではなく、**後から改竄できない観測記録に裏付けられた** observed trust score です。毎日、観測状態(x402_resources / snapshots / events / probes / trust)をリソース単位の canonical レコードに畳み、SHA-256葉→Merkle root→前日root連結→**Ed25519署名**し、`data/public_roots/` と GitHub公開用 `roots/` に出力します。原文・秘密情報は root に含めず、ハッシュと最小メタデータのみ。

```sh
python -m kkj.attest keygen                 # Ed25519鍵を生成(初回)
python -m kkj.attest root                   # 当日の署名付きrootを生成(systemdタイマーで日次)
python -m kkj.attest verify-root 2026-07-05 # 署名・Merkle・前日連結を検証
python -m kkj.attest prove-resource 42 2026-07-05  # 1リソースのinclusion proof
```

- 無料: `GET /x402/attestations`(最新root+検証手順)、`GET /x402/trust/{id}` に `latest_attestation_available`
- 有料(x402): `GET /paid/x402/attest/{id}` $0.02 — 観測記録・trust score・inclusion proof・daily root・署名・検証手順（第三者に見せられる改竄不能な証拠）

**Published roots are immutable.** 公開した `roots/YYYY-MM-DD.root.json` は絶対に差し替えません。早期チェックポイントの個別proofが取得不能な場合でも、以降のrootはその公開チェックポイントの `root_hash` から `previous_root` でハッシュ連鎖され続けます（later roots remain hash-chained from the public checkpoint）。本番で `--force` による公開日付rootの再生成は禁止（`KKJ_ATTEST_ALLOW_FORCE=1` はdev専用の明示override）。proofは公開rootとDB rootが整合する日付に対してのみ発行します。

**🌐 公開サービス: https://5.75.142.199.sslip.io/ (無料ティア 200リクエスト/日)**

```json
// Claude / Cursor などのMCPクライアント設定
{
  "mcpServers": {
    "kkj-watch": { "url": "https://5.75.142.199.sslip.io/mcp" }
  }
}
```

官公需(政府・自治体の入札)の**公告後に起きる全変化**を商品にするエンジン。
公告そのものは無料で誰でも見られる。見落とすと事故るのは「訂正公告・締切変更・様式差替え・質疑回答の追加」であり、kkj-watch はそれを検知して構造化する。

## 3層の提供物

| 層 | 内容 | 実装 |
|---|---|---|
| **Watch** | 案件・原典文書を巡回し、変化をイベント(NEW_CASE / FIELD_CHANGED / DOC_CHANGED)として配信。全スナップショットにSHA-256と取得時刻を付与した**取得証跡**(取得後の完全性を後から検証可能なログ) | `kkj/pipeline.py`, `kkj/doc_watch.py` |
| **Extract** | 公告本文から**確認できる範囲の**応募要件(参加資格・全省庁統一資格等級・必須認証・提出書類・締切)をJSON抽出。応募可否の最終判断は原典文書と自社の資格情報の照合で行ってください | `kkj/extractor.py` (Claude Haiku 4.5) |
| **Diff** | 公告レコード(公告本文テキスト含む)の変更前後のフィールドレベル差分(before/after)。原典PDF自体はハッシュ比較による差替え検知(内容差分は対象外) | `kkj/store.py` |

法的設計: **原文PDFは利用者へ再配布しません**。外部提供するのは抽出した事実・差分メタデータ・原典URLのみです。差分解析・証跡検証のため、内部ではポータル公告レコード(本文テキスト含む)を版管理し、原典PDFはハッシュのみを保持します。巡回は官公需情報ポータル公式APIをインデックスに使い、原典サイトへはrobots.txt順守・アクセス間隔を空けて巡回。

## 使い方

```sh
python -m kkj.pipeline poll          # 案件巡回(タスクスケジューラで3時間おき自動実行中)
python -m kkj.pipeline poll-docs 20  # 原典文書の差替え検知
python -m kkj.pipeline extract 10    # 要件構造化(要 ANTHROPIC_API_KEY)
python -m kkj.pipeline events        # 変更フィード
python -m kkj.pipeline watch-add クラウド   # キーワードウォッチ登録
python -m kkj.pipeline digest        # ウォッチ別の新着・変更ダイジェスト
python -m kkj.server 8787            # JSON API (localhost)
python -m kkj.mcp_server             # MCPサーバー(stdio)
```

### MCP(調達エージェント連携)

このリポジトリの `.mcp.json` により、Claude Code等のMCPクライアントから
`search_cases` / `get_case` / `list_change_events` / `get_requirements` が使える。

### JSON API

`GET /cases` `GET /cases/{key}` `GET /events` `GET /stats`(利用ログ計測付き — フェーズ1のゲート判定: ユニーク利用元10件以上+7日以上継続3件以上)

### x402(AIエージェントの自律支払い)

`/paid/requirements/{key}` は [x402プロトコル](https://docs.cdp.coinbase.com/x402/welcome)対応 — **USDC $0.02/コール**(Base mainnet)。
エージェントは402応答の`accepts`に従いEIP-3009署名を`X-PAYMENT`ヘッダで送るだけでデータを購入できます(アカウント・APIキー不要)。

```
GET https://5.75.142.199.sslip.io/paid/requirements/{key}
→ 402 + paymentRequirements
→ X-PAYMENT付き再リクエスト → 200 + 構造化応募要件JSON(+ retry_token)
```

**エンドポイントと課金:**

| エンドポイント | 価格 | 内容 |
|---|---|---|
| `GET /events` `/cases` | 無料 | 変更履歴・案件一覧(タグ付き) |
| `GET /paid/requirements/{key}` | $0.02 | キャッシュ済みの構造化データのみ。未解析なら課金せず409 |
| `GET /paid/analyze-now/{key}` | $0.30 | 新規LLM解析(支払い前に可用性・予算・サイズを事前確認) |
| `GET /paid/job/{retry_token}` | 無料 | 支払い済みジョブの再取得(再課金なし) |

**paid-but-denied を出さない設計:**

- キャッシュが無い/LLMが実行できない時は**支払い要求(402)を出しません**(409 / 503 / 429 で返す)
- 支払い後にLLMが失敗(429/529/残高切れ/タイムアウト)しても、応答の `retry_token` で**再支払いなし再取得**できます。
  事前チェックは「LLMが確実に成功する」ことまでは保証しません(実残高はAnthropicを呼ぶまで不明)。
  正確には「**実行可能性を事前確認し、失敗時は `retry_token` で再取得可能**」です。
- `retry_token` は URL クエリでも受け付けますが、**`X-Retry-Token` ヘッダ推奨**(クエリはサーバログ・履歴に残るため):

```
GET /paid/analyze-now/{key}
X-Retry-Token: <前回の応答で得たトークン>
```

- 同一 `X-PAYMENT` の同一リソースへの再送は**再決済せず同じ結果**を返します(冪等)。別リソースでの再利用は 409。

## 収益モデル(フェーズ2)

- 従量: 1案件の構造化 ¥10〜50(x402 + APIキー併用)
- 月額: ウォッチ型 ¥3,000〜10,000/社(digest機能が実体)
- 卸: 既存入札SaaSへの差分レイヤー提供(B2B2B)

詳細は `plan`(事業計画)と `docs/phase0_design.md`(技術設計・検証結果)を参照。

## 構成

Python 3.10+。コア(巡回・差分・API・MCP)は標準ライブラリのみで動作。データは `data/kkj.db`(SQLite)。
任意依存: `pypdf`(原典PDFの本文抽出 — 未導入の場合はハッシュによる差替え検知のみに自動縮退)、
x402決済に `PyJWT`/`cryptography`/`cdp-sdk`。
LLM(意味づけ・要件抽出)は Anthropic API(claude-haiku-4-5, structured outputs)。

制約の明記: PDF本文抽出はテキスト埋め込み型PDFが対象です。スキャン(画像)PDFは本文抽出できないため、
その場合の差替え検知はハッシュ比較(変わった事実の検知)までとなります。
