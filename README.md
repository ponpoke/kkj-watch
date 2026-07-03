# kkj-watch — 入札案件の変更検知・要件構造化エンジン

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
→ X-PAYMENT付き再リクエスト → 200 + 構造化応募要件JSON
```

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
