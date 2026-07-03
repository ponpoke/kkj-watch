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
| **Watch** | 案件・原典文書を巡回し、変化をイベント(NEW_CASE / FIELD_CHANGED / DOC_CHANGED)として配信。全スナップショットにSHA-256+取得時刻を付与した改変不能な証跡 | `kkj/pipeline.py`, `kkj/doc_watch.py` |
| **Extract** | 公告本文から応募資格・全省庁統一資格等級・必須認証・提出書類・締切をJSON抽出。「この案件にうちは応募資格があるか」に1コールで回答 | `kkj/extractor.py` (Claude Haiku 4.5) |
| **Diff** | 変更前後の条項レベル差分(before/after) | `kkj/store.py` |

法的設計: **原文は保存も再配布もしない**。ハッシュ+抽出した事実+原典URLのみを扱う。巡回は官公需情報ポータル公式APIをインデックスに使い、原典サイトへはrobots.txt順守・低頻度でアクセス。

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

Python 3.10+ 標準ライブラリのみ(依存ゼロ)。データは `data/kkj.db`(SQLite)。
LLM抽出のみ Anthropic API(claude-haiku-4-5, structured outputs)を使用。
