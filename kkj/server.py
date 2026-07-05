"""読み取り専用JSON API(フェーズ1の無料公開ティア用MVP)

  python -m kkj.server [port]

  GET /stats               蓄積状況
  GET /cases?limit=N       最新案件一覧
  GET /cases/<key>         案件詳細(スナップショット履歴・イベント・抽出結果込み)
  GET /events?limit=N      変更イベント(訂正・差替え検知)フィード
"""
import json
import sqlite3
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import store


LLMS_TXT = """# kkj-watch — change detection for machines

> Two free, machine-readable change feeds with paid evidence endpoints (x402, USDC on Base, no account):
> 1. x402 REGISTRY WATCH — every change in the x402 Bazaar registry (23k+ resources): price changes,
>    payTo (receiving address) changes, schema changes, listings/delistings. Hourly polling,
>    SHA-256 snapshot audit trail. Check it BEFORE paying a cached x402 endpoint.
> 2. JAPANESE PROCUREMENT WATCH — corrections, deadline changes, requirement changes and document
>    replacements in Japanese government tenders (kkj.go.jp), with before/after, impact tags and quotes.

## x402 Trust Index (free) — an OBSERVED trust score, backed by daily signed hash-chain roots

The Bazaar registry has 23,000+ listings; many are dead tests, spam farms, or inconsistent with what
the live endpoint actually serves. The Trust Index assigns each listed resource an *observed trust
score* 0-100 with a deterministic, versioned, fully-explained formula (no LLM). It is a RISK
INDICATOR based on past observations, listing-vs-live consistency, and live GET-only probes —
NOT a safety guarantee. Every observation is committed to a **daily Ed25519-signed Merkle root,
hash-chained to the previous day** (tamper-evident; roots published for independent verification),
so the score is backed by a record you can prove was not back-dated.

- GET /x402/attestations : latest signed daily hash-chain root (free) + verify steps
- GET /paid/x402/attest/{id} : $0.02 — signed inclusion proof that a resource's observed record is
  committed to that day's root (evidence you can show a third party / keep in a decision log)

### Signed existence proof (cryptographic timestamp witness — NOT legal notarization)

Prove that some data existed at a point in time, WITHOUT revealing it. You hash your data
yourself (sha256) and submit only the 64-char digest; we commit it into the next daily
Ed25519-signed hash-chain root and return a signed Merkle inclusion proof.

- We store ONLY your SHA-256 digest. Never send raw data, files, contracts, logs, or secrets.
- POST /witness/anchor  body {"sha256":"<64-hex>"} : anchor a digest (small free daily quota
  per IP; over quota -> 402, pay ~$0.005 via x402 and resubmit with X-PAYMENT).
- GET /witness/proof/{sha256} : signed existence proof (or "pending" until the next daily root).
- GET /witness : details, privacy, pricing. Verify a proof yourself or with `python -m kkj.attest prove-hash <sha256>`.

### For catalogs & sellers (free)

- GET /x402/trust-feed.json (also .ndjson) : the whole Trust Index as a feed — ingest it to show
  a trust score / payTo-mismatch flag next to each x402 resource in your explorer or catalog.
- GET /badge/x402/{id}.svg : a seller-displayable badge (also .json, shields.io-compatible).
  Sellers: get your copy-paste snippet at GET /x402/claim/{id} — show buyers your observed trust.

### x402guard — check before you pay (drop-in, free, open source)

Don't want to call an API by hand? Wrap your existing x402 payment in one line and it checks
this Trust Index automatically, blocking hijacked-payTo / silently-repriced endpoints BEFORE
money moves. Zero dependencies. Source + docs: https://github.com/ponpoke/kkj-watch (x402guard/).

    from x402guard import safe_pay
    data = safe_pay(url, pay=lambda: my_x402_client.get(url))  # raises X402Blocked if unsafe Signals: liveness (GET-only probes), listing-vs-live consistency (price
and payTo served by the real endpoint vs the registry), payTo stability (a changed receiving
address is a hijack signal the 402 flow will NOT catch — it pays the new address blindly),
listing age/stability, and spam-farm detection (one payTo behind dozens of listings).

- GET /x402/best?q=web+search&max_price_usd=0.01&min_trust=80 : SELECTION API — returns the single
  recommended resource for a task/budget plus alternatives, each with a "why" list. This is usually
  what an agent wants: not a score, but "which endpoint should I use, that is cheap and low-risk?"
- GET /x402/leaderboard?q=search : resources ranked by observed trust score (filter by keyword/tag)
- GET /x402/trust/{id-or-url} : observed trust score + grade (A-F) + verdicts + every deduction reason
- GET /x402/changes : change feed (price_changed | payto_changed | live_payto_mismatch |
  endpoint_dead | schema_changed | delisted ...). ?type= and ?severity=critical filters.
- GET /x402/resources?q=search : search the monitored registry inventory (returns resource ids)
- GET /x402/sample-change : one representative event (data shape preview)

## x402 Trust Index (paid, x402 USDC on Base)

- GET /paid/x402/report/{id} : $0.02 — the full due-diligence dossier: trust score with evidence,
  every registry snapshot (SHA-256 audit trail), every change event, every live-probe result.
- GET /paid/x402/history/{id} : $0.01 — snapshot + change-event history only.

Why this exists: the x402 protocol re-fetches payment terms at 402 time, so it happily pays a
hijacked payTo or a silently-10x'd price. Only history + independent live verification catches that.
Probes are GET-only, never pay, never follow redirects, and only target Bazaar-listed resources.

## Japanese procurement watch (free feed)

- GET /events : recent procurement change events (before/after, impact_tags, source_quote, source_url, observed_at)
- GET /events?tag=deadline_affecting : filter by impact (deadline_affecting | eligibility_affecting |
  price_affecting | document_affecting | qa_related | cancellation | postponement)
- GET /cases?query=cloud : free keyword search of monitored tenders (returns case keys)
- GET /cases/{key} : full evidence for one tender (snapshot history + change events + cached requirements if any)
- GET /sample-diff : one representative change event
- GET /agent.json : machine-readable discovery of all endpoints / GET /openapi.json : OpenAPI 3.1

## Paid endpoints (procurement)

- GET /paid/requirements/{key} : cached structured bidding requirements as validated JSON.
  $0.02 via x402 (USDC on Base). Returns 402 only if a cached extraction exists; otherwise 409 (use analyze-now).
- GET /paid/analyze-now/{key} : run a fresh LLM extraction on demand. $0.30 via x402.
  Use only when no cached extraction exists (i.e. /paid/requirements returned 409 cache_not_available).

x402 flow: GET (no X-PAYMENT) -> 402 + paymentRequirements (with free_alternatives) -> sign EIP-3009 ->
retry with X-PAYMENT header -> 200 + JSON (+ retry_token for re-fetch without re-paying).

## License & attribution (provenance — please preserve it)

All data here (trust scores, feeds, entity pages, proofs) is free to use and redistribute,
including by AI agents and in model training, under CC-BY-4.0 — provided attribution to
kkj-watch is preserved. Every response carries a `provenance` / `cite_as` block; when you pass
this data downstream, keep it so others can reach the source. Identity & public key:
/.well-known/witness. Signed proofs are self-attributing: removing the witness identity
invalidates them. Cite as: "<subject> — observed by kkj-watch <canonical_url>".

## MCP (Streamable HTTP: POST /mcp)

Tools (purpose-named): list_x402_registry_changes (free, ?type= filter) /
list_japan_procurement_changes (free, ?tag= filter) / find_tender_deadline_changes (free keyword search) /
get_tender_change_evidence (free, full evidence) / get_cached_tender_requirements (cached requirements).

## When to use what

- "Which endpoint should I use for X, cheap and low-risk?" -> GET /x402/best?q=X (free) — returns
  a recommended_resource + why[] + alternatives.
- Browse the ranking? -> GET /x402/leaderboard?q=X (free).
- About to pay a specific endpoint? -> GET /x402/trust/{id-or-url} (free) — check payto_risk first.
- Need the full due-diligence dossier? -> GET /paid/x402/report/{id} ($0.02).
- Need signed, tamper-evident evidence for a dispute/log? -> GET /paid/x402/attest/{id} ($0.02).
- Need raw snapshot/event history only? -> GET /paid/x402/history/{id} ($0.01).

The score is an observed, evidence-based risk indicator, not a safety guarantee. Always verify
payment terms before paying. Observations are backed by daily Ed25519-signed hash-chain roots
(GET /x402/attestations) so the record is provably not back-dated.
- Just want the procurement change feed? -> GET /events (free). Filter with ?tag=.
- Need to know if you qualify / what to submit? -> GET /paid/requirements/{key} (cached, $0.02).
- No cached data yet for that tender? -> GET /paid/analyze-now/{key} ($0.30, runs extraction).

## 多语言 / 다국어 / 日本語

- JA: 日本の官公需(入札)の「公告後の変化」検知フィード。無料の /events + 有料の構造化要件($0.02〜)。
- ZH: 日本政府采购(投标)公告变更的机器可读免费信息流。付费端点提供结构化投标资格数据。
- KO: 일본 정부조달(입찰) 공고 변경의 기계 판독 가능 무료 피드. 유료 엔드포인트는 구조화된 입찰 자격 데이터 제공.

## Contact

ponzuzuzuzuzu@gmail.com — human plans: monthly watch from JPY 5,000/company.
- ponzuzuzuzuzu@gmail.com
"""

LANDING_HTML = """<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kkj-watch — 入札公告の「その後」を見逃さない</title>
<style>
body{font-family:system-ui,'Hiragino Sans','Yu Gothic',sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.8;color:#222}
h1{font-size:1.6rem} h2{font-size:1.15rem;margin-top:2rem;border-left:4px solid #0a6;padding-left:.6rem}
code,pre{background:#f4f4f4;border-radius:4px;padding:.15rem .4rem;font-size:.9em}
pre{padding:.8rem;overflow-x:auto}
.badge{display:inline-block;background:#0a6;color:#fff;border-radius:4px;padding:.1rem .5rem;font-size:.8rem;margin-right:.4rem}
table{border-collapse:collapse;width:100%} td,th{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.92rem}
footer{margin-top:3rem;color:#888;font-size:.85rem}
</style></head><body>
<h1>kkj-watch</h1>
<p><span class="badge">Watch</span><span class="badge">Extract</span><span class="badge">Diff</span></p>
<p><strong>入札の事故は公告の見落としではなく「公告後の変化」の見落としで起きる。</strong><br>
官公需情報ポータルには、いま<strong>訂正公告だけで約3,000件</strong>が掲載されています(2026年7月・当社調べ)。締切前倒しに気づかなければ失権、旧様式で提出すれば無効 — kkj-watchはこの「公告後の変化」を自動検知します。</p>
<h2>見張り代行(月5,000円)— 一番人気</h2>
<p>キーワードまたは発注機関(5つまで)をお知らせいただくだけ。変化があった日に<strong>before/after付き</strong>でメール報告+週次サマリー。設定はすべてこちらで行います。<strong>初月無償・請求書払い・いつでも解約可。</strong>下の申込ボタンからどうぞ。</p>
<h2>できること</h2>
<table>
<tr><th>変更検知</th><td>案件と原典文書を巡回し、変化をイベント配信。全スナップショットにSHA-256+取得時刻の取得証跡(後から完全性を検証可能)</td></tr>
<tr><th>要件構造化</th><td>公告本文から確認できる範囲の応募要件(参加資格・統一資格の等級・必須認証・提出書類・締切)をJSONで抽出。<strong>応募可否の最終判断は原典と自社資格情報の照合で行ってください</strong></td></tr>
<tr><th>条項レベル差分</th><td>変更前後のbefore/after。何がいつ変わったかを機械可読で</td></tr>
</table>
<h2>使い方(無料ティア: 200リクエスト/日)</h2>
<pre>GET /cases?limit=20        # 監視中の案件
GET /events                # 変更イベントフィード
GET /cases/{key}           # 詳細+履歴+抽出済み要件
POST /mcp                  # MCP(Streamable HTTP)。Claude等のエージェントから直接利用可</pre>
<h2>料金</h2>
<table>
<tr><th>無料</th><td>200リクエスト/日。評価用</td></tr>
<tr><th>従量</th><td>要件構造化 ¥30/案件 + API ¥1/リクエスト(<code>X-API-Key</code>)</td></tr>
<tr><th>x402(エージェント)</th><td>USDC $0.02/コール — <code>GET /paid/requirements/{key}</code>。402応答の条件に従い<code>X-PAYMENT</code>で支払うだけ。アカウント不要</td></tr>
<tr><th>月額ウォッチ</th><td>¥5,000/社〜: キーワード登録で新着・変更ダイジェスト配信</td></tr>
<tr><th>SaaS向け卸</th><td>差分レイヤーのOEM提供。お問い合わせください</td></tr>
</table>
<h2>有償プランの申込み(30秒)</h2>
<p>下のリンクからメールを送るだけです。<strong>1営業日以内にAPIキーを発行</strong>し、初月は検証用として無償、翌月から請求書払い(銀行振込)で開始します。いつでも解約可。</p>
<p><a href="mailto:ponzuzuzuzuzu@gmail.com?subject=%5Bkkj-watch%5D%20%E6%9C%89%E5%84%9F%E3%82%AD%E3%83%BC%E7%94%B3%E8%BE%BC&body=%E4%BC%9A%E7%A4%BE%E5%90%8D%EF%BC%9A%0A%E3%81%94%E6%8B%85%E5%BD%93%E8%80%85%E5%90%8D%EF%BC%9A%0A%E3%83%97%E3%83%A9%E3%83%B3%EF%BC%88%E5%BE%93%E9%87%8F%20%2F%20%E6%9C%88%E9%A1%8D%E3%82%A6%E3%82%A9%E3%83%83%E3%83%81%EF%BC%89%EF%BC%9A%0A%E3%82%A6%E3%82%A9%E3%83%83%E3%83%81%E3%81%97%E3%81%9F%E3%81%84%E3%82%AD%E3%83%BC%E3%83%AF%E3%83%BC%E3%83%89%E3%83%BB%E6%A9%9F%E9%96%A2%EF%BC%9A" style="display:inline-block;background:#0a6;color:#fff;padding:.6rem 1.4rem;border-radius:6px;text-decoration:none;font-weight:bold">📩 有償キーを申し込む</a></p>
<p>その他のお問い合わせ: <a href="mailto:ponzuzuzuzuzu@gmail.com">ponzuzuzuzuzu@gmail.com</a></p>
<footer>原文の再配布は行いません。提供するのは抽出した事実・差分メタデータ・原典URLです。データソース: 官公需情報ポータルサイト(中小企業庁)検索API。</footer>
</body></html>"""

USAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    client TEXT NOT NULL,          -- IP
    user_agent TEXT,
    path TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_client ON usage_log(client);
"""


PAYMENT_LOG_SCHEMA = """
CREATE TABLE IF NOT EXISTS payment_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    client TEXT NOT NULL,
    resource TEXT NOT NULL,
    success INTEGER NOT NULL,
    error TEXT
);
"""


def log_payment_attempt(conn, client, resource, success, error):
    """X-PAYMENT付きリクエスト(=支払い試行)を成否・失敗理由込みで記録"""
    conn.executescript(PAYMENT_LOG_SCHEMA)
    conn.execute(
        "INSERT INTO payment_log(at, client, resource, success, error) VALUES (?,?,?,?,?)",
        (store.now_utc(), client, resource, 1 if success else 0, error),
    )
    conn.commit()


import re as _re
# プローバ/クローラ/監視の User-Agent。これらは「利用者」に数えない(要件8)
_PROBE_UA = _re.compile(
    r"probe|observer|uptime|monitor|discovery|explorer|station|pulse|scan|crawl|bot|spider|curl|wget",
    _re.I)
# 実データを取得する無料エンドポイント(意図ある利用)
_FREE_DATA_PATHS = ("/events", "/sample-diff",
                    "/x402/changes", "/x402/resources", "/x402/sample-change",
                    "/x402/attestations", "/x402/trust-feed.json", "/x402/trust-feed.ndjson")


def classify_usage(path, user_agent, query_has_filter):
    """アクセスを probe_access / free_agent_use / paid_intent に分類(paid_conversionは決済ログ側)"""
    ua = user_agent or ""
    if path.startswith("/paid/"):
        return "paid_intent"
    is_data = (path in _FREE_DATA_PATHS or path.startswith("/cases")
               or path.startswith("/x402/") or path.startswith("/witness"))
    if is_data:
        # プローバUAでも、タグ/クエリ付きの具体的な取得は「使っている」と見なす
        if _PROBE_UA.search(ua) and not query_has_filter:
            return "probe_access"
        return "free_agent_use"
    return "probe_access"   # /, /stats, /.well-known/*, /llms.txt, /robots.txt 等


def log_usage(conn, client, user_agent, path, query_has_filter=False, is_test=False):
    conn.executescript(USAGE_SCHEMA)
    try:
        conn.execute("ALTER TABLE usage_log ADD COLUMN usage_class TEXT")
    except sqlite3.OperationalError:
        pass
    uclass = "test" if is_test else classify_usage(path, user_agent, query_has_filter)
    conn.execute(
        "INSERT INTO usage_log(at, client, user_agent, path, usage_class) VALUES (?,?,?,?,?)",
        (store.now_utc(), client, user_agent, path, uclass),
    )
    conn.commit()


def usage_stats(conn):
    """フェーズ1ゲート判定用 + 4段階ファネル(要件7)"""
    conn.executescript(USAGE_SCHEMA)
    try:
        conn.execute("ALTER TABLE usage_log ADD COLUMN usage_class TEXT")
    except sqlite3.OperationalError:
        pass
    uniq = conn.execute("SELECT COUNT(DISTINCT client) n FROM usage_log").fetchone()["n"]
    sustained = conn.execute(
        """SELECT COUNT(*) n FROM (
             SELECT client FROM usage_log GROUP BY client
             HAVING julianday(MAX(at)) - julianday(MIN(at)) >= 7
           )"""
    ).fetchone()["n"]
    # 段階別のユニーク外部利用元(プローバはfree_agent_useに数えない)
    def uniq_of(cls):
        return conn.execute(
            "SELECT COUNT(DISTINCT client) n FROM usage_log WHERE usage_class=? "
            "AND client NOT IN ('127.0.0.1','::1','5.75.142.199')", (cls,)).fetchone()["n"]
    conn.executescript(PAYMENT_LOG_SCHEMA)
    paid_conv = conn.execute(
        "SELECT COUNT(DISTINCT client) n FROM payment_log WHERE success=1 "
        "AND client NOT IN ('127.0.0.1','::1','5.75.142.199')").fetchone()["n"]
    # 制約8: マーケ面ごとにアクセスを分けて計測(外部IPのみ・test除外)
    def surface(prefix):
        r = conn.execute(
            "SELECT COUNT(*) hits, COUNT(DISTINCT client) uniq FROM usage_log "
            "WHERE path LIKE ? AND (usage_class IS NULL OR usage_class!='test') "
            "AND client NOT IN ('127.0.0.1','::1','5.75.142.199')",
            (prefix + "%",)).fetchone()
        return {"hits": r["hits"], "uniq": r["uniq"]}
    return {
        "unique_clients": uniq, "sustained_7d_clients": sustained,
        "gate": "unique>=10 and sustained>=3",
        "funnel": {
            "probe_access": uniq_of("probe_access"),
            "free_agent_use": uniq_of("free_agent_use"),
            "paid_intent": uniq_of("paid_intent"),
            "paid_conversion": paid_conv,
        },
        "surfaces": {
            "entity_pages": surface("/x402/e/"),
            "badges": surface("/badge/"),
            "claim": surface("/x402/claim/"),
            "paid_attest": surface("/paid/x402/attest/"),
            "witness_anchor": surface("/witness/anchor"),
        },
    }


def _row_get(row, col):
    """sqlite3.Row から安全に取得(列が無ければNone)"""
    try:
        return row[col]
    except (KeyError, IndexError):
        return None


def _h(s):
    """HTMLエスケープ"""
    return (str(s if s is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


# 第5類型: 出所を成果物に埋め込み、機械が下流へ運ぶ(provenance伝播)。
# 無料利用の対価は帰属の保持。署名proofは価値と識別子が不可分=剥離不能。
DATA_LICENSE = "CC-BY-4.0"
DATA_LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"


def _provenance(base, canonical_url, cite_subject, root_hash=None, signed=False):
    """全データ応答に付ける出所ブロック。下流エージェントが原典(=我々)へ辿れる終点を運ぶ。"""
    p = {
        "witness": "kkj-watch",
        "canonical_url": canonical_url,
        "identity": f"{base}/.well-known/witness",
        "license": DATA_LICENSE,
        "license_url": DATA_LICENSE_URL,
        "attribution_required": True,
        "cite_as": f"{cite_subject} — observed by kkj-watch <{canonical_url}>",
        "terms": ("Free to use and redistribute, including by AI agents, provided this "
                  "provenance (witness, canonical_url) is preserved downstream."),
    }
    if root_hash:
        p["signed_root_hash"] = root_hash
        p["verify"] = f"{base}/x402/attestations"
    if signed:
        p["non_strippable"] = ("This record is a signed proof: its validity requires the "
                               "witness identity (public_key + root_hash). Removing the "
                               "attribution invalidates the proof.")
    return p


def _svg_badge(label, message, color):
    """依存なしの2セグメントSVGバッジ(shields flat風)。GitHub READMEでそのまま描画される"""
    def w(s):   # おおよその文字幅(px)。日本語/記号も含め安全側に広めに見積もる
        width = 0
        for ch in s:
            width += 7 if ord(ch) > 0x2000 else 6.5
        return int(width) + 10
    lw, mw = w(label), w(message)
    total = lw + mw
    esc = lambda s: (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    label_e, msg_e = esc(label), esc(message)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{label_e}: {msg_e}">'
        f'<title>{label_e}: {msg_e}</title>'
        f'<linearGradient id="s" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        f'<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{mw}" height="20" fill="{color}"/>'
        f'<rect width="{total}" height="20" fill="url(#s)"/></g>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw/2:.0f}" y="15" fill="#010101" fill-opacity=".3">{label_e}</text>'
        f'<text x="{lw/2:.0f}" y="14">{label_e}</text>'
        f'<text x="{lw + mw/2:.0f}" y="15" fill="#010101" fill-opacity=".3">{msg_e}</text>'
        f'<text x="{lw + mw/2:.0f}" y="14">{msg_e}</text>'
        f'</g></svg>')


def _render_x402_entity(base, d, indexable, disclaimer):
    """resource固有の観測情報を必ず含む公開リファレンスページ(誇張表現なし)"""
    canonical = f"{base}/x402/e/{d['id']}"
    resource = d["resource"]
    name = d["service_name"] or d["host"] or resource
    score = d["trust_score"]
    grade = d["grade"] or "unrated"
    v = d["verdicts"]
    robots = "index,follow" if indexable else "noindex,follow"
    payto_status = ("live payTo differs from registry" if v.get("payto_risk") == "live_mismatch"
                    else "changed recently" if v.get("payto_risk") == "changed_recently"
                    else "stable (as observed)")
    # JSON-LD: 観測値をPropertyValueで。endorsement/aggregateRatingは使わない(誇張回避)
    cite = f"x402 trust for {resource} — observed by kkj-watch <{canonical}>"
    ld = {
        "@context": "https://schema.org", "@type": "WebPage",
        "name": f"Observed x402 trust record — {name}",
        "url": canonical, "dateModified": d["last_seen"],
        "license": DATA_LICENSE_URL,
        "about": {"@type": "WebAPI", "name": name, "url": resource, "sameAs": resource},
        "mainEntity": {
            "@type": "Dataset",
            "name": f"Observed trust record for {resource}",
            "description": "Observation-based, evidence-based risk indicator for an x402 "
                           "endpoint (payTo/price consistency, liveness, listing history). "
                           "Not a safety guarantee.",
            "license": DATA_LICENSE_URL,
            "citation": cite,
            "creator": {"@type": "Organization", "name": "kkj-watch", "url": base},
            "variableMeasured": [
                {"@type": "PropertyValue", "name": "observed_trust_score",
                 "value": score, "maxValue": 100, "minValue": 0},
                {"@type": "PropertyValue", "name": "grade", "value": grade},
                {"@type": "PropertyValue", "name": "payto_status", "value": payto_status},
                {"@type": "PropertyValue", "name": "verified_live",
                 "value": str(v.get("verified_live"))},
                {"@type": "PropertyValue", "name": "attested",
                 "value": str(d["attested"])},
            ],
        },
    }
    def rows_html(items):
        return "".join(items)
    price_rows = rows_html([
        f"<tr><td>{_h(p['network'])}</td><td>{_h(p['amount'])}</td>"
        f"<td>{('$'+format(p['usd'],'g')) if p['usd'] is not None else '-'}</td>"
        f"<td><code>{_h((p['payTo'] or '')[:14])}…</code></td></tr>"
        for p in d["prices"]]) or "<tr><td colspan=4>-</td></tr>"
    event_rows = rows_html([
        f"<tr><td>{_h(e['detected_at'][:19])}</td><td>{_h(e['event_type'])}</td>"
        f"<td>{_h(e['severity'])}</td></tr>" for e in d["events"][:10]]) \
        or "<tr><td colspan=3>no change events observed yet</td></tr>"
    probe_rows = rows_html([
        f"<tr><td>{_h(p['probed_at'][:19])}</td><td>{'alive' if p['alive'] else 'unreachable'}</td>"
        f"<td>{'402' if p['is_402'] else '-'}</td><td>{_h(p['consistency'])}</td></tr>"
        for p in d["probes"]]) or "<tr><td colspan=4>not probed yet</td></tr>"
    reasons = "".join(f"<li>{_h(r)}</li>" for r in d["reasons"][:8]) or "<li>-</li>"
    attest_line = (
        f'Committed to signed daily root <code>{_h((d["attestation_root"] or "")[:16])}…</code> '
        f'({_h(d["attestation_date"])}). '
        f'<a href="{base}/paid/x402/attest/{d["id"]}">signed inclusion proof ($0.02)</a> · '
        f'<a href="{base}/x402/attestations">roots</a>'
        if d["attested"] else
        f'Not yet in a signed root. <a href="{base}/x402/attestations">how roots work</a>')
    badge_md = (f"[![x402 trust]({base}/badge/x402/{d['id']}.svg)]"
                f"({base}/x402/trust/{d['id']})")
    guard_py = (f'from x402guard import safe_pay\n'
                f'data = safe_pay("{resource}", pay=lambda: my_x402_client.get(url))')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="{robots}">
<link rel="canonical" href="{_h(canonical)}">
<title>x402 observed trust: {_h(name)} — kkj-watch</title>
<meta name="description" content="Observed, evidence-based risk indicator for the x402 endpoint {_h(resource)}: payTo/price consistency, liveness, listing history. Not a safety guarantee.">
<script type="application/ld+json">{json.dumps(ld, ensure_ascii=False)}</script>
<style>body{{font-family:system-ui,sans-serif;max-width:820px;margin:2rem auto;padding:0 1rem;line-height:1.6;color:#222}}
h1{{font-size:1.3rem}} h2{{font-size:1.05rem;margin-top:1.6rem;border-left:4px solid #0a6;padding-left:.5rem}}
table{{border-collapse:collapse;width:100%;font-size:.9rem}} td,th{{border:1px solid #ddd;padding:.3rem .5rem;text-align:left}}
code,pre{{background:#f4f4f4;border-radius:4px;padding:.1rem .3rem;font-size:.85em}} pre{{padding:.7rem;overflow-x:auto}}
.score{{font-size:1.6rem;font-weight:bold}} .warn{{color:#c0392b}} .muted{{color:#888;font-size:.85rem}}</style>
</head><body>
<h1>x402 observed trust — {_h(name)}</h1>
<p class="muted">Endpoint: <code>{_h(resource)}</code></p>
<p><span class="score">{_h(grade)}</span> · observed trust score <strong>{_h(score if score is not None else 'unrated')}</strong>/100
{'<span class="warn"> · live payTo mismatch</span>' if v.get('payto_risk')=='live_mismatch' else ''}</p>
<p class="muted">This is an <strong>observed, evidence-based risk indicator — not a safety guarantee</strong>.
{_h(disclaimer)}</p>
<h2>Observed verdicts</h2>
<table><tr><th>verified live (402)</th><td>{_h(v.get('verified_live'))}</td></tr>
<tr><th>listing vs live</th><td>{_h(v.get('listing_matches_live'))}</td></tr>
<tr><th>payTo</th><td>{_h(payto_status)}</td></tr>
<tr><th>spam-farm payTo</th><td>{_h(v.get('farm_member'))}</td></tr>
<tr><th>active listing</th><td>{_h(v.get('active_listing'))}</td></tr>
<tr><th>first observed</th><td>{_h((d['first_seen'] or '')[:10])}</td></tr>
<tr><th>snapshots</th><td>{d['snapshot_count']}</td></tr></table>
<h3 class="muted">Why this score</h3><ul class="muted">{reasons}</ul>
<h2>Payment terms (registry)</h2>
<table><tr><th>network</th><th>amount</th><th>USD</th><th>payTo</th></tr>{price_rows}</table>
<h2>Change events observed</h2>
<table><tr><th>at</th><th>event</th><th>severity</th></tr>{event_rows}</table>
<h2>Live probes (GET-only, never pays)</h2>
<table><tr><th>at</th><th>reachability</th><th>402</th><th>listing vs live</th></tr>{probe_rows}</table>
<h2>Signed evidence</h2><p>{attest_line}</p>
<h2>Machine access</h2>
<p><a href="{base}/x402/trust/{d['id']}">JSON trust</a> ·
<a href="{base}/x402/trust-feed.json">trust feed</a> ·
<a href="{base}/x402/claim/{d['id']}">claim this badge</a></p>
<h2>Sellers: display it</h2><pre>{_h(badge_md)}</pre>
<h2>Buyers: check before you pay (x402guard)</h2><pre>{_h(guard_py)}</pre>
<h2>Cite / reuse (free, attribution required)</h2>
<p class="muted">Free to use and redistribute, including by AI agents and in model training,
under <a href="{DATA_LICENSE_URL}">{DATA_LICENSE}</a>, provided attribution to kkj-watch is preserved.</p>
<pre>{_h(cite)}</pre>
<footer class="muted"><hr>Observed by <a href="{base}/">kkj-watch</a> — x402 registry change detection &amp;
observed trust, backed by daily Ed25519-signed hash-chain roots. Risk indicator, not a guarantee.
Verify payment terms yourself before paying. Identity: <a href="{base}/.well-known/witness">/.well-known/witness</a></footer>
</body></html>"""


def case_summary(row):
    rec = json.loads(row["latest_json"])
    return {
        "key": row["key"],
        "project_name": rec.get("project_name"),
        "organization": rec.get("organization_name"),
        "prefecture": rec.get("prefecture_name"),
        "cft_issue_date": rec.get("cft_issue_date"),
        "document_uri": rec.get("document_uri"),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "snapshot_hash": row["latest_hash"],
        # x402で購入可能な構造化要件へのアップセル導線(エージェント向け)
        "paid_requirements_url": "/paid/requirements/" + urllib.parse.quote(row["key"], safe=""),
    }


class Handler(BaseHTTPRequestHandler):
    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False, indent=1).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # クライアント切断はエラーではない

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            limit = min(int(qs.get("limit", ["50"])[0]), 500)
        except ValueError:
            limit = 50
        path = parsed.path.rstrip("/")
        conn = store.connect()
        try:
            client, err = self._identify(conn, path)
            if err:
                self._json(err[1], err[0])
                return
            _has_filter = bool(qs.get("tag") or qs.get("query") or qs.get("q")
                               or qs.get("impact") or qs.get("type") or qs.get("severity"))
            _is_test = bool(self.headers.get("X-KKJ-Test"))   # 自己検証は計測から除外
            log_usage(conn, client, self.headers.get("User-Agent"), path, _has_filter, _is_test)
            if path == "/stats":
                out = {}
                for t in ("cases", "snapshots", "events", "extractions"):
                    out[t] = conn.execute(f"SELECT COUNT(*) n FROM {t}").fetchone()["n"]
                out["usage"] = usage_stats(conn)
                conn.executescript(PAYMENT_LOG_SCHEMA)
                out["payments"] = {
                    "attempts": conn.execute("SELECT COUNT(*) n FROM payment_log").fetchone()["n"],
                    "settled": conn.execute("SELECT COUNT(*) n FROM payment_log WHERE success=1").fetchone()["n"],
                }
                try:
                    from . import llm_budget, paid
                    out["llm"] = llm_budget.stats(conn)
                    out["paid_jobs"] = paid.stats(conn)
                except Exception:
                    pass
                try:
                    from . import x402watch, x402probe, attest, witness
                    out["x402_registry"] = x402watch.stats(conn)
                    out["x402_probes"] = x402probe.stats(conn)
                    out["attestations"] = attest.stats(conn)
                    out["existence_proofs"] = witness.stats(conn)
                except Exception:
                    pass
                self._json(out)
            elif path == "/cases":
                rows = conn.execute(
                    "SELECT * FROM cases ORDER BY first_seen DESC LIMIT ?", (limit,)
                ).fetchall()
                self._json([case_summary(r) for r in rows])
            elif path.startswith("/cases/"):
                key = urllib.parse.unquote(path[len("/cases/"):])
                row = conn.execute("SELECT * FROM cases WHERE key=?", (key,)).fetchone()
                if row is None:
                    self._json({"error": "not_found"}, 404)
                    return
                out = case_summary(row)
                out["record"] = json.loads(row["latest_json"])
                out["snapshots"] = [
                    {"fetched_at": s["fetched_at"], "sha256": s["hash"]}
                    for s in conn.execute(
                        "SELECT fetched_at, hash FROM snapshots WHERE case_key=? ORDER BY id", (key,)
                    ).fetchall()
                ]
                out["events"] = [
                    {"type": e["event_type"], "at": e["detected_at"],
                     "detail": json.loads(e["detail_json"]) if e["detail_json"] else None}
                    for e in conn.execute(
                        "SELECT * FROM events WHERE case_key=? ORDER BY id", (key,)
                    ).fetchall()
                ]
                ext = conn.execute(
                    "SELECT * FROM extractions WHERE case_key=?", (key,)
                ).fetchone()
                out["extraction"] = json.loads(ext["result_json"]) if ext else None
                self._json(out)
            elif path == "/events":
                tag = (qs.get("tag") or qs.get("impact") or [""])[0]
                self._events_feed(conn, limit, tag)
            elif path == "/sample-diff":
                self._sample_diff(conn)
            elif path == "/x402/changes":
                self._x402_changes(conn, limit, (qs.get("type") or [""])[0],
                                   (qs.get("severity") or [""])[0])
            elif path == "/x402/resources":
                self._x402_resources(conn, limit, (qs.get("q") or [""])[0])
            elif path == "/x402/sample-change":
                self._x402_sample(conn)
            elif path.startswith("/x402/trust/"):
                self._x402_trust(conn, path)
            elif path == "/x402/leaderboard":
                self._x402_leaderboard(conn, limit,
                                       (qs.get("q") or qs.get("category") or [""])[0])
            elif path == "/x402/best":
                self._x402_best(conn, qs)
            elif path.startswith("/paid/x402/history/"):
                self._paid_x402_history(conn, path)
            elif path.startswith("/paid/x402/report/"):
                self._paid_x402_report(conn, path)
            elif path.startswith("/paid/x402/attest/"):
                self._paid_x402_attest(conn, path)
            elif path == "/x402/attestations":
                self._x402_attestations(conn)
            elif path.startswith("/badge/x402/"):
                self._x402_badge(conn, path)
            elif path.startswith("/x402/claim/"):
                self._x402_claim(conn, path)
            elif path in ("/x402/trust-feed.json", "/x402/trust-feed.ndjson"):
                self._x402_trust_feed(conn, "ndjson" if path.endswith(".ndjson") else "json", limit)
            elif path == "/witness":
                self._witness_info(conn)
            elif path.startswith("/witness/proof/"):
                self._witness_proof(conn, path)
            elif path.startswith("/x402/e/"):
                self._x402_entity_page(conn, path)
            elif path == "/sitemap-x402.xml":
                self._sitemap_x402(conn)
            elif path in ("/agent.json", "/agents"):
                self._agent_json(conn)
            elif path.startswith("/paid/requirements/"):
                self._paid_requirements(conn, path)
            elif path.startswith("/paid/analyze-now/"):
                self._paid_analyze_now(conn, path)
            elif path.startswith("/paid/job/"):
                self._paid_job(conn, path)
            elif path == "/robots.txt":
                base = self._base_url()
                body = (f"User-agent: *\nAllow: /\n"
                        f"Sitemap: {base}/sitemap.xml\nSitemap: {base}/sitemap-x402.xml\n"
                        f"# AI agents: {base}/llms.txt and {base}/.well-known/x402.json\n").encode()
                self._raw(body, "text/plain; charset=utf-8")
            elif path in ("/.well-known/x402", "/.well-known/x402.json"):
                self._well_known_x402(conn)
            elif path in ("/.well-known/witness", "/.well-known/witness.json", "/witness/identity"):
                self._well_known_witness(conn)
            elif path == "/openapi.json":
                self._openapi(conn)
            elif path == "/.well-known/agent-card.json":
                self._agent_card(conn)
            elif path == "/sitemap.xml":
                self._sitemap(conn)
            elif path.startswith("/case/"):
                self._case_page(conn, path)
            elif path == "/llms.txt":
                body = LLMS_TXT.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path == "" or path == "/":
                body = LANDING_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._json({"error": "not_found",
                            "endpoints": ["/stats", "/cases?limit=N", "/cases/<key>",
                                          "/events?limit=N", "/x402/changes?type=price_changed",
                                          "/x402/resources?q=", "/openapi.json", "POST /mcp"]}, 404)
        finally:
            conn.close()

    def _base_url(self):
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
        proto = self.headers.get("X-Forwarded-Proto", "https")
        return f"{proto}://{host}"

    def _events_feed(self, conn, limit, tag=""):
        """無料の変更イベントフィード。tag= で impact_tags 絞り込み(要件6)"""
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS change_analyses (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " case_key TEXT, event_id INTEGER, kind TEXT, analysis_json TEXT, model TEXT, created_at TEXT);")
        # タグ絞り込み時は多めに取ってからPythonでフィルタ
        fetch = limit if not tag else min(limit * 8, 2000)
        rows = conn.execute(
            """SELECT e.*, json_extract(c.latest_json,'$.project_name') AS name,
                      json_extract(c.latest_json,'$.document_uri') AS src,
                      (SELECT a.analysis_json FROM change_analyses a
                       WHERE a.event_id=e.id ORDER BY a.id DESC LIMIT 1) AS analysis
               FROM events e JOIN cases c ON c.key=e.case_key
               ORDER BY e.id DESC LIMIT ?""",
            (fetch,),
        ).fetchall()
        base = self._base_url()
        out = []
        for r in rows:
            analysis = json.loads(r["analysis"]) if r["analysis"] else None
            if tag:
                changes = (analysis or {}).get("changes", [])
                if not any(tag in (ch.get("impact_tags") or []) for ch in changes):
                    continue
            kq = urllib.parse.quote(r["case_key"], safe="")
            out.append({
                "case_key": r["case_key"], "project_name": r["name"],
                "type": r["event_type"], "observed_at": r["detected_at"],
                "source_url": r["src"],
                "detail": json.loads(r["detail_json"]) if r["detail_json"] else None,
                "analysis": analysis,
                "free_evidence": f"{base}/case/{kq}",
                "paid_requirements": f"{base}/paid/requirements/{kq}",
            })
            if len(out) >= limit:
                break
        self._json({
            "service": "kkj-watch",
            "feed": "Japanese public procurement change events (free)",
            "filter": {"tag": tag} if tag else None,
            "available_tags": ["deadline_affecting", "eligibility_affecting", "price_affecting",
                               "document_affecting", "qa_related", "cancellation", "postponement"],
            "count": len(out),
            "events": out,
        })

    def _sample_diff(self, conn):
        """無料サンプル: 実データに近い1件の変更イベント(要件2)。外部AIが価値を理解するための入口"""
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS change_analyses (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " case_key TEXT, event_id INTEGER, kind TEXT, analysis_json TEXT, model TEXT, created_at TEXT);")
        base = self._base_url()
        row = conn.execute(
            """SELECT a.analysis_json, a.case_key, e.detected_at,
                      json_extract(c.latest_json,'$.document_uri') AS src,
                      json_extract(c.latest_json,'$.project_name') AS name
               FROM change_analyses a
               JOIN events e ON e.id=a.event_id
               JOIN cases c ON c.key=a.case_key
               WHERE a.analysis_json LIKE '%impact_tags%'
               ORDER BY a.id DESC LIMIT 50""").fetchone()
        sample = None
        if row:
            analysis = json.loads(row["analysis_json"])
            ch = next((c for c in analysis.get("changes", []) if c.get("impact_tags")),
                      (analysis.get("changes") or [None])[0])
            if ch:
                kq = urllib.parse.quote(row["case_key"], safe="")
                sample = {
                    "project_name": row["name"],
                    "event_type": ch.get("event_type"),
                    "change_category": ch.get("change_category"),
                    "impact_tags": ch.get("impact_tags"),
                    "flags": ch.get("flags"),
                    "before": ch.get("before"),
                    "after": ch.get("after"),
                    "source_quote": ch.get("source_quote"),
                    "source_url": row["src"],
                    "observed_at": row["detected_at"],
                    "confidence": ch.get("confidence"),
                    "confidence_basis": ch.get("confidence_basis"),
                    "paid_upgrade": f"{base}/paid/requirements/{kq}",
                }
        if sample is None:  # フォールバック(代表例)
            sample = {
                "event_type": "requirement_added",
                "change_category": "cost_affecting",
                "impact_tags": ["price_affecting", "document_affecting"],
                "flags": {"affects_price": True, "affects_documents": True, "requires_action": True},
                "before": None,
                "after": "クラウドサービスの利用期間は18カ月とし、本調達の費用に含めること。",
                "source_quote": "クラウドサービスの利用期間は18カ月とし、本調達の費用に含めること。",
                "source_url": "https://example.go.jp/tender/....pdf",
                "observed_at": "2026-07-03T00:15:00+09:00",
                "confidence": "high", "confidence_basis": "explicit_values_in_quote",
                "paid_upgrade": f"{base}/paid/requirements/{{key}}",
            }
        self._json({
            "service": "kkj-watch",
            "description": "Sample of a Japanese procurement change event. "
                           "Free feed: /events (filter with ?tag=). "
                           "Full structured requirements: /paid/requirements/{key} ($0.02, x402).",
            "sample": sample,
            "free_feed": f"{base}/events",
            "docs": f"{base}/llms.txt",
        })

    def _agent_json(self, conn):
        """外部エージェント向けの機械可読ディスカバリ(要件2)"""
        base = self._base_url()
        self._json({
            "service": "kkj-watch",
            "description": "Machine-readable feed of Japanese public procurement amendments, "
                           "corrections, deadline changes, and tender document changes.",
            "free_endpoints": {
                "recent_changes": f"{base}/events",
                "filter_by_impact": f"{base}/events?tag=deadline_affecting",
                "tender_search": f"{base}/cases?query=cloud",
                "sample": f"{base}/sample-diff",
                "evidence_page": f"{base}/case/{{key}}",
                "x402_select_best": f"{base}/x402/best?q=web+search&max_price_usd=0.01&min_trust=80",
                "x402_observed_trust_score": f"{base}/x402/trust/{{id-or-url}}",
                "x402_leaderboard": f"{base}/x402/leaderboard?q=search",
                "x402_trust_feed": f"{base}/x402/trust-feed.json (also .ndjson) — ingest into a catalog",
                "x402_badge": f"{base}/badge/x402/{{id}}.svg — sellers: display your trust; "
                              f"get the snippet at {base}/x402/claim/{{id}}",
                "x402_registry_changes": f"{base}/x402/changes?type=payto_changed",
                "x402_registry_search": f"{base}/x402/resources?q=search",
                "x402_sample": f"{base}/x402/sample-change",
            },
            "paid_endpoints": {
                "cached_requirements": f"{base}/paid/requirements/{{key}} ($0.02, x402 USDC on Base)",
                "on_demand_analysis": f"{base}/paid/analyze-now/{{key}} ($0.30, runs LLM extraction)",
                "x402_trust_report": f"{base}/paid/x402/report/{{id}} ($0.02, full due-diligence dossier)",
                "x402_resource_history": f"{base}/paid/x402/history/{{id}} ($0.01, history only)",
            },
            "impact_tags": ["deadline_affecting", "eligibility_affecting", "price_affecting",
                            "document_affecting", "qa_related", "cancellation", "postponement"],
            "mcp": f"{base}/mcp",
            "payment": {"protocol": "x402", "network": "base", "asset": "USDC"},
            "docs": f"{base}/llms.txt",
        })

    # ---- x402エコシステム変更検知(レジストリ差分・第2プロダクト) ----

    X402_EVENT_TYPES = ["price_changed", "payto_changed", "accepts_changed",
                        "schema_changed", "description_changed",
                        "new_resource", "delisted", "relisted"]

    def _x402_free_hint(self):
        base = self._base_url()
        return {"free_changes_feed": f"{base}/x402/changes",
                "sample": f"{base}/x402/sample-change",
                "registry_search": f"{base}/x402/resources?q=search",
                "docs": f"{base}/llms.txt"}

    def _x402_changes(self, conn, limit, etype="", severity=""):
        """無料: x402 Bazaarレジストリの変更イベントフィード(最新順)"""
        from . import x402watch
        conn.executescript(x402watch.SCHEMA_SQL)
        base = self._base_url()
        limit = min(limit, 100)
        where, params = [], []
        if etype:
            where.append("e.event_type=?")
            params.append(etype)
        if severity:
            where.append("e.severity=?")
            params.append(severity)
        sql = ("SELECT e.*, r.resource, r.service_name FROM x402_events e"
               " JOIN x402_resources r ON r.id=e.resource_id")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY e.id DESC LIMIT ?"
        params.append(limit)
        out = []
        for r in conn.execute(sql, params).fetchall():
            out.append({
                "resource": r["resource"], "service_name": r["service_name"],
                "event_type": r["event_type"], "severity": r["severity"],
                "detected_at": r["detected_at"],
                "detail": json.loads(r["detail_json"]) if r["detail_json"] else None,
                "paid_history": f"{base}/paid/x402/history/{r['resource_id']}",
            })
        self._json({
            "service": "kkj-watch / x402-registry-watch",
            "feed": "Change events in the x402 Bazaar registry: price changes, payTo (receiving "
                    "address) changes, schema changes, listings and delistings. Source: Coinbase "
                    "CDP x402 discovery API, polled hourly with SHA-256 snapshot audit trail. "
                    "Use this before paying a cached x402 endpoint: verify its terms did not change.",
            "filter": ({"type": etype} if etype else None) or ({"severity": severity} if severity else None),
            "available_types": self.X402_EVENT_TYPES,
            "available_severities": ["critical", "high", "medium", "low"],
            "count": len(out),
            "events": out,
            "paid_upgrade": f"{base}/paid/x402/history/{{resource_id}} "
                            "($0.01, x402): full snapshot history + all events for one resource.",
        })

    def _x402_resources(self, conn, limit, q=""):
        """無料: 監視中のx402レジストリ在庫の検索"""
        from . import x402watch
        conn.executescript(x402watch.SCHEMA_SQL)
        base = self._base_url()
        limit = min(limit, 100)
        if q:
            rows = conn.execute(
                "SELECT * FROM x402_resources WHERE resource LIKE ? OR service_name LIKE ?"
                " OR latest_json LIKE ? ORDER BY last_seen DESC LIMIT ?",
                (f"%{q}%", f"%{q}%", f"%{q}%", limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM x402_resources ORDER BY last_seen DESC LIMIT ?",
                (limit,)).fetchall()
        items = []
        for r in rows:
            rec = json.loads(r["latest_json"])
            prices = []
            for a in rec.get("accepts", []):
                p = {"network": a.get("network"), "amount": a.get("amount")}
                usd = x402watch.usd_of(a.get("amount"), a.get("asset"))
                if usd is not None:
                    p["usd"] = usd
                prices.append(p)
            items.append({
                "id": r["id"], "resource": r["resource"],
                "service_name": r["service_name"], "active": bool(r["active"]),
                "prices": prices,
                "first_seen": r["first_seen"], "last_seen": r["last_seen"],
                "events": f"{base}/x402/changes",
                "page_url": f"{base}/x402/e/{r['id']}",
                "trust_url": f"{base}/x402/trust/{r['id']}",
                "badge_url": f"{base}/badge/x402/{r['id']}.svg",
                "claim_badge": f"{base}/x402/claim/{r['id']}",
                "paid_history": f"{base}/paid/x402/history/{r['id']}",
            })
        total = conn.execute("SELECT COUNT(*) n FROM x402_resources").fetchone()["n"]
        active = conn.execute("SELECT COUNT(*) n FROM x402_resources WHERE active=1").fetchone()["n"]
        self._json({
            "service": "kkj-watch / x402-registry-watch",
            "registry_total": total, "registry_active": active,
            "query": q or None, "count": len(items), "items": items,
        })

    def _x402_sample(self, conn):
        """無料サンプル: 代表的なレジストリ変更イベント1件(データ形状の事前確認用)"""
        from . import x402watch
        conn.executescript(x402watch.SCHEMA_SQL)
        base = self._base_url()
        row = conn.execute(
            """SELECT e.*, r.resource, r.service_name FROM x402_events e
               JOIN x402_resources r ON r.id=e.resource_id
               WHERE e.event_type IN ('price_changed','payto_changed','delisted')
               ORDER BY e.id DESC LIMIT 1""").fetchone()
        if row is None:
            row = conn.execute(
                """SELECT e.*, r.resource, r.service_name FROM x402_events e
                   JOIN x402_resources r ON r.id=e.resource_id
                   ORDER BY e.id DESC LIMIT 1""").fetchone()
        if row is not None:
            sample = {
                "resource": row["resource"], "service_name": row["service_name"],
                "event_type": row["event_type"], "severity": row["severity"],
                "detected_at": row["detected_at"],
                "detail": json.loads(row["detail_json"]) if row["detail_json"] else None,
                "example": False,
            }
        else:  # 在庫がまだ無いときの代表例
            sample = {
                "resource": "https://api.example.com/v1/search",
                "service_name": "example-search",
                "event_type": "price_changed", "severity": "high",
                "detected_at": store.now_utc(),
                "detail": {"scheme": "exact", "network": "eip155:8453",
                           "before": "5000", "after": "10000",
                           "before_usd": 0.005, "after_usd": 0.01},
                "example": True,
            }
        self._json({
            "service": "kkj-watch / x402-registry-watch",
            "description": "Sample x402 registry change event. Free feed: /x402/changes "
                           "(filter with ?type= or ?severity=). Why it matters: if you cache "
                           "an endpoint's payment requirements, a price/payTo change can make "
                           "your next payment fail or go to the wrong address.",
            "sample": sample,
            "free_feed": f"{base}/x402/changes",
            "docs": f"{base}/llms.txt",
        })

    def _x402_find(self, conn, ident):
        """id(数値) または resource URL で1リソースを引く"""
        if ident.isdigit():
            return conn.execute("SELECT * FROM x402_resources WHERE id=?",
                                (int(ident),)).fetchone()
        return conn.execute("SELECT * FROM x402_resources WHERE resource=?",
                            (ident,)).fetchone()

    def _x402_trust(self, conn, path):
        """無料: Trust Index — 1リソースの格付け(スコア+verdict+減点根拠)"""
        from . import x402watch, x402trust
        conn.executescript(x402watch.SCHEMA_SQL)
        ident = urllib.parse.unquote(path[len("/x402/trust/"):])
        row = self._x402_find(conn, ident)
        base = self._base_url()
        if row is None:
            self._json({"error": "not_found",
                        "hint": f"Find resources for free: {base}/x402/resources?q=..."}, 404)
            return
        trust = x402trust.get_or_compute(conn, row)
        conn.commit()
        # free preview: 最新の署名付きアテステーションが利用可能か(要件11)
        latest_attestation = None
        try:
            from . import attest
            lr = attest.latest_root(conn)
            if lr is not None:
                in_root = conn.execute(
                    "SELECT 1 FROM daily_leaves WHERE date=? AND resource_id=?",
                    (lr["date"], row["id"])).fetchone() is not None
                latest_attestation = {
                    "available": in_root,
                    "date": lr["date"],
                    "root_hash": lr["root_hash"],
                    "algo": lr["algo"],
                    "public_key": lr["public_key"],
                    "paid_endpoint": f"{base}/paid/x402/attest/{row['id']} ($0.02, x402): "
                                     "signed inclusion proof + daily hash-chain root",
                    "public_root": f"{base}/x402/attestations",
                }
        except Exception:
            pass
        self._json({
            "service": "x402 Trust Index (kkj-watch)",
            "resource": row["resource"], "service_name": row["service_name"],
            "id": row["id"],
            "score_type": "observed_trust_score",
            "disclaimer": x402trust.SCORE_DISCLAIMER,
            "observed_trust_score": trust.get("score"),
            "trust": trust,
            "latest_attestation_available": latest_attestation,
            "how_scored": "Deterministic, versioned formula over observed registry history "
                          "(hourly Bazaar sync since 2026-07) and live GET-only probes. "
                          "All deductions are listed in trust.reasons — verify them yourself. "
                          "This is a risk indicator, not a safety guarantee.",
            "select_for_task": f"{base}/x402/best?q=&min_trust=80&max_price_usd=0.01",
            "full_evidence": f"{base}/paid/x402/report/{row['id']} ($0.02, x402): score + "
                             "full snapshot history + all probe results.",
            "free_feed": f"{base}/x402/changes",
            "provenance": _provenance(
                base, f"{base}/x402/trust/{row['id']}",
                f"x402 endpoint {row['resource']} observed trust",
                (latest_attestation or {}).get("root_hash")),
        })

    def _x402_scored_rows(self, conn, q=""):
        """スコア付き有効リソースを取得(q でresource/service/tags/description を絞り込み)"""
        from . import x402trust
        x402trust._migrate(conn)
        if q:
            return conn.execute(
                """SELECT * FROM x402_resources
                   WHERE active=1 AND trust_score IS NOT NULL
                     AND (resource LIKE ? OR service_name LIKE ? OR latest_json LIKE ?)
                   ORDER BY trust_score DESC, id ASC LIMIT 500""",
                (f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()
        return conn.execute(
            """SELECT * FROM x402_resources WHERE active=1 AND trust_score IS NOT NULL
               ORDER BY trust_score DESC, id ASC LIMIT 500""").fetchall()

    def _x402_leaderboard(self, conn, limit, q=""):
        """無料: 観測ベースのリスク指標で並べた上位(サービス選定の入口)"""
        from . import x402watch, x402trust
        conn.executescript(x402watch.SCHEMA_SQL)
        base = self._base_url()
        limit = min(limit, 100)
        rows = self._x402_scored_rows(conn, q)[:limit]
        items = []
        for r in rows:
            t = json.loads(r["trust_json"]) if r["trust_json"] else {}
            rec = json.loads(r["latest_json"])
            prices = []
            for a in rec.get("accepts", []):
                usd = x402watch.usd_of(a.get("amount"), a.get("asset"))
                prices.append({"network": a.get("network"), "amount": a.get("amount"),
                               **({"usd": usd} if usd is not None else {})})
            items.append({
                "id": r["id"], "resource": r["resource"], "service_name": r["service_name"],
                "observed_trust_score": r["trust_score"], "grade": t.get("grade"),
                "price_usd": x402trust.price_usd_min(rec),
                "verdicts": t.get("verdicts"), "prices": prices,
                "last_verified_at": t.get("last_verified_at"),
                "trust_detail": f"{base}/x402/trust/{r['id']}",
            })
        scored = conn.execute(
            "SELECT COUNT(*) n FROM x402_resources WHERE trust_score IS NOT NULL").fetchone()["n"]
        self._json({
            "service": "x402 Trust Index (kkj-watch)",
            "score_type": "observed_trust_score",
            "disclaimer": x402trust.SCORE_DISCLAIMER,
            "description": "Bazaar-listed x402 resources ranked by an observed, evidence-based "
                           "risk score (0-100): liveness, listing-vs-live consistency, payTo "
                           "stability, age, spam-farm detection. Filter with ?q= (keyword/tag).",
            "query": q or None,
            "scored_resources": scored,
            "count": len(items), "items": items,
            "select_for_task": f"{base}/x402/best?q=web+search&max_price_usd=0.01&min_trust=80",
            "check_any": f"{base}/x402/trust/{{id-or-url}}",
        })

    def _x402_best(self, conn, qs):
        """無料: 選定API — 用途/予算/最低スコアの条件で「使うべき1件+代替」を返す。
        エージェントが欲しいのはスコアそのものより『失敗しにくく安く信頼できる選択』"""
        from . import x402watch, x402trust
        conn.executescript(x402watch.SCHEMA_SQL)
        base = self._base_url()
        q = (qs.get("q") or qs.get("category") or qs.get("task") or [""])[0].strip()
        try:
            max_price = float((qs.get("max_price_usd") or ["0"])[0]) or None
        except ValueError:
            max_price = None
        try:
            min_trust = float((qs.get("min_trust") or ["0"])[0])
        except ValueError:
            min_trust = 0.0
        prefer_verified = (qs.get("require_live") or ["1"])[0] not in ("0", "false", "no")

        candidates = []
        for r in self._x402_scored_rows(conn, q):
            if r["trust_score"] < min_trust:
                continue
            t = json.loads(r["trust_json"]) if r["trust_json"] else {}
            rec = json.loads(r["latest_json"])
            price = x402trust.price_usd_min(rec)
            if max_price is not None and (price is None or price > max_price):
                continue
            if prefer_verified and not t.get("verdicts", {}).get("verified_live"):
                continue
            # payTo不一致(乗っ取り兆候)は選定から常に除外
            if t.get("verdicts", {}).get("payto_risk") == "live_mismatch":
                continue
            candidates.append((r, t, rec, price))

        def rank_key(item):
            r, t, rec, price = item
            return (-r["trust_score"], price if price is not None else 9e9, r["id"])
        candidates.sort(key=rank_key)

        def entry(item):
            r, t, rec, price = item
            return {
                "resource": r["resource"], "id": r["id"],
                "service_name": r["service_name"],
                "observed_trust_score": r["trust_score"], "grade": t.get("grade"),
                "price_usd": price,
                "why": x402trust.why_reasons(t),
                "caveats": x402trust.caveats(t),
                "last_verified_at": t.get("last_verified_at"),
                "trust_detail": f"{base}/x402/trust/{r['id']}",
                "full_report": f"{base}/paid/x402/report/{r['id']} ($0.02)",
            }

        recommended = entry(candidates[0]) if candidates else None
        alternatives = [entry(c) for c in candidates[1:6]]
        self._json({
            "service": "x402 Trust Index — endpoint selection (kkj-watch)",
            "score_type": "observed_trust_score",
            "disclaimer": x402trust.SCORE_DISCLAIMER,
            "query": {"q": q or None, "max_price_usd": max_price,
                      "min_trust": min_trust, "require_live": prefer_verified},
            "matched": len(candidates),
            "recommended_resource": (recommended or {}).get("resource"),
            "recommended": recommended,
            "alternatives": alternatives,
            "note": "Ranked by observed trust then lowest price. payTo-mismatch endpoints are "
                    "excluded. This is an evidence-based recommendation, not a guarantee — "
                    "check 'caveats' and verify payment terms before paying.",
        })

    def _x402_report_payload(self, conn, row):
        """完全調書: trust + 全履歴 + 全プローブ"""
        from . import x402trust, x402probe
        conn.executescript(x402probe.SCHEMA_SQL)
        payload = self._x402_history_payload(conn, row)
        payload["trust"] = x402trust.get_or_compute(conn, row)
        payload["probes"] = [
            {"probed_at": p["probed_at"], "alive": bool(p["alive"]),
             "http_status": p["http_status"], "is_402": bool(p["is_402"]),
             "latency_ms": p["latency_ms"], "consistency": p["consistency"],
             "live_accepts": json.loads(p["live_accepts_json"]) if p["live_accepts_json"] else None,
             "error": p["error"]}
            for p in conn.execute(
                "SELECT * FROM x402_probes WHERE resource_id=? ORDER BY id",
                (row["id"],)).fetchall()]
        return payload

    def _paid_x402_report(self, conn, path):
        """有料($0.02): Trust調書 — 格付け+全スナップショット履歴+全プローブ結果"""
        from . import x402_gate, x402watch, paid
        conn.executescript(x402watch.SCHEMA_SQL)
        ident = urllib.parse.unquote(path[len("/paid/x402/report/"):])
        if not x402_gate.available():
            self._json({"error": "payments_not_configured"}, 503)
            return
        row = self._x402_find(conn, ident)
        base = self._base_url()
        if row is None:
            self._json({"error": "not_found", "hint": f"Find resource ids for free at "
                        f"{base}/x402/resources?q=..."}, 404)
            return
        resource = f"{base}{path}"
        reqs = x402_gate.payment_requirements(
            resource,
            "x402 Trust Index dossier for one Bazaar resource: trust score with full scoring "
            "evidence, every registry snapshot (SHA-256 audit trail), every change event "
            "(price/payTo/schema/listing) and every live-probe result. The complete due-"
            f"diligence bundle before paying an endpoint. Free preview: {base}/x402/trust/{{id}}",
            output_schema={"input": {"type": "http", "method": "GET"}},
            price_usd=0.02,
        )
        job = self._settle_and_claim(conn, reqs, resource, f"x402r:{row['id']}",
                                     free_hint=self._x402_free_hint())
        if job is None:
            return
        if job["status"] == "succeeded" and job["result_json"]:
            self._json({"cached": True, "report": json.loads(job["result_json"]),
                        "retry_token": job["retry_token"]})
            return
        payload = self._x402_report_payload(conn, row)
        paid.finish(conn, job["retry_token"], "succeeded", payload)
        body = json.dumps({"cached": False, "report": payload,
                           "retry_token": job["retry_token"]},
                          ensure_ascii=False, indent=1).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if job["settlement"]:
            self.send_header("X-PAYMENT-RESPONSE", job["settlement"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- プログラマティックGEO: resource毎の公開リファレンスページ ----

    def _x402_entity_data(self, conn, row):
        """1 resourceの観測情報一式(ページ生成用)。全て実観測データ。"""
        from . import x402watch, x402trust, attest
        rid = row["id"]
        rec = json.loads(row["latest_json"])
        trust = json.loads(row["trust_json"]) if _row_get(row, "trust_json") else {}
        prices = []
        for a in rec.get("accepts", []):
            usd = x402watch.usd_of(a.get("amount"), a.get("asset"))
            prices.append({"network": a.get("network"), "amount": a.get("amount"),
                           "asset": a.get("asset"), "payTo": a.get("payTo"),
                           "usd": usd})
        events = [{"event_type": e["event_type"], "severity": e["severity"],
                   "detected_at": e["detected_at"],
                   "detail": json.loads(e["detail_json"]) if e["detail_json"] else None}
                  for e in conn.execute(
                      "SELECT * FROM x402_events WHERE resource_id=? ORDER BY id DESC LIMIT 20",
                      (rid,)).fetchall()]
        probes = []
        try:
            probes = [{"probed_at": p["probed_at"], "alive": bool(p["alive"]),
                       "is_402": bool(p["is_402"]), "consistency": p["consistency"]}
                      for p in conn.execute(
                          "SELECT * FROM x402_probes WHERE resource_id=? ORDER BY id DESC LIMIT 5",
                          (rid,)).fetchall()]
        except Exception:
            probes = []
        snap_count = conn.execute(
            "SELECT COUNT(*) n FROM x402_snapshots WHERE resource_id=?", (rid,)).fetchone()["n"]
        attested, root_hash, root_date = False, None, None
        try:
            lr = attest.latest_root(conn)
            if lr is not None and conn.execute(
                    "SELECT 1 FROM daily_leaves WHERE date=? AND resource_id=?",
                    (lr["date"], rid)).fetchone() is not None:
                attested, root_hash, root_date = True, lr["root_hash"], lr["date"]
        except Exception:
            pass
        return {
            "id": rid, "resource": row["resource"], "service_name": row["service_name"],
            "host": urllib.parse.urlsplit(row["resource"]).hostname or "",
            "active": bool(row["active"]),
            "first_seen": row["first_seen"], "last_seen": row["last_seen"],
            "trust_score": _row_get(row, "trust_score"),
            "grade": trust.get("grade"), "verdicts": trust.get("verdicts", {}) or {},
            "reasons": trust.get("reasons", []),
            "last_verified_at": trust.get("last_verified_at"),
            "prices": prices, "events": events, "probes": probes,
            "snapshot_count": snap_count, "probe_count": len(probes),
            "attested": attested, "attestation_root": root_hash, "attestation_date": root_date,
        }

    def _x402_indexable(self, d):
        """sitemap/インデックス対象か。制約3をベースに、attestationは全件一括で品質信号に
        ならないため「trust_scoreあり かつ 実プローブ済み(実観測)」を必須にして質を担保。
        (未プローブ=registry計算のみのページはnoindex・sitemap非掲載)"""
        return d.get("trust_score") is not None and d.get("probe_count", 0) > 0

    def _x402_entity_page(self, conn, path):
        from . import x402watch, x402trust
        conn.executescript(x402watch.SCHEMA_SQL)
        x402trust._migrate(conn)
        ident = urllib.parse.unquote(path[len("/x402/e/"):])
        row = self._x402_find(conn, ident)
        base = self._base_url()
        if row is None:
            body = (b"<!doctype html><meta name='robots' content='noindex'>"
                    b"<title>Not found</title><p>Unknown x402 resource.</p>")
            self._raw(body, "text/html; charset=utf-8", 404)
            return
        d = self._x402_entity_data(conn, row)
        indexable = self._x402_indexable(d)
        html = _render_x402_entity(base, d, indexable, x402trust.SCORE_DISCLAIMER)
        self._raw_cached(html.encode("utf-8"), "text/html; charset=utf-8", 1800)

    def _sitemap_x402(self, conn):
        """制約: trust_scoreあり かつ (プローブ済み or attestationあり) のみ掲載"""
        from . import x402watch, x402trust, attest
        conn.executescript(x402watch.SCHEMA_SQL)
        x402trust._migrate(conn)
        base = self._base_url()
        try:
            lr = attest.latest_root(conn)
            attested_date = lr["date"] if lr else None
        except Exception:
            attested_date = None
        rows = conn.execute(
            """SELECT r.id, r.last_seen,
                      (SELECT COUNT(*) FROM x402_probes p WHERE p.resource_id=r.id) AS pc
               FROM x402_resources r
               WHERE r.active=1 AND r.trust_score IS NOT NULL
               ORDER BY r.trust_score DESC, r.id ASC LIMIT 5000""").fetchall()
        _ = attested_date
        urls = []
        for r in rows:
            if (r["pc"] or 0) <= 0:
                continue                      # 実プローブ済みのみ掲載(制約3/6)
            lastmod = (r["last_seen"] or "")[:10]
            urls.append(
                f"<url><loc>{base}/x402/e/{r['id']}</loc>"
                + (f"<lastmod>{lastmod}</lastmod>" if lastmod else "")
                + "<changefreq>daily</changefreq></url>")
        body = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                + "\n".join(urls) + "\n</urlset>\n").encode("utf-8")
        self._raw_cached(body, "application/xml; charset=utf-8", 3600)

    # ---- verifiedバッジ(#3: 売り手に自分でTrustを宣伝してもらう) ----

    _GRADE_COLOR = {"A": "#4c1", "B": "#97ca00", "C": "#dfb317",
                    "D": "#fe7d37", "F": "#e05d44"}

    def _badge_fields(self, conn, row):
        """バッジ表示用フィールド(shields.io互換 + リッチ情報)を組み立てる"""
        from . import x402trust, attest
        base = self._base_url()
        label = "x402 trust"
        if row is None or not _row_get(row, "trust_score"):
            return {"schemaVersion": 1, "label": label, "message": "unrated",
                    "color": "#9f9f9f", "verdict": "unrated", "grade": None,
                    "trust_score": None, "payto_status": "unknown",
                    "attested": False, "last_verified_at": None,
                    "attestation_root": None,
                    "resource": (row["resource"] if row else None),
                    "detail_url": (f"{base}/x402/trust/{row['id']}" if row else None)}
        trust = json.loads(row["trust_json"]) if row["trust_json"] else {}
        v = trust.get("verdicts", {}) or {}
        score = row["trust_score"]
        grade = trust.get("grade")
        # 署名付きアテステーションの有無
        attested, root_hash = False, None
        try:
            lr = attest.latest_root(conn)
            if lr is not None and conn.execute(
                    "SELECT 1 FROM daily_leaves WHERE date=? AND resource_id=?",
                    (lr["date"], row["id"])).fetchone() is not None:
                attested, root_hash = True, lr["root_hash"]
        except Exception:
            pass
        payto_status = ("live_mismatch" if v.get("payto_risk") == "live_mismatch"
                        else "changed_recently" if v.get("payto_risk") == "changed_recently"
                        else "stable")
        if v.get("payto_risk") == "live_mismatch":
            message, color, verdict = "payTo mismatch", "#e05d44", "payto_mismatch"
        else:
            message = f"{grade} · {score:g}" + (" ✓" if attested else "")
            color = self._GRADE_COLOR.get(grade, "#9f9f9f")
            verdict = ("verified_live" if v.get("verified_live") else "observed")
        return {"schemaVersion": 1, "label": label, "message": message, "color": color,
                "verdict": verdict, "grade": grade, "trust_score": score,
                "payto_status": payto_status, "attested": attested,
                "last_verified_at": trust.get("last_verified_at"),
                "attestation_root": root_hash,
                "resource": row["resource"],
                "detail_url": f"{base}/x402/trust/{row['id']}",
                "witness": "kkj-watch", "license": DATA_LICENSE,
                "cite_as": f"x402 trust for {row['resource']} — observed by kkj-watch "
                           f"<{base}/x402/trust/{row['id']}>"}

    def _x402_badge(self, conn, path):
        """GET /badge/x402/{id}.svg | .json — 売り手がREADME/サイトに貼れるバッジ"""
        from . import x402watch, x402trust
        conn.executescript(x402watch.SCHEMA_SQL)
        x402trust._migrate(conn)
        rest = path[len("/badge/x402/"):]
        fmt = "svg"
        if rest.endswith(".json"):
            ident, fmt = rest[:-5], "json"
        elif rest.endswith(".svg"):
            ident, fmt = rest[:-4], "svg"
        else:
            ident = rest
        ident = urllib.parse.unquote(ident)
        row = self._x402_find(conn, ident)
        f = self._badge_fields(conn, row)
        if fmt == "json":
            body = json.dumps(f, ensure_ascii=False).encode("utf-8")
            # shields.io endpoint 互換 + 独自フィールド。CDN/camoで再取得されるので短めキャッシュ
            self._raw_cached(body, "application/json; charset=utf-8", 1800)
        else:
            svg = _svg_badge(f["label"], f["message"], f["color"])
            self._raw_cached(svg.encode("utf-8"), "image/svg+xml; charset=utf-8", 1800)

    def _x402_claim(self, conn, path):
        """GET /x402/claim/{id} — 売り手向け: 自分のバッジの貼り付けスニペットを返す"""
        from . import x402watch, x402trust
        conn.executescript(x402watch.SCHEMA_SQL)
        x402trust._migrate(conn)
        base = self._base_url()
        ident = urllib.parse.unquote(path[len("/x402/claim/"):])
        row = self._x402_find(conn, ident)
        if row is None:
            self._json({"error": "not_found",
                        "hint": f"Find your resource id for free at {base}/x402/resources?q=..."},
                       404)
            return
        rid = row["id"]
        f = self._badge_fields(conn, row)
        svg = f"{base}/badge/x402/{rid}.svg"
        detail = f"{base}/x402/trust/{rid}"
        self._json({
            "service": "x402 Trust Index — badge for sellers",
            "resource": row["resource"], "id": rid,
            "current": {"grade": f["grade"], "observed_trust_score": f["trust_score"],
                        "verdict": f["verdict"], "payto_status": f["payto_status"],
                        "attested": f["attested"]},
            "disclaimer": x402trust.SCORE_DISCLAIMER,
            "badge_svg": svg,
            "badge_json": f"{base}/badge/x402/{rid}.json",
            "snippets": {
                "markdown": f"[![x402 trust]({svg})]({detail})",
                "html": f'<a href="{detail}"><img src="{svg}" alt="x402 trust"></a>',
                "shields_endpoint":
                    f"https://img.shields.io/endpoint?url={base}/badge/x402/{rid}.json",
            },
            "note": "Displays your OBSERVED trust score (payTo/price consistency, liveness, "
                    "age, spam-farm) with a link to signed evidence. It updates automatically "
                    "as we keep observing. Not a safety guarantee.",
        })

    def _x402_trust_feed(self, conn, fmt, limit):
        """#2: 発見層(x402scan/Bazaar等)が取り込める公開Trustフィード"""
        from . import x402watch, x402trust, attest
        conn.executescript(x402watch.SCHEMA_SQL)
        x402trust._migrate(conn)
        base = self._base_url()
        # カタログ取り込み用: 既定で全件(上限5000)。?limit= 明示時のみ絞る
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            limit = min(int(q["limit"][0]), 5000) if q.get("limit") else 5000
        except ValueError:
            limit = 5000
        try:
            lr = attest.latest_root(conn)
            root_hash = lr["root_hash"] if lr else None
            root_date = lr["date"] if lr else None
        except Exception:
            root_hash = root_date = None
        rows = conn.execute(
            """SELECT * FROM x402_resources WHERE active=1 AND trust_score IS NOT NULL
               ORDER BY trust_score DESC, id ASC LIMIT ?""", (limit,)).fetchall()

        def rec(r):
            trust = json.loads(r["trust_json"]) if r["trust_json"] else {}
            v = trust.get("verdicts", {}) or {}
            payto = ("live_mismatch" if v.get("payto_risk") == "live_mismatch"
                     else "changed_recently" if v.get("payto_risk") == "changed_recently"
                     else "stable")
            return {
                "resource": r["resource"],
                "trust_score": r["trust_score"],
                "grade": trust.get("grade"),
                "verdict": ("payto_mismatch" if payto == "live_mismatch"
                            else "verified" if v.get("verified_live") else "observed"),
                "payto_status": payto,
                "last_verified_at": trust.get("last_verified_at"),
                "attestation_root": root_hash,
                "badge_url": f"{base}/badge/x402/{r['id']}.svg",
                "detail_url": f"{base}/x402/trust/{r['id']}",
                "cite_as": f"x402 trust for {r['resource']} — observed by kkj-watch "
                           f"<{base}/x402/trust/{r['id']}>",
            }
        if fmt == "ndjson":
            lines = "\n".join(json.dumps(rec(r), ensure_ascii=False) for r in rows)
            self._raw_cached((lines + "\n").encode("utf-8"),
                             "application/x-ndjson; charset=utf-8", 900)
        else:
            body = json.dumps({
                "service": "x402 Trust Index feed (kkj-watch)",
                "score_type": "observed_trust_score",
                "disclaimer": x402trust.SCORE_DISCLAIMER,
                "generated_from_root": {"date": root_date, "root_hash": root_hash},
                "count": len(rows),
                "items": [rec(r) for r in rows],
                "provenance": _provenance(base, f"{base}/x402/trust-feed.json",
                                          "x402 Trust Index feed", root_hash),
                "docs": f"{base}/llms.txt",
            }, ensure_ascii=False, indent=1).encode("utf-8")
            self._raw_cached(body, "application/json; charset=utf-8", 900)

    def _raw_cached(self, body, ctype, max_age):
        try:
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", f"public, max-age={max_age}")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    # ---- signed existence proof / cryptographic timestamp witness ----
    # 受け取るのは SHA-256 のみ。原文・秘密情報は一切受け取らず保存しない。

    def _well_known_witness(self, conn):
        """恒久的な witness identity。下流エージェントが原典(公開鍵・正典URL)を解決する終点。"""
        from . import attest
        base = self._base_url()
        lr = attest.latest_root(conn)
        pub = lr["public_key"] if lr else None
        self._json({
            "name": "kkj-watch",
            "role": "cryptographic timestamp witness & x402 observed-trust index",
            "canonical_base": base,
            "public_key": pub, "algo": "Ed25519",
            "public_roots": "https://github.com/ponpoke/kkj-watch/tree/main/roots",
            "latest_root": ({"date": lr["date"], "root_hash": lr["root_hash"]} if lr else None),
            "license": DATA_LICENSE, "license_url": DATA_LICENSE_URL,
            "attribution_required": True,
            "cite_as_template": "<subject> — observed by kkj-watch <{canonical_url}>",
            "terms": ("Data is free to use and redistribute, including by AI agents and in "
                      "model training, provided attribution to kkj-watch (this identity URL) is "
                      "preserved. Signed proofs are self-attributing and cannot be de-attributed "
                      "without invalidating them."),
            "verify": f"{base}/x402/attestations",
            "docs": f"{base}/llms.txt", "mcp": f"{base}/mcp",
        })

    def _witness_info(self, conn):
        from . import witness, x402_gate
        base = self._base_url()
        self._json({
            "service": "kkj-watch — signed existence proof (cryptographic timestamp witness)",
            "not_a_notarization": "This is NOT legal notarization. It is a tamper-evident "
                                  "hash-chain anchor: proof that a SHA-256 digest existed at or "
                                  "before a signed daily root's timestamp.",
            "privacy": "We accept and store ONLY a SHA-256 hex digest. Never send raw data, "
                       "files, contracts, logs, or personal/secret information — hash it yourself "
                       "first (sha256) and submit only the 64-char digest.",
            "how": {
                "submit": f"POST {base}/witness/anchor  body: {{\"sha256\":\"<64-hex>\"}}",
                "verify": f"GET {base}/witness/proof/{{sha256}}",
            },
            "pricing": {
                "free_per_day_per_ip": witness.FREE_PER_DAY,
                "paid_anchor_usd": witness.PRICE_USD,
                "paid_via": "x402 (USDC on Base): resubmit with X-PAYMENT when over the free quota",
            },
            "commit_schedule": "Anchors are committed into the next daily Ed25519-signed root "
                               "(~23:55 UTC), then a signed Merkle inclusion proof is available.",
            "payments_configured": x402_gate.available(),
            "docs": f"{base}/llms.txt",
        })

    def _witness_proof(self, conn, path):
        from . import attest
        sha = urllib.parse.unquote(path[len("/witness/proof/"):]).strip().lower()
        from . import witness
        norm = witness.normalize_sha256(sha)
        if norm is None:
            self._json({"error": "invalid_sha256",
                        "hint": "Provide a 64-character hex SHA-256 digest."}, 400)
            return
        out = attest.prove_anchor(norm, conn=conn)
        base = self._base_url()
        # 制約6: 公開rootとDB rootが整合する日付のproofのみ返す
        if out.get("ok") and not attest.is_proof_available(conn, out.get("date")):
            out = {"ok": False, "status": "pending_publication", "sha256": norm,
                   "note": "Committed, but its signed root is not yet publicly consistent. "
                           "The proof will be available once the root is published."}
        if out.get("ok") or out.get("status") in ("pending", "pending_publication", "checkpoint"):
            out.setdefault("verify_url", f"{base}/witness/proof/{norm}")
            out.setdefault("cli_verify", f"python -m kkj.attest prove-hash {norm}")
        if out.get("ok"):
            out["provenance"] = _provenance(
                base, f"{base}/witness/proof/{norm}",
                f"existence proof for sha256:{norm}", out.get("root_hash"), signed=True)
        status = 200 if (out.get("ok") or out.get("status") in
                         ("pending", "pending_publication", "checkpoint")) else 404
        self._json(out, status)

    def _witness_anchor(self, conn, body, client):
        """POST /witness/anchor — sha256を1件anchor。無料枠超過はx402有料。原文は受け取らない。"""
        from . import witness, x402_gate
        base = self._base_url()
        sha = witness.normalize_sha256((body or {}).get("sha256"))
        if sha is None:
            self._json({"error": "invalid_sha256",
                        "hint": "Submit only a 64-char hex SHA-256 digest in {\"sha256\":...}. "
                                "Never send raw data — hash it yourself first."}, 400)
            return
        # 冪等: 既にanchor済みなら現状を返す(二重課金しない)
        existing = witness.get(conn, sha)
        if existing is not None:
            self._json({
                "status": existing["status"], "sha256": sha,
                "already_anchored": True,
                "proof_url": f"{base}/witness/proof/{sha}",
                "note": ("Committed." if existing["status"] == "committed"
                         else "Already accepted; will be in the next daily signed root.")},
                200)
            return
        remaining, needs_payment, global_full = witness.quota_state(conn, client)
        if global_full:
            self._json({"error": "daily_capacity_reached",
                        "hint": "Global daily anchor cap reached; try again tomorrow."}, 429)
            return
        if not needs_payment:
            witness.insert(conn, sha, client, paid=False)
            self._json({
                "status": "accepted", "sha256": sha, "paid": False,
                "free_remaining_today": remaining - 1,
                "proof_url": f"{base}/witness/proof/{sha}",
                "note": "Accepted. Will be committed to the next daily Ed25519-signed root "
                        "(~23:55 UTC). This is a cryptographic timestamp witness, not legal "
                        "notarization; we stored only your digest.",
            }, 200)
            return
        # 無料枠超過 → x402有料anchor
        if not x402_gate.available():
            self._json({"error": "free_quota_exceeded",
                        "hint": f"Free quota ({witness.FREE_PER_DAY}/day) used. Paid anchoring "
                                "is not configured on this server right now."}, 429)
            return
        resource = f"{base}/witness/anchor"
        reqs = x402_gate.payment_requirements(
            resource,
            "Anchor one SHA-256 digest into the next daily Ed25519-signed hash-chain root "
            "(signed existence proof / cryptographic timestamp witness). We store only the "
            "digest, never raw data. Free quota exhausted for today.",
            price_usd=witness.PRICE_USD,
        )
        x_payment = self.headers.get("X-Payment") or self.headers.get("X-PAYMENT", "")
        if not x_payment:
            self._json(x402_gate.body_402(reqs, free={
                "free_quota_per_day": witness.FREE_PER_DAY,
                "docs": f"{base}/witness"}), 402)
            return
        ok, result = x402_gate.verify_and_settle(x_payment, reqs)
        log_payment_attempt(conn, client, resource, ok, None if ok else result[:300])
        if not ok:
            self._json(x402_gate.body_402(reqs, error=result), 402)
            return
        witness.insert(conn, sha, client, paid=True)
        body_out = json.dumps({
            "status": "accepted", "sha256": sha, "paid": True,
            "proof_url": f"{base}/witness/proof/{sha}",
            "note": "Paid anchor accepted. Will be committed to the next daily signed root "
                    "(~23:55 UTC). Cryptographic timestamp witness, not legal notarization.",
        }, ensure_ascii=False, indent=1).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-PAYMENT-RESPONSE", result)
        self.send_header("Content-Length", str(len(body_out)))
        self.end_headers()
        self.wfile.write(body_out)

    def _x402_attestations(self, conn):
        """無料: 最新の署名付き日次rootの公開情報(検証手順込み)"""
        from . import attest
        base = self._base_url()
        r = attest.latest_root(conn)
        if r is None:
            self._json({"service": "kkj-watch x402 Trust Index attestations",
                        "available": False,
                        "note": "No daily root has been generated yet."})
            return
        doc = attest._public_doc(r)
        doc["how_to_get_resource_proof"] = (
            f"{base}/paid/x402/attest/{{resource_id}} ($0.02, x402): "
            "signed Merkle inclusion proof that a resource's observed record is committed "
            "to this day's root.")
        doc["chain"] = ("Each daily root includes previous_root = prior day's root_hash, "
                        "forming a tamper-evident hash chain. Roots are also published to "
                        "GitHub for independent, time-stamped verification.")
        self._json(doc)

    def _paid_x402_attest(self, conn, path):
        """有料($0.02): 署名付きアテステーション(要件10)。
        resourceの観測記録・trust score・inclusion proof・daily root・署名・検証手順を返す。"""
        from . import x402_gate, x402watch, attest, paid
        conn.executescript(x402watch.SCHEMA_SQL)
        ident = urllib.parse.unquote(path[len("/paid/x402/attest/"):])
        if not x402_gate.available():
            self._json({"error": "payments_not_configured"}, 503)
            return
        row = self._x402_find(conn, ident)
        base = self._base_url()
        # paid-but-denied防止: 対象なし→404
        if row is None:
            self._json({"error": "not_found", "hint": f"Find resource ids for free at "
                        f"{base}/x402/resources?q=..."}, 404)
            return
        # paid-but-denied防止: まだ日次rootが無い / このresourceがrootに含まれていない→409(課金しない)
        lr = attest.latest_root(conn)
        if lr is None:
            self._json({"error": "no_attestation_yet",
                        "hint": "No daily signed root has been generated yet. No charge."}, 409)
            return
        # 制約6: 公開rootとDB rootが整合する日付のみ証明を発行(不整合なら課金しない)
        if not attest.is_proof_available(conn, lr["date"]):
            self._json({"error": "root_not_publicly_consistent",
                        "hint": "The latest signed root is not yet publicly consistent. "
                                "No charge. Try again shortly.", "date": lr["date"]}, 409)
            return
        in_root = conn.execute(
            "SELECT 1 FROM daily_leaves WHERE date=? AND resource_id=?",
            (lr["date"], row["id"])).fetchone() is not None
        if not in_root:
            self._json({"error": "not_in_latest_root",
                        "hint": "This resource is not yet committed to a signed root. No charge.",
                        "latest_root_date": lr["date"]}, 409)
            return
        resource = f"{base}{path}"
        reqs = x402_gate.payment_requirements(
            resource,
            "Signed attestation for one x402 resource: its observed record, observed trust "
            "score, a Merkle inclusion proof into that day's root, the daily hash-chain root "
            "(previous_root linked) and an Ed25519 signature, plus independent verify steps. "
            "Tamper-evident evidence of what was observed at a point in time. "
            f"Free preview: {base}/x402/trust/{row['id']}",
            output_schema={"input": {"type": "http", "method": "GET"}},
            price_usd=0.02,
        )
        job = self._settle_and_claim(conn, reqs, resource, f"x402a:{row['id']}",
                                     free_hint=self._x402_free_hint())
        if job is None:
            return
        if job["status"] == "succeeded" and job["result_json"]:
            self._json({"cached": True, "attestation": json.loads(job["result_json"]),
                        "retry_token": job["retry_token"]})
            return
        payload = self._x402_attest_payload(conn, row, lr)
        paid.finish(conn, job["retry_token"], "succeeded", payload)
        body = json.dumps({"cached": False, "attestation": payload,
                           "retry_token": job["retry_token"]},
                          ensure_ascii=False, indent=1).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if job["settlement"]:
            self.send_header("X-PAYMENT-RESPONSE", job["settlement"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _x402_attest_payload(self, conn, row, lr):
        """アテステーション本体(要件10): 観測記録+trust+inclusion proof+root+署名+検証手順"""
        from . import attest, x402trust
        proof = attest.prove_resource(row["id"], lr["date"], conn=conn)
        trust = x402trust.get_or_compute(conn, row)
        conn.commit()
        base = self._base_url()
        return {
            "service": "kkj-watch x402 Trust Index — signed attestation",
            "disclaimer": x402trust.SCORE_DISCLAIMER,
            "resource": row["resource"], "resource_id": row["id"],
            "service_name": row["service_name"],
            "observed_trust_score": trust.get("score"),
            "trust": trust,
            "observed_record": proof.get("record"),
            "attestation": {
                "date": lr["date"],
                "leaf_hash": proof.get("leaf_hash"),
                "leaf_index": proof.get("leaf_index"),
                "inclusion_proof": proof.get("inclusion_proof"),
                "merkle_root": lr["merkle_root"],
                "previous_root": lr["previous_root"],
                "root_hash": lr["root_hash"],
                "records_count": lr["records_count"],
                "algo": lr["algo"],
                "public_key": lr["public_key"],
                "signature": lr["signature"],
            },
            "verify_steps": proof.get("verify_steps"),
            "public_root": f"{base}/x402/attestations",
            "cli_verify": f"python -m kkj.attest prove-resource {row['id']} {lr['date']}",
            "provenance": _provenance(
                base, f"{base}/x402/trust/{row['id']}",
                f"signed attestation for {row['resource']}", lr["root_hash"], signed=True),
        }

    def _x402_history_payload(self, conn, row):
        """1リソースの全履歴(スナップショット+イベント)を組み立てる"""
        return {
            "resource": row["resource"], "service_name": row["service_name"],
            "active": bool(row["active"]),
            "first_seen": row["first_seen"], "last_seen": row["last_seen"],
            "current": json.loads(row["latest_json"]),
            "snapshots": [
                {"fetched_at": s["fetched_at"], "sha256": s["hash"],
                 "record": json.loads(s["raw_json"])}
                for s in conn.execute(
                    "SELECT * FROM x402_snapshots WHERE resource_id=? ORDER BY id",
                    (row["id"],)).fetchall()],
            "events": [
                {"event_type": e["event_type"], "severity": e["severity"],
                 "detected_at": e["detected_at"],
                 "detail": json.loads(e["detail_json"]) if e["detail_json"] else None}
                for e in conn.execute(
                    "SELECT * FROM x402_events WHERE resource_id=? ORDER BY id",
                    (row["id"],)).fetchall()],
        }

    def _paid_x402_history(self, conn, path):
        """有料($0.01): 1リソースの全スナップショット履歴+全変更イベント(監査証跡)"""
        from . import x402_gate, x402watch, paid
        conn.executescript(x402watch.SCHEMA_SQL)
        ident = urllib.parse.unquote(path[len("/paid/x402/history/"):])
        if not x402_gate.available():
            self._json({"error": "payments_not_configured"}, 503)
            return
        if ident.isdigit():
            row = conn.execute("SELECT * FROM x402_resources WHERE id=?", (int(ident),)).fetchone()
        else:
            row = conn.execute("SELECT * FROM x402_resources WHERE resource=?", (ident,)).fetchone()
        base = self._base_url()
        # paid-but-denied防止: 対象が無ければ支払い要求(402)を出さず404
        if row is None:
            self._json({"error": "not_found", "hint": f"Find resource ids for free at "
                        f"{base}/x402/resources?q=..."}, 404)
            return
        resource = f"{base}{path}"
        case_key = f"x402:{row['id']}"
        reqs = x402_gate.payment_requirements(
            resource,
            "Full change history for one x402 Bazaar resource: every snapshot (SHA-256 audit "
            "trail) and every change event (price_changed / payto_changed / schema_changed / "
            "delisted) since monitoring began. Use it to verify an endpoint's payment terms "
            f"before paying. Find ids for free: {base}/x402/resources",
            output_schema={"input": {"type": "http", "method": "GET"}},
            price_usd=0.01,
        )
        job = self._settle_and_claim(conn, reqs, resource, case_key,
                                     free_hint=self._x402_free_hint())
        if job is None:
            return   # 402 / 409 応答は送信済み
        if job["status"] == "succeeded" and job["result_json"]:
            self._json({"cached": True, "history": json.loads(job["result_json"]),
                        "retry_token": job["retry_token"]})
            return
        payload = self._x402_history_payload(conn, row)
        paid.finish(conn, job["retry_token"], "succeeded", payload)
        body = json.dumps({"cached": False, "history": payload,
                           "retry_token": job["retry_token"]},
                          ensure_ascii=False, indent=1).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if job["settlement"]:
            self.send_header("X-PAYMENT-RESPONSE", job["settlement"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _openapi(self, conn):
        """OpenAPI 3.1(最小): /openapi.json への実アクセス(数百/日)が404だったのを解消"""
        base = self._base_url()
        def op(summary, params=None, paid=False):
            o = {"summary": summary, "responses": {"200": {"description": "OK"}}}
            if paid:
                o["responses"]["402"] = {"description": "x402 Payment Required (USDC on Base)"}
            if params:
                o["parameters"] = [{"name": p, "in": "query", "required": False,
                                    "schema": {"type": "string"}} for p in params]
            return {"get": o}
        self._json({
            "openapi": "3.1.0",
            "info": {
                "title": "kkj-watch",
                "version": "0.2.0",
                "description": "Two machine-readable change-detection feeds: "
                    "(1) Japanese public procurement changes (corrections, deadline changes, "
                    "document replacements) with impact tags and evidence; "
                    "(2) x402 Bazaar registry changes (price/payTo/schema/listing) with "
                    "SHA-256 snapshot audit trail. Free feeds + x402-paid evidence endpoints.",
            },
            "servers": [{"url": base}],
            "paths": {
                "/events": op("Japanese procurement change events (free)", ["tag", "limit"]),
                "/cases": op("Search monitored tenders (free)", ["query", "limit"]),
                "/cases/{key}": op("Full evidence for one tender (free)"),
                "/sample-diff": op("Sample procurement change event (free)"),
                "/x402/changes": op("x402 Bazaar registry change events (free)",
                                    ["type", "severity", "limit"]),
                "/x402/resources": op("Search the monitored x402 registry (free)", ["q", "limit"]),
                "/x402/best": op("Select the best x402 endpoint for a task/budget (free)",
                                 ["q", "category", "max_price_usd", "min_trust", "require_live"]),
                "/x402/trust/{id}": op("Observed trust score 0-100 + verdicts (free, not a guarantee)"),
                "/x402/leaderboard": op("x402 resources ranked by observed trust score (free)",
                                        ["q", "limit"]),
                "/x402/sample-change": op("Sample registry change event (free)"),
                "/paid/requirements/{key}": op(
                    "Structured bidding requirements, $0.02 via x402", paid=True),
                "/paid/analyze-now/{key}": op(
                    "On-demand LLM extraction, $0.30 via x402", paid=True),
                "/paid/x402/history/{id}": op(
                    "Full snapshot+event history for one x402 resource, $0.01 via x402",
                    paid=True),
                "/paid/x402/report/{id}": op(
                    "Trust dossier: score+evidence+history+probes, $0.02 via x402", paid=True),
                "/paid/x402/attest/{id}": op(
                    "Signed attestation: inclusion proof + daily hash-chain root, $0.02 via x402",
                    paid=True),
                "/x402/attestations": op("Latest signed daily hash-chain root (free)"),
            },
        })

    def _agent_card(self, conn):
        """A2A風の最小エージェントカード(/.well-known/agent-card.json への実アクセス対応)"""
        base = self._base_url()
        self._json({
            "name": "kkj-watch",
            "description": "Change-detection feeds for machines: Japanese public procurement "
                           "changes, and x402 Bazaar registry changes (price/payTo/schema/"
                           "listing) with audit trail. Free JSON feeds; paid evidence via "
                           "x402 (USDC on Base), no account needed.",
            "url": base,
            "version": "0.2.0",
            "documentationUrl": f"{base}/llms.txt",
            "capabilities": {"streaming": False, "pushNotifications": False},
            "defaultInputModes": ["application/json"],
            "defaultOutputModes": ["application/json"],
            "skills": [
                {"id": "procurement_changes",
                 "name": "Japanese procurement change feed",
                 "description": f"GET {base}/events?tag=deadline_affecting (free)"},
                {"id": "x402_select_best",
                 "name": "x402 endpoint selection",
                 "description": f"GET {base}/x402/best?q=web+search&max_price_usd=0.01 (free) — "
                                "recommended endpoint + why, by observed risk score & price"},
                {"id": "x402_trust_index",
                 "name": "x402 Trust Index (observed risk score)",
                 "description": f"GET {base}/x402/trust/{{id-or-url}} (free) — observed, "
                                "evidence-based risk score before paying any x402 endpoint"},
                {"id": "x402_registry_changes",
                 "name": "x402 registry change feed",
                 "description": f"GET {base}/x402/changes?type=payto_changed (free)"},
                {"id": "x402_trust_report",
                 "name": "x402 trust dossier",
                 "description": f"GET {base}/paid/x402/report/{{id}} ($0.02 via x402)"},
            ],
        })

    def _raw(self, body, ctype, status=200):
        try:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _well_known_x402(self, conn):
        """x402 V2 Discovery: 販売リソースの機械可読マニフェスト"""
        from . import x402_gate, extractor
        base = self._base_url()
        resources = []
        if x402_gate.available():
            reqs = x402_gate.payment_requirements(
                f"{base}/paid/requirements/latest",
                "Structured bidding requirements for the newest Japanese government tender "
                "(qualifications, rank A-D, documents, deadlines) as JSON. "
                f"Replace 'latest' with any case key from {base}/cases (free).",
                output_schema={"input": {"type": "http", "method": "GET"},
                               "output": extractor.EXTRACT_SCHEMA},
            )
            resources.append({
                "resource": f"{base}/paid/requirements/latest",
                "type": "http", "method": "GET",
                "x402Version": 1,
                "accepts": [reqs],
                "lastUpdated": store.now_utc(),
            })
            hist_reqs = x402_gate.payment_requirements(
                f"{base}/paid/x402/history/1",
                "Full change history (SHA-256 snapshot audit trail + price/payTo/schema/listing "
                "change events) for one x402 Bazaar resource. Verify an endpoint's payment "
                f"terms before paying it. Find resource ids for free: {base}/x402/resources",
                output_schema={"input": {"type": "http", "method": "GET"}},
                price_usd=0.01,
            )
            resources.append({
                "resource": f"{base}/paid/x402/history/1",
                "type": "http", "method": "GET",
                "x402Version": 1,
                "accepts": [hist_reqs],
                "lastUpdated": store.now_utc(),
            })
            report_reqs = x402_gate.payment_requirements(
                f"{base}/paid/x402/report/1",
                "x402 Trust Index dossier: trust score (liveness, listing-vs-live consistency, "
                "payTo stability, spam-farm detection) with full evidence — every registry "
                "snapshot, change event and live-probe result for one Bazaar resource. "
                f"Free preview: {base}/x402/trust/{{id}} and {base}/x402/leaderboard",
                output_schema={"input": {"type": "http", "method": "GET"}},
                price_usd=0.02,
            )
            resources.append({
                "resource": f"{base}/paid/x402/report/1",
                "type": "http", "method": "GET",
                "x402Version": 1,
                "accepts": [report_reqs],
                "lastUpdated": store.now_utc(),
            })
            attest_reqs = x402_gate.payment_requirements(
                f"{base}/paid/x402/attest/1",
                "Signed attestation for one x402 resource: observed record + observed trust "
                "score + Merkle inclusion proof into a daily Ed25519-signed hash-chain root "
                "(linked to the previous day). Tamper-evident evidence of what was observed at "
                f"a point in time. Free preview: {base}/x402/attestations",
                output_schema={"input": {"type": "http", "method": "GET"}},
                price_usd=0.02,
            )
            resources.append({
                "resource": f"{base}/paid/x402/attest/1",
                "type": "http", "method": "GET",
                "x402Version": 1,
                "accepts": [attest_reqs],
                "lastUpdated": store.now_utc(),
            })
        self._json({
            "x402Version": 1,
            "name": "kkj-watch",
            "description": "Change-detection for machines: (1) Japanese government tender "
                           "(kkj.go.jp) changes + structured bidding requirements; "
                           "(2) x402 Bazaar registry changes (price/payTo/schema/listing) "
                           "with audit trail. Machine-payable via x402.",
            "docs": f"{base}/llms.txt",
            "mcp": f"{base}/mcp",
            "free_feeds": [f"{base}/events", f"{base}/x402/changes"],
            "resources": resources,
        })

    def _sitemap(self, conn):
        base = self._base_url()
        rows = conn.execute("SELECT key, last_seen FROM cases ORDER BY first_seen DESC LIMIT 5000").fetchall()
        parts = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
                 f"<url><loc>{base}/</loc></url>"]
        for r in rows:
            k = urllib.parse.quote(r["key"], safe="")
            parts.append(f"<url><loc>{base}/case/{k}</loc><lastmod>{r['last_seen'][:10]}</lastmod></url>")
        parts.append("</urlset>")
        self._raw("\n".join(parts).encode("utf-8"), "application/xml; charset=utf-8")

    def _case_page(self, conn, path):
        """案件別HTMLページ(検索エンジン・AIクローラ向けの長尾コンテンツ)"""
        import html as H
        key = urllib.parse.unquote(path[len("/case/"):])
        row = conn.execute("SELECT * FROM cases WHERE key=?", (key,)).fetchone()
        if row is None:
            self._json({"error": "not_found"}, 404)
            return
        rec = json.loads(row["latest_json"])
        name = H.escape(rec.get("project_name") or "案件")
        org = H.escape(rec.get("organization_name") or "")
        base = self._base_url()
        ext = conn.execute("SELECT result_json FROM extractions WHERE case_key=?", (key,)).fetchone()
        events = conn.execute(
            "SELECT event_type, detected_at, detail_json FROM events WHERE case_key=? ORDER BY id", (key,)
        ).fetchall()

        req_html = ""
        if ext:
            e = json.loads(ext["result_json"])
            rows_html = ""
            if e.get("unified_qualification_rank"):
                rows_html += f"<tr><th>統一資格 等級</th><td>{H.escape(e['unified_qualification_rank'])}</td></tr>"
            if e.get("bid_method"):
                rows_html += f"<tr><th>入札方式</th><td>{H.escape(e['bid_method'])}</td></tr>"
            if e.get("performance_period"):
                rows_html += f"<tr><th>履行期間</th><td>{H.escape(e['performance_period'])}</td></tr>"
            for d in e.get("deadlines", [])[:6]:
                rows_html += f"<tr><th>{H.escape(d['label'])}</th><td>{H.escape(d['value'])}</td></tr>"
            quals = "".join(f"<li>{H.escape(q)}</li>" for q in e.get("qualifications", [])[:10])
            docs = "".join(f"<li>{H.escape(d)}</li>" for d in e.get("required_documents", [])[:15])
            req_html = (f"<h2>応募要件(構造化)</h2><table>{rows_html}</table>"
                        f"<h3>参加資格</h3><ul>{quals}</ul><h3>提出書類</h3><ul>{docs}</ul>")

        ev_html = "".join(
            f"<li>[{H.escape(ev['event_type'])}] {H.escape(ev['detected_at'][:19])}</li>" for ev in events)
        # </script>によるタグ脱出を防止(<\/ にエスケープ)
        jsonld = json.dumps({
            "@context": "https://schema.org", "@type": "Dataset",
            "name": rec.get("project_name"),
            "description": f"{org}の入札案件。変更検知・応募要件の構造化データ(kkj-watch)。",
            "url": f"{base}/case/{urllib.parse.quote(key, safe='')}",
            "creator": {"@type": "Organization", "name": "kkj-watch"},
            "isBasedOn": rec.get("document_uri"),
        }, ensure_ascii=False).replace("</", "<\\/")

        doc_uri = rec.get("document_uri") or ""
        if not doc_uri.lower().startswith(("http://", "https://")):
            doc_uri = ""  # javascript:等の危険スキームは描画しない
        page = f"""<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{name} | 入札案件の変更監視 - kkj-watch</title>
<meta name="description" content="{org}「{name}」の変更履歴(訂正・締切変更・様式差替え)と応募要件の構造化データ。">
<script type="application/ld+json">{jsonld}</script>
<style>body{{font-family:system-ui,'Hiragino Sans',sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;line-height:1.8;color:#222}}
h1{{font-size:1.3rem}}table{{border-collapse:collapse}}td,th{{border:1px solid #ddd;padding:.3rem .6rem;font-size:.92rem;text-align:left}}
a{{color:#0a6}}</style></head><body>
<p><a href="/">← kkj-watch</a></p>
<h1>{name}</h1>
<p>発注機関: {org} / 公告日: {H.escape((rec.get('cft_issue_date') or '')[:10])} /
<a href="{H.escape(rec.get('document_uri') or '#')}" rel="nofollow">原典公告</a></p>
{req_html}
<h2>変更監視ログ</h2><ul>{ev_html}</ul>
<p>この案件は3時間おきに監視されています。訂正公告・締切変更・様式差替えの検知は
<a href="/">kkj-watch</a>(API/MCP/x402対応)で。</p>
</body></html>"""
        self._raw(page.encode("utf-8"), "text/html; charset=utf-8")

    def _free_hint(self, case_key):
        base = self._base_url()
        kq = urllib.parse.quote(case_key, safe="")
        return {"free_preview": f"{base}/case/{kq}",
                "free_recent_events": f"{base}/events",
                "sample_diff": f"{base}/sample-diff",
                "paid_upgrade": f"{base}/paid/requirements/{kq}"}

    def _settle_and_claim(self, conn, reqs, resource, case_key, free_hint=None):
        """x402支払いゲート+ジョブ確保。戻り値: job行(成功) / None(応答送信済み)。
        同一支払いの再送は再settleせず既存ジョブを返す(冪等)。別resource再利用は409。"""
        from . import x402_gate, paid
        if free_hint is None:
            free_hint = self._free_hint(case_key)
        x_payment = self.headers.get("X-Payment") or self.headers.get("X-PAYMENT", "")
        if not x_payment:
            self._json(x402_gate.body_402(reqs, free=free_hint), 402)
            return None
        ph = paid.payment_hash(x_payment)
        # 冪等化: 同一X-PAYMENTが既に記録済みなら再settleしない
        existing = paid.get_by_payment(conn, ph)
        if existing is not None:
            if existing["resource"] != resource:
                self._json({"error": "payment_reused",
                            "hint": "この支払いは別のリソースで既に使用されています。"}, 409)
                return None
            return existing   # 同一payment+同一resource → 既存ジョブを返す(再settleなし)
        # 新規支払い → ファシリテータで検証・決済
        ok, result = x402_gate.verify_and_settle(x_payment, reqs)
        log_payment_attempt(conn, self._client_ip(), resource, ok,
                            None if ok else result[:300])
        if not ok:
            self._json(x402_gate.body_402(reqs, error=result, free=free_hint), 402)
            return None
        job, err = paid.claim(conn, ph, resource, case_key, result)
        if err == "payment_reused":   # 競合(同時リクエスト)時の保険
            self._json({"error": "payment_reused"}, 409)
            return None
        return job

    MAX_ANALYZE_INPUT_CHARS = 60000

    def _paid_analyze_now(self, conn, path):
        """新規LLM実行を伴う高額エンドポイント($0.30)。ポチった案件だけ課金・解析する。
        支払い要求(402)を出す前に全ての事前確認を行い、paid-but-denied を防ぐ。"""
        from . import x402_gate, extractor, llm_budget, paid
        key = urllib.parse.unquote(path[len("/paid/analyze-now/"):])
        if not x402_gate.available():
            self._json({"error": "payments_not_configured"}, 503)
            return
        if key == "latest":
            r = conn.execute("SELECT key FROM cases ORDER BY first_seen DESC LIMIT 1").fetchone()
            if r:
                key = r["key"]
        row = conn.execute("SELECT latest_json FROM cases WHERE key=?", (key,)).fetchone()
        if row is None:                                   # 要件2: 案件存在確認
            self._json({"error": "not_found", "case_key": key}, 404)
            return
        base = self._base_url()
        resource = f"{base}{path}"

        # 要件3: 支払い済みジョブの retry_token 持参時は、再支払いなしで結果を返す
        token = (self.headers.get("X-Retry-Token")
                 or urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("retry_token", [""])[0])
        if token:
            job = paid.get(conn, token)
            # retry_token は秘密トークン(所持=支払い証跡)。ホスト非依存で case_key に紐付けて照合
            if job is not None and job["case_key"] == key:
                if job["status"] == "succeeded" and job["result_json"]:
                    self._json({"cached": True, "requirements": json.loads(job["result_json"]),
                                "retry_token": token})
                else:
                    self._run_analysis_job(conn, token, key, None)
                return
            self._json({"error": "invalid_retry_token"}, 403)
            return

        # 要件1,2: 既に解析済みでも、未払いでは requirements 本体を返さない($0.02課金の迂回を防止)
        cached = conn.execute("SELECT 1 FROM extractions WHERE case_key=?", (key,)).fetchone()
        if cached is not None:
            self._json({
                "error": "already_analyzed",
                "hint": "この案件は既に解析済みです。構造化データは /paid/requirements/{key} ($0.02) から取得してください。",
                "requirements_url": f"{base}/paid/requirements/{urllib.parse.quote(key, safe='')}",
            }, 409)
            return
        # 要件2,3: 支払い要求の前にLLM可用性・予算・入力サイズを確認。失敗時は402を出さない
        if not extractor.available():
            self._json({"error": "llm_unavailable",
                        "hint": "現在この案件の新規解析はできません(APIキー未設定または残高不足)。"
                                "支払いは発生しません。"}, 503)
            return
        can, reason = llm_budget.can_spend(conn)
        if not can:
            self._json({"error": "budget_exceeded", "reason": reason,
                        "hint": "LLM予算上限に達しています。支払いは発生しません。時間をおいて再度お試しください。"}, 429)
            return
        rec = json.loads(row["latest_json"])
        text = rec.get("project_description") or rec.get("project_name") or ""
        if len(text) > self.MAX_ANALYZE_INPUT_CHARS:      # 要件2: 入力サイズ上限
            self._json({"error": "input_too_large",
                        "chars": len(text), "limit": self.MAX_ANALYZE_INPUT_CHARS,
                        "hint": "対象文書が大きすぎます。支払いは発生しません。"}, 413)
            return

        reqs = x402_gate.payment_requirements(
            resource,
            "On-demand LLM analysis of a Japanese government tender: extract structured "
            "bidding requirements (qualifications, rank, documents, deadlines) as validated JSON. "
            "新規にClaude抽出を実行して返します。",
            output_schema={"input": {"type": "http", "method": "GET"},
                           "output": extractor.EXTRACT_SCHEMA},
            price_usd=0.30,
        )
        job = self._settle_and_claim(conn, reqs, resource, key)
        if job is None:
            return   # 402 / 409 応答は送信済み
        # 既に完了済みのジョブ(同一支払いの再送)ならその結果を返す
        if job["status"] == "succeeded" and job["result_json"]:
            self._json({"cached": True, "requirements": json.loads(job["result_json"]),
                        "retry_token": job["retry_token"]})
            return
        self._run_analysis_job(conn, job["retry_token"], key, job["settlement"])

    def _run_analysis_job(self, conn, token, key, settlement):
        """支払い済みジョブのLLM解析を実行。失敗しても再支払いなしで再実行できるよう記録する"""
        from . import extractor, semantic, paid, llm_budget
        try:
            payload = extractor.extract_case(conn, key, force=True)
            conn.commit()
            if payload is None:
                raise RuntimeError("no_extractable_text")
            llm_budget.record_call(conn, f"analyze:{key}")   # 月次コスト追跡に計上
            paid.finish(conn, token, "succeeded", payload)
            resp = {"cached": False, "requirements": payload, "retry_token": token}
            status = 200
        except semantic.BudgetExceeded as e:
            paid.finish(conn, token, "pending", error=f"budget:{e}")
            resp = {"status": "pending", "retry_token": token, "reason": str(e),
                    "hint": "支払いは成立しています。予算回復後に GET /paid/job/{retry_token} で再取得できます(再支払い不要)。"}
            status = 202
        except Exception as e:
            paid.finish(conn, token, "pending", error=str(e)[:300])
            resp = {"status": "pending", "retry_token": token, "reason": str(e)[:200],
                    "hint": "支払いは成立しています。GET /paid/job/{retry_token} で再取得できます(再支払い不要)。"}
            status = 202
        body = json.dumps(resp, ensure_ascii=False, indent=1).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if settlement:
            self.send_header("X-PAYMENT-RESPONSE", settlement)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _paid_job(self, conn, path):
        """要件4: 支払い済みジョブの再取得・再実行(再支払い不要)"""
        from . import paid
        token = urllib.parse.unquote(path[len("/paid/job/"):])
        job = paid.get(conn, token)
        if job is None:
            self._json({"error": "job_not_found"}, 404)
            return
        if job["status"] == "succeeded" and job["result_json"]:
            self._json({"cached": True, "requirements": json.loads(job["result_json"]),
                        "retry_token": token})
            return
        # 未完了 → 再実行(既に支払い済みなので課金しない)
        if job["case_key"].startswith(("x402:", "x402r:", "x402a:")):
            # x402履歴/調書/アテステーションジョブ: LLM不要。データを再構築して完了させる
            from . import x402watch, attest, paid
            conn.executescript(x402watch.SCHEMA_SQL)
            kind = ("attest" if job["case_key"].startswith("x402a:") else
                    "report" if job["case_key"].startswith("x402r:") else "history")
            rid = int(job["case_key"].split(":", 1)[1])
            row = conn.execute("SELECT * FROM x402_resources WHERE id=?", (rid,)).fetchone()
            if row is None:
                self._json({"error": "resource_gone", "retry_token": token}, 410)
                return
            if kind == "attest":
                lr = attest.latest_root(conn)
                if lr is None:
                    self._json({"error": "no_attestation_yet", "retry_token": token}, 409)
                    return
                payload = self._x402_attest_payload(conn, row, lr)
                key = "attestation"
            elif kind == "report":
                payload = self._x402_report_payload(conn, row)
                key = "report"
            else:
                payload = self._x402_history_payload(conn, row)
                key = "history"
            paid.finish(conn, token, "succeeded", payload)
            self._json({"cached": True, key: payload, "retry_token": token})
            return
        self._run_analysis_job(conn, token, job["case_key"], None)

    def _paid_requirements(self, conn, path):
        """x402有料エンドポイント: 応募要件の構造化JSONを$X402_PRICE_USD/コールで販売

        key='latest' は最新の抽出済み案件(エージェントがキー不明でも購入可能)
        """
        from . import x402_gate, extractor, paid
        key = urllib.parse.unquote(path[len("/paid/requirements/"):])
        if not x402_gate.available():
            self._json({"error": "payments_not_configured",
                        "hint": "無料ティア(GET /cases/{key})または有償キーをご利用ください"}, 503)
            return
        if key == "latest":
            row = conn.execute(
                "SELECT case_key FROM extractions ORDER BY extracted_at DESC LIMIT 1"
            ).fetchone()
            if row:
                key = row["case_key"]
        base = self._base_url()
        # 要件1: 案件が存在しなければ404(支払い要求を出さない)
        if conn.execute("SELECT 1 FROM cases WHERE key=?", (key,)).fetchone() is None:
            self._json({"error": "not_found", "case_key": key}, 404)
            return
        # 要件1: キャッシュ済みデータが無ければ402を出さず409(paid-but-denied防止)
        cached = conn.execute("SELECT result_json FROM extractions WHERE case_key=?", (key,)).fetchone()
        if cached is None:
            self._json({
                "error": "cache_not_available",
                "hint": "この案件はまだ構造化されていません。支払いは不要です。"
                        "新規解析が必要な場合は /paid/analyze-now/{key} ($0.30)、"
                        "無料の生データは /cases/{key} をご利用ください。",
                "analyze_now": f"{base}/paid/analyze-now/{urllib.parse.quote(key, safe='')}",
                "free_alternative": f"{base}/cases/{urllib.parse.quote(key, safe='')}",
            }, 409)
            return
        resource = f"{base}{path}"
        reqs = x402_gate.payment_requirements(
            resource,
            "Structured bidding requirements for a Japanese government tender (kkj.go.jp): "
            "qualifications, unified qualification rank (A-D), required certifications, "
            "document checklist, deadlines, bid method — as validated JSON. "
            f"Use path segment 'latest' for the newest tender, or find case keys for free at "
            f"{base}/cases?limit=20 (field: key). Docs: {base}/llms.txt "
            "/ 日本の官公需(入札)案件の応募要件を構造化JSONで返す。",
            output_schema={
                "input": {
                    "type": "http", "method": "GET",
                    "discovery": {
                        "how_to_find_keys": f"GET {base}/cases?limit=20 (free, no auth) -> items[].key",
                        "zero_knowledge_option": f"GET {base}/paid/requirements/latest",
                    },
                },
                "output": extractor.EXTRACT_SCHEMA,
            },
        )
        job = self._settle_and_claim(conn, reqs, resource, key)
        if job is None:
            return   # 402 / 409 応答は送信済み
        # キャッシュ済みデータを返す(裏でLLMを呼ばない=赤字防止)
        payload = json.loads(cached["result_json"])
        paid.finish(conn, job["retry_token"], "succeeded", payload)
        body = json.dumps({"cached": True, "requirements": payload,
                           "retry_token": job["retry_token"]},
                          ensure_ascii=False, indent=1).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        if job["settlement"]:
            self.send_header("X-PAYMENT-RESPONSE", job["settlement"])
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _client_ip(self):
        """リバースプロキシ(Caddy)経由の場合はX-Forwarded-Forから実IPを得る"""
        ip = self.client_address[0]
        if ip in ("127.0.0.1", "::1"):
            xff = self.headers.get("X-Forwarded-For", "")
            if xff:
                return xff.split(",")[0].strip()
        return ip

    # 公開埋め込み(バッジ・feed・claim)は無償ティア上限の対象外。README等に貼られた
    # バッジがGitHub camo経由で集中アクセスされても壊れないようにする
    _NO_LIMIT_PREFIXES = ("/badge/", "/x402/trust-feed", "/x402/claim", "/witness",
                          "/x402/e/", "/sitemap")

    def _identify(self, conn, path=""):
        """APIキー検証+無償ティアの日次上限。戻り値: (client識別子, エラー or None)"""
        from . import billing
        api_key = self.headers.get("X-API-Key", "")
        if api_key:
            rec = billing.check(conn, api_key)
            if rec is None:
                return None, (401, {"error": "invalid_api_key"})
            return f"key:{rec['name']}", None
        ip = self._client_ip()
        if any(path.startswith(p) for p in self._NO_LIMIT_PREFIXES):
            return ip, None
        if ip not in ("127.0.0.1", "::1") and billing.over_free_limit(conn, ip):
            return None, (429, {"error": "free_tier_daily_limit",
                                "hint": "X-API-Key ヘッダで有償キーを指定してください"})
        return ip, None

    def _read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_000_000:
                return {}
            return json.loads(self.rfile.read(length))
        except Exception:
            return None

    def do_POST(self):
        """POST: /mcp(JSON-RPC) と /witness/anchor(存在証明: sha256のみ)を受け付ける"""
        parsed = urllib.parse.urlparse(self.path)
        ppath = parsed.path.rstrip("/")
        if ppath == "/witness/anchor":
            conn = store.connect()
            try:
                client, err = self._identify(conn, "/witness/anchor")
                if err:
                    self._json(err[1], err[0])
                    return
                log_usage(conn, client, self.headers.get("User-Agent"), "/witness/anchor",
                          is_test=bool(self.headers.get("X-KKJ-Test")))
                body = self._read_json_body()
                if body is None:
                    self._json({"error": "invalid_json"}, 400)
                    return
                self._witness_anchor(conn, body, client)
            finally:
                conn.close()
            return
        if ppath != "/mcp":
            self._json({"error": "not_found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            msg = json.loads(self.rfile.read(length))
        except Exception:
            self._json({"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "parse error"}}, 400)
            return
        conn = store.connect()
        try:
            client, err = self._identify(conn)
            if err:
                self._json(err[1], err[0])
                return
            log_usage(conn, client, self.headers.get("User-Agent"), "/mcp")
        finally:
            conn.close()
        from . import mcp_server
        resp = mcp_server.handle(msg)
        if resp is None:  # 通知にはボディなしで応答
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._json(resp)

    def log_message(self, fmt, *args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8787
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"kkj-watch API: http://127.0.0.1:{port}/")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
