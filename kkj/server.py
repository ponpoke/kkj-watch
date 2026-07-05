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

## x402 registry watch (free feed)

- GET /x402/changes : recent registry change events (price_changed | payto_changed | accepts_changed |
  schema_changed | description_changed | new_resource | delisted | relisted)
- GET /x402/changes?type=payto_changed : receiving-address changes (possible wallet rotation/hijack —
  verify before paying). ?severity=critical works too.
- GET /x402/resources?q=search : search the monitored registry inventory (returns resource ids)
- GET /x402/sample-change : one representative event, so an agent can see the data shape before buying
- GET /paid/x402/history/{id} : PAID $0.01 via x402 — full audit trail for one resource:
  every snapshot (SHA-256) and every change event since monitoring began.

Why agents use it: if you cache an endpoint's 402 payment requirements, a silent price or payTo change
makes your next payment fail — or pay the wrong address. This feed is the cheap check.

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

## MCP (Streamable HTTP: POST /mcp)

Tools (purpose-named): list_x402_registry_changes (free, ?type= filter) /
list_japan_procurement_changes (free, ?tag= filter) / find_tender_deadline_changes (free keyword search) /
get_tender_change_evidence (free, full evidence) / get_cached_tender_requirements (cached requirements).

## When to use what

- About to pay an x402 endpoint you saw before? -> GET /x402/changes?type=price_changed (free).
- Need the full audit trail of one x402 resource? -> GET /paid/x402/history/{id} ($0.01).
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
                    "/x402/changes", "/x402/resources", "/x402/sample-change")


def classify_usage(path, user_agent, query_has_filter):
    """アクセスを probe_access / free_agent_use / paid_intent に分類(paid_conversionは決済ログ側)"""
    ua = user_agent or ""
    if path.startswith("/paid/"):
        return "paid_intent"
    is_data = (path in _FREE_DATA_PATHS or path.startswith("/cases"))
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
    return {
        "unique_clients": uniq, "sustained_7d_clients": sustained,
        "gate": "unique>=10 and sustained>=3",
        "funnel": {
            "probe_access": uniq_of("probe_access"),
            "free_agent_use": uniq_of("free_agent_use"),
            "paid_intent": uniq_of("paid_intent"),
            "paid_conversion": paid_conv,
        },
    }


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
            client, err = self._identify(conn)
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
                    from . import x402watch
                    out["x402_registry"] = x402watch.stats(conn)
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
            elif path.startswith("/paid/x402/history/"):
                self._paid_x402_history(conn, path)
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
                body = (f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n"
                        f"# AI agents: {base}/llms.txt and {base}/.well-known/x402.json\n").encode()
                self._raw(body, "text/plain; charset=utf-8")
            elif path in ("/.well-known/x402", "/.well-known/x402.json"):
                self._well_known_x402(conn)
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
                "x402_registry_changes": f"{base}/x402/changes?type=price_changed",
                "x402_registry_search": f"{base}/x402/resources?q=search",
                "x402_sample": f"{base}/x402/sample-change",
            },
            "paid_endpoints": {
                "cached_requirements": f"{base}/paid/requirements/{{key}} ($0.02, x402 USDC on Base)",
                "on_demand_analysis": f"{base}/paid/analyze-now/{{key}} ($0.30, runs LLM extraction)",
                "x402_resource_history": f"{base}/paid/x402/history/{{id}} ($0.01, full audit trail)",
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
                "/x402/sample-change": op("Sample registry change event (free)"),
                "/paid/requirements/{key}": op(
                    "Structured bidding requirements, $0.02 via x402", paid=True),
                "/paid/analyze-now/{key}": op(
                    "On-demand LLM extraction, $0.30 via x402", paid=True),
                "/paid/x402/history/{id}": op(
                    "Full snapshot+event history for one x402 resource, $0.01 via x402",
                    paid=True),
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
                {"id": "x402_registry_changes",
                 "name": "x402 registry change feed",
                 "description": f"GET {base}/x402/changes?type=price_changed (free)"},
                {"id": "x402_resource_history",
                 "name": "x402 resource audit history",
                 "description": f"GET {base}/paid/x402/history/{{id}} ($0.01 via x402)"},
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
        if job["case_key"].startswith("x402:"):
            # x402履歴ジョブ: LLM不要。履歴を再構築して完了させる
            from . import x402watch, paid
            conn.executescript(x402watch.SCHEMA_SQL)
            rid = int(job["case_key"][len("x402:"):])
            row = conn.execute("SELECT * FROM x402_resources WHERE id=?", (rid,)).fetchone()
            if row is None:
                self._json({"error": "resource_gone", "retry_token": token}, 410)
                return
            payload = self._x402_history_payload(conn, row)
            paid.finish(conn, token, "succeeded", payload)
            self._json({"cached": True, "history": payload, "retry_token": token})
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

    def _identify(self, conn):
        """APIキー検証+無償ティアの日次上限。戻り値: (client識別子, エラー or None)"""
        from . import billing
        api_key = self.headers.get("X-API-Key", "")
        if api_key:
            rec = billing.check(conn, api_key)
            if rec is None:
                return None, (401, {"error": "invalid_api_key"})
            return f"key:{rec['name']}", None
        ip = self._client_ip()
        if ip not in ("127.0.0.1", "::1") and billing.over_free_limit(conn, ip):
            return None, (429, {"error": "free_tier_daily_limit",
                                "hint": "X-API-Key ヘッダで有償キーを指定してください"})
        return ip, None

    def do_POST(self):
        """MCP Streamable HTTP: POST /mcp にJSON-RPCを受け付ける(リモートMCP対応)"""
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.rstrip("/") != "/mcp":
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
