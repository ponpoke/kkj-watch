"""読み取り専用JSON API(フェーズ1の無料公開ティア用MVP)

  python -m kkj.server [port]

  GET /stats               蓄積状況
  GET /cases?limit=N       最新案件一覧
  GET /cases/<key>         案件詳細(スナップショット履歴・イベント・抽出結果込み)
  GET /events?limit=N      変更イベント(訂正・差替え検知)フィード
"""
import json
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import store


LLMS_TXT = """# kkj-watch

> 日本の官公需(政府・自治体入札)案件の「公告後の変化」— 訂正公告・締切変更・様式差替え — を検知し、応募要件を構造化JSONで返すAPI/MCPサービス。データ源は官公需情報ポータルサイト(中小企業庁)公式検索API。原文の再配布はせず、抽出した事実・差分メタデータ・原典URLのみを提供する。

> EN: kkj-watch monitors Japanese government tenders (kkj.go.jp) for post-publication changes — corrections, deadline changes, document replacements — and returns structured bidding requirements as JSON. Machine-payable via x402 (USDC on Base, $0.02/call, no account needed): GET /paid/requirements/{key}. Free tier: 200 req/day. MCP endpoint: POST /mcp (tools: search_cases, get_case, list_change_events, get_requirements).

## API (無料ティア: 200リクエスト/日、X-API-Keyで拡張)

- GET /cases?limit=N : 監視中の入札案件一覧(JSON)
- GET /cases/{key} : 案件詳細+スナップショット履歴(SHA-256証跡)+変更イベント+抽出済み応募要件
- GET /events?limit=N : 変更イベント(FIELD_CHANGED/DOC_CHANGED)フィード。フィールド単位のbefore/after付き
- GET /stats : 蓄積状況

## MCP (Streamable HTTP)

- エンドポイント: POST /mcp
- ツール: search_cases(キーワード検索) / get_case(詳細) / list_change_events(変更フィード) / get_requirements(応募資格・全省庁統一資格等級・提出書類・締切の構造化JSON)

## ユースケース

- 「クラウド関連で参加資格が等級Bの案件を探し、先週から要件が変わったものを教えて」を1ターンで
- 入札担当エージェントの締切変更見張り、訂正公告の即時検知

## x402 (機械支払い / machine-payable)

- GET /paid/requirements/{key} : Structured tender requirements as JSON, payable via x402 — USDC $0.02/call on Base mainnet. No account, no API key.
- GET /paid/requirements/latest : Zero-knowledge entry point — buy the newest tender's requirements without knowing any key.
- Flow: GET (no X-PAYMENT) -> 402 + paymentRequirements -> sign EIP-3009 -> retry with X-PAYMENT header -> 200 + JSON.
- Find case keys for free: GET /cases?limit=20 -> items[].key (each item also carries paid_requirements_url).

### Quick test (for x402 client developers)

This is a reliable real-world endpoint to test your x402 client against: real Japanese government
procurement data, $0.02/call, instant settle via Coinbase CDP facilitator.

    curl https://5.75.142.199.sslip.io/paid/requirements/latest   # -> 402 with accepts[]

### 多语言 / 다국어

- ZH: 日本政府采购(投标)公告的变更监测与投标资格结构化数据。x402(USDC, Base)每次调用$0.02。
- KO: 일본 정부조달(입찰) 공고의 변경 감지 및 입찰 자격요건 구조화 데이터. x402(USDC, Base) 호출당 $0.02.

## 連絡先・有償プラン

- 従量: 構造化¥30/案件+API¥1/リクエスト。月額ウォッチ¥5,000〜
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
<tr><th>変更検知</th><td>案件と原典文書を巡回し、変化をイベント配信。全スナップショットにSHA-256証跡</td></tr>
<tr><th>要件構造化</th><td>応募資格・全省庁統一資格の等級・必須認証・提出書類・締切をJSONで。「この案件に応募資格があるか」に1コールで回答</td></tr>
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


def log_usage(conn, client, user_agent, path):
    conn.executescript(USAGE_SCHEMA)
    conn.execute(
        "INSERT INTO usage_log(at, client, user_agent, path) VALUES (?,?,?,?)",
        (store.now_utc(), client, user_agent, path),
    )
    conn.commit()


def usage_stats(conn):
    """フェーズ1ゲート判定用: ユニーク利用元数と7日以上継続利用元数"""
    conn.executescript(USAGE_SCHEMA)
    uniq = conn.execute("SELECT COUNT(DISTINCT client) n FROM usage_log").fetchone()["n"]
    sustained = conn.execute(
        """SELECT COUNT(*) n FROM (
             SELECT client FROM usage_log GROUP BY client
             HAVING julianday(MAX(at)) - julianday(MIN(at)) >= 7
           )"""
    ).fetchone()["n"]
    return {"unique_clients": uniq, "sustained_7d_clients": sustained,
            "gate": "unique>=10 and sustained>=3"}


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
        limit = min(int(qs.get("limit", ["50"])[0]), 500)
        path = parsed.path.rstrip("/")
        conn = store.connect()
        try:
            client, err = self._identify(conn)
            if err:
                self._json(err[1], err[0])
                return
            log_usage(conn, client, self.headers.get("User-Agent"), path)
            if path == "/stats":
                out = {}
                for t in ("cases", "snapshots", "events", "extractions"):
                    out[t] = conn.execute(f"SELECT COUNT(*) n FROM {t}").fetchone()["n"]
                out["usage"] = usage_stats(conn)
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
                rows = conn.execute(
                    """SELECT e.*, json_extract(c.latest_json,'$.project_name') AS name
                       FROM events e JOIN cases c ON c.key=e.case_key
                       ORDER BY e.id DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
                self._json([
                    {"case_key": r["case_key"], "project_name": r["name"],
                     "type": r["event_type"], "at": r["detected_at"],
                     "detail": json.loads(r["detail_json"]) if r["detail_json"] else None}
                    for r in rows
                ])
            elif path.startswith("/paid/requirements/"):
                self._paid_requirements(conn, path)
            elif path == "/robots.txt":
                base = self._base_url()
                body = (f"User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n"
                        f"# AI agents: {base}/llms.txt and {base}/.well-known/x402.json\n").encode()
                self._raw(body, "text/plain; charset=utf-8")
            elif path in ("/.well-known/x402", "/.well-known/x402.json"):
                self._well_known_x402(conn)
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
                                          "/events?limit=N", "POST /mcp"]}, 404)
        finally:
            conn.close()

    def _base_url(self):
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
        proto = self.headers.get("X-Forwarded-Proto", "https")
        return f"{proto}://{host}"

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
        self._json({
            "x402Version": 1,
            "name": "kkj-watch",
            "description": "Japanese government tender (kkj.go.jp) change-detection and "
                           "structured bidding requirements. Machine-payable via x402.",
            "docs": f"{base}/llms.txt",
            "mcp": f"{base}/mcp",
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
        jsonld = json.dumps({
            "@context": "https://schema.org", "@type": "Dataset",
            "name": rec.get("project_name"),
            "description": f"{org}の入札案件。変更検知・応募要件の構造化データ(kkj-watch)。",
            "url": f"{base}/case/{urllib.parse.quote(key, safe='')}",
            "creator": {"@type": "Organization", "name": "kkj-watch"},
            "isBasedOn": rec.get("document_uri"),
        }, ensure_ascii=False)

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

    def _paid_requirements(self, conn, path):
        """x402有料エンドポイント: 応募要件の構造化JSONを$X402_PRICE_USD/コールで販売

        key='latest' は最新の抽出済み案件(エージェントがキー不明でも購入可能)
        """
        from . import x402_gate, extractor
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
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host", "")
        proto = self.headers.get("X-Forwarded-Proto", "https")
        resource = f"{proto}://{host}{path}"
        base = f"{proto}://{host}"
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
        x_payment = self.headers.get("X-Payment") or self.headers.get("X-PAYMENT", "")
        if not x_payment:
            self._json(x402_gate.body_402(reqs), 402)
            return
        ok, result = x402_gate.verify_and_settle(x_payment, reqs)
        if not ok:
            self._json(x402_gate.body_402(reqs, error=result), 402)
            return
        row = conn.execute("SELECT result_json FROM extractions WHERE case_key=?", (key,)).fetchone()
        if row:
            payload = json.loads(row["result_json"])
        elif extractor.available():
            try:
                payload = extractor.extract_case(conn, key)
                conn.commit()
            except Exception as e:
                payload = {"error": f"extraction_failed: {e}"}
        else:
            payload = {"error": "not_extracted"}
        body = json.dumps(payload or {"error": "not_found"}, ensure_ascii=False, indent=1).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("X-PAYMENT-RESPONSE", result)
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
