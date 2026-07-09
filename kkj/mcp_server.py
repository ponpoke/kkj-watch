"""MCPサーバー(stdio): 調達エージェントから直接使える形で公開する配布チャネル

  python -m kkj.mcp_server

標準ライブラリのみでMCP stdioトランスポート(改行区切りJSON-RPC 2.0)を実装。
公開ツール: search_cases / get_case / list_change_events / get_requirements
"""
import json
import sys

from . import store, extractor

PROTOCOL_VERSION = "2025-06-18"

TOOLS = [
    {
        "name": "recommend_x402_endpoint",
        "description": "Given a task and budget, recommend which x402 Bazaar endpoint to use. "
                       "Returns a recommended resource + alternatives, each with a 'why' list "
                       "(alive on recent probes, registry/live terms match, payTo stable, low "
                       "price volatility). Ranks by an OBSERVED, evidence-based risk score then "
                       "lowest price; excludes endpoints whose live payTo differs from the "
                       "registry. This is what you usually want: not a raw score, but 'which "
                       "cheap, low-risk endpoint should I call?'. Not a safety guarantee.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "task/keyword/category (e.g. web search, "
                                                       "price feed, twitter)"},
                "max_price_usd": {"type": "number", "description": "max acceptable USD price/call"},
                "min_trust": {"type": "number", "description": "minimum observed trust score (0-100)"},
                "require_live": {"type": "boolean",
                                 "description": "only endpoints verified live on last probe (default true)"},
            },
        },
    },
    {
        "name": "check_x402_endpoint_trust",
        "description": "Get the OBSERVED trust score (0-100, grade A-F) of one x402 Bazaar resource "
                       "BEFORE paying it. An evidence-based risk indicator (NOT a safety guarantee) "
                       "combining liveness probes, listing-vs-live consistency (does the real "
                       "endpoint serve the same price and payTo as the registry?), payTo stability "
                       "(a changed receiving address is a hijack signal the 402 flow pays blindly), "
                       "listing age and spam-farm detection. Deterministic; all deduction reasons "
                       "included so you can verify them yourself.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "resource": {"type": "string",
                             "description": "resource URL or numeric id (find via "
                                            "/x402/resources?q= or list tools)"},
            },
            "required": ["resource"],
        },
    },
    {
        "name": "list_x402_trusted_endpoints",
        "description": "x402 resources ranked by observed trust score (leaderboard). Filter by "
                       "keyword/tag with q. An evidence-based ranking, not a guarantee. Free.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "q": {"type": "string", "description": "keyword/tag filter"},
                "limit": {"type": "integer", "description": "max items (default 20)"},
            },
        },
    },
    {
        "name": "list_x402_registry_changes",
        "description": "List recent change events in the x402 Bazaar registry (23k+ paid API "
                       "resources): price_changed, payto_changed (receiving-address change — verify "
                       "before paying), accepts_changed, schema_changed, delisted/relisted. Free. "
                       "Hourly polling with SHA-256 snapshot audit trail. Use before paying a "
                       "cached x402 endpoint to confirm its terms did not change.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type": {"type": "string",
                         "description": "event type filter (price_changed / payto_changed / "
                                        "accepts_changed / schema_changed / delisted / relisted)"},
                "severity": {"type": "string",
                             "description": "severity filter (critical / high / medium / low)"},
                "limit": {"type": "integer", "description": "max items (default 20)"},
            },
        },
    },
    {
        "name": "list_japan_procurement_changes",
        "description": "List recent change events in Japanese public procurement (government tenders): "
                       "corrections, deadline changes, requirement changes, document replacements. "
                       "Free. Filter by impact with tag= (deadline_affecting / eligibility_affecting / "
                       "price_affecting / document_affecting). 官公需の変更イベント一覧(無料)。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tag": {"type": "string",
                        "description": "impact tag filter (e.g. deadline_affecting)"},
                "limit": {"type": "integer", "description": "max items (default 20)"},
            },
        },
    },
    {
        "name": "find_tender_deadline_changes",
        "description": "Search monitored Japanese tenders by keyword (matches title, agency, body). "
                       "Free. Returns case keys usable with get_tender_change_evidence / "
                       "get_cached_tender_requirements. キーワードで入札案件を検索(無料)。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "keyword (e.g. cloud / クラウド)"},
                "limit": {"type": "integer", "description": "max items (default 20)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_tender_change_evidence",
        "description": "Get full evidence for one tender: all fields, snapshot history (SHA-256 audit trail), "
                       "change events with before/after and impact tags, plus cached structured requirements "
                       "if available. Free. 案件の変更根拠一式を取得(無料)。",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string", "description": "case key"}},
            "required": ["key"],
        },
    },
    {
        "name": "get_cached_tender_requirements",
        "description": "Get structured bidding requirements (qualifications, unified-qualification rank A-D, "
                       "certifications, document checklist, deadlines, bid method) as validated JSON. "
                       "Returns cached data if available; otherwise indicates paid on-demand analysis is needed. "
                       "応募要件の構造化JSON(キャッシュ優先)。",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string", "description": "case key"}},
            "required": ["key"],
        },
    },
]


def tool_search_cases(args):
    q = f"%{args['query']}%"
    limit = min(int(args.get("limit", 20)), 100)
    conn = store.connect()
    rows = conn.execute(
        """SELECT key, latest_json, first_seen, last_seen FROM cases
           WHERE latest_json LIKE ? ORDER BY first_seen DESC LIMIT ?""",
        (q, limit),
    ).fetchall()
    extracted = {r["case_key"] for r in conn.execute("SELECT case_key FROM extractions")}
    out = []
    for r in rows:
        rec = json.loads(r["latest_json"])
        out.append({
            "key": r["key"],
            "project_name": rec.get("project_name"),
            "organization": rec.get("organization_name"),
            "cft_issue_date": rec.get("cft_issue_date"),
            "document_uri": rec.get("document_uri"),
            # 構造化要件がキャッシュ済み=get_cached_tender_requirementsで即取得可能
            "requirements_cached": r["key"] in extracted,
        })
    conn.close()
    return out


def tool_get_case(args):
    conn = store.connect()
    row = conn.execute("SELECT * FROM cases WHERE key=?", (args["key"],)).fetchone()
    if row is None:
        conn.close()
        return {"error": "not_found"}
    out = {
        "key": row["key"],
        "record": json.loads(row["latest_json"]),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "snapshots": [
            {"fetched_at": s["fetched_at"], "sha256": s["hash"]}
            for s in conn.execute(
                "SELECT fetched_at, hash FROM snapshots WHERE case_key=? ORDER BY id", (row["key"],)
            ).fetchall()
        ],
        "events": [
            {"type": e["event_type"], "at": e["detected_at"],
             "detail": json.loads(e["detail_json"]) if e["detail_json"] else None}
            for e in conn.execute(
                "SELECT * FROM events WHERE case_key=? ORDER BY id", (row["key"],)
            ).fetchall()
        ],
    }
    ext = conn.execute("SELECT result_json FROM extractions WHERE case_key=?", (row["key"],)).fetchone()
    out["requirements"] = json.loads(ext["result_json"]) if ext else None
    conn.close()
    return out


def tool_list_change_events(args):
    limit = min(int(args.get("limit", 20)), 100)
    tag = args.get("tag") or ""
    conn = store.connect()
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS change_analyses (id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " case_key TEXT, event_id INTEGER, kind TEXT, analysis_json TEXT, model TEXT, created_at TEXT);")
    fetch = limit if not tag else min(limit * 8, 1000)
    rows = conn.execute(
        """SELECT e.*, json_extract(c.latest_json,'$.project_name') AS name,
                  json_extract(c.latest_json,'$.organization_name') AS org,
                  json_extract(c.latest_json,'$.document_uri') AS src,
                  (SELECT a.analysis_json FROM change_analyses a
                   WHERE a.event_id=e.id ORDER BY a.id DESC LIMIT 1) AS analysis
           FROM events e JOIN cases c ON c.key=e.case_key
           WHERE e.event_type != 'NEW_CASE'
           ORDER BY e.id DESC LIMIT ?""",
        (fetch,),
    ).fetchall()
    out = []
    for r in rows:
        analysis = json.loads(r["analysis"]) if r["analysis"] else None
        if tag:
            changes = (analysis or {}).get("changes", [])
            if not any(tag in (ch.get("impact_tags") or []) for ch in changes):
                continue
        out.append({
            "case_key": r["case_key"], "project_name": r["name"], "organization": r["org"],
            "type": r["event_type"], "observed_at": r["detected_at"], "source_url": r["src"],
            "analysis": analysis})
        if len(out) >= limit:
            break
    conn.close()
    return out


def tool_list_x402_changes(args):
    """x402 Bazaarレジストリの変更イベント一覧(無料・ルールベース検知)"""
    from . import x402watch
    limit = min(int(args.get("limit", 20)), 100)
    etype = args.get("type") or ""
    severity = args.get("severity") or ""
    conn = store.connect()
    conn.executescript(x402watch.SCHEMA_SQL)
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
    out = [{
        "resource": r["resource"], "service_name": r["service_name"],
        "event_type": r["event_type"], "severity": r["severity"],
        "detected_at": r["detected_at"],
        "detail": json.loads(r["detail_json"]) if r["detail_json"] else None,
    } for r in conn.execute(sql, params).fetchall()]
    conn.close()
    return out


def tool_check_trust(args):
    """1リソースのTrustスコア(無料)"""
    from . import x402watch, x402trust
    ident = str(args.get("resource", "")).strip()
    conn = store.connect()
    conn.executescript(x402watch.SCHEMA_SQL)
    if ident.isdigit():
        row = conn.execute("SELECT * FROM x402_resources WHERE id=?", (int(ident),)).fetchone()
    else:
        row = conn.execute("SELECT * FROM x402_resources WHERE resource=?", (ident,)).fetchone()
    if row is None:
        conn.close()
        return {"error": "not_found",
                "hint": "Search resources with list_x402_registry_changes or /x402/resources?q="}
    trust = x402trust.get_or_compute(conn, row)
    conn.commit()
    out = {"resource": row["resource"], "service_name": row["service_name"],
           "id": row["id"], "trust": trust}
    conn.close()
    return out


def _scored_rows(conn, q=""):
    from . import x402trust
    x402trust._migrate(conn)
    if q:
        return conn.execute(
            """SELECT * FROM x402_resources WHERE active=1 AND trust_score IS NOT NULL
               AND (resource LIKE ? OR service_name LIKE ? OR latest_json LIKE ?)
               ORDER BY trust_score DESC, id ASC LIMIT 500""",
            (f"%{q}%", f"%{q}%", f"%{q}%")).fetchall()
    return conn.execute(
        """SELECT * FROM x402_resources WHERE active=1 AND trust_score IS NOT NULL
           ORDER BY trust_score DESC, id ASC LIMIT 500""").fetchall()


def tool_trust_leaderboard(args):
    """観測トラストスコア上位(無料)"""
    from . import x402watch
    limit = min(int(args.get("limit", 20)), 100)
    q = str(args.get("q", "")).strip()
    conn = store.connect()
    conn.executescript(x402watch.SCHEMA_SQL)
    out = []
    for r in _scored_rows(conn, q)[:limit]:
        t = json.loads(r["trust_json"]) if r["trust_json"] else {}
        out.append({"id": r["id"], "resource": r["resource"],
                    "service_name": r["service_name"],
                    "observed_trust_score": r["trust_score"],
                    "grade": t.get("grade"), "verdicts": t.get("verdicts")})
    conn.close()
    return {"score_type": "observed_trust_score", "count": len(out), "items": out}


def tool_recommend(args):
    """選定API: 用途/予算で使うべき1件+代替を返す(無料)"""
    from . import x402watch, x402trust
    q = str(args.get("q") or args.get("category") or args.get("task") or "").strip()
    try:
        max_price = float(args.get("max_price_usd") or 0) or None
    except (TypeError, ValueError):
        max_price = None
    try:
        min_trust = float(args.get("min_trust") or 0)
    except (TypeError, ValueError):
        min_trust = 0.0
    require_live = args.get("require_live", True) not in (False, 0, "0", "false", "no")
    conn = store.connect()
    conn.executescript(x402watch.SCHEMA_SQL)
    cands = []
    for r in _scored_rows(conn, q):
        if r["trust_score"] < min_trust:
            continue
        t = json.loads(r["trust_json"]) if r["trust_json"] else {}
        rec = json.loads(r["latest_json"])
        price = x402trust.price_usd_min(rec)
        if max_price is not None and (price is None or price > max_price):
            continue
        if require_live and not t.get("verdicts", {}).get("verified_live"):
            continue
        if t.get("verdicts", {}).get("payto_risk") == "live_mismatch":
            continue
        cands.append((r, t, price))
    cands.sort(key=lambda x: (-x[0]["trust_score"], x[2] if x[2] is not None else 9e9, x[0]["id"]))

    def entry(item):
        r, t, price = item
        return {"resource": r["resource"], "id": r["id"],
                "service_name": r["service_name"],
                "observed_trust_score": r["trust_score"], "grade": t.get("grade"),
                "price_usd": price, "why": x402trust.why_reasons(t),
                "caveats": x402trust.caveats(t)}
    out = {
        "score_type": "observed_trust_score",
        "disclaimer": x402trust.SCORE_DISCLAIMER,
        "query": {"q": q or None, "max_price_usd": max_price, "min_trust": min_trust,
                  "require_live": require_live},
        "matched": len(cands),
        "recommended_resource": cands[0][0]["resource"] if cands else None,
        "recommended": entry(cands[0]) if cands else None,
        "alternatives": [entry(c) for c in cands[1:6]],
    }
    conn.close()
    return out


def tool_get_requirements(args):
    """キャッシュ済み構造化要件を返す。未抽出は有料オンデマンド解析へ誘導(裏でLLMを呼ばない=コスト制御)"""
    conn = store.connect()
    ext = conn.execute("SELECT result_json FROM extractions WHERE case_key=?", (args["key"],)).fetchone()
    conn.close()
    if ext:
        return {"cached": True, "requirements": json.loads(ext["result_json"])}
    return {"cached": False, "status": "not_yet_extracted",
            "hint": "この案件はまだ構造化されていません。新規解析は有料エンドポイント "
                    "/paid/analyze-now/{key} ($0.30) をご利用ください。"}


HANDLERS = {
    # 目的ベースの新名(外部エージェント向け)
    "recommend_x402_endpoint": tool_recommend,
    "check_x402_endpoint_trust": tool_check_trust,
    "list_x402_trusted_endpoints": tool_trust_leaderboard,
    "list_x402_registry_changes": tool_list_x402_changes,
    "find_tender_deadline_changes": tool_search_cases,
    "get_tender_change_evidence": tool_get_case,
    "list_japan_procurement_changes": tool_list_change_events,
    "get_cached_tender_requirements": tool_get_requirements,
    # 旧名は後方互換のエイリアスとして維持
    "search_cases": tool_search_cases,
    "get_case": tool_get_case,
    "list_change_events": tool_list_change_events,
    "get_requirements": tool_get_requirements,
}


def handle(msg):
    method = msg.get("method")
    mid = msg.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0", "id": mid,
            "result": {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", PROTOCOL_VERSION),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "kkj-watch", "version": "0.1.0"},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name")
        fn = HANDLERS.get(name)
        if fn is None:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32602, "message": f"unknown tool: {name}"}}
        try:
            result = fn(params.get("arguments", {}))
            text = json.dumps(result, ensure_ascii=False, indent=1)
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": text}], "isError": False}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}}
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"resources": []}}
    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"prompts": []}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    if mid is not None:  # 未対応のリクエストにはエラー応答、通知は無視
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"method not found: {method}"}}
    return None


def main():
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg)
        if resp is not None:
            stdout.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))
            stdout.flush()


if __name__ == "__main__":
    main()
