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
    out = []
    for r in rows:
        rec = json.loads(r["latest_json"])
        out.append({
            "key": r["key"],
            "project_name": rec.get("project_name"),
            "organization": rec.get("organization_name"),
            "cft_issue_date": rec.get("cft_issue_date"),
            "document_uri": rec.get("document_uri"),
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
