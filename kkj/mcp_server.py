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
        "name": "search_cases",
        "description": "監視中の官公需(入札)案件をキーワードで検索する。件名・機関名・本文に対する部分一致。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "検索キーワード(例: クラウド)"},
                "limit": {"type": "integer", "description": "最大件数(既定20)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_case",
        "description": "案件キーを指定して詳細(全フィールド・スナップショット履歴・変更イベント・抽出済み応募要件)を取得する。",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string", "description": "案件キー(search_casesが返すkey)"}},
            "required": ["key"],
        },
    },
    {
        "name": "list_change_events",
        "description": "訂正公告・締切変更・様式差替えなどの変更イベントを新しい順に取得する。入札担当者が最も見落としやすい情報。",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "description": "最大件数(既定20)"}},
        },
    },
    {
        "name": "get_requirements",
        "description": "案件の応募要件(応募資格・全省庁統一資格等級・必須認証・提出書類・締切)を構造化JSONで返す。未抽出ならその場で抽出を試みる。",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string", "description": "案件キー"}},
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
    conn = store.connect()
    rows = conn.execute(
        """SELECT e.*, json_extract(c.latest_json,'$.project_name') AS name,
                  json_extract(c.latest_json,'$.organization_name') AS org
           FROM events e JOIN cases c ON c.key=e.case_key
           WHERE e.event_type != 'NEW_CASE'
           ORDER BY e.id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    out = [
        {"case_key": r["case_key"], "project_name": r["name"], "organization": r["org"],
         "type": r["event_type"], "at": r["detected_at"],
         "detail": json.loads(r["detail_json"]) if r["detail_json"] else None}
        for r in rows
    ]
    conn.close()
    return out


def tool_get_requirements(args):
    conn = store.connect()
    ext = conn.execute("SELECT result_json FROM extractions WHERE case_key=?", (args["key"],)).fetchone()
    if ext:
        conn.close()
        return json.loads(ext["result_json"])
    if not extractor.available():
        conn.close()
        return {"error": "not_extracted", "reason": "ANTHROPIC_API_KEY未設定のためオンデマンド抽出は不可"}
    try:
        result = extractor.extract_case(conn, args["key"])
        conn.commit()
        return result if result is not None else {"error": "not_found_or_no_text"}
    finally:
        conn.close()


HANDLERS = {
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
