"""デプロイ前回帰テスト:  python -m kkj.selftest

外部ネットワークに依存しない範囲で store / differ / billing / mcp のコア動作を検証。
本番DBには触れず、一時DBで実行する。
"""
import json
import sys
import tempfile
from pathlib import Path

from . import config

# 一時DBに差し替えてから他モジュールを使う
_tmp = Path(tempfile.mkdtemp(prefix="kkj_selftest_"))
config.DATA_DIR = _tmp
config.DB_PATH = _tmp / "test.db"

from . import store, billing, mcp_server  # noqa: E402

FAILED = []


def check(name, cond):
    print(("ok  " if cond else "FAIL") + f" {name}")
    if not cond:
        FAILED.append(name)


def main():
    conn = store.connect()

    # 1. 新規案件 → NEW_CASE
    rec = {"key": "TEST1", "project_name": "テスト案件", "period_end": "2026-08-01",
           "fetched_by_portal_at": "2026-07-03T00:00:00"}
    check("new case -> NEW_CASE", store.upsert_case(conn, rec) == "NEW_CASE")

    # 2. 同一内容(ポータル取得日時だけ変化) → 変化なし
    rec2 = dict(rec, fetched_by_portal_at="2026-07-04T00:00:00")
    check("portal-date-only change ignored", store.upsert_case(conn, rec2) is None)

    # 3. 実フィールド変化 → FIELD_CHANGED + before/after
    rec3 = dict(rec, period_end="2026-09-01")
    check("field change -> FIELD_CHANGED", store.upsert_case(conn, rec3) == "FIELD_CHANGED")
    ev = conn.execute("SELECT detail_json FROM events ORDER BY id DESC LIMIT 1").fetchone()
    d = json.loads(ev["detail_json"])
    check("diff has before/after",
          d.get("period_end", {}).get("before") == "2026-08-01"
          and d["period_end"]["after"] == "2026-09-01")

    # 4. スナップショット証跡が2世代
    n = conn.execute("SELECT COUNT(*) n FROM snapshots WHERE case_key='TEST1'").fetchone()["n"]
    check("snapshot trail == 2", n == 2)

    # 5. 文書ハッシュ差替え → DOC_CHANGED
    store.record_document(conn, "TEST1", "http://x/a.pdf", "aaa", 10, "ok")
    ev5 = store.record_document(conn, "TEST1", "http://x/a.pdf", "bbb", 11, "ok")
    check("doc hash change -> DOC_CHANGED", ev5 == "DOC_CHANGED")

    # 6. APIキー発行・検証(別コネクションを使うため先にコミット)
    conn.commit()
    key = billing.issue("selftest", "metered")
    check("issued key validates", billing.check(conn, key) is not None)
    check("bad key rejected", billing.check(conn, "kkjw_bogus") is None)

    # 7. MCPハンドラ
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-06-18"}})
    check("mcp initialize", r["result"]["serverInfo"]["name"] == "kkj-watch")
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    # ツール数は増減するため、コアツールの存在で検証する
    tool_names = {t["name"] for t in r["result"]["tools"]}
    check("mcp tools/list has core tools",
          {"find_tender_deadline_changes", "get_tender_change_evidence",
           "get_cached_tender_requirements", "list_japan_procurement_changes"} <= tool_names)
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "search_cases", "arguments": {"query": "テスト"}}})
    hits = json.loads(r["result"]["content"][0]["text"])
    check("mcp search finds test case", any(h["key"] == "TEST1" for h in hits))
    r = mcp_server.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                           "params": {"name": "nope", "arguments": {}}})
    check("mcp unknown tool -> error", "error" in r)

    conn.commit()
    conn.close()

    print(f"\n{'ALL PASS' if not FAILED else 'FAILED: ' + ', '.join(FAILED)}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
