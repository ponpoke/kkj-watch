"""巡回パイプライン CLI

  python -m kkj.pipeline poll            # APIから対象領域の案件を取得し変化検知
  python -m kkj.pipeline poll-docs [N]   # 原典文書をN件巡回し差替え検知(低頻度)
  python -m kkj.pipeline extract [N]     # 未抽出の案件N件を構造化(要ANTHROPIC_API_KEY)
  python -m kkj.pipeline stats           # 蓄積状況
  python -m kkj.pipeline events [N]      # 直近イベント
"""
import json
import sys
import time
import urllib.parse

from . import api_client, config, extractor, store


def cmd_poll():
    conn = store.connect()
    seen = set()
    counts = {"NEW_CASE": 0, "FIELD_CHANGED": 0, "unchanged": 0}
    for q in config.QUERIES:
        try:
            records, hits = api_client.search(query=q, count=config.FETCH_COUNT)
        except Exception as e:
            print(f"[warn] query '{q}' failed: {e}")
            continue
        fresh = 0
        for rec in records:
            if rec["key"] in seen:
                continue
            seen.add(rec["key"])
            ev = store.upsert_case(conn, rec)
            if ev:
                counts[ev] += 1
            else:
                counts["unchanged"] += 1
            fresh += 1
        conn.commit()
        print(f"query='{q}': api_hits={hits}, fetched={len(records)}, new_to_run={fresh}")
        time.sleep(1.0)  # ポータルAPIへ低頻度アクセス
    conn.commit()
    print(f"\nresult: new={counts['NEW_CASE']}, changed={counts['FIELD_CHANGED']}, unchanged={counts['unchanged']}")
    conn.close()


def cmd_extract(limit=5):
    if not extractor.available():
        print("ANTHROPIC_API_KEY が未設定のため抽出はスキップ")
        return
    conn = store.connect()
    rows = conn.execute(
        """SELECT c.key FROM cases c LEFT JOIN extractions e ON e.case_key = c.key
           WHERE e.case_key IS NULL AND json_extract(c.latest_json,'$.project_description') IS NOT NULL
           ORDER BY c.first_seen DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    for r in rows:
        try:
            result = extractor.extract_case(conn, r["key"])
            conn.commit()
            name = json.loads(conn.execute(
                "SELECT latest_json FROM cases WHERE key=?", (r["key"],)
            ).fetchone()["latest_json"]).get("project_name", "")
            print(f"extracted: {name[:40]}")
            print(json.dumps(result, ensure_ascii=False, indent=2)[:800])
        except Exception as e:
            print(f"[warn] extract failed for {r['key']}: {e}")
    conn.close()


def cmd_backup(keep=14):
    """DBのオンラインバックアップ(世代管理)。変更履歴=資産の保全"""
    import sqlite3
    from datetime import datetime, timezone
    backups = config.DATA_DIR / "backups"
    backups.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest = backups / f"kkj_{stamp}.db"
    src = store.connect()
    dst = sqlite3.connect(dest)
    with dst:
        src.backup(dst)
    dst.close()
    src.close()
    old = sorted(backups.glob("kkj_*.db"))[:-keep]
    for f in old:
        f.unlink()
    print(f"backup: {dest.name} (保持 {min(keep, len(list(backups.glob('kkj_*.db'))))}世代)")


def cmd_stats():
    conn = store.connect()
    for table in ("cases", "snapshots", "events", "documents", "extractions"):
        n = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
        print(f"{table:12s}: {n}")
    by_type = conn.execute(
        "SELECT event_type, COUNT(*) AS n FROM events GROUP BY event_type"
    ).fetchall()
    for r in by_type:
        print(f"  event {r['event_type']}: {r['n']}")
    conn.close()


def cmd_events(limit=10):
    conn = store.connect()
    rows = conn.execute(
        """SELECT e.event_type, e.detected_at, e.detail_json,
                  json_extract(c.latest_json,'$.project_name') AS name,
                  json_extract(c.latest_json,'$.organization_name') AS org
           FROM events e JOIN cases c ON c.key = e.case_key
           ORDER BY e.id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    for r in rows:
        print(f"[{r['event_type']}] {r['detected_at']} {r['org']}: {(r['name'] or '')[:50]}")
        if r["detail_json"]:
            print(f"    diff: {r['detail_json'][:300]}")
    conn.close()


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else "poll"
    if cmd == "poll":
        cmd_poll()
    elif cmd == "poll-docs":
        from . import doc_watch
        doc_watch.poll_docs(int(args[1]) if len(args) > 1 else None)
    elif cmd == "extract":
        cmd_extract(int(args[1]) if len(args) > 1 else 5)
    elif cmd == "watch-add":
        from . import watch
        watch.add(args[1])
    elif cmd == "watch-list":
        from . import watch
        watch.list_watches()
    elif cmd == "digest":
        from . import watch
        watch.digest()
    elif cmd == "backup":
        cmd_backup(int(args[1]) if len(args) > 1 else 14)
    elif cmd == "link":
        from . import linker
        linker.link_corrections(int(args[1]) if len(args) > 1 else 30)
    elif cmd == "analyze":
        from . import semantic
        semantic.analyze_pending_field_events(int(args[1]) if len(args) > 1 else 20)
    elif cmd == "key-issue":
        from . import billing
        plan = args[2] if len(args) > 2 else "metered"
        print(billing.issue(args[1], plan))
    elif cmd == "key-list":
        from . import billing
        billing.list_keys()
    elif cmd == "usage-report":
        from . import billing
        billing.usage_report()
    elif cmd == "stats":
        cmd_stats()
    elif cmd == "events":
        cmd_events(int(args[1]) if len(args) > 1 else 10)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
