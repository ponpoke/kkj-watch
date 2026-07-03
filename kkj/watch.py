"""キーワードウォッチ(フェーズ2の月額商品の実体)

  python -m kkj.pipeline watch-add <キーワード>   # ウォッチ登録
  python -m kkj.pipeline watch-list
  python -m kkj.pipeline digest                    # 前回以降の新着・変更をウォッチ別に出力
"""
import json

from . import store

SCHEMA = """
CREATE TABLE IF NOT EXISTS watches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_digest_at TEXT
);
"""


def connect():
    conn = store.connect()
    conn.executescript(SCHEMA)
    return conn


def add(keyword: str):
    conn = connect()
    conn.execute(
        "INSERT OR IGNORE INTO watches(keyword, created_at) VALUES (?,?)",
        (keyword, store.now_utc()),
    )
    conn.commit()
    conn.close()
    print(f"watch registered: {keyword}")


def list_watches():
    conn = connect()
    for r in conn.execute("SELECT * FROM watches ORDER BY id").fetchall():
        print(f"[{r['id']}] {r['keyword']} (登録: {r['created_at'][:10]}, 最終配信: {r['last_digest_at'] or '未'})")
    conn.close()


def digest(mark=True):
    """ウォッチごとに前回配信以降のイベントをまとめる(メール/Slack配信の中身)"""
    conn = connect()
    watches = conn.execute("SELECT * FROM watches ORDER BY id").fetchall()
    if not watches:
        print("ウォッチ未登録。watch-add <キーワード> で登録してください。")
        conn.close()
        return
    now = store.now_utc()
    for w in watches:
        since = w["last_digest_at"] or w["created_at"]
        rows = conn.execute(
            """SELECT e.event_type, e.detected_at, e.detail_json, c.latest_json
               FROM events e JOIN cases c ON c.key=e.case_key
               WHERE e.detected_at > ? AND c.latest_json LIKE ?
               ORDER BY e.id DESC""",
            (since, f"%{w['keyword']}%"),
        ).fetchall()
        print(f"\n=== ウォッチ「{w['keyword']}」: {len(rows)}件 (since {since[:19]}) ===")
        for r in rows[:30]:
            rec = json.loads(r["latest_json"])
            print(f"[{r['event_type']}] {rec.get('organization_name','')}: {(rec.get('project_name') or '')[:50]}")
            if r["detail_json"]:
                print(f"    {r['detail_json'][:200]}")
        if mark:
            conn.execute("UPDATE watches SET last_digest_at=? WHERE id=?", (now, w["id"]))
    conn.commit()
    conn.close()
