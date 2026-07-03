"""SQLiteストア: 案件スナップショット(ハッシュ付き証跡)・イベント・文書"""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    key TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    latest_hash TEXT NOT NULL,
    latest_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_key TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    hash TEXT NOT NULL,
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_case ON snapshots(case_key);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_key TEXT NOT NULL,
    event_type TEXT NOT NULL,          -- NEW_CASE / FIELD_CHANGED / DOC_CHANGED
    detected_at TEXT NOT NULL,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_key);
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_key TEXT NOT NULL,
    url TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    sha256 TEXT,
    size INTEGER,
    status TEXT NOT NULL               -- ok / error:<reason>
);
CREATE INDEX IF NOT EXISTS idx_documents_case ON documents(case_key);
CREATE TABLE IF NOT EXISTS extractions (
    case_key TEXT PRIMARY KEY,
    extracted_at TEXT NOT NULL,
    model TEXT NOT NULL,
    result_json TEXT NOT NULL
);
"""


def now_utc():
    return datetime.now(timezone.utc).isoformat()


def canonical_hash(record: dict) -> str:
    """スナップショットの正規化ハッシュ(ポータル取得日時は変化検知から除外)"""
    stable = {k: v for k, v in record.items() if k != "fetched_by_portal_at"}
    blob = json.dumps(stable, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def connect():
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    # timeout: 高速レーン(毎時巡回)と低速レーン(文書・抽出)の並走時のロック待ち
    conn = sqlite3.connect(config.DB_PATH, timeout=60)
    conn.executescript(SCHEMA)
    try:  # 移行: 原典文書の抽出テキスト版管理(内部保存・再配布はしない)
        conn.execute("ALTER TABLE documents ADD COLUMN text")
    except sqlite3.OperationalError:
        pass
    conn.row_factory = sqlite3.Row
    return conn


def upsert_case(conn, record: dict):
    """案件を取り込み、発生したイベント種別を返す(None=変化なし)"""
    key = record["key"]
    h = canonical_hash(record)
    ts = now_utc()
    raw = json.dumps(record, ensure_ascii=False, sort_keys=True)

    row = conn.execute("SELECT latest_hash, latest_json FROM cases WHERE key=?", (key,)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO cases(key, first_seen, last_seen, latest_hash, latest_json) VALUES (?,?,?,?,?)",
            (key, ts, ts, h, raw),
        )
        conn.execute(
            "INSERT INTO snapshots(case_key, fetched_at, hash, raw_json) VALUES (?,?,?,?)",
            (key, ts, h, raw),
        )
        conn.execute(
            "INSERT INTO events(case_key, event_type, detected_at, detail_json) VALUES (?,?,?,?)",
            (key, "NEW_CASE", ts, None),
        )
        return "NEW_CASE"

    if row["latest_hash"] == h:
        conn.execute("UPDATE cases SET last_seen=? WHERE key=?", (ts, key))
        return None

    old = json.loads(row["latest_json"])
    diff = field_diff(old, record)
    conn.execute(
        "UPDATE cases SET last_seen=?, latest_hash=?, latest_json=? WHERE key=?",
        (ts, h, raw, key),
    )
    conn.execute(
        "INSERT INTO snapshots(case_key, fetched_at, hash, raw_json) VALUES (?,?,?,?)",
        (key, ts, h, raw),
    )
    conn.execute(
        "INSERT INTO events(case_key, event_type, detected_at, detail_json) VALUES (?,?,?,?)",
        (key, "FIELD_CHANGED", ts, json.dumps(diff, ensure_ascii=False)),
    )
    return "FIELD_CHANGED"


def field_diff(old: dict, new: dict) -> dict:
    """条項レベル差分: 変更/追加/削除されたフィールドを前後の値付きで返す"""
    changes = {}
    keys = set(old) | set(new)
    keys.discard("fetched_by_portal_at")
    for k in sorted(keys):
        ov, nv = old.get(k), new.get(k)
        if ov != nv:
            changes[k] = {"before": ov, "after": nv}
    return changes


def record_document(conn, case_key, url, sha256, size, status, text=None):
    ts = now_utc()
    prev = conn.execute(
        "SELECT sha256 FROM documents WHERE case_key=? AND url=? AND status='ok' ORDER BY id DESC LIMIT 1",
        (case_key, url),
    ).fetchone()
    conn.execute(
        "INSERT INTO documents(case_key, url, fetched_at, sha256, size, status, text) VALUES (?,?,?,?,?,?,?)",
        (case_key, url, ts, sha256, size, status, text),
    )
    if status == "ok" and prev is not None and prev["sha256"] != sha256:
        conn.execute(
            "INSERT INTO events(case_key, event_type, detected_at, detail_json) VALUES (?,?,?,?)",
            (case_key, "DOC_CHANGED", ts,
             json.dumps({"url": url, "before_sha256": prev["sha256"], "after_sha256": sha256})),
        )
        return "DOC_CHANGED"
    return None
