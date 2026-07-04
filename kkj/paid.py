"""x402 支払いジョブ管理: paid-but-denied を防ぐ

- 支払い(X-PAYMENT)は payment_hash で一意記録。別resourceでの再利用を拒否(リプレイ防止)
- 支払い後にLLM失敗しても paid_jobs に記録し、retry_token で再支払いなし再実行
"""
import hashlib
import json
import secrets

from . import store

SCHEMA = """
CREATE TABLE IF NOT EXISTS paid_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_hash TEXT NOT NULL UNIQUE,   -- 同一支払いの再利用防止(要件5)
    resource TEXT NOT NULL,
    case_key TEXT,
    settlement TEXT,
    paid_at TEXT NOT NULL,
    retry_token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,                 -- pending / succeeded / failed
    result_json TEXT,
    error TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_paidjobs_status ON paid_jobs(status);
"""


def ensure(conn):
    conn.executescript(SCHEMA)


def payment_hash(x_payment: str) -> str:
    return hashlib.sha256((x_payment or "").encode("utf-8")).hexdigest()


def claim(conn, ph, resource, case_key, settlement):
    """支払いを記録。戻り値: (job_row, error)
    error: None=新規/再取得OK / 'payment_reused'=同一支払いを別resourceで使用"""
    ensure(conn)
    row = conn.execute("SELECT * FROM paid_jobs WHERE payment_hash=?", (ph,)).fetchone()
    if row is not None:
        if row["resource"] != resource:
            return None, "payment_reused"
        return row, None  # 同一resourceの再取得(retry)は許可
    token = secrets.token_urlsafe(24)
    now = store.now_utc()
    conn.execute(
        "INSERT INTO paid_jobs(payment_hash, resource, case_key, settlement, paid_at,"
        " retry_token, status, updated_at) VALUES (?,?,?,?,?,?,?,?)",
        (ph, resource, case_key, settlement, now, token, "pending", now))
    conn.commit()
    return conn.execute("SELECT * FROM paid_jobs WHERE payment_hash=?", (ph,)).fetchone(), None


def finish(conn, token, status, result=None, error=None):
    ensure(conn)
    conn.execute(
        "UPDATE paid_jobs SET status=?, result_json=?, error=?, updated_at=? WHERE retry_token=?",
        (status, json.dumps(result, ensure_ascii=False) if result is not None else None,
         error, store.now_utc(), token))
    conn.commit()


def get(conn, token):
    ensure(conn)
    return conn.execute("SELECT * FROM paid_jobs WHERE retry_token=?", (token,)).fetchone()


def get_by_payment(conn, ph):
    """支払いハッシュから既存ジョブを引く(再settle回避・冪等化のため)"""
    ensure(conn)
    return conn.execute("SELECT * FROM paid_jobs WHERE payment_hash=?", (ph,)).fetchone()


def stats(conn):
    ensure(conn)
    out = {}
    for s in ("pending", "failed", "succeeded"):
        out[f"paid_jobs_{s}"] = conn.execute(
            "SELECT COUNT(*) n FROM paid_jobs WHERE status=?", (s,)).fetchone()["n"]
    return out
