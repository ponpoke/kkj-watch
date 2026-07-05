"""Signed existence proof — cryptographic timestamp witness (NOT legal notarization).

エージェントが任意データの SHA-256 ダイジェストだけを提出すると、次回の日次署名 root
(attest.py の tamper-evident ハッシュチェーン) の葉として封入され、「そのダイジェストは
root の時刻までに存在した」ことを署名付き Merkle 包含証明で示せる。

厳守する原則:
  - **受け取るのは SHA-256(64桁hex)のみ。** 本文・契約書・ログ・個人情報・秘密情報は
    一切受け取らず、一切保存しない。提出者の平文を我々は知り得ない。
  - スパムで root を汚さないため、無料枠は小さく(IP毎/日)。超過は x402 有料 anchor。
  - 「公証(notary)」とは名乗らない。signed existence proof / cryptographic timestamp
    witness / tamper-evident hash-chain anchor と表現する。
"""
import os
import re

from . import store

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

FREE_PER_DAY = int(os.environ.get("KKJ_WITNESS_FREE_PER_DAY", "5"))     # IP毎の1日無料枠
GLOBAL_MAX_PER_DAY = int(os.environ.get("KKJ_WITNESS_MAX_PER_DAY", "50000"))  # root肥大の保険
PRICE_USD = float(os.environ.get("KKJ_WITNESS_PRICE_USD", "0.005"))    # 有料anchor単価

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS anchors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL UNIQUE,        -- 提出された64桁hexダイジェストのみ(原文は保持しない)
    submitted_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending / committed
    root_date TEXT,                     -- 封入された日次rootの日付
    leaf_index INTEGER,                 -- その日のMerkle葉インデックス
    paid INTEGER NOT NULL DEFAULT 0,
    client TEXT                         -- レート制御用(内部のみ・証明には含めない)
);
CREATE INDEX IF NOT EXISTS idx_anchors_status ON anchors(status);
CREATE INDEX IF NOT EXISTS idx_anchors_client ON anchors(client, submitted_at);
"""


def normalize_sha256(value):
    """sha256を検証・正規化。64桁hex以外はNone(=rawデータ・不正入力を弾く)"""
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if v.startswith("0x"):
        v = v[2:]
    return v if SHA256_RE.match(v) else None


def get(conn, sha256):
    conn.executescript(SCHEMA_SQL)
    return conn.execute("SELECT * FROM anchors WHERE sha256=?", (sha256,)).fetchone()


def free_used_today(conn, client):
    return conn.execute(
        "SELECT COUNT(*) n FROM anchors WHERE client=? AND paid=0 "
        "AND substr(submitted_at,1,10)=substr(?,1,10)",
        (client, store.now_utc())).fetchone()["n"]


def total_today(conn):
    return conn.execute(
        "SELECT COUNT(*) n FROM anchors WHERE substr(submitted_at,1,10)=substr(?,1,10)",
        (store.now_utc(),)).fetchone()["n"]


def quota_state(conn, client):
    """(free_remaining, needs_payment, global_full) を返す"""
    conn.executescript(SCHEMA_SQL)
    if total_today(conn) >= GLOBAL_MAX_PER_DAY:
        return 0, True, True
    used = free_used_today(conn, client)
    remaining = max(0, FREE_PER_DAY - used)
    return remaining, remaining == 0, False


def insert(conn, sha256, client, paid):
    """anchorをpendingで登録(冪等: 既存があればそれを返す)。原文は受け取らない。"""
    conn.executescript(SCHEMA_SQL)
    existing = get(conn, sha256)
    if existing is not None:
        return existing, False
    conn.execute(
        "INSERT INTO anchors(sha256, submitted_at, status, paid, client) VALUES (?,?,?,?,?)",
        (sha256, store.now_utc(), "pending", 1 if paid else 0, client))
    conn.commit()
    return get(conn, sha256), True


# ---- attest.root から呼ばれる: 未封入anchorを葉レコード化 / 封入確定 ----

def anchor_record(row):
    """Merkle葉に入れる canonical レコード(sha256+最小メタのみ・原文なし)"""
    return {
        "type": "existence_anchor",
        "sha256": row["sha256"],
        "submitted_at": row["submitted_at"],
    }


def pending(conn):
    conn.executescript(SCHEMA_SQL)
    return conn.execute(
        "SELECT * FROM anchors WHERE status='pending' ORDER BY id").fetchall()


def mark_committed(conn, anchor_id, date, leaf_index):
    conn.execute(
        "UPDATE anchors SET status='committed', root_date=?, leaf_index=? WHERE id=?",
        (date, leaf_index, anchor_id))


def stats(conn=None):
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    out = {
        "anchors_total": conn.execute("SELECT COUNT(*) n FROM anchors").fetchone()["n"],
        "committed": conn.execute(
            "SELECT COUNT(*) n FROM anchors WHERE status='committed'").fetchone()["n"],
        "pending": conn.execute(
            "SELECT COUNT(*) n FROM anchors WHERE status='pending'").fetchone()["n"],
        "paid": conn.execute("SELECT COUNT(*) n FROM anchors WHERE paid=1").fetchone()["n"],
        "free_per_day": FREE_PER_DAY, "price_usd": PRICE_USD,
    }
    if own:
        conn.close()
    return out
