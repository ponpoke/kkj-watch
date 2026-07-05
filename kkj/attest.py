"""観測記録の日次ハッシュチェーン + Ed25519署名アテステーション

x402 Trust Index の長期的な堀。現在スコアではなく「後から改竄できない観測記録」に
する証跡レイヤー。毎日、観測状態(x402_resources / snapshots / events / probes / trust)を
リソース単位の canonical レコードに畳み、SHA-256葉→Merkle root→前日rootを含めて署名する。

原文・本文・秘密情報は root に含めない。含めるのはハッシュと最小メタデータのみ(要件12)。

  python -m kkj.attest keygen                        # Ed25519鍵を生成(初回)
  python -m kkj.attest pubkey                         # 公開鍵を表示
  python -m kkj.attest root [YYYY-MM-DD] [--force]    # 日次rootを生成・署名
  python -m kkj.attest verify-root YYYY-MM-DD         # 署名・Merkle・連結を検証
  python -m kkj.attest prove-resource RESOURCE_ID YYYY-MM-DD   # inclusion proof

鍵の場所: 環境変数 KKJ_ATTEST_KEY (PEMパス)、既定 data/attest_ed25519.key(0600)。
公開鍵: data/attest_ed25519.pub。root JSON にも public_key を毎回埋め込む。
"""
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from . import config, store

ROOT_DIR = config.BASE_DIR / "roots"                 # GitHub公開用(要件8)
PUBLIC_ROOTS_DIR = config.DATA_DIR / "public_roots"  # ローカル出力(要件6)
KEY_PATH = os.environ.get("KKJ_ATTEST_KEY", str(config.DATA_DIR / "attest_ed25519.key"))
PUB_PATH = str(config.DATA_DIR / "attest_ed25519.pub")
ALGO = "Ed25519"
ROOT_FORMAT_VERSION = 1

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS daily_roots (
    date TEXT PRIMARY KEY,             -- YYYY-MM-DD (UTC)
    chain_index INTEGER NOT NULL,
    previous_root TEXT,                -- 前日の root_hash(連結)
    records_count INTEGER NOT NULL,
    merkle_root TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    algo TEXT NOT NULL,
    public_key TEXT NOT NULL,          -- base64(raw 32B)
    signature TEXT NOT NULL,           -- base64(sig over root_hash bytes)
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_leaves (
    date TEXT NOT NULL,
    leaf_index INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,      -- resource葉のみ有効(anchor葉は0)
    leaf_hash TEXT NOT NULL,           -- sha256(canonical(record))
    record_json TEXT NOT NULL,         -- ハッシュ+最小メタのみ(原文なし)
    leaf_type TEXT NOT NULL DEFAULT 'resource',   -- resource / anchor
    ref TEXT,                          -- resource_id or anchor sha256
    PRIMARY KEY (date, leaf_index)
);
CREATE INDEX IF NOT EXISTS idx_daily_leaves_res ON daily_leaves(date, resource_id);
"""
# 注: leaf_type/ref のインデックスは _migrate_leaves で列追加後に作成する
# (旧DBに列が無い状態でインデックスを張ろうとすると失敗するため)


# ---------- canonical / hash ----------

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_record(obj) -> str:
    return sha256_hex(canonical(obj))


# ---------- Merkle(重複末尾方式・葉=sha256(record)、節=sha256(left||right)) ----------

def merkle_root(leaf_hashes):
    if not leaf_hashes:
        return sha256_hex(b"")                    # 空木の番兵
    level = [bytes.fromhex(h) for h in leaf_hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]   # 奇数は末尾複製
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()


def merkle_proof(leaf_hashes, index):
    """指定葉のinclusion proof(下→上のsibling列)を返す"""
    path = []
    level = [bytes.fromhex(h) for h in leaf_hashes]
    idx = index
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            if i == idx or i + 1 == idx:
                if idx % 2 == 0:                  # 自分が左 → siblingは右
                    path.append({"position": "right", "sibling": right.hex()})
                else:                             # 自分が右 → siblingは左
                    path.append({"position": "left", "sibling": left.hex()})
                idx = i // 2
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return path


def verify_proof(leaf_hash, path, expected_root) -> bool:
    cur = bytes.fromhex(leaf_hash)
    for step in path:
        sib = bytes.fromhex(step["sibling"])
        if step["position"] == "right":
            cur = hashlib.sha256(cur + sib).digest()
        else:
            cur = hashlib.sha256(sib + cur).digest()
    return cur.hex() == expected_root


# ---------- Ed25519 鍵・署名 ----------

def _load_priv():
    from cryptography.hazmat.primitives import serialization
    with open(KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _pub_b64(priv) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def keygen(force=False):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    if os.path.exists(KEY_PATH) and not force:
        priv = _load_priv()
        return _pub_b64(priv), False
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    with open(KEY_PATH, "wb") as f:
        f.write(pem)
    try:
        os.chmod(KEY_PATH, 0o600)
    except OSError:
        pass
    pub = _pub_b64(priv)
    with open(PUB_PATH, "w") as f:
        f.write(pub + "\n")
    return pub, True


def sign(root_hash_hex: str, priv=None) -> str:
    priv = priv or _load_priv()
    sig = priv.sign(root_hash_hex.encode())
    return base64.b64encode(sig).decode()


def verify_signature(root_hash_hex: str, signature_b64: str, public_key_b64: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pub.verify(base64.b64decode(signature_b64), root_hash_hex.encode())
        return True
    except Exception:
        return False


# ---------- 日次レコード構築(要件1,12: ハッシュ+最小メタのみ) ----------

def build_resource_leaf(conn, r):
    """1リソースの canonical 観測レコード。snapshots/events/probes/trust を
    ハッシュに畳み込む(原文は含めない)。"""
    rid = r["id"]
    snaps = [{"id": s["id"], "fetched_at": s["fetched_at"], "hash": s["hash"]}
             for s in conn.execute(
                 "SELECT id, fetched_at, hash FROM x402_snapshots WHERE resource_id=? ORDER BY id",
                 (rid,)).fetchall()]
    events = [{"id": e["id"], "event_type": e["event_type"], "severity": e["severity"],
               "detected_at": e["detected_at"],
               "detail_hash": sha256_hex((e["detail_json"] or "").encode())}
              for e in conn.execute(
                  "SELECT id, event_type, severity, detected_at, detail_json "
                  "FROM x402_events WHERE resource_id=? ORDER BY id", (rid,)).fetchall()]
    probes = []
    try:
        probes = [{"id": p["id"], "probed_at": p["probed_at"], "alive": p["alive"],
                   "is_402": p["is_402"], "consistency": p["consistency"],
                   "live_accepts_hash": sha256_hex((p["live_accepts_json"] or "").encode())}
                  for p in conn.execute(
                      "SELECT id, probed_at, alive, is_402, consistency, live_accepts_json "
                      "FROM x402_probes WHERE resource_id=? ORDER BY id", (rid,)).fetchall()]
    except Exception:
        probes = []
    trust_hash = sha256_hex((r["trust_json"] or "").encode()) if _has(r, "trust_json") else None
    trust_score = r["trust_score"] if _has(r, "trust_score") else None
    record = {
        "type": "x402_resource_observation",
        "id": rid,
        "resource": r["resource"],
        "service_name": r["service_name"],
        "active": bool(r["active"]),
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"],
        "latest_hash": r["latest_hash"],
        "snapshots_count": len(snaps),
        "snapshots_hash": hash_record(snaps),
        "events_count": len(events),
        "events_hash": hash_record(events),
        "probes_count": len(probes),
        "probes_hash": hash_record(probes),
        "trust_score": trust_score,
        "trust_hash": trust_hash,
    }
    return record


def _row_get(row, col):
    """sqlite3.Row から安全に取得(列が無ければNone)"""
    try:
        return row[col]
    except (KeyError, IndexError):
        return None


def _has(row, col):
    """sqlite3.Row にその列が存在するか(値のNull有無ではなく列の有無)"""
    try:
        row[col]
        return True
    except (KeyError, IndexError):
        return False


def _today_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _migrate_leaves(conn):
    """既存DBの daily_leaves に leaf_type/ref 列を追加し、列追加後にインデックスを張る"""
    for sql in ("ALTER TABLE daily_leaves ADD COLUMN leaf_type TEXT NOT NULL DEFAULT 'resource'",
                "ALTER TABLE daily_leaves ADD COLUMN ref TEXT"):
        try:
            conn.execute(sql)
        except Exception:
            pass
    try:
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_daily_leaves_ref "
            "ON daily_leaves(date, leaf_type, ref)")
    except Exception:
        pass


def _init(conn):
    """attest系テーブルを初期化(スキーマ + 列マイグレーション)"""
    conn.executescript(SCHEMA_SQL)
    _migrate_leaves(conn)
    try:
        # leaves_available=0 は「公開genesis checkpoint(葉を持たない)」を表す
        conn.execute(
            "ALTER TABLE daily_roots ADD COLUMN leaves_available INTEGER NOT NULL DEFAULT 1")
    except Exception:
        pass


def published_root_hash(date):
    """roots/ または public_roots/ に公開済みの root_hash(なければNone)"""
    for d in (ROOT_DIR, PUBLIC_ROOTS_DIR):
        f = d / f"{date}.root.json"
        if f.exists():
            try:
                return json.load(open(f, encoding="utf-8")).get("root_hash")
            except Exception:
                pass
    return None


def is_published(date):
    return published_root_hash(date) is not None


def is_proof_available(conn, date):
    """制約6: 公開rootとDB rootが整合し、かつ葉がある日付のみ proof を返せる"""
    _init(conn)
    row = conn.execute(
        "SELECT root_hash, leaves_available FROM daily_roots WHERE date=?", (date,)).fetchone()
    if row is None or not row["leaves_available"]:
        return False
    ph = published_root_hash(date)
    if ph is None:
        return True                    # public_roots未書込は稀。DBに葉があれば内部的に可
    return ph == row["root_hash"]


def _write_root_file(doc, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1, sort_keys=True)


def root(date=None, force=False, conn=None, publish_github=True):
    """日次rootを生成・署名・保存・出力。戻り値: root doc(公開形)"""
    own = conn is None
    if own:
        conn = store.connect()
    from . import x402watch, x402trust, witness
    conn.executescript(x402watch.SCHEMA_SQL)
    x402trust._migrate(conn)
    _init(conn)
    conn.executescript(witness.SCHEMA_SQL)
    date = date or _today_utc()

    existing = conn.execute("SELECT * FROM daily_roots WHERE date=?", (date,)).fetchone()
    published = is_published(date)
    # 制約7: 既に公開済みの日付rootは、--forceなしでは再生成不可(DB行が無くても保護)
    if (existing is not None or published) and not force:
        if existing is not None:
            out = _public_doc(existing)
        else:                              # 公開済みだがDBに行が無い(genesis checkpoint等)
            out = {"date": date, "root_hash": published_root_hash(date),
                   "note": "already published; not regenerating"}
        if own:
            conn.close()
        return out
    # 制約7: 本番では公開済み日付への --force を禁止(暴発防止)
    if force and published and os.environ.get("KKJ_ATTEST_ALLOW_FORCE") != "1":
        if own:
            conn.close()
        raise RuntimeError(
            f"refusing to --force regenerate an already-published root for {date}. "
            "Published roots are immutable. (dev override: KKJ_ATTEST_ALLOW_FORCE=1)")

    # 鍵(なければ生成)
    pub_b64, _ = keygen()
    priv = _load_priv()

    # 葉の構築(1: resource観測をid順、2: 未封入の存在anchorをid順) — 決定的
    leaves, leaf_hashes = [], []          # 各要素: (index, kind, ref, leaf_hash, record_json)
    idx = 0
    for r in conn.execute("SELECT * FROM x402_resources ORDER BY id").fetchall():
        rec = build_resource_leaf(conn, r)
        lh = hash_record(rec)
        leaves.append((idx, "resource", str(r["id"]), lh, canonical(rec).decode("utf-8")))
        leaf_hashes.append(lh)
        idx += 1
    pending_anchors = witness.pending(conn)
    anchor_commits = []                   # (anchor_id, leaf_index)
    for a in pending_anchors:
        rec = witness.anchor_record(a)
        lh = hash_record(rec)
        leaves.append((idx, "anchor", a["sha256"], lh, canonical(rec).decode("utf-8")))
        leaf_hashes.append(lh)
        anchor_commits.append((a["id"], idx))
        idx += 1

    mroot = merkle_root(leaf_hashes)
    prev = conn.execute(
        "SELECT root_hash, chain_index FROM daily_roots ORDER BY chain_index DESC LIMIT 1"
    ).fetchone()
    previous_root = prev["root_hash"] if prev else None
    chain_index = (prev["chain_index"] + 1) if prev else 0
    created_at = store.now_utc()

    # 署名対象 = root_hash(= 全フィールドを含むdocのSHA-256)。要件3の項目を含める
    signed_doc = {
        "date": date,
        "previous_root": previous_root,
        "records_count": len(leaves),
        "merkle_root": mroot,
        "created_at": created_at,
    }
    root_hash = sha256_hex(canonical(signed_doc))
    signature = sign(root_hash, priv)

    # 保存(冪等: force時は置換)
    conn.execute("DELETE FROM daily_roots WHERE date=?", (date,))
    conn.execute("DELETE FROM daily_leaves WHERE date=?", (date,))
    conn.execute(
        "INSERT INTO daily_roots(date, chain_index, previous_root, records_count, merkle_root,"
        " root_hash, algo, public_key, signature, created_at, leaves_available)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,1)",
        (date, chain_index, previous_root, len(leaves), mroot, root_hash, ALGO,
         pub_b64, signature, created_at))
    conn.executemany(
        "INSERT INTO daily_leaves(date, leaf_index, resource_id, leaf_hash, record_json,"
        " leaf_type, ref) VALUES (?,?,?,?,?,?,?)",
        [(date, i, (int(ref) if kind == "resource" else 0), lh, rj, kind, ref)
         for (i, kind, ref, lh, rj) in leaves])
    for anchor_id, leaf_index in anchor_commits:      # 存在anchorを封入確定
        witness.mark_committed(conn, anchor_id, date, leaf_index)
    conn.commit()

    row = conn.execute("SELECT * FROM daily_roots WHERE date=?", (date,)).fetchone()
    out = _public_doc(row)
    _write_root_file(out, PUBLIC_ROOTS_DIR / f"{date}.root.json")
    if publish_github:
        _write_root_file(out, ROOT_DIR / f"{date}.root.json")
        _write_root_file(out, ROOT_DIR / "latest.json")
    if own:
        conn.close()
    return out


def _public_doc(row):
    """公開root JSON(要件3,6の項目。原文・葉は含めない=要件12)"""
    return {
        "format_version": ROOT_FORMAT_VERSION,
        "service": "kkj-watch x402 Trust Index",
        "record": "daily signed hash-chain root of observed x402 registry records",
        "date": row["date"],
        "chain_index": row["chain_index"],
        "previous_root": row["previous_root"],
        "records_count": row["records_count"],
        "merkle_root": row["merkle_root"],
        "root_hash": row["root_hash"],
        "algo": row["algo"],
        "public_key": row["public_key"],
        "signature": row["signature"],
        "created_at": row["created_at"],
        "verify": {
            "root_hash": "sha256(canonical({date,previous_root,records_count,merkle_root,created_at}))",
            "signature": "Ed25519.verify(public_key, signature, utf8(root_hash))",
            "merkle": "leaf=sha256(canonical(record)); node=sha256(left||right); duplicate last if odd",
            "chain": "this.previous_root == prior day's root_hash",
            "cli": "python -m kkj.attest verify-root " + row["date"],
        },
    }


# ---------- 検証(要件9) ----------

def verify_root(date, conn=None):
    own = conn is None
    if own:
        conn = store.connect()
    _init(conn)
    row = conn.execute("SELECT * FROM daily_roots WHERE date=?", (date,)).fetchone()
    if row is None:
        if own:
            conn.close()
        return {"ok": False, "error": "root_not_found", "date": date}
    # genesis checkpoint(葉なし): 署名・root_hash・連結のみ検証(Merkleは葉が無いため対象外)
    if not _row_get(row, "leaves_available"):
        signed_doc = {"date": row["date"], "previous_root": row["previous_root"],
                      "records_count": row["records_count"], "merkle_root": row["merkle_root"],
                      "created_at": row["created_at"]}
        rh_ok = sha256_hex(canonical(signed_doc)) == row["root_hash"]
        sig_ok = verify_signature(row["root_hash"], row["signature"], row["public_key"])
        chain_ok = (row["previous_root"] is None) if row["chain_index"] == 0 else True
        out = {"ok": bool(rh_ok and sig_ok), "checkpoint": True, "date": date,
               "chain_index": row["chain_index"],
               "checks": {"root_hash": rh_ok, "signature": sig_ok, "chain_link": chain_ok,
                          "merkle": "n/a (public genesis checkpoint; leaves not retained)"},
               "root_hash": row["root_hash"], "public_key": row["public_key"],
               "note": "Public genesis checkpoint. Later roots are hash-chained from this "
                       "root_hash; individual leaf proofs are available from the next root onward."}
        if own:
            conn.close()
        return out
    # 1) Merkle再計算(保存された葉から)
    leaf_hashes = [r["leaf_hash"] for r in conn.execute(
        "SELECT leaf_hash FROM daily_leaves WHERE date=? ORDER BY leaf_index", (date,)).fetchall()]
    recomputed_merkle = merkle_root(leaf_hashes)
    merkle_ok = (recomputed_merkle == row["merkle_root"])
    # 2) root_hash再計算
    signed_doc = {"date": row["date"], "previous_root": row["previous_root"],
                  "records_count": row["records_count"], "merkle_root": row["merkle_root"],
                  "created_at": row["created_at"]}
    recomputed_root = sha256_hex(canonical(signed_doc))
    root_hash_ok = (recomputed_root == row["root_hash"])
    # 3) 署名
    sig_ok = verify_signature(row["root_hash"], row["signature"], row["public_key"])
    # 4) 連結(前日root_hashと一致)
    prev = conn.execute(
        "SELECT root_hash FROM daily_roots WHERE chain_index=?",
        (row["chain_index"] - 1,)).fetchone()
    if row["chain_index"] == 0:
        chain_ok = (row["previous_root"] is None)
    else:
        chain_ok = (prev is not None and row["previous_root"] == prev["root_hash"])
    # 5) 葉数一致
    count_ok = (len(leaf_hashes) == row["records_count"])
    out = {
        "ok": bool(merkle_ok and root_hash_ok and sig_ok and chain_ok and count_ok),
        "date": date, "chain_index": row["chain_index"],
        "checks": {"merkle": merkle_ok, "root_hash": root_hash_ok, "signature": sig_ok,
                   "chain_link": chain_ok, "records_count": count_ok},
        "merkle_root": row["merkle_root"], "root_hash": row["root_hash"],
        "previous_root": row["previous_root"], "public_key": row["public_key"],
    }
    if own:
        conn.close()
    return out


def _checkpoint_response(date):
    return {
        "ok": False, "status": "checkpoint", "date": date,
        "note": "This date is a public genesis checkpoint: its individual leaves are not "
                "retained, so per-item proofs are unavailable. Later roots remain "
                "hash-chained from this checkpoint's root_hash (previous_root), so proofs "
                "issued from the next root onward are anchored to the public checkpoint.",
    }


def prove_resource(resource_id, date, conn=None):
    own = conn is None
    if own:
        conn = store.connect()
    _init(conn)
    row = conn.execute("SELECT * FROM daily_roots WHERE date=?", (date,)).fetchone()
    if row is None:
        if own:
            conn.close()
        return {"ok": False, "error": "root_not_found", "date": date}
    if not _row_get(row, "leaves_available"):
        if own:
            conn.close()
        return _checkpoint_response(date)
    leaves = conn.execute(
        "SELECT leaf_index, resource_id, leaf_hash, record_json FROM daily_leaves "
        "WHERE date=? ORDER BY leaf_index", (date,)).fetchall()
    leaf_hashes = [l["leaf_hash"] for l in leaves]
    target = next((l for l in leaves if l["resource_id"] == int(resource_id)), None)
    if target is None:
        if own:
            conn.close()
        return {"ok": False, "error": "resource_not_in_root", "resource_id": resource_id,
                "date": date}
    idx = target["leaf_index"]
    path = merkle_proof(leaf_hashes, idx)
    ok = verify_proof(target["leaf_hash"], path, row["merkle_root"])
    sig_ok = verify_signature(row["root_hash"], row["signature"], row["public_key"])
    out = {
        "ok": bool(ok and sig_ok),
        "date": date, "resource_id": int(resource_id),
        "record": json.loads(target["record_json"]),
        "leaf_hash": target["leaf_hash"], "leaf_index": idx,
        "inclusion_proof": path,
        "merkle_root": row["merkle_root"], "root_hash": row["root_hash"],
        "previous_root": row["previous_root"],
        "algo": row["algo"], "public_key": row["public_key"], "signature": row["signature"],
        "verify_steps": [
            "1. leaf_hash == sha256(canonical(record))",
            "2. fold inclusion_proof over leaf_hash (node=sha256(left||right)) == merkle_root",
            "3. root_hash == sha256(canonical({date,previous_root,records_count,merkle_root,created_at}))",
            "4. Ed25519.verify(public_key, signature, utf8(root_hash))",
        ],
        "signature_ok": sig_ok,
    }
    if own:
        conn.close()
    return out


def prove_anchor(sha256, conn=None):
    """存在anchor(sha256)の署名付きinclusion proofを返す。未封入ならpending。"""
    own = conn is None
    if own:
        conn = store.connect()
    _init(conn)
    from . import witness
    a = witness.get(conn, sha256)
    if a is None:
        if own:
            conn.close()
        return {"ok": False, "error": "not_anchored", "sha256": sha256}
    if a["status"] != "committed":
        if own:
            conn.close()
        return {"ok": False, "status": "pending", "sha256": sha256,
                "note": "Accepted. Will be included in the next daily signed root (~23:55 UTC)."}
    date = a["root_date"]
    row = conn.execute("SELECT * FROM daily_roots WHERE date=?", (date,)).fetchone()
    if row is not None and not _row_get(row, "leaves_available"):
        if own:
            conn.close()
        return _checkpoint_response(date)
    leaves = conn.execute(
        "SELECT leaf_index, leaf_hash, record_json, leaf_type, ref FROM daily_leaves "
        "WHERE date=? ORDER BY leaf_index", (date,)).fetchall()
    leaf_hashes = [l["leaf_hash"] for l in leaves]
    target = next((l for l in leaves if l["leaf_type"] == "anchor" and l["ref"] == sha256), None)
    if row is None or target is None:
        if own:
            conn.close()
        return {"ok": False, "error": "root_or_leaf_missing", "sha256": sha256}
    idx = target["leaf_index"]
    path = merkle_proof(leaf_hashes, idx)
    ok = verify_proof(target["leaf_hash"], path, row["merkle_root"])
    sig_ok = verify_signature(row["root_hash"], row["signature"], row["public_key"])
    out = {
        "ok": bool(ok and sig_ok),
        "kind": "signed_existence_proof",
        "statement": f"The SHA-256 digest {sha256} existed at or before "
                     f"{row['created_at']} (committed to our tamper-evident hash chain).",
        "not_a_notarization": "This is a cryptographic timestamp witness, not a legal "
                              "notarization. We store only the digest, never the underlying data.",
        "sha256": sha256, "date": date,
        "record": json.loads(target["record_json"]),
        "leaf_hash": target["leaf_hash"], "leaf_index": idx,
        "inclusion_proof": path,
        "merkle_root": row["merkle_root"], "root_hash": row["root_hash"],
        "previous_root": row["previous_root"], "created_at": row["created_at"],
        "algo": row["algo"], "public_key": row["public_key"], "signature": row["signature"],
        "witness": "kkj-watch",
        "attribution": "Signed existence proof by kkj-watch. This proof is invalid without the "
                       "witness identity (public_key + root_hash); it cannot be de-attributed.",
        "verify_steps": [
            "1. leaf_hash == sha256(canonical(record)); record.sha256 is your digest",
            "2. fold inclusion_proof over leaf_hash (node=sha256(left||right)) == merkle_root",
            "3. root_hash == sha256(canonical({date,previous_root,records_count,merkle_root,created_at}))",
            "4. Ed25519.verify(public_key, signature, utf8(root_hash))",
        ],
        "signature_ok": sig_ok,
    }
    if own:
        conn.close()
    return out


def latest_root(conn):
    conn.executescript(SCHEMA_SQL)
    return conn.execute(
        "SELECT * FROM daily_roots ORDER BY chain_index DESC LIMIT 1").fetchone()


def stats(conn=None):
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    r = latest_root(conn)
    out = {
        "roots": conn.execute("SELECT COUNT(*) n FROM daily_roots").fetchone()["n"],
        "latest": (_public_doc(r) if r else None),
        "public_key": (r["public_key"] if r else None),
    }
    if own:
        conn.close()
    return out


def main():
    args = sys.argv[1:]
    cmd = args[0] if args else "root"
    if cmd == "keygen":
        pub, created = keygen(force="--force" in args)
        print(json.dumps({"public_key": pub, "created": created, "algo": ALGO,
                          "key_path": KEY_PATH}, indent=1))
    elif cmd == "pubkey":
        pub, _ = keygen()
        print(pub)
    elif cmd == "root":
        date = next((a for a in args[1:] if not a.startswith("--")), None)
        print(json.dumps(root(date=date, force="--force" in args), ensure_ascii=False, indent=1))
    elif cmd == "verify-root":
        print(json.dumps(verify_root(args[1]), ensure_ascii=False, indent=1))
    elif cmd == "prove-resource":
        print(json.dumps(prove_resource(args[1], args[2]), ensure_ascii=False, indent=1))
    elif cmd == "prove-hash":
        print(json.dumps(prove_anchor(args[1]), ensure_ascii=False, indent=1))
    else:
        print("usage: python -m kkj.attest [keygen|pubkey|root [DATE] [--force]|"
              "verify-root DATE|prove-resource RID DATE|prove-hash SHA256]")


if __name__ == "__main__":
    main()
