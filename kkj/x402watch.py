"""x402エコシステム(Bazaar)レジストリの変更検知

「エージェント経済の変更検知レイヤー」第1弾。Coinbase CDPのx402 Bazaar discovery API
(公開・認証不要・単一固定ホスト)に登録された全リソースの掲載内容を巡回し、
価格(amount)・受取アドレス(payTo)・スキーマ・掲載状態の変化を構造化イベントとして検知する。

安全設計(重要):
  - 監視対象は Bazaar レジストリの掲載内容のみ。掲載されている23k超の外部エンドポイント
    へは一切リクエストしない(SSRF/迷惑クロール/コスト増リスクをゼロにする)。
  - 任意URL登録機能は提供しない。
  - 通信先は https://api.cdp.coinbase.com 固定。

イベント種別(ルールベース・LLM不要・コストゼロ):
  new_resource        新規掲載
  delisted / relisted 掲載削除・再掲載(完全同期成功時のみ判定)
  price_changed       同一(scheme,network,asset)で amount が変化
  payto_changed       受取アドレス変化(ウォレット差し替え/乗っ取りの兆候: severity=critical)
  accepts_changed     支払い手段(ネットワーク/アセット)の追加・削除
  schema_changed      入出力スキーマ(extensions)の変化
  description_changed 説明文の変化

  python -m kkj.x402watch sync    # 1回同期(systemdタイマーから毎時)
  python -m kkj.x402watch stats   # 蓄積状況
"""
import hashlib
import json
import sys
import time
import urllib.parse
import urllib.request

from . import store

BAZAAR_URL = "https://api.cdp.coinbase.com/platform/v2/x402/discovery/resources"
PAGE_LIMIT = 100
PAGE_DELAY_SEC = 0.15
FETCH_TIMEOUT = 30
MAX_PAGES = 600          # 暴走上限(6万件相当)
USER_AGENT = "kkj-watch-x402registry/0.1 (registry change-detection; contact: ponzuzuzuzuzu@gmail.com)"

# 既知のUSDCアセット(6 decimals) → USD換算表示に使う
USDC_ASSETS = {
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",   # Base
    "0x036CbD53842c5426634e7929541eC2318f3dCF7e",   # Base Sepolia
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",  # Solana mainnet
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS x402_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource TEXT NOT NULL UNIQUE,
    service_name TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    miss_count INTEGER NOT NULL DEFAULT 0,
    latest_hash TEXT NOT NULL,
    latest_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_x402res_resource ON x402_resources(resource);
CREATE TABLE IF NOT EXISTS x402_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    fetched_at TEXT NOT NULL,
    hash TEXT NOT NULL,
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_x402snap_res ON x402_snapshots(resource_id);
CREATE TABLE IF NOT EXISTS x402_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,            -- critical / high / medium / low
    detected_at TEXT NOT NULL,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_x402ev_res ON x402_events(resource_id);
CREATE INDEX IF NOT EXISTS idx_x402ev_at ON x402_events(detected_at);
CREATE TABLE IF NOT EXISTS x402_sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    total INTEGER, fetched INTEGER,
    new_n INTEGER, changed_n INTEGER, delisted_n INTEGER,
    complete INTEGER NOT NULL,
    error TEXT
);
"""


def usd_of(amount, asset):
    """USDCアセットならUSD額(6 decimals)。それ以外はNone(誤換算を出さない)"""
    if asset in USDC_ASSETS:
        try:
            return round(int(amount) / 1_000_000, 6)
        except (TypeError, ValueError):
            return None
    return None


def normalize(item: dict) -> dict:
    """Bazaar掲載1件を変化検知用に正規化(lastUpdated/iconUrl等の揮発・無価値フィールドは除外)"""
    seen, accepts = set(), []
    for a in item.get("accepts") or []:
        rec = {
            "scheme": a.get("scheme"),
            "network": a.get("network"),
            "asset": a.get("asset"),
            "amount": str(a.get("amount") if a.get("amount") is not None
                          else a.get("maxAmountRequired") or ""),
            "payTo": a.get("payTo"),
        }
        k = json.dumps(rec, sort_keys=True)
        if k not in seen:               # Bazaarは同一acceptを重複掲載することがある
            seen.add(k)
            accepts.append(rec)
    accepts.sort(key=lambda x: (x["scheme"] or "", x["network"] or "", x["asset"] or ""))
    desc = item.get("description") or ""
    schema_blob = json.dumps(item.get("extensions") or {}, sort_keys=True, ensure_ascii=False)
    return {
        "resource": item.get("resource"),
        "type": item.get("type"),
        "x402Version": item.get("x402Version"),
        "serviceName": item.get("serviceName"),
        "tags": sorted(item.get("tags") or []),
        "description": desc[:400],
        "description_sha256": hashlib.sha256(desc.encode("utf-8")).hexdigest(),
        "schema_sha256": hashlib.sha256(schema_blob.encode("utf-8")).hexdigest(),
        "accepts": accepts,
    }


def canonical_hash(norm: dict) -> str:
    return hashlib.sha256(
        json.dumps(norm, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def diff_events(old: dict, new: dict) -> list:
    """正規化レコード2つを比較し (event_type, severity, detail) のリストを返す"""
    evs = []
    okey = {(a["scheme"], a["network"], a["asset"]): a for a in old.get("accepts", [])}
    nkey = {(a["scheme"], a["network"], a["asset"]): a for a in new.get("accepts", [])}
    for k in sorted(set(okey) & set(nkey), key=str):
        oa, na = okey[k], nkey[k]
        if oa["amount"] != na["amount"]:
            evs.append(("price_changed", "high", {
                "scheme": k[0], "network": k[1], "asset": k[2],
                "before": oa["amount"], "after": na["amount"],
                "before_usd": usd_of(oa["amount"], k[2]),
                "after_usd": usd_of(na["amount"], k[2]),
            }))
        if oa["payTo"] != na["payTo"]:
            evs.append(("payto_changed", "critical", {
                "scheme": k[0], "network": k[1], "asset": k[2],
                "before": oa["payTo"], "after": na["payTo"],
                "note": "Receiving address changed. Verify with the provider before paying "
                        "(possible wallet rotation or hijack).",
            }))
    added = sorted(set(nkey) - set(okey), key=str)
    removed = sorted(set(okey) - set(nkey), key=str)
    if added or removed:
        evs.append(("accepts_changed", "medium", {
            "added": [{"scheme": k[0], "network": k[1], "asset": k[2],
                       "amount": nkey[k]["amount"], "payTo": nkey[k]["payTo"]} for k in added],
            "removed": [{"scheme": k[0], "network": k[1], "asset": k[2]} for k in removed],
        }))
    if old.get("schema_sha256") != new.get("schema_sha256"):
        evs.append(("schema_changed", "medium", {
            "before_sha256": old.get("schema_sha256"), "after_sha256": new.get("schema_sha256"),
            "note": "Input/output schema changed. Cached request templates may be stale.",
        }))
    if old.get("description_sha256") != new.get("description_sha256"):
        evs.append(("description_changed", "low", {
            "before": old.get("description"), "after": new.get("description"),
        }))
    return evs


def fetch_pages():
    """Bazaar全ページを取得。戻り値: (items, complete, error)"""
    items, offset, err = [], 0, None
    for _ in range(MAX_PAGES):
        url = f"{BAZAAR_URL}?{urllib.parse.urlencode({'limit': PAGE_LIMIT, 'offset': offset})}"
        req = urllib.request.Request(url, headers={
            "Accept": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                page = json.loads(resp.read())
        except Exception as e:
            time.sleep(2)               # 1回だけリトライ
            try:
                with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
                    page = json.loads(resp.read())
            except Exception as e2:
                err = f"page offset={offset}: {e2}"
                return items, False, err
        batch = page.get("items") or []
        items.extend(batch)
        total = (page.get("pagination") or {}).get("total", 0)
        offset += len(batch)
        if not batch or offset >= total:
            return items, True, None
        time.sleep(PAGE_DELAY_SEC)
    return items, False, "max_pages_exceeded"


def sync(conn=None):
    """1回の同期: 全ページ取得→差分イベント化→delist判定(完全同期時のみ)"""
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    ts = store.now_utc()
    seed = conn.execute("SELECT COUNT(*) n FROM x402_resources").fetchone()["n"] == 0

    items, complete, err = fetch_pages()
    new_n = changed_n = delisted_n = 0
    seen_urls = set()
    for item in items:
        url = item.get("resource")
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        norm = normalize(item)
        h = canonical_hash(norm)
        raw = json.dumps(norm, ensure_ascii=False, sort_keys=True)
        row = conn.execute(
            "SELECT id, active, latest_hash, latest_json FROM x402_resources WHERE resource=?",
            (url,)).fetchone()
        if row is None:
            cur = conn.execute(
                "INSERT INTO x402_resources(resource, service_name, first_seen, last_seen,"
                " active, latest_hash, latest_json) VALUES (?,?,?,?,1,?,?)",
                (url, norm.get("serviceName"), ts, ts, h, raw))
            rid = cur.lastrowid
            conn.execute(
                "INSERT INTO x402_snapshots(resource_id, fetched_at, hash, raw_json) VALUES (?,?,?,?)",
                (rid, ts, h, raw))
            if not seed:                # 初回シード時は2.3万件のイベント洪水を出さない
                conn.execute(
                    "INSERT INTO x402_events(resource_id, event_type, severity, detected_at,"
                    " detail_json) VALUES (?,?,?,?,?)",
                    (rid, "new_resource", "medium", ts, json.dumps({
                        "resource": url, "serviceName": norm.get("serviceName"),
                        "accepts": norm["accepts"], "description": norm["description"][:200],
                    }, ensure_ascii=False)))
            new_n += 1
            continue
        rid = row["id"]
        conn.execute("UPDATE x402_resources SET miss_count=0 WHERE id=? AND miss_count>0", (rid,))
        if not row["active"]:
            conn.execute("UPDATE x402_resources SET active=1 WHERE id=?", (rid,))
            conn.execute(
                "INSERT INTO x402_events(resource_id, event_type, severity, detected_at,"
                " detail_json) VALUES (?,?,?,?,?)",
                (rid, "relisted", "medium", ts, json.dumps({"resource": url})))
        if row["latest_hash"] == h:
            conn.execute("UPDATE x402_resources SET last_seen=? WHERE id=?", (ts, rid))
            continue
        old = json.loads(row["latest_json"])
        conn.execute(
            "UPDATE x402_resources SET last_seen=?, latest_hash=?, latest_json=?,"
            " service_name=? WHERE id=?",
            (ts, h, raw, norm.get("serviceName"), rid))
        conn.execute(
            "INSERT INTO x402_snapshots(resource_id, fetched_at, hash, raw_json) VALUES (?,?,?,?)",
            (rid, ts, h, raw))
        for etype, sev, detail in diff_events(old, norm):
            detail["resource"] = url
            conn.execute(
                "INSERT INTO x402_events(resource_id, event_type, severity, detected_at,"
                " detail_json) VALUES (?,?,?,?,?)",
                (rid, etype, sev, ts, json.dumps(detail, ensure_ascii=False)))
        changed_n += 1

    # delist判定は「完全同期に成功し、かつ2回連続で不在」のときだけ。
    # (途中失敗の大量誤検知と、offsetページネーションの順序ずれによる取りこぼしを防ぐ)
    if complete and seen_urls:
        for r in conn.execute(
                "SELECT id, resource, miss_count FROM x402_resources WHERE active=1").fetchall():
            if r["resource"] in seen_urls:
                continue
            if r["miss_count"] + 1 >= 2:
                conn.execute(
                    "UPDATE x402_resources SET active=0, miss_count=0 WHERE id=?", (r["id"],))
                if not seed:
                    conn.execute(
                        "INSERT INTO x402_events(resource_id, event_type, severity, detected_at,"
                        " detail_json) VALUES (?,?,?,?,?)",
                        (r["id"], "delisted", "high", ts, json.dumps(
                            {"resource": r["resource"],
                             "note": "Removed from the Bazaar registry. The endpoint may be "
                                     "gone or unlisted; do not rely on cached payment terms."})))
                delisted_n += 1
            else:
                conn.execute(
                    "UPDATE x402_resources SET miss_count=miss_count+1 WHERE id=?", (r["id"],))

    conn.execute(
        "INSERT INTO x402_sync_log(at, total, fetched, new_n, changed_n, delisted_n, complete,"
        " error) VALUES (?,?,?,?,?,?,?,?)",
        (ts, len(seen_urls), len(items), new_n, changed_n, delisted_n, 1 if complete else 0, err))
    conn.commit()
    out = {"at": ts, "seed": seed, "fetched": len(items), "unique": len(seen_urls),
           "new": new_n, "changed": changed_n, "delisted": delisted_n,
           "complete": complete, "error": err}
    if own:
        conn.close()
    return out


def stats(conn=None):
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    out = {
        "resources": conn.execute("SELECT COUNT(*) n FROM x402_resources").fetchone()["n"],
        "active": conn.execute(
            "SELECT COUNT(*) n FROM x402_resources WHERE active=1").fetchone()["n"],
        "snapshots": conn.execute("SELECT COUNT(*) n FROM x402_snapshots").fetchone()["n"],
        "events": conn.execute("SELECT COUNT(*) n FROM x402_events").fetchone()["n"],
        "events_by_type": {r["event_type"]: r["n"] for r in conn.execute(
            "SELECT event_type, COUNT(*) n FROM x402_events GROUP BY event_type")},
        "last_sync": None,
    }
    r = conn.execute("SELECT * FROM x402_sync_log ORDER BY id DESC LIMIT 1").fetchone()
    if r:
        out["last_sync"] = {k: r[k] for k in r.keys()}
    if own:
        conn.close()
    return out


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "sync"
    if cmd == "sync":
        print(json.dumps(sync(), ensure_ascii=False, indent=1))
    elif cmd == "stats":
        print(json.dumps(stats(), ensure_ascii=False, indent=1))
    else:
        print("usage: python -m kkj.x402watch [sync|stats]")


if __name__ == "__main__":
    main()
