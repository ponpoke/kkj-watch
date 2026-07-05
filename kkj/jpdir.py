"""日本エージェント資源目録 — 機械可読な公開リソースの検証済み一次インデックス

日本のエージェント向け機械可読リソース(公的データAPI・x402対応・機械可読価格表)を、
実際に叩いて確認した稼働状況・機械可読性・スキーマ指紋・認証要否付きで目録化する。
価値は運営者の権威ではなく「叩いたら動いた」という検証の事実性(=前システムと同じ原理)。

安全・コスト設計:
  - 掲載は curated seed のみ(任意URL登録なし)。SSRFガードは x402probe を流用
  - GETのみ・低頻度(日次)・不払い。LLM不要。運用コストはVPS+ストレージのみ
  - 出所(provenance)を全出力に埋め込み、下流エージェントが原典へ辿れる終点を運ぶ

  python -m kkj.jpdir sync    # 目録同期(seedを叩いて観測を更新、systemdタイマーで日次)
  python -m kkj.jpdir stats
"""
import hashlib
import json
import sys
import urllib.parse

from . import store, x402probe

USER_AGENT = ("kkj-watch-jpdir/0.1 (verified directory of Japanese machine-readable resources; "
              "GET-only, low-frequency; contact: ponzuzuzuzuzu@gmail.com)")
MAX_BODY = 200000

# curated seed: 日本の機械可読な公開リソース。auth_required は既知の前提(叩く前から分かる)。
SEED = [
    {"name": "気象庁 天気予報(東京)", "provider": "気象庁 (JMA)", "category": "weather",
     "url": "https://www.jma.go.jp/bosai/forecast/data/forecast/130000.json",
     "docs": "https://www.jma.go.jp/bosai/", "auth_required": False},
    {"name": "郵便番号検索 API", "provider": "アイビス (zipcloud)", "category": "geo",
     "url": "https://zipcloud.ibsnet.co.jp/api/search?zipcode=1000001",
     "docs": "https://zipcloud.ibsnet.co.jp/doc/api", "auth_required": False},
    {"name": "国土地理院 住所検索", "provider": "国土地理院 (GSI)", "category": "geo",
     "url": "https://msearch.gsi.go.jp/address-search/AddressSearch?q=%E7%9A%87%E5%B1%85",
     "docs": "https://maps.gsi.go.jp/development/api.html", "auth_required": False},
    {"name": "e-Gov 法令API(法令一覧)", "provider": "デジタル庁 (e-Gov)", "category": "legal",
     "url": "https://laws.e-gov.go.jp/api/1/lawlists/1",
     "docs": "https://laws.e-gov.go.jp/apitop/", "auth_required": False},
    {"name": "data.go.jp CKAN(データセット一覧)", "provider": "デジタル庁", "category": "opendata",
     "url": "https://www.data.go.jp/data/api/3/action/package_list",
     "docs": "https://www.data.go.jp/", "auth_required": False},
    {"name": "e-Stat 統計API(統計表一覧)", "provider": "総務省統計局 (e-Stat)", "category": "statistics",
     "url": "https://api.e-stat.go.jp/rest/3.0/app/json/getStatsList",
     "docs": "https://www.e-stat.go.jp/api/", "auth_required": True},
    {"name": "RESAS 地域経済API(都道府県一覧)", "provider": "内閣府 (RESAS)", "category": "statistics",
     "url": "https://opendata.resas-portal.go.jp/api/v1/prefectures",
     "docs": "https://opendata.resas-portal.go.jp/", "auth_required": True},
    {"name": "官公需情報ポータル 検索API", "provider": "中小企業庁 (kkj)", "category": "procurement",
     "url": "https://www.kkj.go.jp/api/",
     "docs": "https://www.kkj.go.jp/", "auth_required": False},
]

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS jp_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    name TEXT, provider TEXT, category TEXT, docs TEXT,
    auth_required INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    latest_hash TEXT, latest_json TEXT,
    fail_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS jp_probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    probed_at TEXT NOT NULL,
    alive INTEGER NOT NULL,
    http_status INTEGER,
    content_type TEXT,
    machine_readable TEXT,          -- json / xml / csv / html / other / none
    schema_fingerprint TEXT,        -- 構造のSHA-256(先頭12hex)
    auth_observed TEXT,             -- open / auth_required / unknown
    latency_ms INTEGER, size INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_jp_probes_res ON jp_probes(resource_id, id);
CREATE TABLE IF NOT EXISTS jp_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    event_type TEXT NOT NULL, severity TEXT NOT NULL,
    detected_at TEXT NOT NULL, detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_jp_events_res ON jp_events(resource_id, id);
"""

DEAD_AFTER = 2


def _fingerprint(body: bytes, kind: str) -> str:
    """機械可読データの構造指紋。中身の値ではなく『形』のSHA-256(変化検知用)"""
    try:
        if kind == "json":
            d = json.loads(body)
            shape = _json_shape(d)
        elif kind == "xml":
            import re
            tags = re.findall(rb"<([A-Za-z_][\w:.-]*)", body[:MAX_BODY])
            shape = sorted(set(t.decode("ascii", "ignore") for t in tags))
        elif kind == "csv":
            first = body.split(b"\n", 1)[0]
            shape = [c.strip() for c in first.split(b",")]
            shape = [c.decode("utf-8", "ignore") for c in shape]
        else:
            return ""
        blob = json.dumps(shape, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()[:12]
    except Exception:
        return ""


def _json_shape(d, depth=0):
    """JSONの構造(キー名と型)だけを抽出。値は含めない=個人情報も保存しない"""
    if depth > 4:
        return "…"
    if isinstance(d, dict):
        return {k: _json_shape(v, depth + 1) for k, v in sorted(d.items())}
    if isinstance(d, list):
        return [_json_shape(d[0], depth + 1)] if d else []
    return type(d).__name__


def _classify_body(content_type: str, body: bytes) -> str:
    ct = (content_type or "").lower()
    head = body[:512].lstrip()
    if "json" in ct or head[:1] in (b"{", b"["):
        try:
            json.loads(body)
            return "json"
        except Exception:
            pass
    if "xml" in ct or head[:5] == b"<?xml" or head[:1] == b"<" and b"html" not in head[:120].lower():
        return "xml"
    if "csv" in ct:
        return "csv"
    if "html" in ct or head[:120].lower().startswith((b"<!doctype html", b"<html")):
        return "html"
    return "other"


def observe(row_or_seed, fetch=None):
    """1リソースを叩いて観測レコードを返す(原文は保持せず、形の指紋のみ)"""
    fetch = fetch or x402probe.fetch
    url = row_or_seed["url"]
    status, body, latency, err = fetch(url)
    alive = status is not None
    ct = ""
    machine = "none"
    fp = ""
    auth = "unknown"
    if alive:
        # content-type はfetchが返さないので簡易にbodyから推定(x402probe.fetchはbodyのみ)
        machine = _classify_body(ct, body or b"")
        fp = _fingerprint(body or b"", machine)
        if status in (401, 403):
            auth = "auth_required"
        elif status == 200:
            auth = "open"
    return {
        "alive": alive, "http_status": status, "content_type": ct or None,
        "machine_readable": machine, "schema_fingerprint": fp or None,
        "auth_observed": auth, "latency_ms": latency, "size": len(body) if body else 0,
        "error": err,
    }


def sync(conn=None, fetch=None):
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    ts = store.now_utc()
    # seedを登録(冪等)
    for s in SEED:
        r = conn.execute("SELECT id FROM jp_resources WHERE url=?", (s["url"],)).fetchone()
        if r is None:
            conn.execute(
                "INSERT INTO jp_resources(url,name,provider,category,docs,auth_required,"
                "first_seen,last_seen,active) VALUES (?,?,?,?,?,?,?,?,1)",
                (s["url"], s["name"], s["provider"], s["category"], s["docs"],
                 1 if s["auth_required"] else 0, ts, ts))
    conn.commit()

    summary = {}
    for row in conn.execute("SELECT * FROM jp_resources ORDER BY id").fetchall():
        obs = observe(row, fetch=fetch)
        conn.execute(
            "INSERT INTO jp_probes(resource_id,probed_at,alive,http_status,content_type,"
            "machine_readable,schema_fingerprint,auth_observed,latency_ms,size,error)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (row["id"], ts, 1 if obs["alive"] else 0, obs["http_status"], obs["content_type"],
             obs["machine_readable"], obs["schema_fingerprint"], obs["auth_observed"],
             obs["latency_ms"], obs["size"], obs["error"]))
        # 観測サマリを latest_json に(形の指紋のみ・原文なし)
        latest = {
            "alive": obs["alive"], "http_status": obs["http_status"],
            "machine_readable": obs["machine_readable"],
            "schema_fingerprint": obs["schema_fingerprint"],
            "auth_observed": obs["auth_observed"], "latency_ms": obs["latency_ms"],
        }
        h = hashlib.sha256(json.dumps(latest, sort_keys=True).encode()).hexdigest()
        prev = conn.execute("SELECT latest_hash, latest_json, fail_count FROM jp_resources"
                            " WHERE id=?", (row["id"],)).fetchone()
        # イベント: スキーマ変更 / 生存(2連続不在でdown, 復活)
        prev_json = json.loads(prev["latest_json"]) if prev and prev["latest_json"] else {}
        if (prev_json.get("schema_fingerprint") and obs["schema_fingerprint"]
                and prev_json["schema_fingerprint"] != obs["schema_fingerprint"]):
            _event(conn, row["id"], "schema_changed", "medium", ts,
                   {"before": prev_json["schema_fingerprint"], "after": obs["schema_fingerprint"]})
        fc = prev["fail_count"] if prev else 0
        if not obs["alive"]:
            fc += 1
            if fc == DEAD_AFTER:
                _event(conn, row["id"], "unreachable", "high", ts, {"error": obs["error"]})
        else:
            if fc >= DEAD_AFTER:
                _event(conn, row["id"], "recovered", "medium", ts, {"http_status": obs["http_status"]})
            fc = 0
        conn.execute("UPDATE jp_resources SET last_seen=?, latest_hash=?, latest_json=?,"
                     " fail_count=? WHERE id=?",
                     (ts, h, json.dumps(latest, ensure_ascii=False), fc, row["id"]))
        summary[obs["machine_readable"]] = summary.get(obs["machine_readable"], 0) + 1
    conn.commit()
    out = {"at": ts, "resources": len(SEED), "by_format": summary}
    if own:
        conn.close()
    return out


def _event(conn, rid, etype, sev, ts, detail):
    conn.execute(
        "INSERT INTO jp_events(resource_id,event_type,severity,detected_at,detail_json)"
        " VALUES (?,?,?,?,?)", (rid, etype, sev, ts, json.dumps(detail, ensure_ascii=False)))


def stats(conn=None):
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    out = {
        "resources": conn.execute("SELECT COUNT(*) n FROM jp_resources").fetchone()["n"],
        "probes": conn.execute("SELECT COUNT(*) n FROM jp_probes").fetchone()["n"],
        "by_format": {r["machine_readable"]: r["n"] for r in conn.execute(
            "SELECT machine_readable, COUNT(*) n FROM jp_resources r "
            "LEFT JOIN (SELECT resource_id, machine_readable FROM jp_probes p "
            "WHERE p.id=(SELECT MAX(id) FROM jp_probes WHERE resource_id=p.resource_id)) x "
            "ON x.resource_id=r.id GROUP BY machine_readable")},
    }
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
        print("usage: python -m kkj.jpdir [sync|stats]")


if __name__ == "__main__":
    main()
