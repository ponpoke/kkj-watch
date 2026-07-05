"""x402 Trust Index — 掲載リソースの説明可能な格付け(0-100)

汚染されたレジストリ(23k掲載・大半が死んだテスト/スパム)から「実在し、生きていて、
掲載どおりの条件で、乗っ取り兆候のない」リソースを機械可読で選別するための格付け層。

設計原則:
  - 決定的・説明可能・バージョン付き(formula_version)。LLM不使用=コストゼロ
  - 減点根拠は全て reasons[] に列挙(エージェントが自分で再検証できる)
  - 履歴(x402watch)+実物検証(x402probe)の両方を合成。履歴は時間でしか作れない=堀

配点(合計100):
  listing_age        15  登録からの経過(30日で満点)
  listing_stability  10  直近30日にdelist/relistがない
  payto_stability    15  直近90日にpayTo変更・実物payTo不一致がない
  price_stability    10  直近30日に価格変更がない(変更=5点、実物不一致=0点)
  liveness           25  実物プローブ: 402応答=25 / 応答あり(GETでは402以外)=12 / 死=0
  consistency        20  掲載vs実物: 一致=20 / GET検証不能=8 / 価格不一致=4 / payTo不一致=0
  not_farm            5  スパムファーム(同一payToが5ホスト20掲載以上)でない
"""
import json
import time
import urllib.parse

from . import store, x402watch

FORMULA_VERSION = 1
FARM_MIN_RESOURCES = 20
FARM_MIN_HOSTS = 5

MIGRATE_SQL = (
    "ALTER TABLE x402_resources ADD COLUMN trust_score REAL",
    "ALTER TABLE x402_resources ADD COLUMN trust_json TEXT",
)

_farm_cache = {"at": 0.0, "payto_farms": frozenset()}
FARM_CACHE_TTL = 900


def _migrate(conn):
    conn.executescript(x402watch.SCHEMA_SQL)
    for sql in MIGRATE_SQL:
        try:
            conn.execute(sql)
        except Exception:
            pass


def farm_paytos(conn):
    """スパムファーム判定: 同一payToが多ホストにわたり大量掲載されているものの集合"""
    now = time.monotonic()
    if now - _farm_cache["at"] < FARM_CACHE_TTL:
        return _farm_cache["payto_farms"]
    stats = {}
    for r in conn.execute(
            "SELECT resource, latest_json FROM x402_resources WHERE active=1").fetchall():
        host = urllib.parse.urlsplit(r["resource"]).hostname or ""
        try:
            accepts = json.loads(r["latest_json"]).get("accepts", [])
        except Exception:
            continue
        for a in accepts:
            p = (a.get("payTo") or "").lower()
            if not p:
                continue
            s = stats.setdefault(p, [0, set()])
            s[0] += 1
            s[1].add(host)
    farms = frozenset(p for p, (n, hosts) in stats.items()
                      if n >= FARM_MIN_RESOURCES and len(hosts) >= FARM_MIN_HOSTS)
    _farm_cache.update(at=now, payto_farms=farms)
    return farms


def compute(conn, row):
    """1リソースのTrustスコアを計算(決定的・説明可能)"""
    rid = row["id"]
    reasons = []
    rec = json.loads(row["latest_json"])

    def ev_count(types, days):
        q = ",".join("?" * len(types))
        return conn.execute(
            f"SELECT COUNT(*) n FROM x402_events WHERE resource_id=? AND event_type IN ({q})"
            f" AND detected_at > datetime('now','-{int(days)} day')",
            (rid, *types)).fetchone()["n"]

    # listing_age (15)
    age_days = max(0.0, (time.time() - _epoch(row["first_seen"])) / 86400)
    s_age = round(min(age_days, 30) / 30 * 15, 1)
    if age_days < 7:
        reasons.append(f"listed only {age_days:.1f} days ago")

    # listing_stability (10)
    churn = ev_count(("delisted", "relisted"), 30)
    s_listing = 10 if churn == 0 else 0
    if churn:
        reasons.append(f"{churn} delist/relist events in 30d")
    if not row["active"]:
        reasons.append("currently delisted from the registry")

    # payto_stability (15)
    payto_ev = ev_count(("payto_changed", "live_payto_mismatch"), 90)
    s_payto = 15 if payto_ev == 0 else 0
    if payto_ev:
        reasons.append(f"{payto_ev} payTo change/mismatch events in 90d - verify before paying")

    # price_stability (10)
    price_ev = ev_count(("price_changed",), 30)
    s_price = 10 if price_ev == 0 else 5
    if price_ev:
        reasons.append(f"{price_ev} price changes in 30d")

    # liveness (25) + consistency (20): 最新プローブから
    probe = conn.execute(
        "SELECT * FROM x402_probes WHERE resource_id=? ORDER BY id DESC LIMIT 1",
        (rid,)).fetchone()
    verified_live = False
    last_verified = None
    if probe is None:
        s_live, s_cons = 0, 0
        consistency = "unverified"
        reasons.append("not yet probed (liveness unverified)")
    else:
        last_verified = probe["probed_at"]
        consistency = probe["consistency"]
        if probe["alive"] and probe["is_402"]:
            s_live = 25
            verified_live = True
        elif probe["alive"]:
            s_live = 12
            reasons.append("reachable but did not serve x402 (402) on GET")
        else:
            s_live = 0
            reasons.append("unreachable on last probe")
        s_cons = {"ok": 20, "not_x402": 8, "price_mismatch": 4,
                  "payto_mismatch": 0}.get(consistency, 0)
        if consistency == "payto_mismatch":
            s_live = min(s_live, 5)
            reasons.append("CRITICAL: live payTo differs from the registry listing")
        elif consistency == "price_mismatch":
            reasons.append("live price differs from the registry listing")

    # not_farm (5)
    farms = farm_paytos(conn)
    is_farm = any((a.get("payTo") or "").lower() in farms
                  for a in rec.get("accepts", []))
    s_farm = 0 if is_farm else 5
    if is_farm:
        reasons.append(f"payTo is shared across {FARM_MIN_RESOURCES}+ listings on "
                       f"{FARM_MIN_HOSTS}+ hosts (possible spam farm)")

    score = round(s_age + s_listing + s_payto + s_price + s_live + s_cons + s_farm, 1)
    grade = ("A" if score >= 85 else "B" if score >= 70 else
             "C" if score >= 50 else "D" if score >= 30 else "F")
    return {
        "score": score, "grade": grade,
        "formula_version": FORMULA_VERSION,
        "verdicts": {
            "verified_live": verified_live,
            "listing_matches_live": {"ok": "ok", "payto_mismatch": "mismatch",
                                     "price_mismatch": "mismatch"}.get(consistency, "unknown"),
            "payto_risk": ("live_mismatch" if consistency == "payto_mismatch"
                           else "changed_recently" if payto_ev else "none"),
            "farm_member": is_farm,
            "active_listing": bool(row["active"]),
        },
        "components": {"listing_age": s_age, "listing_stability": s_listing,
                       "payto_stability": s_payto, "price_stability": s_price,
                       "liveness": s_live, "consistency": s_cons, "not_farm": s_farm},
        "age_days": round(age_days, 1),
        "last_verified_at": last_verified,
        "reasons": reasons,
        "computed_at": store.now_utc(),
    }


def _epoch(iso: str) -> float:
    from datetime import datetime
    try:
        return datetime.fromisoformat(iso).timestamp()
    except Exception:
        return time.time()


def update_score(conn, resource_id: int):
    """プローブ後などにスコアを再計算して保存"""
    _migrate(conn)
    row = conn.execute("SELECT * FROM x402_resources WHERE id=?", (resource_id,)).fetchone()
    if row is None:
        return None
    t = compute(conn, row)
    conn.execute("UPDATE x402_resources SET trust_score=?, trust_json=? WHERE id=?",
                 (t["score"], json.dumps(t, ensure_ascii=False), resource_id))
    return t


def get_or_compute(conn, row):
    """保存済みスコアがあれば返し、なければレジストリ情報のみで計算(保存もする)"""
    _migrate(conn)
    try:
        if row["trust_json"]:
            return json.loads(row["trust_json"])
    except (KeyError, IndexError):
        pass
    return update_score(conn, row["id"])
