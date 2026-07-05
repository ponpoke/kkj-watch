"""x402watch のユニットテスト(ネットワーク不要・一時DB使用)

  python -m kkj.test_x402watch
"""
import json
import os
import tempfile

# 一時DBに切り替えてから import(config.DB_PATH を差し替え)
_tmp = tempfile.mkdtemp()
from . import config
config.DATA_DIR = type(config.DATA_DIR)(_tmp)
config.DB_PATH = config.DATA_DIR / "test_x402.db"

from . import store, x402watch  # noqa: E402

PASS = FAIL = 0


def check(name, cond, info=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok: {name}")
    else:
        FAIL += 1
        print(f"  NG: {name} {info}")


def item(resource, amount="1000", payto="0xAAA", desc="d", network="eip155:8453",
         asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", extensions=None):
    return {
        "resource": resource, "type": "http", "x402Version": 2,
        "serviceName": "svc", "tags": [], "description": desc,
        "extensions": extensions or {},
        "accepts": [{"scheme": "exact", "network": network, "asset": asset,
                     "amount": amount, "payTo": payto}],
    }


def fake_pages(items):
    """fetch_pages を固定リストに差し替え"""
    x402watch.fetch_pages = lambda: (list(items), True, None)


def events_of(conn, resource):
    return conn.execute(
        """SELECT e.event_type, e.severity, e.detail_json FROM x402_events e
           JOIN x402_resources r ON r.id=e.resource_id WHERE r.resource=?
           ORDER BY e.id""", (resource,)).fetchall()


def main():
    print("== normalize / diff_events ==")
    n1 = x402watch.normalize(item("https://a.example/x"))
    n2 = x402watch.normalize(item("https://a.example/x"))
    check("同一itemは同一ハッシュ",
          x402watch.canonical_hash(n1) == x402watch.canonical_hash(n2))
    # Bazaarの重複acceptsは畳む
    dup = item("https://a.example/x")
    dup["accepts"].append(dict(dup["accepts"][0]))
    check("重複acceptsを除去", len(x402watch.normalize(dup)["accepts"]) == 1)
    # lastUpdated/iconUrl は変化検知に影響しない
    volatile = item("https://a.example/x")
    volatile["lastUpdated"] = "2099-01-01T00:00:00Z"
    volatile["iconUrl"] = "https://cdn/icon2.png"
    check("揮発フィールドはハッシュ不変",
          x402watch.canonical_hash(x402watch.normalize(volatile))
          == x402watch.canonical_hash(n1))

    evs = x402watch.diff_events(
        x402watch.normalize(item("u", amount="1000")),
        x402watch.normalize(item("u", amount="2500")))
    check("price_changed検知", [e[0] for e in evs] == ["price_changed"])
    check("USD換算(USDC 6dp)", evs[0][2]["before_usd"] == 0.001
          and evs[0][2]["after_usd"] == 0.0025, str(evs[0][2]))

    evs = x402watch.diff_events(
        x402watch.normalize(item("u", payto="0xAAA")),
        x402watch.normalize(item("u", payto="0xBBB")))
    check("payto_changed=critical", evs[0][0] == "payto_changed" and evs[0][1] == "critical")

    evs = x402watch.diff_events(
        x402watch.normalize(item("u", extensions={})),
        x402watch.normalize(item("u", extensions={"bazaar": {"v": 2}})))
    check("schema_changed検知", [e[0] for e in evs] == ["schema_changed"])

    old = x402watch.normalize(item("u", network="eip155:8453"))
    new = x402watch.normalize(item("u", network="eip155:137"))
    evs = x402watch.diff_events(old, new)
    check("accepts_changed(ネットワーク変更)",
          [e[0] for e in evs] == ["accepts_changed"]
          and len(evs[0][2]["added"]) == 1 and len(evs[0][2]["removed"]) == 1)

    check("非USDCアセットはUSD換算しない",
          x402watch.usd_of("100000000000000000", "0xPOL") is None)

    print("== sync(シード→変更→delist→relist) ==")
    conn = store.connect()
    fake_pages([item("https://a.example/x"), item("https://b.example/y", amount="5000")])
    out = x402watch.sync(conn)
    check("初回はseed", out["seed"] and out["new"] == 2)
    check("seed時はイベントなし",
          conn.execute("SELECT COUNT(*) n FROM x402_events").fetchone()["n"] == 0)
    check("スナップショット2件",
          conn.execute("SELECT COUNT(*) n FROM x402_snapshots").fetchone()["n"] == 2)

    # 変化なし再同期 → イベント/スナップショット増えない
    out = x402watch.sync(conn)
    check("無変化syncでイベント0",
          out["changed"] == 0
          and conn.execute("SELECT COUNT(*) n FROM x402_events").fetchone()["n"] == 0)

    # 価格変更 + b が1回不在(ページネーション順序ずれ耐性: まだdelistしない)
    fake_pages([item("https://a.example/x", amount="3000")])
    out = x402watch.sync(conn)
    evs = events_of(conn, "https://a.example/x")
    check("2回目以降は price_changed 発火",
          [e["event_type"] for e in evs] == ["price_changed"], str([dict(e) for e in evs]))
    check("1回不在ではまだ delist しない",
          out["delisted"] == 0
          and conn.execute("SELECT active, miss_count FROM x402_resources WHERE resource=?",
                           ("https://b.example/y",)).fetchone()["miss_count"] == 1)
    # 2回連続不在 → delist
    out = x402watch.sync(conn)
    bevs = events_of(conn, "https://b.example/y")
    check("2回連続不在で delisted 発火", [e["event_type"] for e in bevs] == ["delisted"])
    check("delist後 active=0",
          conn.execute("SELECT active FROM x402_resources WHERE resource=?",
                       ("https://b.example/y",)).fetchone()["active"] == 0)

    # 不完全同期(途中失敗)では delist しない
    x402watch.fetch_pages = lambda: ([item("https://a.example/x", amount="3000")], False, "boom")
    out = x402watch.sync(conn)
    check("不完全syncでは delist しない", out["delisted"] == 0 and out["error"] == "boom")
    check("aはまだactive",
          conn.execute("SELECT active FROM x402_resources WHERE resource=?",
                       ("https://a.example/x",)).fetchone()["active"] == 1)

    # relist
    fake_pages([item("https://a.example/x", amount="3000"),
                item("https://b.example/y", amount="5000")])
    x402watch.sync(conn)
    bevs = events_of(conn, "https://b.example/y")
    check("relisted 発火", [e["event_type"] for e in bevs] == ["delisted", "relisted"])

    # payTo変更はcriticalイベント
    fake_pages([item("https://a.example/x", amount="3000", payto="0xEVIL"),
                item("https://b.example/y", amount="5000")])
    x402watch.sync(conn)
    evs = events_of(conn, "https://a.example/x")
    check("payto_changed が critical で記録",
          evs[-1]["event_type"] == "payto_changed" and evs[-1]["severity"] == "critical")

    conn.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
