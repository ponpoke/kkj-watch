"""x402probe / x402trust のユニットテスト(ネットワーク不要・一時DB)

  python -m kkj.test_x402probe
"""
import json
import tempfile

_tmp = tempfile.mkdtemp()
from . import config
config.DATA_DIR = type(config.DATA_DIR)(_tmp)
config.DB_PATH = config.DATA_DIR / "test_x402probe.db"

from . import store, x402watch, x402probe, x402trust  # noqa: E402

PASS = FAIL = 0


def check(name, cond, info=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok: {name}")
    else:
        FAIL += 1
        print(f"  NG: {name} {info}")


def item(resource, amount="1000", payto="0xAAA"):
    return {"resource": resource, "type": "http", "x402Version": 2,
            "serviceName": "svc", "tags": [], "description": "d", "extensions": {},
            "accepts": [{"scheme": "exact", "network": "eip155:8453",
                         "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                         "amount": amount, "payTo": payto}]}


def body_402(amount="1000", payto="0xAAA", network="base"):
    return json.dumps({"x402Version": 1, "accepts": [
        {"scheme": "exact", "network": network, "maxAmountRequired": amount,
         "payTo": payto}]}).encode()


def set_fetch(status, body=b"", err=None):
    x402probe.fetch = lambda url: (status, body, 5, err)


def last_events(conn, url, n=5):
    return [r["event_type"] for r in conn.execute(
        """SELECT e.event_type FROM x402_events e JOIN x402_resources r ON r.id=e.resource_id
           WHERE r.resource=? ORDER BY e.id DESC LIMIT ?""", (url, n)).fetchall()][::-1]


def main():
    print("== SSRFガード: _ip_ok(純粋関数・DNS不要) ==")
    for ip in ("127.0.0.1", "10.0.0.1", "172.16.0.1", "172.31.255.255",
               "192.168.1.5", "169.254.169.254", "100.64.0.1", "0.0.0.0",
               "::1", "fc00::1", "fd12::1", "fe80::1", "::ffff:127.0.0.1",
               "::ffff:10.0.0.1", "224.0.0.1", "198.18.0.1"):
        check(f"拒否IP: {ip}", not x402probe._ip_ok(ip))
    for ip in ("1.1.1.1", "8.8.8.8", "203.0.113.0" if False else "104.16.1.1",
               "2606:4700:4700::1111"):
        check(f"許可IP: {ip}", x402probe._ip_ok(ip))

    print("== SSRFガード: assert_url_allowed(スキーム+解決IP) ==")
    for bad in ("ftp://example.com/x", "file:///etc/passwd", "gopher://x/1",
                "https://127.0.0.1/x", "http://169.254.169.254/latest/meta-data/",
                "https://[::1]/x", "https://192.168.1.5/x"):
        try:
            x402probe.assert_url_allowed(bad)
            check(f"拒否URL: {bad}", False)
        except Exception:
            check(f"拒否URL: {bad}", True)
    for good in ("https://1.1.1.1/x", "http://1.1.1.1/x"):   # httpも許可(要件)
        try:
            x402probe.assert_url_allowed(good)
            check(f"許可URL: {good}", True)
        except Exception as e:
            check(f"許可URL: {good}", False, str(e))

    print("== 402本文の解釈と照合 ==")
    la = x402probe.parse_live_accepts(body_402())
    check("v1名baseをCAIPへ正規化", la[0]["network"] == "eip155:8453")
    check("maxAmountRequired読取", la[0]["amount"] == "1000")
    reg = item("u")["accepts"]
    check("一致→ok", x402probe.check_consistency(reg, la)[0] == "ok")
    c, d = x402probe.check_consistency(reg, x402probe.parse_live_accepts(body_402(payto="0xEVIL")))
    check("payTo不一致検知", c == "payto_mismatch" and d["live_payTo"] == ["0xevil"])
    c, d = x402probe.check_consistency(reg, x402probe.parse_live_accepts(body_402(amount="9999")))
    check("価格不一致検知", c == "price_mismatch" and d["live_amount"] == "9999")
    check("壊れたJSON→not_x402",
          x402probe.check_consistency(reg, x402probe.parse_live_accepts(b"<html>"))[0] == "not_x402")

    print("== プローブ状態遷移 ==")
    conn = store.connect()
    x402watch.fetch_pages = lambda: ([item("https://ok.example/a")], True, None)
    x402watch.sync(conn)
    conn.executescript(x402probe.SCHEMA_SQL)
    row = conn.execute("SELECT * FROM x402_resources WHERE resource=?",
                       ("https://ok.example/a",)).fetchone()
    x402probe.assert_url_allowed = lambda url: None   # DNSなしでテスト

    ts = store.now_utc()
    set_fetch(402, body_402())
    check("一致プローブ→ok", x402probe.probe_one(conn, row, ts) == "ok")
    check("イベントなし", last_events(conn, row["resource"]) == [])

    set_fetch(402, body_402(payto="0xEVIL"))
    check("payTo不一致→イベント発火",
          x402probe.probe_one(conn, row, ts) == "payto_mismatch"
          and last_events(conn, row["resource"]) == ["live_payto_mismatch"])
    x402probe.probe_one(conn, row, ts)
    check("同状態の再発火なし", last_events(conn, row["resource"]) == ["live_payto_mismatch"])

    set_fetch(402, body_402())
    x402probe.probe_one(conn, row, ts)
    check("回復→consistency_restored",
          last_events(conn, row["resource"])[-1] == "consistency_restored")

    set_fetch(None, b"", "timeout")
    check("1回死→イベントなし",
          x402probe.probe_one(conn, row, ts) == "unreachable"
          and last_events(conn, row["resource"])[-1] == "consistency_restored")
    x402probe.probe_one(conn, row, ts)
    check("2回連続死→endpoint_dead",
          last_events(conn, row["resource"])[-1] == "endpoint_dead")
    set_fetch(200, b"hello")
    check("復活→endpoint_recovered + not_x402",
          x402probe.probe_one(conn, row, ts) == "not_x402"
          and last_events(conn, row["resource"])[-1] == "endpoint_recovered")

    print("== Trustスコア ==")
    set_fetch(402, body_402())
    x402probe.probe_one(conn, row, ts)
    t = x402trust.update_score(conn, row["id"])
    check("検証済み+一致で高スコア", t["score"] >= 60 and t["verdicts"]["verified_live"],
          json.dumps(t["components"]))
    check("説明可能(components合計=score)",
          abs(sum(t["components"].values()) - t["score"]) < 0.01)

    set_fetch(402, body_402(payto="0xEVIL"))
    x402probe.probe_one(conn, row, ts)
    t = x402trust.update_score(conn, row["id"])
    check("payTo不一致でF級+critical理由",
          t["grade"] in ("D", "F") and t["verdicts"]["payto_risk"] == "live_mismatch",
          f"score={t['score']}")

    # ファーム検出: 同一payToを6ホスト×25掲載
    farm_items = [item(f"https://h{i%6}.example/r{i}", payto="0xFARM") for i in range(25)]
    x402watch.fetch_pages = lambda: ([item("https://ok.example/a")] + farm_items, True, None)
    x402watch.sync(conn)
    x402trust._farm_cache["at"] = 0   # キャッシュ無効化
    frow = conn.execute("SELECT * FROM x402_resources WHERE resource=?",
                        ("https://h0.example/r0",)).fetchone()
    t = x402trust.compute(conn, frow)
    check("スパムファーム検出", t["verdicts"]["farm_member"]
          and t["components"]["not_farm"] == 0, json.dumps(t["verdicts"]))
    t = x402trust.compute(conn, conn.execute(
        "SELECT * FROM x402_resources WHERE resource=?", ("https://ok.example/a",)).fetchone())
    check("非ファームは満点", t["components"]["not_farm"] == 5)

    print("== 選定ヘルパー(why/price/disclaimer) ==")
    okrow = conn.execute("SELECT * FROM x402_resources WHERE resource=?",
                         ("https://ok.example/a",)).fetchone()
    # 検証済み・一致状態にしてから
    set_fetch(402, body_402())
    x402probe.probe_one(conn, okrow, ts)
    t = x402trust.update_score(conn, okrow["id"])
    why = x402trust.why_reasons(t)
    check("why[]に肯定的根拠が入る", len(why) >= 2 and any("402" in w for w in why), str(why))
    rec = json.loads(okrow["latest_json"])
    check("USDC価格をUSD換算", x402trust.price_usd_min(rec) == 0.001,
          str(x402trust.price_usd_min(rec)))
    check("disclaimerは保証でなくリスク指標",
          "not a safety guarantee" in x402trust.SCORE_DISCLAIMER.lower()
          or "not a guarantee" in x402trust.SCORE_DISCLAIMER.lower())

    print("== 対象選定(ホスト集中回避) ==")
    picked = x402probe.pick_targets(conn, 100)
    hosts = {}
    for p in picked:
        import urllib.parse as up
        h = up.urlsplit(p["resource"]).hostname
        hosts[h] = hosts.get(h, 0) + 1
    check("ホスト毎3件以内", max(hosts.values()) <= 3, str(hosts))

    conn.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
