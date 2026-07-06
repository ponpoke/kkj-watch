"""discovery(発見サーフェスKPI)の分類・集計・除外・conversion分離の回帰テスト。"""
import sqlite3
from datetime import datetime, timedelta, timezone

from . import discovery


def _conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(
        "CREATE TABLE usage_log(id INTEGER PRIMARY KEY, at TEXT, client TEXT,"
        " user_agent TEXT, path TEXT, usage_class TEXT);"
        "CREATE TABLE payment_log(id INTEGER PRIMARY KEY, at TEXT, client TEXT,"
        " resource TEXT, success INTEGER, error TEXT);")
    return c


def _log(c, client, ua, path, uclass=None, at=None):
    at = at or datetime.now(timezone.utc).isoformat()
    c.execute("INSERT INTO usage_log(at,client,user_agent,path,usage_class) VALUES(?,?,?,?,?)",
              (at, client, ua, path, uclass))


def test_classify_actor():
    ai = "Mozilla/5.0 (compatible; GPTBot/1.4; +https://openai.com/gptbot)"
    assert discovery.classify_actor(ai) == "ai_crawler"
    assert discovery.classify_actor("...OAI-SearchBot/1.4...") == "ai_crawler"
    assert discovery.classify_actor("ClaudeBot/1.0") == "ai_crawler"
    assert discovery.classify_actor("Agent402/1.0") == "x402_ecosystem"
    assert discovery.classify_actor("x402station/0.1 uptime") == "x402_ecosystem"
    assert discovery.classify_actor("CarbonMonitor/0.1 healthcheck") == "x402_ecosystem"
    assert discovery.classify_actor("forum-labs-trust-prober/1.0 (x402)") == "x402_ecosystem"
    assert discovery.classify_actor("Mozilla/5.0 (compatible; Googlebot/2.1)") == "search_engine"
    assert discovery.classify_actor("Bingbot/2.0") == "search_engine"
    assert discovery.classify_actor("curl/8.7.1") == "tooling"
    assert discovery.classify_actor("l9explore/1.2.2") == "tooling"
    assert discovery.classify_actor("Mozilla/5.0 (Windows NT 10.0) Chrome/131") == "browser"
    assert discovery.classify_actor("") == "unknown"
    assert discovery.classify_actor(None) == "unknown"


def test_gptbot_beats_generic_bot():
    # "bot"を含むがAIクローラとして確定させる(ecosystemやtoolingに落ちない)
    assert discovery.classify_actor("GPTBot/1.4 bot spider") == "ai_crawler"


def test_classify_surface():
    assert discovery.classify_surface("/.well-known/x402") == "capability"
    assert discovery.classify_surface("/openapi.json") == "capability"
    assert discovery.classify_surface("/agent.json") == "capability"
    assert discovery.classify_surface("/llms.txt") == "capability"
    assert discovery.classify_surface("/paid/requirements/latest") == "paid"
    assert discovery.classify_surface("/x402/e/26") == "geo"
    assert discovery.classify_surface("/jp/e/kkj") == "geo"
    assert discovery.classify_surface("/case/abc") == "geo"
    assert discovery.classify_surface("/x402/trust-feed.json") == "feed"
    assert discovery.classify_surface("/jp/directory.json") == "feed"
    assert discovery.classify_surface("/badge/x402/4.svg") == "badge"
    assert discovery.classify_surface("/sitemap-x402.xml") == "sitemap"
    assert discovery.classify_surface("/x402/leaderboard") == "other"


def test_excludes_self_and_test():
    c = _conn()
    _log(c, "5.75.142.199", "Agent402/1.0", "/.well-known/x402")   # 内部VPS→除外
    _log(c, "121.109.189.96", "curl/8", "/paid/requirements/latest")  # dev→除外
    _log(c, "9.9.9.9", "GPTBot/1.4", "/x402/e/1", uclass="test")    # test→除外
    _log(c, "8.8.8.8", "Agent402/1.0", "/.well-known/x402")         # 外部→計上
    r = discovery.report(conn=c)
    assert r["totals"]["all"]["uniq_ip"] == 1
    assert r["headline"]["all"]["ecosystem_discovery"]["uniq_ip"] == 1
    assert r["headline"]["all"]["capability_fetch"]["uniq_ip"] == 1


def test_headline_two_axes():
    c = _conn()
    # エコシステムbotが有料面を叩く: actor軸(ecosystem)とsurface軸(paid)の両方に計上される
    _log(c, "1.1.1.1", "x402station/0.1", "/paid/requirements/latest")
    _log(c, "2.2.2.2", "GPTBot/1.4", "/x402/trust-feed.json")   # ai + feed
    r = discovery.report(conn=c)
    h = r["headline"]["all"]
    assert h["ecosystem_discovery"]["uniq_ip"] == 1
    assert h["paid_probe"]["uniq_ip"] == 1
    assert h["organic_ai_crawl"]["uniq_ip"] == 1
    assert h["feed_ingest"]["uniq_ip"] == 1
    assert h["geo_crawl"]["uniq_ip"] == 0


def test_conversion_external_vs_selftest():
    c = _conn()
    now = datetime.now(timezone.utc).isoformat()
    # 自己テストの成功と、外部の失敗のみ → external_settled は 0(要件6)
    c.execute("INSERT INTO payment_log(at,client,resource,success,error) VALUES(?,?,?,?,?)",
              (now, "5.75.142.199", "/paid/x", 1, None))
    c.execute("INSERT INTO payment_log(at,client,resource,success,error) VALUES(?,?,?,?,?)",
              (now, "3.3.3.3", "/paid/x", 0, "no pay"))
    r = discovery.report(conn=c)
    assert r["conversion"]["external_settled"]["all"]["uniq_ip"] == 0
    assert r["conversion"]["self_test_settled"]["uniq_ip"] == 1
    assert r["headline"]["all"]["paid_conversion"]["uniq_ip"] == 0


def test_external_conversion_counts():
    c = _conn()
    now = datetime.now(timezone.utc).isoformat()
    c.execute("INSERT INTO payment_log(at,client,resource,success,error) VALUES(?,?,?,?,?)",
              (now, "4.4.4.4", "/paid/x", 1, None))   # 外部の実settle
    r = discovery.report(conn=c)
    assert r["conversion"]["external_settled"]["all"]["uniq_ip"] == 1
    assert r["headline"]["all"]["paid_conversion"]["uniq_ip"] == 1
    assert "収益" in r["verdict"]


def test_time_windows():
    c = _conn()
    old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    _log(c, "1.1.1.1", "Agent402/1.0", "/.well-known/x402", at=old)
    _log(c, "2.2.2.2", "Agent402/1.0", "/.well-known/x402", at=recent)
    r = discovery.report(conn=c)
    assert r["totals"]["all"]["uniq_ip"] == 2
    assert r["totals"]["7d"]["uniq_ip"] == 1
    assert r["totals"]["24h"]["uniq_ip"] == 1


def test_verdict_empty():
    c = _conn()
    r = discovery.report(conn=c)
    assert "様子見" in r["verdict"]


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for f in fns:
        f()
        print("ok", f.__name__)
    print(f"\n{len(fns)} passed")
