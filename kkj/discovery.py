"""発見サーフェスKPI — 外部の実アクセスを、自己テスト/内部IPと分離して面(surface)別に精密計測。

独自ドメイン移行の判断材料。「誰が(actor)・どの面(surface)を・どれだけ」来ているかを、
UA / IP / path / 直近24h・7d の4視点で出す。実収益(paid_conversion)は payment_log の
外部settle成功のみを数え、自己テストと厳密に分離する。

分類の2軸(要件1,5):
  actor(UA別・排他):
    x402_ecosystem  … x402監視/発見サービス(Agent402, x402station, x402-observer,
                       forum-labs, 402explorer, CarbonMonitor, mako-pulse 等)。検索botとは別。
    ai_crawler      … LLM/AIクローラ(GPTBot, OAI-SearchBot, ClaudeBot, Perplexity 等)
    search_engine   … 検索クローラ(Googlebot, Bingbot, Applebot 等)
    tooling / browser / unknown
  surface(path別・排他):
    capability(/.well-known/x402, /openapi.json, /agent.json, /llms.txt)
    paid(/paid/…)  geo(/x402/e/, /jp/e/, /case/)  feed(/x402/trust-feed, /jp/directory)
    badge(/badge/…)  sitemap(/sitemap…)  other

見出し8バケット(要件1) = 2軸 + 決済outcome:
    ecosystem_discovery = actor:x402_ecosystem      organic_ai_crawl = actor:ai_crawler
    capability_fetch    = surface:capability         paid_probe       = surface:paid(402を読むだけ)
    geo_crawl           = surface:geo                feed_ingest      = surface:feed
    badge_surface       = surface:badge              paid_conversion  = 外部settle成功(唯一の収益指標)

要件3: 自己IP(dev/VPS/localhost) と usage_class='test'(X-KKJ-Test由来) を常に除外。
要件8: 検索/AIクローラは rDNS forward-confirm で verified を判定(結果はcrawler_verify表に
       キャッシュ)。OpenAI/Anthropic等は公開IPレンジ運用でrDNS非対応 → "ua_claimed"として区別。

  python -m kkj.discovery            # レポート(rDNS解決を実行しキャッシュ更新)
  python -m kkj.discovery --no-dns   # 解決せずキャッシュのみ
"""
import re as _re
import socket
from datetime import datetime, timedelta, timezone

from . import store

# 要件3: 自己IP・localhost・VPS自身
INTERNAL = ("127.0.0.1", "::1", "5.75.142.199")
SELF_IPS = ("121.109.189.96",)          # 開発者(私)の検証アクセス元
EXCLUDE = INTERNAL + SELF_IPS

# ---- actor 分類(UA別・排他)。順序＝優先度。GPTBot等は"bot"を含むので先に確定させる ----
_AI_CRAWLER = _re.compile(
    r"gptbot|oai-searchbot|chatgpt-user|claudebot|claude-web|anthropic-ai|perplexity|"
    r"ccbot|google-extended|amazonbot|bytespider|meta-externalagent|cohere-ai|diffbot|"
    r"applebot-extended|timpibot|youbot|awario|imagesiftbot", _re.I)
_SEARCH_ENGINE = _re.compile(
    r"googlebot|bingbot|bingpreview|duckduckbot|applebot|yandex|baiduspider|slurp|sogou",
    _re.I)
# x402エコシステムの監視/発見サービス(要件5: 検索botと別カテゴリ)
_X402_ECO = _re.compile(
    r"agent402|x402station|x402-observer|x402observer|forum-labs|402explorer|carbonmonitor|"
    r"mako-pulse|litebeam|decixa|entroute|nitrograph|dexter|agent-tools\.cloud|"
    r"trust-prober|x402guard|x402", _re.I)
_TOOLING = _re.compile(
    r"curl|wget|python-urllib|python-requests|python-httpx|httpx|go-http|okhttp|node-fetch|"
    r"libredtail|l9explore|pathscan|nmap|masscan|zgrab|scanner", _re.I)
_BROWSERISH = _re.compile(r"mozilla|chrome|safari|firefox|edge", _re.I)


def classify_actor(ua: str) -> str:
    ua = ua or ""
    if not ua.strip():
        return "unknown"
    if _AI_CRAWLER.search(ua):
        return "ai_crawler"
    if _SEARCH_ENGINE.search(ua):
        return "search_engine"
    if _X402_ECO.search(ua):
        return "x402_ecosystem"
    if _TOOLING.search(ua):
        return "tooling"
    if _BROWSERISH.search(ua):
        return "browser"
    return "unknown"


# ---- surface 分類(path別・排他)。要件2の対象パスを網羅 ----
_CAPABILITY = ("/.well-known/x402", "/openapi.json", "/agent.json", "/llms.txt")


def classify_surface(path: str) -> str:
    p = path or ""
    if p.startswith("/x402/e/") or p.startswith("/jp/e/") or p.startswith("/case/"):
        return "geo"
    if p.startswith("/x402/trust-feed") or p.startswith("/jp/directory"):
        return "feed"
    if p.startswith("/badge"):
        return "badge"
    if p.startswith("/paid/"):
        return "paid"
    if p.startswith("/sitemap"):
        return "sitemap"
    if p in _CAPABILITY or p.startswith("/.well-known/x402"):
        return "capability"
    return "other"


# ---- rDNS forward-confirm 検証(要件8) ----
# UAが名乗る主体ごとの正当rDNSドメイン。forward-confirm(host→IPが元IPを含む)まで確認して初めてverified。
_RDNS_EXPECT = [
    (_re.compile(r"googlebot|google-extended|apis-google|mediapartners-google", _re.I),
     ("googlebot.com", "google.com")),
    (_re.compile(r"bingbot|bingpreview|msnbot", _re.I), ("search.msn.com",)),
    (_re.compile(r"applebot", _re.I), ("applebot.apple.com", "apple.com")),
    (_re.compile(r"duckduckbot", _re.I), ("duckduckgo.com",)),
    (_re.compile(r"yandex", _re.I), ("yandex.com", "yandex.ru", "yandex.net")),
    (_re.compile(r"baiduspider", _re.I), ("baidu.com", "baidu.jp")),
]
# rDNS非対応で公開IPレンジ運用の主体(検証はレンジ照合が必要 → ここではua_claimedとして正直に区別)
_RANGE_ONLY = _re.compile(
    r"gptbot|oai-searchbot|chatgpt-user|claudebot|claude-web|anthropic-ai|perplexity|"
    r"amazonbot|bytespider|meta-externalagent", _re.I)

_VERIFY_SCHEMA = """
CREATE TABLE IF NOT EXISTS crawler_verify (
    ip TEXT PRIMARY KEY,
    ua_sample TEXT,
    verified INTEGER,        -- 1=forward-confirmed, 0=failed/mismatch, NULL=n/a
    method TEXT,             -- rdns / ua_claimed / n/a
    rdns TEXT,
    note TEXT,
    checked_at TEXT
);
"""


def _rdns_check(ip: str, ua: str, timeout: float = 3.0):
    """rDNS forward-confirm。返り値 {verified, method, rdns, note}。ネットワークI/Oを伴う。"""
    for pat, domains in _RDNS_EXPECT:
        if pat.search(ua or ""):
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                socket.setdefaulttimeout(old)
                return {"verified": 0, "method": "rdns", "rdns": None,
                        "note": "no PTR record"}
            suffix_ok = any(host == d or host.endswith("." + d) for d in domains)
            fc = False
            if suffix_ok:
                try:
                    _, _, ips = socket.gethostbyname_ex(host)
                    fc = ip in ips
                except Exception:
                    fc = False
            socket.setdefaulttimeout(old)
            return {"verified": 1 if (suffix_ok and fc) else 0, "method": "rdns",
                    "rdns": host,
                    "note": "forward-confirmed" if (suffix_ok and fc)
                    else ("PTR domain mismatch" if not suffix_ok else "forward-confirm failed")}
    if _RANGE_ONLY.search(ua or ""):
        return {"verified": 0, "method": "ua_claimed", "rdns": None,
                "note": "provider verifies by published IP range, not rDNS"}
    return {"verified": None, "method": "n/a", "rdns": None, "note": ""}


def _load_verify_cache(conn):
    conn.executescript(_VERIFY_SCHEMA)
    out = {}
    for r in conn.execute("SELECT * FROM crawler_verify").fetchall():
        out[r["ip"]] = dict(r)
    return out


def _resolve_missing(conn, need, cache, max_lookups=60):
    """need = [(ip, ua)] のうちキャッシュ未登録/7日超のものをrDNS解決してupsert。"""
    conn.executescript(_VERIFY_SCHEMA)
    now = datetime.now(timezone.utc)
    stale = (now - timedelta(days=7)).isoformat()
    done = 0
    for ip, ua in need:
        if done >= max_lookups:
            break
        c = cache.get(ip)
        if c and (c.get("checked_at") or "") >= stale:
            continue
        res = _rdns_check(ip, ua)
        conn.execute(
            "INSERT INTO crawler_verify(ip, ua_sample, verified, method, rdns, note, checked_at) "
            "VALUES (?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET "
            "ua_sample=excluded.ua_sample, verified=excluded.verified, method=excluded.method, "
            "rdns=excluded.rdns, note=excluded.note, checked_at=excluded.checked_at",
            (ip, (ua or "")[:120], res["verified"], res["method"], res["rdns"],
             res["note"], now.isoformat()))
        cache[ip] = {"ip": ip, "ua_sample": ua, "verified": res["verified"],
                     "method": res["method"], "rdns": res["rdns"], "note": res["note"],
                     "checked_at": now.isoformat()}
        done += 1
    if done:
        conn.commit()
    return done


# ---- 集計 ----
def _blank():
    return {"hits": 0, "_ips": set()}


def _bump(d, key, ip):
    b = d.setdefault(key, _blank())
    b["hits"] += 1
    b["_ips"].add(ip)


def _finalize(d):
    return {k: {"hits": v["hits"], "uniq_ip": len(v["_ips"])} for k, v in d.items()}


def report(conn=None, resolve=False):
    own = conn is None
    if own:
        conn = store.connect()
    try:
        conn.execute("SELECT 1 FROM usage_log LIMIT 1")
    except Exception:
        if own:
            conn.close()
        return {"note": "no usage_log yet"}

    now = datetime.now(timezone.utc)
    cut24 = (now - timedelta(hours=24)).isoformat()
    cut7 = (now - timedelta(days=7)).isoformat()

    placeholders = ",".join("?" * len(EXCLUDE))
    rows = conn.execute(
        f"SELECT at, client, user_agent, path FROM usage_log "
        f"WHERE client NOT IN ({placeholders}) "
        f"AND (usage_class IS NULL OR usage_class!='test')",
        EXCLUDE).fetchall()

    # 見出し8バケット(paid_conversion除く7つ)を all/7d/24h の各窓で
    WINDOWS = ("all", "7d", "24h")
    headline = {w: {} for w in WINDOWS}
    by_actor = {}
    by_surface = {}
    by_ip = {}          # ip -> {hits, actors:set, ua_samples:set, paths:set}
    by_ua = {}          # ua(trunc) -> {hits, _ips, actor}
    by_path = {}        # path -> {hits, _ips}
    total = {w: _blank() for w in WINDOWS}

    def headline_buckets(actor, surface):
        out = []
        if actor == "x402_ecosystem":
            out.append("ecosystem_discovery")
        if actor == "ai_crawler":
            out.append("organic_ai_crawl")
        out.append({"capability": "capability_fetch", "paid": "paid_probe",
                    "geo": "geo_crawl", "feed": "feed_ingest",
                    "badge": "badge_surface"}.get(surface))
        return [b for b in out if b]

    for r in rows:
        ip = r["client"]
        ua = r["user_agent"] or ""
        path = r["path"] or ""
        at = r["at"] or ""
        actor = classify_actor(ua)
        surface = classify_surface(path)
        wins = ["all"]
        if at >= cut7:
            wins.append("7d")
        if at >= cut24:
            wins.append("24h")

        buckets = headline_buckets(actor, surface)
        for w in wins:
            total[w]["hits"] += 1
            total[w]["_ips"].add(ip)
            for b in buckets:
                _bump(headline[w], b, ip)

        _bump(by_actor, actor, ip)
        _bump(by_surface, surface, ip)
        uak = (ua[:70] or "(none)")
        ub = by_ua.setdefault(uak, {"hits": 0, "_ips": set(), "actor": actor})
        ub["hits"] += 1
        ub["_ips"].add(ip)
        pb = by_path.setdefault(path, _blank())
        pb["hits"] += 1
        pb["_ips"].add(ip)
        ipb = by_ip.setdefault(ip, {"hits": 0, "actors": set(), "ua": set(), "paths": set()})
        ipb["hits"] += 1
        ipb["actors"].add(actor)
        if ua:
            ipb["ua"].add(ua[:80])
        ipb["paths"].add(surface)

    # 決済(paid_conversion) — 外部settle成功のみ(要件6)。自己テストと分離して両方出す。
    conn.executescript(
        "CREATE TABLE IF NOT EXISTS payment_log ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, client TEXT, resource TEXT,"
        "success INTEGER, error TEXT)")

    def pay_count(where, params):
        r = conn.execute(
            f"SELECT COUNT(*) hits, COUNT(DISTINCT client) uniq FROM payment_log WHERE {where}",
            params).fetchone()
        return {"hits": r["hits"], "uniq_ip": r["uniq"]}

    ext = f"client NOT IN ({placeholders})"
    conv = {
        "all": pay_count(f"success=1 AND {ext}", EXCLUDE),
        "7d": pay_count(f"success=1 AND {ext} AND at>=?", (*EXCLUDE, cut7)),
        "24h": pay_count(f"success=1 AND {ext} AND at>=?", (*EXCLUDE, cut24)),
    }
    self_settled = pay_count(
        f"success=1 AND client IN ({placeholders})", EXCLUDE)

    # rDNS検証(要件8): 検索/AIクローラのIPだけ対象
    cache = _load_verify_cache(conn)
    crawler_ips = {}
    for ip, info in by_ip.items():
        if info["actors"] & {"ai_crawler", "search_engine"}:
            crawler_ips[ip] = next(iter(info["ua"]), "") if info["ua"] else ""
    if resolve and crawler_ips:
        _resolve_missing(conn, list(crawler_ips.items()), cache)

    verified_crawlers = []
    for ip, ua in sorted(crawler_ips.items(),
                         key=lambda kv: -by_ip[kv[0]]["hits"]):
        c = cache.get(ip, {})
        verified_crawlers.append({
            "ip": ip, "actor": sorted(by_ip[ip]["actors"])[0],
            "ua": (ua or "")[:70], "hits": by_ip[ip]["hits"],
            "verified": c.get("verified"), "method": c.get("method", "unchecked"),
            "rdns": c.get("rdns"), "note": c.get("note", ""),
        })

    # 見出し8バケットを窓ごとに整形(paid_conversionを合流)
    def headline_out(w):
        h = _finalize(headline[w])
        for k in ("ecosystem_discovery", "capability_fetch", "paid_probe",
                  "organic_ai_crawl", "geo_crawl", "feed_ingest", "badge_surface"):
            h.setdefault(k, {"hits": 0, "uniq_ip": 0})
        h["paid_conversion"] = conv[w]
        return h

    def topn(d, n=15, keyfn=lambda v: -v["hits"]):
        items = sorted(d.items(), key=lambda kv: keyfn(kv[1]))[:n]
        return items

    top_ips = [{"ip": ip, "hits": v["hits"], "actor": sorted(v["actors"])[0],
                "surfaces": sorted(v["paths"]),
                "ua": (next(iter(v["ua"]), "") if v["ua"] else "")}
               for ip, v in topn(by_ip)]
    top_paths = [{"path": p, "hits": v["hits"], "uniq_ip": len(v["_ips"])}
                 for p, v in topn(by_path)]
    top_ua = [{"ua": u, "hits": v["hits"], "uniq_ip": len(v["_ips"]), "actor": v["actor"]}
              for u, v in topn(by_ua)]

    out = {
        "window": {"now": now.isoformat(), "cut_24h": cut24, "cut_7d": cut7},
        "excludes": {"internal_ips": list(INTERNAL), "self_dev_ips": list(SELF_IPS),
                     "test_class": "usage_class='test' (X-KKJ-Test header)"},
        "axes_note": ("actor軸(UA別)と surface軸(path別)は別軸。1リクエストは actor系1バケット"
                      "(ecosystem_discovery/organic_ai_crawl)と surface系1バケット"
                      "(capability/paid/geo/feed/badge)の両方に計上され得る。"
                      "収益は paid_conversion のみ。"),
        "totals": {w: {"hits": total[w]["hits"], "uniq_ip": len(total[w]["_ips"])}
                   for w in WINDOWS},
        "headline": {w: headline_out(w) for w in WINDOWS},
        "by_actor": _finalize(by_actor),
        "by_surface": _finalize(by_surface),
        "top_ips": top_ips,
        "top_paths": top_paths,
        "top_user_agents": top_ua,
        "verified_crawlers": verified_crawlers,
        "conversion": {"external_settled": conv, "self_test_settled": self_settled,
                       "note": "external_settled が唯一の実収益。self_test_settled は自己検証"},
        "verdict": _verdict(headline["all"], conv["all"], by_actor),
    }
    if own:
        conn.close()
    return out


def _u(d, k):
    return d.get(k, {}).get("uniq_ip", 0) if isinstance(d.get(k), dict) else 0


def _verdict(head_all, conv_all, by_actor):
    h = _finalize(head_all)
    eco = h.get("ecosystem_discovery", {}).get("uniq_ip", 0)
    cap = h.get("capability_fetch", {}).get("uniq_ip", 0)
    probe = h.get("paid_probe", {}).get("uniq_ip", 0)
    ai = h.get("organic_ai_crawl", {}).get("uniq_ip", 0)
    geo = h.get("geo_crawl", {}).get("uniq_ip", 0)
    feed = h.get("feed_ingest", {}).get("uniq_ip", 0)
    conv = conv_all.get("uniq_ip", 0)
    if eco == 0 and ai == 0 and cap == 0 and geo == 0 and feed == 0 and conv == 0:
        return "外部の実アクセスはまだ検出されていない。sslip.ioのまま様子見でよい。"
    stages = []
    if eco or cap or probe:
        stages.append(f"[発見] x402エコシステム {eco} IPが監視・能力取得 {cap} IP・有料面プローブ {probe} IP")
    if ai or feed:
        stages.append(f"[採録] AIクローラ {ai} IP到着・データフィード取得 {feed} IP")
    if geo:
        stages.append(f"[巡回] GEOエンティティページを {geo} IPが巡回")
    if conv:
        stages.append(f"[収益] 外部settle成功 {conv} IP")
    if conv:
        tail = "。実収益が発生している。"
    elif geo:
        tail = "。GEOページ巡回が始まった→独自ドメイン正典化の投資対効果が最大化する頃合い。"
    else:
        tail = ("。発見・採録は出ているがGEOページ巡回と実決済は未達。"
                "次に見るべきは『クローラがフィード止まりでなくGEOページを巡回し始めるか』"
                "『監視botが読むだけから実決済に変わるか』。前者が出たら独自ドメインで正典化。")
    return "段階: " + " / ".join(stages) + tail


def main():
    import json
    import sys
    resolve = "--no-dns" not in sys.argv
    print(json.dumps(report(resolve=resolve), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
