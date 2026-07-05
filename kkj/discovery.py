"""発見KPIレポート — 外部の実アクセスが出ているかを、自己テスト/内部IPと分離して精密計測

独自ドメイン移行の判断材料。「外部botが来るか / GEOページが巡回されるか / trust-feedが
取られるか / x402guardが参照されるか」を User-Agent と外部IPで見分ける。

判定の要点:
  - 検索/LLMクローラは UA で確実に見分けられる(Googlebot / GPTBot / ClaudeBot 等)。
    curl等の自己テストは crawler UA を名乗らないので自動的に除外される。
  - x402guard の参照は UA "x402guard/..." で分かる(裏でTrust APIを叩く)。
  - 内部IP(VPS/localhost)と usage_class='test' は常に除外。

  python -m kkj.discovery          # レポート
"""
import re as _re

from . import store

INTERNAL = ("127.0.0.1", "::1", "5.75.142.199")
# 開発者(私)の検証アクセス元。x402guard/curl等の自己テストはここから出るので外部集計から除外
SELF_IPS = ("121.109.189.96",)
EXCLUDE = INTERNAL + SELF_IPS

# 検索エンジンのクローラ
SEARCH_BOTS = _re.compile(
    r"googlebot|bingbot|duckduckbot|applebot|yandex|baiduspider|slurp|sogou", _re.I)
# LLM/AI のクローラ・フェッチャ(知識採録・RAG)
AI_BOTS = _re.compile(
    r"gptbot|chatgpt-user|oai-searchbot|claudebot|claude-web|anthropic-ai|perplexity|"
    r"ccbot|google-extended|amazonbot|bytespider|meta-externalagent|cohere-ai|"
    r"diffbot|timpibot|youbot|awario|imagesiftbot", _re.I)
GUARD = _re.compile(r"x402guard", _re.I)
X402_ECO = _re.compile(
    r"x402station|x402-observer|forum-labs|402explorer|coinbasebazaar|dexter|nitrograph|"
    r"carbonmonitor|mako-pulse|litebeam|decixa|entroute", _re.I)
TOOLING = _re.compile(r"curl|wget|python-urllib|python-requests|httpx|go-http|okhttp|node", _re.I)


def classify_ua(ua: str) -> str:
    ua = ua or ""
    if GUARD.search(ua):
        return "x402guard"
    if SEARCH_BOTS.search(ua):
        return "search_bot"
    if AI_BOTS.search(ua):
        return "ai_bot"
    if X402_ECO.search(ua):
        return "x402_ecosystem_bot"
    if TOOLING.search(ua):
        return "tooling"
    if not ua:
        return "unknown"
    return "other"


def _rows(conn, path_like):
    q = ",".join("?" * len(EXCLUDE))
    return conn.execute(
        f"SELECT client, user_agent, path FROM usage_log "
        f"WHERE path LIKE ? AND client NOT IN ({q}) "
        f"AND (usage_class IS NULL OR usage_class!='test')",
        (path_like, *EXCLUDE)).fetchall()


def _tally(rows):
    """(category -> {hits, uniq})"""
    out = {}
    seen = {}
    for r in rows:
        c = classify_ua(r["user_agent"])
        d = out.setdefault(c, {"hits": 0, "uniq": 0})
        d["hits"] += 1
        seen.setdefault(c, set()).add(r["client"])
    for c, s in seen.items():
        out[c]["uniq"] = len(s)
    return out


def report(conn=None):
    own = conn is None
    if own:
        conn = store.connect()
    try:
        conn.execute("SELECT 1 FROM usage_log LIMIT 1")
    except Exception:
        if own:
            conn.close()
        return {"note": "no usage_log yet"}

    # GEOページ(x402 + jp + 案件)への巡回
    geo = _tally(_rows(conn, "/x402/e/%") + _rows(conn, "/jp/e/%") + _rows(conn, "/case/%"))
    sitemaps = _tally(_rows(conn, "/sitemap%"))
    trust_feed = _tally(_rows(conn, "/x402/trust-feed%"))
    jp_dir = _tally(_rows(conn, "/jp/directory%"))
    guard_refs = _tally(_rows(conn, "/x402/trust/%"))

    def bots_only(t):
        return {k: v for k, v in t.items() if k in ("search_bot", "ai_bot")}

    out = {
        "excludes": {"internal_ips": list(INTERNAL), "self_dev_ips": list(SELF_IPS),
                     "test_class": True,
                     "note": "crawlers identified by User-Agent; self-tests (curl/x402guard from "
                             "the dev IP) are excluded so only genuine external access remains"},
        "KPI": {
            "external_bots_crawling_geo_pages": bots_only(geo),
            "sitemap_fetched_by_bots": bots_only(sitemaps),
            "trust_feed_fetches": trust_feed,
            "jp_directory_fetches": jp_dir,
            "x402guard_references": guard_refs.get("x402guard", {"hits": 0, "uniq": 0}),
        },
        "detail": {
            "geo_pages_all": geo, "sitemaps_all": sitemaps,
            "trust_feed_all": trust_feed,
        },
        "verdict": _verdict(geo, sitemaps, trust_feed, guard_refs),
    }
    if own:
        conn.close()
    return out


def _verdict(geo, sitemaps, trust_feed, guard_refs):
    geo_bots = sum(geo.get(k, {}).get("uniq", 0) for k in ("search_bot", "ai_bot"))
    sitemap_bots = sum(sitemaps.get(k, {}).get("uniq", 0) for k in ("search_bot", "ai_bot"))
    guard = guard_refs.get("x402guard", {}).get("uniq", 0)   # dev IP除外後=外部のみ
    real_feed = sum(v.get("uniq", 0) for k, v in trust_feed.items()
                    if k in ("ai_bot", "search_bot", "other"))
    # 段階を明示。GEOの本命は「entityページの巡回」
    if geo_bots == 0 and sitemap_bots == 0 and guard == 0 and real_feed == 0:
        return ("外部の実アクセスはまだ検出されていない。sslip.ioのまま様子見でよい。")
    stages = []
    if sitemap_bots:
        stages.append(f"[発見] 検索/LLMクローラ {sitemap_bots} 種がサイトマップを取得")
    if geo_bots:
        stages.append(f"[巡回] クローラ {geo_bots} 種が実際にGEOページ(/x402/e/等)を取得")
    if real_feed:
        stages.append(f"[機械利用] trust-feedを外部 {real_feed} 件が取得")
    if guard:
        stages.append(f"[統合] x402guard参照 {guard} 件(外部)")
    tail = ("。次に見るべきは『クローラがサイトマップ止まりでなくGEOページを巡回し始めるか』。"
            "それが起きたら独自ドメインで正典化する頃合い。"
            if not geo_bots else
            "。GEOページ巡回が始まっている→独自ドメイン移行を検討する頃合い。")
    return "段階: " + " / ".join(stages) + tail


def main():
    import json
    print(json.dumps(report(), ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
