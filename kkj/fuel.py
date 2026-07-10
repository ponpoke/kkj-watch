"""エージェント燃料データ棚(fuel): 無認証・公開の上流APIを機械可読+署名provenanceで販売

x402買い手の実需要(data=最大セグメント、$0.01-0.05帯)に合わせた薄いデータ商品群。

設計原則:
- 上流は固定ホワイトリスト(UPSTREAM_HOSTS)のみ。任意URLは一切受けない(SSRF方針の維持)
- 上流は全て無認証・公開APIで、生データでなく集計/正規化した派生値を返す
- 応答に provenance(upstream出所+fetched_at+sha256+Ed25519署名)を同梱=「attested data」
- 短期キャッシュで上流のレート制限を保護(fuel_cacheテーブル)
- 上流フェッチは支払い試行時のみ行う(unpaidの402応答では上流を呼ばない)

  python -m kkj.fuel catalog   # 商品一覧
  python -m kkj.fuel demo      # 各fetcherを1回ずつ実演(上流アクセスあり)
"""
import base64
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request

from . import config, store

USER_AGENT = "kkj-fuel/0.1 (+https://5.75.142.199.sslip.io/fuel)"
TIMEOUT_SEC = 12

# 上流ホワイトリスト(これ以外への接続はコードパスが存在しない)
UPSTREAM_HOSTS = (
    "api.npmjs.org",            # npmダウンロード統計(公開)
    "registry.npmjs.org",       # npmメタ(公開)
    "api.github.com",           # GitHub search API(無認証10req/min→要キャッシュ)
    "hn.algolia.com",           # Hacker News検索API(公開・無認証)
    "cloudflare-dns.com",       # DNS over HTTPS(公開)
    "rdap.org",                 # RDAPブートストラップ(公開・レジストリへ302)
    "yields.llama.fi",          # DefiLlama利回り(公開)
    "api.alternative.me",       # Crypto Fear & Greed(公開)
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS fuel_cache (
  cache_key  TEXT PRIMARY KEY,
  fetched_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS fuel_sales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  product TEXT NOT NULL,
  resource TEXT NOT NULL,
  cache_hit INTEGER NOT NULL DEFAULT 0
);
"""

_RE_NPM = re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]{0,213}$")
_RE_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_RE_KEYWORD = re.compile(r"^[\w .+#/-]{1,80}$")
_RE_GH_LANG = re.compile(r"^[a-z0-9+#.-]{1,30}$")


class FuelError(Exception):
    """入力不正(→400、支払い要求前に返す)"""


class UpstreamError(Exception):
    """上流不達(→503、支払いは発生させない)"""


def _get(url: str, accept: str | None = None) -> bytes:
    host = urllib.parse.urlsplit(url).hostname or ""
    if host not in UPSTREAM_HOSTS:
        raise UpstreamError(f"host not whitelisted: {host}")
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        **({"Accept": accept} if accept else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
            return resp.read()
    except Exception as e:
        raise UpstreamError(f"{host}: {e}") from e


def _get_json(url: str, accept: str | None = None):
    try:
        return json.loads(_get(url, accept).decode("utf-8", "replace"))
    except UpstreamError:
        raise
    except Exception as e:
        raise UpstreamError(f"bad upstream JSON: {e}") from e


# ---------- 各商品のfetcher(dataとupstream URLリストを返す) ----------

def fetch_npm_downloads(package: str):
    if not _RE_NPM.match(package):
        raise FuelError("invalid npm package name")
    q = urllib.parse.quote(package, safe="@/")
    u_week = f"https://api.npmjs.org/downloads/point/last-week/{q}"
    u_range = f"https://api.npmjs.org/downloads/range/last-month/{q}"
    week = _get_json(u_week)
    if "error" in week:
        raise FuelError(f"npm: {week['error']}")
    rng = _get_json(u_range)
    days = rng.get("downloads") or []
    total_month = sum(d.get("downloads", 0) for d in days)
    half = len(days) // 2 or 1
    first = sum(d.get("downloads", 0) for d in days[:half])
    second = sum(d.get("downloads", 0) for d in days[half:])
    data = {
        "package": package,
        "downloads_last_week": week.get("downloads"),
        "downloads_last_month": total_month,
        "daily": days[-14:],                      # 直近14日の日次
        "trend_ratio_2nd_half_vs_1st": round(second / first, 4) if first else None,
    }
    return data, [u_week, u_range]


def fetch_github_trending(language: str | None = None):
    if language and not _RE_GH_LANG.match(language):
        raise FuelError("invalid language filter")
    from datetime import datetime, timedelta, timezone
    since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")
    qparts = [f"created:>{since}"]
    if language:
        qparts.append(f"language:{language}")
    q = urllib.parse.quote(" ".join(qparts))
    url = (f"https://api.github.com/search/repositories?q={q}"
           f"&sort=stars&order=desc&per_page=25")
    j = _get_json(url, accept="application/vnd.github+json")
    items = [{
        "full_name": r.get("full_name"),
        "html_url": r.get("html_url"),
        "description": (r.get("description") or "")[:200],
        "language": r.get("language"),
        "stars": r.get("stargazers_count"),
        "forks": r.get("forks_count"),
        "created_at": r.get("created_at"),
        "topics": (r.get("topics") or [])[:8],
    } for r in (j.get("items") or [])]
    data = {"window": f"repos created since {since}, ranked by stars",
            "language": language, "count": len(items), "repos": items}
    return data, [url]


def fetch_hn_frontpage():
    url = "https://hn.algolia.com/api/v1/search?tags=front_page&hitsPerPage=30"
    j = _get_json(url)
    hits = j.get("hits") or []
    stories = [{
        "title": h.get("title"), "url": h.get("url"),
        "points": h.get("points"), "num_comments": h.get("num_comments"),
        "created_at": h.get("created_at"),
        "hn_url": f"https://news.ycombinator.com/item?id={h.get('objectID')}",
    } for h in hits]
    data = {
        "count": len(stories),
        "total_points": sum(s["points"] or 0 for s in stories),
        "total_comments": sum(s["num_comments"] or 0 for s in stories),
        "stories": stories,
    }
    return data, [url]


def fetch_hn_buzz(keyword: str):
    """キーワードの直近7日の注目度(件数/点/コメント)。センチメントの捏造はしない。"""
    if not _RE_KEYWORD.match(keyword):
        raise FuelError("invalid keyword")
    import time as _t
    since = int(_t.time()) - 7 * 86400
    q = urllib.parse.quote(keyword)
    url = (f"https://hn.algolia.com/api/v1/search?query={q}&tags=story"
           f"&numericFilters=created_at_i>{since}&hitsPerPage=50")
    j = _get_json(url)
    hits = j.get("hits") or []
    top = sorted(hits, key=lambda h: h.get("points") or 0, reverse=True)[:10]
    data = {
        "keyword": keyword, "window_days": 7,
        "story_count": j.get("nbHits"),
        "sampled": len(hits),
        "total_points_sampled": sum(h.get("points") or 0 for h in hits),
        "total_comments_sampled": sum(h.get("num_comments") or 0 for h in hits),
        "top_stories": [{
            "title": h.get("title"), "url": h.get("url"),
            "points": h.get("points"), "num_comments": h.get("num_comments"),
            "created_at": h.get("created_at"),
        } for h in top],
        "note": "attention metrics only; no sentiment inference",
    }
    return data, [url]


_DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS")


def fetch_dns(name: str):
    name = name.lower().rstrip(".")
    if not _RE_HOSTNAME.match(name):
        raise FuelError("invalid hostname")
    records, urls = {}, []
    for t in _DNS_TYPES:
        url = f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={t}"
        urls.append(url)
        j = _get_json(url, accept="application/dns-json")
        records[t] = [{"data": a.get("data"), "ttl": a.get("TTL")}
                      for a in (j.get("Answer") or [])]
    data = {"name": name, "records": records,
            "resolver": "cloudflare-dns.com (DNS over HTTPS)"}
    return data, urls


def fetch_rdap(domain: str):
    domain = domain.lower().rstrip(".")
    if not _RE_HOSTNAME.match(domain):
        raise FuelError("invalid domain")
    url = f"https://rdap.org/domain/{urllib.parse.quote(domain)}"
    # rdap.orgは権威レジストリへ302する公式ブートストラップ。リダイレクト先も公開レジストリ。
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/rdap+json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SEC) as resp:
            j = json.loads(resp.read().decode("utf-8", "replace"))
            final_url = resp.geturl()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise FuelError("domain not found in RDAP")
        raise UpstreamError(f"rdap: HTTP {e.code}") from e
    except Exception as e:
        raise UpstreamError(f"rdap: {e}") from e
    events = {ev.get("eventAction"): ev.get("eventDate")
              for ev in (j.get("events") or [])}
    registrar = None
    for ent in (j.get("entities") or []):
        if "registrar" in (ent.get("roles") or []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    registrar = item[3]
    data = {
        "domain": domain,
        "handle": j.get("handle"),
        "status": j.get("status"),
        "registrar": registrar,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "nameservers": [n.get("ldhName") for n in (j.get("nameservers") or [])],
        "rdap_source": final_url,
    }
    return data, [url, final_url]


def fetch_defi_yields(project: str | None = None, chain: str | None = None,
                      stablecoin: bool | None = None):
    for v in (project, chain):
        if v and not re.match(r"^[a-z0-9 .-]{1,40}$", v):
            raise FuelError("invalid filter")
    url = "https://yields.llama.fi/pools"
    j = _get_json(url)
    pools = j.get("data") or []
    pools.sort(key=lambda p: p.get("tvlUsd") or 0, reverse=True)
    pools = pools[:500]                       # カバレッジはTVL上位500(応答に明記)
    if project:
        pools = [p for p in pools if (p.get("project") or "").lower() == project]
    if chain:
        pools = [p for p in pools if (p.get("chain") or "").lower() == chain]
    if stablecoin is not None:
        pools = [p for p in pools if bool(p.get("stablecoin")) == stablecoin]
    out = [{
        "project": p.get("project"), "chain": p.get("chain"),
        "symbol": p.get("symbol"), "tvl_usd": p.get("tvlUsd"),
        "apy": p.get("apy"), "apy_base": p.get("apyBase"),
        "apy_reward": p.get("apyReward"), "stablecoin": p.get("stablecoin"),
        "pool_id": p.get("pool"),
    } for p in pools[:50]]
    data = {"coverage": "top 500 pools by TVL (DefiLlama), filtered, top 50 returned",
            "filters": {"project": project, "chain": chain, "stablecoin": stablecoin},
            "count": len(out), "pools": out}
    return data, [url]


def fetch_fear_greed():
    url = "https://api.alternative.me/fng/?limit=30"
    j = _get_json(url)
    series = [{"value": int(d.get("value", 0)),
               "classification": d.get("value_classification"),
               "timestamp": d.get("timestamp")}
              for d in (j.get("data") or [])]
    data = {"now": series[0] if series else None, "series_30d": series,
            "source": "alternative.me Crypto Fear & Greed Index"}
    return data, [url]


# ---------- 商品カタログ ----------
# key: URLパスの{key}部。price_usd/cache_ttl_sec/説明はここが単一の真実。

CATALOG = {
    "npm/downloads": {
        "price_usd": 0.01, "cache_ttl_sec": 6 * 3600, "param": "package",
        "example": "/paid/fuel/npm/downloads/react",
        "summary": "npm package download stats: last-week + last-month totals, "
                   "14-day daily series, momentum ratio. Any package name.",
    },
    "github/trending": {
        "price_usd": 0.02, "cache_ttl_sec": 1800, "param": None,
        "example": "/paid/fuel/github/trending?language=python",
        "summary": "Trending GitHub repos: created in the last 7 days ranked by stars "
                   "(top 25, optional ?language= filter).",
    },
    "hn/frontpage": {
        "price_usd": 0.01, "cache_ttl_sec": 600, "param": None,
        "example": "/paid/fuel/hn/frontpage",
        "summary": "Hacker News front page right now: 30 stories with points/comments "
                   "and aggregate attention totals.",
    },
    "hn/buzz": {
        "price_usd": 0.02, "cache_ttl_sec": 1800, "param": "keyword",
        "example": "/paid/fuel/hn/buzz/x402",
        "summary": "7-day Hacker News attention metrics for any keyword: story count, "
                   "points, comments, top stories. Metrics only, no sentiment inference.",
    },
    "dns": {
        "price_usd": 0.01, "cache_ttl_sec": 300, "param": "name",
        "example": "/paid/fuel/dns/example.com",
        "summary": "DNS lookup via DoH (Cloudflare): A/AAAA/MX/TXT/NS records with TTLs "
                   "for any hostname, normalized JSON.",
    },
    "rdap": {
        "price_usd": 0.02, "cache_ttl_sec": 24 * 3600, "param": "domain",
        "example": "/paid/fuel/rdap/coinbase.com",
        "summary": "Domain registration data (RDAP, the structured WHOIS successor): "
                   "registrar, created/expiry dates, status, nameservers.",
    },
    "defi/yields": {
        "price_usd": 0.02, "cache_ttl_sec": 900, "param": None,
        "example": "/paid/fuel/defi/yields?project=aave-v3&stablecoin=1",
        "summary": "DeFi yield rates from top-500-TVL pools (DefiLlama): APY breakdown, "
                   "TVL, optional project/chain/stablecoin filters.",
    },
    "crypto/fear-greed": {
        "price_usd": 0.01, "cache_ttl_sec": 3600, "param": None,
        "example": "/paid/fuel/crypto/fear-greed",
        "summary": "Crypto Fear & Greed Index: current value + 30-day series "
                   "(alternative.me).",
    },
}


def validate(product: str, arg: str | None):
    """上流を呼ばない入力検証。不正はFuelError(→402より前に400を返すために使う)"""
    meta = CATALOG.get(product)
    if meta is None:
        raise FuelError("unknown product")
    if meta["param"] and not arg:
        raise FuelError(f"{meta['param']} required, e.g. {meta['example']}")
    if not arg:
        return
    if product == "npm/downloads" and not _RE_NPM.match(arg):
        raise FuelError("invalid npm package name")
    if product == "hn/buzz" and not _RE_KEYWORD.match(arg):
        raise FuelError("invalid keyword")
    if product in ("dns", "rdap") and not _RE_HOSTNAME.match(arg.lower().rstrip(".")):
        raise FuelError("invalid hostname")


def dispatch(product: str, arg: str | None, qs: dict):
    """商品key+パラメータ→(data, upstream_urls)。入力不正はFuelError。"""
    def q1(k):
        v = qs.get(k)
        return v[0] if v else None
    if product == "npm/downloads":
        if not arg:
            raise FuelError("package name required: /paid/fuel/npm/downloads/{package}")
        return fetch_npm_downloads(arg)
    if product == "github/trending":
        return fetch_github_trending(q1("language"))
    if product == "hn/frontpage":
        return fetch_hn_frontpage()
    if product == "hn/buzz":
        if not arg:
            raise FuelError("keyword required: /paid/fuel/hn/buzz/{keyword}")
        return fetch_hn_buzz(arg)
    if product == "dns":
        if not arg:
            raise FuelError("hostname required: /paid/fuel/dns/{hostname}")
        return fetch_dns(arg)
    if product == "rdap":
        if not arg:
            raise FuelError("domain required: /paid/fuel/rdap/{domain}")
        return fetch_rdap(arg)
    if product == "defi/yields":
        st = q1("stablecoin")
        return fetch_defi_yields(
            q1("project"), q1("chain"),
            None if st is None else st in ("1", "true", "yes"))
    if product == "crypto/fear-greed":
        return fetch_fear_greed()
    raise FuelError("unknown product")


# ---------- キャッシュ+provenance ----------

def _cache_key(product: str, arg, qs: dict) -> str:
    rel = {k: v for k, v in sorted(qs.items())
           if k in ("language", "project", "chain", "stablecoin")}
    return json.dumps([product, arg, rel], sort_keys=True)


def get_product(conn, product: str, arg: str | None, qs: dict):
    """キャッシュ優先で商品データを返す: (data_dict, provenance_dict, cache_hit)"""
    conn.executescript(SCHEMA_SQL)
    meta = CATALOG[product]
    key = _cache_key(product, arg, qs)
    now = store.now_utc()
    row = conn.execute("SELECT * FROM fuel_cache WHERE cache_key=?", (key,)).fetchone()
    if row is not None:
        import datetime
        age = (datetime.datetime.fromisoformat(now)
               - datetime.datetime.fromisoformat(row["fetched_at"])).total_seconds()
        if age < meta["cache_ttl_sec"]:
            cached = json.loads(row["payload_json"])
            prov = _provenance(cached["data"], cached["upstream"], row["fetched_at"],
                               int(age))
            return cached["data"], prov, True
    data, upstream = dispatch(product, arg, qs)
    conn.execute("INSERT OR REPLACE INTO fuel_cache(cache_key, fetched_at, payload_json)"
                 " VALUES (?,?,?)",
                 (key, now, json.dumps({"data": data, "upstream": upstream},
                                       ensure_ascii=False)))
    conn.commit()
    return data, _provenance(data, upstream, now, 0), False


def _provenance(data, upstream_urls, fetched_at, cache_age_sec):
    """Ed25519署名つき出所情報。鍵が無い環境(dev)では署名なしで返す。"""
    canonical = json.dumps(data, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    prov = {
        "upstream": upstream_urls,
        "fetched_at": fetched_at,
        "cache_age_sec": cache_age_sec,
        "sha256": digest,
        "canonicalization": "JSON sort_keys, separators=(',',':'), UTF-8, of the data field",
        "note": "derived/aggregated metrics from public no-auth upstream APIs; "
                "verify against upstream anytime",
    }
    try:
        from . import attest
        priv = attest._load_priv()
        prov["signature_ed25519_b64"] = base64.b64encode(
            priv.sign(digest.encode())).decode()
        prov["public_key_b64"] = attest._pub_b64(priv)
        prov["signer"] = "kkj-watch (https://5.75.142.199.sslip.io/.well-known/witness)"
    except Exception:
        prov["signature_ed25519_b64"] = None
    return prov


def log_sale(conn, product: str, resource: str, cache_hit: bool):
    try:
        conn.execute("INSERT INTO fuel_sales(at, product, resource, cache_hit)"
                     " VALUES (?,?,?,?)",
                     (store.now_utc(), product, resource, 1 if cache_hit else 0))
        conn.commit()
    except Exception:
        pass                                   # 計測はベストエフォート(販売を止めない)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "catalog"
    if cmd == "catalog":
        print(json.dumps(CATALOG, ensure_ascii=False, indent=1))
    elif cmd == "demo":
        conn = store.connect()
        demos = [("npm/downloads", "react", {}), ("github/trending", None, {}),
                 ("hn/frontpage", None, {}), ("hn/buzz", "x402", {}),
                 ("dns", "example.com", {}), ("rdap", "coinbase.com", {}),
                 ("defi/yields", None, {"stablecoin": ["1"]}),
                 ("crypto/fear-greed", None, {})]
        for product, arg, qs in demos:
            try:
                data, prov, hit = get_product(conn, product, arg, qs)
                blob = json.dumps(data, ensure_ascii=False)
                print(f"ok  {product:22s} bytes={len(blob):6d} cache={hit} "
                      f"sha256={prov['sha256'][:12]} signed={bool(prov.get('signature_ed25519_b64'))}")
            except Exception as e:
                print(f"NG  {product:22s} {type(e).__name__}: {e}")
        conn.close()
    else:
        print("usage: python -m kkj.fuel [catalog|demo]")


if __name__ == "__main__":
    main()
