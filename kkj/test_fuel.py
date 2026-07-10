"""fuel(エージェント燃料データ棚)のオフラインテスト(上流モック・一時DB)

  python -m kkj.test_fuel
"""
import json
import tempfile

_tmp = tempfile.mkdtemp()
from . import config
config.DATA_DIR = type(config.DATA_DIR)(_tmp)
config.DB_PATH = config.DATA_DIR / "test_fuel.db"

from . import store, fuel  # noqa: E402

PASS = FAIL = 0


def ck(name, cond, info=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok: {name}")
    else:
        FAIL += 1
        print(f"  NG: {name} {info}")


def main():
    print("== 入力検証(402より前に400を返すためのvalidate) ==")
    for product, arg in (("npm/downloads", "react"), ("npm/downloads", "@scope/pkg"),
                         ("hn/buzz", "x402"), ("dns", "example.com"),
                         ("rdap", "coinbase.com"), ("github/trending", None),
                         ("crypto/fear-greed", None)):
        try:
            fuel.validate(product, arg)
            ck(f"許可: {product} {arg}", True)
        except Exception as e:
            ck(f"許可: {product} {arg}", False, str(e))
    for product, arg in (("npm/downloads", "../../etc"), ("npm/downloads", "UPPER"),
                         ("npm/downloads", None), ("dns", "not a host!"),
                         ("dns", "localhost"),          # 単一ラベルは拒否(要ドット)
                         ("rdap", "-bad.example.com"), ("hn/buzz", "x" * 100),
                         ("nope/nothing", None)):
        try:
            fuel.validate(product, arg)
            ck(f"拒否: {product} {arg!r}", False)
        except fuel.FuelError:
            ck(f"拒否: {product} {arg!r}", True)

    print("== 上流ホワイトリスト ==")
    try:
        fuel._get("https://evil.example.com/x")
        ck("非ホワイトリストホストを拒否", False)
    except fuel.UpstreamError:
        ck("非ホワイトリストホストを拒否", True)

    print("== fetcher(上流モック) ==")
    calls = []
    def fake_get_json(url, accept=None):
        calls.append(url)
        if "api.npmjs.org/downloads/point" in url:
            return {"downloads": 700, "package": "react"}
        if "api.npmjs.org/downloads/range" in url:
            return {"downloads": [{"day": f"2026-06-{i:02d}", "downloads": 100 + i * 10}
                                  for i in range(1, 29)]}
        if "hn.algolia.com" in url and "front_page" in url:
            return {"hits": [{"title": "A", "url": "u", "points": 100, "num_comments": 50,
                              "created_at": "t", "objectID": "1"},
                             {"title": "B", "url": "u", "points": 30, "num_comments": 10,
                              "created_at": "t", "objectID": "2"}]}
        if "hn.algolia.com" in url:
            return {"nbHits": 7, "hits": [
                {"title": "hi", "url": "u", "points": 42, "num_comments": 9,
                 "created_at": "t"}]}
        if "cloudflare-dns.com" in url:
            return {"Answer": [{"data": "1.2.3.4", "TTL": 300}]} if "type=A" in url else {}
        if "yields.llama.fi" in url:
            return {"data": [
                {"project": "aave-v3", "chain": "Ethereum", "symbol": "USDC",
                 "tvlUsd": 9e8, "apy": 4.2, "apyBase": 4.0, "apyReward": 0.2,
                 "stablecoin": True, "pool": "p1"},
                {"project": "uniswap-v3", "chain": "Base", "symbol": "ETH-USDC",
                 "tvlUsd": 5e8, "apy": 12.0, "apyBase": 12.0, "apyReward": None,
                 "stablecoin": False, "pool": "p2"}]}
        if "api.alternative.me" in url:
            return {"data": [{"value": "55", "value_classification": "Greed",
                              "timestamp": "1"}]}
        if "api.github.com" in url:
            return {"items": [{"full_name": "a/b", "html_url": "h", "description": "d",
                               "language": "Python", "stargazers_count": 500,
                               "forks_count": 10, "created_at": "t", "topics": ["x"]}]}
        raise AssertionError("unexpected url " + url)
    fuel._get_json = fake_get_json

    data, up = fuel.fetch_npm_downloads("react")
    ck("npm: 週間DL", data["downloads_last_week"] == 700)
    ck("npm: 月間合計を集計", data["downloads_last_month"] == sum(100 + i * 10
                                                              for i in range(1, 29)))
    ck("npm: momentum比が正", data["trend_ratio_2nd_half_vs_1st"] > 1)
    ck("npm: upstream 2 URL", len(up) == 2)

    data, _ = fuel.fetch_hn_frontpage()
    ck("hn: 集計(points計)", data["total_points"] == 130)

    data, _ = fuel.fetch_hn_buzz("x402")
    ck("hn buzz: nbHits", data["story_count"] == 7)
    ck("hn buzz: センチメント捏造なし宣言", "no sentiment" in data["note"])

    data, up = fuel.fetch_dns("example.com")
    ck("dns: 5レコード種を照会", len(up) == 5 and set(data["records"]) ==
       {"A", "AAAA", "MX", "TXT", "NS"})
    ck("dns: A抽出", data["records"]["A"][0]["data"] == "1.2.3.4")

    data, _ = fuel.fetch_defi_yields(stablecoin=True)
    ck("defi: stablecoinフィルタ", data["count"] == 1
       and data["pools"][0]["project"] == "aave-v3")

    data, _ = fuel.fetch_github_trending("python")
    ck("github: repos整形", data["repos"][0]["stars"] == 500)

    data, _ = fuel.fetch_fear_greed()
    ck("fng: now値", data["now"]["value"] == 55)

    print("== キャッシュ+provenance ==")
    conn = store.connect()
    calls.clear()
    d1, p1, hit1 = fuel.get_product(conn, "crypto/fear-greed", None, {})
    n_after_first = len(calls)
    d2, p2, hit2 = fuel.get_product(conn, "crypto/fear-greed", None, {})
    ck("初回は上流フェッチ", not hit1 and n_after_first == 1)
    ck("2回目はキャッシュ(上流を呼ばない)", hit2 and len(calls) == 1)
    ck("キャッシュでもsha256一致", p1["sha256"] == p2["sha256"])
    ck("cache_age_secが進む", p2["cache_age_sec"] >= 0)
    import hashlib
    expect = hashlib.sha256(json.dumps(d1, ensure_ascii=False, sort_keys=True,
                                       separators=(",", ":")).encode()).hexdigest()
    ck("provenance sha256はdata正規形のハッシュ", p1["sha256"] == expect)
    ck("鍵なし環境では署名None(エラーにしない)",
       p1.get("signature_ed25519_b64") is None or isinstance(
           p1["signature_ed25519_b64"], str))

    print("== カタログ整合 ==")
    for key, meta in fuel.CATALOG.items():
        ck(f"カタログ: {key} 価格/例/要約あり",
           meta["price_usd"] > 0 and meta["example"].startswith("/paid/fuel/")
           and len(meta["summary"]) > 20)
    ck("価格帯は$0.01-0.05(実需要の甘い所)",
       all(0.01 <= m["price_usd"] <= 0.05 for m in fuel.CATALOG.values()))

    conn.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
