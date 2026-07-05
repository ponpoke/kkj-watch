"""x402 Trust Index — Bazaar掲載resourceの生存・整合性プローブ

x402watch(レジストリ掲載内容の差分)を補完する実物検証レイヤー。
Bazaarに掲載されている公開resourceに「未払いのGETリクエスト」を送り、
実際に返る402の支払い条件が掲載内容と一致するかを検証する。

安全設計(絶対条件):
  - 対象は Bazaar レジストリに掲載済みの resource のみ(任意URL登録は存在しない)
  - GETのみ(POSTしない=副作用ゼロ)。支払いは絶対に送らない
  - https限定 + 解決した全IPがグローバルであること(SSRF防御) + リダイレクト追従しない
  - ホストごとに1サイクル3件まで・リクエスト間隔・タイムアウト10秒・応答64KB上限
  - 頻度: 1リソースあたり最短でも数十時間に1回(監視網として最小限)
  これは x402station / forum-labs-trust-prober 等が当サービスに毎日行っている
  エコシステム標準のプローブ行為と同種・同程度である。

検知イベント(状態遷移時のみ発火・スパムしない):
  live_payto_mismatch   実物の受取アドレスが掲載と不一致(乗っ取り/詐欺兆候: critical)
  live_price_mismatch   実物の価格が掲載と不一致(high)
  endpoint_dead         2回連続で応答なし(high)
  endpoint_recovered    死亡判定後に復活(medium)
  not_x402              402以外を返す=x402で保護されていない掲載(low)

  python -m kkj.x402probe run [budget]   # 1サイクル(既定400件)
  python -m kkj.x402probe stats
"""
import http.client
import ipaddress
import json
import socket
import ssl
import sys
import time
import urllib.parse

from . import store, x402watch

USER_AGENT = ("kkj-x402-trust-index/0.1 (liveness+consistency verification of "
              "Bazaar-listed x402 resources; GET-only, never pays; "
              "contact: ponzuzuzuzuzu@gmail.com)")
TIMEOUT = 10
MAX_BODY = 65536
DEFAULT_BUDGET = 400
PER_HOST_CAP = 3
REQUEST_DELAY_SEC = 0.3
DEAD_AFTER_FAILS = 2

# レジストリ(CAIP-2)と実物402(v1名)のネットワーク表記ゆれを正規化
NETWORK_ALIASES = {
    "base": "eip155:8453", "base-sepolia": "eip155:84532",
    "polygon": "eip155:137", "polygon-amoy": "eip155:80002",
    "avalanche": "eip155:43114", "ethereum": "eip155:1",
    "solana": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS x402_probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    probed_at TEXT NOT NULL,
    alive INTEGER NOT NULL,
    http_status INTEGER,
    is_402 INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER,
    live_accepts_json TEXT,
    consistency TEXT NOT NULL,         -- ok / payto_mismatch / price_mismatch / not_x402 / unreachable / skipped:<reason>
    fail_count INTEGER NOT NULL DEFAULT 0,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_x402probe_res ON x402_probes(resource_id, id);
"""


def canon_network(net):
    return NETWORK_ALIASES.get(net or "", net or "")


# SSRF: 明示的に拒否する非公開/特殊用途レンジ(is_globalに加えた二重防御)
ALLOWED_SCHEMES = ("http", "https")
BLOCKED_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8",          # このホスト
    "127.0.0.0/8",        # ループバック
    "10.0.0.0/8",         # プライベート
    "172.16.0.0/12",      # プライベート
    "192.168.0.0/16",     # プライベート
    "169.254.0.0/16",     # リンクローカル(=クラウドmetadata 169.254.169.254)
    "100.64.0.0/10",      # CGNAT
    "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24",     # 特殊用途/ドキュメント用
    "::1/128",            # IPv6ループバック
    "fc00::/7",           # IPv6ユニークローカル
    "fe80::/10",          # IPv6リンクローカル
    "::ffff:0:0/96",      # IPv4射影(::ffff:127.0.0.1等での回避を防ぐ)
    "64:ff9b::/96",       # NAT64
))


def _ip_ok(ip_str: str) -> bool:
    """公開IPのみ許可。is_global かつ 明示ブロックレンジに属さないこと"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return _ip_ok(str(ip.ipv4_mapped))     # ::ffff:10.0.0.1 等を実IPで判定
    if not ip.is_global:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local:
        return False
    return not any(ip in net for net in BLOCKED_NETS)


def resolve_public_ips(host: str, port: int):
    """ホスト名を解決し、返った全IPが公開IPであることを検証。
    1つでも非公開が混じれば拒否(DNSリバインディングの的を減らす)。戻り値: [(family, ip)]"""
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    out = []
    for info in infos:
        ip = info[4][0]
        if not _ip_ok(ip):
            raise ValueError(f"non-public address {ip} for host {host}")
        out.append((info[0], ip))
    if not out:
        raise ValueError(f"no addresses for {host}")
    return out


def assert_url_allowed(url: str):
    """SSRF防御の入口: スキーム検査 + 解決した全IPが公開IPであること"""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"scheme not allowed: {p.scheme or '(none)'}")
    if not p.hostname:
        raise ValueError("no hostname")
    port = p.port or (443 if p.scheme == "https" else 80)
    resolve_public_ips(p.hostname, port)


def _pinned_connection(scheme, host, ip, port):
    """検証済みIPへ接続をピン留めしたHTTP(S)接続。
    SNI/証明書検証/Hostヘッダは本来のホスト名で行いつつ、TCP接続先だけを
    検証済みIPに固定する = 検査後の再解決による差し替え(リバインディング)を封じる。"""
    if scheme == "https":
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=TIMEOUT, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=TIMEOUT)
    conn._create_connection = (
        lambda address, timeout=TIMEOUT, source_address=None:
        socket.create_connection((ip, port), timeout=timeout))
    return conn


def fetch(url: str):
    """未払いGET(不払い・リダイレクト非追従・IPピン留め)。
    戻り値: (http_status|None, body_bytes, latency_ms, error|None)"""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ALLOWED_SCHEMES:
        return None, b"", 0, f"scheme not allowed: {p.scheme or '(none)'}"
    host = p.hostname
    if not host:
        return None, b"", 0, "no hostname"
    port = p.port or (443 if p.scheme == "https" else 80)
    try:
        family, ip = resolve_public_ips(host, port)[0]   # 検証済みIPへピン留め
    except Exception as e:
        return None, b"", 0, f"blocked: {e}"
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    t0 = time.monotonic()
    conn = None
    try:
        conn = _pinned_connection(p.scheme, host, ip, port)
        # http.client はリダイレクトを追従しない(3xxはそのまま返る)
        conn.request("GET", path, headers={
            "User-Agent": USER_AGENT, "Accept": "application/json",
            "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(MAX_BODY)
        return resp.status, body, int((time.monotonic() - t0) * 1000), None
    except Exception as e:
        return None, b"", int((time.monotonic() - t0) * 1000), str(e)[:200]
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def parse_live_accepts(body: bytes):
    """402本文からaccepts(価格/payTo/network)を抽出。壊れたJSONはNone"""
    try:
        d = json.loads(body)
    except Exception:
        return None
    if not isinstance(d, dict):        # null / 配列 / 文字列だけの"JSON"を返す実装がある
        return None
    out = []
    for a in d.get("accepts") or []:
        if not isinstance(a, dict):
            continue
        out.append({
            "scheme": a.get("scheme"),
            "network": canon_network(a.get("network")),
            "amount": str(a.get("maxAmountRequired") if a.get("maxAmountRequired") is not None
                          else a.get("amount") or ""),
            "payTo": a.get("payTo"),
        })
    return out


def check_consistency(registry_accepts: list, live_accepts: list):
    """掲載(レジストリ)と実物(live 402)の支払い条件を照合。
    戻り値: (consistency, detail|None)。payTo不一致が最優先(詐欺/乗っ取り兆候)"""
    if not live_accepts:
        return "not_x402", None
    reg_payto = {(a.get("payTo") or "").lower() for a in registry_accepts if a.get("payTo")}
    live_payto = {(a.get("payTo") or "").lower() for a in live_accepts if a.get("payTo")}
    if reg_payto and live_payto and not (reg_payto & live_payto):
        return "payto_mismatch", {
            "registry_payTo": sorted(reg_payto), "live_payTo": sorted(live_payto),
            "note": "The receiving address served by the live endpoint does not match the "
                    "registry listing. Do NOT pay until verified with the provider.",
        }
    reg_by_net = {canon_network(a.get("network")): a for a in registry_accepts}
    for la in live_accepts:
        ra = reg_by_net.get(la["network"])
        if ra and la["amount"] and str(ra.get("amount")) != la["amount"]:
            return "price_mismatch", {
                "network": la["network"],
                "registry_amount": str(ra.get("amount")), "live_amount": la["amount"],
                "registry_usd": x402watch.usd_of(ra.get("amount"), ra.get("asset")),
                "live_usd": x402watch.usd_of(la["amount"], ra.get("asset")),
            }
    return "ok", None


def pick_targets(conn, budget: int):
    """プローブ対象を選ぶ: ①直近24hに変更があったもの ②未プローブ/最古プローブ順。
    ホストごとに PER_HOST_CAP 件まで(集中アクセスしない)"""
    rows = conn.execute(
        """SELECT r.id, r.resource, r.latest_json,
                  (SELECT MAX(p.id) FROM x402_probes p WHERE p.resource_id=r.id) AS last_probe_id,
                  (SELECT COUNT(*) FROM x402_events e WHERE e.resource_id=r.id
                     AND e.detected_at > datetime('now','-1 day')) AS recent_changes
           FROM x402_resources r WHERE r.active=1
           ORDER BY recent_changes DESC, COALESCE(last_probe_id, 0) ASC
           LIMIT ?""", (budget * 3,)).fetchall()
    picked, host_count = [], {}
    for r in rows:
        host = urllib.parse.urlsplit(r["resource"]).hostname or ""
        if host_count.get(host, 0) >= PER_HOST_CAP:
            continue
        host_count[host] = host_count.get(host, 0) + 1
        picked.append(r)
        if len(picked) >= budget:
            break
    return picked


def probe_one(conn, row, ts):
    """1リソースをプローブし、状態遷移イベントを発火。戻り値: consistency"""
    rid, url = row["id"], row["resource"]
    prev = conn.execute(
        "SELECT * FROM x402_probes WHERE resource_id=? ORDER BY id DESC LIMIT 1",
        (rid,)).fetchone()
    prev_fails = prev["fail_count"] if prev else 0
    prev_cons = prev["consistency"] if prev else None

    try:
        assert_url_allowed(url)
    except Exception as e:
        conn.execute(
            "INSERT INTO x402_probes(resource_id, probed_at, alive, http_status, is_402,"
            " latency_ms, live_accepts_json, consistency, fail_count, error)"
            " VALUES (?,?,0,NULL,0,NULL,NULL,?,?,?)",
            (rid, ts, "skipped:unsafe_url", prev_fails, str(e)[:200]))
        return "skipped"

    status, body, latency, err = fetch(url)
    alive = status is not None
    is_402 = status == 402
    live_accepts = parse_live_accepts(body) if is_402 else None

    if not alive:
        consistency = "unreachable"
        fail_count = prev_fails + 1
    elif is_402 and live_accepts:
        registry_accepts = json.loads(row["latest_json"]).get("accepts", [])
        consistency, detail = check_consistency(registry_accepts, live_accepts)
        fail_count = 0
    else:
        # 200/404/405等: ホストは生きているがGETでは402を返さない
        # (POST専用やパスパラメータ必須の掲載も多い→「不明」であって「不正」ではない)
        consistency = "not_x402"
        detail = None
        fail_count = 0

    conn.execute(
        "INSERT INTO x402_probes(resource_id, probed_at, alive, http_status, is_402,"
        " latency_ms, live_accepts_json, consistency, fail_count, error)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (rid, ts, 1 if alive else 0, status, 1 if is_402 else 0, latency,
         json.dumps(live_accepts, ensure_ascii=False) if live_accepts else None,
         consistency, fail_count, err))

    # --- 状態遷移イベント(初回観測 or 状態が変わった時だけ) ---
    def emit(etype, sev, det):
        det["resource"] = url
        conn.execute(
            "INSERT INTO x402_events(resource_id, event_type, severity, detected_at,"
            " detail_json) VALUES (?,?,?,?,?)",
            (rid, etype, sev, ts, json.dumps(det, ensure_ascii=False)))

    if not alive and fail_count == DEAD_AFTER_FAILS:
        emit("endpoint_dead", "high",
             {"note": f"No response on {DEAD_AFTER_FAILS} consecutive probes.",
              "last_error": err})
    if alive and prev_fails >= DEAD_AFTER_FAILS:
        emit("endpoint_recovered", "medium", {"http_status": status})
    if consistency == "payto_mismatch" and prev_cons != "payto_mismatch":
        emit("live_payto_mismatch", "critical", detail)
    if consistency == "price_mismatch" and prev_cons != "price_mismatch":
        emit("live_price_mismatch", "high", detail)
    if (consistency == "ok" and prev_cons in ("payto_mismatch", "price_mismatch")):
        emit("consistency_restored", "medium", {"previous": prev_cons})
    return consistency


def run(budget=DEFAULT_BUDGET, conn=None, delay=REQUEST_DELAY_SEC):
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(x402watch.SCHEMA_SQL)
    conn.executescript(SCHEMA_SQL)
    ts = store.now_utc()
    targets = pick_targets(conn, budget)
    summary = {}
    for row in targets:
        try:
            c = probe_one(conn, row, ts)
        except Exception as e:          # 1件の異常でサイクル全体を落とさない
            c = "error"
            conn.execute(
                "INSERT INTO x402_probes(resource_id, probed_at, alive, http_status, is_402,"
                " latency_ms, live_accepts_json, consistency, fail_count, error)"
                " VALUES (?,?,0,NULL,0,NULL,NULL,'error',0,?)",
                (row["id"], ts, str(e)[:200]))
        summary[c] = summary.get(c, 0) + 1
        # プローブ結果からTrustスコアを即時更新
        try:
            from . import x402trust
            x402trust.update_score(conn, row["id"])
        except Exception:
            pass
        if delay:
            time.sleep(delay)
    conn.commit()
    out = {"at": ts, "probed": len(targets), "by_consistency": summary}
    if own:
        conn.close()
    return out


def stats(conn=None):
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    out = {
        "probes_total": conn.execute("SELECT COUNT(*) n FROM x402_probes").fetchone()["n"],
        "resources_probed": conn.execute(
            "SELECT COUNT(DISTINCT resource_id) n FROM x402_probes").fetchone()["n"],
        "latest_by_consistency": {r["consistency"]: r["n"] for r in conn.execute(
            """SELECT consistency, COUNT(*) n FROM x402_probes p
               WHERE p.id = (SELECT MAX(id) FROM x402_probes WHERE resource_id=p.resource_id)
               GROUP BY consistency""")},
    }
    if own:
        conn.close()
    return out


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "run":
        budget = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_BUDGET
        print(json.dumps(run(budget), ensure_ascii=False, indent=1))
    elif cmd == "stats":
        print(json.dumps(stats(), ensure_ascii=False, indent=1))
    else:
        print("usage: python -m kkj.x402probe [run [budget]|stats]")


if __name__ == "__main__":
    main()
