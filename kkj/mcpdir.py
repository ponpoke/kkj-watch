"""MCP Trust Directory — 公開リモートMCPサーバーの観測目録(信頼レイヤー)

MCPサーバーは11,000+あるが信頼レイヤーが存在しない。最大の実害ベクトルは
「tool poisoning」= ツール説明文(エージェントが読む指示)の悪意ある書き換え。
本モジュールはcuratedなリモートMCPサーバーを日次で観測し、ツール定義の
SHA-256指紋でrug-pull(説明文すり替え)・ツール増減・死活を検知する。

安全設計(絶対条件):
  - 対象はcurated SEEDのみ(任意URL登録は存在しない)
  - JSON-RPCは initialize / notifications/initialized / tools/list のみ。
    tools/call は絶対に送らない(副作用ゼロ・読み取り専用)
  - SSRFガードはx402probe流用(公開IPのみ・検証済みIPへピン留め・リダイレクト非追従)
  - タイムアウト15秒・応答256KB上限・サーバーあたり最大3リクエスト/日
  - 保存するのはツール定義(公開情報)とその指紋のみ。個人情報なし

日次ダイジェストは witness(既存のEd25519署名付き日次ハッシュチェーン)に
アンカーされ、観測記録が後付けで改竄されていないことを第三者検証できる。

  python -m kkj.mcpdir sync
  python -m kkj.mcpdir stats
"""
import hashlib
import http.client
import json
import sys
import urllib.parse

from . import store, x402probe

USER_AGENT = ("kkj-mcp-trust-probe/0.1 (read-only MCP liveness+tool-definition "
              "drift observation; initialize/tools-list only, never calls tools; "
              "contact: ponzuzuzuzuzu@gmail.com)")
PROTOCOL_VERSION = "2025-06-18"
TIMEOUT = 15
MAX_BODY = 262144
DEAD_AFTER = 2

# curated seed: 公開されている(または公開と案内されている)リモートMCPエンドポイント。
# auth必須のものも「auth_requiredの観測」として価値があるため含める。
SEED = [
    {"url": "https://5.75.142.199.sslip.io/mcp", "name": "kkj-watch",
     "provider": "kkj-watch", "docs": "https://5.75.142.199.sslip.io/llms.txt"},
    {"url": "https://mcp.deepwiki.com/mcp", "name": "DeepWiki",
     "provider": "Cognition", "docs": "https://docs.devin.ai/work-with-devin/deepwiki-mcp"},
    {"url": "https://mcp.context7.com/mcp", "name": "Context7",
     "provider": "Upstash", "docs": "https://context7.com"},
    {"url": "https://docs.mcp.cloudflare.com/mcp", "name": "Cloudflare Docs",
     "provider": "Cloudflare", "docs": "https://developers.cloudflare.com/agents/model-context-protocol/"},
    {"url": "https://mcp.semgrep.ai/mcp", "name": "Semgrep",
     "provider": "Semgrep", "docs": "https://semgrep.dev/docs/mcp"},
    {"url": "https://gitmcp.io/docs", "name": "GitMCP (generic docs)",
     "provider": "GitMCP", "docs": "https://gitmcp.io"},
    {"url": "https://huggingface.co/mcp", "name": "Hugging Face",
     "provider": "Hugging Face", "docs": "https://huggingface.co/settings/mcp"},
    {"url": "https://mcp.linear.app/mcp", "name": "Linear",
     "provider": "Linear", "docs": "https://linear.app/docs/mcp"},
    {"url": "https://mcp.notion.com/mcp", "name": "Notion",
     "provider": "Notion", "docs": "https://developers.notion.com/docs/mcp"},
    {"url": "https://mcp.stripe.com", "name": "Stripe",
     "provider": "Stripe", "docs": "https://docs.stripe.com/mcp"},
    {"url": "https://api.githubcopilot.com/mcp/", "name": "GitHub",
     "provider": "GitHub", "docs": "https://docs.github.com/en/copilot/customizing-copilot/using-model-context-protocol"},
    {"url": "https://mcp.exa.ai/mcp", "name": "Exa",
     "provider": "Exa", "docs": "https://docs.exa.ai/reference/exa-mcp"},
]

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS mcp_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    name TEXT, provider TEXT, docs TEXT,
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    fail_count INTEGER NOT NULL DEFAULT 0,
    latest_hash TEXT, latest_json TEXT
);
CREATE TABLE IF NOT EXISTS mcp_probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    probed_at TEXT NOT NULL,
    alive INTEGER NOT NULL,
    http_status INTEGER,
    auth_observed TEXT,
    is_mcp INTEGER NOT NULL DEFAULT 0,
    protocol_version TEXT, server_name TEXT, server_version TEXT,
    tools_count INTEGER, tools_hash TEXT,
    latency_ms INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_mcp_probes_res ON mcp_probes(resource_id, id);
CREATE TABLE IF NOT EXISTS mcp_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    fetched_at TEXT NOT NULL,
    tools_hash TEXT NOT NULL,
    tools_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS mcp_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,      -- tool_description_changed / tool_added / tool_removed /
                                   -- tool_schema_changed / unreachable / recovered /
                                   -- server_version_changed / auth_changed
    severity TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    detail_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_mcp_events_res ON mcp_events(resource_id, id);
CREATE TABLE IF NOT EXISTS mcp_digests (
    date TEXT PRIMARY KEY,
    digest TEXT NOT NULL
);
"""


def canonical(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def tool_fingerprint(tool: dict) -> dict:
    """1ツールの指紋。説明文の変化(=tool poisoningベクトル)を独立に検知できるよう
    description単体のハッシュも持つ"""
    name = tool.get("name") or ""
    desc = tool.get("description") or ""
    schema = tool.get("inputSchema") or {}
    return {
        "name": name,
        "sha256": hashlib.sha256(canonical(
            {"name": name, "description": desc, "inputSchema": schema}
        ).encode()).hexdigest(),
        "description_sha256": hashlib.sha256(desc.encode()).hexdigest(),
        "schema_sha256": hashlib.sha256(canonical(schema).encode()).hexdigest(),
    }


def tools_combined_hash(fps: list) -> str:
    return hashlib.sha256(canonical(
        sorted((f["name"], f["sha256"]) for f in fps)).encode()).hexdigest()


def _parse_rpc_body(body: bytes, content_type: str):
    """plain JSON / SSE(text/event-stream) の両方からJSON-RPC応答を取り出す"""
    text = body.decode("utf-8", "replace")
    if "event-stream" in (content_type or "") or text.lstrip().startswith(("event:", "data:", ":")):
        result = None
        for line in text.splitlines():
            if line.startswith("data:"):
                payload = line[5:].strip()
                try:
                    d = json.loads(payload)
                except Exception:
                    continue
                if isinstance(d, dict) and ("result" in d or "error" in d):
                    result = d
        return result
    try:
        d = json.loads(text)
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def rpc_post(url: str, method: str, params, req_id=1, session_id=None,
             notification=False):
    """1回のJSON-RPC POST(IPピン留め・リダイレクト非追従)。
    戻り値: (http_status|None, rpc_dict|None, session_id|None, error|None)"""
    p = urllib.parse.urlsplit(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    try:
        family, ip = x402probe.resolve_public_ips(host, port)[0]
    except Exception as e:
        return None, None, None, f"blocked: {e}"
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if not notification:
        msg["id"] = req_id
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Connection": "close",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    conn = None
    try:
        conn = x402probe._pinned_connection(p.scheme, host, ip, port)
        conn.timeout = TIMEOUT
        conn.request("POST", path, body=json.dumps(msg), headers=headers)
        resp = conn.getresponse()
        body = resp.read(MAX_BODY)
        sid = resp.getheader("Mcp-Session-Id") or session_id
        rpc = _parse_rpc_body(body, resp.getheader("Content-Type") or "")
        return resp.status, rpc, sid, None
    except Exception as e:
        return None, None, session_id, str(e)[:200]
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def observe(url: str, rpc=None):
    """1サーバーを観測: initialize → initialized → tools/list(読み取り専用)。
    戻り値dictは公開情報とその指紋のみ"""
    rpc = rpc or rpc_post
    import time
    t0 = time.monotonic()
    try:
        x402probe.assert_url_allowed(url)
    except Exception as e:
        return {"alive": False, "http_status": None, "auth": "unknown", "is_mcp": False,
                "error": f"blocked: {e}", "latency_ms": 0, "protocol_version": None,
                "server_name": None, "server_version": None, "tools": None}
    status, rpc_resp, sid, err = rpc(url, "initialize", {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "kkj-mcp-trust-probe", "version": "0.1"},
    })
    latency = int((time.monotonic() - t0) * 1000)
    out = {"alive": status is not None, "http_status": status, "auth": "unknown",
           "is_mcp": False, "error": err, "latency_ms": latency,
           "protocol_version": None, "server_name": None, "server_version": None,
           "tools": None}
    if status is None:
        return out
    if status in (401, 403):
        out["auth"] = "auth_required"
        return out
    result = (rpc_resp or {}).get("result") or {}
    info = result.get("serverInfo") or {}
    if not (info or result.get("protocolVersion")):
        return out              # 応答はあるがMCPではない
    out["is_mcp"] = True
    out["auth"] = "open"
    out["protocol_version"] = result.get("protocolVersion")
    out["server_name"] = info.get("name")
    out["server_version"] = info.get("version")
    # spec準拠: initialized通知(失敗は無視) → tools/list
    rpc(url, "notifications/initialized", None, session_id=sid, notification=True)
    st2, resp2, _, err2 = rpc(url, "tools/list", {}, req_id=2, session_id=sid)
    tools = ((resp2 or {}).get("result") or {}).get("tools")
    if isinstance(tools, list):
        out["tools"] = [t for t in tools if isinstance(t, dict)]
    elif err2:
        out["error"] = (out["error"] or "") or f"tools/list: {err2}"
    return out


def _diff_events(prev: dict, cur: dict, prev_tools_full):
    """観測差分をイベント化。説明文の書き換え=最重要(tool poisoningベクトル)"""
    evs = []
    pt = {t["name"]: t for t in (prev.get("tools") or [])}
    ct = {t["name"]: t for t in (cur.get("tools") or [])}
    prev_full = {t.get("name"): t for t in (prev_tools_full or [])}
    added = sorted(set(ct) - set(pt))
    removed = sorted(set(pt) - set(ct))
    if added:
        evs.append(("tool_added", "medium", {"tools": added}))
    if removed:
        evs.append(("tool_removed", "medium", {"tools": removed}))
    for name in sorted(set(pt) & set(ct)):
        if pt[name]["sha256"] == ct[name]["sha256"]:
            continue
        if pt[name]["description_sha256"] != ct[name]["description_sha256"]:
            old_desc = (prev_full.get(name) or {}).get("description") or ""
            evs.append(("tool_description_changed", "high", {
                "tool": name,
                "before_sha256": pt[name]["description_sha256"],
                "after_sha256": ct[name]["description_sha256"],
                "before_excerpt": old_desc[:300],
                "note": "The tool description (the instructions an agent reads) changed. "
                        "This is the tool-poisoning / rug-pull vector: re-review before "
                        "continuing to trust this server.",
            }))
        elif pt[name]["schema_sha256"] != ct[name]["schema_sha256"]:
            evs.append(("tool_schema_changed", "medium", {"tool": name}))
    if (prev.get("server_version") and cur.get("server_version")
            and prev["server_version"] != cur["server_version"]):
        evs.append(("server_version_changed", "low", {
            "before": prev["server_version"], "after": cur["server_version"]}))
    if (prev.get("auth") in ("open", "auth_required") and cur.get("auth") in ("open", "auth_required")
            and prev["auth"] != cur["auth"]):
        evs.append(("auth_changed", "medium", {
            "before": prev["auth"], "after": cur["auth"]}))
    return evs


def sync(conn=None, rpc=None):
    """1回の同期: seed整備→全サーバー観測→差分イベント→日次ダイジェストをwitnessへ"""
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    ts = store.now_utc()
    seed_urls = {s["url"] for s in SEED}
    for r in conn.execute("SELECT id, url FROM mcp_resources").fetchall():
        if r["url"] not in seed_urls:
            conn.execute("DELETE FROM mcp_probes WHERE resource_id=?", (r["id"],))
            conn.execute("DELETE FROM mcp_snapshots WHERE resource_id=?", (r["id"],))
            conn.execute("DELETE FROM mcp_events WHERE resource_id=?", (r["id"],))
            conn.execute("DELETE FROM mcp_resources WHERE id=?", (r["id"],))
    for s in SEED:
        if conn.execute("SELECT 1 FROM mcp_resources WHERE url=?", (s["url"],)).fetchone() is None:
            conn.execute(
                "INSERT INTO mcp_resources(url,name,provider,docs,first_seen,last_seen,active)"
                " VALUES (?,?,?,?,?,?,1)",
                (s["url"], s["name"], s["provider"], s["docs"], ts, ts))
    conn.commit()

    summary = {}
    for row in conn.execute("SELECT * FROM mcp_resources ORDER BY id").fetchall():
        obs = observe(row["url"], rpc=rpc)
        fps = [tool_fingerprint(t) for t in (obs["tools"] or [])] if obs["tools"] else []
        th = tools_combined_hash(fps) if fps else None
        conn.execute(
            "INSERT INTO mcp_probes(resource_id,probed_at,alive,http_status,auth_observed,"
            " is_mcp,protocol_version,server_name,server_version,tools_count,tools_hash,"
            " latency_ms,error) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (row["id"], ts, 1 if obs["alive"] else 0, obs["http_status"], obs["auth"],
             1 if obs["is_mcp"] else 0, obs["protocol_version"], obs["server_name"],
             obs["server_version"], len(fps) if obs["tools"] is not None else None,
             th, obs["latency_ms"], obs["error"]))

        latest = {
            "alive": obs["alive"], "http_status": obs["http_status"], "auth": obs["auth"],
            "is_mcp": obs["is_mcp"], "protocol_version": obs["protocol_version"],
            "server_name": obs["server_name"], "server_version": obs["server_version"],
            "tools": fps, "tools_hash": th,
        }
        h = hashlib.sha256(canonical(latest).encode()).hexdigest()
        prev_json = json.loads(row["latest_json"]) if row["latest_json"] else {}

        def emit(etype, sev, det):
            det["url"] = row["url"]
            conn.execute(
                "INSERT INTO mcp_events(resource_id,event_type,severity,detected_at,"
                "detail_json) VALUES (?,?,?,?,?)",
                (row["id"], etype, sev, ts, json.dumps(det, ensure_ascii=False)))

        fc = row["fail_count"]
        if not obs["alive"]:
            fc += 1
            if fc == DEAD_AFTER:
                emit("unreachable", "high", {"error": obs["error"]})
        else:
            if fc >= DEAD_AFTER:
                emit("recovered", "medium", {"http_status": obs["http_status"]})
            fc = 0
            if prev_json:
                prev_snapshot_tools = None
                if prev_json.get("tools_hash"):
                    sr = conn.execute(
                        "SELECT tools_json FROM mcp_snapshots WHERE resource_id=?"
                        " ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
                    if sr:
                        prev_snapshot_tools = json.loads(sr["tools_json"])
                for etype, sev, det in _diff_events(prev_json, latest, prev_snapshot_tools):
                    emit(etype, sev, det)
        # ツール定義の全文スナップショットは「変化した時だけ」保存(証拠・容量節約)
        if th and th != prev_json.get("tools_hash"):
            conn.execute(
                "INSERT INTO mcp_snapshots(resource_id,fetched_at,tools_hash,tools_json)"
                " VALUES (?,?,?,?)",
                (row["id"], ts, th, json.dumps(obs["tools"], ensure_ascii=False)))
        conn.execute(
            "UPDATE mcp_resources SET last_seen=?, latest_hash=?, latest_json=?,"
            " fail_count=? WHERE id=?",
            (ts, h, json.dumps(latest, ensure_ascii=False), fc, row["id"]))
        key = "mcp" if obs["is_mcp"] else ("auth" if obs["auth"] == "auth_required"
                                           else ("down" if not obs["alive"] else "not_mcp"))
        summary[key] = summary.get(key, 0) + 1
        # 1件ごとにcommit: 次のネットワークI/O中に書き込みロックを持ち越さない
        conn.commit()

    # 日次ダイジェスト: 全観測のcanonicalハッシュを既存の署名チェーン(witness)へ
    digest = hashlib.sha256(canonical(
        {r["url"]: r["latest_hash"] for r in
         conn.execute("SELECT url, latest_hash FROM mcp_resources ORDER BY url")}
    ).encode()).hexdigest()
    try:
        from . import witness
        witness.insert(conn, digest, "mcp-trust-directory-daily", paid=False)
        conn.execute("INSERT OR REPLACE INTO mcp_digests(date, digest) VALUES (?,?)",
                     (ts[:10], digest))
    except Exception:
        pass
    conn.commit()
    out = {"at": ts, "resources": len(SEED), "by_state": summary, "digest": digest}
    if own:
        conn.close()
    return out


def stats(conn=None):
    own = conn is None
    if own:
        conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    out = {
        "resources": conn.execute("SELECT COUNT(*) n FROM mcp_resources").fetchone()["n"],
        "probes": conn.execute("SELECT COUNT(*) n FROM mcp_probes").fetchone()["n"],
        "snapshots": conn.execute("SELECT COUNT(*) n FROM mcp_snapshots").fetchone()["n"],
        "events_by_type": {r["event_type"]: r["n"] for r in conn.execute(
            "SELECT event_type, COUNT(*) n FROM mcp_events GROUP BY event_type")},
        "latest_digest": None,
    }
    r = conn.execute("SELECT * FROM mcp_digests ORDER BY date DESC LIMIT 1").fetchone()
    if r:
        out["latest_digest"] = {"date": r["date"], "digest": r["digest"]}
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
        print(__doc__)


if __name__ == "__main__":
    main()
