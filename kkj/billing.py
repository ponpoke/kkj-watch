"""課金レイヤー: APIキー発行・検証・従量メータリング

  python -m kkj.pipeline key-issue <名前> [plan]   # plan: free / metered / monthly
  python -m kkj.pipeline key-list
  python -m kkj.pipeline usage-report              # キー別の当月利用量(請求の元データ)
"""
import secrets

from . import store

SCHEMA = """
CREATE TABLE IF NOT EXISTS apikeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'free',   -- free / metered(従量) / monthly(月額)
    created_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
"""

# 無償ティアの1日あたりリクエスト上限(IP単位)。キー保有者は無制限(メータリング課金)
FREE_DAILY_LIMIT = 200

# 従量単価(円): 構造化(get_requirements/extraction) 1件あたり
PRICE_PER_EXTRACTION = 30
# その他のAPI呼び出し 1リクエストあたり
PRICE_PER_REQUEST = 1


def connect():
    conn = store.connect()
    conn.executescript(SCHEMA)
    return conn


def issue(name: str, plan: str = "metered") -> str:
    key = "kkjw_" + secrets.token_urlsafe(24)
    conn = connect()
    conn.execute(
        "INSERT INTO apikeys(key, name, plan, created_at) VALUES (?,?,?,?)",
        (key, name, plan, store.now_utc()),
    )
    conn.commit()
    conn.close()
    return key


def list_keys():
    conn = connect()
    for r in conn.execute("SELECT * FROM apikeys ORDER BY id").fetchall():
        state = "REVOKED" if r["revoked"] else "active"
        print(f"[{r['id']}] {r['name']} plan={r['plan']} {state} key={r['key'][:12]}...")
    conn.close()


def check(conn, key: str):
    """有効なキーならレコードを返す"""
    if not key:
        return None
    conn.executescript(SCHEMA)
    return conn.execute(
        "SELECT * FROM apikeys WHERE key=? AND revoked=0", (key,)
    ).fetchone()


def over_free_limit(conn, client_ip: str) -> bool:
    n = conn.execute(
        "SELECT COUNT(*) n FROM usage_log WHERE client=? AND at >= date('now')",
        (client_ip,),
    ).fetchone()["n"]
    return n > FREE_DAILY_LIMIT


def usage_report():
    """キー別の当月利用量と概算請求額(手動請求の元データ)"""
    conn = connect()
    rows = conn.execute(
        """SELECT client, COUNT(*) AS requests,
                  SUM(CASE WHEN path LIKE '%extract%' OR path LIKE '%requirements%' THEN 1 ELSE 0 END) AS extractions
           FROM usage_log
           WHERE client LIKE 'key:%' AND at >= date('now','start of month')
           GROUP BY client ORDER BY requests DESC"""
    ).fetchall()
    if not rows:
        print("当月のキー付き利用なし")
    for r in rows:
        amount = r["extractions"] * PRICE_PER_EXTRACTION + (r["requests"] - r["extractions"]) * PRICE_PER_REQUEST
        print(f"{r['client']}: requests={r['requests']}, extractions={r['extractions']}, 概算¥{amount:,}")
    conn.close()
