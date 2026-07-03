"""原典文書ウォッチ: ExternalDocumentURI を低頻度巡回しハッシュ比較で差替え検知

原文は再配布しない(法的設計)。保存するのはハッシュ+取得時刻+サイズのみ。
robots.txt を確認し、拒否されたホストはスキップする。
"""
import hashlib
import time
import urllib.parse
import urllib.request
import urllib.robotparser

from . import config, store

_robots_cache = {}


def allowed_by_robots(url: str) -> bool:
    host = urllib.parse.urlsplit(url)
    base = f"{host.scheme}://{host.netloc}"
    rp = _robots_cache.get(base)
    if rp is None:
        rp = urllib.robotparser.RobotFileParser()
        try:
            rp.set_url(base + "/robots.txt")
            rp.read()
        except Exception:
            rp = None  # robots.txt取得不能 → 許可扱い(存在しないサイトが多数)
        _robots_cache[base] = rp
    if rp is None:
        return True
    try:
        return rp.can_fetch(config.USER_AGENT, url)
    except Exception:
        return True


def fetch_hash(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
    h = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(req, timeout=config.DOC_FETCH_TIMEOUT) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            if size > 50 * 1024 * 1024:  # 50MB上限
                raise ValueError("too large")
    return h.hexdigest(), size


def poll_docs(limit=None):
    """未取得または最も古い文書から順に巡回"""
    limit = limit or config.DOC_FETCH_MAX_PER_RUN
    conn = store.connect()
    # 優先順位: ①未取得 ②締切が14日以内(差替えの実害が最大の層) ③最も古く取得したもの
    rows = conn.execute(
        """SELECT c.key, json_extract(c.latest_json,'$.document_uri') AS url,
                  (SELECT MAX(fetched_at) FROM documents d WHERE d.case_key=c.key) AS last_fetch,
                  substr(coalesce(json_extract(c.latest_json,'$.period_end'),''),1,10) AS deadline
           FROM cases c
           WHERE json_extract(c.latest_json,'$.document_uri') IS NOT NULL
           ORDER BY (last_fetch IS NOT NULL),
                    CASE WHEN deadline >= date('now') AND deadline <= date('now','+14 day')
                         THEN 0 ELSE 1 END,
                    last_fetch ASC
           LIMIT ?""",
        (limit,),
    ).fetchall()

    changed = 0
    for r in rows:
        url = r["url"]
        if not url.lower().startswith(("http://", "https://")):
            store.record_document(conn, r["key"], url, None, None, "error:bad_scheme")
            conn.commit()
            continue
        if not allowed_by_robots(url):
            store.record_document(conn, r["key"], url, None, None, "error:robots_disallow")
            conn.commit()
            continue
        try:
            sha, size = fetch_hash(url)
            ev = store.record_document(conn, r["key"], url, sha, size, "ok")
            if ev == "DOC_CHANGED":
                changed += 1
                print(f"[DOC_CHANGED] {url}")
        except Exception as e:
            store.record_document(conn, r["key"], url, None, None, f"error:{type(e).__name__}")
        conn.commit()
        time.sleep(config.DOC_FETCH_DELAY_SEC)

    print(f"docs polled: {len(rows)}, changed: {changed}")
    conn.close()


if __name__ == "__main__":
    poll_docs()
