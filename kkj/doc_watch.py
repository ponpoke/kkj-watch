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


def _assert_public_host(url: str):
    """SSRF対策: 解決先がプライベート/リンクローカル/ループバックなら拒否"""
    import ipaddress
    import socket
    host = urllib.parse.urlsplit(url).hostname or ""
    for info in socket.getaddrinfo(host, None):
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ValueError(f"non-public address: {ip}")


def fetch_hash(url: str):
    """SHA-256と、可能ならPDF抽出テキスト(内部版管理用)を返す"""
    _assert_public_host(url)
    req = urllib.request.Request(url, headers={"User-Agent": config.USER_AGENT})
    h = hashlib.sha256()
    size = 0
    buf = bytearray()
    with urllib.request.urlopen(req, timeout=config.DOC_FETCH_TIMEOUT) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
            if size <= 15 * 1024 * 1024:  # テキスト抽出は15MBまで
                buf.extend(chunk)
            if size > 50 * 1024 * 1024:  # 50MB上限
                raise ValueError("too large")
    return h.hexdigest(), size, extract_text(bytes(buf))


def extract_text(data: bytes):
    """PDFなら本文テキストを抽出(pypdf未導入・非PDFはNone)"""
    if not data.startswith(b"%PDF"):
        return None
    try:
        import io
        from pypdf import PdfReader
        reader = PdfReader(io.BytesIO(data))
        parts = []
        total = 0
        for page in reader.pages[:80]:
            t = page.extract_text() or ""
            parts.append(t)
            total += len(t)
            if total > 200_000:
                break
        text = "\n".join(parts).strip()
        return text or None
    except Exception:
        return None


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
            old = conn.execute(
                "SELECT text FROM documents WHERE case_key=? AND url=? AND status='ok' ORDER BY id DESC LIMIT 1",
                (r["key"], url)).fetchone()
            sha, size, text = fetch_hash(url)
            ev = store.record_document(conn, r["key"], url, sha, size, "ok", text)
            if ev == "DOC_CHANGED":
                changed += 1
                print(f"[DOC_CHANGED] {url}")
                _analyze_doc_diff(conn, r["key"], url,
                                  old["text"] if old else None, text)
        except Exception as e:
            store.record_document(conn, r["key"], url, None, None, f"error:{type(e).__name__}")
        conn.commit()
        time.sleep(config.DOC_FETCH_DELAY_SEC)

    print(f"docs polled: {len(rows)}, changed: {changed}")
    conn.close()


def _analyze_doc_diff(conn, case_key, url, old_text, new_text):
    """PDF差替えの新旧本文を意味差分(両版のテキスト+LLMクレジットがある場合のみ)"""
    import os
    from . import semantic
    if not (old_text and new_text and semantic.available()
            and os.environ.get("KKJ_DOC_LLM") == "1"):
        return  # コスト制御: 既定はLLMを使わず、DOC_CHANGEDの事実検知まで
    try:
        import json as _json
        rec = _json.loads(conn.execute(
            "SELECT latest_json FROM cases WHERE key=?", (case_key,)).fetchone()["latest_json"])
        analysis = semantic.analyze_pair(
            rec.get("project_name", ""), old_text, new_text, "原典文書(PDF)の差替え",
            provenance={"source_kind": "原典文書(PDF)", "source_url": url,
                        "original_key": case_key})
        ev = conn.execute(
            "SELECT id FROM events WHERE case_key=? AND event_type='DOC_CHANGED' ORDER BY id DESC LIMIT 1",
            (case_key,)).fetchone()
        semantic.save(conn, case_key, ev["id"] if ev else None, "doc_diff", analysis)
        print(f"  doc_diff: {analysis.get('summary', '')[:60]}")
    except Exception as e:
        print(f"  [warn] doc_diff analysis failed: {e}")


if __name__ == "__main__":
    poll_docs()
