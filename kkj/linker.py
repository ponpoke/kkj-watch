"""訂正公告→元公告の紐付けと意味差分

「【訂正公告】○○業務」のような別建て公告を、同一機関+タイトル核の照合で
元公告に紐付け、CORRECTION_NOTICEイベント+両本文の意味差分を生成する。
"""
import difflib
import json
import re

from . import semantic, store

MARKERS = ("訂正", "変更", "延期", "中止", "取消", "再公告")
_BRACKETS = re.compile(r"[【\[(（].{0,12}?[】\])）]")
_NOISE = re.compile(r"[\s　・:：、。「」()（）\[\]【】]")


def title_core(title: str) -> str:
    """タイトルからマーカー語・括弧書き・記号を除いた核を得る"""
    t = _BRACKETS.sub("", title or "")
    for m in MARKERS + ("公告", "について", "に係る", "の"):
        t = t.replace(m, "")
    return _NOISE.sub("", t)


def is_correction_title(title: str) -> bool:
    head = (title or "")[:20]
    return any(m in head for m in MARKERS)


def find_original(conn, correction):
    """同一機関で、タイトル核が最も類似する先行案件を探す"""
    rec = json.loads(correction["latest_json"])
    org = rec.get("organization_name")
    core = title_core(rec.get("project_name", ""))
    if not org or len(core) < 6:
        return None
    best, best_score = None, 0.0
    for cand in conn.execute(
        """SELECT key, latest_json, first_seen FROM cases
           WHERE key != ? AND json_extract(latest_json,'$.organization_name') = ?""",
        (correction["key"], org)).fetchall():
        crec = json.loads(cand["latest_json"])
        ctitle = crec.get("project_name", "")
        if is_correction_title(ctitle):
            continue
        ccore = title_core(ctitle)
        if not ccore:
            continue
        if ccore in core or core in ccore:
            score = 1.0
        else:
            score = difflib.SequenceMatcher(None, core, ccore).ratio()
        if score > best_score:
            best, best_score = cand, score
    return best if best_score >= 0.75 else None


def link_corrections(limit=30, analyze=True):
    """未紐付けの訂正系公告を元公告へリンクし、意味差分を生成"""
    conn = store.connect()
    conn.executescript(semantic.SCHEMA_SQL)
    rows = conn.execute(
        """SELECT key, latest_json FROM cases c
           WHERE NOT EXISTS (SELECT 1 FROM events e
                             WHERE e.event_type='CORRECTION_LINKED' AND e.case_key=c.key)
           ORDER BY first_seen DESC LIMIT 500""").fetchall()
    linked = 0
    for r in rows:
        rec = json.loads(r["latest_json"])
        title = rec.get("project_name", "")
        if not is_correction_title(title):
            continue
        orig = find_original(conn, r)
        if orig is None:
            continue
        orec = json.loads(orig["latest_json"])
        ts = store.now_utc()
        detail = {"correction_key": r["key"], "correction_title": title,
                  "original_key": orig["key"], "original_title": orec.get("project_name")}
        # 元公告側にイベント(ウォッチ・フィードで拾われる)
        conn.execute(
            "INSERT INTO events(case_key, event_type, detected_at, detail_json) VALUES (?,?,?,?)",
            (orig["key"], "CORRECTION_NOTICE", ts, json.dumps(detail, ensure_ascii=False)))
        # 訂正公告側に紐付け済みマーク
        conn.execute(
            "INSERT INTO events(case_key, event_type, detected_at, detail_json) VALUES (?,?,?,?)",
            (r["key"], "CORRECTION_LINKED", ts, json.dumps(detail, ensure_ascii=False)))
        conn.commit()
        linked += 1
        print(f"linked: {title[:40]} -> {orec.get('project_name','')[:40]}")
        if analyze and semantic.available():
            try:
                analysis = semantic.analyze_pair(
                    orec.get("project_name", ""),
                    orec.get("project_description") or orec.get("project_name", ""),
                    rec.get("project_description") or title,
                    "訂正・変更公告(元公告との比較)")
                ev_id = conn.execute(
                    "SELECT id FROM events WHERE case_key=? AND event_type='CORRECTION_NOTICE' ORDER BY id DESC LIMIT 1",
                    (orig["key"],)).fetchone()[0]
                semantic.save(conn, orig["key"], ev_id, "correction_notice", analysis)
                conn.commit()
                print(f"  analysis: {analysis.get('summary','')[:60]}")
            except Exception as e:
                print(f"  [warn] semantic failed: {e}")
        if linked >= limit:
            break
    conn.close()
    print(f"linker: linked {linked}")
