"""変更の意味づけ層: before/after を分類・影響・確度付きの構造化イベントにする

買い手が意思決定できる形:
{"event_type": "deadline_changed", "before": "...", "after": "...",
 "impact": "提案書提出期限が7日延長", "confidence": "high", ...}
"""
import json
import os
import urllib.request

from . import config, store

API_URL = "https://api.anthropic.com/v1/messages"

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "変更全体の一行要約(日本語)"},
        "changes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "event_type": {
                        "type": "string",
                        "enum": ["deadline_changed", "requirement_added", "requirement_removed",
                                 "requirement_changed", "document_replaced", "scope_changed",
                                 "schedule_changed", "cancellation", "postponement", "other"],
                    },
                    "before": {"type": ["string", "null"], "description": "変更前の値(原文ベース)。新規追加ならnull"},
                    "after": {"type": ["string", "null"], "description": "変更後の値(原文ベース)。削除ならnull"},
                    "impact": {"type": "string", "description": "入札参加者への影響の一行説明(日本語)"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"],
                                   "description": "原文から直接確認できる=high、推測を含む=medium/low"},
                    "source_quote": {"type": ["string", "null"],
                                     "description": "この変更の根拠となる原文の一節をそのまま引用(要約禁止)。原文に該当箇所がなければnull"},
                },
                "required": ["event_type", "before", "after", "impact", "confidence", "source_quote"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "changes"],
    "additionalProperties": False,
}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS change_analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_key TEXT NOT NULL,
    event_id INTEGER,                  -- eventsテーブルの対象行(紐付け解析はNULL可)
    kind TEXT NOT NULL,                -- field_diff / correction_notice / doc_diff
    analysis_json TEXT NOT NULL,
    model TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_case ON change_analyses(case_key);
CREATE INDEX IF NOT EXISTS idx_analyses_event ON change_analyses(event_id);
"""


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def _llm(prompt: str) -> dict:
    body = {
        "model": config.EXTRACT_MODEL,
        "max_tokens": 2048,
        "output_config": {"format": {"type": "json_schema", "schema": ANALYSIS_SCHEMA}},
        "messages": [{"role": "user", "content": prompt[:24000]}],
    }
    req = urllib.request.Request(
        API_URL, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "x-api-key": os.environ["ANTHROPIC_API_KEY"],
                 "anthropic-version": "2023-06-01"},
        method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return json.loads(next(b["text"] for b in data["content"] if b["type"] == "text"))


import re

# 機械的confidence基準: 明示的な値(日時・金額・数量・資格)が原文引用に含まれるか
_EXPLICIT = re.compile(
    r"\d{1,2}[月/]\d{1,2}日?|\d{1,2}[:時]\d{2}|令和\d|平成\d|\d{4}年"
    r"|[0-9,]+円|[0-9.]+[%％]|\d+[かヶケカ][月年]|\d+日間"
    r"|ISO ?\d+|ISMS|Pマーク|プライバシーマーク|[ABCD]等級|等級|統一資格")


def harden_confidence(analysis: dict) -> dict:
    """LLM自己評価に機械的基準を重ねる:
    - source_quoteなし → 最大medium(根拠文で裏取りできない)
    - 引用+before/afterに明示的な値なし → 最大medium(意味推定のみ)
    """
    for ch in analysis.get("changes", []):
        # 引用は根拠確認に足る最小限へ(著作権・再配布面の配慮で400字上限)
        if ch.get("source_quote") and len(ch["source_quote"]) > 400:
            ch["source_quote"] = ch["source_quote"][:400] + "…"
        quote = ch.get("source_quote") or ""
        blob = " ".join(str(ch.get(k) or "") for k in ("before", "after")) + " " + quote
        explicit = bool(_EXPLICIT.search(blob))
        if not quote:
            ch["confidence_basis"] = "no_source_quote"
            if ch.get("confidence") == "high":
                ch["confidence"] = "medium"
        elif explicit:
            ch["confidence_basis"] = "explicit_values_in_quote"
        else:
            ch["confidence_basis"] = "semantic_only"
            if ch.get("confidence") == "high":
                ch["confidence"] = "medium"
    return analysis


def analyze_pair(title: str, before_text: str, after_text: str, source: str,
                 provenance: dict | None = None) -> dict:
    """新旧テキストの意味差分(訂正公告・文書差替え・本文変更 共通)

    provenance: {"source_kind","source_url","original_key","correction_key"} 等を
    そのまま結果に添付(LLM出力ではなくシステムが保証するメタデータ)
    """
    analysis = _llm(
        "以下は日本の官公需(入札)案件の変更前後の内容です。入札参加者にとって意味のある変更を"
        "分類して抽出してください。原文にない情報は捏造せず、確認できないものはconfidenceを下げてください。"
        "source_quoteには根拠となる原文の一節をそのまま引用してください(言い換え禁止)。\n"
        f"案件名: {title}\n情報源: {source}\n\n"
        f"=== 変更前 ===\n{before_text[:10000]}\n\n=== 変更後 ===\n{after_text[:10000]}"
    )
    analysis = harden_confidence(analysis)
    if provenance:
        analysis["source"] = provenance
    return analysis


def save(conn, case_key, event_id, kind, analysis):
    conn.executescript(SCHEMA_SQL)
    conn.execute(
        "INSERT INTO change_analyses(case_key, event_id, kind, analysis_json, model, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (case_key, event_id, kind, json.dumps(analysis, ensure_ascii=False),
         config.EXTRACT_MODEL, store.now_utc()))


def analyze_pending_field_events(limit=20):
    """未解析のFIELD_CHANGEDイベントを意味づけ(スナップショットの新旧レコードを比較)"""
    if not available():
        print("ANTHROPIC_API_KEY未設定のためanalyzeはスキップ")
        return
    conn = store.connect()
    conn.executescript(SCHEMA_SQL)
    rows = conn.execute(
        """SELECT e.id, e.case_key, e.detected_at,
                  json_extract(c.latest_json,'$.project_name') AS title
           FROM events e JOIN cases c ON c.key=e.case_key
           WHERE e.event_type='FIELD_CHANGED'
             AND NOT EXISTS (SELECT 1 FROM change_analyses a WHERE a.event_id=e.id)
           ORDER BY e.id DESC LIMIT ?""", (limit,)).fetchall()
    done = 0
    for r in rows:
        snaps = conn.execute(
            "SELECT raw_json FROM snapshots WHERE case_key=? AND fetched_at<=? ORDER BY id DESC LIMIT 2",
            (r["case_key"], r["detected_at"])).fetchall()
        if len(snaps) < 2:
            continue
        after_rec, before_rec = json.loads(snaps[0]["raw_json"]), json.loads(snaps[1]["raw_json"])
        fmt = lambda d: "\n".join(f"{k}: {v}" for k, v in sorted(d.items()))
        try:
            analysis = analyze_pair(
                r["title"] or "", fmt(before_rec), fmt(after_rec), "官公需ポータル公告レコード",
                provenance={"source_kind": "公告レコード(ポータル)",
                            "source_url": after_rec.get("document_uri"),
                            "original_key": r["case_key"]})
            save(conn, r["case_key"], r["id"], "field_diff", analysis)
            conn.commit()
            done += 1
            print(f"analyzed event {r['id']}: {analysis.get('summary','')[:60]}")
        except Exception as e:
            print(f"[warn] analyze failed for event {r['id']}: {e}")
    conn.close()
    print(f"semantic: analyzed {done}/{len(rows)}")
