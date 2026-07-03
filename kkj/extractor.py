"""要件構造化(Extract): 公告テキストから応募要件をJSON抽出。

Claude Haiku 4.5 を Messages API (raw HTTP, urllib) で呼ぶ。
pipインストール不可の環境のためSDKではなく標準ライブラリで実装。
ANTHROPIC_API_KEY が未設定なら no-op。
"""
import json
import os
import urllib.request

from . import config, store

API_URL = "https://api.anthropic.com/v1/messages"

# 「この案件にうちは応募資格があるか」に1コールで答えられる形式
EXTRACT_SCHEMA = {
    "type": "object",
    "properties": {
        "qualifications": {
            "type": "array",
            "items": {"type": "string"},
            "description": "応募資格・参加資格の要件一覧(全省庁統一資格の等級・地域要件を含む)",
        },
        "unified_qualification_rank": {
            "type": ["string", "null"],
            "description": "全省庁統一資格の等級要件(例: 'A,B,C' )。なければnull",
        },
        "required_certifications": {
            "type": "array",
            "items": {"type": "string"},
            "description": "必須認証(ISO27001, ISMS, プライバシーマーク等)",
        },
        "required_documents": {
            "type": "array",
            "items": {"type": "string"},
            "description": "提出書類一覧",
        },
        "performance_period": {
            "type": ["string", "null"],
            "description": "履行期間(原文表記のまま)",
        },
        "deadlines": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "label": {"type": "string", "description": "何の期限か(入札書提出、質問受付等)"},
                    "value": {"type": "string", "description": "日時(原文表記)"},
                },
                "required": ["label", "value"],
                "additionalProperties": False,
            },
        },
        "contact": {"type": ["string", "null"], "description": "問い合わせ先"},
        "bid_method": {"type": ["string", "null"], "description": "入札方式(一般競争入札等)"},
    },
    "required": [
        "qualifications", "unified_qualification_rank", "required_certifications",
        "required_documents", "performance_period", "deadlines", "contact", "bid_method",
    ],
    "additionalProperties": False,
}


def available() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def extract(text: str) -> dict:
    """公告テキストを構造化JSONにする(Haiku 4.5, structured outputs)"""
    body = {
        "model": config.EXTRACT_MODEL,
        "max_tokens": config.EXTRACT_MAX_TOKENS,
        "output_config": {"format": {"type": "json_schema", "schema": EXTRACT_SCHEMA}},
        "messages": [
            {
                "role": "user",
                "content": (
                    "以下は日本の官公需(入札)公告の本文です。応募要件を抽出してください。"
                    "原文にない情報は捏造せず、該当なしはnullまたは空配列にしてください。\n\n"
                    + text[:12000]
                ),
            }
        ],
    }
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "x-api-key": os.environ["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    text_block = next(b["text"] for b in data["content"] if b["type"] == "text")
    return json.loads(text_block)


def extract_case(conn, case_key: str, force=False):
    """案件のProjectDescriptionを構造化して保存"""
    if not available():
        return None
    if not force:
        done = conn.execute("SELECT 1 FROM extractions WHERE case_key=?", (case_key,)).fetchone()
        if done:
            return None
    row = conn.execute("SELECT latest_json FROM cases WHERE key=?", (case_key,)).fetchone()
    if row is None:
        return None
    rec = json.loads(row["latest_json"])
    text = rec.get("project_description") or rec.get("project_name")
    if not text:
        return None
    result = extract(text)
    conn.execute(
        "INSERT OR REPLACE INTO extractions(case_key, extracted_at, model, result_json) VALUES (?,?,?,?)",
        (case_key, store.now_utc(), config.EXTRACT_MODEL, json.dumps(result, ensure_ascii=False)),
    )
    return result
