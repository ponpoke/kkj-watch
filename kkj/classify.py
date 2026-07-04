"""機械的な変更分類(LLM不要・コストゼロ)

store.field_diff の出力(フィールド単位のbefore/after)を、買い手が読める
構造化イベント(event_type + impact + confidence + source_quote)に変換する。
LLMクレジットが無くてもコア商品(変更検知+意味のある差分)はこれで成立する。
意味づけLLMは、この機械分類の上に「高価値変更の言語化」として任意で乗せる。
"""
import re

# ポータル公告レコードのフィールド → イベント種別
FIELD_EVENT = {
    "period_end": "deadline_changed",
    "period_start": "schedule_changed",
    "cft_issue_date": "schedule_changed",
    "certification": "requirement_changed",
    "project_description": "requirement_changed",
    "project_name": "other",
    "organization_name": "other",
    "document_uri": "document_replaced",
    "file_type": "document_replaced",
    "file_size": "document_replaced",
}

FIELD_LABEL = {
    "period_end": "納入期限・履行期限",
    "period_start": "開始日",
    "cft_issue_date": "公告日",
    "certification": "入札資格",
    "project_description": "公告本文",
    "document_uri": "原典文書",
    "project_name": "件名",
}

_EXPLICIT = re.compile(
    r"\d{1,2}[月/]\d{1,2}日?|\d{1,2}[:時]\d{2}|令和\d|平成\d|\d{4}年"
    r"|[0-9,]+円|[0-9.]+[%％]|\d+[かヶケカ][月年]|\d+日間|[ABCD]等級")


def _impact(field, et, before, after):
    label = FIELD_LABEL.get(field, field)
    if et == "deadline_changed":
        return f"{label}が変更されました。提出スケジュールの再確認が必要です。"
    if et == "schedule_changed":
        return f"{label}が変更されました。"
    if et == "requirement_added":
        return f"{label}に要件が追加されました。参加可否・見積に影響する可能性があります。"
    if et == "requirement_removed":
        return f"{label}の要件が削除されました。参加可能な事業者の範囲が変わる可能性があります。"
    if et == "requirement_changed":
        return f"{label}が変更されました。参加可否・見積に影響する可能性があります。"
    if et == "document_replaced":
        return "原典文書が差し替えられました。最新の様式・仕様を確認してください。"
    return f"{label}が変更されました。"


def machine_analysis(diff: dict) -> dict:
    """field_diff({field:{before,after}}) → 構造化analysis(engine=rule)"""
    changes = []
    labels = []
    for field, ba in diff.items():
        before, after = ba.get("before"), ba.get("after")
        et = FIELD_EVENT.get(field, "other")
        if et == "requirement_changed" and (before in (None, "")) != (after in (None, "")):
            et = "requirement_added" if before in (None, "") else "requirement_removed"
        blob = f"{before} {after}"
        conf = "high" if _EXPLICIT.search(blob) else "medium"
        changes.append({
            "event_type": et,
            "before": before,
            "after": after,
            "impact": _impact(field, et, before, after),
            "confidence": conf,
            "confidence_basis": "explicit_values" if conf == "high" else "field_change_only",
            "source_quote": None,       # 機械分類は原文引用を持たない(LLM層が付与)
            "changed_field": field,
        })
        labels.append(FIELD_LABEL.get(field, field))
    summary = "、".join(dict.fromkeys(labels)) + " が変更されました。" if labels else "変更あり。"
    return {"summary": summary, "changes": changes, "engine": "rule"}
