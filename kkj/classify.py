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

# ルールベースの重要度タグ(LLM不要)。買い手AIはこのタグで自分の文脈に要約できる。
TAG_PATTERNS = {
    "price_affecting": re.compile(
        r"金額|予定価格|上限額|予算|費用に含め|見積|単価|円|価格"),
    "deadline_affecting": re.compile(
        r"締切|提出期限|入札日|開札|納入期限|履行期限|期間|日時|延長|前倒"),
    "eligibility_affecting": re.compile(
        r"資格|等級|ISO|ISMS|[Pp]マーク|プライバシーマーク|認証|実績|技術者|地域要件|参加要件"),
    "document_affecting": re.compile(
        r"様式|提出書類|仕様書|別紙|要領|添付|フォーマット"),
    "qa_related": re.compile(r"質疑|回答書|質問|Q&A|Ｑ＆Ａ"),
    "cancellation": re.compile(r"中止|取消|取り消し"),
    "postponement": re.compile(r"延期|順延"),
}

# タグ → flags/category の対応
_FLAG_OF = {
    "price_affecting": "affects_price",
    "deadline_affecting": "affects_deadline",
    "eligibility_affecting": "affects_eligibility",
    "document_affecting": "affects_documents",
}


def tag_change(field, event_type, before, after, quote=None):
    """変更テキストから重要度タグ・flags・カテゴリを機械抽出(LLM不要)"""
    blob = " ".join(str(x) for x in (field, event_type, before, after, quote) if x)
    tags = [name for name, pat in TAG_PATTERNS.items() if pat.search(blob)]
    flags = {v: False for v in ("affects_price", "affects_deadline",
                                "affects_eligibility", "affects_documents", "requires_action")}
    for t in tags:
        if t in _FLAG_OF:
            flags[_FLAG_OF[t]] = True
    material = bool(tags) or event_type in (
        "deadline_changed", "requirement_added", "requirement_removed",
        "requirement_changed", "cancellation", "postponement", "document_replaced")
    flags["requires_action"] = material
    if "cancellation" in tags:
        category = "cancellation"
    elif "price_affecting" in tags:
        category = "cost_affecting"
    elif "eligibility_affecting" in tags:
        category = "eligibility_affecting"
    elif "deadline_affecting" in tags:
        category = "schedule_affecting"
    else:
        category = "informational"
    return tags, flags, category, material


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
        tags, flags, category, material = tag_change(field, et, before, after)
        changes.append({
            "event_type": et,
            "change_category": category,
            "before": before,
            "after": after,
            "impact": _impact(field, et, before, after),   # 短い定型文(任意)
            "impact_tags": tags,                            # AI向けの主データ
            "flags": flags,
            "material": material,
            "confidence": conf,
            "confidence_basis": "explicit_values" if conf == "high" else "field_change_only",
            "source_quote": None,       # 機械分類は原文引用を持たない(LLM層が付与)
            "changed_field": field,
        })
        labels.append(FIELD_LABEL.get(field, field))
    summary = "、".join(dict.fromkeys(labels)) + " が変更されました。" if labels else "変更あり。"
    return {"summary": summary, "changes": changes, "engine": "rule",
            "material": any(c["material"] for c in changes)}
