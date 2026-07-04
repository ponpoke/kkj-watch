"""LLM予算ガード + 結果キャッシュ

- 同一入力(before+after+prompt_version+model)は二度とLLMを呼ばない(キャッシュ)
- 日次/時間あたりの呼び出し上限、日次USD予算上限
- 上限超過・キー無し・残高不足時は呼ばず pending を返す(巡回・保存は止めない)
"""
import hashlib
import json
import os

from . import store

PROMPT_VERSION = "v1"

# 環境変数で上書き可(売上が出るまで絞る)
DEFAULTS = {
    "LLM_MAX_CALLS_PER_HOUR": 20,
    "LLM_MAX_CALLS_PER_DAY": 200,
    "LLM_DAILY_BUDGET_USD": 1.00,
    "LLM_MONTHLY_BUDGET_USD": 5.00,   # 月次ハードストップ($5超で全LLM停止)
}
# Haiku 4.5 概算: 入力~3.5Ktok*$1 + 出力~0.6Ktok*$5 ≈ $0.0065/コール
EST_COST_PER_CALL_USD = 0.0065

SCHEMA = """
CREATE TABLE IF NOT EXISTS llm_cache (
    cache_key TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS llm_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    cache_key TEXT,
    hit INTEGER NOT NULL      -- 1=cache hit(課金なし) / 0=実API呼び出し
);
"""


def _limit(name):
    try:
        return type(DEFAULTS[name])(os.environ.get(name, DEFAULTS[name]))
    except (ValueError, TypeError):
        return DEFAULTS[name]


def cache_key(before_text, after_text, model):
    h = hashlib.sha256()
    h.update(f"{PROMPT_VERSION}\0{model}\0{before_text}\0{after_text}".encode("utf-8"))
    return h.hexdigest()


def _ensure(conn):
    conn.executescript(SCHEMA)


def cache_get(conn, key):
    _ensure(conn)
    row = conn.execute("SELECT result_json FROM llm_cache WHERE cache_key=?", (key,)).fetchone()
    if row:
        conn.execute("INSERT INTO llm_calls(at, cache_key, hit) VALUES (?,?,1)",
                     (store.now_utc(), key))
        conn.commit()
        return json.loads(row["result_json"])
    return None


def cache_put(conn, key, result):
    _ensure(conn)
    conn.execute("INSERT OR REPLACE INTO llm_cache(cache_key, result_json, created_at) VALUES (?,?,?)",
                 (key, json.dumps(result, ensure_ascii=False), store.now_utc()))
    conn.commit()


def can_spend(conn):
    """予算内でLLMを呼べるか。戻り値: (bool, 理由)"""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False, "no_api_key"
    _ensure(conn)
    hour = conn.execute(
        "SELECT COUNT(*) n FROM llm_calls WHERE hit=0 AND at >= datetime('now','-1 hour')").fetchone()["n"]
    if hour >= _limit("LLM_MAX_CALLS_PER_HOUR"):
        return False, "hourly_limit"
    day = conn.execute(
        "SELECT COUNT(*) n FROM llm_calls WHERE hit=0 AND at >= date('now')").fetchone()["n"]
    if day >= _limit("LLM_MAX_CALLS_PER_DAY"):
        return False, "daily_limit"
    if day * EST_COST_PER_CALL_USD >= _limit("LLM_DAILY_BUDGET_USD"):
        return False, "daily_budget"
    month = conn.execute(
        "SELECT COUNT(*) n FROM llm_calls WHERE hit=0 AND at >= date('now','start of month')").fetchone()["n"]
    if month * EST_COST_PER_CALL_USD >= _limit("LLM_MONTHLY_BUDGET_USD"):
        return False, "monthly_budget"   # ハードストップ
    return True, "ok"


def record_call(conn, key):
    _ensure(conn)
    conn.execute("INSERT INTO llm_calls(at, cache_key, hit) VALUES (?,?,0)", (store.now_utc(), key))
    conn.commit()


def stats(conn):
    _ensure(conn)
    day_calls = conn.execute(
        "SELECT COUNT(*) n FROM llm_calls WHERE hit=0 AND at >= date('now')").fetchone()["n"]
    hits = conn.execute(
        "SELECT COUNT(*) n FROM llm_calls WHERE hit=1 AND at >= date('now')").fetchone()["n"]
    month_calls = conn.execute(
        "SELECT COUNT(*) n FROM llm_calls WHERE hit=0 AND at >= date('now','start of month')").fetchone()["n"]
    total = day_calls + hits
    ok, reason = can_spend(conn)
    return {
        "llm_calls_today": day_calls,
        "cache_hits_today": hits,
        "cache_hit_rate": round(hits / total, 3) if total else None,
        "est_cost_today_usd": round(day_calls * EST_COST_PER_CALL_USD, 4),
        "est_cost_month_usd": round(month_calls * EST_COST_PER_CALL_USD, 4),
        "daily_call_limit": _limit("LLM_MAX_CALLS_PER_DAY"),
        "daily_budget_usd": _limit("LLM_DAILY_BUDGET_USD"),
        "monthly_budget_usd": _limit("LLM_MONTHLY_BUDGET_USD"),
        "can_spend": ok,
        "block_reason": None if ok else reason,
    }
