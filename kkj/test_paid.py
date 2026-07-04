"""paid-but-denied 防止のテスト:  python -m kkj.test_paid

一時DBで実サーバを起動し、支払い前の判定(402を出すべきでない場面)を検証する。
外部ファシリテータには依存しない(支払い前の分岐のみを対象)。
"""
import json
import os
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import config

_tmp = Path(tempfile.mkdtemp(prefix="kkj_test_paid_"))
config.DATA_DIR = _tmp
config.DB_PATH = _tmp / "test.db"

from . import store, paid  # noqa: E402
from http.server import ThreadingHTTPServer  # noqa: E402
from . import server as srv  # noqa: E402

FAILED = []


def check(name, cond, extra=""):
    print(("ok  " if cond else "FAIL") + f" {name} {extra}")
    if not cond:
        FAILED.append(name)


def get(port, path, headers=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


def main():
    # 準備: 案件を1件(未抽出)と、抽出済み1件を作る
    conn = store.connect()
    store.upsert_case(conn, {"key": "UNEXTRACTED", "project_name": "未抽出テスト案件",
                             "project_description": "システム開発業務", "period_end": "2026-09-01",
                             "fetched_by_portal_at": "2026-07-04T00:00:00"})
    store.upsert_case(conn, {"key": "EXTRACTED", "project_name": "抽出済みテスト案件",
                             "project_description": "保守業務", "period_end": "2026-09-01",
                             "fetched_by_portal_at": "2026-07-04T00:00:00"})
    conn.execute("INSERT INTO extractions(case_key, extracted_at, model, result_json) VALUES (?,?,?,?)",
                 ("EXTRACTED", store.now_utc(), "test", json.dumps({"qualifications": ["A"]})))
    conn.commit()
    conn.close()

    # x402 を有効化(支払い先ダミー)。テストは支払い前の分岐のみ検証
    os.environ["X402_PAY_TO"] = "0x1111111111111111111111111111111111111111"
    os.environ["X402_NETWORK"] = "base-sepolia"

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), srv.Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    time.sleep(0.3)

    # 要件1: cache miss では 402 を返さない(409 cache_not_available)
    st, body = get(port, "/paid/requirements/UNEXTRACTED")
    check("cache-miss は 402 を返さない", st == 409 and body.get("error") == "cache_not_available",
          f"(got {st})")

    # 対照: 抽出済みなら 402(支払い要求)
    st, body = get(port, "/paid/requirements/EXTRACTED")
    check("抽出済みは 402(支払い要求)", st == 402 and "accepts" in body, f"(got {st})")

    # 存在しない案件は 404(支払い要求なし)
    st, body = get(port, "/paid/requirements/NOSUCHKEY")
    check("存在しない案件は 404", st == 404, f"(got {st})")

    # 要件2,3: LLM不可(APIキー無し)では analyze-now が 402 を返さない(503)
    os.environ.pop("ANTHROPIC_API_KEY", None)
    st, body = get(port, "/paid/analyze-now/UNEXTRACTED")
    check("LLM不可時は支払い要求を出さない(503)", st == 503 and body.get("error") == "llm_unavailable",
          f"(got {st})")

    # 要件2,3: 予算超過では 402 を返さない(429)。APIキーはダミーで有効化
    os.environ["ANTHROPIC_API_KEY"] = "sk-ant-dummy"
    os.environ["LLM_MONTHLY_BUDGET_USD"] = "0"
    st, body = get(port, "/paid/analyze-now/UNEXTRACTED")
    check("予算超過時は支払い要求を出さない(429)", st == 429 and body.get("error") == "budget_exceeded",
          f"(got {st})")
    os.environ["LLM_MONTHLY_BUDGET_USD"] = "5"

    # 要件1,5: 解析済み案件でも analyze-now を未払いで叩くと requirements 本体を返さない(課金バイパス防止)
    st, body = get(port, "/paid/analyze-now/EXTRACTED")
    check("解析済みでも未払いなら requirements を返さない(課金バイパス防止)",
          st == 409 and body.get("error") == "already_analyzed" and "requirements" not in body,
          f"(got {st}, keys={list(body)})")

    # 要件2: 解析済みは /paid/requirements へ誘導される
    check("解析済みは /paid/requirements へ誘導", "requirements_url" in body)

    # 要件3: 無効な retry_token は結果を返さない(403)
    st, body = get(port, "/paid/analyze-now/EXTRACTED?retry_token=bogus")
    check("無効な retry_token は結果を返さない(403)",
          st == 403 and "requirements" not in body, f"(got {st})")

    # 要件3: 支払い済みの有効な retry_token(case_key一致)は再課金なしで結果を返す
    c2 = store.connect()
    j, _ = paid.claim(c2, paid.payment_hash("PAY_E2E"),
                      "https://any/paid/analyze-now/EXTRACTED", "EXTRACTED", "s")
    paid.finish(c2, j["retry_token"], "succeeded", {"qualifications": ["Z"]})
    c2.close()
    st, body = get(port, "/paid/analyze-now/EXTRACTED?retry_token=" + j["retry_token"])
    check("有効な retry_token は再課金なしで結果を返す(ホスト非依存)",
          st == 200 and body.get("cached") is True
          and body.get("requirements", {}).get("qualifications") == ["Z"], f"(got {st})")
    # 別case_keyのtokenは拒否(トークン横流し防止)
    st, body = get(port, "/paid/analyze-now/UNEXTRACTED?retry_token=" + j["retry_token"])
    check("別case_keyへのtoken使用は403", st == 403, f"(got {st})")

    httpd.shutdown()

    # 要件5: 同一支払いの別resource再利用を拒否
    conn = store.connect()
    ph = paid.payment_hash("PAYMENT_X")
    job, err = paid.claim(conn, ph, "https://h/paid/analyze-now/A", "A", "settle1")
    check("初回 claim は成功", err is None and job is not None)
    _, err2 = paid.claim(conn, ph, "https://h/paid/analyze-now/B", "B", "settle1")
    check("同一支払いの別resource再利用を拒否", err2 == "payment_reused")
    job_same, err3 = paid.claim(conn, ph, "https://h/paid/analyze-now/A", "A", "settle1")
    check("同一支払い・同一resourceの再取得は許可", err3 is None and job_same["retry_token"] == job["retry_token"])
    # 点3: get_by_payment で同一支払いの既存ジョブを引ける(再settle回避)
    found = paid.get_by_payment(conn, ph)
    check("get_by_payment: 同一支払いの既存ジョブを引ける",
          found is not None and found["retry_token"] == job["retry_token"])

    # 要件4: 支払い後失敗 → retry_token で再取得(再支払い不要)
    paid.finish(conn, job["retry_token"], "pending", error="429 rate limit")
    fetched = paid.get(conn, job["retry_token"])
    check("失敗ジョブは pending として保存される", fetched["status"] == "pending")
    paid.finish(conn, job["retry_token"], "succeeded", {"qualifications": ["X"]})
    done = paid.get(conn, job["retry_token"])
    check("retry_without_repayment: 再実行で succeeded + 結果取得",
          done["status"] == "succeeded" and json.loads(done["result_json"])["qualifications"] == ["X"])

    # 要件4: /paid/job は pending の間は requirements 本体を返さない
    ph2 = paid.payment_hash("PAYMENT_Y")
    pending_job, _ = paid.claim(conn, ph2, "https://h/paid/analyze-now/C", "C", "settle2")
    check("新規ジョブは pending", pending_job["status"] == "pending")
    check("pending ジョブは結果(result_json)を持たない", pending_job["result_json"] is None)
    conn.close()

    print(f"\n{'ALL PASS' if not FAILED else 'FAILED: ' + ', '.join(FAILED)}")
    import sys
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
