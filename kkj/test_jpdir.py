"""jpdir(日本資源目録)のオフラインテスト(fetchモック・一時DB)

  python -m kkj.test_jpdir
"""
import json
import tempfile

_tmp = tempfile.mkdtemp()
from . import config
config.DATA_DIR = type(config.DATA_DIR)(_tmp)
config.DB_PATH = config.DATA_DIR / "test_jpdir.db"

from . import store, jpdir  # noqa: E402

PASS = FAIL = 0


def ck(name, cond, info=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok: {name}")
    else:
        FAIL += 1
        print(f"  NG: {name} {info}")


def main():
    print("== 機械可読判定 / 指紋 ==")
    ck("JSON判定", jpdir._classify_body("application/json", b'{"a":1}') == "json")
    ck("配列JSON判定", jpdir._classify_body("", b'[1,2,3]') == "json")
    ck("XML判定", jpdir._classify_body("text/xml", b'<?xml version="1.0"?><a/>') == "xml")
    ck("HTML判定", jpdir._classify_body("text/html", b'<!doctype html><html>') == "html")
    fp1 = jpdir._fingerprint(b'{"name":"x","age":1}', "json")
    fp2 = jpdir._fingerprint(b'{"name":"y","age":99}', "json")  # 値違い・形同じ
    fp3 = jpdir._fingerprint(b'{"name":"x","email":"z"}', "json")  # 形違い
    ck("形が同じなら指紋一致(値は無視=PII保存せず)", fp1 == fp2 and fp1 != "")
    ck("形が違えば指紋変化", fp1 != fp3)

    print("== sync(モックfetch) ==")
    conn = store.connect()
    # open JSON を返すfetch
    def fetch_ok(url):
        return 200, b'{"forecast":[{"date":"x","temp":1}]}', 12, None
    out = jpdir.sync(conn, fetch=fetch_ok)
    ck("seed件数ぶん観測", out["resources"] == len(jpdir.SEED))
    ck("json形式で観測", out["by_format"].get("json", 0) >= 1)
    r = conn.execute("SELECT * FROM jp_resources LIMIT 1").fetchone()
    latest = json.loads(r["latest_json"])
    ck("latest_jsonは指紋のみ(原文なし)",
       "schema_fingerprint" in latest and "forecast" not in json.dumps(latest))
    ck("probe記録あり",
       conn.execute("SELECT COUNT(*) n FROM jp_probes").fetchone()["n"] == len(jpdir.SEED))

    print("== スキーマ変更・生存イベント ==")
    rid = r["id"]
    # 形を変えて再sync → schema_changed
    def fetch_changed(url):
        return 200, b'{"forecast":[{"date":"x","humidity":9}]}', 12, None
    jpdir.sync(conn, fetch=fetch_changed)
    evs = [e["event_type"] for e in conn.execute(
        "SELECT event_type FROM jp_events WHERE resource_id=? ORDER BY id", (rid,)).fetchall()]
    ck("schema_changed発火", "schema_changed" in evs, str(evs))
    # 2連続不在 → unreachable
    def fetch_dead(url):
        return None, b"", 0, "timeout"
    jpdir.sync(conn, fetch=fetch_dead)
    jpdir.sync(conn, fetch=fetch_dead)
    evs = [e["event_type"] for e in conn.execute(
        "SELECT event_type FROM jp_events WHERE resource_id=? ORDER BY id", (rid,)).fetchall()]
    ck("2連続不在でunreachable", "unreachable" in evs)
    # 復活
    jpdir.sync(conn, fetch=fetch_ok)
    evs = [e["event_type"] for e in conn.execute(
        "SELECT event_type FROM jp_events WHERE resource_id=? ORDER BY id", (rid,)).fetchall()]
    ck("復活でrecovered", "recovered" in evs)

    print("== 認証要否の観測 ==")
    def fetch_403(url):
        return 403, b'{"error":"forbidden"}', 5, None
    jpdir.sync(conn, fetch=fetch_403)
    r2 = conn.execute("SELECT latest_json FROM jp_resources LIMIT 1").fetchone()
    ck("403でauth_required観測", json.loads(r2["latest_json"])["auth_observed"] == "auth_required")

    conn.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
