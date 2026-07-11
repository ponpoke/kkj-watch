"""pipeline.cmd_pruneのオフラインテスト(一時DB)

  python -m kkj.test_pipeline
"""
import tempfile
from datetime import datetime, timedelta, timezone

_tmp = tempfile.mkdtemp()
from . import config
config.DATA_DIR = type(config.DATA_DIR)(_tmp)
config.DB_PATH = config.DATA_DIR / "test_pipeline.db"

from . import pipeline, store, server, x402probe  # noqa: E402

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
    conn = store.connect()
    conn.executescript(server.USAGE_SCHEMA)
    conn.executescript(x402probe.SCHEMA_SQL)
    now = datetime.now(timezone.utc)

    print("== usage_log: 90日超の行だけ削除 ==")
    old_at = (now - timedelta(days=91)).isoformat()
    recent_at = (now - timedelta(days=10)).isoformat()
    for at in (old_at, old_at, recent_at):
        conn.execute("INSERT INTO usage_log(at, client, user_agent, path) VALUES (?,?,?,?)",
                     (at, "1.2.3.4", "ua", "/x"))
    conn.commit()

    print("== x402_probes: resource毎に直近probes_keep件だけ残す ==")
    for rid, n in ((1, 150), (2, 5)):
        for i in range(n):
            conn.execute(
                "INSERT INTO x402_probes(resource_id, probed_at, alive, http_status, is_402,"
                " consistency) VALUES (?,?,1,402,1,'ok')", (rid, now.isoformat()))
    conn.commit()
    conn.close()

    pipeline.cmd_prune(usage_days=90, probes_keep=100)

    conn = store.connect()
    n_usage = conn.execute("SELECT COUNT(*) n FROM usage_log").fetchone()["n"]
    ck("usage_log: 古い2件が消え、新しい1件が残る", n_usage == 1, f"got {n_usage}")

    n1 = conn.execute("SELECT COUNT(*) n FROM x402_probes WHERE resource_id=1").fetchone()["n"]
    ck("x402_probes: 150件→直近100件に切り詰め", n1 == 100, f"got {n1}")
    n2 = conn.execute("SELECT COUNT(*) n FROM x402_probes WHERE resource_id=2").fetchone()["n"]
    ck("x402_probes: 100件未満(5件)はそのまま", n2 == 5, f"got {n2}")

    kept_max_id = conn.execute(
        "SELECT MAX(id) n FROM x402_probes WHERE resource_id=1").fetchone()["n"]
    kept_min_id = conn.execute(
        "SELECT MIN(id) n FROM x402_probes WHERE resource_id=1").fetchone()["n"]
    ck("x402_probes: 残るのは新しい(id大きい)方", kept_max_id - kept_min_id == 99,
       f"min={kept_min_id} max={kept_max_id}")

    print("== 何も削れない時はVACUUMをスキップ(冪等) ==")
    pipeline.cmd_prune(usage_days=90, probes_keep=100)   # 2回目: 追加削除なし、例外なく完了
    ck("2回連続実行してもエラーにならない", True)

    conn.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
