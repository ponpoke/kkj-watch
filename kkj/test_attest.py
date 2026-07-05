"""attest(日次ハッシュチェーン+Ed25519署名+Merkle+inclusion proof)のテスト

  python -m kkj.test_attest
"""
import json
import tempfile

_tmp = tempfile.mkdtemp()
from . import config
config.DATA_DIR = type(config.DATA_DIR)(_tmp)
config.DB_PATH = config.DATA_DIR / "test_attest.db"
config.BASE_DIR = type(config.BASE_DIR)(_tmp)

from . import store, x402watch, x402trust, attest  # noqa: E402
# attestのパス定数をtmpへ差し替え
attest.ROOT_DIR = config.BASE_DIR / "roots"
attest.PUBLIC_ROOTS_DIR = config.DATA_DIR / "public_roots"
attest.KEY_PATH = str(config.DATA_DIR / "attest_ed25519.key")
attest.PUB_PATH = str(config.DATA_DIR / "attest_ed25519.pub")

PASS = FAIL = 0


def check(name, cond, info=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok: {name}")
    else:
        FAIL += 1
        print(f"  NG: {name} {info}")


def item(resource, amount="1000", payto="0xAAA"):
    return {"resource": resource, "type": "http", "x402Version": 2,
            "serviceName": "svc", "tags": [], "description": "d", "extensions": {},
            "accepts": [{"scheme": "exact", "network": "eip155:8453",
                         "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                         "amount": amount, "payTo": payto}]}


def main():
    print("== Merkle基本 ==")
    # 単葉・2葉・3葉(奇数=末尾複製)・inclusion proof往復
    for n in (1, 2, 3, 4, 5, 8, 9):
        leaves = [attest.sha256_hex(bytes([i])) for i in range(n)]
        root = attest.merkle_root(leaves)
        allok = all(
            attest.verify_proof(leaves[i], attest.merkle_proof(leaves, i), root)
            for i in range(n))
        check(f"proof往復 n={n}", allok)
    # 改竄検知: 葉を1つ差し替えるとrootが変わる
    base = [attest.sha256_hex(bytes([i])) for i in range(5)]
    tampered = list(base)
    tampered[2] = attest.sha256_hex(b"evil")
    check("葉改竄でroot変化", attest.merkle_root(base) != attest.merkle_root(tampered))
    # 偽proofはverify_proofで落ちる
    r = attest.merkle_root(base)
    p = attest.merkle_proof(base, 2)
    check("偽leafはproof不成立", not attest.verify_proof(attest.sha256_hex(b"evil"), p, r))

    print("== 鍵生成・署名 ==")
    pub, created = attest.keygen()
    check("鍵生成", created and pub)
    pub2, created2 = attest.keygen()
    check("再呼び出しは既存鍵(冪等)", not created2 and pub2 == pub)
    h = attest.sha256_hex(b"payload")
    sig = attest.sign(h)
    check("正しい署名は検証成功", attest.verify_signature(h, sig, pub))
    check("改竄payloadは検証失敗", not attest.verify_signature(attest.sha256_hex(b"x"), sig, pub))

    print("== 日次root(連結・要件3項目) ==")
    conn = store.connect()
    x402watch.fetch_pages = lambda: (
        [item("https://a.example/x"), item("https://b.example/y", amount="5000"),
         item("https://c.example/z", payto="0xCCC")], True, None)
    x402watch.sync(conn)
    for r in conn.execute("SELECT id FROM x402_resources").fetchall():
        x402trust.update_score(conn, r["id"])
    conn.commit()

    d1 = attest.root(date="2026-07-01", conn=conn, publish_github=True)
    check("root項目(要件3)", all(k in d1 for k in
          ("date", "previous_root", "records_count", "merkle_root", "root_hash", "created_at")))
    check("初日previous_root=null", d1["previous_root"] is None)
    check("records_count=リソース数", d1["records_count"] == 3, str(d1["records_count"]))
    check("署名・公開鍵付き", d1["signature"] and d1["public_key"] == pub)
    check("public_roots出力", (attest.PUBLIC_ROOTS_DIR / "2026-07-01.root.json").exists())
    check("roots/(GitHub用)出力", (attest.ROOT_DIR / "2026-07-01.root.json").exists()
          and (attest.ROOT_DIR / "latest.json").exists())
    check("rootに原文/葉を含めない(要件12)",
          "record_json" not in json.dumps(d1) and "raw_json" not in json.dumps(d1)
          and "records" not in d1)

    # 翌日: 変化を入れてroot(前日連結)
    x402watch.fetch_pages = lambda: (
        [item("https://a.example/x", amount="9999"),   # price変更
         item("https://b.example/y", amount="5000"),
         item("https://c.example/z", payto="0xCCC")], True, None)
    x402watch.sync(conn)
    for r in conn.execute("SELECT id FROM x402_resources").fetchall():
        x402trust.update_score(conn, r["id"])
    d2 = attest.root(date="2026-07-02", conn=conn)
    check("2日目previous_root=前日root_hash", d2["previous_root"] == d1["root_hash"])
    check("chain_index増加", d2["chain_index"] == 1)
    check("内容変化でmerkle_root変化", d2["merkle_root"] != d1["merkle_root"])

    print("== verify-root ==")
    v1 = attest.verify_root("2026-07-01", conn=conn)
    v2 = attest.verify_root("2026-07-02", conn=conn)
    check("初日verify全合格", v1["ok"] and all(v1["checks"].values()), json.dumps(v1["checks"]))
    check("2日目verify全合格", v2["ok"] and all(v2["checks"].values()), json.dumps(v2["checks"]))
    check("存在しない日はok=False", not attest.verify_root("2099-01-01", conn=conn)["ok"])

    # 改竄検知: 保存済み葉を書き換えるとverifyが落ちる
    conn.execute("UPDATE daily_leaves SET leaf_hash=? WHERE date=? AND leaf_index=0",
                 (attest.sha256_hex(b"tampered"), "2026-07-01"))
    conn.commit()
    vt = attest.verify_root("2026-07-01", conn=conn)
    check("葉改竄をverifyが検知", not vt["ok"] and not vt["checks"]["merkle"])
    # 復元
    attest.root(date="2026-07-01", force=True, conn=conn)
    # forceで初日を作り直すと root_hash が変わり得る→2日目の連結が壊れるので張り直し
    attest.root(date="2026-07-02", force=True, conn=conn)
    check("force再生成後もverify合格", attest.verify_root("2026-07-02", conn=conn)["ok"])

    print("== prove-resource(inclusion proof) ==")
    rid = conn.execute("SELECT id FROM x402_resources WHERE resource=?",
                       ("https://b.example/y",)).fetchone()["id"]
    pr = attest.prove_resource(rid, "2026-07-02", conn=conn)
    check("proof全体ok", pr["ok"], json.dumps(pr.get("checks", pr.get("error", ""))))
    check("recordはハッシュ+メタのみ(原文なし)",
          "snapshots_hash" in pr["record"] and "raw_json" not in json.dumps(pr["record"]))
    # 独立検証: leaf_hash再計算→path畳み込み→root一致→署名
    import hashlib
    leaf = attest.sha256_hex(attest.canonical(pr["record"]))
    check("leaf_hash再計算一致", leaf == pr["leaf_hash"])
    check("pathを畳むとmerkle_root一致",
          attest.verify_proof(leaf, pr["inclusion_proof"], pr["merkle_root"]))
    signed_doc = {"date": "2026-07-02", "previous_root": pr["previous_root"],
                  "records_count": conn.execute(
                      "SELECT records_count FROM daily_roots WHERE date=?",
                      ("2026-07-02",)).fetchone()[0],
                  "merkle_root": pr["merkle_root"],
                  "created_at": conn.execute(
                      "SELECT created_at FROM daily_roots WHERE date=?",
                      ("2026-07-02",)).fetchone()[0]}
    check("root_hash再計算一致",
          attest.sha256_hex(attest.canonical(signed_doc)) == pr["root_hash"])
    check("署名検証成功", attest.verify_signature(pr["root_hash"], pr["signature"],
                                              pr["public_key"]))
    check("存在しないリソースはok=False",
          not attest.prove_resource(999999, "2026-07-02", conn=conn)["ok"])

    conn.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
