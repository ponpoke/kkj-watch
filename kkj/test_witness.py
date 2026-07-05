"""witness(存在証明) + attest anchor統合のテスト

  python -m kkj.test_witness
"""
import hashlib
import json
import tempfile

_tmp = tempfile.mkdtemp()
from . import config
config.DATA_DIR = type(config.DATA_DIR)(_tmp)
config.DB_PATH = config.DATA_DIR / "test_witness.db"
config.BASE_DIR = type(config.BASE_DIR)(_tmp)

from . import store, x402watch, x402trust, attest, witness  # noqa: E402
attest.ROOT_DIR = config.BASE_DIR / "roots"
attest.PUBLIC_ROOTS_DIR = config.DATA_DIR / "public_roots"
attest.KEY_PATH = str(config.DATA_DIR / "k.key")
attest.PUB_PATH = str(config.DATA_DIR / "k.pub")

PASS = FAIL = 0


def ck(name, cond, info=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok: {name}")
    else:
        FAIL += 1
        print(f"  NG: {name} {info}")


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()


def main():
    print("== sha256検証(rawデータ・不正を弾く) ==")
    ck("正規64hex OK", witness.normalize_sha256(h("hello")) == h("hello"))
    ck("0x接頭辞を除去", witness.normalize_sha256("0x" + h("x")) == h("x"))
    ck("大文字→小文字", witness.normalize_sha256(h("x").upper()) == h("x"))
    ck("短い文字列は拒否", witness.normalize_sha256("abc") is None)
    ck("生テキストは拒否", witness.normalize_sha256("secret contract text") is None)
    ck("非hexは拒否", witness.normalize_sha256("z" * 64) is None)
    ck("Noneは拒否", witness.normalize_sha256(None) is None)

    conn = store.connect()
    x402watch.fetch_pages = lambda: (
        [{"resource": "https://a.example/x", "type": "http", "x402Version": 2,
          "serviceName": "s", "tags": [], "description": "d", "extensions": {},
          "accepts": [{"scheme": "exact", "network": "eip155:8453",
                       "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                       "amount": "1000", "payTo": "0xAAA"}]}], True, None)
    x402watch.sync(conn)
    x402trust.update_score(conn, 1)
    conn.commit()

    print("== insert冪等 / quota ==")
    d1 = h("doc-1")
    row, created = witness.insert(conn, d1, "1.2.3.4", paid=False)
    ck("初回挿入", created and row["status"] == "pending")
    row2, created2 = witness.insert(conn, d1, "9.9.9.9", paid=False)
    ck("同一sha256は冪等(再挿入しない)", not created2 and row2["sha256"] == d1)
    rem, needs, full = witness.quota_state(conn, "1.2.3.4")
    ck("無料枠を消費", rem == witness.FREE_PER_DAY - 1)

    print("== pendingはproof未成立 ==")
    p = attest.prove_anchor(d1, conn=conn)
    ck("未封入はpending", p.get("status") == "pending" and not p.get("ok"))
    ck("未anchorはnot_anchored", attest.prove_anchor(h("never"), conn=conn)["error"] == "not_anchored")

    print("== 日次rootでanchor封入 ==")
    # もう1件足しておく
    witness.insert(conn, h("doc-2"), "1.2.3.4", paid=True)
    out = attest.root(date="2026-07-06", conn=conn)
    ck("records_count=resource1+anchor2", out["records_count"] == 3, str(out["records_count"]))
    a = witness.get(conn, d1)
    ck("anchorがcommitted", a["status"] == "committed" and a["root_date"] == "2026-07-06")

    print("== prove-hash(署名付き存在証明) ==")
    pr = attest.prove_anchor(d1, conn=conn)
    ck("proof ok", pr["ok"], json.dumps(pr.get("error", "")))
    ck("recordはsha256のみ(原文なし)",
       pr["record"]["sha256"] == d1 and pr["record"]["type"] == "existence_anchor"
       and "raw" not in json.dumps(pr["record"]))
    ck("kind表記が公証でない",
       pr["kind"] == "signed_existence_proof" and "not_a_notarization" in pr)

    # 買い手側の独立検証(4段)
    leaf = attest.sha256_hex(attest.canonical(pr["record"]))
    ck("1 leaf_hash再計算一致", leaf == pr["leaf_hash"])
    ck("2 inclusion_proof→merkle_root",
       attest.verify_proof(leaf, pr["inclusion_proof"], pr["merkle_root"]))
    sd = {"date": "2026-07-06", "previous_root": pr["previous_root"],
          "records_count": conn.execute(
              "SELECT records_count FROM daily_roots WHERE date=?", ("2026-07-06",)).fetchone()[0],
          "merkle_root": pr["merkle_root"], "created_at": pr["created_at"]}
    ck("3 root_hash再計算一致",
       attest.sha256_hex(attest.canonical(sd)) == pr["root_hash"])
    ck("4 Ed25519署名検証",
       attest.verify_signature(pr["root_hash"], pr["signature"], pr["public_key"]))

    print("== resource証明も引き続き成立(回帰) ==")
    rp = attest.prove_resource(1, "2026-07-06", conn=conn)
    ck("resource proof ok", rp["ok"])
    ck("verify-root全合格", attest.verify_root("2026-07-06", conn=conn)["ok"])

    conn.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
