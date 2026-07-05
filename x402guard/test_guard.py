"""x402guard のオフラインテスト(_fetch_trustをモック)

  python -m x402guard.test_guard
"""
from . import guard
from .guard import Policy, check, safe_pay, X402Blocked, X402GuardError

PASS = FAIL = 0


def ck(name, cond, info=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok: {name}")
    else:
        FAIL += 1
        print(f"  NG: {name} {info}")


def resp(score=90, payto_risk="none", listing="ok", verified=True,
         farm=False, active=True, attested=True, not_found=False):
    if not_found:
        return {"error": "not_found"}
    return {
        "observed_trust_score": score,
        "trust": {"score": score, "grade": "A" if score >= 85 else "C",
                  "verdicts": {"payto_risk": payto_risk, "listing_matches_live": listing,
                               "verified_live": verified, "farm_member": farm,
                               "active_listing": active}},
        "latest_attestation_available": {"available": attested},
    }


def mock(r):
    guard._fetch_trust = lambda url, policy: r


def main():
    print("== decide: 正常な高信頼 → allow ==")
    mock(resp(score=90))
    v = check("https://good.example/x")
    ck("allow", v.decision == "allow" and v.ok, v.decision)
    ck("スコア/attested取得", v.observed_trust_score == 90 and v.attested)

    print("== payTo live mismatch → block(critical) ==")
    mock(resp(score=90, payto_risk="live_mismatch"))
    v = check("https://evil.example/x")
    ck("block", v.decision == "block" and not v.ok)
    ck("critical理由", any("payTo differs" in r for r in v.reasons))

    print("== 低trust → block ==")
    mock(resp(score=20))
    ck("min_trust未満でblock", check("u").decision == "block")
    mock(resp(score=55))
    ck("warn_trust未満でwarn", check("u").decision == "warn")

    print("== price mismatch → warn ==")
    mock(resp(score=90, listing="mismatch"))
    v = check("u")
    ck("price mismatchはwarn", v.decision == "warn"
       and any("price differs" in r for r in v.reasons))

    print("== payTo changed recently → warn(blockではない) ==")
    mock(resp(score=90, payto_risk="changed_recently"))
    ck("changed_recentlyはwarn", check("u").decision == "warn")

    print("== 未検証live → warn ==")
    mock(resp(score=90, verified=False))
    ck("verified_live=Falseはwarn", check("u").decision == "warn")

    print("== farm → 既定warn / policyでblock ==")
    mock(resp(score=90, farm=True))
    ck("farm既定warn", check("u").decision == "warn")
    ck("farm block policy", check("u", Policy(block_on_farm=True)).decision == "block")

    print("== 未知リソース(404) ==")
    mock(resp(not_found=True))
    ck("未知は既定warn", check("u").decision == "warn" and not check("u").known)
    ck("block_on_unknownでblock", check("u", Policy(block_on_unknown=True)).decision == "block")

    print("== 到達不能: fail-open / fail-closed ==")
    def boom(url, policy):
        raise OSError("connection refused")
    guard._fetch_trust = boom
    ck("fail-open=warn+proceed", check("u", Policy(fail_open=True)).decision == "warn")
    try:
        check("u", Policy(fail_open=False))
        ck("fail-closed=raise", False)
    except X402GuardError:
        ck("fail-closed=raise", True)

    print("== safe_pay: allow時のみpay()実行 ==")
    calls = {"n": 0}
    mock(resp(score=90))
    out = safe_pay("u", pay=lambda: (calls.__setitem__("n", calls["n"] + 1), "DATA")[1])
    ck("allowでpay実行+戻り値", out == "DATA" and calls["n"] == 1)

    print("== safe_pay: block時はpay()を呼ばずraise ==")
    mock(resp(payto_risk="live_mismatch"))
    calls["n"] = 0
    try:
        safe_pay("u", pay=lambda: calls.__setitem__("n", calls["n"] + 1))
        ck("blockでraise", False)
    except X402Blocked as e:
        ck("blockでraise+pay未実行", calls["n"] == 0 and e.verdict.decision == "block")

    print("== safe_pay: block時 on_block指定なら raiseせずpay抑止 ==")
    mock(resp(payto_risk="live_mismatch"))
    seen = {}
    r = safe_pay("u", pay=lambda: "SHOULD_NOT", on_block=lambda v: seen.update(d=v.decision))
    ck("on_blockでpay抑止", r is None and seen.get("d") == "block")

    print("== safe_pay: warn時はコールバック後にpay実行 ==")
    mock(resp(score=55))
    warned = {}
    out = safe_pay("u", pay=lambda: "DATA", on_warn=lambda v: warned.update(d=v.decision))
    ck("warnでpay実行+on_warn呼ぶ", out == "DATA" and warned.get("d") == "warn")

    print(f"\n{PASS} passed, {FAIL} failed")
    raise SystemExit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
