"""x402guard core: check() + safe_pay() over the kkj-watch x402 Trust Index."""
import json
import urllib.parse
import urllib.request
import warnings
from dataclasses import dataclass, field
from typing import Callable, Optional

DEFAULT_BASE_URL = "https://5.75.142.199.sslip.io"


class X402GuardError(Exception):
    """Guard could not complete a check (and policy did not allow proceeding)."""


class X402Blocked(Exception):
    """The safety policy blocked this payment. `.verdict` holds the details."""

    def __init__(self, verdict):
        self.verdict = verdict
        super().__init__(
            f"x402 payment blocked ({verdict.resource}): "
            + "; ".join(verdict.reasons or ["blocked by policy"]))


@dataclass
class Policy:
    """When to block vs warn vs allow. Defaults are safe but do not needlessly break payments."""
    base_url: str = DEFAULT_BASE_URL
    timeout: float = 8.0
    # hard blocks
    block_on_payto_mismatch: bool = True      # live payTo != registry (hijack signal) — critical
    min_trust: float = 40.0                    # block below this observed score
    block_on_farm: bool = False               # payTo shared across a spam farm
    block_on_delisted: bool = False           # removed from the registry
    block_on_unknown: bool = False            # resource not in the Trust Index at all
    # warnings (proceed, but surface)
    warn_trust: float = 70.0                   # warn below this observed score
    warn_on_price_mismatch: bool = True        # live price != registry
    warn_on_unverified_live: bool = True       # could not confirm a live 402
    warn_on_payto_changed: bool = True         # payTo changed recently (not a live mismatch)
    # availability behaviour
    fail_open: bool = True                     # if the Trust Index is unreachable: True=warn+proceed,
    #                                            False=raise X402GuardError (fail closed)


@dataclass
class Verdict:
    decision: str                              # "allow" | "warn" | "block"
    resource: str
    observed_trust_score: Optional[float] = None
    grade: Optional[str] = None
    reasons: list = field(default_factory=list)
    verdicts: dict = field(default_factory=dict)
    attested: bool = False                     # a signed attestation is available for this resource
    known: bool = True                         # resource found in the Trust Index
    error: Optional[str] = None                # set if the check itself failed (fail_open path)
    raw: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.decision != "block"


def _fetch_trust(resource_url: str, policy: Policy) -> dict:
    enc = urllib.parse.quote(resource_url, safe="")
    url = f"{policy.base_url.rstrip('/')}/x402/trust/{enc}"
    req = urllib.request.Request(url, headers={
        "Accept": "application/json", "User-Agent": "x402guard/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=policy.timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"error": "not_found"}
        raise
    # 他の例外(タイムアウト/接続不可)は呼び出し側で捕捉


def decide(trust_resp: dict, resource: str, policy: Policy) -> Verdict:
    """Trust応答からallow/warn/blockを決定(決定的・説明付き)。"""
    if trust_resp.get("error") == "not_found":
        reasons = ["resource is not in the Trust Index (no observation history)"]
        decision = "block" if policy.block_on_unknown else "warn"
        return Verdict(decision=decision, resource=resource, reasons=reasons,
                       known=False, raw=trust_resp)

    trust = trust_resp.get("trust", {}) or {}
    v = trust.get("verdicts", {}) or {}
    score = trust_resp.get("observed_trust_score", trust.get("score"))
    grade = trust.get("grade")
    attested = bool((trust_resp.get("latest_attestation_available") or {}).get("available"))

    blocks, warns = [], []

    if policy.block_on_payto_mismatch and v.get("payto_risk") == "live_mismatch":
        blocks.append("CRITICAL: live payTo differs from the registry listing (possible hijack)")
    if score is not None and score < policy.min_trust:
        blocks.append(f"observed trust score {score} < min_trust {policy.min_trust}")
    if policy.block_on_farm and v.get("farm_member"):
        blocks.append("payTo is part of a detected spam farm")
    if policy.block_on_delisted and v.get("active_listing") is False:
        blocks.append("resource is delisted from the registry")
    if policy.block_on_unknown and v.get("verified_live") is None:
        blocks.append("no verification data")

    if policy.warn_on_payto_changed and v.get("payto_risk") == "changed_recently":
        warns.append("payTo changed recently (verify before paying)")
    if policy.warn_on_price_mismatch and v.get("listing_matches_live") == "mismatch" \
            and v.get("payto_risk") != "live_mismatch":
        warns.append("live price differs from the registry listing")
    if policy.warn_on_unverified_live and v.get("verified_live") is False:
        warns.append("could not confirm a live 402 on the last probe")
    if v.get("farm_member") and not policy.block_on_farm:
        warns.append("payTo is part of a detected spam farm")
    if v.get("active_listing") is False and not policy.block_on_delisted:
        warns.append("resource is delisted from the registry")
    if score is not None and policy.min_trust <= score < policy.warn_trust:
        warns.append(f"observed trust score {score} < warn_trust {policy.warn_trust}")

    decision = "block" if blocks else ("warn" if warns else "allow")
    return Verdict(decision=decision, resource=resource,
                   observed_trust_score=score, grade=grade,
                   reasons=(blocks + warns), verdicts=v, attested=attested,
                   known=True, raw=trust_resp)


def check(resource_url: str, policy: Optional[Policy] = None) -> Verdict:
    """Return a Verdict for one x402 resource URL (does not pay)."""
    policy = policy or Policy()
    try:
        resp = _fetch_trust(resource_url, policy)
    except Exception as e:                      # 接続不可/タイムアウト/5xx
        if policy.fail_open:
            return Verdict(decision="warn", resource=resource_url,
                           reasons=[f"Trust Index unreachable ({e}); proceeding (fail-open)"],
                           known=False, error=str(e))
        raise X402GuardError(f"Trust Index unreachable: {e}") from e
    return decide(resp, resource_url, policy)


def safe_pay(resource_url: str, pay: Callable[[], object],
             policy: Optional[Policy] = None,
             on_warn: Optional[Callable[[Verdict], None]] = None,
             on_block: Optional[Callable[[Verdict], None]] = None):
    """Check the endpoint, then run `pay()` unless the policy blocks it.

    - block: raise X402Blocked (or call on_block if given, and skip payment)
    - warn:  call on_warn (or emit a warning), then run pay()
    - allow: run pay()

    Returns whatever `pay()` returns.
    """
    policy = policy or Policy()
    verdict = check(resource_url, policy)
    if verdict.decision == "block":
        if on_block is not None:
            on_block(verdict)
            return None
        raise X402Blocked(verdict)
    if verdict.decision == "warn":
        if on_warn is not None:
            on_warn(verdict)
        else:
            warnings.warn("x402guard: " + "; ".join(verdict.reasons), stacklevel=2)
    return pay()


def _cli():
    import sys
    if len(sys.argv) < 2:
        print("usage: python -m x402guard <resource_url> [--base URL] [--min-trust N]")
        raise SystemExit(2)
    url = sys.argv[1]
    policy = Policy()
    if "--base" in sys.argv:
        policy.base_url = sys.argv[sys.argv.index("--base") + 1]
    if "--min-trust" in sys.argv:
        policy.min_trust = float(sys.argv[sys.argv.index("--min-trust") + 1])
    v = check(url, policy)
    print(json.dumps({
        "decision": v.decision, "resource": v.resource,
        "observed_trust_score": v.observed_trust_score, "grade": v.grade,
        "known": v.known, "attested": v.attested, "reasons": v.reasons,
        "verdicts": v.verdicts, "error": v.error,
    }, ensure_ascii=False, indent=1))
    raise SystemExit(0 if v.decision != "block" else 1)


if __name__ == "__main__":
    _cli()
