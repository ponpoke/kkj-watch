"""x402guard — safe payment middleware for x402 AI agents.

Check an x402 endpoint's *observed* trust (payTo match, price match, liveness, spam-farm,
recent critical events) BEFORE you pay it, in one line. Backed by kkj-watch's x402 Trust
Index (daily Ed25519-signed hash-chain roots). This is a risk check, not a safety guarantee.

    from x402guard import safe_pay

    data = safe_pay(url, pay=lambda: my_x402_client.get(url))
    # -> raises X402Blocked if the live payTo differs from the registry, trust is too low, etc.
    # -> otherwise runs your pay() and returns its result

Zero dependencies (standard library only). Configure with Policy(...).
"""
from .guard import (  # noqa: F401
    check, safe_pay, Policy, Verdict, X402Blocked, X402GuardError,
    DEFAULT_BASE_URL,
)

__all__ = ["check", "safe_pay", "Policy", "Verdict", "X402Blocked",
           "X402GuardError", "DEFAULT_BASE_URL"]
__version__ = "0.1.0"
