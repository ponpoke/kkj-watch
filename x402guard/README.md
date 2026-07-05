# x402guard — check before you pay (one line)

A tiny, zero-dependency safety layer for x402 AI agents. Before your agent pays an x402
endpoint, `x402guard` checks its **observed** trust — does the live endpoint serve the same
`payTo` (receiving address) and price as the registry? Is it alive? Is the `payTo` part of a
spam farm? Did it change recently? — and blocks the payment on a hijack signal.

Backed by the [kkj-watch x402 Trust Index](https://5.75.142.199.sslip.io/x402/attestations),
whose observations are committed to **daily Ed25519-signed hash-chain roots**. This is an
observed, evidence-based risk check — **not a safety guarantee**. Always keep your own limits.

## Why

The x402 flow re-fetches payment terms at 402 time, so it will happily pay a **hijacked
payTo** or a silently **10×'d price**. `x402guard` sits in your payment path and stops that,
without asking your agent to adopt any new habit — you just wrap your existing pay call.

## Install

Zero dependencies (Python standard library only). Copy the `x402guard/` folder into your
project, or vendor it. No pip, no keys, no account.

## Use

```python
from x402guard import safe_pay

# Wrap your existing x402 payment. If the endpoint looks hijacked / untrustworthy,
# safe_pay raises X402Blocked BEFORE any money moves.
data = safe_pay(url, pay=lambda: my_x402_client.get(url))
```

Just want the verdict (no payment)?

```python
from x402guard import check

v = check("https://api.example.com/search")
print(v.decision)              # "allow" | "warn" | "block"
print(v.observed_trust_score)  # 0-100
print(v.reasons)               # why
```

CLI:

```console
$ python -m x402guard https://x402.browserbase.com/browser/session/create
{ "decision": "block",
  "reasons": ["CRITICAL: live payTo differs from the registry listing (possible hijack)"] }
# exit code 1 on block, 0 otherwise
```

## Policy

```python
from x402guard import safe_pay, Policy

policy = Policy(
    min_trust=50,                    # block below this observed score
    warn_trust=75,                   # warn below this
    block_on_payto_mismatch=True,    # live payTo != registry -> block (default: on)
    block_on_farm=False,             # spam-farm payTo -> block (default: warn)
    block_on_delisted=False,         # removed from registry -> block (default: warn)
    fail_open=True,                  # Trust Index unreachable -> warn+proceed (set False to fail closed)
    base_url="https://5.75.142.199.sslip.io",
)
data = safe_pay(url, pay=lambda: my_x402_client.get(url), policy=policy)
```

- **block** → `safe_pay` raises `X402Blocked` (or calls your `on_block`) and does **not** pay.
- **warn**  → emits a warning (or calls your `on_warn`), then pays.
- **allow** → pays.

## Decision rules (deterministic)

| Signal | Default |
|---|---|
| live payTo differs from registry (`payto_risk = live_mismatch`) | **block** |
| observed trust score < `min_trust` | **block** |
| payTo in a spam farm | warn (block optional) |
| resource delisted | warn (block optional) |
| live price differs from registry | warn |
| payTo changed recently | warn |
| could not confirm a live 402 | warn |
| score between `min_trust` and `warn_trust` | warn |
| resource unknown to the Trust Index | warn (block optional) |
| Trust Index unreachable | warn + proceed (fail-open) or raise (fail-closed) |

It is a risk check, not a guarantee — verify payment terms and keep spend limits.
