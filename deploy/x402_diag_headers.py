"""Bazaar掲載診断: facilitatorのverify/settle応答ヘッダ(EXTENSION-RESPONSES等)を
そのまま出力する。kkj.x402_gateの envelope 組み立てをそのまま再利用し、
本番コードには手を入れない。VPSのvenvで実行。

  venv/bin/python deploy/x402_diag_headers.py <URL>
"""
import asyncio
import base64
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHAIN_ID = {"base": 8453, "base-sepolia": 84532}


def chain_id(network: str) -> int:
    if network.startswith("eip155:"):
        return int(network.split(":", 1)[1])
    return CHAIN_ID[network]


def http_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def main():
    url = sys.argv[1]
    from kkj import x402_gate

    status, _, body = http_get(url)
    assert status == 402, f"expected 402, got {status}: {body[:200]}"
    body_json = json.loads(body)
    req = body_json["accepts"][0]
    resource = body_json.get("resource") or {}
    req = {**req, "resource": resource.get("url"), "description": resource.get("description"),
           "mimeType": resource.get("mimeType")}
    print(f"[1] 402 requirements: {json.dumps(req, ensure_ascii=False)}")

    now = int(time.time())
    nonce = "0x" + secrets.token_hex(32)
    valid_after = now - 60
    valid_before = now + int(req.get("maxTimeoutSeconds", 120)) + 60
    domain = {
        "name": req.get("extra", {}).get("name", "USDC"),
        "version": req.get("extra", {}).get("version", "2"),
        "chainId": chain_id(req["network"]),
        "verifyingContract": req["asset"],
    }
    types = {
        "TransferWithAuthorization": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "validAfter", "type": "uint256"},
            {"name": "validBefore", "type": "uint256"},
            {"name": "nonce", "type": "bytes32"},
        ]
    }

    async def sign():
        from cdp import CdpClient
        async with CdpClient() as cdp:
            acct = await cdp.evm.get_or_create_account(name="kkj-test-payer")
            message = {
                "from": acct.address, "to": req["payTo"],
                "value": req["amount"],
                "validAfter": str(valid_after), "validBefore": str(valid_before),
                "nonce": nonce,
            }
            full_types = {"EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ], **types}
            try:
                sig = await acct.sign_typed_data(
                    domain=domain, types=full_types,
                    primary_type="TransferWithAuthorization", message=message)
            except TypeError:
                sig = await acct.sign_typed_data({
                    "domain": domain, "types": full_types,
                    "primaryType": "TransferWithAuthorization", "message": message})
            return acct.address, str(sig)

    payer, signature = asyncio.run(sign())
    print(f"[2] payer: {payer}")
    auth = {
        "from": payer, "to": req["payTo"], "value": req["amount"],
        "validAfter": str(valid_after), "validBefore": str(valid_before), "nonce": nonce,
    }
    payment = {"scheme": "exact", "network": req["network"],
               "payload": {"signature": signature, "authorization": auth}}

    envelope = x402_gate._v2_envelope(payment, req)
    print(f"[3] envelope.paymentPayload.resource = "
          f"{json.dumps(envelope['paymentPayload'].get('resource'), ensure_ascii=False)}")

    cfg = x402_gate.config()
    base = x402_gate.FACILITATOR[cfg["network"]]

    def post(endpoint):
        url_ = f"{base}/{endpoint}"
        headers = {"Content-Type": "application/json"}
        path = url_.split("api.cdp.coinbase.com", 1)[1]
        headers["Authorization"] = f"Bearer {x402_gate._cdp_jwt('POST', path)}"
        r = urllib.request.Request(url_, data=json.dumps(envelope).encode(),
                                    headers=headers, method="POST")
        try:
            with urllib.request.urlopen(r, timeout=90) as resp:
                return resp.status, dict(resp.headers), json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), json.loads(e.read().decode())

    for ep in ("verify", "settle"):
        st, hdrs, body = post(ep)
        ext = {k: v for k, v in hdrs.items() if "extension" in k.lower() or "bazaar" in k.lower()}
        print(f"[{ep}] status={st}")
        print(f"  all_headers={json.dumps(hdrs, ensure_ascii=False)}")
        print(f"  extension_headers={json.dumps(ext, ensure_ascii=False)}")
        print(f"  body={json.dumps(body, ensure_ascii=False)[:400]}")
        if ep == "verify" and not body.get("isValid"):
            print("verify failed, aborting before settle")
            return


if __name__ == "__main__":
    main()
