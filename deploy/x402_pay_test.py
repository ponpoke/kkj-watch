"""x402実支払いテスト(V1 exact / EIP-3009直組み)。VPSのvenvで実行。

  venv/bin/python x402_pay_test.py <URL>

CDPから支払い用ウォレット(kkj-test-payer)の鍵をエクスポートし、
402応答のpaymentRequirementsに従いUSDCのtransferWithAuthorizationに署名して購入する。
"""
import asyncio
import base64
import json
import os
import secrets
import sys
import time
import urllib.request
import urllib.error

CHAIN_ID = {"base": 8453, "base-sepolia": 84532}


def chain_id(network: str) -> int:
    """V1名("base")とCAIP-2("eip155:8453")の両表記を受ける
    (V2移行後の402応答はCAIP-2を返す)"""
    if network.startswith("eip155:"):
        return int(network.split(":", 1)[1])
    return CHAIN_ID[network]


def load_env():
    try:
        f = open("/etc/kkj-watch.env")
    except OSError:
        return   # 非rootではsystemd-run等のEnvironmentFile注入を前提にする
    with f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v)


async def cdp_sign_typed_data(domain, types, primary_type, message):
    """CDPサーバーウォレットでEIP-712署名(秘密鍵のエクスポート不要)"""
    from cdp import CdpClient
    async with CdpClient() as cdp:
        acct = await cdp.evm.get_or_create_account(name="kkj-test-payer")
        full_types = {"EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
        ], **types}
        try:
            sig = await acct.sign_typed_data(
                domain=domain, types=full_types,
                primary_type=primary_type, message=message)
        except TypeError:
            sig = await acct.sign_typed_data({
                "domain": domain, "types": full_types,
                "primaryType": primary_type, "message": message})
        return acct.address, sig


def http_get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def main():
    load_env()
    url = sys.argv[1]

    # 1. 402と支払い条件を取得
    status, _, body = http_get(url)
    assert status == 402, f"expected 402, got {status}: {body[:200]}"
    req = json.loads(body)["accepts"][0]
    print(f"[1] 402 OK: {req['maxAmountRequired']} μUSDC on {req['network']} -> {req['payTo']}")

    # 2. CDPサーバーウォレットで署名(鍵はCDP側に留まる)
    now = int(time.time())
    nonce = "0x" + secrets.token_hex(32)
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
    valid_after = now - 60
    valid_before = now + int(req.get("maxTimeoutSeconds", 120)) + 60
    # まずアドレスが要るのでダミー無しの2段階: メッセージはfrom確定後に作る
    import json as _json
    from cdp import CdpClient

    async def sign():
        async with CdpClient() as cdp:
            acct = await cdp.evm.get_or_create_account(name="kkj-test-payer")
            message = {
                "from": acct.address, "to": req["payTo"],
                "value": req["maxAmountRequired"],
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
    print(f"[2] payer: {payer} (CDP署名)")
    auth = {
        "from": payer, "to": req["payTo"], "value": req["maxAmountRequired"],
        "validAfter": str(valid_after), "validBefore": str(valid_before), "nonce": nonce,
    }
    payment = {
        "x402Version": 1,
        "scheme": "exact",
        "network": req["network"],
        "payload": {"signature": signature, "authorization": auth},
    }
    x_payment = base64.b64encode(json.dumps(payment).encode()).decode()
    print("[3] signed EIP-3009 transferWithAuthorization")

    # 3. 支払い付きで再リクエスト
    status, headers, body = http_get(url, {"X-PAYMENT": x_payment})
    print(f"[4] paid request -> {status}")
    pr = headers.get("X-PAYMENT-RESPONSE") or headers.get("x-payment-response")
    if pr:
        print("    settle:", base64.b64decode(pr).decode()[:200])
    print(body.decode()[:600])
    sys.exit(0 if status == 200 else 1)


if __name__ == "__main__":
    main()
