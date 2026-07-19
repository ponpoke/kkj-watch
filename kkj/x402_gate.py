"""x402決済ゲート: AIエージェントがHTTP経由で自律的に支払う(USDC on Base)

環境変数(/etc/kkj-watch.env):
  X402_PAY_TO          受取アドレス(0x...)     ← これが無いと無効(free挙動のまま)
  X402_NETWORK         base | base-sepolia     (既定: base-sepolia)
  X402_PRICE_USD       1コール単価             (既定: 0.02)
  CDP_API_KEY_ID       CDPキー(mainnet base のverify/settleに必要)
  CDP_API_KEY_SECRET

依存: base-sepolia(テストネット)は標準ライブラリのみで動作。
      base(メインネット)はCDPファシリテータのJWT認証に PyJWT+cryptography が必要
      (VPS側: apt install python3-pip && pip install PyJWT cryptography)
"""
import base64
import json
import os
import time
import urllib.request

USDC = {
    "base": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "base-sepolia": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
}
# EIP-712ドメイン(オンチェーンのDOMAIN_SEPARATORと照合済み)
USDC_EIP712 = {
    "base": {"name": "USD Coin", "version": "2"},
    "base-sepolia": {"name": "USDC", "version": "2"},
}
FACILITATOR = {
    "base": "https://api.cdp.coinbase.com/platform/v2/x402",
    "base-sepolia": "https://x402.org/facilitator",
}

# CDPファシリテータは2026-07からCAIP-2形式のネットワークIDのみ受理
# (旧表記"base"はスキーマ400で拒否される)。Bazaar discoveryのインデックスも
# 同時期にx402Version 2/CAIP-2主体に移行しており(実測: 新規掲載の98.6%がV2)、
# V1表記のままの402応答は新規リソースとして掲載されない(既存の実測結果)。
# → 402応答・ファシリテータ通信の両方でV2/CAIP-2に正規化する。
CAIP2_NETWORK = {"base": "eip155:8453", "base-sepolia": "eip155:84532"}


def _caip2(net):
    return CAIP2_NETWORK.get(net or "", net or "")


def v2_requirements(req: dict) -> dict:
    """x402V2PaymentRequirements向け正規化: network=CAIP-2 + 'amount'必須
    (V1のmaxAmountRequiredと同値、両方保持してV1専用クライアントとの互換性も維持)。
    402応答・ファシリテータ通信の両方で使う。"""
    out = {**req, "network": _caip2(req.get("network"))}
    if "amount" not in out and out.get("maxAmountRequired"):
        out["amount"] = out["maxAmountRequired"]
    return out


def _v2_envelope(payment: dict, requirements: dict) -> dict:
    """CDPファシリテータ(2026-07以降)が受理するx402 V2エンベロープを組む。
    実測: V1形式(network='base')は外側スキーマで拒否、CAIP-2化だけの
    V1エンベロープは内側ルーティング(invalid_network)で拒否。
    V2 = CAIP-2 + requirements側'amount' + payload側'accepted'(選択条件のエコー)。
    EIP-3009署名はネットワーク文字列を含まないため変換は署名検証に影響しない。
    paymentPayload.resourceはBazaar掲載の必須条件(CDPはsettle成功時にこのURLで
    カタログ登録する。無いと決済は成功しても掲載されない — docs/実測で確認)。
    V2仕様のResourceInfoはオブジェクト{url,description,mimeType}であり、
    文字列を入れるとスキーマ400で拒否される(実測)。"""
    reqs2 = v2_requirements(requirements)
    pay2 = {
        "x402Version": 2,
        "scheme": payment.get("scheme", "exact"),
        "network": reqs2["network"],
        "payload": payment.get("payload"),
        "accepted": reqs2,
    }
    if reqs2.get("resource"):
        pay2["resource"] = {
            "url": reqs2["resource"],
            "description": reqs2.get("description", ""),
            "mimeType": reqs2.get("mimeType", "application/json"),
        }
    return {"x402Version": 2, "paymentPayload": pay2, "paymentRequirements": reqs2}


def config():
    return {
        "pay_to": os.environ.get("X402_PAY_TO", ""),
        "network": os.environ.get("X402_NETWORK", "base-sepolia"),
        "price_usd": float(os.environ.get("X402_PRICE_USD", "0.02")),
    }


def available() -> bool:
    return bool(config()["pay_to"])


def payment_requirements(resource_url: str, description: str, output_schema=None,
                         price_usd: float | None = None) -> dict:
    cfg = config()
    price = price_usd if price_usd is not None else cfg["price_usd"]
    req = {
        "scheme": "exact",
        "network": cfg["network"],
        "maxAmountRequired": str(int(round(price * 1_000_000))),  # USDC 6 decimals
        "resource": resource_url,
        "description": description,
        "mimeType": "application/json",
        "payTo": cfg["pay_to"],
        "maxTimeoutSeconds": 120,
        "asset": USDC[cfg["network"]],
        "extra": USDC_EIP712[cfg["network"]],
    }
    if output_schema:
        req["outputSchema"] = output_schema
    return req


def body_402(requirements: dict, error="X-PAYMENT header is required", free=None) -> dict:
    body = {"x402Version": 2, "error": error, "accepts": [v2_requirements(requirements)]}
    if free:
        body["free_alternatives"] = free   # 購入前に無料で価値を確認できる導線(要件3)
    return body


def _cdp_jwt(method: str, path: str) -> str:
    """CDPファシリテータ用JWT。旧型キー(EC DER→ES256)と新型キー(Ed25519→EdDSA)の
    両対応。PyJWT+cryptographyが必要(メインネットのみ)"""
    import jwt  # lazy import
    key_id = os.environ["CDP_API_KEY_ID"]
    secret = os.environ["CDP_API_KEY_SECRET"]
    now = int(time.time())
    claims = {
        "sub": key_id, "iss": "cdp",
        "nbf": now, "exp": now + 120,
        "uris": [f"{method} api.cdp.coinbase.com{path}"],
    }
    key = base64.b64decode(secret)
    try:
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        pk = load_der_private_key(key, password=None)
        alg = "ES256"
    except Exception:
        # 新型CDPキー: base64の生Ed25519(先頭32バイトがseed)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pk = Ed25519PrivateKey.from_private_bytes(key[:32])
        alg = "EdDSA"
    return jwt.encode(claims, pk, algorithm=alg,
                      headers={"kid": key_id, "nonce": os.urandom(8).hex()})


def _facilitator_post(endpoint: str, payload: dict) -> dict:
    cfg = config()
    base = FACILITATOR[cfg["network"]]
    url = f"{base}/{endpoint}"
    headers = {"Content-Type": "application/json"}
    if cfg["network"] == "base":
        path = url.split("api.cdp.coinbase.com", 1)[1]
        headers["Authorization"] = f"Bearer {_cdp_jwt('POST', path)}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # 4xx/5xxの本文(スキーマエラー詳細)を握りつぶさない
        detail = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"facilitator {endpoint} {e.code}: {detail}") from None


def verify_and_settle(x_payment_b64: str, requirements: dict):
    """X-PAYMENTヘッダを検証・決済。戻り値: (成功bool, X-PAYMENT-RESPONSE用b64 or エラーメッセージ)"""
    try:
        payment = json.loads(base64.b64decode(x_payment_b64))
    except Exception:
        return False, "invalid X-PAYMENT encoding"
    # base(メインネットCDP): V2エンベロープの素HTTP。x402 SDKは2026-07のCDP
    # スキーマ変更(V1拒否)に追従しておらず使わない。
    # base-sepolia(x402.orgテストネット): 従来のV1エンベロープ。
    cfg = config()
    if cfg["network"] == "base":
        envelope = _v2_envelope(payment, requirements)
    else:
        envelope = {
            "x402Version": 1,
            "paymentPayload": payment,
            "paymentRequirements": requirements,
        }
    try:
        v = _facilitator_post("verify", envelope)
        if not v.get("isValid"):
            return False, (f"verify failed: {v.get('invalidReason', 'unknown')}"
                           f" {v.get('invalidMessage', '')}").strip()
        s = _facilitator_post("settle", envelope)
        if not s.get("success"):
            return False, f"settle failed: {s.get('errorReason', s.get('error', 'unknown'))}"
        return True, base64.b64encode(json.dumps(s).encode()).decode()
    except Exception as e:
        # スキーマ不一致の原因切り分け用: クライアントが送ってきたpaymentPayloadの
        # 形(トップレベルのキーのみ、signature/authorizationの値は伏せる)を残す
        shape = {k: ("..." if k in ("payload",) else v) for k, v in payment.items()} \
            if isinstance(payment, dict) else str(type(payment))
        print(f"[x402_diag] verify_and_settle failed: {e} | payment_keys={shape} "
              f"| payload_keys={list(payment.get('payload', {}).keys()) if isinstance(payment, dict) and isinstance(payment.get('payload'), dict) else None}")
        return False, f"facilitator error: {e}"
