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
FACILITATOR = {
    "base": "https://api.cdp.coinbase.com/platform/v2/x402",
    "base-sepolia": "https://x402.org/facilitator",
}


def config():
    return {
        "pay_to": os.environ.get("X402_PAY_TO", ""),
        "network": os.environ.get("X402_NETWORK", "base-sepolia"),
        "price_usd": float(os.environ.get("X402_PRICE_USD", "0.02")),
    }


def available() -> bool:
    return bool(config()["pay_to"])


def payment_requirements(resource_url: str, description: str, output_schema=None) -> dict:
    cfg = config()
    req = {
        "scheme": "exact",
        "network": cfg["network"],
        "maxAmountRequired": str(int(cfg["price_usd"] * 1_000_000)),  # USDC 6 decimals
        "resource": resource_url,
        "description": description,
        "mimeType": "application/json",
        "payTo": cfg["pay_to"],
        "maxTimeoutSeconds": 120,
        "asset": USDC[cfg["network"]],
        "extra": {"name": "USDC", "version": "2"},
    }
    if output_schema:
        req["outputSchema"] = output_schema
    return req


def body_402(requirements: dict, error="X-PAYMENT header is required") -> dict:
    return {"x402Version": 1, "error": error, "accepts": [requirements]}


def _cdp_jwt(method: str, path: str) -> str:
    """CDPファシリテータ用JWT(ES256)。PyJWT+cryptographyが必要(メインネットのみ)"""
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
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    pk = load_der_private_key(key, password=None)
    return jwt.encode(claims, pk, algorithm="ES256", headers={"kid": key_id, "nonce": os.urandom(8).hex()})


def _facilitator_post(endpoint: str, payload: dict) -> dict:
    cfg = config()
    base = FACILITATOR[cfg["network"]]
    url = f"{base}/{endpoint}"
    headers = {"Content-Type": "application/json"}
    if cfg["network"] == "base":
        path = url.split("api.cdp.coinbase.com", 1)[1]
        headers["Authorization"] = f"Bearer {_cdp_jwt('POST', path)}"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read())


def _sdk_verify_settle(payment_dict: dict, req_dict: dict):
    """x402 SDK + CDP認証ファシリテータ(base / base-sepolia両対応)"""
    import x402
    from x402.http import HTTPFacilitatorClientSync
    from cdp.x402 import create_facilitator_config
    cfg = create_facilitator_config(
        os.environ["CDP_API_KEY_ID"], os.environ["CDP_API_KEY_SECRET"])
    fc = HTTPFacilitatorClientSync(cfg)
    payload = x402.parse_payment_payload(payment_dict)
    reqs = x402.PaymentRequirementsV1.model_validate(req_dict)
    v = fc.verify(payload, reqs)
    if not getattr(v, "is_valid", False):
        return False, f"verify failed: {getattr(v, 'invalid_reason', v)}"
    s = fc.settle(payload, reqs)
    if not getattr(s, "success", False):
        return False, f"settle failed: {getattr(s, 'error_reason', s)}"
    return True, base64.b64encode(
        s.model_dump_json(by_alias=True).encode()).decode()


def verify_and_settle(x_payment_b64: str, requirements: dict):
    """X-PAYMENTヘッダを検証・決済。戻り値: (成功bool, X-PAYMENT-RESPONSE用b64 or エラーメッセージ)"""
    try:
        payment = json.loads(base64.b64decode(x_payment_b64))
    except Exception:
        return False, "invalid X-PAYMENT encoding"
    # 第1候補: x402 SDK + CDPファシリテータ(要 venv実行 + CDPキー)
    if os.environ.get("CDP_API_KEY_ID"):
        try:
            return _sdk_verify_settle(payment, requirements)
        except ImportError:
            pass  # SDK無し → レガシー経路へ
        except Exception as e:
            return False, f"facilitator error: {e}"
    # 第2候補: 素のHTTP(x402.orgテストネットファシリテータ等)
    envelope = {
        "x402Version": 1,
        "paymentPayload": payment,
        "paymentRequirements": requirements,
    }
    try:
        v = _facilitator_post("verify", envelope)
        if not v.get("isValid"):
            return False, f"verify failed: {v.get('invalidReason', 'unknown')}"
        s = _facilitator_post("settle", envelope)
        if not s.get("success"):
            return False, f"settle failed: {s.get('errorReason', s.get('error', 'unknown'))}"
        return True, base64.b64encode(json.dumps(s).encode()).decode()
    except Exception as e:
        return False, f"facilitator error: {e}"
