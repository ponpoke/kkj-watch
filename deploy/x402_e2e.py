"""x402エンドツーエンドテスト(VPS上で /opt/kkj-watch/venv/bin/python で実行)

前提: /etc/kkj-watch.env に CDP_API_KEY_ID / CDP_API_KEY_SECRET / CDP_WALLET_SECRET
手順: (1)受取・支払い両ウォレットをCDPで作成 (2)テストネットfaucetでUSDC入手
      (3)X402_PAY_TO設定を出力 (4)x402クライアントで実際に支払ってデータ取得

使い方:
  venv/bin/python x402_e2e.py wallets     # ウォレット2つ作成(受取用/支払い用)
  venv/bin/python x402_e2e.py faucet      # 支払い用にbase-sepolia USDCを請求
  venv/bin/python x402_e2e.py pay <URL>   # x402支払い付きGET(例: https://.../paid/requirements/<key>)
"""
import asyncio
import json
import os
import sys

STATE = "/opt/kkj-watch/data/x402_test_wallets.json"


def load_env():
    for line in open("/etc/kkj-watch.env"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)


async def make_wallets():
    from cdp import CdpClient
    async with CdpClient() as cdp:
        recv = await cdp.evm.get_or_create_account(name="kkj-receiver")
        payer = await cdp.evm.get_or_create_account(name="kkj-test-payer")
        state = {"receiver": recv.address, "payer": payer.address}
        json.dump(state, open(STATE, "w"))
        print(json.dumps(state, indent=1))
        print("\n→ /etc/kkj-watch.env に追記してください:")
        print(f"X402_PAY_TO={recv.address}")
        print("X402_NETWORK=base-sepolia   # テスト後に base へ切替")


async def faucet():
    from cdp import CdpClient
    state = json.load(open(STATE))
    async with CdpClient() as cdp:
        for token in ("usdc", "eth"):
            try:
                r = await cdp.evm.request_faucet(
                    address=state["payer"], network="base-sepolia", token=token)
                print(f"faucet {token}: {r}")
            except Exception as e:
                print(f"faucet {token} failed: {e}")


async def pay(url: str):
    from cdp import CdpClient
    state = json.load(open(STATE))
    async with CdpClient() as cdp:
        account = await cdp.evm.get_or_create_account(name="kkj-test-payer")
        # x402 pythonクライアント: httpxベース
        import httpx
        from x402.clients.httpx import x402HttpxClient
        async with x402HttpxClient(account=account, base_url=url) as client:
            resp = await client.get(url)
            print("status:", resp.status_code)
            print("X-PAYMENT-RESPONSE:", resp.headers.get("X-PAYMENT-RESPONSE", "")[:80])
            body = await resp.aread()
            print(body.decode()[:1000])


def main():
    load_env()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "wallets"
    if cmd == "wallets":
        asyncio.run(make_wallets())
    elif cmd == "faucet":
        asyncio.run(faucet())
    elif cmd == "pay":
        asyncio.run(pay(sys.argv[2]))
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
