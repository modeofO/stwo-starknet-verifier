"""L1 leg of the integration qm31 campaign: claim the alpha STRK withdrawal,
then deposit it through the integration StarkGate bridge to the counterfactual
L2 account.

Usage: l1_leg.py {claimable|run} [amount_strk]

  claimable  exit 0 if the alpha withdrawal of amount_strk (default 10) is
             claimable on L1 (state update has landed), exit 1 otherwise.
             Uses eth_call as the oracle.
  run        claim -> approve -> deposit for amount_strk, printing each tx hash.

Keys come from ~/.config/qm31-integration/keys.json (l1_private_key funds gas;
l2_account_address receives the deposit on integration-sepolia).

Bridge interfaces established 2026-07-29 by bytecode selector probing:
  alpha STRK bridge  0xcE5485..  StarknetERC20Bridge_2.0_4   withdraw(address,uint256,address)
  integr STRK bridge 0x6FE45B..  StarknetERC20Bridge_2023_1  deposit(uint256,uint256) payable
"""
import json
import pathlib
import sys

from web3 import Web3

RPC = "https://ethereum-sepolia-rpc.publicnode.com"
L1_STRK = "0xCa14007Eff0dB1f8135f4C25B34De49AB0d42766"
ALPHA_BRIDGE = "0xcE5485Cfb26914C5dcE00B9BAF0580364daFC7a4"
INTEGRATION_BRIDGE = "0x6FE45BEFC2C0E0F619D5ccFB6fA4D40590f6bC53"
AMOUNT = int(sys.argv[2]) * 10**18 if len(sys.argv) > 2 else 10 * 10**18
DEPOSIT_MSG_FEE = 10**15  # 0.001 ETH for the L1->L2 message

keys = json.loads((pathlib.Path.home() / ".config/qm31-integration/keys.json").read_text())
w3 = Web3(Web3.HTTPProvider(RPC))
acct = w3.eth.account.from_key(keys["l1_private_key"])
l2_recipient = int(keys["l2_account_address"], 16)

erc20 = w3.eth.contract(
    address=Web3.to_checksum_address(L1_STRK),
    abi=[
        {"name": "approve", "type": "function", "stateMutability": "nonpayable",
         "inputs": [{"name": "spender", "type": "address"}, {"name": "amount", "type": "uint256"}],
         "outputs": [{"type": "bool"}]},
        {"name": "balanceOf", "type": "function", "stateMutability": "view",
         "inputs": [{"name": "owner", "type": "address"}], "outputs": [{"type": "uint256"}]},
    ],
)
alpha_bridge = w3.eth.contract(
    address=Web3.to_checksum_address(ALPHA_BRIDGE),
    abi=[{"name": "withdraw", "type": "function", "stateMutability": "nonpayable",
          "inputs": [{"name": "token", "type": "address"}, {"name": "amount", "type": "uint256"},
                     {"name": "recipient", "type": "address"}], "outputs": []}],
)
integration_bridge = w3.eth.contract(
    address=Web3.to_checksum_address(INTEGRATION_BRIDGE),
    abi=[{"name": "deposit", "type": "function", "stateMutability": "payable",
          "inputs": [{"name": "amount", "type": "uint256"}, {"name": "l2Recipient", "type": "uint256"}],
          "outputs": []}],
)

withdraw_call = alpha_bridge.functions.withdraw(
    Web3.to_checksum_address(L1_STRK), AMOUNT, acct.address
)


def is_claimable():
    try:
        withdraw_call.call({"from": acct.address})
        return True
    except Exception:
        return False


def send(fn, value=0):
    tx = fn.build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address),
        "gasPrice": int(w3.eth.gas_price * 1.5),
        "value": value,
        "chainId": 11155111,
    })
    signed = acct.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(h, timeout=300)
    status = "ok" if receipt.status == 1 else "REVERTED"
    print(f"{fn.fn_name}: {h.hex()} [{status}]")
    if receipt.status != 1:
        sys.exit(f"transaction reverted: {h.hex()}")
    return receipt


cmd = sys.argv[1]
if cmd == "claimable":
    ok = is_claimable()
    print("claimable" if ok else "not yet claimable")
    sys.exit(0 if ok else 1)
elif cmd == "run":
    if not is_claimable():
        sys.exit("withdrawal not claimable yet")
    send(withdraw_call)
    print(f"L1 STRK balance: {erc20.functions.balanceOf(acct.address).call() / 1e18} STRK")
    send(erc20.functions.approve(Web3.to_checksum_address(INTEGRATION_BRIDGE), AMOUNT))
    send(integration_bridge.functions.deposit(AMOUNT, l2_recipient), value=DEPOSIT_MSG_FEE)
    print(f"deposited {AMOUNT / 1e18} STRK -> integration L2 {hex(l2_recipient)}")
