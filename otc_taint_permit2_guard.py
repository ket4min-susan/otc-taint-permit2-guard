#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
otc-taint-permit2-guard — Sub-Second On-Chain USDT/USDC Blacklist & Permit2 Calldata Inspector
Author: ket4min-susan / memwm (memwmain@gmail.com)

1. Live Contract Blacklist Verification:
   - Ethereum Mainnet USDT (`0xdAC17F958D2ee523a2206206994597C13D831ec7`) `isBlackListed(address)` (`0xe47d6060`)
   - Ethereum Mainnet USDC (`0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`) `isBlacklisted(address)` (`0xfe575a87`)
   - Base Mainnet USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) `isBlacklisted(address)` (`0xfe575a87`)
2. Pre-Sign Calldata & EIP-712 Drainer Selector Disassembler:
   - Flags `approve`, `increaseAllowance`, `increaseApproval`, `Permit2.permit`, and `setApprovalForAll`
     selectors disguised as "OTC AML Wallet Verification" or "Web3 Escrow Check" portals.
"""

import json
import sys
import urllib.request
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ETH_RPC = "https://eth.llamarpc.com"
BASE_RPC = "https://mainnet.base.org"

USDT_ETH = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDC_ETH = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

DANGEROUS_SELECTORS = {
    "0x095ea7b3": "ERC20.approve(address,uint256) — UNLIMITED SPEND APPROVAL DRAINER",
    "0x39509351": "ERC20.increaseAllowance(address,uint256) — ALLOWANCE ESCALATION DRAINER",
    "0xd73dd623": "USDT.increaseApproval(address,uint256) — LEGACY USDT ALLOWANCE DRAINER",
    "0xd505accf": "EIP2612.permit(...) — GASLESS SIGNATURE DRAINER",
    "0x2b67b570": "Permit2.permit(address,PermitSingle,bytes) — UNISWAP PERMIT2 SINGLE DRAINER",
    "0x30f28b7a": "Permit2.permit(address,PermitBatch,bytes) — UNISWAP PERMIT2 BATCH DRAINER",
    "0xa22cb465": "ERC721/1155.setApprovalForAll(address,bool) — FULL COLLECTION OPERATOR HIJACK",
}


def eth_call_bool(rpc_url: str, contract: str, selector_4byte: str, wallet_address: str) -> bool:
    clean_addr = wallet_address.lower().replace("0x", "").rjust(64, "0")
    data = selector_4byte + clean_addr
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": contract, "data": data}, "latest"],
    }
    try:
        req = urllib.request.Request(
            rpc_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "otc-taint-permit2-guard/2.6.11"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            res = json.loads(resp.read().decode("utf-8"))
            hex_val = res.get("result", "0x0")
            return int(hex_val, 16) != 0 if hex_val and hex_val != "0x" else False
    except Exception:
        return False


def check_address_blacklist_status(wallet_address: str) -> dict:
    usdt_eth_blacklisted = eth_call_bool(ETH_RPC, USDT_ETH, "0xe47d6060", wallet_address)
    usdc_eth_blacklisted = eth_call_bool(ETH_RPC, USDC_ETH, "0xfe575a87", wallet_address)
    usdc_base_blacklisted = eth_call_bool(BASE_RPC, USDC_BASE, "0xfe575a87", wallet_address)

    is_tainted = any([usdt_eth_blacklisted, usdc_eth_blacklisted, usdc_base_blacklisted])
    return {
        "address": wallet_address,
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "usdt_eth_blacklisted": usdt_eth_blacklisted,
        "usdc_eth_blacklisted": usdc_eth_blacklisted,
        "usdc_base_blacklisted": usdc_base_blacklisted,
        "verdict": "REJECT_TAINTED_BLACKLISTED" if is_tainted else "CLEAN_ON_CONTRACT_BLACKLISTS",
    }


def inspect_calldata_for_drainer(raw_calldata: str) -> dict:
    clean = raw_calldata.strip().lower()
    if not clean.startswith("0x"):
        clean = "0x" + clean
    selector = clean[:10]
    warning = DANGEROUS_SELECTORS.get(selector)
    if warning:
        spender = "0x" + clean[34:74] if len(clean) >= 74 else "unknown"
        return {
            "safe": False,
            "selector": selector,
            "threat_detected": warning,
            "extracted_spender_or_target": spender,
            "action": "BLOCK_IMMEDIATELY — DO NOT SIGN THIS TRANSACTION!",
        }
    return {
        "safe": True,
        "selector": selector,
        "threat_detected": None,
        "action": "No known allowance/Permit2 drainer selector matched.",
    }


if __name__ == "__main__":
    target_addr = sys.argv[1] if len(sys.argv) > 1 else "0x5754284f345afc66a98fbb0a0afe71e0f007b949"
    report = {
        "address_blacklist_audit": check_address_blacklist_status(target_addr),
        "sample_drainer_simulation": inspect_calldata_for_drainer(
            "0x095ea7b3000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
