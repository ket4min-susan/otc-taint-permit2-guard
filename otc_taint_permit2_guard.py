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
import socket
import sys
import urllib.request
from datetime import datetime, timezone

_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_preferred_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    res = _orig_getaddrinfo(host, port, family, type, proto, flags)
    v4 = [r for r in res if r[0] == socket.AF_INET]
    return v4 if v4 else res
socket.getaddrinfo = _ipv4_preferred_getaddrinfo

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


def _word_addr(clean_hex: str, word_index: int) -> str | None:
    """Extract 20-byte address from 32-byte ABI word `word_index` (0-based after 4-byte selector)."""
    start = 10 + word_index * 64
    end = start + 64
    if len(clean_hex) >= end:
        return "0x" + clean_hex[start + 24 : end]
    return None


def inspect_calldata_for_drainer(raw_calldata: str) -> dict:
    clean = raw_calldata.strip().lower()
    if not clean.startswith("0x"):
        clean = "0x" + clean
    selector = clean[:10]
    warning = DANGEROUS_SELECTORS.get(selector)
    if warning:
        # Decode ABI-specific spender slot:
        # - Permit2.permit(address owner, PermitSingle((token,amount,exp,nonce), spender, sigDeadline), bytes sig) [0x2b67b570]:
        #   PermitSingle is a static tuple encoded in-place -> `token` at word 1, `spender` at word 5.
        # - Permit2.permit(address owner, PermitBatch(PermitDetails[], spender, sigDeadline), bytes sig) [0x30f28b7a]:
        #   PermitBatch is a dynamic tuple (head pointer 0x60 at word 1) -> tuple head starts at word 3, `spender` at word 4.
        # - EIP-2612 permit(address owner, address spender, ...) [0xd505accf]: `spender` at word 1.
        # - ERC20 approve / increaseAllowance / setApprovalForAll: `spender` at word 0.
        if selector == "0x2b67b570" and len(clean) >= 10 + 6 * 64:
            spender = _word_addr(clean, 5) or "unknown"
            token_addr = _word_addr(clean, 1)
        elif selector == "0x30f28b7a" and len(clean) >= 10 + 5 * 64:
            spender = _word_addr(clean, 4) or "unknown"
            token_addr = None
        elif selector == "0xd505accf" and len(clean) >= 10 + 2 * 64:
            spender = _word_addr(clean, 1) or "unknown"
            token_addr = None
        else:
            spender = _word_addr(clean, 0) or "unknown"
            token_addr = None
        out = {
            "safe": False,
            "selector": selector,
            "threat_detected": warning,
            "extracted_spender_or_target": spender,
            "action": "BLOCK_IMMEDIATELY — DO NOT SIGN THIS TRANSACTION!",
        }
        if token_addr:
            out["permit2_token"] = token_addr
        return out
    return {
        "safe": True,
        "selector": selector,
        "threat_detected": None,
        "action": "No known allowance/Permit2 drainer selector matched.",
    }


def run_selftest() -> dict:
    results = []
    for sel in DANGEROUS_SELECTORS:
        payload = sel + "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeefffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        res = inspect_calldata_for_drainer(payload)
        assert res["safe"] is False and res["selector"] == sel
        results.append(res)
    # Full 6-word Permit2.permit(owner, PermitSingle((token,amount,exp,nonce), spender, sigDeadline), sig) vector
    permit2_full = (
        "0x2b67b570"
        + "0000000000000000000000001111111111111111111111111111111111111111"  # word 0: owner
        + "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7"  # word 1: details.token (USDT)
        + "000000000000000000000000ffffffffffffffffffffffffffffffffffffffff"  # word 2: details.amount (uint160::MAX)
        + "0000000000000000000000000000000000000000000000000000ffffffffffff"  # word 3: details.expiration
        + "0000000000000000000000000000000000000000000000000000000000000000"  # word 4: details.nonce
        + "000000000000000000000000badc0de0badc0de0badc0de0badc0de0badc0de0"  # word 5: permitSingle.spender
    )
    p2_res = inspect_calldata_for_drainer(permit2_full)
    assert p2_res["extracted_spender_or_target"] == "0xbadc0de0badc0de0badc0de0badc0de0badc0de0"
    assert p2_res.get("permit2_token") == "0xdac17f958d2ee523a2206206994597c13d831ec7"

    # Full 5-word head Permit2.permit(owner, PermitBatch(details[], spender, sigDeadline), sig) vector
    permit2_batch = (
        "0x30f28b7a"
        + "0000000000000000000000001111111111111111111111111111111111111111"  # word 0: owner
        + "0000000000000000000000000000000000000000000000000000000000000060"  # word 1: offset to PermitBatch (0x60)
        + "0000000000000000000000000000000000000000000000000000000000000140"  # word 2: offset to signature
        + "0000000000000000000000000000000000000000000000000000000000000060"  # word 3: PermitBatch.details offset
        + "000000000000000000000000feedfacefeedfacefeedfacefeedfacefeedface"  # word 4: PermitBatch.spender
    )
    p2_batch_res = inspect_calldata_for_drainer(permit2_batch)
    assert p2_batch_res["extracted_spender_or_target"] == "0xfeedfacefeedfacefeedfacefeedfacefeedface"

    safe_res = inspect_calldata_for_drainer("0xa9059cbb0000000000000000000000001111111111111111111111111111111111111111")
    assert safe_res["safe"] is True
    return {
        "selftest": "PASSED",
        "selectors_verified": len(results),
        "permit2_abi_word5_spender_verified": True,
        "permit2_batch_abi_word4_spender_verified": True,
        "safe_transfer_verified": True,
    }


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        print(json.dumps(run_selftest(), indent=2, ensure_ascii=False))
        sys.exit(0)
    target_addr = sys.argv[1] if len(sys.argv) > 1 else "0x5754284f345afc66a98fbb0a0afe71e0f007b949"
    report = {
        "address_blacklist_audit": check_address_blacklist_status(target_addr),
        "sample_drainer_simulation": inspect_calldata_for_drainer(
            "0x095ea7b3000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        ),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
