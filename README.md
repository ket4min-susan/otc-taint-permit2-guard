# `otc-taint-permit2-guard` (`v2.6.11`)

Sub-second on-chain **USDT/USDC contract blacklist verifier** and **pre-sign EIP-712 `Permit2` / ERC20 allowance drainer calldata disassembler** for off-exchange OTC settlement.

See **[`RESEARCH_NOTE_2026_11.md`](./RESEARCH_NOTE_2026_11.md)** for the full technical analysis on multi-hop peel-chain taint propagation and malicious OTC escrow portals following the October 2026 `$6.3B` CEX breach.

## Core Capabilities

1. **Live Contract Storage Blacklist Verification (`Engine A`):**
   - Queries Ethereum Mainnet `USDT` (`0xdAC17F958D2ee523a2206206994597C13D831ec7`) selector `0xe47d6060` (`isBlackListed(address)`).
   - Queries Ethereum Mainnet `USDC` (`0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`) and Base `USDC` (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) selector `0xfe575a87` (`isBlacklisted(address)`).
2. **Pre-Sign Calldata & Permit2 Selector Disassembler (`Engine B`):**
   - Blocks state-mutating allowance hijack calls (`0x095ea7b3` `approve`, `0x39509351` `increaseAllowance`, `0xd73dd623` `increaseApproval`, `0x2b67b570` `Permit2.permit(PermitSingle)`, `0x30f28b7a` `Permit2.permit(PermitBatch)`) disguised as OTC "AML Check" web portals.

## Usage

```bash
python otc_taint_permit2_guard.py 0xCounterpartyOrDepositAddress
```
