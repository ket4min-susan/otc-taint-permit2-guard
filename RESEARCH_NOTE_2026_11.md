# AI-Analyze-Dectect-Expoloit-System — Technical Research Note (`v2.6.11`)

**Author:** `ket4min-susan` / `memwm` (`memwmain@gmail.com`)  
**Module:** `onchain-forensics/otc-taint-and-calldata-inspector`  
**Live Telemetry Anchor:** `PAXG: $3900.97 | XAUT: $3876.2 (Basis: +$24.77) | BTC: $77893.11 | ETH: $2267.31 | SOL: $95.49`  

## 1. Empirical Context

Following the late-October 2026 **$6.3B CEX compromise** (lateral movement from an engineer workstation into signing infrastructure) and the on-chain freezing of **$2.3B in USDT/USDC** via `AddedBlackList(address)` / `Blacklisted(address)`, ~**$3.3B** in unfrozen exploit proceeds is actively fragmenting across peel chains and Southeast Asian off-exchange OTC desks.

Combined with Vietnam's Resolution `05/2025` and Decree `284/2026`, retail and institutional flow migrating off P2P orderbooks into unverified OTC settlement channels faces two high-severity technical vectors:

1. **Delayed Contract-Level Freeze via k-Hop Peel Chains (`Tainted-USDT-Injection`):** Discounted OTC inventory (`-3%` to `-7%` below par) carries upstream taint from exploit clusters or sanctioned regional liquidity pools. Touching a CEX deposit address within $k \in [1, 7]$ hops triggers automated KYT lockups, while reactive `addBlackList(address)` calls brick token transferability at the contract storage slot.
2. **Weaponized 'AML Check / OTC Escrow' Portals (`Permit2` & Allowance Hijack):** Counterparties request pre-settlement wallet verification via DApps that present a benign UI while encoding state-mutating allowance selectors in raw calldata.

## 2. Detection Invariants & Selector Signatures

```text
[Pre-Sign JSON-RPC / Counterparty Address]
   ├─► Engine A (Live Contract Blacklist & k-Hop Graph Inspector)
   │     ├─ eth_call 0xe47d6060 -> USDT.isBlackListed(address) [ETH: 0xdAC17F...]
   │     ├─ eth_call 0xfe575a87 -> USDC.isBlacklisted(address) [ETH: 0xA0b869... / Base: 0x833589...]
   │     └─ Directed k-hop taint decay score T(v) >= 0.015 -> Quarantine Gate Reject
   └─► Engine B (Calldata & EIP-712 AST Decompiler)
         ├─ 0x095ea7b3 : approve(address,uint256)
         ├─ 0x39509351 : increaseAllowance(address,uint256)
         ├─ 0xd73dd623 : increaseApproval(address,uint256)
         ├─ 0x2b67b570 : Permit2.permit(address,PermitSingle,bytes)
         └─ 0x30f28b7a : Permit2.permit(address,PermitBatch,bytes)
```

## 3. Protocol Audit Notes (Solidity & Rust State Machines)

- **ERC4626 Utilization Asymmetry (`revert-finance/v4lend`):** Calling `IERC4626.redeem(shares)` unconditionally inside hook force-exit paths (`RevertHookAutoLendActions.sol`) reverts with `ERC4626ExceededMaxRedeem` whenever vault utilization leaves `maxRedeem(address(this)) < shares`, bricking exit flows and dropping popped `TickLinkedList` triggers. Always clamp `sharesToRedeem = min(vault.maxRedeem(address(this)), shares)` and transfer residual vault shares directly.
- **Canonical Chain Continuity (`tari-project/tari`):** Base node state machines must verify canonical header continuity across both `sync_kernels` and `sync_utxos` prior to committing block diffs to prevent orphaned UTXO lock states.

## 4. Maintainer & Auditor Q&A Notes (`ERC4626`, `Tari Ootle CBOR`, `Go-Hybrid O8`, `Permit2`)

- **Why transfer residual `ERC4626` shares directly instead of queuing async withdrawal (`revert-finance/v4lend`):** Queuing an async withdrawal inside `afterRemoveLiquidity` traps user accounting inside the hook's internal share ledger and breaks atomic single-tx exit semantics. Clamping `redeemShares = min(vault.maxRedeem(address(this)), shares)` and transferring `shares - redeemShares` via `ERC20.transfer` delivers 100% of available underlying liquidity plus fungible vault shares for the illiquid tail at a warm `STATICCALL` cost of ~2,600 gas.
- **Why bound `MAX_CBOR_NESTING_DEPTH = 32` (`tari-project/tari-ootle#3231`):** Enforced before `IndexedWellKnownTypes::from_value` traverses nested `tari_bor::Value` trees on WASM return values and template args so a malicious guest WASM call cannot exhaust host stack frames prior to metered allocation charging.
- **Why reject conditional `map`/`slice`/`chan` moves across loop back-edges (`limitlessprojects/Go-Hybrid#2625/#2707`):** At the loop header join point, a conditional move on iteration `i` without definite re-initialization before the back-edge leaves the slot in a `MaybeMoved` state for iteration `i + 1`, violating the `O8` slot-loan invariant.