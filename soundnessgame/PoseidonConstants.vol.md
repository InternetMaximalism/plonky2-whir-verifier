# PoseidonConstants.sol — Soundness Report

Based on my thorough reading of the entire file, here are the findings:

---

~~## 1. `mdsDiag` Silently Returns 0 for Out-of-Bounds Indices~~
> Fixed in round 1

**Description:** `mdsDiag` (lines 35–38) lacks a `default { revert(0, 0) }` guard. For any `i >= 12` (i.e., outside the valid Goldilocks sponge width), it returns 0 instead of reverting.

**Affected code:** Lines 35–38
```solidity
function mdsDiag(uint256 i) internal pure returns (uint256) {
    if (i == 0) return 8;
    return 0;           // no revert for i >= SPONGE_WIDTH
}
```

**Why this is a soundness concern:** `mdsCirc` (lines 15–32) uses `default { revert(0, 0) }` to guard against bad indices. The inconsistency means off-by-one bugs in callers (e.g., a loop iterating `i = 0..12` instead of `i = 0..11`) propagate silently rather than aborting. An erroneously wide diagonal loop produces a subtly different MDS matrix, computing a hash that diverges from the canonical Goldilocks Poseidon permutation—allowing a prover to submit a Merkle proof valid against the corrupted hash function while being invalid against the correct one.

**Suggested fix:** Add a bounds check consistent with `mdsCirc`:
```solidity
function mdsDiag(uint256 i) internal pure returns (uint256) {
    require(i < SPONGE_WIDTH);   // or use assembly with default { revert(0, 0) }
    if (i == 0) return 8;
    return 0;
}
```

---

~~## 2. `wHat`, `vs`, and `initialMatrix` Index Aliasing Without Component Bounds Validation~~
> Fixed in round 1

**Description:** These three functions (lines 817–1065, 1067–1315, 1317–1444) compute a flat index as `idx = round * 11 + col` (or `row * 11 + col`) and then perform a switch on `idx`. Only the combined `idx` value is bounds-checked (via `default { revert(0, 0) }` at the maximum), not the individual `col`/`row` components.

**Affected code:** Lines 818, 1068, 1318
```solidity
uint256 idx = round * 11 + col;   // no check: col < 11
```

**Why this is a soundness concern:** Consider `wHat(0, 11)`: col=11 is out-of-bounds for a matrix with 11 columns, but the computed `idx = 11` is a valid case in the switch—it silently returns the value that belongs to `wHat(1, 0)`. More generally, any `col ∈ {11, ..., 21}` combined with an appropriate `round` still lands within the valid `[0, 241]` range, returning a constant from a completely different matrix entry with no revert. If a caller derives `col` from prover-supplied data (e.g., part of a proof transcript or witness) without independently clamping it to `[0, 10]`, an adversary can steer the partial-round linear layer to use arbitrary preselected constants from the table, producing a predictable but wrong hash that a malicious proof could be crafted to satisfy.

**Suggested fix:** Validate individual components before computing the flat index:
```solidity
function wHat(uint256 round, uint256 col) internal pure returns (uint256 val) {
    require(round < N_PARTIAL_ROUNDS && col < SPONGE_WIDTH - 1);
    uint256 idx = round * 11 + col;
    // ... switch ...
}
```

---

~~## 3. Zero Round Constant at `fastPartialRoundConstant(21)` — Last Partial Round Additive Identity~~
> Skipped in round 1: Intentionally zero: confirmed against Plonky2 Rust source FAST_PARTIAL_ROUND_CONSTANTS[21] = 0x0

**Description:** `fastPartialRoundConstant` (lines 788–815) returns `0x0000000000000000` for round index 21 (the last of 22 partial rounds). Zero is the additive identity in any field, so this round effectively has no constant addition on state[0].

**Affected code:** Line 812
```solidity
case 21 { val := 0x0000000000000000 }
```

**Why this is a soundness concern:** In the Poseidon specification, round constants are chosen to eliminate algebraic structure and ensure that no non-trivial annihilating polynomial for the full permutation can be found. A round with constant = 0 is structurally equivalent to omitting that round's AddRoundConstants step, which reduces the algebraic complexity slightly. If this zero is erroneous—i.e., the reference plonky2 implementation stores a non-zero value here—the on-chain verifier computes a different permutation than the off-chain prover, creating a mismatch. A more subtle risk: if a prover-side implementation also zeroes this constant (e.g., by reading from a table with the same bug), the two implementations agree on a weaker permutation that may have better-known algebraic attacks. The correctness of this zero should be verified against the canonical plonky2 `PoseidonGoldilocks` source constants (specifically `FAST_PARTIAL_ROUND_CONSTANTS[21]`).

**Suggested fix:** Cross-verify against plonky2's `src/hash/poseidon_goldilocks.rs` constant `FAST_PARTIAL_ROUND_CONSTANTS`. If that value is non-zero, this entry must be corrected. If it is genuinely zero by design (the last partial-round constant is folded into a subsequent full-round constant in the optimized schedule), add an explanatory comment to document the intent and prevent future "correction" to a wrong non-zero value.

---

~~## 4. Duplicate Constant Tables with No Cross-Validation~~
> Skipped in round 1: Code quality / redundancy only; no soundness impact

**Description:** The 360 round constants are encoded twice: as named `RC_0` through `RC_359` constants (lines 41–400) and again inside the `roundConstant(uint256 idx)` switch (lines 402–767). These two encodings must be bit-for-bit identical, but Solidity provides no mechanism to enforce this at compile time or runtime.

**Affected code:** Lines 41–400 vs. lines 402–767

**Why this is a soundness concern:** If a maintenance change updates the `RC_*` constants (e.g., a bug fix or parameter change) without updating the corresponding `roundConstant()` switch entries—or vice versa—two parts of the verifier will compute different round constant values. Code paths calling `RC_48` directly and code paths calling `roundConstant(48)` would compute divergent hash outputs for the same input, creating an inconsistent permutation. An adversary who can influence which code path is taken could exploit the divergence to find inputs that hash to the same value under one path but not the other, potentially forging Merkle membership proofs.

**Suggested fix:** Remove the duplication. Either use only the named constants with `roundConstant()` returning them via a lookup (e.g., an array initialized from the constants), or remove the `RC_*` declarations entirely and require all callers to go through `roundConstant()`. At minimum, add a Foundry test that asserts `roundConstant(i) == RC_i` for all `i ∈ [0, 359]`.
