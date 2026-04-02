# DuplexSponge.sol — Soundness Report

Now I have enough context. Let me compile my findings from the thorough analysis.

---

~~## 1. `ratchet()` Silently Discards Pending Absorb Data Without Committing It~~
> Fixed in round 1

**Description:** When `ratchet()` is called with `absorbPos > 0`, any bytes already written to the rate portion (positions `0..absorbPos-1`) are zeroed out by the clearing loop before permutation. Those partially-absorbed bytes are never permuted into the capacity — they are simply discarded.

**Affected code:** `DuplexSponge.sol` lines 87–95

```solidity
function ratchet(Sponge memory s) internal pure {
    // Zero out the rate portion
    for (uint256 i = 0; i < RATE / 8; i++) {
        s.state.state[i] = 0;           // ← overwrites partial absorb data
    }
    LibKeccak.permutation(s.state);
    s.absorbPos = 0;
    s.squeezePos = RATE;
}
```

**Why this is a soundness concern:** In a Fiat-Shamir transcript, if the verifier calls `ratchet()` between two `absorb()` calls — even with only a partial amount of proof data absorbed — the pending message bytes are silently erased and never mixed into the hash state. A verifier that calls `ratchet` at a phase boundary while `absorbPos > 0` would derive challenges from a state that excluded those bytes, diverging from the prover's transcript. An adversary who could induce such a condition (e.g., by crafting transcript data that causes one absorb call to straddle a ratchet point) could produce different challenge values on-chain than the honest prover intended. There is no assertion or revert that catches the `absorbPos > 0` case.

**Suggested fix:** Assert before zeroing:
```solidity
require(s.absorbPos == 0, "DuplexSponge: ratchet with pending absorb");
```
or, if spongefish semantics permit, permute the pending absorb data into the state first before clearing the rate:
```solidity
if (s.absorbPos > 0) {
    LibKeccak.permutation(s.state);
    s.absorbPos = 0;
}
// then zero rate and permute again
```

---

~~## 2. Zero-Byte `squeeze()` Mutates `absorbPos` as a Side Effect~~
> Fixed in round 1

**Description:** `squeeze(s, 0)` unconditionally executes `s.absorbPos = 0` on line 66, even though no output is produced and no permutation fires. The loop body is never entered, but the absorb position is permanently reset.

**Affected code:** `DuplexSponge.sol` line 66

```solidity
function squeeze(Sponge memory s, uint256 n) internal pure returns (bytes memory output) {
    output = new bytes(n);
    s.absorbPos = 0; // ← fires even when n == 0
    ...
    while (outputPos < n) { ... }  // never entered when n == 0
}
```

**Why this is a soundness concern:** Any higher-level caller that calls `squeeze(s, 0)` as a no-op (e.g., to probe transcript length or as a conditional path that evaluates to zero bytes) will silently reset `absorbPos` to 0. If an absorb was in progress (`absorbPos > 0`), the next `absorb()` call will start overwriting state bytes from position 0, discarding the positional context of the previous partial absorb. Because the state bytes themselves are not cleared, the actual absorbed data remains in the sponge state, but the position cursor is out of sync — subsequent multi-call absorbs that cross this zero-squeeze will produce different sponge states than the Rust reference. This creates a transcript mismatch that could allow a crafted proof sequence to produce unexpected challenges.

**Suggested fix:** Guard the reset with the loop condition:
```solidity
if (n > 0) {
    s.absorbPos = 0;
}
```

---

~~## 3. `_writeStateBytes` / `_readStateBytes`: No Bounds Check on Caller-Supplied `inputOffset`~~
> Fixed in round 1

**Description:** Both internal helpers validate `stateOffset + len <= RATE` (lines 109, 130) but perform no check that `inputOffset + len <= input.length`. Access to `input[inputOffset + i]` relies entirely on Solidity's 0.8.x implicit bounds check, which reverts with a generic `Panic(0x32)` rather than an informative error.

**Affected code:** `_writeStateBytes` lines 109–119, `_readStateBytes` lines 130–137

**Why this is a soundness concern:** While a revert prevents state corruption, the absence of an explicit check means malformed or truncated proof data causes an opaque revert with no diagnostic information. More critically, if a future refactor relaxes the callers' preconditions (e.g., moves the `chunkLen` capping logic), an `inputOffset + len > input.length` condition would still revert, but via a different code path than intended. An explicit check makes the security boundary auditable and prevents any silent read of uninitialized memory if the compiler's behavior around dynamic arrays ever changes.

**Suggested fix:**
```solidity
require(inputOffset + len <= input.length, "DuplexSponge: input read out of bounds");
```
at the top of `_writeStateBytes`.
