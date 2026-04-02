# Keccak256Chain.sol — Soundness Report

~~## 1. Domain Separation Collision: `absorb` vs `ratchet`~~
> Skipped in round 1: Domain-separation collision not currently exploitable with the 8/32-byte absorb pattern in use; fixing would break Rust transcript compatibility

**Description:** The `absorb` function hashes `state || input` with no domain tag. When `input` is exactly the 7-byte string `"ratchet"` (`0x72617463686574`), the resulting hash is identical to calling `ratchet()`, since both compute `keccak256(state || "ratchet")` over 39 bytes.

**Affected code:** `absorb` (lines 23–42), `ratchet` (lines 99–112).

Specifically, `absorb` computes:
```
keccak256(scratch, totalLen)  // where totalLen = 32 + inputLen
```
And `ratchet` computes:
```
keccak256(scratch, 39)  // state(32) || "ratchet"(7)
```
When `inputLen == 7` and the input bytes equal `"ratchet"`, both compute exactly `keccak256(state || "ratchet")`.

**Why this is a soundness concern:** In the Fiat-Shamir transform, domain separation between prover-message absorption and protocol control operations (ratchet) is required to prevent transcript ambiguity. If a prover message can produce the same transcript state as a `ratchet()` call, the transcript is not injective over protocol positions. A prover that crafts a 7-byte commitment equal to `0x72617463686574` would cause the verifier's challenge derivation to proceed from a state indistinguishable from one reached via ratchet from a different position. The current protocol absorbs 8-byte field elements and 32-byte Merkle roots, so this collision is not presently triggerable—but any future use with 7-byte inputs breaks the invariant structurally.

**Suggested fix:** Add an absorb-specific domain tag. For example, prepend a single domain byte or use a distinct length encoding:
```solidity
// Option: prefix with 0x00 domain byte before state in the absorb hash
result := keccak256(absorb_tagged_scratch, totalLen)  // "absorb"(6) || state(32) || input
```
Alternatively, ensure `absorb` always prepends its own distinguishing tag (e.g., `0x01`) that neither `ratchet` (no tag) nor `squeeze` ("squeeze" prefix) can produce.

---

~~## 2. Domain Separation Collision: `absorb` vs `squeeze`~~
> Skipped in round 1: Same root cause as #1; fixing would diverge from the Rust spongefish transcript implementation

**Description:** By the same mechanism, when `inputLen == 15` and the 15-byte input equals `"squeeze" || counter_be` (7-byte tag followed by an 8-byte big-endian counter), `absorb` computes:
```
keccak256(state || "squeeze" || counter_be)   // 47 bytes
```
which is identical to the hash computed inside `squeeze` for the corresponding block (lines 60–65):
```solidity
let tagWord := or(shl(200, 0x73717565657a65), shl(136, counter))
mstore(add(scratch, 32), tagWord)
let h := keccak256(scratch, 47)
```

**Affected code:** `absorb` (lines 23–42), `squeeze`/`squeezeByte` (lines 47–96).

**Why this is a soundness concern:** A prover that absorbs a 15-byte message of the form `"squeeze" || \x00\x00\x00\x00\x00\x00\x00\x00` causes the new transcript state to equal the first squeeze output hash for counter 0. If the protocol subsequently derives a challenge by squeezing, the challenge seed is predictable—the state after `absorb("squeeze\x00\x00\x00\x00\x00\x00\x00\x00")` equals `keccak256(state || "squeeze\x00\x00\x00\x00\x00\x00\x00\x00")`, the same value produced by `squeeze` block 0. This can allow a malicious prover to choose commitments such that the verifier's squeeze output at a given counter is fixed and known before the commitment is sent. Again, current data widths (8-byte or 32-byte absorbs) don't trigger this, but it is a structural break in domain separation.

**Suggested fix:** Same as issue 1—add a distinct domain byte for `absorb`. This eliminates both collisions simultaneously since no other operation starts with that byte.

---

~~## 3. `squeezeByte` Computes Hash Before Overflow Guard~~
> Fixed in round 1

**Description:** In `squeezeByte`, the keccak256 hash is computed inside the assembly block (lines 83–93) and only then is the overflow check performed (line 94):
```solidity
assembly {
    // ... hash computed and result stored in b ...
    b := shr(248, h)  // line 92
}
require(counter + 1 <= type(uint64).max, "squeezeCounter overflow");  // line 94
s.squeezeCounter = uint64(counter + 1);  // line 95
```
In contrast, `squeeze` performs the overflow check before entering the assembly loop (line 53).

**Affected code:** Lines 80–96.

**Why this is a soundness concern:** When `counter == type(uint64).max`, the assembly computes `shl(136, 2^64 - 1)` in 256-bit arithmetic (placing the counter at bits 199–136) and hashes it, then the `require` reverts. The return value `b` is discarded by the revert, so no incorrect byte escapes. However, the 256-bit counter value used in the hash (`counter` is `uint256` in assembly) is not range-checked before use: if `s.squeezeCounter` were somehow set to a value exceeding `uint64.max` (possible via direct struct manipulation by a caller using inline assembly or low-level memory writes), the assembly would silently use the full 256-bit counter. This would produce hashes with bits overlapping the `"squeeze"` tag field (`shl(136, large_counter)` can set bits above position 199), corrupting the tag encoding and producing challenges inconsistent with the Rust transcript.

**Suggested fix:** Move the overflow check before the assembly block, matching `squeeze`'s pattern:
```solidity
require(counter + 1 <= type(uint64).max, "squeezeCounter overflow");
assembly {
    // ... compute hash ...
}
s.squeezeCounter = uint64(counter + 1);
```
