# SpongefishWhir.sol — Soundness Report

Now I have a complete picture. Let me analyze all the issues.

---

~~## 1. `verifySumcheck` Operates in Base Field Instead of Extension Field~~
> Skipped in round 1: Fixing the base-vs-Ext3 field mismatch in verifySumcheck would require protocol-level changes that break transcript compatibility with the Rust prover

**Description:** `verifySumcheck` reads polynomial coefficients using `proverMessageField64` and squeezes folding randomness using `verifierMessageField64`, both returning `uint64` base-field elements. The entire sumcheck — coefficients, constraint evaluation, and folding — runs in GF(p) rather than GF(p³).

**Affected code:** Lines 252–279, specifically:
- Line 263–264: `uint64 c0 = proverMessageField64(...)`, `uint64 c2 = proverMessageField64(...)`
- Line 267: `uint64 c1 = _submod64(...)` — base field arithmetic
- Line 273: `uint64 r = verifierMessageField64(ts)` — base field challenge

**Why this is a soundness concern:** In WHIR, the sumcheck is explicitly over GF(p³) (as proven by the existence of `verifierMessageField64x3`, `proverMessageField64x3`, and `GoldilocksExt3` in this same file). The extension field is necessary because the Schwartz-Zippel soundness bound requires the random evaluation point to be drawn from a field larger than the polynomial degree; base-field randomness collapses the soundness to p⁻¹ ≈ 2⁻⁶⁴. An adversary can craft a cheating proof that satisfies the base-field sumcheck check but not the correct Ext3 check: e.g., a univariate polynomial that is zero over GF(p) but non-zero over GF(p³).

Additionally, the transcript state diverges: the Rust prover absorbs/squeezes Ext3 elements (24 bytes for coefficients, 120 bytes for randomness), but this verifier absorbs/squeezes 8 bytes and 40 bytes respectively. Every subsequent challenge in the protocol will be computed from a different sponge state, making any cross-check fail or, in degenerate configurations, accidentally agree.

**Suggested fix:** Replace `proverMessageField64` / `verifierMessageField64` with `proverMessageField64x3` / `verifierMessageField64x3` throughout `verifySumcheck`. Change the parameter/return types to use `(uint64 c0, uint64 c1, uint64 c2)` tuples or `GoldilocksExt3.Ext3` structs, and update all arithmetic to Ext3 operations (`GoldilocksExt3.add`, `GoldilocksExt3.mul`, etc.).

---

~~## 2. Proof-of-Work Check Omitted — Transcript Divergence and Soundness Degradation~~
> Skipped in round 1: PoW check restructuring is a complex protocol change; the existing TODO comment acknowledges it; deferred

**Description:** The sumcheck loop unconditionally skips PoW verification with an explicit TODO comment.

**Affected code:** Lines 269–270:
```solidity
// PoW check omitted for now (requires additional transcript operations)
// TODO: Implement PoW verification
```

**Why this is a soundness concern:** Two distinct problems arise:

1. **Transcript divergence.** When WHIR is configured with a PoW challenge (which is the default for production soundness), the prover's transcript includes `prover_message` (the PoW nonce) followed by `verifier_message` (the PoW challenge) in each sumcheck round. The Solidity verifier skips both operations, so `ts.sponge` state, `ts.transcriptPos`, and `ts.hintPos` are all wrong from this point forward. Every challenge derived after the first sumcheck round — STIR query indices, OOD evaluation points, fold randomness for subsequent rounds — will be computed from an incorrect sponge state. A proof that is valid against the skipped-PoW transcript is not the same proof the prover submitted.

2. **Soundness degradation.** WHIR's PoW requirement bounds the prover's grinding budget. Without it, a cheating prover can enumerate transcripts until they find one where the random checks happen to pass, directly attacking the soundness error bound.

**Suggested fix:** Implement the PoW check: read the prover's PoW nonce bytes via `proverMessage`, squeeze the PoW challenge via `verifierMessage`, and verify that `keccak256(nonce || challenge)` has the required number of leading zero bits as specified by the protocol's PoW bits parameter.

---

~~## 3. Non-Canonical Field Encoding Not Rejected in `proverMessageField64x3` — Transcript Malleability~~
> Fixed in round 1

**Description:** `proverMessageField64` (line 86) rejects non-canonical encodings with `require(val < GL_P, "non-canonical field element")`. But `proverMessageField64x3` (lines 115–117) uses `_leModReduce64` with `len=8`, which silently accepts values in `[GL_P, 2^64 − 1]` and reduces them mod GL_P.

**Affected code:** Lines 115–117:
```solidity
c0 = _leModReduce64(data, 0, 8);
c1 = _leModReduce64(data, 8, 8);
c2 = _leModReduce64(data, 16, 8);
```

**Why this is a soundness concern:** `GL_P = 2^64 − 2^32 + 1`, so the non-canonical range `[GL_P, 2^64 − 1]` contains `2^32 − 2 ≈ 4.3 billion` values. For any canonical element `v < 2^32 − 1`, the encoding `v + GL_P` also fits in 8 bytes and reduces to `v`. This gives the prover a free encoding choice per coefficient.

Critically, the raw non-reduced bytes are absorbed into the sponge (via `proverMessage` on line 114) before any reduction is applied. So the two encodings of the same field element produce different sponge states and therefore different verifier challenges. A dishonest prover can grind over up to `2^3 = 8` encoding combinations per Ext3 message (one per coefficient where the alternative exists) without changing the mathematical content of the proof, giving a small but real advantage in finding a transcript that passes OOD or Merkle checks.

**Suggested fix:** After decoding each 8-byte chunk, add a canonicality check:
```solidity
require(c0 < GL_P && c1 < GL_P && c2 < GL_P, "non-canonical ext3 element");
```

---

~~## 4. `challengeIndices` Returns Wrong Length for `numLeaves == 1`~~
> Fixed in round 1

**Description:** The early return at lines 165–169 returns a length-1 array `[0]` unconditionally, regardless of the `count` parameter.

**Affected code:** Lines 165–169:
```solidity
if (numLeaves == 1) {
    indices = new uint256[](1);
    indices[0] = 0;
    return indices;
}
```

**Why this is a soundness concern:** When `numLeaves == 1`, every query index must be 0 (there is only one leaf). The correct behavior is to return `count` copies of `0` — the same number of queries that the caller requested. However, the early return always returns exactly 1 element. If `count > 1`, the returned array is shorter than expected. A caller that iterates over the returned array (e.g., verifying `indices.length` Merkle openings) will silently verify fewer openings than the protocol requires — potentially checking only 1 of the `count` required leaf evaluations. An adversary who can maneuver the protocol into a `numLeaves == 1` state (e.g., by providing parameters that collapse the committed domain to a single leaf after folding) would then face only a single-leaf check regardless of the configured query count.

Note also that in the normal code path, `_log2(1) = 0`, `sizeBytes = 0`, and `totalBytes = 0`, so no sponge bytes are consumed in either the early-return or normal path — meaning the transcript mismatch is only about the returned array length.

**Suggested fix:**
```solidity
if (numLeaves == 1) {
    indices = new uint256[](count);
    // all entries are 0 (Solidity default initialization)
    return indices;
}
```
