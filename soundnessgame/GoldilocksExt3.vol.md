# GoldilocksExt3.sol — Soundness Report

Now I have enough context to give a thorough analysis. Here is my report.

---

~~## 1. Nonresidue Not Verified Against Rust Prover (`Field64_3`)~~
> Skipped in round 1: Not a real issue: NONRESIDUE=2 is confirmed correct from WHIR Rust source (MontFp!("2") in fields.rs)

**Description**
The library declares the extension field as F_p[x] / (x³ − 2), hardcoding NONRESIDUE = 2 throughout the multiplication formula (and identically in `WhirLinearAlgebra.sol`). The Rust prover uses `whir::algebra::fields::Field64_3`. If the WHIR crate's `Field64_3` was compiled with a different irreducible polynomial — e.g. x³ − 7, which is the polynomial Plonky2 uses for its own `GoldilocksExt3` — every single extension-field multiplication in the Solidity verifier computes a different value than the prover intended.

**Affected code**
- Lines 8–9 (comment/polynomial declaration)
- Lines 93–94 (c0 formula: `2*(a1*b2 + a2*b1)`)
- Lines 97–98 (c1 formula: `2*a2*b2`)
- Every `mulmod(2, ...)` in `WhirLinearAlgebra.sol`

**Why this is a soundness concern**
All MLE evaluations, sumcheck round-polynomial evaluations, and WHIR folding challenges are computed over `Field64_3`. If the extension ring has a different multiplication table from what the prover used, the verifier's checks are evaluated on a completely different algebraic object. The verification equations would hold or fail independently of whether the underlying proof is valid, destroying the soundness guarantee.

**Suggested fix**
Locate the definition of `Field64_3` in the pinned WHIR commit (`df0470f`) and confirm `W = 2`. If the crate uses `W = 7` (or any other value), update every `mulmod(2, ...)` for the cross-terms to `mulmod(W, ...)` with the correct constant, and update the inv adjugate formulas accordingly.

---

~~## 2. Irreducibility of x³ − 2 Over GF(p) Not Established~~
> Skipped in round 1: Not a real issue: 2 IS a cubic non-residue over Goldilocks; FROBENIUS_COEFF_FP3_C1[1] = 4294967295 ≠ 1 confirms it

**Description**
For F_p[x]/(x³ − 2) to be a field (GF(p³)), 2 must be a cubic non-residue mod p = 2⁶⁴ − 2³² + 1. If 2^((p−1)/3) ≡ 1 (mod p) then 2 is a cubic residue, x³ − 2 factors over GF(p), and the quotient ring has zero divisors — it is **not** a field.

The Goldilocks prime has p − 1 = 2³² · (2³² − 1) = 2³² · 3 · 5 · 17 · 257 · 65537, so 3 ∣ (p − 1) and one-third of elements of GF(p)* are cubic residues. The Plonky2 project explicitly chose W = 7 after verifying 7 is a cubic non-residue; whether 2 is also a non-residue is an open arithmetic question that is never checked in this codebase.

**Affected code**
- Line 9 (polynomial declaration)
- Lines 93–101 (`mul` formula encodes x³ = 2)

**Why this is a soundness concern**
The security proofs for sumcheck and WHIR rely on the Schwartz-Zippel lemma, which requires the evaluation domain to be a field. If F_p[x]/(x³ − 2) ≅ F_p × F_p[x]/(g(x)) for some degree-2 factor g (or ≅ F_p × F_p × F_p), the ring has zero-divisors. An adversarial prover can exploit the ring's non-field structure to find witness values that satisfy the verification equations without a valid underlying statement, because the "polynomial identity testing" argument breaks.

The `inv` function does revert when norm = 0 (line 159–161), which is a correct safeguard, but it only papers over the symptom; the field assumption underlying the protocol is still violated.

**Suggested fix**
Compute 2^((p−1)/3) mod p offline (e.g. in Python: `pow(2, (p-1)//3, p)` where `p = 0xFFFFFFFF00000001`). If the result is 1, replace the nonresidue with a verified cubic non-residue. Add a deployment-time assertion or a constant-expression comment documenting the result of this check.

---

~~## 3. `fromBase` Silently Accepts Non-Canonical Inputs~~
> Fixed in round 1

**Description**
`fromBase(uint64 x)` stores `x` directly as `r.c0` without checking `x < P`. The value `x = P = 0xFFFFFFFF00000001` is a valid `uint64` (P < 2⁶⁴ − 1) and represents the field element 0 in non-canonical form.

**Affected code**
- Lines 30–32

**Why this is a soundness concern**
`isZero` and `eq` both use `% P` and handle this correctly. However, any code path that reads `c0` directly and compares it to 0 (e.g. `element.c0 == 0`) would incorrectly treat P as non-zero. If a higher-level verifier check performs such a raw comparison — for example, checking whether a folded evaluation equals zero — a prover could supply the value P instead of 0 to bypass the check without triggering `isZero`. The vulnerability depends on how callers use the struct, but the library itself creates the hazard by permitting silent non-canonical construction.

**Suggested fix**
Add a range assertion in `fromBase`:
```solidity
function fromBase(uint64 x) internal pure returns (Ext3 memory r) {
    require(x < uint64(P), "GoldilocksExt3: non-canonical");
    r.c0 = x;
}
```
Or canonicalize: `r.c0 = x < uint64(P) ? x : x - uint64(P);` (safe since the only non-canonical uint64 value ≥ P is P itself, as 2P > 2⁶⁴).
