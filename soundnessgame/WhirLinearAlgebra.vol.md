# WhirLinearAlgebra.sol — Soundness Report

Now I have enough context. Here is my analysis of `WhirLinearAlgebra.sol`:

---

~~## 1. `mleEvaluateEq` Assembly Silently Truncates on Length Mismatch — `require` Is the Sole Soundness Barrier~~
> Fixed in round 1

**Description:**
The Solidity `require` enforces equal array lengths, but the assembly block immediately recomputes `n = min(pLen, epLen)` and uses that silently:

```solidity
require(point.length == evalPoint.length, "mleEvaluateEq: length mismatch");
assembly {
    let n := pLen
    if lt(epLen, n) { n := epLen }   // silently truncates
```

The assembly does NOT re-enforce the equal-length contract; it just uses the shorter one. If the `require` were removed or bypassed (e.g., via a future refactor, a delegatecall path, or an inline-assembly caller that skips the Solidity wrapper), the eq polynomial would be evaluated over only a prefix of the variables.

**Affected lines:** 174, 181–184

**Why this is a soundness concern:**
The WHIR sumcheck binding check (`line 433` of SpongefishWhirVerify.sol: `require(GoldilocksExt3.eq(linearFormRlc, eqVal), ...)`) depends on `mleEvaluateEq` checking ALL variables of the evaluation point. If only the first `k < n` variables are checked, an attacker can choose the remaining `n - k` coordinates of `point` arbitrarily, collapsing a higher-dimensional equality check to a lower-dimensional one. This destroys the binding guarantee of WHIR.

**Suggested fix:**
Remove the `if lt(epLen, n)` branch inside the assembly block entirely, or add an explicit assembly-level revert:

```assembly
let n := pLen
if iszero(eq(pLen, epLen)) { revert(0, 0) }
```

This makes the assembly self-enforcing, so the soundness check does not rely solely on the Solidity-layer `require`.

---

~~## 2. Same Truncation Pattern in `mleEvaluateEqCanonical`~~
> Fixed in round 1

**Description:**
Identical issue at lines 117–118:

```assembly
let n := numVariables
if lt(epLen, n) { n := epLen }
```

If `evalPoint.length < numVariables`, assembly uses `epLen` instead of `numVariables`, silently computing the eq product over fewer variables. The Solidity `require(evalPoint.length >= numVariables, ...)` is again the sole protection.

**Affected lines:** 109, 117–118

**Why this is a soundness concern:**
In the protocol (`SpongefishWhirVerify.sol:414`), this is the fall-through path when no explicit evaluation point is provided. A prover submitting a truncated `allFoldingRandomness` array could cause fewer eq factors to be checked, reducing the polynomial evaluation to a lower-dimensional version that is easier to satisfy fraudulently.

**Suggested fix:**
Same as Issue 1 — add an assembly-level revert instead of a min:

```assembly
if lt(epLen, numVariables) { revert(0, 0) }
let n := numVariables
```

---

~~## 3. Missing Input Validation for `start` in `mleEvaluateUnivariateFrom` — Silent Identity Return~~
> Fixed in round 1

**Description:**
The function takes an unchecked `start` parameter. If `start >= point.length`, the loop condition `gt(len, start)` is false from the first iteration, and the function returns `(1, 0, 0)` (the identity element) without processing any variables:

```assembly
// start=100, len=5 → gt(5,100) = false → loop never executes → returns 1
for { let i := len } gt(i, start) { i := sub(i, 1) } {
```

**Affected lines:** 24–28, 45

**Why this is a soundness concern:**
In `SpongefishWhirVerify.sol:354–358`, `start` is computed as `totalFoldingLen - numVariables`. If `numVariables` were larger than `totalFoldingLen` (a caller precondition that is not validated in `mleEvaluateUnivariateFrom` itself), the function silently returns 1. An attacker able to influence `numVariables` (it comes from the proof structure) to exceed `totalFoldingLen` would cause the MLE evaluation to pass through as 1 regardless of the claimed value. The subsequent linear-form check at line 433 would then verify `linearFormRlc == eqVal * initialLinearFormRlcSum`, with the MLE contribution effectively zeroed out.

**Suggested fix:**
Add an explicit bounds check:

```solidity
require(start <= point.length, "mleEvaluateUnivariateFrom: start out of bounds");
```

Or inside the assembly, add:

```assembly
if gt(start, len) { revert(0, 0) }
```

---

~~## 4. Non-Canonical Intermediate Representation `omr1 = p` When Input Extension Component is Zero~~
> Fixed in round 1

**Description:**
Throughout all hot-path functions, the negation of an extension component is computed as:

```assembly
let omr1 := sub(p, addmod(r1, 0, p))
```

When `r1 = 0`, `addmod(0, 0, p) = 0` and `sub(p, 0) = p = 0xFFFFFFFF00000001`. So `omr1 = p`, which represents 0 mod p but is not in the canonical range `[0, p-1]`.

**Affected lines:** 55–56, 140–141, 208–209, 271–274, 328–330

**Why this is a soundness concern:**
Currently, all uses of `omr1`/`omr2` pass through `mulmod(..., omr1, p)` or `addmod(omr1, ..., p)`, both of which correctly reduce mod `p` (e.g., `mulmod(x, p, p) = 0`). So the current code produces correct results. However:

1. If `omr1` or `omr2` were ever stored to memory or returned without going through `mulmod`/`addmod` first (e.g., as part of a future refactor that inlines or caches negated values), the non-canonical representation would corrupt subsequent arithmetic.
2. Any equality comparison against `omr1` (e.g., `iszero(omr1)`) would return false when it should return true (since `p != 0`).

**Suggested fix:**
Use `addmod` for the subtraction itself to guarantee canonical output:

```assembly
let omr1 := addmod(sub(p, addmod(r1, 0, p)), 0, p)
```

Or equivalently, canonicalize with a conditional:

```assembly
let ri1red := addmod(r1, 0, p)
let omr1 := mul(iszero(iszero(ri1red)), sub(p, ri1red))
```

This matches the pattern already used in `GoldilocksExt3.neg()` (lines 71–74 of GoldilocksExt3.sol).
