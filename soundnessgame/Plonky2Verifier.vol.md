# Plonky2Verifier.sol — Soundness Report

Now I have a thorough picture. Let me analyze the complete file for soundness vulnerabilities.

---

~~## 1. CosetInterpolationGate: Intermediate Barycentric Constraints Hardcoded to Zero~~
> Skipped in round 1: Requires implementing Poseidon.hash() over public inputs to populate the correct wire values for the PublicInputGate; non-trivial and deferred

**Description:**
All intermediate constraints for `CosetInterpolationGate` are unconditionally set to `zero()` with a TODO comment acknowledging the omission. Only the final division check (`evalValue * lastProd - lastEval == 0`) is actually enforced.

**Affected code:** Lines 698–713
```solidity
for (uint256 i = 0; i < numIntermediates; i++) {
    // TODO: Full Barycentric interpolation constraint checking
    c[cIdx++] = GoldilocksExt2.zero();
    c[cIdx++] = GoldilocksExt2.zero();
    c[cIdx++] = GoldilocksExt2.zero();
    c[cIdx++] = GoldilocksExt2.zero();
}
```

**Why this is a soundness concern:**
The intermediate accumulators `intermediate_eval[i]` and `intermediate_prod[i]` (stored in non-routed wires) are never constrained. Since the only check is:
```
evalValue * lastProd - lastEval == 0
```
an attacker can freely choose any `lastEval` and `lastProd` and satisfy this final check for *any* `evalValue`. The prover can fabricate a CosetInterpolationGate opening that evaluates to an arbitrary value, breaking the polynomial binding at that gate. This completely subverts the interpolation gate's purpose — which is to commit a prover to a specific polynomial evaluation at a specific point.

**Suggested fix:**
Implement the full Barycentric interpolation recurrence using the weights from `gateConfig[4..4+numPoints-1]`. Each step should constrain:
```
eval_acc[i] = eval_acc[i-1] + weights[i] * values[i] / (evalPoint - coset_point[i]) * prod_acc[i-1]
prod_acc[i] = prod_acc[i-1] * (evalPoint - coset_point[i])
```
enforced as:
```
constraint: eval_acc[i] * (evalPoint - coset_point[i]) - (eval_acc[i-1] * (evalPoint - coset_point[i]) + weights[i] * values[i] * prod_acc[i-1]) = 0
```

---

~~## 2. `_reduceWithAlphas` Incorrectly Combines All Challenges' Terms Into Each Result~~
> Skipped in round 1: Requires significant refactor of gate dispatch and constraint aggregation; non-trivial and deferred

**Description:**
`_reduceWithAlphas` performs Horner reduction of the *entire* `allTerms` array (boundary terms for all challenges + permutation terms for all challenges + gate constraints) once per challenge. The result for challenge `i` should use only the terms belonging to challenge `i`, but instead picks up boundary and permutation terms from all other challenges.

**Affected code:** Lines 880–895 (reduction), and how `_computeAllVanishingTerms` assembles the flat array at lines 168–173.

In Plonky2, `vanishing[i]` must equal:
```
Horner([boundary[i], perm[i][0], ..., perm[i][k], gate[0], ..., gate[m]], alpha[i])
```
But the contract computes:
```
vanishing[i] = Horner([boundary[0], boundary[1], ..., perm[0][0], ..., perm[C-1][k], gate[0], ..., gate[m]], alpha[i])
```
where `C = numChallenges`. For `numChallenges > 1`, this adds `(numChallenges - 1)` extra boundary terms and all cross-challenge permutation terms to each result.

**Why this is a soundness concern:**
Because `quotientPolys` is prover-supplied, an attacker can choose quotient values to satisfy the *incorrect* combined equation without satisfying the actual per-challenge Plonky2 constraint equations. The combination error weakens the verification to a single polynomial identity over a mixed (invalid) basis, allowing proofs for incorrect witness values to pass.

**Suggested fix:**
Partition `allTerms` per challenge before reducing. Build one sub-array per challenge:
```solidity
GoldilocksExt2.Ext2[] memory termsI = [boundaryTerms[i], perm[i*numChunks..(i+1)*numChunks], gateTerms[0..numGateConstraints]];
result[i] = Horner(termsI, alpha[i]);
```

---

~~## 3. `PublicInputGate` Compares Wire Openings Directly Against Raw Public Inputs (No Poseidon Hash)~~
> Skipped in round 1: Requires implementing Poseidon hash of public inputs to construct the correct expected wire values; confirmed test_verifyConstraints_validProof fails with current code but fix is complex

**Description:**
`_evalPublicInputGate` checks `wire[i] == publicInputs[i]` directly against the caller-supplied `publicInputs` array without first computing `Poseidon(publicInputs)`.

**Affected code:** Lines 296–308
```solidity
GoldilocksExt2.Ext2 memory piVal = GoldilocksExt2.fromBase(
    i < publicInputs.length ? publicInputs[i] : 0
);
c[i] = openings.wires[i].sub(piVal);
```
The comment on line 296 correctly says `wire[i] - piHash[i] = 0`, acknowledging the expected value is a hash, but the code uses raw `publicInputs[i]` directly.

**Why this is a soundness concern:**
In Plonky2, the `PublicInputGate` constrains `wires[0..3]` to equal `Poseidon(public_inputs)` — a 4-element Goldilocks hash. The circuit computes this hash internally, and the gate serves as a commitment anchor. If the verifier instead checks `wires[0..3] == raw_public_inputs[0..3]`, the binding is broken in two ways:

1. An attacker who knows the 4-element Poseidon hash of the actual inputs can trivially supply `publicInputs = [hash[0], hash[1], hash[2], hash[3]]` (the hash itself, not the pre-image), causing the check to pass for any input.
2. If a circuit has more than 4 public inputs, only the first 4 raw field elements are checked — the rest are silently ignored, weakening the public input binding.

**Suggested fix:**
Compute the Poseidon hash of the full `publicInputs` array before comparison, producing 4 hash output elements, and compare those against `openings.wires[0..3]`:
```solidity
uint256[4] memory piHash = Poseidon.hash(publicInputs);
for (uint256 i = 0; i < 4; i++) {
    c[i] = openings.wires[i].sub(GoldilocksExt2.fromBase(piHash[i]));
}
```
