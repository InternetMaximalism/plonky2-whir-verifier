# WHIR-Plonky2 Verifier: Cryptographic Construction

## Overview

This document describes the complete cryptographic construction for replacing Plonky2's FRI-based polynomial commitment scheme with WHIR, achieving post-quantum security via hash-based commitments.

The system proves: "A Plonky2 circuit computation is correct" using:
1. **WHIR** — hash-based polynomial commitment (replaces FRI)
2. **Sumcheck bridge** — binds WHIR's MLE evaluation to univariate polynomial evaluation
3. **Decomposition chain** — binds individual polynomial openings to the WHIR commitment
4. **Plonky2 constraint check** — verifies circuit satisfaction at the evaluation point

All cryptographic operations use Keccak-256, providing post-quantum security.

---

## 1. Field Parameters

### Goldilocks Base Field

```
p = 2^64 - 2^32 + 1 = 0xFFFFFFFF00000001 = 18446744069414584321
```

All base field arithmetic is modulo p. Elements are represented as u64.

### Quadratic Extension (Ext2) — Circuit Internal

Used internally by Plonky2 circuits (extension degree D=2):

```
F_{p^2} = F_p[alpha] / (alpha^2 - 7)
```

- Elements: (c0, c1) representing c0 + c1 * alpha
- Non-residue W = 7
- Multiplication: (a0 + a1*alpha)(b0 + b1*alpha) = (a0*b0 + 7*a1*b1) + (a0*b1 + a1*b0)*alpha
- |F_{p^2}| ~ 2^128

### Cubic Extension (Ext3) — Evaluation Domain

Used for all evaluation-point arithmetic and on-chain verification:

```
F_{p^3} = F_p[x] / (x^3 - 2)
```

- Elements: (c0, c1, c2) representing c0 + c1*x + c2*x^2
- Non-residue = 2 (x^3 = 2)
- Multiplication:
  - r0 = a0*b0 + 2*(a1*b2 + a2*b1)
  - r1 = a0*b1 + a1*b0 + 2*a2*b2
  - r2 = a0*b2 + a1*b1 + a2*b0
- |F_{p^3}| ~ 2^192

### Circuit Extension over Ext3 (Ext2-over-Ext3)

Plonky2's D=2 circuit extension elements, when evaluated at zeta in Ext3, become pairs of Ext3 values with Ext2 arithmetic (W=7):

```
(a0, a1) * (b0, b1) = (a0*b0 + 7*a1*b1, a0*b1 + a1*b0)
```

where a0, a1, b0, b1 are each Ext3 elements, and *, + are Ext3 operations.

---

## 2. Protocol Flow

### High-Level Architecture

```
Plonky2 Circuit Proof
  |
  v
[Phase 1] WHIR Commitment (Merkle tree over polynomial coefficients)
  |
  v
[Phase 2] Challenge Derivation (Keccak from Merkle root)
  |        -> betas, gammas, alphas, zeta (Ext3)
  |        -> g*zeta (shifted evaluation point)
  v
[Phase 3] Dual Sumcheck Bridges
  |        Bridge #1: <f, h_zeta> = P(zeta)    -> point r1
  |        Bridge #2: <f, h_{g*zeta}> = P(g*zeta) -> point r2
  v
[Phase 4] WHIR Evaluation Proof (dual-point: r1 and r2)
  |        Proves: f(r1) = v1, f(r2) = v2
  v
[Phase 5] Binding Verification (on-chain)
  |        f(r1) * h_zeta(r1) == finalClaim1
  |        f(r2) * h_{g*zeta}(r2) == finalClaim2
  v
[Phase 6] Inter-Batch Decomposition
  |        P(zeta) = batch_0(zeta) + zeta^d0 * batch_1(zeta) + ...
  |        P(g*zeta) = batch_0(g*zeta) + (g*zeta)^d0 * batch_1(g*zeta) + ...
  v
[Phase 7] Intra-Batch Sub-Decomposition
  |        batch_i(zeta) = poly_0(zeta) + zeta^N * poly_1(zeta) + ...
  |        batch_2(g*zeta) -> extract Z(g*zeta)
  v
[Phase 8] Constraint Verification
           vanishing(zeta)[i] == Z_H(zeta) * quotient(zeta)[i]
           using fully verified openings and on-chain derived challenges
```

---

## 3. Polynomial Batch Structure

### Four Concatenated Batches

The prover concatenates all polynomial coefficients into a single vector:

| Batch | Contents | Polynomial Count |
|-------|----------|-----------------|
| 0 | constants_sigmas (selectors + lookup_selectors + constants + sigma permutation polys) | num_selectors + num_lookup_selectors + num_constants + num_routed_wires |
| 1 | wires (witness wire polynomials) | num_wires (typically 135) |
| 2 | zs_partial_products (Z polynomial + partial products per challenge) | num_challenges * (1 + num_partial_products) |
| 3 | quotient_chunks | num_challenges * quotient_degree_factor |

Each individual polynomial has degree N = 2^degree_bits.

### Concatenation

```
combined_poly = pad(batch_0) || pad(batch_1) || pad(batch_2) || pad(batch_3)
```

where pad() pads each batch to a power of 2 (minimum 256 elements). The final combined polynomial is further padded to a power of 2 for WHIR commitment.

`batch_sizes = [|pad(batch_0)|, |pad(batch_1)|, |pad(batch_2)|, |pad(batch_3)|]`

### Within Each Batch

Individual polynomials of uniform degree N are flattened:

```
batch_i = [poly_0_coeff_0, ..., poly_0_coeff_{N-1}, poly_1_coeff_0, ..., poly_1_coeff_{N-1}, ...]
```

The evaluation at zeta:

```
batch_i(zeta) = poly_0(zeta) + zeta^N * poly_1(zeta) + zeta^{2N} * poly_2(zeta) + ...
```

---

## 4. WHIR Commitment

### Merkle Tree Construction

WHIR commits to the combined polynomial via a hash-based Merkle tree:

1. Polynomial coefficients are encoded into the leaves of the Merkle tree
2. Tree is built bottom-up using Keccak-256
3. The root hash (32 bytes) is the commitment

The Merkle root is the first 32 bytes of the WHIR transcript (`proof_narg[0..32]`).

### WHIR Proof Properties

- **Hash function**: Keccak-256 (post-quantum secure)
- **Security level**: 80 bits (configurable)
- **Folding factor**: 4
- **Rate**: 1/4 (starting_log_inv_rate = 2)
- **Multi-point evaluation**: Proves f(r1) and f(r2) in a single proof

---

## 5. Challenge Derivation

### Unified Keccak Fiat-Shamir (deriveKeccakChallengesV2)

All Plonky2 challenges are derived on-chain from the WHIR commitment:

```
Step 1: Initial hash
  state = Keccak256(
    "plonky2-challenges-v2"       // domain tag (21 bytes)
    || session_name               // e.g., "whir-plonky2-combined-valid" (27 bytes)
    || merkle_root                // first 32 bytes of WHIR transcript
    || PI_0_le || PI_1_le || ...  // public inputs as u64 little-endian (8 bytes each)
  )

Step 2: Sequential squeeze
  For each challenge value:
    state = Keccak256(state)
    value = u64_from_le_bytes(state[0..8]) % p

Step 3: Challenge sequence (in order)
  betas[0..num_challenges]    // permutation challenges
  gammas[0..num_challenges]   // permutation challenges
  alphas[0..num_challenges]   // constraint reduction challenges
  zeta.c0                     // evaluation point component 0
  zeta.c1                     // evaluation point component 1
  zeta.c2                     // evaluation point component 2
```

### Soundness Argument

- zeta depends on the Merkle root, which depends on the committed polynomial
- The prover commits before zeta is derived (Fiat-Shamir heuristic)
- Changing the polynomial changes the Merkle root, which changes zeta
- Finding a polynomial where constraints hold at its derived zeta requires inverting Keccak

### Generator Computation

```
g = primitive_root_of_unity(degree_bits)
    // g is the generator of the multiplicative subgroup H of order 2^degree_bits
    // g^(2^degree_bits) = 1 in F_p

g_zeta = g * zeta  (Ext3 scalar multiplication, g is a base-field element)
```

---

## 6. Sumcheck Bridge Protocol

### Purpose

Proves that the WHIR-committed polynomial, when viewed as a univariate polynomial via coefficient ordering, evaluates to a specific value at zeta.

### Mathematical Statement

```
<f, h_zeta> = p(zeta)
```

where:
- f: {0,1}^n -> F is the MLE of the polynomial coefficients
- h_zeta(b) = zeta^{int(b)} for b in {0,1}^n (powers-of-zeta function)
- p(zeta) = sum_{i=0}^{2^n - 1} coeff_i * zeta^i (univariate evaluation)
- n = log2(polynomial_length)

### h_zeta Function (Big-Endian MLE)

```
h_zeta(r1, ..., rn) = product_{j=0}^{n-1} (1 - r_j + r_j * zeta^{2^{n-1-j}})
```

The zeta powers are precomputed: `zeta_pow[k] = zeta^{2^k}` for k = 0..n-1 via repeated squaring.

### Protocol Rounds

For i = 0, 1, ..., n-1:

1. **Prover sends** g_i = [g_i(0), g_i(1), g_i(2)] (degree-2 polynomial evaluations)

2. **Verifier checks**: g_i(0) + g_i(1) == current_claim

3. **Verifier derives challenge** r_i via Fiat-Shamir:
   ```
   fsAccum = fsAccum || ext3_to_le_bytes(g_i(0)) || ext3_to_le_bytes(g_i(1)) || ext3_to_le_bytes(g_i(2))
   h = Keccak256(fsAccum)
   r_i = Ext3(
     le_u64(h >> 192) % p,
     le_u64(h >> 128) % p,
     le_u64(h >> 64) % p
   )
   ```

4. **Update claim**: current_claim = g_i(r_i) via Lagrange interpolation on {0, 1, 2}:
   ```
   g_i(r) = g_i(0) * (r-1)(r-2)/2 - g_i(1) * r(r-2) + g_i(2) * r(r-1)/2
   ```
   where 2^{-1} mod p = 9223372034707292161

5. **Output**: evaluation point r = (r_0, r_1, ..., r_{n-1}), final_claim

### Fiat-Shamir Initialization

```
fsAccum = tag || session_name_bytes || ext3_to_le_bytes(zeta)
```

- Tag for bridge #1: `"sumcheck-challenges"`
- Tag for bridge #2: `"sumcheck-challenges-gzeta"`

### Binding Verification

After sumcheck completes:

```
f(r) * h_zeta(r) == final_claim
```

where f(r) is the WHIR-proven MLE evaluation at point r.

### Dual Bridge

Two independent sumcheck instances run on the same committed polynomial:

| Bridge | Evaluation Point | Fiat-Shamir Tag | WHIR Eval Point | Purpose |
|--------|-----------------|-----------------|-----------------|---------|
| #1 | zeta | "sumcheck-challenges" | r1 | Main polynomial evaluations |
| #2 | g*zeta | "sumcheck-challenges-gzeta" | r2 | Next-row evaluations for permutation |

### Soundness Error

The sumcheck over Ext3 with degree-2 round polynomials:

```
epsilon <= n * 2 / |F_{p^3}| ~ n * 2 / 2^192 ~ 2^{-187}  (for n = 16)
```

---

## 7. Decomposition Chain

### Inter-Batch Decomposition

Verifies that batch-level evaluations sum to the total polynomial evaluation:

```
P(zeta) = batch_0(zeta) + zeta^{d0} * batch_1(zeta) + zeta^{d0+d1} * batch_2(zeta) + zeta^{d0+d1+d2} * batch_3(zeta)
```

Similarly for g*zeta:

```
P(g*zeta) = batch_0(g*zeta) + (g*zeta)^{d0} * batch_1(g*zeta) + ...
```

### Intra-Batch Sub-Decomposition

Within each batch, verifies individual polynomial evaluations:

```
batch_i(zeta) = poly_0(zeta) + zeta^N * poly_1(zeta) + zeta^{2N} * poly_2(zeta) + ...
```

Verified using Horner's method (from last to first):

```
recomputed = poly_{k-1}(zeta)
for j = k-2 down to 0:
    recomputed = recomputed * zeta^N + poly_j(zeta)
assert recomputed == batch_i(zeta)
```

### Opening Extraction

After sub-decomposition, verified per-polynomial evaluations at zeta map to Openings:

| Batch | Polynomials | Openings Field |
|-------|-------------|----------------|
| 0 (first part) | selectors + lookup_selectors + constants | `openings.constants` |
| 0 (last part) | sigma permutation polynomials | `openings.plonkSigmas` |
| 1 | wire polynomials | `openings.wires` |
| 2 at zeta | Z + partial_products (per challenge) | `openings.plonkZs`, `openings.partialProducts` |
| 2 at g*zeta | Z (per challenge) | `openings.plonkZsNext` |
| 3 | quotient chunks | `openings.quotientPolys` |

Batch 2 layout per challenge: `[Z, PP_0, PP_1, ..., PP_{numPartialProducts-1}]`

- `openings.plonkZs[ch] = batch2_evals[ch * stride]` where stride = 1 + numPartialProducts
- `openings.partialProducts[ch * numPP + pp] = batch2_evals[ch * stride + 1 + pp]`
- `openings.plonkZsNext[ch] = batch2_g_zeta_evals[ch * stride]`

---

## 8. Plonky2 Constraint Verification

### Main Equation

For each alpha challenge index i:

```
vanishing(zeta)[i] == Z_H(zeta) * reduce_with_powers(quotient_chunks[i], zeta^n)
```

where:
- `Z_H(zeta) = zeta^n - 1` (vanishing polynomial of trace subgroup H, n = 2^degree_bits)
- `reduce_with_powers(chunks, base) = chunks[0] + base * chunks[1] + base^2 * chunks[2] + ...` (Horner)

### Vanishing Polynomial Components

```
vanishing(zeta) = reduce_with_alphas(boundary_terms || permutation_terms || gate_constraints)
```

Combined via Horner reduction using alpha challenges:

```
acc = 0
for term in terms (from last to first):
    acc = acc * alpha + term
```

### Boundary Terms

For each challenge i:

```
boundary_terms[i] = L_0(zeta) * (Z[i](zeta) - 1)
```

where:
- L_0(zeta) = (zeta^n - 1) / (n * (zeta - 1)) (Lagrange polynomial at first row)
- Z[i](zeta) = permutation accumulator opening

### Permutation Terms

For each challenge i, chunked over num_partial_products:

```
prevAcc * numerator_product - nextAcc * denominator_product
```

where:
- numerator_product = product_{j in chunk} (wire_j(zeta) + beta * zeta * k_j + gamma)
- denominator_product = product_{j in chunk} (wire_j(zeta) + beta * sigma_j(zeta) + gamma)
- prevAcc = Z(zeta) for first chunk, partialProducts[chunk-1] otherwise
- nextAcc = plonkZsNext (= Z(g*zeta)) for last chunk, partialProducts[chunk] otherwise

### Gate Constraints

```
constraints[j] = sum_{gate} filter(gate, selector) * gate.eval_unfiltered(j)
```

where filter is the selector-based activation polynomial (nonzero only when gate is active at the relevant row).

---

## 9. WHIR Verification (On-Chain, 6 Phases)

### Phase 1: Initial Commitment + OOD + RLC

1. Read Merkle root from transcript (32 bytes)
2. Derive out-of-domain (OOD) challenge points
3. Read OOD answer matrix from transcript
4. Compute random linear combination (RLC) coefficients via geometric challenge
5. Compute "the sum" combining evaluations and OOD answers

### Phase 2: Initial Sumcheck

Standard sumcheck rounds over the initial variables:
- For each round: read [c0, c2], compute c1 = theSum - 2*c0 - c2
- Derive folding randomness r_i via Fiat-Shamir
- Update theSum

### Phase 3: Intermediate Rounds

For each folding round:
1. New Merkle commitment
2. OOD challenges and answers
3. Merkle opening verification (hash path checking)
4. Sumcheck (Phase 2 pattern)

### Phase 4: Final Vector + Merkle Opening

Read the final vector of field elements and verify Merkle opening proof.

### Phase 5: Final Sumcheck

Same as Phase 2, for the final sumcheck rounds.

### Phase 6: FinalClaim Verification

Multi-point evaluation check:

```
polyEval = fold(finalVector, foldingRandomness)  // eq-weighted dot product
linearFormRlc = theSum / polyEval

// Subtract round constraint contributions
for each round_constraint:
    linearFormRlc -= mle_eval(univariate_point, foldingRandomness) * rlc_coeff

// Verify against evaluation points
if numLinearForms == 1:
    expectedRlc = rlc[0] * eq(evaluationPoint, foldingRandomness)
else:  // dual-point
    expectedRlc = rlc[0] * eq(evaluationPoint1, foldingRandomness)
                + rlc[1] * eq(evaluationPoint2, foldingRandomness)

assert linearFormRlc == expectedRlc
```

---

## 10. Complete Soundness Argument

### Binding Chain

```
WHIR commitment (Merkle root M)
    |
    |-- Challenges derived: zeta = Keccak(M, session, PI)
    |                       betas, gammas, alphas from same chain
    |
    |-- WHIR proves: f(r1) = v1, f(r2) = v2
    |   (r1, r2 are sumcheck-derived from zeta, g*zeta)
    |
    |-- Sumcheck bridge #1: v1 * h_zeta(r1) == finalClaim1
    |   => P(zeta) = claimedSum1 is correct for committed f
    |
    |-- Sumcheck bridge #2: v2 * h_{g*zeta}(r2) == finalClaim2
    |   => P(g*zeta) = claimedSum2 is correct for committed f
    |
    |-- Inter-batch decomposition:
    |   P(zeta) == sum_i batch_i(zeta) * zeta^offset_i
    |   P(g*zeta) == sum_i batch_i(g*zeta) * (g*zeta)^offset_i
    |   => batch evaluations are correct
    |
    |-- Intra-batch sub-decomposition:
    |   batch_i(zeta) == sum_j poly_j(zeta) * zeta^{j*N}
    |   batch_2(g*zeta) == sum_j poly_j(g*zeta) * (g*zeta)^{j*N}
    |   => individual polynomial evaluations are correct
    |
    |-- Opening extraction:
    |   constants, sigmas, wires, Zs, partialProducts, ZsNext, quotientPolys
    |   all derived from verified sub-decomposition values
    |
    |-- Constraint verification:
    |   vanishing(zeta) == Z_H(zeta) * quotient(zeta)
    |   using on-chain derived challenges and verified openings
    |
    v
  PROOF VERIFIED: circuit computation is correct
```

### What a Malicious Prover Cannot Do

1. **Forge challenges**: Challenges are derived on-chain from Merkle root. Changing challenges requires changing the Merkle root, which changes the committed polynomial.

2. **Forge openings**: All openings are derived through the decomposition chain from the WHIR-proven evaluation. Changing any opening would violate the decomposition check.

3. **Forge Z(g*zeta)**: The next-row evaluation is bound through the second sumcheck bridge and batch 2 sub-decomposition at g*zeta.

4. **Choose favorable zeta**: zeta is derived from Keccak(Merkle root + ...). Finding a polynomial whose Merkle root hashes to a favorable zeta requires inverting Keccak.

### Security Level

| Component | Security |
|-----------|----------|
| WHIR commitment | 80-bit (configurable, hash-based) |
| Sumcheck soundness | ~187-bit (n * 2 / |Ext3|) |
| Schwartz-Zippel (constraint check) | ~192-bit (degree / |Ext3|) |
| Fiat-Shamir (challenge binding) | Keccak-256 preimage resistance |
| Post-quantum | Yes (no ECC, purely hash-based) |

---

## 11. Gas Costs (On-Chain)

Measured for a 10-step Poseidon hash-chain circuit (degree_bits=4):

| Step | Operation | Gas |
|------|-----------|-----|
| 1 | WHIR dual-point verification | ~8.2M |
| 2-3 | Sumcheck bridges (zeta + g*zeta) | ~6.2M |
| 4 | Challenge derivation | ~0.1M |
| 5-6 | Inter-batch decomposition (zeta + g*zeta) | ~0.4M |
| 7-8 | Intra-batch sub-decomposition | ~15M |
| 9 | Opening extraction | negligible |
| 10 | Plonky2 constraint check (Ext3) | ~3.2M |
| **Total** | **Full E2E verification** | **~32.5M** |

Sub-decomposition dominates because it verifies 255 individual polynomials (84+135+20+16) on-chain. Gas optimization opportunities exist through batched exponentiation and assembly optimization.
