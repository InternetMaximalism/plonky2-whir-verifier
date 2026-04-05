# WHIR-Plonky2 Constraint Verification Architecture

This document describes the complete structure of polynomial commitment, evaluation proof, and constraint verification when replacing FRI with WHIR.

## Background: Algebraic Differences Between FRI and WHIR

Both FRI and WHIR are proximity tests for Reed-Solomon codes, but they operate over different algebraic structures.

| | FRI | WHIR |
|---|---|---|
| Polynomial representation | Univariate p(x) = Σ cᵢxⁱ | MLE f: {0,1}^n → F |
| Evaluation domain | Multiplicative subgroup H ⊂ F | Boolean hypercube {0,1}^n |
| Arbitrary-point evaluation | Quotient trick: (P(x)-v)/(x-ζ) | Sumcheck inner-product reduction |
| Folding | Domain halving | Sumcheck rounds |

FRI's quotient trick provides evaluation proofs at arbitrary points as an inherent part of the protocol. WHIR lacks this mechanism, so a **sumcheck bridge** converts MLE evaluation → univariate evaluation.

## Polynomial Representation

For each Plonky2 univariate polynomial p(x) = Σᵢ cᵢ xⁱ (deg < N = 2^n), interpret the coefficient sequence as an MLE:

```
f_p : {0,1}^n → F
f_p(b) = c_{int(b)}
```

where int(b) is the integer interpretation of b ∈ {0,1}^n under WHIR's big-endian convention.

WHIR runs its proximity test on f_p, proving that f_p is δ-close to a Reed-Solomon codeword. This is equivalent to proving that the underlying univariate polynomial p(x) has degree < 2^n.

## Sumcheck Bridge: MLE Evaluation → Univariate Evaluation

### Core Identity

```
p(ζ) = Σ_{b ∈ {0,1}^n} f_p(b) · ζ^{int(b)} = ⟨f_p, h_ζ⟩
```

where the "powers-of-ζ function" is defined as:

```
h_ζ : {0,1}^n → F
h_ζ(b) = ζ^{int(b)}
```

This inner product equals the univariate evaluation p(ζ) by definition.

### Sumcheck Protocol

The LFKN sumcheck proves ⟨f_p, h_ζ⟩ = p(ζ):

- The product f_p · h_ζ has degree 2 in each variable → degree-2 univariate polynomials sent per round
- After n rounds, a random point r = (r₁, ..., rₙ) is determined via Fiat-Shamir
- Final check:

```
f_p(r) · h̃_ζ(r) = final_claim
```

where h̃_ζ(r) is the MLE evaluation of h_ζ, computable by the verifier:

```
h̃_ζ(r) = Π_{j=0}^{n-1} (1 - rⱼ + rⱼ · ζ^{2^{n-1-j}})
```

(WHIR big-endian convention: r[0] = MSB)

- `f_p(r)` is proved via WHIR's evaluation proof
- `h̃_ζ(r)` is deterministically computed by the verifier from ζ and r

### Soundness

Over GoldilocksExt3 (|F| ≈ 2^192), the sumcheck soundness error:

```
ε_sumcheck ≤ n · 2 / |F| ≈ 2^{-187}  (for n = 16)
```

## Plonky2 Constraint Equation

Using the verified evaluation values (openings) obtained via the sumcheck bridge, the verifier checks Plonky2 constraint satisfaction.

### Equation to Verify

For each challenge i (i = 0, ..., numChallenges - 1):

```
vanishing_i(ζ) = Z_H(ζ) · Q_i(ζ)
```

### Left-Hand Side: vanishing_i(ζ)

The vanishing polynomial is the Horner reduction of three components using α challenges:

```
vanishing_i(ζ) = Σⱼ αⱼ · term_j
```

#### (a) Boundary Terms

```
boundary_i = L₀(ζ) · (Z_i(ζ) - 1)
```

- L₀(ζ) = (ζⁿ - 1) / (n · (ζ - 1)) — Lagrange basis at the first row
- Z_i(ζ) — permutation accumulator evaluation at ζ
- Semantics: Z must equal 1 at row 0

#### (b) Permutation Check

For each chunk k:

```
perm_i = Z_i(ζ) · ∏ₖ (Wₖ(ζ) + βᵢ · ζ · kₖ + γᵢ)
       - Z_i(gζ) · ∏ₖ (Wₖ(ζ) + βᵢ · σₖ(ζ) + γᵢ)
```

- βᵢ, γᵢ — permutation challenges (Fiat-Shamir)
- kₖ — coset shift constants
- σₖ(ζ) — permutation polynomial evaluation
- Z_i(gζ) — permutation accumulator at the "next row" → **requires a separate sumcheck bridge using h_{gζ}**

#### (c) Gate Constraints

```
gates = Σ_gate filter(gate, selector(ζ)) · gate.eval(W(ζ), constants(ζ))
```

- filter: selector-based gate activation polynomial
- gate.eval: gate-specific constraint (ArithmeticGate, PoseidonGate, etc.)
- Example: ArithmeticGate → output - (m0 · m1 · c0 + addend · c1) = 0

### Right-Hand Side: Z_H(ζ) · Q_i(ζ)

```
Z_H(ζ) = ζⁿ - 1                                    — vanishing polynomial of H
Q_i(ζ) = reduce_with_powers(quotient_chunks_i, ζⁿ)  — quotient polynomial (split representation)
```

## End-to-End Verification Flow

```
┌───────────────────────────────────────────────────────────────────┐
│  Phase 1: WHIR Commitment                                         │
│                                                                    │
│  For each polynomial p, commit the coefficient MLE f_p via WHIR   │
│  → Proves f_p is δ-close to an RS codeword                       │
│  → Guarantees the univariate polynomial p(x) has bounded degree   │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  Phase 2: Challenge Derivation                                     │
│                                                                    │
│  ζ ← Fiat-Shamir(all commitments)                                 │
│  β, γ ← Fiat-Shamir (permutation challenges)                      │
│  α ← Fiat-Shamir (constraint composition challenge)                │
└────────────────────────────┬──────────────────────────────────────┘
                             │
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  Phase 3: Sumcheck Bridge (per polynomial)                         │
│                                                                    │
│  Identity: Σ_{b ∈ {0,1}^n} f_p(b) · ζ^{int(b)} = p(ζ)           │
│                                                                    │
│  n rounds of LFKN sumcheck                                         │
│  → Generates random point r = (r₁, ..., rₙ)                       │
│  → Final check: f_p(r) · h̃_ζ(r) = final_claim                    │
│                                                                    │
│  f_p(r) : proved by WHIR evaluation proof                         │
│  h̃_ζ(r) : verifier computes = Π(1 - rⱼ + rⱼ · ζ^{2^{n-1-j}})   │
│                                                                    │
│  Output: verified evaluation p(ζ)                                  │
│  Note: Z(gζ) requires a separate bridge using h_{gζ}              │
└────────────────────────────┬──────────────────────────────────────┘
                             │ W(ζ), Z(ζ), Z(gζ), σ(ζ), Q(ζ), const(ζ)
                             ▼
┌───────────────────────────────────────────────────────────────────┐
│  Phase 4: Plonky2 Constraint Verification (F = 0)                  │
│                                                                    │
│  vanishing_i(ζ) = α-reduction(boundary + perm + gates)            │
│                                                                    │
│  Check: vanishing_i(ζ) == Z_H(ζ) · Q_i(ζ)                        │
│                                                                    │
│  Holds for all i → constraints satisfied                           │
└───────────────────────────────────────────────────────────────────┘
```

## Soundness Composition

| Stage | Guarantee | Soundness Error |
|-------|-----------|-----------------|
| WHIR proximity | f_p is coefficient MLE of a bounded-degree polynomial | δ (protocol parameter dependent) |
| Sumcheck bridge | ⟨f_p, h_ζ⟩ = p(ζ) | ≤ n·2/\|F\| ≈ 2^{-187} |
| Schwartz-Zippel | F(ζ) = 0 implies constraints hold everywhere | ≤ deg(F)/\|F\| |
| Fiat-Shamir | ζ is determined after commitments | Prover cannot predict ζ |
| Composite | Overall soundness | ≈ Σ(individual errors) ≪ 1 |

## Mapping to User Notation

The notation `W(ξ...1,0)` corresponds to:

```
W(ζ) = Σ_{b ∈ {0,1}^n} f_W(b) · ζ^{int(b)}
        ~~~~~~~~~~~~~~~~   ~~~~~~~~~~~~
        values on {0,1}    challenge ξ = ζ
        (the "1,0")        (the "ξ")
```

- ξ = ζ (Fiat-Shamir challenge)
- 1, 0 = summation variables on the hypercube {0,1}^n
- F(...) = Plonky2 constraint: vanishing(ζ) - Z_H(ζ)·Q(ζ) = 0

In place of FRI's `P(ζ) = 0` check, WHIR achieves equivalent verification through the chain: **MLE inner product → sumcheck bridge → univariate evaluation → constraint check**.

## Implementation File Map

| Component | File |
|---|---|
| WHIR commit + sumcheck bridge (Rust) | `src/prover.rs` (whir_commit_and_prove_with_sumcheck) |
| Sumcheck prover/verifier (Rust) | `src/sumcheck.rs` |
| h̃_ζ(r) computation | `src/sumcheck.rs` (eval_h_zeta) |
| Plonky2 constraint verification (Solidity) | `contracts/src/Plonky2Verifier.sol` (verifyConstraints) |
| WHIR on-chain verification (Solidity) | `contracts/src/spongefish/SpongefishWhirVerify.sol` |
| Sumcheck bridge on-chain verification (Solidity) | `contracts/src/spongefish/SumcheckBridgeVerifier.sol` |
