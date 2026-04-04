# plonky2-whir-verifier

Generic Plonky2 → WHIR post-quantum verification pipeline with sumcheck binding.

Replaces Plonky2's FRI polynomial commitment with **WHIR** (Keccak/SHA3-based), achieving cryptographic soundness through a **sumcheck inner product argument** bridge.

## Soundness Architecture

A naive approach — running WHIR and constraint checks independently — leaves no binding between the WHIR-committed polynomial and the openings used for constraint verification, allowing a malicious prover to submit forged openings.

This system introduces a **sumcheck inner product argument** that reduces univariate evaluation to multilinear evaluation, closing this gap.

### Off-chain Prover (Rust)

```
Plonky2 Prover
├─ Generate coefficients for W(x), Z(x), σ(x), Q(x)
├─ Concatenate into MLE and commit (WHIR / Keccak256)
├─ Derive ζ from WHIR transcript via Fiat-Shamir
├─ Prove ⟨f, h_ζ⟩ = p(ζ) via sumcheck            ← binding
│   └─ n rounds (degree 2/round, n = log₂(poly_size))
└─ WHIR evaluation proof: f(r) = v at sumcheck point r
```

### On-chain Verifier (Solidity)

```
On-chain Verifier
├─ Verify sumcheck (n rounds of polynomial consistency checks)
├─ Verify WHIR evaluation proof
├─ Compute h_ζ(r) and check f(r) · h_ζ(r) = claimed_value
└─ Plonky2 constraint check using verified openings (vanishing poly check)
```

### Why Sumcheck?

| Problem | Cause | Solution |
|---------|-------|----------|
| WHIR operates on MLE (multilinear) | Plonky2 requires univariate p(ζ) | Reduce via sumcheck: ⟨f, h_ζ⟩ = p(ζ) |
| Openings unbound to commitment | Missing evaluation proof | Sumcheck → WHIR eval proof for binding |
| Challenges computed off-chain | No Fiat-Shamir re-derivation | Derive ζ on-chain from WHIR transcript |

**Soundness**: Over GoldilocksExt3 (|F| ≈ 2^192), sumcheck error ≤ n·2/|F| ≈ **2^{-187}** (n=13).

## Full Verification Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Off-chain (Rust)                                           │
│                                                             │
│  Plonky2 Circuit + Witness                                  │
│       │                                                     │
│       ▼                                                     │
│  prove_with_whir()                                          │
│       ├── Plonky2 Prover → W, Z, σ, Q polynomials          │
│       ├── Concatenate 4 batches → MLE f on {0,1}^n         │
│       ├── WHIR Commit(f) → Merkle root (Keccak256)          │
│       ├── ζ ← Fiat-Shamir(WHIR transcript)                  │
│       ├── Sumcheck: prove ⟨f, h_ζ⟩ = p(ζ)                   │
│       │    └── n rounds → random point r ∈ F^n              │
│       ├── WHIR Eval Proof: f(r) = v                         │
│       └── Export: VK (test_vk.json) + Proof (test_proof.json)│
└──────────────────────┬──────────────────────────────────────┘
                       │ JSON export
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  On-chain (Solidity)                                        │
│                                                             │
│  Deploy: initialize(vk) — set verifying key once (immutable)│
│                                                             │
│  Verify: verify(proof)                                      │
│  ┌───────────────────────┐                                  │
│  │ SpongefishWhirVerify  │ WHIR eval proof: f(r) = v        │
│  └────────┬──────────────┘                                  │
│           ▼                                                 │
│  ┌───────────────────┐                                      │
│  │ Sumcheck Verify    │ n rounds of g_i(0)+g_i(1) checks    │
│  └────────┬──────────┘                                      │
│           ▼                                                 │
│  ┌───────────────────────┐                                  │
│  │ h_ζ(r) computation    │ Compute h_ζ(r), verify           │
│  │                       │ f(r) · h_ζ(r) = claim            │
│  └────────┬──────────────┘                                  │
│           ▼                                                 │
│  ┌───────────────────────┐                                  │
│  │ Plonky2Verifier       │ Constraint satisfaction check     │
│  │                       │ (vanishing poly)                  │
│  └───────────────────────┘                                  │
│                                                             │
│  All steps pass → verification success                      │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- **Rust nightly** (tested with 1.96.0+)
- **Foundry** (forge, tested with v1.5.1+)

### Build & Test

```bash
# 1. Generate test fixtures (outputs to contracts/test/data/)
#    Fixtures are gitignored — you must generate them before running Solidity tests.
cargo +nightly run --bin generate_fixture --release

# 2. Run Solidity tests
cd contracts
forge test
```

> **Note**: `forge test` will auto-generate fixtures via `vm.ffi` if `ffi = true` in `foundry.toml` and fixture files are missing. However, this requires Rust nightly to be available in the shell. For reliability, run step 1 manually first.

### Run Rust tests

```bash
cargo +nightly test --release
```

> Debug builds fail due to `debug_assertions` in the whir crate. Always use `--release`.

## Repository Structure

```
plonky2-whir-verifier/
├── Cargo.toml                      # Rust workspace (nightly required)
│
├── src/                            # Rust library
│   ├── lib.rs                      # Entry point (feature-gated)
│   ├── prover.rs                   # WHIR prover/verifier + export
│   ├── sumcheck.rs                 # Sumcheck inner product prover/verifier
│   ├── wrapper.rs                  # Generic wrapper circuit
│   └── error.rs                    # Error types
│
├── docs/
│   └── cryptographic-construction.md  # Full protocol specification
│
└── contracts/                      # Solidity (Foundry)
    ├── foundry.toml
    ├── src/
    │   ├── WhirPlonky2Verifier.sol # Unified verifier entry point (immutable VK + verify())
    │   ├── Plonky2Verifier.sol     # Constraint satisfaction check
    │   ├── GoldilocksField.sol     # Goldilocks field arithmetic (p = 2^64 - 2^32 + 1)
    │   ├── PoseidonConstants.sol   # Poseidon round constants
    │   ├── PoseidonGateEval.sol    # Poseidon gate constraint evaluation
    │   └── spongefish/
    │       ├── SpongefishWhirVerify.sol  # WHIR verification (dual-point)
    │       ├── SumcheckBridgeVerifier.sol # Sumcheck bridge + recomposition
    │       ├── SpongefishWhir.sol        # WHIR transcript processing
    │       ├── SpongefishMerkle.sol      # Merkle tree verification
    │       ├── Keccak256Chain.sol        # Keccak sponge construction
    │       ├── DuplexSponge.sol          # Duplex sponge mode
    │       ├── GoldilocksExt3.sol        # Cubic extension field F_p[x]/(x^3-2)
    │       ├── WhirLinearAlgebra.sol     # Sumcheck linear algebra
    │       └── LibKeccak.sol            # Keccak256 primitives
    └── test/
        ├── GenericE2E.t.sol            # Generic E2E tests
        ├── Plonky2Verifier.t.sol       # Constraint verification tests
        └── data/                       # Test fixtures (gitignored, auto-generated)
```

## Key Modules

### Rust (`src/`)

| Module | Description |
|--------|-------------|
| `prover.rs` | `prove_with_whir()` / `verify_whir_plonky2_proof()` / `export_unified_proof()` — WHIR proof generation, verification, export |
| `sumcheck.rs` | `sumcheck_prove()` / `sumcheck_verify()` — univariate ↔ multilinear bridge |
| `wrapper.rs` | `WrapperCircuit<F, InnerC, OuterC, D>` — re-proving with different configs |
| `error.rs` | `WrapperProofFailed` / `InvalidProof` error types |

### Solidity (`contracts/src/`)

| Contract | Description |
|----------|-------------|
| `WhirPlonky2Verifier` | Unified verifier: immutable VK + `verify(proof)` entry point |
| `Plonky2Verifier` | Constraint satisfaction: vanishing poly == Z_H * quotient at ζ |
| `SpongefishWhirVerify` | WHIR polynomial commitment verification (dual-point) |
| `SumcheckBridgeVerifier` | Sumcheck bridge, recomposition, decomposition |
| `GoldilocksField` | Goldilocks field: add, mul, inv, pow |
| `GoldilocksExt3` | Cubic extension field arithmetic |
| `PoseidonGateEval` | Poseidon hash gate constraint evaluation |
| `Keccak256Chain` | Keccak256-based Fiat-Shamir transcript |

## Contract Architecture

```solidity
// Deploy: set verifying key once (immutable, circuit-specific)
verifier.initialize(circuitConfig, whirParams, protocolId, sessionId, instance);

// Verify: submit proof only (no VK data needed)
bool valid = verifier.verify(proof);
```

The verifying key (VK) contains circuit topology, WHIR protocol parameters, and session/protocol IDs. It is set once at deployment and cannot be changed. Only proofs are submitted for verification.

## Benchmarks

Measured on 2026-04-04 (rate=1/16, Ext3, Foundry v1.5.1, solc 0.8.29, via-ir).

### Gas Consumption — On-chain Verification

| Operation | Gas | Note |
|-----------|-----|------|
| **verify() (excl. JSON parsing)** | **~8.7M** | Production on-chain cost |
| test_unified_verify (incl. JSON parsing) | 18.2M | Forge test measurement |
| WHIR dual-point verification | 6.1M | |
| Sumcheck bridges (ζ + gζ) | 2.7M | |
| Plonky2 constraint check (Ext3) | 2.0M | |
| Recomposition + decomposition | ~0.2M | Yul assembly |

### Cost Estimate (L1, ETH ≈ $2,050)

| Gas Price | verify() cost |
|-----------|--------------|
| 5 gwei | $0.09 |
| 15 gwei | $0.27 |
| 30 gwei | $0.53 |

### Off-chain Proving (Rust nightly, release build)

| Phase | Time |
|-------|------|
| Plonky2 prove | ~12 ms |
| WHIR prove (dual-point) | ~20 ms |
| **Total** | **~32 ms** |

### Test Results

```
Solidity: 10 tests passed, 0 failed (GenericE2ETest)
```

## Security Considerations

### Resolved Issues

1. **Binding gap** (Critical): No cryptographic binding between WHIR commitment and Plonky2 openings. Resolved via sumcheck inner product argument + recomposition check.

2. **Fiat-Shamir challenges** (Critical): ζ, β, γ, α were pre-computed off-chain without on-chain re-derivation. Resolved by deriving all challenges on-chain from the WHIR Merkle root via Keccak.

3. **Z(gζ) unverified** (Critical): Next-row evaluation for permutation check was unbound. Resolved via dual sumcheck bridge (second bridge at gζ) + batch2 sub-decomposition.

4. **Ext2 embedding unsound**: Embedding Ext2 in Ext3 as (c0,c1,0) is not a field homomorphism — Ext3 multiplication produces nonzero c2. Resolved by migrating all arithmetic to native Ext3.

### Design Decisions

- **Multilinear ↔ Univariate bridge**: WHIR uses MLE (multilinear extension), Plonky2 uses univariate polynomials. The sumcheck reduces ⟨f, h_ζ⟩ = p(ζ), bridging the algebraic structures.
- **Hash function**: WHIR transcript uses Keccak256 (post-quantum). Plonky2 internals use Poseidon. On-chain verification uses Keccak throughout.
- **Immutable VK**: The verifying key is set at deployment and cannot be modified, preventing VK substitution attacks.
- **Reed-Solomon rate**: 1/16 (starting_log_inv_rate=4) for optimal gas cost.
- **Ext3 field**: F_p[x]/(x^3-2), p = 2^64 - 2^32 + 1. Provides ~2^192 security for Schwartz-Zippel.

## Documentation

- [`docs/cryptographic-construction.md`](docs/cryptographic-construction.md) — Complete protocol specification with soundness argument, field parameters, byte-level protocol flow, and security analysis.
