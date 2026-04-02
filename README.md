# plonky2-whir-verifier

Generic Plonky2 → WHIR post-quantum verification pipeline with sumcheck binding.

Plonky2 の FRI 多項式コミットメントを **WHIR** (Keccak/SHA3 ベース) に置き換え、**sumcheck inner product argument** で暗号学的に sound な binding を実現するシステムです。

## Soundness Architecture

従来のアプローチ（WHIR と制約チェックを独立に実行）では、WHIR がコミットした多項式と制約検証に使われる openings の間にバインディングがなく、悪意あるプルーバーが偽の openings を提出できる脆弱性がありました。

本システムでは **sumcheck inner product argument** を導入し、univariate 評価を multilinear 評価に帰着させることで、この問題を解決しています。

### Off-chain Prover (Rust)

```
Plonky2 Prover
├─ W(x), Z(x), σ(x), Q(x) の係数を生成
├─ 連結して MLE にコミット（WHIR / Keccak256）
├─ ζ を WHIR transcript から Fiat-Shamir で導出
├─ sumcheck で ⟨f, h_ζ⟩ = p(ζ) を証明          ← binding
│   └─ n ラウンド (degree 2/round, n = log₂(poly_size))
└─ WHIR evaluation proof: f(r) = v at sumcheck point r
```

### On-chain Verifier (Solidity)

```
On-chain Verifier
├─ sumcheck を検証（n ラウンド分の多項式一致チェック）
├─ WHIR evaluation proof を検証
├─ h_ζ(r) を計算して f(r) · h_ζ(r) = claimed_value を確認
└─ openings で Plonky2 制約チェック（vanishing poly check）
```

### Why Sumcheck?

| 問題 | 原因 | 解決 |
|------|------|------|
| WHIR は MLE (multilinear) で動作 | Plonky2 は univariate p(ζ) が必要 | sumcheck で ⟨f, h_ζ⟩ = p(ζ) に帰着 |
| openings と commitment が未結合 | evaluation proof が欠如 | sumcheck → WHIR eval proof で binding |
| チャレンジがオフチェーン計算 | Fiat-Shamir 再導出なし | WHIR transcript から ζ を on-chain で導出 |

**Soundness**: GoldilocksExt3 (|F| ≈ 2^192) 上で sumcheck error ≤ n·2/|F| ≈ **2^{-187}** (n=13).

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
│       ├── 4 バッチに連結 → MLE f on {0,1}^n                  │
│       ├── WHIR Commit(f) → Merkle root (Keccak256)          │
│       ├── ζ ← Fiat-Shamir(WHIR transcript)                  │
│       ├── Sumcheck: prove ⟨f, h_ζ⟩ = p(ζ)                   │
│       │    └── n rounds → random point r ∈ F^n              │
│       ├── WHIR Eval Proof: f(r) = v                         │
│       └── Export: sumcheck proof + WHIR proof + openings    │
└──────────────────────┬──────────────────────────────────────┘
                       │ JSON export
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  On-chain (Solidity)                                        │
│                                                             │
│  ┌───────────────────┐                                      │
│  │ Sumcheck Verify    │ n ラウンドの g_i(0)+g_i(1) 一致検証  │
│  └────────┬──────────┘                                      │
│           ▼                                                 │
│  ┌───────────────────────┐                                  │
│  │ SpongefishWhirVerify  │ WHIR eval proof: f(r) = v        │
│  └────────┬──────────────┘                                  │
│           ▼                                                 │
│  ┌───────────────────────┐                                  │
│  │ h_ζ(r) computation    │ verifier が h_ζ(r) を計算して     │
│  │                       │ f(r) · h_ζ(r) = claim を確認     │
│  └────────┬──────────────┘                                  │
│           ▼                                                 │
│  ┌───────────────────────┐                                  │
│  │ Plonky2Verifier       │ 制約充足検証 (vanishing poly)     │
│  └───────────────────────┘                                  │
│                                                             │
│  全ステップ pass → 検証成功                                   │
└─────────────────────────────────────────────────────────────┘
```

## Repository Structure

```
plonky2-whir-verifier/
├── Cargo.toml                      # Rust workspace (nightly required)
│
├── src/                            # Rust library
│   ├── lib.rs                      # Entry point (feature-gated)
│   ├── prover.rs                   # WHIR prover/verifier + export (~1200 lines)
│   ├── sumcheck.rs                 # Sumcheck inner product prover/verifier
│   ├── wrapper.rs                  # Generic wrapper circuit
│   └── error.rs                    # Error types
│
├── tests/fixtures/                 # Rust test fixtures (JSON)
│
└── contracts/                      # Solidity (Foundry)
    ├── foundry.toml
    ├── src/
    │   ├── Plonky2Verifier.sol     # 制約充足検証
    │   ├── GoldilocksField.sol     # Goldilocks 体演算 (p = 2^64 - 2^32 + 1)
    │   ├── PoseidonConstants.sol   # Poseidon ラウンド定数
    │   ├── PoseidonGateEval.sol    # Poseidon ゲート制約評価
    │   └── spongefish/
    │       ├── SpongefishWhirVerify.sol  # WHIR 検証 + sumcheck point 対応
    │       ├── SpongefishWhir.sol        # WHIR トランスクリプト処理
    │       ├── SpongefishMerkle.sol      # Merkle ツリー検証
    │       ├── Keccak256Chain.sol        # Keccak スポンジ構成
    │       ├── DuplexSponge.sol          # Duplex スポンジモード
    │       ├── GoldilocksExt3.sol        # 3次拡大体 (x^3 - 2)
    │       ├── WhirLinearAlgebra.sol     # Sumcheck 線形代数
    │       └── LibKeccak.sol            # Keccak256 プリミティブ
    └── test/
        ├── GenericE2E.t.sol            # 汎用 E2E テスト
        ├── WhirOnchainE2E.t.sol        # WHIR 統合テスト
        ├── Plonky2Verifier.t.sol       # 制約検証テスト
        ├── SpongefishWhir.t.sol        # トランスクリプトテスト
        ├── GoldilocksField.t.sol       # 体演算テスト
        ├── PoseidonGateEval.t.sol      # ゲート評価テスト
        └── data/                       # テストフィクスチャ (JSON)
```

## Key Modules

### Rust (`src/`)

| Module | Description |
|--------|-------------|
| `prover.rs` | `prove_with_whir()` / `verify_whir_plonky2_proof()` / `export_onchain_data()` — WHIR 証明生成・検証・エクスポート |
| `sumcheck.rs` | `SumcheckProver::prove()` / `SumcheckVerifier::verify()` — univariate ↔ multilinear bridge |
| `wrapper.rs` | `WrapperCircuit<F, InnerC, OuterC, D>` — 異なるコンフィグでの再証明用 |
| `error.rs` | `WrapperProofFailed` / `InvalidProof` エラー型 |

### Solidity (`contracts/src/`)

| Contract | Description |
|----------|-------------|
| `Plonky2Verifier` | 制約充足検証: vanishing poly == Z_H * quotient at ζ |
| `SpongefishWhirVerify` | WHIR 多項式コミットメント検証 (sumcheck point 対応) |
| `GoldilocksField` | Goldilocks 体の加算・乗算・逆元・べき乗 |
| `GoldilocksExt3` | 3次拡大体演算 |
| `PoseidonGateEval` | Poseidon ハッシュゲートの制約評価 |
| `Keccak256Chain` | Keccak256 ベースの Fiat-Shamir トランスクリプト |

## Benchmarks

Measured on 2026-04-02.

### Off-chain Proving (Rust nightly 1.96.0, release build)

| Phase | Time |
|-------|------|
| Plonky2 prove | 8.36 ms |
| WHIR prove | 6.09 ms |
| **Total** | **14.45 ms** |
| Estimated on-chain gas | ~1,069K |

### Gas Consumption — On-chain Verification (Foundry v1.5.1, solc 0.8.29, via-ir, 200 runs)

| Operation | Gas |
|-----------|-----|
| **Full E2E** (WHIR + Constraints) | 21,123,272 |
| WHIR combined verification (1 proof) | 17,484,148 |
| Pure WHIR verify (combined) | 13,794,219 |
| Plonky2 constraint verification (wrapper) | 1,563,559 |
| Plonky2 constraint verification (standard) | 1,648,731 |
| Sumcheck bridge overhead | ~24,000 |

### Gas Consumption (Unit Tests)

| Test | Gas |
|------|-----|
| Transcript init from fixture | 1,549,605 |
| Poseidon gate constraint evaluation | 142,779 |
| Keccak256Chain deterministic | 6,152 |
| GoldilocksExt3 `reduceWithPowers` | 4,030 |
| GoldilocksField `inv` | 2,458 |
| GoldilocksExt3 `inv` | 2,378 |
| GoldilocksField `evalL0` | 2,015 |

### Contract Sizes

| Contract | Runtime (B) | Initcode (B) |
|----------|-------------|--------------|
| Plonky2Verifier | 20,741 | 20,767 |
| Others (libraries) | 57 | 85 |

> `Plonky2Verifier` は EVM の 24,576 B 制限に対し残り 3,835 B。他のコントラクトはすべてライブラリとしてデプロイされるため極小。

### Test Results

```
Solidity: 35 tests passed, 0 failed (6 test suites)
Rust:      8 passed, 0 failed (--release, includes 3 sumcheck tests)
```

> Note: debug ビルドでは whir クレート内の `debug_assertions` により一部テストが失敗します。`cargo +nightly test --release` を使用してください。

## Prerequisites

- **Rust nightly** (plonky2 dependency requires `#![feature(specialization)]`)
- **Foundry** (forge v1.5.1+)

## Usage

### Solidity Tests

```bash
cd contracts
forge test -vv
```

### Gas Report

```bash
cd contracts
forge test --gas-report
```

### Rust (requires nightly)

```bash
cargo +nightly test --release
```

## Security Considerations

### Resolved Issues

1. **Binding gap** (Critical): WHIR commitment と Plonky2 openings の間に暗号学的バインディングがなかった。sumcheck inner product argument で解決。

2. **Fiat-Shamir challenges** (Critical): ζ, β, γ, α がオフチェーンで事前計算され、on-chain で再導出されていなかった。WHIR transcript (Keccak) からの導出で解決。

### Design Decisions

- **Multilinear ↔ Univariate bridge**: WHIR は MLE (multilinear extension)、Plonky2 は univariate polynomial を使用。sumcheck で ⟨f, h_ζ⟩ = p(ζ) に帰着させることで、両者の代数構造の不整合を解消。
- **Hash function**: WHIR transcript は Keccak256 (post-quantum)、Plonky2 内部は Poseidon。on-chain では Keccak 統一。
- **Constraint check retention**: 制約チェック (~1.5M gas) は WHIR に統合せず独立に残す。統合には WHIR evaluation point の大改修が必要で、gas 削減効果が限定的なため。
