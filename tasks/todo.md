# Sumcheck Bridge: WHIR-Plonky2 Soundness Fix

## Problem Statement

現在のアーキテクチャでは WHIR と Plonky2 制約チェックの間に binding がなく、
悪意ある prover が偽の openings を提出して両方のチェックを通過できる（unsound）。

FRI が提供していた evaluation proof（コミット済み多項式の ζ での評価証明）が
WHIR 置換時に失われている。

## Solution: Sumcheck Bridge

univariate 評価 p(ζ) を multilinear MLE 評価に帰着させる sumcheck を追加し、
WHIR の evaluation proof で binding を確立する。

```
p(ζ) = Σ_{b∈{0,1}ⁿ} f(b) · ζ^int(b) = <f, h_ζ>
```

sumcheck で n ラウンドの対話に帰着 → 最終点 r で:
- f(r) は WHIR evaluation proof で証明
- h_ζ(r) は verifier が計算（ζ と r から決定論的）

---

## Phase 0: 設計検証 (Research)

- [ ] 0.1: sumcheck inner product argument の暗号学的安全性を検証
  - Schwartz-Zippel による soundness error bound の計算
  - n ラウンド sumcheck の各ラウンドの次数と soundness loss
  - 128-bit security に必要な field size の確認（Goldilocks 64-bit で十分か）

- [ ] 0.2: ガスコスト見積り
  - sumcheck 検証: n ラウンド × (多項式評価 + Fiat-Shamir squeeze)
  - h_ζ(r) 計算: n 回の field mul + add
  - 合計が FRI 直接検証 (~18.7M) より安くなるか

- [ ] 0.3: Fiat-Shamir transcript 統一の設計
  - 現在: WHIR は Keccak、Plonky2 は Poseidon（別々の transcript）
  - 目標: 全チャレンジを Keccak transcript から導出
  - ζ の導出タイミング: WHIR コミット後、sumcheck 前

---

## Phase 1: Rust Prover 改修

### 1A: Fiat-Shamir 統一

- [ ] 1A.1: WHIR transcript (spongefish/Keccak) で Plonky2 チャレンジを導出
  - WHIR コミット完了後、transcript を継続
  - wires_cap, zs_cap, quotient_cap を absorb
  - betas, gammas, alphas, ζ を squeeze
  - Plonky2 の Poseidon Challenger は使わない

- [ ] 1A.2: 新しい ζ で openings を再計算
  - prove_with_polys() から得た係数ベクトルで直接評価
  - W(ζ), Z(ζ), σ(ζ), Q(ζ) を Keccak 由来の ζ で計算

### 1B: Sumcheck Prover

- [ ] 1B.1: sumcheck inner product prover の実装
  - 入力: f (MLE 係数), h_ζ (ζ のべき乗テーブル), claim (p(ζ))
  - 各ラウンド i: 変数 x_i を fix し、他を {0,1} で sum
  - univariate polynomial g_i(X) を生成（次数 1: f は multilinear）
  - Fiat-Shamir で r_i を導出
  - n ラウンド後、最終点 r = (r_1, ..., r_n) を出力

- [ ] 1B.2: sumcheck proof のシリアライズ
  - 各ラウンドの g_i(0), g_i(1) を transcript に absorb
  - （g_i は次数 1 なので 2 点で決定）
  - proof = [g_1(0), g_1(1), g_2(0), g_2(1), ..., g_n(0), g_n(1)]

### 1C: WHIR Evaluation Point 変更

- [ ] 1C.1: canonical point (1,2,...,n) → sumcheck 由来の r に変更
  - whir crate の commit/prove API が任意の evaluation point を受け付けるか確認
  - 受け付けない場合、leohio/whir フォークの改修が必要

- [ ] 1C.2: evaluation proof の生成
  - WHIR が f(r) = v を証明
  - v は sumcheck の最終 claim と整合

### 1D: Export 改修

- [ ] 1D.1: export_onchain_data() の拡張
  - 追加データ: sumcheck proof (2n 個の field elements)
  - 追加データ: ζ (transcript 由来、検証用)
  - 追加データ: batch sizes (openings の decomposition 用)
  - challenges は export するが on-chain で再導出も可能に

- [ ] 1D.2: fixture 生成の更新
  - generate_fixture.rs を更新
  - 新フォーマットの JSON fixture を生成

---

## Phase 2: Solidity Verifier 改修

### 2A: Sumcheck Verifier

- [ ] 2A.1: SumcheckVerifier.sol の新規作成
  - 入力: sumcheck proof, claimed sum, ζ
  - 各ラウンド i:
    - g_i(0) + g_i(1) == 前ラウンドの claim を検証
    - Fiat-Shamir で r_i を squeeze
    - 次ラウンドの claim = g_i(r_i) を計算
  - 出力: 最終点 r = (r_1,...,r_n), 最終 claim v

- [ ] 2A.2: h_ζ(r) の on-chain 計算
  - h_ζ(r) = Π_{j=1}^{n} ((1-r_j)(1-0) + r_j · ζ^(2^(j-1)))
  - 注: h_ζ は MLE of [1, ζ, ζ², ..., ζ^(2ⁿ-1)] を r で評価
  - テンソル積構造: h_ζ(r) = Π_{j=1}^{n} (1 - r_j + r_j · ζ^(2^(j-1)))

### 2B: WHIR Verification 改修

- [ ] 2B.1: SpongefishWhirVerify.sol の evaluation point 変更
  - canonical point → sumcheck 由来の r
  - verifyWhirProof の引数に r を追加

### 2C: 統合

- [ ] 2C.1: CombinedVerifier.sol の新規作成
  - 統合フロー:
    1. WHIR transcript を replay → コミットメント検証
    2. transcript 継続 → ζ, betas, gammas, alphas を導出
    3. sumcheck 検証 → 最終点 r, 最終 claim v を取得
    4. WHIR evaluation proof 検証 → f(r) = v' を確認
    5. h_ζ(r) を計算 → v == v' · h_ζ(r) を検証（注: 要確認）
    6. openings で制約チェック（既存ロジック）

- [ ] 2C.2: openings decomposition
  - v から個別の W(ζ), Z(ζ), σ(ζ), Q(ζ) を分離
  - batch sizes に基づいて分解
  - 各 batch の evaluation = Σ coeffs · ζ^i → batch 間の ζ offset で分離可能

---

## Phase 3: テスト & 検証

- [ ] 3.1: Rust 単体テスト
  - sumcheck prover/verifier の round-trip テスト
  - 新 Fiat-Shamir での proof 生成 → off-chain 検証

- [ ] 3.2: Solidity 単体テスト
  - SumcheckVerifier の fixture-based テスト
  - h_ζ(r) 計算の正確性テスト

- [ ] 3.3: E2E テスト
  - Rust で新フォーマット proof 生成 → Solidity で on-chain 検証
  - validity proof と fraud proof の両方

- [ ] 3.4: ガスベンチマーク
  - 各コンポーネントのガス測定
  - FRI 直接検証 (~18.7M) との比較

---

## リスク & 未解決事項

1. **leohio/whir の改修必要性**: canonical point 以外での evaluation proof を
   whir crate がサポートしているか要確認。サポートしていなければフォーク改修必要。

2. **Goldilocks field の soundness**: 64-bit field での sumcheck は
   各ラウンド d/|F| の soundness loss。n=16 ラウンド、d=1 なら
   total error ≈ 16/2^64 ≈ 無視可能。

3. **openings decomposition の正確性**: 連結多項式から個別 batch の ζ 評価を
   on-chain で分離する数学的手続きの詳細設計が必要。

4. **ガス効率**: sumcheck n ラウンド + h_ζ(r) 計算の追加ガスが、
   現在の ~21.1M からどの程度増えるか。FRI (~18.7M) を上回る可能性。

5. **Ext2 vs Ext3**: Plonky2 は GoldilocksExt2 (α²=7)、WHIR は GoldilocksExt3。
   sumcheck bridge で field extension の変換が必要になる可能性。
