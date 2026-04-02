//! Sumcheck inner product argument for bridging univariate ↔ multilinear evaluation.
//!
//! # Purpose
//!
//! Proves that the inner product of a committed MLE `f` with the "powers-of-ζ"
//! function `h_ζ` equals a claimed univariate evaluation:
//!
//! ```text
//! Σ_{b ∈ {0,1}^n} f(b) · h_ζ(b) = p(ζ)
//! ```
//!
//! where `h_ζ(b) = ζ^{int(b)}` for `b ∈ {0,1}^n`, `int(b) = Σ b_j · 2^{j-1}`.
//!
//! After `n` rounds of the LFKN sumcheck protocol, the verifier is left with:
//! - A random point `r = (r_1, ..., r_n) ∈ F^n`
//! - A final claim that `f(r) · h_ζ(r) = v`
//! - `f(r)` is proved via WHIR evaluation proof
//! - `h_ζ(r)` is computed by the verifier (deterministic from ζ and r)
//!
//! # Soundness
//!
//! Over GoldilocksExt3 (|F| ≈ 2^192), the product f·h_ζ has degree 2 in each
//! variable, giving soundness error ≤ n·2/|F| ≈ 2^{-187} for n=16.

use whir::algebra::fields::{Field64, Field64_3};
use ark_ff::{Field, AdditiveGroup};

/// Embed a base field element into the cubic extension.
/// Field64_3 = CubicExtField, which implements From<u64>.
/// For Field64 → Field64_3: extract canonical u64, then construct.
pub fn base_to_ext3(v: Field64) -> Field64_3 {
    use ark_ff::PrimeField;
    let canonical = v.into_bigint().0[0];
    Field64_3::from(canonical)
}

/// Sumcheck proof: for each of n rounds, the prover sends g_i(0), g_i(1), g_i(2).
/// (Degree-2 univariate in each round since f·h_ζ has degree 2 per variable.)
///
/// Stored as raw u64 triples for serialization (Field64_3 = 3 × u64).
#[derive(Clone, Debug)]
pub struct SumcheckProof {
    /// Round polynomials: `round_polys[i] = [g_i(0), g_i(1), g_i(2)]` in Ext3.
    pub round_polys: Vec<[Field64_3; 3]>,
}

/// Result of sumcheck verification (or prover output).
#[derive(Clone, Debug)]
pub struct SumcheckResult {
    /// The random evaluation point r = (r_1, ..., r_n).
    pub point: Vec<Field64_3>,
    /// The final claim: f(r) · h_ζ(r) should equal this value.
    pub final_claim: Field64_3,
}

// ---------------------------------------------------------------------------
// h_ζ helper: powers-of-ζ function as MLE
// ---------------------------------------------------------------------------

/// Compute h_ζ(r) using WHIR's big-endian convention.
///
/// WHIR uses big-endian: r[0] = MSB, r[n-1] = LSB.
/// h_ζ(b) = ζ^{int(b)} where int interprets b in natural binary order.
///
/// For the tensor-product MLE:
///   h_ζ(r) = Π_{j=0}^{n-1} (1 - r_j + r_j · ζ^{2^{n-1-j}})
///
/// because r[j] corresponds to the bit at position 2^{n-1-j}.
pub fn eval_h_zeta(zeta: Field64_3, r: &[Field64_3]) -> Field64_3 {
    let n = r.len();
    let one = Field64_3::ONE;
    let mut result = one;

    // Precompute ζ^{2^k} for k = 0..n-1
    let mut zeta_powers = vec![zeta]; // zeta_powers[k] = ζ^{2^k}
    for _ in 1..n {
        let prev = *zeta_powers.last().unwrap();
        zeta_powers.push(prev * prev);
    }

    for j in 0..n {
        // r[j] corresponds to bit position 2^{n-1-j} (big-endian)
        let zp = zeta_powers[n - 1 - j];
        let term = (one - r[j]) + r[j] * zp;
        result *= term;
    }

    result
}

/// Build the full table h_ζ(b) for all b ∈ {0,1}^n.
///
/// WHIR uses big-endian bit ordering: for a point (x_0, ..., x_{n-1}),
/// x_0 is the most significant bit. So index i corresponds to
/// b_0 = (i >> (n-1)) & 1, ..., b_{n-1} = i & 1.
///
/// h_ζ(b) = ζ^{int_LE(b)} where int_LE interprets bits in little-endian
/// relative to the WHIR variable ordering.
///
/// For consistency with WHIR's MLE: the entry at index i stores ζ raised
/// to the power given by the bit-reversal of i (since WHIR's MSB-first
/// ordering reverses the natural bit indexing).
///
/// Returns a vector of length 2^n.
fn build_h_zeta_table(zeta: Field64_3, n: usize) -> Vec<Field64_3> {
    let size = 1usize << n;
    let mut table = vec![Field64_3::ONE; size];

    // We need h_ζ such that: Σ_i f[i] * h[i] = Σ_i c_i * ζ^i = p(ζ)
    // where f[i] = c_i (coefficient i of the univariate polynomial).
    // So h[i] = ζ^i (simple powers of ζ).
    if size > 1 {
        table[1] = zeta;
        for i in 2..size {
            table[i] = table[i - 1] * zeta;
        }
    }

    table
}

// ---------------------------------------------------------------------------
// Sumcheck prover
// ---------------------------------------------------------------------------

/// Run the sumcheck prover for the inner product <f, h_ζ>.
///
/// # Arguments
/// - `f_evals`: evaluations of f on {0,1}^n (length 2^n), in Field64 (base field)
/// - `zeta`: the univariate evaluation point in Ext3
/// - `claimed_sum`: the claimed value Σ f(b)·h_ζ(b) = p(ζ)
/// - `challenge_fn`: callback that takes round polynomial [g(0), g(1), g(2)]
///   and returns the verifier's random challenge r_i (for Fiat-Shamir integration)
///
/// # Returns
/// `(SumcheckProof, SumcheckResult)` — the proof and the final random point + claim.
pub fn sumcheck_prove<CF>(
    f_evals: &[Field64],
    zeta: Field64_3,
    claimed_sum: Field64_3,
    mut challenge_fn: CF,
) -> (SumcheckProof, SumcheckResult)
where
    CF: FnMut(&[Field64_3; 3]) -> Field64_3,
{
    let n = f_evals.len().trailing_zeros() as usize;
    let size = 1usize << n;
    assert_eq!(f_evals.len(), size, "f_evals length must be a power of 2");

    // Working copies: f and h values on the current "active" hypercube.
    // We progressively fix variables, halving the table each round.
    let mut f_table: Vec<Field64_3> = f_evals
        .iter()
        .map(|&v| base_to_ext3(v))
        .collect();
    let mut h_table = build_h_zeta_table(zeta, n);

    let mut round_polys = Vec::with_capacity(n);
    let mut challenges = Vec::with_capacity(n);
    let mut current_claim = claimed_sum;

    for round in 0..n {
        let half = 1usize << (n - round - 1);

        // Compute g_round(t) for t ∈ {0, 1, 2}:
        // g_round(t) = Σ_{b' ∈ {0,1}^{n-round-1}} f(t, b') · h(t, b')
        //
        // where f(t, b') and h(t, b') are obtained by fixing the current
        // variable x_{round} = t and summing over the remaining variables.
        //
        // For the "bookkeeping" representation:
        //   f_table[j]       = f(x_{round}=0, b'=j)
        //   f_table[half + j] = f(x_{round}=1, b'=j)
        // Similarly for h_table.

        let mut g = [Field64_3::ZERO; 3];

        for j in 0..half {
            let f0 = f_table[j];
            let f1 = f_table[half + j];
            let h0 = h_table[j];
            let h1 = h_table[half + j];

            // t=0: f(0,b') · h(0,b')
            g[0] += f0 * h0;

            // t=1: f(1,b') · h(1,b')
            g[1] += f1 * h1;

            // t=2: f(2,b') · h(2,b')
            // f(2,b') = f0 + 2·(f1 - f0) = 2·f1 - f0 (linear interpolation)
            // h(2,b') = h0 + 2·(h1 - h0) = 2·h1 - h0
            let two = Field64_3::from(2u64);
            let f2 = two * f1 - f0;
            let h2 = two * h1 - h0;
            g[2] += f2 * h2;
        }

        // Sanity check: g(0) + g(1) should equal current_claim
        debug_assert_eq!(
            g[0] + g[1],
            current_claim,
            "Sumcheck round {} consistency check failed",
            round
        );

        round_polys.push(g);

        // Get verifier's challenge for this round
        let r_i = challenge_fn(&g);
        challenges.push(r_i);

        // Update claim: g(r_i) via degree-2 interpolation on {0, 1, 2}
        // Using Lagrange: g(r) = g(0)·(r-1)(r-2)/2 + g(1)·r(r-2)/(-1) + g(2)·r(r-1)/2
        current_claim = eval_degree2_at(g, r_i);

        // "Fold" the tables: fix x_{round} = r_i
        // f_new[j] = f0[j] + r_i · (f1[j] - f0[j]) = (1 - r_i)·f0[j] + r_i·f1[j]
        let one_minus_r = Field64_3::ONE - r_i;
        for j in 0..half {
            f_table[j] = one_minus_r * f_table[j] + r_i * f_table[half + j];
            h_table[j] = one_minus_r * h_table[j] + r_i * h_table[half + j];
        }
        f_table.truncate(half);
        h_table.truncate(half);
    }

    // After n rounds, f_table and h_table each have 1 element:
    // f_table[0] = f(r), h_table[0] = h_ζ(r)
    debug_assert_eq!(f_table.len(), 1);
    debug_assert_eq!(h_table.len(), 1);

    let proof = SumcheckProof { round_polys };
    let result = SumcheckResult {
        point: challenges,
        final_claim: current_claim,
    };

    (proof, result)
}

/// Evaluate a degree-2 polynomial given by evaluations at {0, 1, 2} at point r.
///
/// Uses Lagrange interpolation:
///   g(r) = g(0)·(r-1)(r-2)/2 + g(1)·r·(r-2)/(-1) + g(2)·r·(r-1)/2
fn eval_degree2_at(g: [Field64_3; 3], r: Field64_3) -> Field64_3 {
    let one = Field64_3::ONE;
    let two = Field64_3::from(2u64);
    let inv2 = two.inverse().expect("2 is invertible in Ext3");

    // Lagrange basis at r:
    // L_0(r) = (r-1)(r-2) / (0-1)(0-2) = (r-1)(r-2) / 2
    // L_1(r) = r(r-2) / (1-0)(1-2) = r(r-2) / (-1) = -r(r-2)
    // L_2(r) = r(r-1) / (2-0)(2-1) = r(r-1) / 2
    let r_minus_1 = r - one;
    let r_minus_2 = r - two;

    let l0 = r_minus_1 * r_minus_2 * inv2;
    let l1 = -(r * r_minus_2);  // negation = multiply by -1
    let l2 = r * r_minus_1 * inv2;

    g[0] * l0 + g[1] * l1 + g[2] * l2
}

// ---------------------------------------------------------------------------
// Sumcheck verifier
// ---------------------------------------------------------------------------

/// Verify a sumcheck proof for the inner product <f, h_ζ>.
///
/// # Arguments
/// - `proof`: the sumcheck proof (round polynomials)
/// - `claimed_sum`: the claimed inner product value
/// - `challenge_fn`: callback that takes round polynomial and returns r_i
///   (must match the prover's Fiat-Shamir)
///
/// # Returns
/// `Ok(SumcheckResult)` with the final point and claim, or error.
pub fn sumcheck_verify<CF>(
    proof: &SumcheckProof,
    claimed_sum: Field64_3,
    mut challenge_fn: CF,
) -> Result<SumcheckResult, String>
where
    CF: FnMut(&[Field64_3; 3]) -> Field64_3,
{
    let n = proof.round_polys.len();
    let mut current_claim = claimed_sum;
    let mut challenges = Vec::with_capacity(n);

    for (round, g) in proof.round_polys.iter().enumerate() {
        // Check: g(0) + g(1) == current_claim
        if g[0] + g[1] != current_claim {
            return Err(format!(
                "Sumcheck round {}: g(0) + g(1) = {:?} != claim {:?}",
                round,
                g[0] + g[1],
                current_claim,
            ));
        }

        // Get verifier's challenge
        let r_i = challenge_fn(g);
        challenges.push(r_i);

        // Update claim: g(r_i)
        current_claim = eval_degree2_at(*g, r_i);
    }

    Ok(SumcheckResult {
        point: challenges,
        final_claim: current_claim,
    })
}

// ---------------------------------------------------------------------------
// Univariate evaluation via MLE
// ---------------------------------------------------------------------------

/// Evaluate a univariate polynomial p(x) = Σ c_i · x^i at point ζ,
/// given its coefficients laid out as MLE evaluations on {0,1}^n.
///
/// This computes p(ζ) = Σ_{b ∈ {0,1}^n} f(b) · ζ^{int(b)} = <f, h_ζ>.
pub fn eval_univariate_via_mle(coeffs: &[Field64], zeta: Field64_3) -> Field64_3 {
    let mut sum = Field64_3::ZERO;
    let mut zeta_power = Field64_3::ONE;
    for &c in coeffs.iter() {
        sum += base_to_ext3(c) * zeta_power;
        zeta_power *= zeta;
    }
    sum
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_std::rand::Rng;

    #[test]
    fn test_eval_h_zeta_matches_direct() {
        let mut rng = ark_std::test_rng();
        let n = 4;
        let zeta = Field64_3::rand(&mut rng);
        let r: Vec<Field64_3> = (0..n).map(|_| Field64_3::rand(&mut rng)).collect();

        // Direct: Σ_{b ∈ {0,1}^n} eq_BE(b,r) · ζ^{int(b)}
        // WHIR big-endian: r[j] corresponds to bit at position 2^{n-1-j}
        let h_table = build_h_zeta_table(zeta, n);
        let mut direct = Field64_3::ZERO;
        for (i, &h_val) in h_table.iter().enumerate() {
            // eq_BE(index i, r): bit j of index = (i >> (n-1-j)) & 1
            let mut eq_val = Field64_3::ONE;
            for j in 0..n {
                if (i >> (n - 1 - j)) & 1 == 1 {
                    eq_val *= r[j];
                } else {
                    eq_val *= Field64_3::ONE - r[j];
                }
            }
            direct += eq_val * h_val;
        }

        let fast = eval_h_zeta(zeta, &r);
        assert_eq!(fast, direct, "eval_h_zeta mismatch");
    }

    #[test]
    fn test_sumcheck_roundtrip() {
        let mut rng = ark_std::test_rng();
        let n = 8;
        let size = 1usize << n;

        // Random polynomial coefficients (base field)
        let coeffs: Vec<Field64> = (0..size)
            .map(|_| Field64::from(ark_std::test_rng().gen::<u64>() % (1u64 << 62)))
            .collect();

        // Random ζ in Ext3
        let zeta = Field64_3::rand(&mut rng);

        // Compute claimed sum = p(ζ) = Σ c_i · ζ^i
        let claimed_sum = eval_univariate_via_mle(&coeffs, zeta);

        // Simulate Fiat-Shamir with deterministic challenges
        let mut prover_challenges = Vec::new();
        let (proof, prover_result) = sumcheck_prove(
            &coeffs,
            zeta,
            claimed_sum,
            |_g| {
                let r = Field64_3::rand(&mut ark_std::test_rng());
                prover_challenges.push(r);
                r
            },
        );

        // Verify with same challenges
        let mut challenge_idx = 0;
        let verify_result = sumcheck_verify(
            &proof,
            claimed_sum,
            |_g| {
                let r = prover_challenges[challenge_idx];
                challenge_idx += 1;
                r
            },
        )
        .expect("Sumcheck verification failed");

        // Check: points match
        assert_eq!(prover_result.point, verify_result.point);
        // Check: final claims match
        assert_eq!(prover_result.final_claim, verify_result.final_claim);

        // Check: final_claim == f(r) · h_ζ(r)
        let r = &verify_result.point;
        let h_at_r = eval_h_zeta(zeta, r);

        // Compute f(r) via MLE evaluation (big-endian: r[j] = bit at 2^{n-1-j})
        let mut f_at_r = Field64_3::ZERO;
        for (i, &c) in coeffs.iter().enumerate() {
            let mut eq_val = Field64_3::ONE;
            for j in 0..n {
                if (i >> (n - 1 - j)) & 1 == 1 {
                    eq_val *= r[j];
                } else {
                    eq_val *= Field64_3::ONE - r[j];
                }
            }
            f_at_r += base_to_ext3(c) * eq_val;
        }

        assert_eq!(
            verify_result.final_claim,
            f_at_r * h_at_r,
            "Final claim mismatch: claim != f(r) * h_ζ(r)"
        );
    }

    #[test]
    fn test_soundness_bad_claim_rejected() {
        let mut rng = ark_std::test_rng();
        let n = 4;
        let size = 1usize << n;

        let coeffs: Vec<Field64> = (0..size)
            .map(|_| Field64::from(ark_std::test_rng().gen::<u64>() % (1u64 << 62)))
            .collect();

        let zeta = Field64_3::rand(&mut rng);
        let correct_sum = eval_univariate_via_mle(&coeffs, zeta);

        // Try with wrong claim
        let wrong_sum = correct_sum + Field64_3::ONE;

        let mut prover_challenges = Vec::new();
        let (proof, _) = sumcheck_prove(
            &coeffs,
            zeta,
            correct_sum, // prover uses correct sum
            |_g| {
                let r = Field64_3::rand(&mut ark_std::test_rng());
                prover_challenges.push(r);
                r
            },
        );

        // Verify with wrong claimed sum — should fail at round 0
        let mut challenge_idx = 0;
        let result = sumcheck_verify(
            &proof,
            wrong_sum, // verifier uses wrong sum
            |_g| {
                let r = prover_challenges[challenge_idx];
                challenge_idx += 1;
                r
            },
        );

        assert!(result.is_err(), "Should reject wrong claimed sum");
    }
}
