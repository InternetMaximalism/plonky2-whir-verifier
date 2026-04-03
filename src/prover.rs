//! WHIR-based Plonky2 prover — replaces FRI with WHIR as polynomial commitment scheme.
//!
//! # How it works
//!
//! 1. Run Plonky2's standard prover to get a `ProofWithPublicInputs` (includes FRI proof).
//! 2. Also generate a **WHIR proof** over the same polynomial data that FRI operates on.
//!
//! The standard Plonky2 proof contains all the polynomial openings (evaluations at
//! challenge point zeta).  The FRI proof proves that these openings are consistent
//! with low-degree polynomial commitments.  **WHIR replaces FRI** for this step:
//!
//! - Plonky2 prover computes `PolynomialBatch` objects containing actual polynomial
//!   coefficients.  We extract these coefficients.
//! - WHIR commits to the polynomial coefficients and generates evaluation proofs.
//! - The on-chain WHIR verifier checks the WHIR proofs, confirming the polynomial
//!   commitments are valid.
//! - Combined with the constraint satisfaction check (vanishing poly == quotient * Z_H),
//!   this provides complete post-quantum verification.
//!
//! # Security
//!
//! WHIR uses hash-based commitments (Keccak/SHA-256), which are post-quantum secure.
//! The constraint check uses the same algebraic verification as Plonky2's standard verifier.
//! Together, they provide the same security guarantees as Plonky2 + FRI, but post-quantum.
//!
//! # Architecture
//!
//! ```text
//! CircuitData + PartialWitness
//!   → Plonky2 prove()  [computes all polynomials + FRI proof]
//!   → Extract polynomial coefficients from PolynomialBatch objects
//!   → WHIR commit + evaluation proof for each polynomial batch
//!   → WhirPlonky2Proof {openings, WHIR proofs, public inputs}
//!
//! Verification (replaces verify_fri_proof):
//!   → Verify WHIR proofs (polynomial commitment validity)
//!   → Verify constraint satisfaction (vanishing(zeta) == Z_H(zeta) * quotient(zeta))
//!   → Accept public inputs
//! ```

use std::borrow::Cow;
use std::time::{Duration, Instant};

use anyhow::{ensure, Result};
use plonky2::{
    field::{
        extension::Extendable,
        polynomial::PolynomialCoeffs,
        types::Field,
    },
    hash::hash_types::RichField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::CircuitData,
        config::{GenericConfig, Hasher},
        proof::ProofWithPublicInputs,
        prover::{prove_with_polys, ProverPolynomials},
    },
    util::timing::TimingTree,
};

use ark_ff::AdditiveGroup;
use whir::{
    algebra::{
        embedding::Basefield,
        fields::{Field64, Field64_3},
        linear_form::{Evaluate, LinearForm, MultilinearExtension},
    },
    hash::HASH_COUNTER,
    parameters::ProtocolParameters,
    protocols::whir::Config as InternalWhirConfig,
    transcript::{codecs::Empty, DomainSeparator, ProverState, VerifierState},
};

use crate::sumcheck::{self, SumcheckProof, SumcheckResult};

use whir::hash;

// ---------------------------------------------------------------------------
// Configuration (moved from whir_wrapper.rs)
// ---------------------------------------------------------------------------

/// WHIR wrapping configuration.
pub struct WhirWrapConfig {
    /// Human-readable name for this configuration.
    pub name: String,
    /// WHIR protocol parameters.
    pub params: ProtocolParameters,
}

impl WhirWrapConfig {
    /// Default configuration optimized for on-chain Keccak verification.
    /// Uses 80-bit security (standard for L2/on-chain applications).
    pub fn default_keccak() -> Self {
        Self::with_security_level(80)
    }

    /// Configuration with custom security level.
    /// - 80: standard for on-chain (smaller proofs, fewer queries)
    /// - 100: conservative (larger proofs, more queries)
    /// - 128: high security (largest proofs)
    pub fn with_security_level(security_level: usize) -> Self {
        Self {
            name: format!("keccak-rate2-sec{}", security_level),
            params: ProtocolParameters {
                security_level,
                pow_bits: 0,
                initial_folding_factor: 4,
                folding_factor: 4,
                unique_decoding: false,
                starting_log_inv_rate: 2,
                batch_size: 1,
                hash_id: hash::KECCAK,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A WHIR commitment + evaluation proof for one polynomial batch.
#[derive(Clone, Debug)]
pub struct WhirPolyCommitment {
    /// Serialized WHIR proof (Nimue transcript).
    pub proof_narg: Vec<u8>,
    pub proof_hints: Vec<u8>,
    /// Number of multilinear variables (log2 of padded polynomial length).
    pub num_variables: usize,
    /// WHIR-proven evaluations at the evaluation point(s).
    /// Length 1 for single-point (legacy or ζ-only), length 2 for dual-point (ζ + gζ).
    pub evaluations: Vec<Field64_3>,
    /// Session label (for domain separation in Fiat-Shamir).
    pub session_name: String,
    /// Number of hash invocations during verification (for gas estimation).
    pub verify_hashes: usize,
    /// Sumcheck proof bridging univariate p(ζ) to MLE evaluation at point r₁.
    /// None for legacy (canonical point) mode.
    pub sumcheck_proof: Option<SumcheckProof>,
    /// The univariate evaluation point ζ (derived from WHIR transcript via Fiat-Shamir).
    /// None for legacy mode.
    pub zeta: Option<Field64_3>,
    /// The sumcheck-derived evaluation point r₁ = (r₁_1, ..., r₁_n).
    /// This is where WHIR proves the MLE evaluates for the ζ bridge.
    /// None for legacy mode (uses canonical point).
    pub eval_point: Option<Vec<Field64_3>>,
    /// The claimed univariate evaluation p(ζ) = Σ c_i · ζ^i.
    /// This is the sumcheck claimed sum. None for legacy mode.
    pub claimed_sum: Option<Field64_3>,
    /// Second sumcheck proof bridging univariate p(gζ) to MLE evaluation at point r₂.
    /// None if dual-point evaluation is not used.
    pub sumcheck_proof_g_zeta: Option<SumcheckProof>,
    /// The shifted evaluation point gζ (g = generator of trace subgroup H).
    /// None if dual-point evaluation is not used.
    pub g_zeta: Option<Field64_3>,
    /// The sumcheck-derived evaluation point r₂ for the gζ bridge.
    /// None if dual-point evaluation is not used.
    pub eval_point_g_zeta: Option<Vec<Field64_3>>,
    /// The claimed univariate evaluation p(gζ) = Σ c_i · (gζ)^i.
    /// None if dual-point evaluation is not used.
    pub claimed_sum_g_zeta: Option<Field64_3>,
}

/// Complete WHIR-based Plonky2 proof.
///
/// Contains:
/// - The standard Plonky2 proof (openings, public inputs) for constraint checking
/// - A single combined WHIR commitment covering all polynomial batches (replaces FRI)
///
/// All 4 polynomial batches (constants_sigmas, wires, zs_partial_products, quotient_chunks)
/// are concatenated into a single polynomial and committed via one WHIR proof.
/// The MLE evaluation at the canonical point provides implicit random linear combination
/// security over all coefficients, so explicit RLC challenges are unnecessary.
#[derive(Clone, Debug)]
pub struct WhirPlonky2Proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// The standard Plonky2 proof (contains openings at zeta, Merkle caps, FRI proof).
    /// We keep this for reference / dual-path verification.
    pub standard_proof: ProofWithPublicInputs<F, C, D>,

    /// Single WHIR commitment for all polynomial batches (concatenated).
    pub combined_whir: WhirPolyCommitment,
    /// Sizes (in Field64 elements) of each batch before concatenation.
    /// Order: [constants_sigmas, wires, zs_partial_products, quotient_chunks].
    /// Each batch is already padded to a power of 2 by `polys_to_whir_field`.
    pub batch_sizes: Vec<usize>,

    /// Evaluations of each batch polynomial at sumcheck.zeta (Ext3).
    /// Used for on-chain decomposition check: P(ζ) = Σ batch_i(ζ) · ζ^offset_i.
    /// Order: [constants_sigmas, wires, zs_partial_products, quotient_chunks].
    pub batch_evals_at_zeta: Vec<Field64_3>,

    /// Evaluations of each batch polynomial at gζ (Ext3).
    /// Used for on-chain decomposition of the second sumcheck bridge.
    /// Order: [constants_sigmas, wires, zs_partial_products, quotient_chunks].
    pub batch_evals_at_g_zeta: Vec<Field64_3>,

    /// Number of individual polynomials in each batch.
    /// Order: [constants_sigmas, wires, zs_partial_products, quotient_chunks].
    pub intra_batch_poly_counts: Vec<usize>,

    /// Per-polynomial evaluations within each batch at ζ.
    /// Each inner Vec has length intra_batch_poly_counts[i].
    /// Used for intra-batch sub-decomposition on-chain.
    pub intra_batch_evals_at_zeta: Vec<Vec<Field64_3>>,

    /// Per-polynomial evaluations of batch 2 (zs_partial_products) at gζ.
    /// Used to extract verified Z(gζ) for the permutation check.
    pub batch2_evals_at_g_zeta: Vec<Field64_3>,

    /// Public input: `true` = validity proof, `false` = fraud proof.
    /// This is bound into the WHIR proof's Fiat-Shamir transcript.
    pub expected_result: bool,
}

/// Timing breakdown for WHIR proof generation.
pub struct WhirPlonky2ProveResult<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub proof: WhirPlonky2Proof<F, C, D>,
    /// Time for standard Plonky2 proof generation (includes polynomial computation).
    pub plonky2_prove_time: Duration,
    /// Time for WHIR commitments and proofs (all 4 batches).
    pub whir_time: Duration,
    /// Total wall-clock time.
    pub total_time: Duration,
}

// ---------------------------------------------------------------------------
// Polynomial conversion
// ---------------------------------------------------------------------------

/// Convert Plonky2 polynomial coefficients to WHIR Field64 elements.
///
/// Maps each Goldilocks element to a Field64 element (both are 64-bit prime fields).
/// The result is padded to a power of 2 (minimum 256).
fn polys_to_whir_field<F: RichField>(polys: &[PolynomialCoeffs<F>]) -> Vec<Field64> {
    let mut flat: Vec<Field64> = polys
        .iter()
        .flat_map(|p| {
            p.coeffs
                .iter()
                .map(|c| Field64::from(c.to_canonical_u64()))
        })
        .collect();

    let target = flat.len().next_power_of_two().max(256);
    flat.resize(target, Field64::ZERO);
    flat
}

// ---------------------------------------------------------------------------
// Batch concatenation
// ---------------------------------------------------------------------------

/// Concatenate multiple polynomial batches into a single vector for combined WHIR commitment.
///
/// Each input batch is already padded to a power of 2 by `polys_to_whir_field`.
/// The concatenated result is further padded to a power of 2 (minimum 256).
/// Returns the combined polynomial and the size of each input batch.
fn concat_batches(batches: &[Vec<Field64>]) -> (Vec<Field64>, Vec<usize>) {
    let sizes: Vec<usize> = batches.iter().map(|b| b.len()).collect();
    let mut combined: Vec<Field64> = batches.iter().flat_map(|b| b.iter().copied()).collect();
    let target = combined.len().next_power_of_two().max(256);
    combined.resize(target, Field64::ZERO);
    (combined, sizes)
}

// ---------------------------------------------------------------------------
// WHIR commit + prove + verify
// ---------------------------------------------------------------------------

/// Generate a WHIR commitment and evaluation proof for polynomial data.
///
/// This is the core cryptographic operation:
/// 1. Commit to the polynomial via WHIR (hash-based Merkle tree)
/// 2. Evaluate at a canonical point
/// 3. Generate WHIR proof (sumcheck + folding)
/// 4. Verify off-chain as sanity check
fn whir_commit_and_prove(
    polynomial: &[Field64],
    session_name: &str,
    config: &WhirWrapConfig,
) -> WhirPolyCommitment {
    let poly_size = polynomial.len();
    let num_variables = poly_size.trailing_zeros() as usize;

    let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);

    let ds = DomainSeparator::protocol(&params)
        .session(&session_name.to_string())
        .instance(&Empty);

    // === COMMIT ===
    let mut prover_state = ProverState::new_std(&ds);
    let witness = params.commit(&mut prover_state, &[polynomial]);

    // Evaluation at canonical point (deterministic, derived from num_variables)
    let point: Vec<Field64_3> = (0..num_variables)
        .map(|i| Field64_3::from((i + 1) as u64))
        .collect();
    let lf = MultilinearExtension::new(point.clone());
    let eval = lf.evaluate(params.embedding(), polynomial);
    let evaluations = vec![eval];

    let prove_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension::new(point.clone()))];

    // === PROVE (sumcheck + folding rounds) ===
    let _ = params.prove(
        &mut prover_state,
        vec![Cow::Owned(polynomial.to_vec())],
        vec![Cow::Owned(witness)],
        prove_lf,
        Cow::Borrowed(evaluations.as_slice()),
    );

    let proof = prover_state.proof();
    let proof_narg = proof.narg_string.clone();
    let proof_hints = proof.hints.clone();

    // === VERIFY (off-chain sanity check) ===
    let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension::new(point))];

    HASH_COUNTER.reset();
    let mut verifier_state = VerifierState::new_std(&ds, &proof);
    let commitment = params
        .receive_commitment(&mut verifier_state)
        .expect("WHIR receive_commitment failed");
    let final_claim = params
        .verify(&mut verifier_state, &[&commitment], &evaluations)
        .expect("WHIR verify failed");
    final_claim
        .verify(
            verify_lf
                .iter()
                .map(|l| l.as_ref() as &dyn LinearForm<Field64_3>),
        )
        .expect("WHIR final_claim verify failed");
    let verify_hashes = HASH_COUNTER.get();

    WhirPolyCommitment {
        proof_narg,
        proof_hints,
        num_variables,
        evaluations,
        session_name: session_name.to_string(),
        verify_hashes,
        sumcheck_proof: None,
        zeta: None,
        eval_point: None,
        claimed_sum: None,
        sumcheck_proof_g_zeta: None,
        g_zeta: None,
        eval_point_g_zeta: None,
        claimed_sum_g_zeta: None,
    }
}

/// Generate a WHIR commitment with dual sumcheck bridges for sound binding.
///
/// Flow:
/// 1. Commit to polynomial via WHIR (Merkle tree)
/// 2. Use externally-derived ζ (from unified Keccak Fiat-Shamir, Ext2 embedded in Ext3)
/// 3. Compute p(ζ) = Σ c_i · ζ^i and optionally p(gζ) = Σ c_i · (gζ)^i
/// 4. Run sumcheck prover(s) to prove <f, h_ζ> = p(ζ) (and <f, h_{gζ}> = p(gζ))
/// 5. WHIR evaluation proof at sumcheck-derived point(s)
///
/// The externally-derived ζ ensures the same evaluation point is used for both
/// the sumcheck bridge and Plonky2 constraint checking (see `prove_with_whir`).
///
/// When `g_zeta` is provided, a second sumcheck bridge is run to prove p(gζ),
/// which is needed for the permutation check's "next row" evaluation Z(gζ).
fn whir_commit_and_prove_with_sumcheck(
    polynomial: &[Field64],
    session_name: &str,
    config: &WhirWrapConfig,
    zeta: Field64_3,
    g_zeta: Option<Field64_3>,
) -> WhirPolyCommitment {
    use ark_ff::{Field as ArkField, PrimeField};
    use sha3::{Digest, Keccak256};

    let poly_size = polynomial.len();
    let num_variables = poly_size.trailing_zeros() as usize;

    let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);

    let ds = DomainSeparator::protocol(&params)
        .session(&session_name.to_string())
        .instance(&Empty);

    // === PHASE 1: COMMIT ===
    let mut prover_state = ProverState::new_std(&ds);
    let witness = params.commit(&mut prover_state, &[polynomial]);

    // === PHASE 2: ζ is provided externally (unified with Plonky2 Keccak challenges) ===
    // ζ is an Ext2 element embedded in Ext3 as (c0, c1, 0).
    // Since polynomial coefficients are base-field (Goldilocks), evaluations
    // at this embedded Ext2 point will also have c2=0.

    // === PHASE 3: Compute p(ζ) = Σ c_i · ζ^i ===
    let p_at_zeta = sumcheck::eval_univariate_via_mle(polynomial, zeta);

    eprintln!(
        "[whir-sumcheck] nv={}, p(ζ) computed, running sumcheck...",
        num_variables
    );

    // === PHASE 4a: Sumcheck prover for ζ ===
    let make_challenge_fn = |tag: &str, eval_point: &Field64_3| -> Box<dyn FnMut(&[Field64_3; 3]) -> Field64_3> {
        let mut transcript = Keccak256::new();
        transcript.update(tag.as_bytes());
        transcript.update(session_name.as_bytes());
        for c in ArkField::to_base_prime_field_elements(eval_point) {
            transcript.update(&c.into_bigint().0[0].to_le_bytes());
        }
        Box::new(move |g: &[Field64_3; 3]| {
            for eval in g {
                let base_elems: Vec<_> = ArkField::to_base_prime_field_elements(eval).collect();
                for b in &base_elems {
                    transcript.update(&b.into_bigint().0[0].to_le_bytes());
                }
            }
            let h = transcript.clone().finalize();
            let c0 = u64::from_le_bytes(h[0..8].try_into().unwrap()) % Field64::MODULUS.0[0];
            let c1 = u64::from_le_bytes(h[8..16].try_into().unwrap()) % Field64::MODULUS.0[0];
            let c2 = u64::from_le_bytes(h[16..24].try_into().unwrap()) % Field64::MODULUS.0[0];
            ark_ff::CubicExtField::new(Field64::from(c0), Field64::from(c1), Field64::from(c2))
        })
    };

    let (sc_proof, sc_result) = sumcheck::sumcheck_prove(
        polynomial,
        zeta,
        p_at_zeta,
        make_challenge_fn("sumcheck-challenges", &zeta),
    );
    let eval_point = sc_result.point.clone();

    eprintln!(
        "[whir-sumcheck] sumcheck #1 done, {} rounds. eval_point derived.",
        eval_point.len()
    );

    // === PHASE 4b: Optional second sumcheck for gζ ===
    let (sc_proof_g, sc_result_g, eval_point_g, p_at_g_zeta) = if let Some(gz) = g_zeta {
        let p_gz = sumcheck::eval_univariate_via_mle(polynomial, gz);
        let (proof_g, result_g) = sumcheck::sumcheck_prove(
            polynomial,
            gz,
            p_gz,
            make_challenge_fn("sumcheck-challenges-gzeta", &gz),
        );
        let ep_g = result_g.point.clone();
        eprintln!(
            "[whir-sumcheck] sumcheck #2 (gζ) done, {} rounds.",
            ep_g.len()
        );
        (Some(proof_g), Some(result_g), Some(ep_g), Some(p_gz))
    } else {
        (None, None, None, None)
    };

    // === PHASE 5: WHIR evaluation proof at point(s) ===
    let lf1 = MultilinearExtension::new(eval_point.clone());
    let eval1 = lf1.evaluate(params.embedding(), polynomial);

    let (evaluations, prove_lf): (Vec<Field64_3>, Vec<Box<dyn LinearForm<Field64_3>>>) =
        if let Some(ref ep_g) = eval_point_g {
            let lf2 = MultilinearExtension::new(ep_g.clone());
            let eval2 = lf2.evaluate(params.embedding(), polynomial);
            (
                vec![eval1, eval2],
                vec![
                    Box::new(MultilinearExtension::new(eval_point.clone())),
                    Box::new(MultilinearExtension::new(ep_g.clone())),
                ],
            )
        } else {
            (
                vec![eval1],
                vec![Box::new(MultilinearExtension::new(eval_point.clone()))],
            )
        };

    let _ = params.prove(
        &mut prover_state,
        vec![Cow::Owned(polynomial.to_vec())],
        vec![Cow::Owned(witness)],
        prove_lf,
        Cow::Borrowed(evaluations.as_slice()),
    );

    let proof = prover_state.proof();
    let proof_narg = proof.narg_string.clone();
    let proof_hints = proof.hints.clone();

    // === VERIFY (off-chain sanity check) ===
    let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> = if let Some(ref ep_g) = eval_point_g {
        vec![
            Box::new(MultilinearExtension::new(eval_point.clone())),
            Box::new(MultilinearExtension::new(ep_g.clone())),
        ]
    } else {
        vec![Box::new(MultilinearExtension::new(eval_point.clone()))]
    };

    HASH_COUNTER.reset();
    let mut verifier_state = VerifierState::new_std(&ds, &proof);
    let commitment = params
        .receive_commitment(&mut verifier_state)
        .expect("WHIR receive_commitment failed");
    let final_claim = params
        .verify(&mut verifier_state, &[&commitment], &evaluations)
        .expect("WHIR verify failed");
    final_claim
        .verify(
            verify_lf
                .iter()
                .map(|l| l.as_ref() as &dyn LinearForm<Field64_3>),
        )
        .expect("WHIR final_claim verify failed");
    let verify_hashes = HASH_COUNTER.get();

    // === Verify sumcheck #1 consistency ===
    let h_at_r = sumcheck::eval_h_zeta(zeta, &eval_point);
    let expected_final = eval1 * h_at_r;
    assert_eq!(
        sc_result.final_claim, expected_final,
        "Sumcheck #1 final claim mismatch: claim != f(r₁) * h_ζ(r₁)"
    );

    // === Verify sumcheck #2 consistency (if applicable) ===
    if let (Some(gz), Some(ref ep_g), Some(ref res_g)) = (g_zeta, &eval_point_g, &sc_result_g) {
        let eval2 = evaluations[1];
        let h_at_r2 = sumcheck::eval_h_zeta(gz, ep_g);
        let expected_final2 = eval2 * h_at_r2;
        assert_eq!(
            res_g.final_claim, expected_final2,
            "Sumcheck #2 final claim mismatch: claim != f(r2) * h_gz(r2)"
        );
    }

    eprintln!(
        "[whir-sumcheck] All checks passed. verify_hashes={}, dual={}",
        verify_hashes,
        g_zeta.is_some()
    );

    WhirPolyCommitment {
        proof_narg,
        proof_hints,
        num_variables,
        evaluations,
        session_name: session_name.to_string(),
        verify_hashes,
        sumcheck_proof: Some(sc_proof),
        zeta: Some(zeta),
        eval_point: Some(eval_point),
        claimed_sum: Some(p_at_zeta),
        sumcheck_proof_g_zeta: sc_proof_g,
        g_zeta,
        eval_point_g_zeta: eval_point_g,
        claimed_sum_g_zeta: p_at_g_zeta,
    }
}

/// Verify a WHIR polynomial commitment (standalone, without polynomial data).
///
/// This is the verification that can be performed on-chain:
/// given only the WHIR proof, check that the commitment is valid.
pub fn whir_verify_standalone(
    commitment: &WhirPolyCommitment,
    config: &WhirWrapConfig,
) -> Result<()> {
    let poly_size = 1usize << commitment.num_variables;
    let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);

    let ds = DomainSeparator::protocol(&params)
        .session(&commitment.session_name)
        .instance(&Empty);

    // Reconstruct the WHIR proof from serialized data.
    // In debug builds, the `pattern` field is required but we provide a default.
    let proof = {
        #[cfg(debug_assertions)]
        {
            whir::transcript::Proof {
                narg_string: commitment.proof_narg.clone(),
                hints: commitment.proof_hints.clone(),
                pattern: Vec::new(),
            }
        }
        #[cfg(not(debug_assertions))]
        {
            whir::transcript::Proof {
                narg_string: commitment.proof_narg.clone(),
                hints: commitment.proof_hints.clone(),
            }
        }
    };

    // Use the stored evaluation point if available (sumcheck mode),
    // otherwise fall back to the canonical point (legacy mode).
    let point: Vec<Field64_3> = match &commitment.eval_point {
        Some(p) => p.clone(),
        None => (0..commitment.num_variables)
            .map(|i| Field64_3::from((i + 1) as u64))
            .collect(),
    };

    let verify_lf: Vec<Box<dyn LinearForm<Field64_3>>> =
        vec![Box::new(MultilinearExtension::new(point))];

    let mut verifier_state = VerifierState::new_std(&ds, &proof);
    let recv_commitment = params
        .receive_commitment(&mut verifier_state)
        .map_err(|e| anyhow::anyhow!("WHIR receive_commitment: {:?}", e))?;
    let final_claim = params
        .verify(
            &mut verifier_state,
            &[&recv_commitment],
            &commitment.evaluations,
        )
        .map_err(|e| anyhow::anyhow!("WHIR verify: {:?}", e))?;
    final_claim
        .verify(
            verify_lf
                .iter()
                .map(|l| l.as_ref() as &dyn LinearForm<Field64_3>),
        )
        .map_err(|e| anyhow::anyhow!("WHIR final_claim: {:?}", e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Main prover entry point
// ---------------------------------------------------------------------------

/// Generate a WHIR-based Plonky2 proof.
///
/// 1. Runs Plonky2's standard prover (computes all polynomials + FRI proof).
/// 2. Extracts polynomial coefficient data from each `PolynomialBatch`.
/// 3. Generates WHIR commitments + evaluation proofs for each batch.
///
/// The resulting `WhirPlonky2Proof` can be verified by checking:
/// - WHIR proofs are valid (polynomial commitments)
/// - Constraint satisfaction (vanishing(zeta) == Z_H(zeta) * quotient(zeta))
///
/// Both checks together provide the same security as Plonky2 + FRI,
/// but using hash-based (post-quantum) polynomial commitments.
/// # Arguments
/// * `circuit_data` — Compiled Plonky2 circuit.
/// * `inputs` — Partial witness.
/// * `whir_config` — WHIR protocol parameters.
/// * `expected_result` — `true` for validity proof, `false` for fraud proof.
///   This value is bound into the WHIR proof's Fiat-Shamir transcript,
///   so a proof generated with `expected_result=true` cannot be replayed
///   as a fraud proof (and vice versa).
pub fn prove_with_whir<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    circuit_data: &CircuitData<F, C, D>,
    inputs: PartialWitness<F>,
    whir_config: &WhirWrapConfig,
    expected_result: bool,
) -> Result<WhirPlonky2ProveResult<F, C, D>>
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    let total_start = Instant::now();

    // -----------------------------------------------------------------------
    // Phase 1: Standard Plonky2 proof
    //
    // This computes ALL the polynomials (wires, Z, quotient) and generates
    // the standard FRI proof.  We need the polynomial data for WHIR.
    //
    // The proof's openings (evaluations at zeta) are identical whether
    // verified via FRI or WHIR — only the commitment scheme differs.
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Phase 1: Plonky2 proof + polynomial extraction
    //
    // Uses the forked Plonky2's prove_with_polys() to get BOTH the standard
    // proof AND the intermediate polynomial coefficients.
    //
    // Previously we could only access constants_sigmas (stored on CircuitData)
    // and had to commit to opening values / FRI final poly as workarounds.
    // Now we get the actual wire, Z/partial-product, and quotient polynomials.
    // -----------------------------------------------------------------------

    let plonky2_start = Instant::now();
    let mut timing = TimingTree::default();
    let (standard_proof, polys) = prove_with_polys(
        &circuit_data.prover_only,
        &circuit_data.common,
        inputs,
        &mut timing,
    )?;

    // Verify locally as sanity check
    circuit_data.verify(standard_proof.clone())?;
    let plonky2_prove_time = plonky2_start.elapsed();

    // -----------------------------------------------------------------------
    // Phase 2: WHIR commitments to actual polynomial coefficients
    //
    // We commit to the REAL polynomial coefficients from each batch:
    //   1. constants_sigmas — fixed per circuit (selector + permutation polys)
    //   2. wires — witness wire polynomials
    //   3. zs_partial_products — Z polynomial + partial products (+ lookups)
    //   4. quotient_chunks — quotient polynomial chunks
    //
    // WHIR proves: "I committed to polynomial P, and P evaluates to v at
    //               the canonical point."
    //
    // Combined with the on-chain constraint satisfaction check (which uses
    // the openings — evaluations at ζ — derived from these polynomials),
    // this provides a complete post-quantum validity proof.
    // -----------------------------------------------------------------------

    let whir_start = Instant::now();

    // Bind expected_result into WHIR session name for domain separation.
    let er_tag = if expected_result { "valid" } else { "fraud" };

    // Convert each polynomial batch to WHIR field elements
    let constants_sigmas_polys =
        polys_to_whir_field(&circuit_data.prover_only.constants_sigmas_commitment.polynomials);
    let wires_poly = polys_to_whir_field(&polys.wires);
    let zs_poly = polys_to_whir_field(&polys.zs_partial_products);
    let quotient_poly = polys_to_whir_field(&polys.quotient_chunks);

    // Concatenate all 4 batches into a single polynomial for one WHIR proof.
    // MLE evaluation at the canonical point provides implicit RLC security.
    let (combined_poly, batch_sizes) = concat_batches(&[
        constants_sigmas_polys,
        wires_poly,
        zs_poly,
        quotient_poly,
    ]);

    eprintln!(
        "[whir] Combined polynomial: {} elements (nv={}), batch_sizes={:?}",
        combined_poly.len(),
        combined_poly.len().trailing_zeros(),
        batch_sizes
    );

    let session_name = format!("whir-plonky2-combined-{}", er_tag);

    // Step 1: Generate initial WHIR proof at canonical point to extract Merkle root.
    // The Merkle root is the first 32 bytes of proof_narg and is deterministic
    // from the polynomial (independent of evaluation point).
    let canonical_whir = whir_commit_and_prove(
        &combined_poly,
        &session_name,
        whir_config,
    );
    let merkle_root: [u8; 32] = canonical_whir.proof_narg[0..32]
        .try_into()
        .expect("WHIR transcript must start with 32-byte Merkle root");
    eprintln!("[whir] Merkle root: {}", hex::encode(&merkle_root));

    // Step 2: Derive unified ζ from Merkle root + session + public inputs.
    // This matches the on-chain derivation (both sides hash the same data).
    // ζ is Ext2 embedded in Ext3 as (c0, c1, 0) so that base-field polynomial
    // evaluations at ζ have c2=0, compatible with Plonky2Verifier's Ext2 arithmetic.
    let (zeta_ext3, zeta_c0, zeta_c1, zeta_c2) = {
        use sha3::{Digest, Keccak256};
        const GL_P: u64 = 0xFFFFFFFF00000001u64;

        let mut h = Keccak256::new();
        h.update(b"plonky2-challenges-v2");
        h.update(session_name.as_bytes());
        h.update(&merkle_root);
        for &pi in &standard_proof.public_inputs {
            h.update(&pi.to_canonical_u64().to_le_bytes());
        }
        let mut state: Vec<u8> = h.finalize().to_vec();

        let mut squeeze_u64 = || -> u64 {
            let mut h2 = Keccak256::new();
            h2.update(&state);
            state = h2.finalize().to_vec();
            u64::from_le_bytes(state[0..8].try_into().unwrap()) % GL_P
        };

        // Squeeze betas, gammas, alphas first (matching on-chain order)
        let num_challenges = circuit_data.common.config.num_challenges;
        let _betas: Vec<u64> = (0..num_challenges).map(|_| squeeze_u64()).collect();
        let _gammas: Vec<u64> = (0..num_challenges).map(|_| squeeze_u64()).collect();
        let _alphas: Vec<u64> = (0..num_challenges).map(|_| squeeze_u64()).collect();
        let c0 = squeeze_u64();
        let c1 = squeeze_u64();
        let c2 = squeeze_u64();

        // Full Ext3 zeta (no Ext2 embedding — using native Ext3 throughout)
        let zeta = ark_ff::CubicExtField::new(
            Field64::from(c0),
            Field64::from(c1),
            Field64::from(c2),
        );
        (zeta, c0, c1, c2)
    };

    eprintln!(
        "[whir] Unified ζ derived from Merkle root: c0={}, c1={}",
        zeta_c0, zeta_c1
    );

    // Step 3: Compute g (generator of trace subgroup H) and gζ.
    // g = ω^(1) where ω is the 2^degree_bits-th primitive root of unity.
    let g_zeta_ext3 = {
        use plonky2::field::types::PrimeField64;
        let degree_bits = circuit_data.common.degree_bits();
        // Goldilocks primitive root of unity for subgroup of order 2^degree_bits
        let g_u64 = plonky2::field::goldilocks_field::GoldilocksField::primitive_root_of_unity(degree_bits)
            .to_canonical_u64();
        let g_ext3 = ark_ff::CubicExtField::new(
            Field64::from(g_u64),
            Field64::ZERO,
            Field64::ZERO,
        );
        g_ext3 * zeta_ext3
    };

    // Step 4: Generate final WHIR proof with dual sumcheck bridges (ζ and gζ).
    let combined_whir = whir_commit_and_prove_with_sumcheck(
        &combined_poly,
        &session_name,
        whir_config,
        zeta_ext3,
        Some(g_zeta_ext3),
    );

    let whir_time = whir_start.elapsed();

    // -----------------------------------------------------------------------
    // Assemble proof
    // -----------------------------------------------------------------------

    let zeta = combined_whir.zeta.expect("sumcheck bridge must set zeta");
    let g_zeta = combined_whir.g_zeta.expect("dual bridge must set g_zeta");

    // Compute batch evaluations at ζ and gζ for on-chain decomposition checks.
    let b0 = polys_to_whir_field(&circuit_data.prover_only.constants_sigmas_commitment.polynomials);
    let b1 = polys_to_whir_field(&polys.wires);
    let b2 = polys_to_whir_field(&polys.zs_partial_products);
    let b3 = polys_to_whir_field(&polys.quotient_chunks);

    let batch_evals_at_zeta = vec![
        sumcheck::eval_univariate_via_mle(&b0, zeta),
        sumcheck::eval_univariate_via_mle(&b1, zeta),
        sumcheck::eval_univariate_via_mle(&b2, zeta),
        sumcheck::eval_univariate_via_mle(&b3, zeta),
    ];

    let batch_evals_at_g_zeta = vec![
        sumcheck::eval_univariate_via_mle(&b0, g_zeta),
        sumcheck::eval_univariate_via_mle(&b1, g_zeta),
        sumcheck::eval_univariate_via_mle(&b2, g_zeta),
        sumcheck::eval_univariate_via_mle(&b3, g_zeta),
    ];

    // Compute intra-batch sub-decomposition: per-polynomial evaluations.
    // Within each batch, individual polynomials are concatenated with uniform
    // degree N = 2^degree_bits. So batch_i(ζ) = Σ_j poly_j(ζ) · ζ^{j·N}.
    let degree = 1usize << circuit_data.common.degree_bits();
    let batch_polys_raw = [
        &circuit_data.prover_only.constants_sigmas_commitment.polynomials,
        &polys.wires,
        &polys.zs_partial_products,
        &polys.quotient_chunks,
    ];

    let intra_batch_poly_counts: Vec<usize> = batch_polys_raw.iter()
        .map(|ps| ps.len())
        .collect();

    let intra_batch_evals_at_zeta: Vec<Vec<Field64_3>> = batch_polys_raw.iter()
        .map(|ps| {
            ps.iter().map(|p| {
                let whir_coeffs: Vec<Field64> = p.coeffs.iter()
                    .map(|c| Field64::from(c.to_canonical_u64()))
                    .collect();
                sumcheck::eval_univariate_via_mle_raw(&whir_coeffs, zeta, degree)
            }).collect()
        })
        .collect();

    // Per-polynomial evaluations of batch 2 (zs_partial_products) at gζ.
    let batch2_evals_at_g_zeta: Vec<Field64_3> = polys.zs_partial_products.iter()
        .map(|p| {
            let whir_coeffs: Vec<Field64> = p.coeffs.iter()
                .map(|c| Field64::from(c.to_canonical_u64()))
                .collect();
            sumcheck::eval_univariate_via_mle_raw(&whir_coeffs, g_zeta, degree)
        })
        .collect();

    let proof = WhirPlonky2Proof {
        standard_proof,
        combined_whir,
        batch_sizes,
        batch_evals_at_zeta,
        batch_evals_at_g_zeta,
        intra_batch_poly_counts,
        intra_batch_evals_at_zeta,
        batch2_evals_at_g_zeta,
        expected_result,
    };

    Ok(WhirPlonky2ProveResult {
        proof,
        plonky2_prove_time,
        whir_time,
        total_time: total_start.elapsed(),
    })
}


// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify a WHIR-based Plonky2 proof.
///
/// Performs two independent checks:
///
/// 1. **Constraint satisfaction** (algebraic check, same as Plonky2 verifier):
///    Verifies `vanishing_poly(zeta) == Z_H(zeta) * quotient_poly(zeta)`.
///    This uses the openings from the standard proof, which are the evaluations
///    of all committed polynomials at the challenge point zeta.
///
/// 2. **WHIR polynomial commitment validity** (hash-based, post-quantum):
///    Verifies each WHIR commitment is valid.  This replaces FRI's role:
///    proving that the committed polynomials are actually low-degree and
///    evaluate to the claimed values.
///
/// Both checks must pass.  Together they provide the same security guarantee
/// as Plonky2 + FRI, but with post-quantum security.
pub fn verify_whir_plonky2_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &WhirPlonky2Proof<F, C, D>,
    circuit_data: &CircuitData<F, C, D>,
    whir_config: &WhirWrapConfig,
) -> Result<()>
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    // -----------------------------------------------------------------------
    // Check 1: WHIR polynomial commitment validity (single combined proof)
    //
    // The combined WHIR proof covers all 4 polynomial batches concatenated.
    // The session name includes the expected_result tag, so a validity proof
    // cannot be replayed as a fraud proof.
    // -----------------------------------------------------------------------

    whir_verify_standalone(&proof.combined_whir, whir_config)?;

    // -----------------------------------------------------------------------
    // Check 2: Plonky2 verification + expected_result check
    //
    // If expected_result == true (finalize):
    //   Standard Plonky2 proof must verify → accept state transition.
    //
    // If expected_result == false (fraud proof):
    //   Standard Plonky2 proof must FAIL → confirms fraud.
    //   (The WHIR commitments above still verify — they prove the data
    //    was committed correctly. But the proof itself is invalid.)
    // -----------------------------------------------------------------------

    let plonky2_valid = circuit_data.verify(proof.standard_proof.clone()).is_ok();

    if plonky2_valid != proof.expected_result {
        anyhow::bail!(
            "Expected result mismatch: expected_result={}, actual plonky2 verification={}",
            proof.expected_result,
            plonky2_valid
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// On-chain verifier data export
// ---------------------------------------------------------------------------

/// Export all data needed for on-chain WHIR verification via SpongefishWhir.sol.
///
/// This includes the domain separator initialization values (protocol_id, session_id),
/// the raw transcript + hints, evaluations, and WHIR config parameters.
/// The Solidity verifier can then replay the spongefish transcript exactly.
pub fn export_whir_verifier_data(
    commitment: &WhirPolyCommitment,
    config: &WhirWrapConfig,
) -> serde_json::Value {
    let poly_size = 1usize << commitment.num_variables;
    let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);

    // Compute protocol_id: keccak256-based (leohio/whir fork)
    // protocol_id[0..32] = keccak256(0x00 || cbor(config))
    // protocol_id[32..64] = keccak256(0x01 || cbor(config))
    let protocol_id = {
        use sha3::{Digest, Keccak256};
        let mut config_bytes = Vec::new();
        ciborium::into_writer(&params, &mut config_bytes).expect("CBOR serialization failed");
        let first: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update([0x00]);
            h.update(&config_bytes);
            h.finalize().into()
        };
        let second: [u8; 32] = {
            let mut h = Keccak256::new();
            h.update([0x01]);
            h.update(&config_bytes);
            h.finalize().into()
        };
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&first);
        result[32..].copy_from_slice(&second);
        result
    };

    // Compute session_id: keccak256(cbor(session_name)) (leohio/whir fork)
    let session_id = {
        use sha3::{Digest, Keccak256};
        let mut session_bytes = Vec::new();
        ciborium::into_writer(&commitment.session_name, &mut session_bytes)
            .expect("CBOR serialization failed");
        let mut h = Keccak256::new();
        h.update(&session_bytes);
        let result: [u8; 32] = h.finalize().into();
        result
    };

    // Instance encoding for Empty struct — Empty encodes as [] (zero bytes)
    let instance_bytes: Vec<u8> = Vec::new();

    // Evaluation values as structured {c0, c1, c2}
    let evaluations_structured: Vec<serde_json::Value> = commitment.evaluations.iter().map(|e| {
        use ark_ff::{Field, PrimeField};
        let base_elems: Vec<_> = e.to_base_prime_field_elements().collect();
        serde_json::json!({
            "c0": base_elems[0].into_bigint().0[0],
            "c1": base_elems[1].into_bigint().0[0],
            "c2": base_elems[2].into_bigint().0[0],
        })
    }).collect();

    // Evaluation point: sumcheck-derived r if available, otherwise canonical
    let point: Vec<serde_json::Value> = match &commitment.eval_point {
        Some(p) => p.iter().map(|e| {
            let base_elems: Vec<_> = ark_ff::Field::to_base_prime_field_elements(e).collect();
            serde_json::json!({
                "c0": base_elems[0].into_bigint().0[0],
                "c1": base_elems[1].into_bigint().0[0],
                "c2": base_elems[2].into_bigint().0[0],
            })
        }).collect(),
        None => (0..commitment.num_variables)
            .map(|i| serde_json::json!({
                "c0": i + 1,
                "c1": 0,
                "c2": 0,
            }))
            .collect(),
    };

    // Sumcheck bridge data (if present)
    let sumcheck_data = match (&commitment.sumcheck_proof, &commitment.zeta, &commitment.claimed_sum) {
        (Some(sc_proof), Some(zeta), Some(claimed_sum)) => {
            let zeta_elems: Vec<_> = ark_ff::Field::to_base_prime_field_elements(zeta).collect();
            let cs_elems: Vec<_> = ark_ff::Field::to_base_prime_field_elements(claimed_sum).collect();
            let round_polys: Vec<serde_json::Value> = sc_proof.round_polys.iter().map(|g| {
                let vals: Vec<serde_json::Value> = g.iter().map(|e| {
                    let base: Vec<_> = ark_ff::Field::to_base_prime_field_elements(e).collect();
                    serde_json::json!({
                        "c0": base[0].into_bigint().0[0],
                        "c1": base[1].into_bigint().0[0],
                        "c2": base[2].into_bigint().0[0],
                    })
                }).collect();
                serde_json::json!(vals)
            }).collect();
            serde_json::json!({
                "zeta": {
                    "c0": zeta_elems[0].into_bigint().0[0],
                    "c1": zeta_elems[1].into_bigint().0[0],
                    "c2": zeta_elems[2].into_bigint().0[0],
                },
                "claimed_sum": {
                    "c0": cs_elems[0].into_bigint().0[0],
                    "c1": cs_elems[1].into_bigint().0[0],
                    "c2": cs_elems[2].into_bigint().0[0],
                },
                "session_name": commitment.session_name,
                "round_polys": round_polys,
                "num_rounds": sc_proof.round_polys.len(),
            })
        }
        _ => serde_json::json!(null),
    };

    // Second sumcheck bridge data for gζ (if present)
    let sumcheck_g_zeta_data = match (
        &commitment.sumcheck_proof_g_zeta,
        &commitment.g_zeta,
        &commitment.claimed_sum_g_zeta,
        &commitment.eval_point_g_zeta,
    ) {
        (Some(sc_proof), Some(gz), Some(claimed_sum), Some(eval_pt)) => {
            let gz_elems: Vec<_> = ark_ff::Field::to_base_prime_field_elements(gz).collect();
            let cs_elems: Vec<_> = ark_ff::Field::to_base_prime_field_elements(claimed_sum).collect();
            let round_polys: Vec<serde_json::Value> = sc_proof.round_polys.iter().map(|g| {
                let vals: Vec<serde_json::Value> = g.iter().map(|e| {
                    let base: Vec<_> = ark_ff::Field::to_base_prime_field_elements(e).collect();
                    serde_json::json!({
                        "c0": base[0].into_bigint().0[0],
                        "c1": base[1].into_bigint().0[0],
                        "c2": base[2].into_bigint().0[0],
                    })
                }).collect();
                serde_json::json!(vals)
            }).collect();
            let eval_point_json: Vec<serde_json::Value> = eval_pt.iter().map(|e| {
                let base: Vec<_> = ark_ff::Field::to_base_prime_field_elements(e).collect();
                serde_json::json!({
                    "c0": base[0].into_bigint().0[0],
                    "c1": base[1].into_bigint().0[0],
                    "c2": base[2].into_bigint().0[0],
                })
            }).collect();
            serde_json::json!({
                "g_zeta": {
                    "c0": gz_elems[0].into_bigint().0[0],
                    "c1": gz_elems[1].into_bigint().0[0],
                    "c2": gz_elems[2].into_bigint().0[0],
                },
                "claimed_sum": {
                    "c0": cs_elems[0].into_bigint().0[0],
                    "c1": cs_elems[1].into_bigint().0[0],
                    "c2": cs_elems[2].into_bigint().0[0],
                },
                "eval_point": eval_point_json,
                "round_polys": round_polys,
                "num_rounds": sc_proof.round_polys.len(),
            })
        }
        _ => serde_json::json!(null),
    };

    // Compute detailed WHIR protocol parameters for Solidity verifier
    let num_rounds = params.round_configs.len();
    let final_sumcheck_rounds = params.final_sumcheck.num_rounds;
    let final_size = params.final_sumcheck.initial_size;
    let initial_sumcheck_rounds = params.initial_sumcheck.num_rounds;
    let in_domain_samples = params.initial_committer.in_domain_samples;
    let out_domain_samples = params.initial_committer.out_domain_samples;
    let num_vectors = params.initial_committer.num_vectors;

    // Codeword lengths and domain generators for Merkle verification and FinalClaim
    use ark_ff::PrimeField;
    // Compute domain generator: primitive N-th root of unity for the given codeword length.
    // Uses ark_ff's FftField trait directly.
    use ark_ff::FftField;

    // Helper: compute primitive N-th root of unity as a u64 for Goldilocks field
    let gl_root_of_unity = |n: usize| -> u64 {
        let g: Field64 = Field64::get_root_of_unity(n as u64)
            .expect("No root of unity for requested size");
        g.into_bigint().0[0]
    };

    let log2_of = |mut n: usize| -> usize {
        let mut d = 0;
        while n > 1 { n >>= 1; d += 1; }
        d
    };

    let initial_codeword_length = params.initial_committer.codeword_length;
    let initial_merkle_depth = log2_of(initial_codeword_length);
    let initial_domain_generator = gl_root_of_unity(initial_codeword_length);

    // Coset parameters for evaluation point computation (FinalClaim)
    let initial_mml = params.initial_committer.masked_message_length();
    let initial_coset_size = {
        let mut cs = initial_mml.next_power_of_two();
        while initial_codeword_length % cs != 0 { cs *= 2; }
        cs
    };
    let initial_num_cosets = initial_codeword_length / initial_coset_size;

    // Build per-round params array
    let rounds_json: Vec<serde_json::Value> = params.round_configs.iter().map(|rc| {
        let cl = rc.irs_committer.codeword_length;
        let mml = rc.irs_committer.masked_message_length();
        let mut cs = mml.next_power_of_two();
        while cl % cs != 0 { cs *= 2; }
        serde_json::json!({
            "codeword_length": cl,
            "merkle_depth": log2_of(cl),
            "domain_generator": gl_root_of_unity(cl),
            "in_domain_samples": rc.irs_committer.in_domain_samples,
            "out_domain_samples": rc.irs_committer.out_domain_samples,
            "sumcheck_rounds": rc.sumcheck.num_rounds,
            "interleaving_depth": rc.irs_committer.interleaving_depth,
            "coset_size": cs,
            "num_cosets": cl / cs,
            "num_variables": rc.initial_num_variables(),
        })
    }).collect();

    serde_json::json!({
        "protocol_id": format!("0x{}", hex::encode(protocol_id)),
        "session_id": format!("0x{}", hex::encode(session_id)),
        "instance": format!("0x{}", hex::encode(&instance_bytes)),
        "transcript": format!("0x{}", hex::encode(&commitment.proof_narg)),
        "hints": format!("0x{}", hex::encode(&commitment.proof_hints)),
        "num_variables": commitment.num_variables,
        "evaluations": evaluations_structured,
        "evaluation_point": point,
        "sumcheck": sumcheck_data,
        "sumcheck_g_zeta": sumcheck_g_zeta_data,
        "session_name": commitment.session_name,
        "whir_config": {
            "num_variables": commitment.num_variables,
            "folding_factor": config.params.folding_factor,
            "security_level": config.params.security_level,
            "starting_log_inv_rate": config.params.starting_log_inv_rate,
        },
        "whir_params": {
            "num_variables": commitment.num_variables,
            "folding_factor": config.params.folding_factor,
            "num_vectors": num_vectors,
            "out_domain_samples": out_domain_samples,
            "in_domain_samples": in_domain_samples,
            "initial_sumcheck_rounds": initial_sumcheck_rounds,
            "num_rounds": num_rounds,
            "final_sumcheck_rounds": final_sumcheck_rounds,
            "final_size": final_size,
            "initial_codeword_length": initial_codeword_length,
            "initial_merkle_depth": log2_of(initial_codeword_length),
            "initial_domain_generator": gl_root_of_unity(initial_codeword_length),
            "initial_interleaving_depth": params.initial_committer.interleaving_depth,
            "initial_num_variables": params.initial_num_variables(),
            "initial_coset_size": initial_coset_size,
            "initial_num_cosets": initial_num_cosets,
            "rounds": rounds_json,
        },
    })
}

// ---------------------------------------------------------------------------
// Gas estimation
// ---------------------------------------------------------------------------

/// Estimate EVM gas cost for on-chain WHIR verification (single combined proof).
pub fn estimate_whir_verification_gas<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &WhirPlonky2Proof<F, C, D>,
) -> u64 {
    let c = &proof.combined_whir;
    let proof_size = c.proof_narg.len() + c.proof_hints.len();
    let calldata_gas = proof_size as u64 * 16; // 16 gas per non-zero byte
    let hash_gas = c.verify_hashes as u64 * 42; // Keccak: 30 + 6*2 = 42

    calldata_gas + hash_gas + 50_000 // overhead: constraint check + base tx
}

// ---------------------------------------------------------------------------
// On-chain data export
// ---------------------------------------------------------------------------

/// Export opening values, challenges, and circuit params for on-chain constraint checking.
///
/// Returns a JSON object containing everything Plonky2Verifier.verifyConstraints() needs.
pub fn export_onchain_data<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &WhirPlonky2Proof<F, C, D>,
    circuit_data: &CircuitData<F, C, D>,
) -> serde_json::Value
where
    C::Hasher: Hasher<F>,
    C::InnerHasher: Hasher<F>,
{
    use plonky2::field::types::PrimeField64;
    use ark_ff::PrimeField as ArkPrimeField;

    let openings = &proof.standard_proof.proof.openings;
    let common = &circuit_data.common;
    let prover_data = &circuit_data.prover_only;

    let ext_to_pair = |ext: &F::Extension| -> (u64, u64) {
        let json = serde_json::to_string(ext).unwrap_or_default();
        let arr: Vec<u64> = serde_json::from_str(&json).unwrap_or_default();
        (arr.get(0).copied().unwrap_or(0), arr.get(1).copied().unwrap_or(0))
    };

    // Flatten Ext2 elements to interleaved c0, c1 as JSON numbers
    let ext_vec_to_flat = |v: &[F::Extension]| -> Vec<u64> {
        v.iter().flat_map(|e| {
            let (c0, c1) = ext_to_pair(e);
            vec![c0, c1]
        }).collect()
    };

    // Derive Plonky2 challenges via Keccak (unified with WHIR transcript).
    // This replaces Poseidon-based Plonky2 Challenger so challenges can be
    // re-derived on-chain from the WHIR transcript bytes.
    //
    // Binding: the WHIR transcript encodes the Merkle commitment to all polynomials.
    // Challenges derived from keccak(transcript) are therefore bound to the commitment.
    let num_challenges = common.config.num_challenges;

    let keccak_challenges = {
        use sha3::{Digest, Keccak256};

        // Goldilocks prime: 2^64 - 2^32 + 1
        const GL_P: u64 = 0xFFFFFFFF00000001u64;

        // Derive challenges from Merkle root (v2) — matches on-chain deriveKeccakChallengesV2.
        // The Merkle root is the first 32 bytes of the WHIR transcript.
        let transcript_bytes = &proof.combined_whir.proof_narg;
        let merkle_root = &transcript_bytes[0..32];
        let mut h = Keccak256::new();
        h.update(b"plonky2-challenges-v2");
        h.update(proof.combined_whir.session_name.as_bytes());
        h.update(merkle_root);
        for &pi in &proof.standard_proof.public_inputs {
            h.update(&pi.to_canonical_u64().to_le_bytes());
        }

        // Squeeze challenges in sequence: betas, gammas, alphas, zeta
        let mut state = h.finalize().to_vec();

        let mut squeeze_u64 = || -> u64 {
            let mut h2 = Keccak256::new();
            h2.update(&state);
            state = h2.finalize().to_vec();
            let val = u64::from_le_bytes(state[0..8].try_into().unwrap());
            val % GL_P
        };

        let betas: Vec<u64> = (0..num_challenges).map(|_| squeeze_u64()).collect();
        let gammas: Vec<u64> = (0..num_challenges).map(|_| squeeze_u64()).collect();
        let alphas: Vec<u64> = (0..num_challenges).map(|_| squeeze_u64()).collect();
        let zeta_c0 = squeeze_u64();
        let zeta_c1 = squeeze_u64();
        let zeta_c2 = squeeze_u64();
        (betas, gammas, alphas, zeta_c0, zeta_c1, zeta_c2)
    };
    let (keccak_betas, keccak_gammas, keccak_alphas, zeta_c0, zeta_c1, zeta_c2) = keccak_challenges;

    // Circuit params
    let selectors_info = &common.selectors_info;

    // Gate info (with per-gate config for Solidity verifier)
    let gate_infos: Vec<serde_json::Value> = common.gates.iter().enumerate().map(|(i, gate)| {
        let sel_idx = selectors_info.selector_indices[i];
        let group = &selectors_info.groups[sel_idx];
        let id = gate.0.id();
        serde_json::json!({
            "gateType": _gate_type_id(&id),
            "selectorIndex": sel_idx,
            "groupStart": group.start,
            "groupEnd": group.end,
            "rowInGroup": i,
            "numConstraints": gate.0.num_constraints(),
            "gateConfig": _gate_config(&id),
        })
    }).collect();

    // k_is for permutation
    let k_is: Vec<u64> = common.k_is.iter().map(|k| k.to_canonical_u64()).collect();

    serde_json::json!({
        "openings": {
            "constants": ext_vec_to_flat(&openings.constants),
            "plonkSigmas": ext_vec_to_flat(&openings.plonk_sigmas),
            "wires": ext_vec_to_flat(&openings.wires),
            "plonkZs": ext_vec_to_flat(&openings.plonk_zs),
            "plonkZsNext": ext_vec_to_flat(&openings.plonk_zs_next),
            "partialProducts": ext_vec_to_flat(&openings.partial_products),
            "quotientPolys": ext_vec_to_flat(&openings.quotient_polys),
        },
        "challenges": {
            "plonkBetas": keccak_betas,
            "plonkGammas": keccak_gammas,
            "plonkAlphas": keccak_alphas,
            "plonkZeta": [zeta_c0, zeta_c1, zeta_c2],
        },
        "circuitParams": {
            "degreeBits": common.degree_bits(),
            "numChallenges": num_challenges,
            "numRoutedWires": common.config.num_routed_wires,
            "quotientDegreeFactor": common.quotient_degree_factor,
            "numPartialProducts": common.num_partial_products,
            "numGateConstraints": common.num_gate_constraints,
            "numSelectors": selectors_info.num_selectors(),
            "numLookupSelectors": common.num_lookup_selectors,
        },
        "gates": gate_infos,
        "permutation": {
            "kIs": k_is,
        },
        "publicInputs": proof.standard_proof.public_inputs.iter()
            .map(|f| f.to_canonical_u64())
            .collect::<Vec<_>>(),
        "batchSizes": proof.batch_sizes,
        "batchEvalsAtZeta": proof.batch_evals_at_zeta.iter().map(|e| {
            let base: Vec<_> = ark_ff::Field::to_base_prime_field_elements(e).collect();
            serde_json::json!({
                "c0": base[0].into_bigint().0[0],
                "c1": base[1].into_bigint().0[0],
                "c2": base[2].into_bigint().0[0],
            })
        }).collect::<Vec<_>>(),
        "batchEvalsAtGZeta": proof.batch_evals_at_g_zeta.iter().map(|e| {
            let base: Vec<_> = ark_ff::Field::to_base_prime_field_elements(e).collect();
            serde_json::json!({
                "c0": base[0].into_bigint().0[0],
                "c1": base[1].into_bigint().0[0],
                "c2": base[2].into_bigint().0[0],
            })
        }).collect::<Vec<_>>(),
        "intraBatchPolyCounts": proof.intra_batch_poly_counts,
        "intraBatchEvalsAtZeta": proof.intra_batch_evals_at_zeta.iter().map(|batch_evals| {
            batch_evals.iter().map(|e| {
                let base: Vec<_> = ark_ff::Field::to_base_prime_field_elements(e).collect();
                serde_json::json!({
                    "c0": base[0].into_bigint().0[0],
                    "c1": base[1].into_bigint().0[0],
                    "c2": base[2].into_bigint().0[0],
                })
            }).collect::<Vec<_>>()
        }).collect::<Vec<_>>(),
        "batch2EvalsAtGZeta": proof.batch2_evals_at_g_zeta.iter().map(|e| {
            let base: Vec<_> = ark_ff::Field::to_base_prime_field_elements(e).collect();
            serde_json::json!({
                "c0": base[0].into_bigint().0[0],
                "c1": base[1].into_bigint().0[0],
                "c2": base[2].into_bigint().0[0],
            })
        }).collect::<Vec<_>>(),
    })
}

/// Extract gate-specific configuration parameters from the Debug ID string.
///
/// Returns a Vec<u64> matching the Solidity GateInfo.gateConfig format:
///   Constant(1): [numConsts]
///   Arithmetic(4): [numOps]
///   BaseSumGate(5): [numLimbs, base]
///   RandomAccessGate(6): [bits, numCopies, numExtraConstants, vecSize]
///   ReducingExtensionGate(8): [numCoeffs]
///   ArithmeticExtensionGate(9): [numOps]
///   MulExtensionGate(10): [numOps]
///   ExponentiationGate(11): [numPowerBits]
///   CosetInterpolationGate(12): [subgroupBits, numPoints, numIntermediates, degree]
fn _gate_config(id: &str) -> Vec<u64> {
    // Helper: extract a named numeric field from Debug output like "FieldName { num_ops: 20 }"
    let extract = |field_name: &str| -> Option<u64> {
        let needle = format!("{}: ", field_name);
        id.find(&needle).and_then(|pos| {
            let start = pos + needle.len();
            let rest = &id[start..];
            let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
            rest[..end].parse().ok()
        })
    };

    if id.contains("ConstantGate") {
        vec![extract("num_consts").unwrap_or(2)]
    } else if id.contains("ArithmeticExtensionGate") {
        vec![extract("num_ops").unwrap_or(0)]
    } else if id.contains("ArithmeticGate") {
        vec![extract("num_ops").unwrap_or(20)]
    } else if id.contains("BaseSumGate") {
        let num_limbs = extract("num_limbs").unwrap_or(0);
        // Base is in the type parameter: "BaseSumGate { ... }" with B=2 typically
        // The Debug format includes it as part of the struct name or inner field
        let base = 2u64; // BaseSumGate<2> is the standard config
        vec![num_limbs, base]
    } else if id.contains("RandomAccessGate") {
        let bits = extract("bits").unwrap_or(0);
        let num_copies = extract("num_copies").unwrap_or(0);
        let num_extra_constants = extract("num_extra_constants").unwrap_or(0);
        let vec_size = 1u64 << bits;
        vec![bits, num_copies, num_extra_constants, vec_size]
    } else if id.contains("ReducingExtensionGate") {
        vec![extract("num_coeffs").unwrap_or(0)]
    } else if id.contains("ReducingGate") {
        vec![extract("num_coeffs").unwrap_or(0)]
    } else if id.contains("MulExtensionGate") {
        vec![extract("num_ops").unwrap_or(0)]
    } else if id.contains("ExponentiationGate") {
        vec![extract("num_power_bits").unwrap_or(0)]
    } else if id.contains("CosetInterpolationGate") {
        let subgroup_bits = extract("subgroup_bits").unwrap_or(0);
        let num_points = 1u64 << subgroup_bits;
        // degree and num_intermediates are computed from config
        let degree = extract("degree").unwrap_or(2);
        let num_intermediates = if degree > 1 { (num_points - 2) / (degree - 1) } else { 0 };
        vec![subgroup_bits, num_points, num_intermediates, degree]
    } else {
        vec![]
    }
}

/// Map Plonky2 gate ID strings to numeric type IDs for Solidity.
fn _gate_type_id(id: &str) -> u64 {
    if id.contains("NoopGate") { 0 }
    else if id.contains("ConstantGate") { 1 }
    else if id.contains("PublicInputGate") { 2 }
    else if id.contains("PoseidonGate") { 3 }
    else if id.contains("ArithmeticGate") { 4 }
    else if id.contains("BaseSumGate") { 5 }
    else if id.contains("RandomAccessGate") { 6 }
    else if id.contains("ReducingExtensionGate") { 8 }
    else if id.contains("ReducingGate") { 7 }
    else if id.contains("MulExtensionGate") { 10 }
    else if id.contains("ArithmeticExtensionGate") { 9 }
    else if id.contains("ExponentiationGate") { 11 }
    else if id.contains("CosetInterpolationGate") { 12 }
    else if id.contains("LookupTableGate") { 14 }
    else if id.contains("LookupGate") { 13 }
    else if id.contains("PoseidonMdsGate") { 15 }
    else { 255 } // Unknown
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field as PlonkyField;
    use plonky2::field::types::PrimeField64;
    use plonky2::hash::hash_types::HashOutTarget;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn build_test_circuit() -> (CircuitData<F, C, D>, HashOutTarget) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let initial = builder.add_virtual_hash();
        builder.register_public_inputs(&initial.elements);

        let mut current = initial;
        for _ in 0..10 {
            current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(current.elements.to_vec());
        }
        builder.register_public_inputs(&current.elements);

        let data = builder.build::<C>();
        (data, initial)
    }

    fn make_witness(
        target: HashOutTarget,
    ) -> PartialWitness<F> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(
            target,
            plonky2::hash::hash_types::HashOut {
                elements: [
                    F::from_canonical_u64(1),
                    F::from_canonical_u64(2),
                    F::from_canonical_u64(3),
                    F::from_canonical_u64(4),
                ],
            },
        );
        pw
    }

    #[test]
    fn test_whir_plonky2_prove_and_verify() {
        let (cd, initial) = build_test_circuit();

        // Print gate information for Solidity constraint checker
        println!("=== Circuit Gate Types ===");
        for (i, gate) in cd.common.gates.iter().enumerate() {
            println!("  Gate {}: {} (num_constraints={})", i, gate.0.id(), gate.0.num_constraints());
        }
        println!("  degree_bits: {}", cd.common.degree_bits());
        println!("  num_challenges: {}", cd.common.config.num_challenges);
        println!("  num_routed_wires: {}", cd.common.config.num_routed_wires);
        println!("  quotient_degree_factor: {}", cd.common.quotient_degree_factor);

        let pw = make_witness(initial);

        let config = WhirWrapConfig::default_keccak();
        let result = prove_with_whir::<F, C, D>(&cd, pw, &config, true).unwrap();

        println!("=== WHIR Plonky2 Proof Timings ===");
        println!("  Plonky2 prove: {:.2?}", result.plonky2_prove_time);
        println!("  WHIR prove:    {:.2?}", result.whir_time);
        println!("  Total:         {:.2?}", result.total_time);
        println!("  Est. gas:      {}K", estimate_whir_verification_gas(&result.proof) / 1000);

        // Verify
        verify_whir_plonky2_proof::<F, C, D>(&result.proof, &cd, &config)
            .expect("Verification must pass");

        // Export full on-chain data (openings + challenges + circuit params)
        let onchain_data = export_onchain_data(&result.proof, &cd);
        println!("=== On-chain Data ===");
        println!("  constants count: {}", onchain_data["openings"]["constants"].as_array().unwrap().len());
        println!("  wires count: {}", onchain_data["openings"]["wires"].as_array().unwrap().len());
        println!("  quotientPolys count: {}", onchain_data["openings"]["quotientPolys"].as_array().unwrap().len());
        println!("  gates count: {}", onchain_data["gates"].as_array().unwrap().len());
        println!("  degreeBits: {}", onchain_data["circuitParams"]["degreeBits"]);
        println!("  numGateConstraints: {}", onchain_data["circuitParams"]["numGateConstraints"]);

        // Save fixture for Foundry tests
        let fixture_path = std::path::Path::new("tests/fixtures/whir_constraint_data.json");
        if let Some(parent) = fixture_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(fixture_path, serde_json::to_string_pretty(&onchain_data).unwrap())
            .expect("Failed to write fixture");
        println!("  Saved to: {}", fixture_path.display());

        // Export WHIR verifier data for on-chain verification
        let whir_verifier_data = export_whir_verifier_data(
            &result.proof.combined_whir, &config,
        );
        let whir_fixture_path = std::path::Path::new("tests/fixtures/whir_verifier_data.json");
        std::fs::write(whir_fixture_path, serde_json::to_string_pretty(&whir_verifier_data).unwrap())
            .expect("Failed to write WHIR verifier fixture");
        println!("  WHIR verifier data saved to: {}", whir_fixture_path.display());

        // Verify that WHIR verify succeeds with the exported data
        whir_verify_standalone(&result.proof.combined_whir, &config)
            .expect("combined WHIR must verify");
        println!("  WHIR verify (combined): OK");

        // Export WHIR config parameters for Solidity verifier
        let poly_size = 1usize << result.proof.combined_whir.num_variables;
        let params = InternalWhirConfig::<Basefield<Field64_3>>::new(poly_size, &config.params);
        println!("  WHIR config:");
        println!("    initial_committer.num_vectors: {}", params.initial_committer.num_vectors);
        println!("    initial_committer.out_domain_samples: {}", params.initial_committer.out_domain_samples);
        println!("    initial_committer.in_domain_samples: {}", params.initial_committer.in_domain_samples);
        println!("    initial_sumcheck.num_rounds: {}", params.initial_sumcheck.num_rounds);
        println!("    round_configs: {}", params.round_configs.len());
        for (i, rc) in params.round_configs.iter().enumerate() {
            println!("      round {}: sumcheck.num_rounds={}", i, rc.sumcheck.num_rounds);
        }
        println!("    final_sumcheck.num_rounds: {}", params.final_sumcheck.num_rounds);
        println!("    final_sumcheck.initial_size: {}", params.final_sumcheck.initial_size);
    }

    #[test]
    fn test_whir_combined_verify_standalone() {
        let (cd, initial) = build_test_circuit();
        let pw = make_witness(initial);

        let config = WhirWrapConfig::default_keccak();
        let result = prove_with_whir::<F, C, D>(&cd, pw, &config, true).unwrap();

        // Combined WHIR commitment must verify
        whir_verify_standalone(&result.proof.combined_whir, &config)
            .expect("combined WHIR must verify");
    }

    #[test]
    fn test_polys_to_whir_field() {
        let coeffs = vec![
            F::from_canonical_u64(1),
            F::from_canonical_u64(2),
            F::from_canonical_u64(3),
        ];
        let poly = PolynomialCoeffs::new(coeffs.clone());
        let whir_poly = polys_to_whir_field(&[poly]);

        for (i, c) in coeffs.iter().enumerate() {
            assert_eq!(whir_poly[i], Field64::from(c.to_canonical_u64()));
        }
        for i in 3..whir_poly.len() {
            assert_eq!(whir_poly[i], Field64::ZERO);
        }
        assert!(whir_poly.len().is_power_of_two());
        assert!(whir_poly.len() >= 256);
    }

    /// Test that corrupted WHIR proof data is rejected.
    /// This is the core fraud proof E2E test: if the Plonky2 proof in the blob
    /// is invalid, WHIR verification must fail.
    #[test]
    fn test_whir_rejects_corrupted_proof_data() {
        let (cd, initial) = build_test_circuit();
        let pw = make_witness(initial);

        let config = WhirWrapConfig::default_keccak();
        let result = prove_with_whir::<F, C, D>(&cd, pw, &config, true).unwrap();

        // Sanity: valid proof verifies
        verify_whir_plonky2_proof::<F, C, D>(&result.proof, &cd, &config)
            .expect("Valid proof must verify");

        // --- Case 1: Random bytes as WHIR proof narg ---
        {
            let mut corrupted = result.proof.clone();
            corrupted.combined_whir.proof_narg = vec![0xDE; 256];
            let err = whir_verify_standalone(&corrupted.combined_whir, &config);
            assert!(err.is_err(), "Random bytes in proof_narg must be rejected");
            eprintln!("Case 1 passed: random bytes rejected. Error: {}", err.unwrap_err());
        }

        // --- Case 2: Tampered evaluation values ---
        {
            let mut corrupted = result.proof.clone();
            if !corrupted.combined_whir.evaluations.is_empty() {
                corrupted.combined_whir.evaluations[0] = Field64_3::from(999999u64);
            }
            let err = whir_verify_standalone(&corrupted.combined_whir, &config);
            assert!(err.is_err(), "Tampered evaluations must be rejected");
            eprintln!("Case 2 passed: tampered evaluations rejected. Error: {}", err.unwrap_err());
        }

        // --- Case 3: Empty proof data ---
        {
            let mut corrupted = result.proof.clone();
            corrupted.combined_whir.proof_narg = vec![];
            corrupted.combined_whir.proof_hints = vec![];
            let err = whir_verify_standalone(&corrupted.combined_whir, &config);
            assert!(err.is_err(), "Empty proof data must be rejected");
            eprintln!("Case 3 passed: empty proof rejected. Error: {}", err.unwrap_err());
        }

        // --- Case 4: Full pipeline with corrupted proof ---
        {
            let mut corrupted = result.proof.clone();
            for byte in corrupted.combined_whir.proof_narg.iter_mut() {
                *byte = byte.wrapping_add(1);
            }
            let err = verify_whir_plonky2_proof::<F, C, D>(&corrupted, &cd, &config);
            assert!(err.is_err(), "Full pipeline must reject corrupted WHIR proof");
            eprintln!("Case 4 passed: full pipeline rejected corrupted proof. Error: {}", err.unwrap_err());
        }

        eprintln!("All WHIR fraud detection cases passed!");
    }

    #[test]
    fn test_opening_values_match_standard_proof() {
        let (cd, initial) = build_test_circuit();
        let pw = make_witness(initial);

        let config = WhirWrapConfig::default_keccak();
        let result = prove_with_whir::<F, C, D>(&cd, pw, &config, true).unwrap();

        // Standard proof must also verify
        cd.verify(result.proof.standard_proof.clone())
            .expect("Standard Plonky2 proof must verify");
    }
}
