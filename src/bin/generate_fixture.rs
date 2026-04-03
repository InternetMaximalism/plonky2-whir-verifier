//! Generate E2E fixtures for on-chain WHIR + Plonky2 constraint verification.
//!
//! Uses a generic Poseidon hash-chain circuit (no intmax3-specific types).
//!
//! Pipeline:
//!   1. Build a test Plonky2 circuit (Poseidon hash chain)
//!   2. Wrap with WrapperCircuit (PoseidonGoldilocksConfig → PoseidonGoldilocksConfig)
//!   3. Generate WHIR polynomial commitment proof
//!   4. Export constraint data + WHIR verifier data as JSON fixtures
//!
//! Usage:
//!   cargo run --bin generate_fixture --release

use std::{fs, path::Path};

use anyhow::Result;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    field::types::Field as PlonkyField,
    hash::hash_types::HashOut,
    hash::poseidon::PoseidonHash,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::PoseidonGoldilocksConfig,
    },
};

use plonky2_whir_verifier::prover::{
    export_onchain_data, export_unified_proof, export_whir_verifier_data, prove_with_whir,
    WhirWrapConfig,
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// Build a generic test circuit: 10-step Poseidon hash chain.
/// Public inputs: [initial_hash(4), final_hash(4)].
fn build_test_circuit() -> (CircuitData<F, C, D>, plonky2::hash::hash_types::HashOutTarget) {
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

fn main() -> Result<()> {
    let out_dir = Path::new("contracts/test/data");
    let whir_dir = out_dir.join("whir");
    fs::create_dir_all(&whir_dir)?;

    eprintln!("[fixture] Step 1: Build test circuit (Poseidon hash chain)");
    let (cd, initial_target) = build_test_circuit();
    eprintln!(
        "[fixture]   degree_bits={}, gates={}",
        cd.common.degree_bits(),
        cd.common.gates.len()
    );

    eprintln!("[fixture] Step 2: Generate Plonky2 proof");
    let mut pw = PartialWitness::new();
    pw.set_hash_target(
        initial_target,
        HashOut {
            elements: [
                F::from_canonical_u64(1),
                F::from_canonical_u64(2),
                F::from_canonical_u64(3),
                F::from_canonical_u64(4),
            ],
        },
    );

    eprintln!("[fixture] Step 3: Generate WHIR proof");
    let whir_config = WhirWrapConfig::default_keccak();
    let whir_result = prove_with_whir::<F, C, D>(&cd, pw, &whir_config, true)?;
    eprintln!(
        "[fixture]   Plonky2 time: {:?}",
        whir_result.plonky2_prove_time
    );
    eprintln!("[fixture]   WHIR time:    {:?}", whir_result.whir_time);
    eprintln!("[fixture]   Total time:   {:?}", whir_result.total_time);

    // Export constraint data
    eprintln!("[fixture] Step 4: Export constraint data");
    let onchain_data = export_onchain_data(&whir_result.proof, &cd);
    fs::write(
        out_dir.join("test_constraint_data.json"),
        serde_json::to_string_pretty(&onchain_data)?,
    )?;
    eprintln!("[fixture]   → contracts/test/data/test_constraint_data.json");

    // Export combined WHIR verifier data
    eprintln!("[fixture] Step 5: Export WHIR verifier data");
    let whir_data = export_whir_verifier_data(&whir_result.proof.combined_whir, &whir_config);
    fs::write(
        whir_dir.join("test_combined_verifier_data.json"),
        serde_json::to_string_pretty(&whir_data)?,
    )?;
    eprintln!("[fixture]   → contracts/test/data/whir/test_combined_verifier_data.json");

    // Export unified proof (single file for WhirPlonky2Verifier)
    eprintln!("[fixture] Step 6: Export unified proof");
    let unified_data = export_unified_proof(&whir_result.proof, &cd, &whir_config);
    fs::write(
        out_dir.join("test_proof.json"),
        serde_json::to_string_pretty(&unified_data)?,
    )?;
    eprintln!("[fixture]   → contracts/test/data/test_proof.json");

    // Export WHIR proof raw data
    {
        use plonky2::field::types::PrimeField64;
        let proof = &whir_result.proof;
        let whir_proof_fixture = serde_json::json!({
            "combined": {
                "transcript": format!("0x{}", hex::encode(&proof.combined_whir.proof_narg)),
                "hints": format!("0x{}", hex::encode(&proof.combined_whir.proof_hints)),
                "num_variables": proof.combined_whir.num_variables,
            },
            "batch_sizes": proof.batch_sizes,
            "expected_result": proof.expected_result,
            "public_inputs": proof.standard_proof.public_inputs.iter()
                .map(|f| f.to_canonical_u64())
                .collect::<Vec<_>>(),
        });
        fs::write(
            whir_dir.join("test_whir_proof.json"),
            serde_json::to_string_pretty(&whir_proof_fixture)?,
        )?;
        eprintln!("[fixture]   → contracts/test/data/whir/test_whir_proof.json");
    }

    eprintln!("[fixture] Done! All fixtures generated (including unified test_proof.json).");
    Ok(())
}
