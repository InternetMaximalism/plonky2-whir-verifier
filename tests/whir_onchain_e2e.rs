//! End-to-end test: Plonky2 proof → WHIR → on-chain verification
//!
//! Run with:
//!   cargo test --test whir_onchain_e2e --release -- --nocapture
//!
//! This test:
//! 1. Generates a Plonky2 proof for a generic Poseidon hash-chain circuit
//! 2. Generates WHIR polynomial commitment proofs
//! 3. Exports constraint data + WHIR verifier data as JSON fixtures
//! 4. Runs Forge tests that verify on-chain:
//!    - SpongefishWhirVerify: WHIR polynomial commitment (combined)
//!    - Plonky2Verifier: Plonky2 constraint satisfaction check
//!    - Combined E2E: all verifications in a single transaction

#![cfg(feature = "whir")]

use std::{
    path::PathBuf,
    process::Command,
};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn contracts_dir() -> PathBuf {
    repo_root().join("contracts")
}

fn run_checked(cmd: &mut Command, label: &str) {
    eprintln!("[e2e] Running: {label}");
    let output = cmd.output().unwrap_or_else(|err| {
        panic!("{label} failed to start: {err}");
    });

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        panic!(
            "{label} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
    for line in stderr.lines() {
        if line.starts_with("[fixture]") || line.starts_with("[e2e]") {
            eprintln!("  {line}");
        }
    }
    for line in stdout.lines() {
        if line.contains("PASS") || line.contains("FAIL") || line.contains("gas:") {
            eprintln!("  {line}");
        }
    }
}

fn run_forge_test(test_contract: &str, test_name: &str) {
    let mut cmd = Command::new("forge");
    cmd.current_dir(contracts_dir())
        .arg("test")
        .arg("--match-contract")
        .arg(test_contract)
        .arg("--match-test")
        .arg(test_name)
        .arg("-vv");
    run_checked(
        &mut cmd,
        &format!("forge test {test_contract}::{test_name}"),
    );
}

#[cfg_attr(debug_assertions, ignore = "run with --release --features whir")]
#[test]
fn whir_onchain_e2e() {
    eprintln!("=== WHIR On-chain E2E Test (generic circuit) ===");
    eprintln!("Pipeline: Poseidon hash-chain → WHIR → on-chain verify");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 1: Generate fixtures via generate_fixture binary
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 1: Generate fixtures");

    let generator = repo_root().join("target/release/generate_fixture");
    if !generator.exists() {
        eprintln!("[e2e] Building generate_fixture...");
        let mut build_cmd = Command::new("cargo");
        build_cmd
            .current_dir(repo_root())
            .arg("build")
            .arg("--bin")
            .arg("generate_fixture")
            .arg("--release");
        run_checked(&mut build_cmd, "cargo build generate_fixture");
    }

    let mut gen_cmd = Command::new(&generator);
    gen_cmd.current_dir(repo_root());
    run_checked(&mut gen_cmd, "generate_fixture");

    // Verify fixtures exist
    let fixture_dir = contracts_dir().join("test/data");
    assert!(
        fixture_dir.join("test_constraint_data.json").exists(),
        "test_constraint_data.json not generated"
    );
    assert!(
        fixture_dir
            .join("whir/test_combined_verifier_data.json")
            .exists(),
        "test_combined_verifier_data.json not generated"
    );
    eprintln!("[e2e] Fixtures generated successfully");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 2: On-chain WHIR polynomial commitment verification
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 2: WHIR polynomial commitment verification (combined)");
    run_forge_test("GenericE2ETest", "test_whir_combined");
    eprintln!("[e2e] WHIR combined verification: PASS");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 3: On-chain Plonky2 constraint satisfaction check
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 3: Plonky2 constraint satisfaction");
    run_forge_test("GenericE2ETest", "test_plonky2_constraints");
    eprintln!("[e2e] Plonky2 constraint check: PASS");
    eprintln!();

    // -----------------------------------------------------------------------
    // Step 4: Combined E2E
    // -----------------------------------------------------------------------
    eprintln!("[e2e] Step 4: Combined E2E (WHIR + Plonky2 in one transaction)");
    run_forge_test("GenericE2ETest", "test_full_e2e");
    eprintln!("[e2e] Combined E2E: PASS");
    eprintln!();

    eprintln!("=== ALL E2E TESTS PASSED ===");
}
