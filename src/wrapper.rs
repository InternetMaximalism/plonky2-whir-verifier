use std::marker::PhantomData;

use crate::error::{Error, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite as _},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};

/// Generic wrapper circuit that re-proves any Plonky2 proof under a different config.
///
/// This is typically used to convert a proof from one hash configuration (e.g., Keccak)
/// to another (e.g., Poseidon) before applying WHIR.
pub struct WrapperCircuit<F, InnerC, OuterC, const D: usize>
where
    F: RichField + Extendable<D>,
    InnerC: GenericConfig<D, F = F>,
    OuterC: GenericConfig<D, F = F>,
{
    pub data: CircuitData<F, OuterC, D>,
    pub wrap_proof: ProofWithPublicInputsTarget<D>,
    _maker: PhantomData<InnerC>,
}

impl<F, InnerC, OuterC, const D: usize> WrapperCircuit<F, InnerC, OuterC, D>
where
    F: RichField + Extendable<D>,
    OuterC: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F> + 'static,
    InnerC::Hasher: AlgebraicHasher<F>,
{
    pub fn new(inner_circuit_verifier_data: &VerifierCircuitData<F, InnerC, D>) -> Self {
        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        // Inline of add_proof_target_and_verify (avoids external dependency)
        let wrap_proof = {
            let proof =
                builder.add_virtual_proof_with_pis(&inner_circuit_verifier_data.common);
            let vd_target =
                builder.constant_verifier_data(&inner_circuit_verifier_data.verifier_only);
            builder.verify_proof::<InnerC>(
                &proof,
                &vd_target,
                &inner_circuit_verifier_data.common,
            );
            proof
        };
        builder.register_public_inputs(&wrap_proof.public_inputs);
        let data = builder.build();
        Self {
            data,
            wrap_proof,
            _maker: PhantomData,
        }
    }

    pub fn prove(
        &self,
        inner_proof: &ProofWithPublicInputs<F, InnerC, D>,
    ) -> Result<ProofWithPublicInputs<F, OuterC, D>> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.wrap_proof, inner_proof);
        self.data
            .prove(pw)
            .map_err(|e| Error::WrapperProofFailed(format!("{}", e)))
    }
}
