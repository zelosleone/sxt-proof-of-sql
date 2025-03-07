use super::{
    build_vmv_prover_state, build_vmv_verifier_state, compute_T_vec_prime, compute_nu,
    eval_vmv_re_prove, eval_vmv_re_verify, extended_dory_inner_product_prove,
    extended_dory_inner_product_verify,
    extended_dory_reduce_helper::extended_dory_reduce_verify_fold_s_vecs, DeferredGT,
    DoryCommitment, DoryMessages, DoryProverPublicSetup, DoryScalar, DoryVerifierPublicSetup, F,
};
use crate::{
    base::{commitment::CommitmentEvaluationProof, proof::Transcript},
    utils::log,
};
use snafu::Snafu;

/// The `CommitmentEvaluationProof` for the Dory PCS.
pub type DoryEvaluationProof = DoryMessages;

/// The error type for the Dory PCS.
#[derive(Snafu, Debug)]
pub enum DoryError {
    /// This error occurs when the generators offset is invalid.
    #[snafu(display("invalid generators offset: {offset}"))]
    InvalidGeneratorsOffset { offset: u64 },
    /// This error occurs when the proof fails to verify.
    #[snafu(display("verification error"))]
    VerificationError,
    /// This error occurs when the setup is too small.
    #[snafu(display("setup is too small: the setup is {actual}, but the proof requires a setup of size {required}"))]
    SmallSetup { actual: usize, required: usize },
}

impl CommitmentEvaluationProof for DoryEvaluationProof {
    type Scalar = DoryScalar;
    type Commitment = DoryCommitment;
    type Error = DoryError;
    type ProverPublicSetup<'a> = DoryProverPublicSetup<'a>;
    type VerifierPublicSetup<'a> = DoryVerifierPublicSetup<'a>;

    #[tracing::instrument(name = "DoryEvaluationProof::new", level = "debug", skip_all)]
    fn new(
        transcript: &mut impl Transcript,
        a: &[Self::Scalar],
        b_point: &[Self::Scalar],
        generators_offset: u64,
        setup: &Self::ProverPublicSetup<'_>,
    ) -> Self {
        log::log_memory_usage("Start");

        // Dory PCS Logic
        if generators_offset != 0 {
            // TODO: support offsets other than 0.
            // Note: this will always result in a verification error.
            return DoryMessages::default();
        }
        let a: &[F] = bytemuck::TransparentWrapper::peel_slice(a);
        let b_point: &[F] = bytemuck::TransparentWrapper::peel_slice(b_point);
        let prover_setup = setup.prover_setup();
        let nu = compute_nu(b_point.len(), setup.sigma());
        if nu > prover_setup.max_nu {
            return DoryMessages::default(); // Note: this will always result in a verification error.
        }
        let T_vec_prime = compute_T_vec_prime(a, setup.sigma(), nu, prover_setup);
        let state = build_vmv_prover_state(a, b_point, T_vec_prime, setup.sigma(), nu);

        let mut messages = DoryMessages::default();
        let extended_state = eval_vmv_re_prove(&mut messages, transcript, state, prover_setup);
        extended_dory_inner_product_prove(&mut messages, transcript, extended_state, prover_setup);

        log::log_memory_usage("End");

        messages
    }

    #[tracing::instrument(
        name = "DoryEvaluationProof::verify_batched_proof",
        level = "debug",
        skip_all
    )]
    fn verify_batched_proof(
        &self,
        transcript: &mut impl Transcript,
        commit_batch: &[Self::Commitment],
        batching_factors: &[Self::Scalar],
        evaluations: &[Self::Scalar],
        b_point: &[Self::Scalar],
        generators_offset: u64,
        _table_length: usize,
        setup: &Self::VerifierPublicSetup<'_>,
    ) -> Result<(), Self::Error> {
        log::log_memory_usage("Start");

        let a_commit = DeferredGT::new(
            commit_batch.iter().map(|c| c.0),
            batching_factors.iter().map(|f| f.0),
        );
        let product: Self::Scalar = evaluations
            .iter()
            .zip(batching_factors)
            .map(|(&e, &f)| e * f)
            .sum();
        // Dory PCS Logic
        if generators_offset != 0 {
            return Err(DoryError::InvalidGeneratorsOffset {
                offset: generators_offset,
            });
        }
        let b_point: &[F] = bytemuck::TransparentWrapper::peel_slice(b_point);
        let verifier_setup = setup.verifier_setup();
        let mut messages = self.clone();
        let nu = compute_nu(b_point.len(), setup.sigma());
        if nu > verifier_setup.max_nu {
            return Err(DoryError::SmallSetup {
                actual: verifier_setup.max_nu,
                required: nu,
            });
        }
        let state = build_vmv_verifier_state(product.0, b_point, a_commit, setup.sigma(), nu);
        let extended_state = eval_vmv_re_verify(&mut messages, transcript, state, verifier_setup)
            .ok_or(DoryError::VerificationError)?;
        if !extended_dory_inner_product_verify(
            &mut messages,
            transcript,
            extended_state,
            verifier_setup,
            extended_dory_reduce_verify_fold_s_vecs,
        ) {
            Err(DoryError::VerificationError)?;
        }

        log::log_memory_usage("End");

        Ok(())
    }
}
