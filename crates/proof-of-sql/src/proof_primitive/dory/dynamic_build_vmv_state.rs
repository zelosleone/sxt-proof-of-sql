use super::{
    dynamic_dory_helper::compute_dynamic_v_vec, DeferredGT, DoryScalar, G1Affine, VMVProverState,
    VMVVerifierState, F,
};
use crate::proof_primitive::dynamic_matrix_utils::standard_basis_helper::compute_dynamic_vecs;
use crate::base::slice_ops::slice_cast_unchecked;
use alloc::vec::Vec;

/// Builds a [`VMVProverState`] from the given parameters.
pub(super) fn build_dynamic_vmv_prover_state(
    a: &[F],
    b_point: &[F],
    T_vec_prime: Vec<G1Affine>,
    nu: usize,
) -> VMVProverState {
    // Use unsafe cast to convert F slice to DoryScalar slice
    let b_point_dory: &[DoryScalar] = unsafe { slice_cast_unchecked(b_point) };
    let (lo_vec, hi_vec) = compute_dynamic_vecs(b_point_dory);
    
    // Convert back to F slices
    let lo_vec_f: &[F] = unsafe { slice_cast_unchecked(&lo_vec) };
    let hi_vec_f: &[F] = unsafe { slice_cast_unchecked(&hi_vec) };
    
    let v_vec = compute_dynamic_v_vec(a, hi_vec_f, nu);
    VMVProverState {
        v_vec,
        T_vec_prime,
        L_vec: hi_vec_f.to_vec(),
        R_vec: lo_vec_f.to_vec(),
        #[cfg(test)]
        l_tensor: Vec::with_capacity(0),
        #[cfg(test)]
        r_tensor: b_point.to_vec(),
        nu,
    }
}

/// Builds a [`VMVVerifierState`] from the given parameters.
pub(super) fn build_dynamic_vmv_verifier_state(
    y: F,
    b_point: &[F],
    T: DeferredGT,
    nu: usize,
) -> VMVVerifierState {
    VMVVerifierState {
        y,
        T,
        l_tensor: Vec::with_capacity(0),
        r_tensor: b_point.to_vec(),
        nu,
    }
}
