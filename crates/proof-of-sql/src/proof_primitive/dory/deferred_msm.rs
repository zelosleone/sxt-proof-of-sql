use crate::utils::log;
use alloc::{vec, vec::Vec};
use ark_ec::VariableBaseMSM;
use core::ops::{Add, AddAssign, Mul, MulAssign};
use itertools::Itertools;
use num_traits::One;
use super::{F, G1Affine};
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::Mutex;
use std::hash::{Hash, Hasher};
use blake3::Hasher as Blake3Hasher;
use ark_serialize::CanonicalSerialize;

// Global MSM cache with a LRU eviction policy
lazy_static::lazy_static! {
    static ref MSM_CACHE: Mutex<HashMap<u64, Vec<G1Affine>>> = Mutex::new(HashMap::new());
    static ref CACHE_ENABLED: AtomicBool = AtomicBool::new(true);
}

pub fn compute_hash<T: CanonicalSerialize>(data: &T) -> u64 {
    let mut hasher = Blake3Hasher::new();
    let mut bytes = Vec::new();
    data.serialize_compressed(&mut bytes).unwrap();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    let first_bytes = &hash.as_bytes()[0..8];
    u64::from_le_bytes(first_bytes.try_into().unwrap())
}

pub fn enable_msm_cache(enabled: bool) {
    CACHE_ENABLED.store(enabled, Ordering::SeqCst);
}

pub fn clear_msm_cache() {
    let mut cache = MSM_CACHE.lock().unwrap();
    cache.clear();
}

#[derive(Debug, Clone)]
/// A wrapper around a Multi-Scalar Multiplication (MSM) that defers the computation until the end.
/// This can be a mostly drop-in replace to a group element.
pub struct DeferredMSM<G, F> {
    /// pairs of group elements and optional scalars that ultimately form the final msm
    pairs: Vec<(G, Option<F>)>,
}

impl<G, F> DeferredMSM<G, F> {
    /// Construct a new [`DeferredMSM`]
    pub fn new(gs: impl IntoIterator<Item = G>, fs: impl IntoIterator<Item = F>) -> Self {
        Self {
            pairs: gs.into_iter().zip_eq(fs.into_iter().map(Some)).collect(),
        }
    }
}
impl<G, F: One> DeferredMSM<G, F> {
    /// Collapse/compute the MSM into a single group element
    #[tracing::instrument(name = "DeferredMSM::compute", level = "debug", skip_all)]
    pub fn compute<V: VariableBaseMSM<MulBase = G, ScalarField = F>>(self) -> V {
        log::log_memory_usage("Start");

        let (bases, scalars): (Vec<_>, Vec<_>) = self
            .pairs
            .into_iter()
            .map(|(gt, f)| (gt, f.unwrap_or(F::one())))
            .unzip();
        let res = V::msm_unchecked(&bases, &scalars);

        log::log_memory_usage("End");

        res
    }
}

impl<G, F> From<G> for DeferredMSM<G, F> {
    fn from(value: G) -> Self {
        Self {
            pairs: vec![(value, None)],
        }
    }
}
impl<G, F> AddAssign<G> for DeferredMSM<G, F> {
    fn add_assign(&mut self, rhs: G) {
        self.pairs.push((rhs, None));
    }
}
impl<G, F: MulAssign + Copy> MulAssign<F> for DeferredMSM<G, F> {
    fn mul_assign(&mut self, rhs: F) {
        self.pairs.iter_mut().for_each(|(_, f)| match f {
            Some(i) => *i *= rhs,
            None => *f = Some(rhs),
        });
    }
}
impl<G, F: MulAssign + Copy> Mul<F> for DeferredMSM<G, F> {
    type Output = Self;
    fn mul(mut self, rhs: F) -> Self::Output {
        self *= rhs;
        self
    }
}
impl<G, F> AddAssign<DeferredMSM<G, F>> for DeferredMSM<G, F> {
    fn add_assign(&mut self, rhs: DeferredMSM<G, F>) {
        self.pairs.extend(rhs.pairs);
    }
}
impl<G, F> Add<DeferredMSM<G, F>> for DeferredMSM<G, F> {
    type Output = Self;
    fn add(mut self, rhs: DeferredMSM<G, F>) -> Self::Output {
        self += rhs;
        self
    }
}
impl<G, F> Add<G> for DeferredMSM<G, F> {
    type Output = Self;
    fn add(mut self, rhs: G) -> Self::Output {
        self += rhs;
        self
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_ec::{
        pairing::{Pairing, PairingOutput},
        short_weierstrass::{Affine, SWCurveConfig},
        AffineRepr, CurveConfig,
    };
    use ark_ff::prelude::UniformRand;
    impl<V: VariableBaseMSM<ScalarField = F>, F: One> PartialEq<V> for DeferredMSM<V::MulBase, F>
    where
        Self: Clone,
    {
        fn eq(&self, other: &V) -> bool {
            self.clone().compute::<V>().eq(other)
        }
    }
    impl<P: SWCurveConfig> PartialEq<DeferredMSM<Affine<P>, <P as CurveConfig>::ScalarField>>
        for DeferredMSM<Affine<P>, <P as CurveConfig>::ScalarField>
    {
        fn eq(&self, other: &DeferredMSM<Affine<P>, <P as CurveConfig>::ScalarField>) -> bool {
            self.clone().compute::<<Affine<P> as AffineRepr>::Group>()
                == other.clone().compute::<<Affine<P> as AffineRepr>::Group>()
        }
    }
    impl<P: Pairing> PartialEq<DeferredMSM<PairingOutput<P>, P::ScalarField>>
        for DeferredMSM<PairingOutput<P>, P::ScalarField>
    {
        fn eq(&self, other: &DeferredMSM<PairingOutput<P>, P::ScalarField>) -> bool {
            self.clone().compute::<PairingOutput<P>>()
                == other.clone().compute::<PairingOutput<P>>()
        }
    }

    #[test]
    fn we_can_compute_deferred_group_elements() {
        let rng = &mut ark_std::test_rng();
        let g0 = G1Affine::rand(rng);
        let mut result: DeferredMSM<G1Affine, Fr> = g0.into(); // From<G> for DeferredMSM<G, F>
        let g1 = G1Affine::rand(rng);
        let f1 = Fr::rand(rng);
        let gf1 = DeferredMSM::<G1Affine, Fr>::from(g1) * f1; // Mul<F> for DeferredMSM<G, F>
        result += gf1; // AddAssign<DeferredMSM<G, F>> for DeferredMSM<G, F>
        let g2 = G1Affine::rand(rng);
        result += g2; // AddAssign<G> for DeferredMSM<G, F>
        let f2 = Fr::rand(rng);
        result *= f2; // MulAssign<F> for DeferredMSM<G, F>

        let expected_result = (g0 + g1 * f1 + g2) * f2;

        assert_eq!(result, expected_result);
    }
}
