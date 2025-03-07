use crate::base::if_rayon;
use alloc::vec::Vec;
#[cfg(feature = "rayon")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use core::mem;

/// This operation takes a slice and casts it to a vector of a different type using the provided function.
pub fn slice_cast_with<'a, F, T>(value: &'a [F], cast: impl Fn(&'a F) -> T + Send + Sync) -> Vec<T>
where
    F: Sync,
    T: Send,
{
    if_rayon!(
        value.par_iter().with_min_len(super::MIN_RAYON_LEN),
        value.iter()
    )
    .map(cast)
    .collect()
}

/// This operation takes a slice and casts it to a mutable slice of a different type using the provided function.
pub fn slice_cast_mut_with<'a, F, T>(
    value: &'a [F],
    result: &mut [T],
    cast: impl Fn(&'a F) -> T + Sync,
) where
    F: Sync,
    T: Send + Sync,
{
    if_rayon!(
        value.par_iter().with_min_len(super::MIN_RAYON_LEN),
        value.iter()
    )
    .zip(result)
    .for_each(|(a, b)| *b = cast(a));
}

/// Fast, zero-copy slice cast that reinterprets the memory of one slice type as another.
/// 
/// # Safety
/// 
/// This function is unsafe because it does not check:
/// - If the memory alignment of F is compatible with T
/// - If the memory layout of F is compatible with T
/// - If the total size of the slice is a multiple of the size of T
///
/// The caller must ensure these conditions are met.
#[inline]
pub unsafe fn slice_cast_unchecked<'a, F, T>(value: &'a [F]) -> &'a [T] {
    let ptr = value.as_ptr() as *const T;
    let len = value.len() * mem::size_of::<F>() / mem::size_of::<T>();
    core::slice::from_raw_parts(ptr, len)
}

/// This operation takes a slice and casts it to a vector of a different type.
/// 
/// Note: This creates a new Vec by copying each element. For zero-copy operations
/// where appropriate, use slice_cast_unchecked instead.
pub fn slice_cast<'a, F, T>(value: &'a [F]) -> Vec<T>
where
    F: Sync,
    T: Send,
    &'a F: Into<T>,
{
    slice_cast_with(value, Into::into)
}

/// This operation takes a slice and casts it to a mutable slice of a different type.
pub fn slice_cast_mut<'a, F, T>(value: &'a [F], result: &mut [T])
where
    F: Sync,
    T: Send + Sync,
    &'a F: Into<T>,
{
    slice_cast_mut_with(value, result, Into::into);
}
