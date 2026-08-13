// SPDX-License-Identifier: BSD-2-Clause
use std::ops::{Deref, DerefMut};

use smallvec::SmallVec;

use crate::core::VcpuId;

/// Arbitrary.
const TYPICAL_VCPUS: usize = 8;

type Inner<T> = SmallVec<[T; TYPICAL_VCPUS]>;

/// Owned list, one item per vCPU.
///
/// Borrowed counterpart is [`PerVcpuSlice`], as `[T]` is to [`Vec`].
///
/// Invariants:
/// - non-empty
/// - indexed by [`VcpuId`]
///
/// [`SmallVec`] storage keeps up to `TYPICAL_VCPUS` items on the stack, so the common
/// case needs no heap allocation.
///
/// ```
/// # use styx_processor::processor::PerVcpu;
/// let states = PerVcpu::collect([10, 20, 30]).unwrap();
///
/// assert_eq!(states.first(), &10); // PerVcpuSlice method
/// assert_eq!(states.len(), 3); // slice method
/// assert_eq!(states[1], 20); // slice indexing
/// ```
#[derive(Clone, Debug)]
pub struct PerVcpu<T>(Inner<T>);

impl<T> PerVcpu<T> {
    /// Collect an iterator, one item per vCPU in [`VcpuId`] order.
    ///
    /// `None` if the iterator is empty.
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpu;
    /// let tokens = PerVcpu::collect(0..3).unwrap();
    /// assert_eq!(&tokens[..], &[0, 1, 2]);
    ///
    /// assert!(PerVcpu::collect(0..0).is_none());
    /// ```
    pub fn collect<I>(iter: I) -> Option<Self>
    where
        I: IntoIterator<Item = T>,
    {
        let collection = iter.into_iter().collect::<Inner<T>>();
        if collection.is_empty() {
            None
        } else {
            Some(Self(collection))
        }
    }

    /// Append the item for the next vCPU.
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpu;
    /// let mut states = PerVcpu::collect([10]).unwrap();
    /// states.push(20);
    ///
    /// assert_eq!(&states[..], &[10, 20]);
    /// ```
    pub fn push(&mut self, item: T) {
        self.0.push(item)
    }

    /// Map every item, keeping vCPU order.
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpu;
    /// let states = PerVcpu::collect([1, 2, 3]).unwrap();
    /// let doubled = states.map(|state| state * 2);
    ///
    /// assert_eq!(&doubled[..], &[2, 4, 6]);
    /// ```
    pub fn map<F, U>(self, f: F) -> PerVcpu<U>
    where
        F: FnMut(T) -> U,
    {
        PerVcpu(self.0.into_iter().map(f).collect())
    }
}

/// Consume into the items, in [`VcpuId`] order.
///
/// ```
/// # use styx_processor::processor::PerVcpu;
/// let states = PerVcpu::collect([10, 20]).unwrap();
/// let owned: Vec<_> = states.into_iter().collect();
///
/// assert_eq!(owned, vec![10, 20]);
/// ```
impl<T> IntoIterator for PerVcpu<T> {
    type Item = T;
    type IntoIter = smallvec::IntoIter<[T; TYPICAL_VCPUS]>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> Deref for PerVcpu<T> {
    type Target = PerVcpuSlice<T>;

    fn deref(&self) -> &Self::Target {
        PerVcpuSlice::new(&self.0).expect("PerVcpu is never empty")
    }
}

impl<T> DerefMut for PerVcpu<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        PerVcpuSlice::new_mut(&mut self.0).expect("PerVcpu is never empty")
    }
}

/// Borrowed list, one item per vCPU. Never empty.
///
/// Counterpart to [`PerVcpu`], as `[T]` is to [`Vec`]. Take `&PerVcpuSlice<T>` or
/// `&mut PerVcpuSlice<T>` in function args; [`PerVcpu`] derefs to it, and a plain slice
/// converts with [`PerVcpuSlice::new()`].
///
/// Derefs to `[T]`, so slice methods and indexing still work.
///
/// ```
/// # use styx_processor::processor::{PerVcpu, PerVcpuSlice};
/// fn count(vcpus: &PerVcpuSlice<u32>) -> usize {
///     vcpus.len()
/// }
///
/// // owned coerces
/// let owned = PerVcpu::collect([1, 2]).unwrap();
/// assert_eq!(count(&owned), 2);
///
/// // borrowed converts
/// let raw = [1, 2, 3];
/// assert_eq!(count(PerVcpuSlice::new(&raw).unwrap()), 3);
/// ```
#[repr(transparent)]
#[derive(Debug)]
pub struct PerVcpuSlice<T>([T]);

impl<T> PerVcpuSlice<T> {
    /// Wrap a slice, one item per vCPU in [`VcpuId`] order.
    ///
    /// `None` if the slice is empty.
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpuSlice;
    /// let states = [10, 20];
    /// assert_eq!(PerVcpuSlice::new(&states).unwrap().len(), 2);
    ///
    /// let empty: [u32; 0] = [];
    /// assert!(PerVcpuSlice::new(&empty).is_none());
    /// ```
    pub fn new(slice: &[T]) -> Option<&Self> {
        if slice.is_empty() {
            return None;
        }
        // # Safety
        // `PerVcpuSlice<T>` is `repr(transparent)` over `[T]`, so both have identical
        // layout and pointer metadata. The cast changes the type only. The non-empty
        // invariant is checked above.
        Some(unsafe { &*(slice as *const [T] as *const Self) })
    }

    /// Mutable [`PerVcpuSlice::new()`].
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpuSlice;
    /// let mut states = [10, 20];
    /// let states = PerVcpuSlice::new_mut(&mut states).unwrap();
    /// *states.first_mut() = 11;
    ///
    /// assert_eq!(&states[..], &[11, 20]);
    /// ```
    pub fn new_mut(slice: &mut [T]) -> Option<&mut Self> {
        if slice.is_empty() {
            return None;
        }
        // # Safety
        // See `PerVcpuSlice::new()`. The exclusive borrow of `slice` is moved into the
        // returned reference, so no aliasing is introduced.
        Some(unsafe { &mut *(slice as *mut [T] as *mut Self) })
    }

    pub fn single(single: &T) -> &Self {
        let slice = std::slice::from_ref(single);
        Self::new(slice).expect("one value")
    }

    pub fn single_mut(single: &mut T) -> &mut Self {
        let slice = std::slice::from_mut(single);
        Self::new_mut(slice).expect("one value")
    }

    /// Item of the first vCPU.
    ///
    /// Infallible, unlike slice `first`, because the list is never empty.
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpu;
    /// let states = PerVcpu::collect([10, 20]).unwrap();
    /// assert_eq!(states.first(), &10);
    /// ```
    pub fn first(&self) -> &T {
        &self.0[0]
    }

    /// Mutable [`PerVcpuSlice::first()`].
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpu;
    /// let mut states = PerVcpu::collect([10, 20]).unwrap();
    /// *states.first_mut() = 11;
    ///
    /// assert_eq!(states.first(), &11);
    /// ```
    pub fn first_mut(&mut self) -> &mut T {
        &mut self.0[0]
    }

    /// Item of `id`. `None` if no such vCPU.
    ///
    /// Takes a [`VcpuId`], unlike slice `get`.
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpu;
    /// let states = PerVcpu::collect([10, 20]).unwrap();
    ///
    /// assert_eq!(states.get(1), Some(&20));
    /// assert_eq!(states.get(9), None);
    /// ```
    pub fn get(&self, id: VcpuId) -> Option<&T> {
        self.0.get(id as usize)
    }

    /// Mutable [`PerVcpuSlice::get()`].
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpu;
    /// let mut states = PerVcpu::collect([10, 20]).unwrap();
    /// *states.get_mut(1).unwrap() = 21;
    ///
    /// assert_eq!(states.get(1), Some(&21));
    /// ```
    pub fn get_mut(&mut self, id: VcpuId) -> Option<&mut T> {
        self.0.get_mut(id as usize)
    }

    /// Iterate items with their [`VcpuId`].
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpu;
    /// let states = PerVcpu::collect([10, 20]).unwrap();
    /// let ids: Vec<_> = states.enumerate().map(|(id, _)| id).collect();
    ///
    /// assert_eq!(ids, vec![0, 1]);
    /// ```
    pub fn enumerate(&self) -> impl Iterator<Item = (VcpuId, &T)> {
        self.iter().enumerate().map(|(idx, t)| (idx as VcpuId, t))
    }

    /// Mutable [`PerVcpuSlice::enumerate()`].
    ///
    /// ```
    /// # use styx_processor::processor::PerVcpu;
    /// let mut states = PerVcpu::collect([10, 20]).unwrap();
    /// for (id, state) in states.enumerate_mut() {
    ///     *state += id as u32;
    /// }
    ///
    /// assert_eq!(&states[..], &[10, 21]);
    /// ```
    pub fn enumerate_mut(&mut self) -> impl Iterator<Item = (VcpuId, &mut T)> {
        self.iter_mut()
            .enumerate()
            .map(|(idx, t)| (idx as VcpuId, t))
    }

    /// Map every item, keeping vCPU order.
    pub fn map<F, U>(&self, mut f: F) -> PerVcpu<U>
    where
        F: FnMut(VcpuId, &T) -> U,
    {
        PerVcpu(
            self.0
                .iter()
                .enumerate()
                .map(|(i, t)| f(i as VcpuId, t))
                .collect(),
        )
    }

    /// Map every item, keeping vCPU order.
    pub fn map_mut<F, U>(&mut self, mut f: F) -> PerVcpu<U>
    where
        F: FnMut(VcpuId, &mut T) -> U,
    {
        PerVcpu(
            self.0
                .iter_mut()
                .enumerate()
                .map(|(i, t)| f(i as VcpuId, t))
                .collect(),
        )
    }
}

impl<T> Deref for PerVcpuSlice<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for PerVcpuSlice<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
