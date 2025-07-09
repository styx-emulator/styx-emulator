// SPDX-License-Identifier: BSD-2-Clause
use std::ops::{
    Bound, Range, RangeBounds, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
};

/// Represents a range of addresses in Styx.
///
/// This was chosen over any of the RangeX types because it offers the most
/// flexibility for users providing their address range. Additionally, using a
/// newtype instead of `(Bound<u64>, Bound<u64>)` allows us to implement methods
/// and From/To impls.
///
/// ## Example Creation
///
/// ```
/// use styx_processor::hooks::AddressRange;
///
/// let range: AddressRange = (0x100..0x200).into();
/// let range: AddressRange = (0x100..=0x200).into();
/// let range: AddressRange = (..0x1000).into();
/// let range: AddressRange = AddressRange::from_bounds(&..);
/// ```
///
#[derive(Debug, Clone)]
pub struct AddressRange {
    start: Bound<u64>,
    end: Bound<u64>,
}

impl AddressRange {
    pub fn from_bounds(bounds: &impl RangeBounds<u64>) -> Self {
        Self {
            start: bounds.start_bound().cloned(),
            end: bounds.end_bound().cloned(),
        }
    }

    pub fn to_range(&self) -> RangeInclusive<u64> {
        let start = match self.start {
            Bound::Included(start) => start,
            Bound::Excluded(start) => start + 1,
            Bound::Unbounded => 0,
        };
        let end = match self.end {
            Bound::Included(end) => end,
            Bound::Excluded(end) => end - 1,
            Bound::Unbounded => u64::MAX,
        };
        start..=end
    }
}

impl RangeBounds<u64> for AddressRange {
    fn start_bound(&self) -> Bound<&u64> {
        self.start.as_ref()
    }

    fn end_bound(&self) -> Bound<&u64> {
        self.end.as_ref()
    }
}

impl From<u64> for AddressRange {
    fn from(value: u64) -> Self {
        Self {
            start: Bound::Included(value),
            end: Bound::Included(value),
        }
    }
}
impl From<Range<u64>> for AddressRange {
    fn from(value: Range<u64>) -> Self {
        Self {
            start: value.start_bound().cloned(),
            end: value.end_bound().cloned(),
        }
    }
}
impl From<RangeInclusive<u64>> for AddressRange {
    fn from(value: RangeInclusive<u64>) -> Self {
        Self {
            start: value.start_bound().cloned(),
            end: value.end_bound().cloned(),
        }
    }
}
impl From<RangeFull> for AddressRange {
    fn from(value: RangeFull) -> Self {
        Self {
            start: value.start_bound().cloned(),
            end: value.end_bound().cloned(),
        }
    }
}
impl From<RangeFrom<u64>> for AddressRange {
    fn from(value: RangeFrom<u64>) -> Self {
        Self {
            start: value.start_bound().cloned(),
            end: value.end_bound().cloned(),
        }
    }
}
impl From<RangeTo<u64>> for AddressRange {
    fn from(value: RangeTo<u64>) -> Self {
        Self {
            start: value.start_bound().cloned(),
            end: value.end_bound().cloned(),
        }
    }
}
impl From<RangeToInclusive<u64>> for AddressRange {
    fn from(value: RangeToInclusive<u64>) -> Self {
        Self {
            start: value.start_bound().cloned(),
            end: value.end_bound().cloned(),
        }
    }
}
