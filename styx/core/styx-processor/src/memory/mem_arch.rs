// SPDX-License-Identifier: BSD-2-Clause
/// A property of memory with ergonomic handling of the Harvard/VonNeuman differences.
///
/// If the user does not care if the underlying architecture is VonNeuman or Harvard
/// and their operation correlates to the code or data spaces, then they can use
/// [`Self::data()`] or [`Self::code()`].
///
/// If the user requires a unified memory space then they can use [`Self::von_neuman()`]
/// to get an `Option` that will be `Some` if the space is indeed VonNeuman.
/// Or the user can just as easily match on this enum.
///
/// This should be a cheap value to obtain and store because the Harvard case obtains
/// both the code and data property.
#[derive(Debug, Clone, Copy)]
pub enum MemoryArchitecture<T> {
    Harvard { code: T, data: T },
    VonNeuman(T),
}

impl<T> MemoryArchitecture<T> {
    /// Get the value assuming this is VonNeuman, otherwise `None`.
    pub fn von_neuman(self) -> Option<T> {
        match self {
            MemoryArchitecture::Harvard { .. } => None,
            MemoryArchitecture::VonNeuman(value) => Some(value),
        }
    }

    /// Get the `data` code storage, or just *the* storage in the VonNeuman case.
    pub fn data(self) -> T {
        match self {
            MemoryArchitecture::Harvard { code: _, data } => data,
            MemoryArchitecture::VonNeuman(value) => value,
        }
    }

    /// Get the `code` code storage, or just *the* storage in the VonNeuman case.
    pub fn code(self) -> T {
        match self {
            MemoryArchitecture::Harvard { code, data: _ } => code,
            MemoryArchitecture::VonNeuman(value) => value,
        }
    }

    /// Combine two either arches with identical types.
    ///
    /// Panics if `self` and `other` are not the same type.
    pub fn with<O, R>(
        self,
        other: MemoryArchitecture<O>,
        mut f: impl FnMut(T, O) -> R,
    ) -> MemoryArchitecture<R> {
        match (self, other) {
            (
                MemoryArchitecture::Harvard {
                    code: code_self,
                    data: data_self,
                },
                MemoryArchitecture::Harvard {
                    code: code_other,
                    data: data_other,
                },
            ) => MemoryArchitecture::Harvard {
                code: f(code_self, code_other),
                data: f(data_self, data_other),
            },
            (
                MemoryArchitecture::VonNeuman(value_self),
                MemoryArchitecture::VonNeuman(value_other),
            ) => MemoryArchitecture::VonNeuman(f(value_self, value_other)),
            _ => panic!("memory arches do not match"),
        }
    }
}
