// SPDX-License-Identifier: BSD-2-Clause
/// A property of memory with ergonomic handling of the Harvard/von Neumann differences.
///
/// If the user does not care if the underlying architecture is von Neumann or Harvard
/// and their operation correlates to the code or data spaces, then they can use
/// [`Self::data()`] or [`Self::code()`].
///
/// If the user requires a unified memory space then they can use [`Self::von_neuman()`]
/// to get an `Option` that will be `Some` if the space is indeed von Neumann.
/// Or the user can just as easily match on this enum.
///
/// This should be a cheap value to obtain and store because the Harvard case obtains
/// both the code and data property.
#[derive(Debug, Clone, Copy)]
pub enum MemoryArchitecture<T> {
    Harvard { code: T, data: T },
    VonNeumann(T),
}

impl<T> MemoryArchitecture<T> {
    /// Get the value assuming this is von Neumann (non-separate code/data regions), otherwise `None`.
    pub fn von_neuman(self) -> Option<T> {
        match self {
            MemoryArchitecture::Harvard { .. } => None,
            MemoryArchitecture::VonNeumann(value) => Some(value),
        }
    }

    /// Get the `data` code storage, or just *the* storage in the von Neumann case.
    pub fn data(self) -> T {
        match self {
            MemoryArchitecture::Harvard { code: _, data } => data,
            MemoryArchitecture::VonNeumann(value) => value,
        }
    }

    /// Get the `code` code storage, or just *the* storage in the von Neumann case.
    pub fn code(self) -> T {
        match self {
            MemoryArchitecture::Harvard { code, data: _ } => code,
            MemoryArchitecture::VonNeumann(value) => value,
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
                MemoryArchitecture::VonNeumann(value_self),
                MemoryArchitecture::VonNeumann(value_other),
            ) => MemoryArchitecture::VonNeumann(f(value_self, value_other)),
            _ => panic!("memory arches do not match"),
        }
    }
}
