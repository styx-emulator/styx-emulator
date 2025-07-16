// SPDX-License-Identifier: BSD-2-Clause
/// Macro to create the required enums for the architecture registers.
///
/// Given a name and arbitrary number of tuples, it will create
/// the four required components:
/// - An enum with the register names (`<arch>Register` e.g. [`ArmRegister`](crate::arch::arm::ArmRegister))
/// - An enum with the register descriptions ([`CpuRegister`](crate::arch::CpuRegister))
/// - conversions to [`ArchRegister`](crate::arch::backends::ArchRegister)
/// - conversions to [`BasicArchRegister`](crate::arch::backends::BasicArchRegister)
macro_rules! create_basic_register_enums {
    ($enum_name:ident, $(($reg_name:ident, $size:expr_2021)),+ $(,)?) => {
        ::paste::paste! {
            #[derive(Debug,
                     PartialEq,
                     Eq,
                     Clone,
                     Copy,
                     Hash,
                     PartialOrd,
                     Ord,
                     ::derive_more::Display,
                     ::num_derive::FromPrimitive,
                     ::num_derive::ToPrimitive,
                     ::strum_macros::EnumString,
                     ::strum_macros::EnumIter,
                     ::strum_macros::IntoStaticStr)]
            #[strum(ascii_case_insensitive)]
            pub enum [<$enum_name Register>] {
                $($reg_name),+
            }

            impl From<[<$enum_name Register>]> for crate::arch::backends::ArchRegister {
                fn from(reg: [<$enum_name Register>]) -> Self {
                    crate::arch::backends::ArchRegister::Basic(
                        crate::arch::backends::BasicArchRegister::[<$enum_name>](reg),
                    )
                }
            }

            impl From<[<$enum_name Register>]> for crate::arch::backends::BasicArchRegister {
                fn from(reg: [<$enum_name Register>]) -> Self {
                    crate::arch::backends::BasicArchRegister::[<$enum_name>](reg)
                }
            }

            impl [<$enum_name Register>] {
                /// Emits the [`CpuRegister`] struct corresponding to
                /// the current value of `self`
                pub fn register(&self) -> CpuRegister {
                    match self {
                        $(Self::$reg_name => CpuRegister {
                            name: stringify!([<$reg_name:upper>]),
                            bit_size: NonZeroUsize::new($size).expect("Register size must be non-zero"),
                            reg_enum: (*self).into(),
                            register_value: self.register_value_enum(),
                        }),+
                    }
                }

                /// Returns the register value enum for the current register
                pub const fn register_value_enum(&self) -> RegisterValue {
                    match self {
                        $(Self::$reg_name => RegisterValue::from_bit_size($size)),+
                    }
                }

                /// Get all possible register enums
                pub fn all() -> Vec<Self> {
                    vec![$(Self::$reg_name),+]
                }

                /// Get the value by name
                pub fn from_name(name: &str) -> Option<Self> {
                    match name {
                        $(stringify!($reg_name) => Some(Self::$reg_name),)+
                        _ => None,
                    }
                }
            }
        }
    };
}

// people in this crate are allowed to use this macro
pub(crate) use create_basic_register_enums;

/// Macro to create enums for Special Registers.
///
/// Given a name and an arbitrary number of special register types,
/// it will create the required enums and implementations:
/// - An enum with the register names (`Special<Name>Register` e.g. [`SpecialArmRegister`](crate::arch::arm::SpecialArmRegister))
/// - An enum with the register descriptions ([`CpuRegister`](crate::arch::CpuRegister))
/// - conversions to [`ArchRegister`](crate::arch::backends::ArchRegister)
/// - conversions to [`SpecialArchRegister`](crate::arch::backends::SpecialArchRegister)
///
/// It **requires** types to be named in specific ways.
/// - For each special register type, it requires a type named
///   `<SpecialRegister>Value` to be defined and have [`RegisterValueCompatible`](crate::arch::RegisterValueCompatible)
///   implemented.
/// - See [`CoProcessor`](crate::arch::arm::CoProcessor) and [`CoProcessorValue`](crate::arch::arm::CoProcessorValue) as an
///   example.
///
macro_rules! create_special_register_enums {
    ($enum_name:ident) => {
        ::paste::paste! {
            #[derive(Debug,
                     Clone,
                     Copy,
                     PartialEq,
                     Eq,
                     PartialOrd,
                     Ord,
                     Hash,
                     ::derive_more::Display,
                     ::strum_macros::IntoStaticStr,
                     ::strum_macros::EnumIter,
                     ::strum_macros::EnumString)]
            #[strum(ascii_case_insensitive)]
            pub enum [<Special $enum_name Register>] {}

            impl From<[<Special $enum_name Register>]> for crate::arch::backends::SpecialArchRegister {
                fn from(value: [<Special $enum_name Register>]) -> Self {
                    crate::arch::backends::SpecialArchRegister::[<$enum_name>](value)
                }
            }

            impl From<[<Special $enum_name Register>]> for crate::arch::backends::ArchRegister {
                fn from(value: [<Special $enum_name Register>]) -> Self {
                    crate::arch::backends::ArchRegister::Special(
                        crate::arch::backends::SpecialArchRegister::[<$enum_name>](value),
                    )
                }
            }

            impl [<Special $enum_name Register>] {
                /// Emits the [`CpuRegister`] struct corresponding to
                /// the current value of `self`
                pub fn register(&self) -> CpuRegister {
                    CpuRegister {
                        name: self.into(),
                        bit_size: NonZeroUsize::new(self.register_bit_size())
                            .expect("Register bit size must be non-zero"),
                        reg_enum: (*self).into(),
                        #[allow(unreachable_code)] // TODO: remove when this enum gets a value
                        register_value: self.register_value_enum(),
                    }
                }

                /// Returns the register bit size
                pub const fn register_bit_size(&self) -> usize {
                    match *self {}
                }

                /// Returns the register value enum for the current register
                pub const fn register_value_enum(&self) -> RegisterValue {
                    RegisterValue::from_bit_size(self.register_bit_size())
                }
            }
        }
    };
    ($enum_name:ident, $($special_register_type:ident)+) => {
        ::paste::paste! {
            #[derive(Debug,
                     Clone,
                     Copy,
                     PartialEq,
                     Eq,
                     PartialOrd,
                     Ord,
                     Hash,
                     ::derive_more::Display,
                     ::strum_macros::IntoStaticStr,
                     ::strum_macros::EnumIter,
                     ::strum_macros::EnumString)]
            #[strum(ascii_case_insensitive)]
            pub enum [<Special $enum_name Register>] {
                $([<$special_register_type>]($special_register_type)),+
            }

            impl From<[<Special $enum_name Register>]> for crate::arch::backends::SpecialArchRegister {
                fn from(value: [<Special $enum_name Register>]) -> Self {
                    crate::arch::backends::SpecialArchRegister::[<$enum_name>](value)
                }
            }

            impl From<[<Special $enum_name Register>]> for crate::arch::backends::ArchRegister {
                fn from(value: [<Special $enum_name Register>]) -> Self {
                    crate::arch::backends::ArchRegister::Special(
                        crate::arch::backends::SpecialArchRegister::[<$enum_name>](value),
                    )
                }
            }

            impl [<Special $enum_name Register>] {
                /// Emits the [`CpuRegister`] struct corresponding to
                /// the current value of `self`
                pub fn register(&self) -> CpuRegister {
                    match self {
                        $(Self::$special_register_type(_) => CpuRegister {
                            name: stringify!($special_register_type),
                            bit_size: NonZeroUsize::new(::std::mem::size_of::<[<$special_register_type>]>())
                                .expect("Register bit size must be non-zero"),
                            reg_enum: (*self).into(),
                            #[allow(unreachable_code)] // TODO: remove when this enum gets a value
                            register_value: self.register_value_enum(),
                        }),+
                    }
                }

                /// Returns the register value enum for the current register
                pub const fn register_value_enum(&self) -> RegisterValue {
                    let reg = match self {
                        $(Self::[<$special_register_type>](_) =>
                            [<Special $enum_name RegisterValues>]::[<$special_register_type>]([<$special_register_type Value>]::const_default()),
                        ),+
                    };

                    RegisterValue::[<$enum_name Special>](reg)
                }
            }

            // now the register values
            #[derive(Debug, PartialEq, Eq, Clone, Copy, Display)]
            pub enum [<Special $enum_name RegisterValues>] {
                $($special_register_type([<$special_register_type Value>]),)+
            }

            impl PartialOrd for [<Special $enum_name RegisterValues>] {
                fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                    Some(self.cmp(other))
                }
            }

            /// Each special register type is considered equal to itself,
            /// and less than everything else.
            impl Ord for [<Special $enum_name RegisterValues>] {
                fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                    match self {
                        $(
                            Self::[<$special_register_type>](_) => match other {
                                Self::[<$special_register_type>](_) => std::cmp::Ordering::Equal,
                                // less than everything else
                                #[allow(unreachable_patterns)]
                                _ => std::cmp::Ordering::Less,
                            }
                        ),+
                        // less than everything else
                        #[allow(unreachable_patterns)]
                        _ => std::cmp::Ordering::Less,
                    }
                }
            }

            // now the register values
            impl From<[<Special $enum_name RegisterValues>]> for RegisterValue {
                fn from(value: [<Special $enum_name RegisterValues>]) -> Self {
                    Self::[<$enum_name Special>](value)
                }
            }

            // for each of the special register types, impl from it to `RegisterValue`
            $(
                impl From<[<$special_register_type Value>]> for RegisterValue {
                    fn from(value: [<$special_register_type Value>]) -> Self {
                        [<Special $enum_name RegisterValues>]::[<$special_register_type>](value).into()
                    }
                }
            )*
        }
    };

}

// people in this crate are allowed to use this macro
pub(crate) use create_special_register_enums;
