// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! styx procedural macro definitions

mod build_with;
mod enum_mirror;

use proc_macro::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream, Parser},
    parse_macro_input, parse_quote,
    punctuated::Punctuated,
    Attribute, Data, DeriveInput, Fields, Ident, LitStr, Meta, Path, Token,
};

/// styx_event attribute - proceural macro for creating new events. Used in
/// conjunction with [`macro@styx_event_dispatch`] and also derives
/// the `Traceable` trait using
/// [`#[proc_macro_derive(Traceable)]`](derive_traceable)
///
/// # Notional Example
/// ```text
///    #[styx_event(etype=TraceEventType::CTRL)]
///    struct ControlEvent {
///        pub reserved_u16: u16,
///        pub reserved_1: u32,
///        pub reserved_2: u32,
///        pub reserved_3: u32,
///    }
/// ```
/// # Usage Rules:
/// - **etype** is used to set the default TraceEventType and must be consistent
///   with [`macro@styx_event_dispatch`]
/// - struct must be sized the same as the base event
/// - struct should be aligned on 4 byte boundaries
#[proc_macro_attribute]
pub fn styx_event(args: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    // Get the struct fields make sure we are dealing with a struct
    let (_, event_fields, _) = match input.data {
        syn::Data::Struct(syn::DataStruct {
            struct_token,
            fields,
            semi_token,
        }) => (struct_token, fields, semi_token),
        _ => panic!("styx_event macro expects a struct"),
    };
    // parse the attributes of styx_event(), for example:
    let (type_field_name, event_enum_type) = StyxEventAttrOption::parse(args);
    let input_struct_name = input.ident;
    let input_struct_attrs = input.attrs;

    let impl_new_docstr = format!(
        "Creates a new `{}` with `{}` set to `{}`",
        input_struct_name,
        type_field_name,
        path_to_string(&event_enum_type)
    );
    let input_struct_fields = if let syn::Fields::Named(fields) = &event_fields {
        fields.named.iter().cloned().collect::<Vec<syn::Field>>()
    } else {
        vec![]
    };

    // Return the code
    proc_macro::TokenStream::from(quote! {
        #[derive(Clone, Debug, Default)]
        #[derive(Serialize, Deserialize)]
        #[derive(Eq, PartialEq)]
        // Derive Traceable
        #[derive(Traceable)]
        // repr(C) required to ensure alignment
        #[repr(C)]
        #(#input_struct_attrs)*

        pub struct #input_struct_name {
            #[doc="Event number"]
            pub event_num: u64,

            #[doc="Event type"]
            pub etype: TraceEventType,

            #(#input_struct_fields),*
        }

        impl From<BaseTraceEvent> for #input_struct_name {
            #[inline(always)]
            fn from(value: BaseTraceEvent) -> Self {
                unsafe { std::mem::transmute(value) }
            }
        }

        impl #input_struct_name {
            #[doc = #impl_new_docstr]
            pub fn new() -> Self {
                Self {
                    #type_field_name : #event_enum_type,
                    ..Default::default()
                }
            }
        }

    })
}

/// styx_event_dispatch macro to bind event types to specific event implementations
/// Expects to see something like this:
/// ```text
///     #[styx_event_dispatch(BaseTraceEvent, Traceable)]
///     pub enum TraceableItem {
///         InsnExecEvent(TraceEventType::INST_EXEC),
///         InsnFetchEvent(TraceEventType::INST_FETCH),
///         ...
///         ControlEvent(TraceEventType::CTRL),
///     }
/// ```
/// Used in conjunction with the [`macro@styx_event`] macro
#[proc_macro_attribute]
pub fn styx_event_dispatch(args: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let enum_dispatch_ident = input.ident;
    let (base_event, dispatched_trait) = base_and_trait(args, 2);
    let bindings = parse_enum_types_bindings(input.data);
    let event_attrs = input.attrs;

    // Collect arm matches for the impl from BaseTraceEvent => SpecificEvent
    // Store as a vec of proc_macro2::TokenStream
    let mut match_arms: Vec<proc_macro2::TokenStream> = Vec::new();
    bindings.iter().for_each(|(ident, path)| {
        match_arms.push(quote! {
            #path => #ident::from(value).into(),
        });
    });

    // gather enum dispatch variants as a vec of TokenStream
    let enum_dispatch_items = bindings
        .into_iter()
        .map(|(ident, _path)| {
            quote! {
                #ident,
            }
        })
        .collect::<Vec<proc_macro2::TokenStream>>();

    proc_macro::TokenStream::from(quote! {
        impl From<#base_event> for #enum_dispatch_ident {
            #[inline]
            fn from(value: #base_event) -> Self {
                match (value.event_type()) {
                    #(#match_arms)*
                    _ => panic!("unknown event >> {:?} <<", value),
                }
            }
        }

        #[allow(clippy::enum_variant_names)]
        #[enum_dispatch(#dispatched_trait)]
        #(#event_attrs)*
        pub enum #enum_dispatch_ident {
            #(#enum_dispatch_items)*
        }
    })
}

/// Derives the `Traceable` for the event, which is defined in the `styx-trace`
/// crate. This is used in 3 locations, but there should be no
/// other reason to use it.
///
/// 1. In the `styx-trace` crate, it's on `BaseTraceEvent` _(a base case)_.
/// 2. in the `styx-trace` crate, it's passed as an attribute to the
///    [styx_event_dispatch](macro@crate::styx_event_dispatch) macro.
/// 3. It's called from the [styx_event](macro@crate::styx_event) macro.
#[proc_macro_derive(Traceable)]
pub fn derive_traceable(item: TokenStream) -> TokenStream {
    let event_name = parse_macro_input!(item as DeriveInput).ident;
    quote! {
        impl Traceable for #event_name {

            /// Get the event type
            #[inline(always)]
            fn event_type(&self) -> TraceEventType {
                self.etype
            }


            /// Get the event number for the event
            #[inline(always)]
            fn event_num(&self) -> u64 {
                self.event_num
            }

            /// Convert to json
            #[inline(always)]
            fn json(&self) -> String {
                serde_json::to_string(&self).unwrap()
            }


            /// Convert to text - but really just the derived `Debug` impl
            #[inline(always)]
            fn text(&self) -> String {
                format!("{:?}", &self)
            }

            /// Convert to binary version of the event
            #[inline(always)]
            fn binary(&self) -> &BinaryTraceEventType {
                unsafe{
                    std::mem::transmute::<&#event_name, &BinaryTraceEventType>(self)
                }
            }

        }
    }
    .into()
}

/// Parse and return  the base event type and the dispatched trait.
/// Expect something that looks like this:
/// ```text
/// #[styx_event_dispatch(BaseTraceEvent, Traceable)]
/// pub enum TraceableItem {
///  ...
/// }
/// ```
fn base_and_trait(args: TokenStream, expect_count: usize) -> (Ident, Ident) {
    // parse into a Vec, check length, return the base event name and trait name
    let vals = parse_idents(args.into());
    assert_eq!(vals.len(), expect_count);
    (vals[0].to_owned(), vals[1].to_owned())
}

/// parse a single path item, like `A::B`, return the syn::Path
/// panic! if we get more than 1
fn parse_single_path(ts: proc_macro2::TokenStream) -> Path {
    let paths = parse_paths(ts);
    assert_eq!(paths.len(), 1);
    paths[0].clone()
}

/// parse, return a list of syn::Path separated by commas
fn parse_paths(ts: proc_macro2::TokenStream) -> Vec<Path> {
    Punctuated::<Path, Token![,]>::parse_terminated
        .parse(ts.into())
        .unwrap()
        .into_iter()
        .collect::<Vec<Path>>()
}

/// parse comma-separated list of Idents
#[inline]
fn parse_idents(ts: proc_macro2::TokenStream) -> Vec<Ident> {
    let parser = Punctuated::<Ident, Token![,]>::parse_terminated;
    let vals: Vec<Ident> = parser.parse(ts.into()).unwrap().into_iter().collect();
    vals
}

/// helper function to parse event type bindings.
/// # Input: syn::Data::Enum that looks like this:
/// ```text
///     InsnExecEvent(TraceEventType::INST_EXEC),
///     InsnFetchEvent(TraceEventType::INST_FETCH),
///     ...
/// ```
/// # Returns
/// - a vector of tuples (Ident, Path)
#[inline]
fn parse_enum_types_bindings(enum_data: Data) -> Vec<(Ident, Path)> {
    let mut bindings: Vec<(Ident, Path)> = Vec::new();
    match enum_data {
        syn::Data::Enum(syn::DataEnum {
            enum_token: _,
            brace_token: _,
            variants,
        }) => {
            variants.iter().for_each(|v| {
                if let syn::Fields::Unnamed(unamed_fields) = &v.fields {
                    unamed_fields.unnamed.iter().for_each(|nf| {
                        bindings.push((v.ident.clone(), parse_single_path(nf.to_token_stream())));
                    });
                }
            });
        }
        _ => panic!("expected enum with an un-named field"),
    };
    bindings
}

/// helper function to get a string repr from a syn::Path, since rust prohibits
/// Display impl in/from this crate
#[inline]
fn path_to_string(p: &Path) -> String {
    p.to_token_stream().to_string().replace(' ', "")
}

#[derive(Clone)]
struct StyxEventAttrOption {
    name: Ident,
    pub value: Path,
}

impl StyxEventAttrOption {
    fn path(&self) -> Path {
        self.value.to_owned()
    }
    fn ident(&self) -> Ident {
        self.name.to_owned()
    }

    /// parse the #[macro@styx_event] item attribute, the expectation is, for example:
    /// ```text
    ///     #[styx_event(etype=TraceEventType::MEM_READ)]`
    ///     struct MemReadEvent {...}
    /// ```
    /// returns (Ident, Path) where Ident is name of the field (ie: `etype`) and
    /// Path is the enumeration value (ie: `TraceEventType::MEM_READ`)
    fn parse(args: TokenStream) -> (Ident, Path) {
        let event_opts = Punctuated::<StyxEventAttrOption, Token![,]>::parse_terminated
            .parse(args)
            .unwrap()
            .into_iter()
            .collect::<Vec<StyxEventAttrOption>>();
        // currently, "etype" is the only arg, and is required.
        assert!(event_opts[0].name == "etype");
        (event_opts[0].ident(), event_opts[0].path())
    }
}

/// parse styx event attributes
/// they look like this: `[styx_event(etype=TraceEventType::INST_FETCH)]`
/// The only valid one, at present, is `etype`
impl Parse for StyxEventAttrOption {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let name: Ident = input.parse()?;
        let _: Token![=] = input.parse()?; // discard '='
        let value: Path = input.parse()?;
        Ok(Self { name, value })
    }
}

/// Convert to proc_macro2::TokenStream
macro_rules! strts2 {
    ($Expr: expr) => {
        $Expr.parse::<proc_macro2::TokenStream>().unwrap()
    };
}

// const's for collecting hte `gdb_target_description` attributes
const ARGS_ATTR_NAME: &str = "args";
const ANCHOR_FIELD: &str = "args";
const ATTR_GDB_ARCH_NAME: &str = "gdb_arch_name";
const ATTR_GDB_FEATURE_XML_NAME: &str = "gdb_feature_xml";
const ATTR_REGISTER_MAP_NAME: &str = "register_map";
const ATTR_PC_REGISTER_NAME: &str = "pc_register";
const ATTR_ENDIANNESS_NAME: &str = "endianness";

/// Simple enum used to assist in the selection of endianness
/// for gdb targets, defaults to [`Endianness::None`] to allow
/// for asserting that the user selects an endianness
#[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Endianness {
    BigEndian,
    LittleEndian,
    #[default]
    None,
}

/// Derive boilerplate impls for gdbstub
///
/// ## Attribute Args
/// - `gdb_arch_name` - the name of the target architecture as understood by `gdb`
/// - `gdb_feature_xml` - a list of `&[u8]` that each contain contents of xml, import the
///   default gdb xml set via `styx-util::gdb_xml::<name>`
/// - `register_map` - a [`BTreeMap`](std::collections::BTreeMap)`<usize, CpuRegister>` that maps the `gdb` known indecies
///   of the register to the `styx`-defined `CpuRegister` struct, most easily obtainable from
///   the respective `<Arch>Registers::Register` enum
/// - `pc_register` - the `styx` enum value that represents the pc register of the `gdb` target arch
/// - `endianness` - the `styx_cpu::ArchEndian` variant mapping to the target
///
///
/// **Warning** the `register_map` arg for invocation of this macro must be consistent with `gdb`
///
/// ## Example
///
/// ```ignore
/// extern crate styx_macros;
/// use gdbstub;
/// use std::collections::BTreeMap;
/// use std::marker::PhantomData;
/// use styx_core::macros::gdb_target_description;
/// use styx_core::util::gdb_xml::{ARM_M_PROFILE, ARM_CORE};
/// use styx_core::cpu::arch::backends::ArchRegister;
/// use styx_core::cpu::arch::arm::{ArmRegister, BasicArchRegister};
/// use styx_core::cpu::arch::CpuRegister;
/// use styx_core::sync::lazy_static;
///
/// lazy_static! {
///     // the indecies -> register *must* match the expected
///     // ordering as found in `data/gdb_xml/*.xml`, otherwise
///     // you will get very confusing gdb output
///     static ref ARM_M_PROFILE_REGISTER_MAP: BTreeMap<usize, CpuRegister> = BTreeMap::from([
///         (0, ArmRegister::Pc.register()),
///         // ...
///     ]);
/// }
///
/// #[gdbstub_target_description]
/// #[derive(Debug, Default)]
/// pub struct GdbDescription {
///     #[args(
///         gdb_arch_name("arm"),
///         gdb_feature_xml(ARM_M_PROFILE, ARM_CORE),
///         register_map(ARM_M_PROFILE_REGISTER_MAP),
///         pc_register(ArchRegister::Basic(BasicArchRegister::Arm(ArmRegister::Pc))),
///         endianness(ArchEndian::LittleEndian),
///     )]
///     args: PhantomData<()>,
/// }
/// ```
///
/// [BTreeMap]: std::collections::BTreeMap
#[proc_macro_attribute]
pub fn gdb_target_description(_args: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let (_, input_fields, _) = match input.data {
        syn::Data::Struct(syn::DataStruct {
            struct_token,
            fields,
            semi_token,
        }) => (struct_token, fields, semi_token),
        _ => panic!("macro expects a struct struct"),
    };
    let input_name = input.ident;
    let input_attrs = input.attrs;

    // Get GdbArchOptions from the macro attributes
    let (options, input_fields) = GdbArchOptions::parse_struct_fields(input_fields);

    //
    // Remap defined structs via the input name to avoid collisions
    //

    // The name of the trait that implements gdbstub::arch::Registers,
    let reg_impl_struct: Ident = format_ident!("{}RegistersImpl", input_name);
    let reg_impl_struct_mod = format_ident!("{}_registers_impl", input_name);
    let reg_id_struct_name = format_ident!("{}RegId", input_name);
    let pc_register_var_name = format_ident!("{}_PC_REGISTER", input_name);

    //
    // parse the input data
    //
    let arch_name_inner = options.gdb_arch_name;
    let gdb_arch_name = quote! { #arch_name_inner };
    let arch_meta_registers = quote! {crate::arch::backends::ArchRegister};
    let input_register_map = strts2!(options.input_register_map);
    // get the `styx`-known meta register value to use for `gdbstub`
    let pc_register: proc_macro2::TokenStream = options.pc_register.parse().unwrap();
    let pc_register_value = quote! { #pc_register };
    // create the tokens to emit a list of the provided tokens
    // that represent the target applicable `target.xml`
    let gdb_feature_xml = options
        .gdb_feature_xml
        .iter()
        .map(|x| strts2!(x))
        .collect::<Vec<proc_macro2::TokenStream>>();

    // choose which endianness to serialize registers with
    let endian_specific_serialize = match options.endianness {
        Endianness::BigEndian => {
            quote! {for b in &val.to_be_bytes() { write_byte(Some(*b)); }}
        }
        Endianness::LittleEndian => {
            quote! {for b in &val.to_le_bytes() { write_byte(Some(*b)); }}
        }
        _ => unreachable!("must have endianness selected"),
    };

    // choose which endianness to de-serialize registers with
    let endian_specific_deserialize = match options.endianness {
        Endianness::BigEndian => {
            quote! {Self::ProgramCounter::from_be_bytes(next.try_into().unwrap())}
        }
        Endianness::LittleEndian => {
            quote! {Self::ProgramCounter::from_le_bytes(next.try_into().unwrap())}
        }
        _ => unreachable!("must have endianness selected"),
    };

    // utilize pre-built breakpoint kinds if we are able, note that this
    // really doesn't impact much, just use things that ship with the
    // underlying gdbstub library.
    let target_breakpoint_kind: syn::Path = if arch_name_inner.to_uppercase().contains("ARM") {
        parse_quote! { gdbstub_arch::arm::ArmBreakpointKind }
    } else if arch_name_inner.to_uppercase().contains("MIPS") {
        parse_quote! { gdbstub_arch::mips::MipsBreakpointKind }
    } else {
        parse_quote! { usize }
    };

    // Output for macro
    proc_macro::TokenStream::from(quote! {
        #(#input_attrs)*
        pub struct #input_name
            #input_fields

        /// Implements [`RegId`](https://docs.rs/gdbstub/0.6.6/gdbstub/arch/trait.RegId.html)
        /// by wrapping `ArchRegister`
        /// and providing convenience methods to/from `gdbstub` types
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct #reg_id_struct_name(#arch_meta_registers);

        /// impl a support trait requiring many QoL
        impl crate::arch::GdbArchIdSupportTrait for #reg_id_struct_name {}

        /// Convert from `styx` to `gdbstub`
        impl From<#arch_meta_registers> for #reg_id_struct_name {
            fn from(value: #arch_meta_registers) -> Self {
                Self(value)
            }
        }

        /// Convert from `gdbstub` to `styx`
        impl From<#reg_id_struct_name> for #arch_meta_registers {
            fn from(value: #reg_id_struct_name) -> Self {
                value.0
            }
        }

        impl gdbstub::arch::RegId for #reg_id_struct_name {
            fn from_raw_id(id: usize) -> Option<(Self, Option<std::num::NonZeroUsize>)> {
                if let Some(ref register) = #input_register_map.get(&id) {
                    Some((
                        register.variant().into(),
                        Some(register.byte_size()),
                    ))
                } else {
                    None
                }
            }
        }

        /// Wrapper around buffer to hold target register values.
        ///
        /// Implemented as a [`BTreeMap`](std::collections::BTreeMap)
        /// for fast lookups and the ability to convert between `gdb` indicies,
        /// `gdb-rsp` indicies that match the `target.xml`, and the internal
        /// representation of registers a la `ArchRegister` .
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct #reg_impl_struct {
            reg_store: ::std::collections::BTreeMap<#arch_meta_registers, <Self as gdbstub::arch::Registers>::ProgramCounter>,
        }

        /// Populate the inner [`BTreeMap`] with the registers that are found
        /// in the input `register_map`, no other keys are ever inserted into
        /// this [`BTreeMap`].
        ///
        /// [BTreeMap]: std::collections::BTreeMap
        impl std::default::Default for #reg_impl_struct {
            fn default() -> Self {
                Self {
                    reg_store: ::std::collections::BTreeMap::from_iter(
                        #input_register_map
                            .iter()
                            .map(|(_, reg)| (reg.variant(), 0))
                            .collect::<Vec<(
                                #arch_meta_registers,
                                <Self as gdbstub::arch::Registers>::ProgramCounter,
                            )>>(),
                    ),
                }
            }
        }

        impl #reg_impl_struct {
            /// `styx`-known register that represents the current `PC`
            #[allow(non_upper_case_globals)]
            const #pc_register_var_name: #arch_meta_registers = #pc_register_value;
        }

        #[allow(non_snake_case)]
        mod #reg_impl_struct_mod {
            extern crate log;
            use super::*;
            impl crate::arch::GdbRegistersHelper for #reg_impl_struct {
                fn set_register_tank(&mut self, pairs: &[(crate::arch::CpuRegister, Self::ProgramCounter)]) {
                    for &(ref meta_reg, value) in pairs {
                        // if the entry of `key` exists, then set the `value` to `value`
                        self.reg_store.entry(meta_reg.variant()).and_modify(|inner_val| *inner_val = value);
                    }
                }

                fn register_tank(&self) -> Vec<(#arch_meta_registers, Self::ProgramCounter)> {
                    self.reg_store
                    .iter()
                    .map(|(&r, &v)| {
                        ::log::trace!("Getting register: `{}`, value: `0x{:x}`", r, v);
                        (r, v)
                    })
                    .collect()
                }

                /// Use the input `register_map` to convert between `gdb` and `styx`
                /// known registr representative enum values
                fn from_usize(reg: usize) -> Option<#arch_meta_registers> {
                    if let Some(register) = #input_register_map.get(&reg) {
                        Some(register.variant())
                    } else {
                        None
                    }
                }
            }

            /// Implementation of gdbstub's
            /// [Registers](https://docs.rs/gdbstub/0.6.6/gdbstub/arch/trait.Registers.html)
            /// trait.
            impl gdbstub::arch::Registers for #reg_impl_struct {
                type ProgramCounter = u32;

                fn pc(&self) -> Self::ProgramCounter {
                    self.reg_store[&Self::#pc_register_var_name]
                }

                /// Serialize the registers buffer
                fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
                    ::log::trace!("gdb_serialize");

                    // serialize the entire register store
                    for (_, reg) in #input_register_map.iter() {
                        let reg_variant = reg.variant();
                        let val = self.reg_store.get(&reg_variant).unwrap();
                        ::log::trace!("Serialize: {}, `0x{:x}`", reg.variant(), val);
                        #endian_specific_serialize
                    }
                }

                /// Deserialize each register value (gdb -> reg_tank -> emulator).
                fn gdb_deserialize(&mut self, mut bytes: &[u8]) -> Result<(), ()> {

                    let reg_sz = std::mem::size_of::<Self::ProgramCounter>();
                    ::log::trace!(
                        "gdb_deserialize &[{};u8], reg_count: {}",
                        bytes.len(),
                        bytes.len() / reg_sz
                    );

                    // create an iterator function (next_reg)
                    let mut next_reg = || {
                        if bytes.len() < 4 {
                            Err(())
                        } else {
                            let (next, rest) = bytes.split_at(reg_sz);
                            bytes = rest;
                            Ok(#endian_specific_deserialize)
                        }
                    };

                    // deserialize the entire register store
                    for (_, reg) in #input_register_map.iter() {
                        let val = self.reg_store.get_mut(&reg.variant()).unwrap();
                        ::log::trace!("De-serialize: {}, `0x{:x}`", reg.variant(), val);
                        *val = next_reg()?;
                    }


                    // make sure there is no extra data lying around
                    if next_reg().is_ok() {
                        return Err(());
                    }

                    Ok(())
                }
            }
        }

        impl crate::arch::GdbTargetDescription for #input_name {
            /// Getter for the `gdb`-known name for the specific target description
            fn gdb_arch_name(&self) -> String {
                String::from(#gdb_arch_name)
            }

            /// Getter for the `gdb`-consumable target xml list.
            ///
            /// This method is consumed by other helper traits to ease the
            /// creation of the gdb target descriptions.
            fn feature_xml_impl(&self) -> Vec<String> {
                let x: Vec<&[u8]> = vec![#(#gdb_feature_xml)*];
                x.iter().map(|s| String::from_utf8(s.to_vec()).unwrap()).collect::<Vec<String>>()
            }
        }


        /// Implementation of
        /// [gdbstub - Arch](https://docs.rs/gdbstub/0.6.6/gdbstub/arch/trait.Arch.html)
        impl gdbstub::arch::Arch for #input_name {
            type Usize = u32;
            type Registers = #reg_impl_struct;
            type RegId = #reg_id_struct_name;
            type BreakpointKind = #target_breakpoint_kind;
        }

    })
}

#[derive(Debug, Clone, Default)]
/// A data structure for storing parsed attribute args for
/// [`gdb_target_description`](macro@gdb_target_description)
struct GdbArchOptions {
    gdb_arch_name: String,
    /// Enum variant of register under `ArchRegister`
    pc_register: String,
    endianness: Endianness,
    input_register_map: String,
    gdb_feature_xml: Vec<String>,
}

/// Methods for parsing attribute args for
/// [`gdb_target_description`](macro@gdb_target_description)
impl GdbArchOptions {
    /// Asserts that all fields are non-zero and populated in a matter
    /// that could actually yield useful results
    fn valid(&self) -> bool {
        assert!(
            self.endianness != Endianness::None,
            "endianness must be set"
        );
        assert!(
            !self.input_register_map.is_empty(),
            "register_map must be set"
        );
        assert!(!self.pc_register.is_empty(), "pc_register must be set");
        assert!(!self.gdb_arch_name.is_empty(), "gdb_arch_name must be set");

        true
    }

    /// parse attribute args for [`gdb_target_description`](macro@gdb_target_description)
    fn parse_attr_args(a: &syn::Attribute) -> Self {
        let mut opts = Self::default();

        // pull out the defined attributes that are passed to
        // the macro
        let args_list = a
            .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            .unwrap();

        for meta in args_list {
            match meta {
                // This is meant to parse something of the form:
                // `register_map(TYPE_NAME_OF_REGISTER_MAP)`, where the `TYPE_NAME`
                // is an ident / expression that points to the desired input map.
                Meta::List(meta) if meta.path.is_ident(ATTR_REGISTER_MAP_NAME) => {
                    let nested = meta
                        .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                        .unwrap();
                    // we should only have one input to this arg, so blindly
                    // take the first input
                    if let Some(input_arg) = nested.into_iter().next() {
                        opts.input_register_map = input_arg
                            .path()
                            .to_token_stream()
                            .to_string()
                            .replace(' ', "");
                    } else {
                        panic!(
                            "Missing {} arg content of `gdb_target_description`",
                            ATTR_REGISTER_MAP_NAME,
                        );
                    }
                }
                // This is meant to parse something of the form:
                // `endianness(ArchEndian::BigEndian)`
                // where the input is a member of the `ArchEndian` enum
                Meta::List(meta) if meta.path.is_ident(ATTR_ENDIANNESS_NAME) => {
                    let nested = meta
                        .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                        .unwrap_or_else(|_| panic!("endianness name"));
                    // we should only have one input to this arg, so blindly
                    // take the first input
                    if let Some(input_arg) = nested.into_iter().next() {
                        let endianness = input_arg
                            .path()
                            .to_token_stream()
                            .to_string()
                            .replace(' ', "")
                            .to_lowercase();

                        if endianness.contains("little") {
                            opts.endianness = Endianness::LittleEndian;
                        } else if endianness.contains("big") {
                            opts.endianness = Endianness::BigEndian;
                        } else {
                            panic!("endianness must be one of `ArchEndian` variants");
                        }
                    } else {
                        panic!(
                            "Missing {} arg content of `gdb_target_description`",
                            ATTR_ENDIANNESS_NAME,
                        );
                    }
                }

                // This is meant to parse something of the form
                // `gdb_arch_name("powerpc:MPC8XX")`,
                // where the provided argument is a string literal that
                // gdb clients recognize
                // TODO: validate that the provided arch name is actually something
                // that gdb client understand
                Meta::List(meta) if meta.path.is_ident(ATTR_GDB_ARCH_NAME) => {
                    let nested: LitStr = meta
                        .parse_args()
                        .unwrap_or_else(|_| panic!("gdb arch name"));

                    opts.gdb_arch_name = nested.value();
                }

                // This is meant to parse something of the form
                // `gdb_feature_xml(GDB_FEATURE_1, GDB_FEATURE_2)`
                // where each gdb feature is sourced from `styx-util::gdb_xml`
                // and has the type `&[u8]`.
                Meta::List(meta) if meta.path.is_ident(ATTR_GDB_FEATURE_XML_NAME) => {
                    let nested = meta
                        .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                        .unwrap_or_else(|_| panic!("gdb feature xml"));
                    let mut features = Vec::new();

                    // add all the attached features
                    for meta in nested {
                        features.push(meta.path().to_token_stream().to_string().replace(' ', ""));
                    }

                    assert!(!features.is_empty(), "Must have at least 1 gdb_feature_xml");
                    opts.gdb_feature_xml = features;
                }

                // This is meant to parse something of the form:
                // `pc_register(ArchRegister::Ppc32(Ppc32Register::Pc))`
                // unfortunately the input register must be the entire
                // `ArchRegister`
                Meta::List(meta) if meta.path.is_ident(ATTR_PC_REGISTER_NAME) => {
                    let nested = meta
                        .parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
                        .unwrap_or_else(|_| panic!("pc register name"));
                    // we should only have one input to this arg, so blindly
                    // take the input
                    opts.pc_register = nested.into_token_stream().to_string();
                }

                // This arg does not belong here
                _ => {
                    eprintln!("Something else: {}", meta.to_token_stream());
                }
            };
        }

        // ensures that each attribute has a user set value
        assert!(opts.valid());
        opts
    }

    /// parse struct fields for [`gdb_target_description`](macro@gdb_target_description)
    fn parse_struct_fields(fields: Fields) -> (GdbArchOptions, Fields) {
        let mut opts: Option<GdbArchOptions> = None;
        let mut mod_fields = fields;

        if let syn::Fields::Named(fields) = &mut mod_fields {
            fields.named.iter_mut().for_each(|nf| {
                if nf.ident.clone().unwrap().to_string().eq(ANCHOR_FIELD) {
                    for a in nf.attrs.iter() {
                        if a.path().is_ident(ARGS_ATTR_NAME) {
                            opts = Some(Self::parse_attr_args(a));
                        }
                    }
                }
            });
        }

        if let syn::Fields::Named(fields) = &mut mod_fields {
            let dead_code_attr: Attribute = parse_quote! { #[allow(dead_code)] };
            // Remove attributes, then add a dead code pass
            for f in fields.named.iter_mut() {
                f.attrs.clear();
                f.attrs.push(dead_code_attr.to_owned());
            }
        }

        (opts.unwrap(), mod_fields)
    }
}

/// Generates a with method based on a set/add method
///
/// # Example
/// ```rust
/// struct MyBuilder(i32, i32);
///
/// impl MyBuilder {
///     #[styx_macros::build_with]
///     fn set_x(&mut self, value: i32) {
///         self.0 = value;
///     }
///
///     #[styx_macros::build_with]
///     fn set_y(&mut self, value: i32) {
///         self.1 = value;
///     }
/// }
///
/// let mut builder = MyBuilder(0, 0);
/// builder.set_x(3);
/// builder.set_y(5);
///
/// builder.with_x(3).with_y(5);
/// ```
#[proc_macro_attribute]
pub fn build_with(attr: TokenStream, item: TokenStream) -> TokenStream {
    build_with::build_with(attr.into(), item.into())
        .unwrap_or_else(|e| e.into_compile_error())
        .into()
}

/// A macro for "mirroring" an enum in another package.
///
/// # Example
/// ```rust
/// mod parent {
///     mod source {
///         pub(super) enum Color {
///             Red,
///             Green,
///             Blue
///         }
///     }
///
///     mod downstream {
///         // this version doesn't have color support yet, so we get a compile error
///         #[styx_macros::enum_mirror(super::source::Color)]
///         enum Color {
///             Red,
///             Green,
///             Blue
///         }
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn enum_mirror(attr: TokenStream, item: TokenStream) -> TokenStream {
    enum_mirror::enum_mirror(attr.into(), item.into())
        .unwrap_or_else(|e| e.into_compile_error())
        .into()
}
