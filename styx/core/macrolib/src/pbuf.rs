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
use crate::debug::PrintDebug;
use crate::named_field_ex::ArgType;
use crate::{parse_single_path, path_to_string};
use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::parse::Parser;

pub const PROST_OPTION_STR: &str = "::core::option::Option<";

/// Helper implementation for deriving clap constructs from tonic-generated
/// protobuf messages and enumerations
pub struct ClapPbHelper {}
impl ClapPbHelper {
    /// determines if the given type used as a rust type for the proto compiler
    pub fn clap_pb_is_rust_type(emitted_type: &str) -> bool {
        match emitted_type {
            // prost types emitted by tonic
            "::prost::alloc::string::String"
            // native rust types (that tonic emits)
            | "f64" | "i64" | "u64" | "f32" | "i32" | "u32" | "u8" | "bool"
            // HashMap is emitted, but not supported by clap
            | "HashMap" => true,
            _ => false,
        }
    }

    /// these types are valid but not supported by clap
    pub fn clap_pb_unsupported_type(emitted_type: &str) -> bool {
        matches!(emitted_type, "HashMap")
    }

    /// determine what sort of arg we have
    pub fn clap_pb_arg_type(p: &syn::Path) -> ArgType {
        if let Some(ty) = ClapPbHelper::clap_pb_get_rust_type(p) {
            let unsupported_rust_type = ClapPbHelper::clap_pb_unsupported_type(&ty);
            let is_proto_rust_type = ClapPbHelper::clap_pb_is_rust_type(&ty);
            let is_composite = !is_proto_rust_type;
            if unsupported_rust_type {
                ArgType::Unsupported(ty)
            } else if is_composite {
                ArgType::Composite(ty)
            } else {
                ArgType::Arg(ty)
            }
        } else {
            ArgType::Unhandled(path_to_string(p))
        }
    }

    /// determine the base rust type
    /// Returning None here implies a parse error,
    ///   ie: the type is not something considered at time of writing this.
    // Dev note: this is a very hacky way to parse this, but syn::Path and
    // segments are way more involved than the subset we are trying to support,
    // which is ONLY those types being emitted by a protobuf compiler
    pub fn clap_pb_get_rust_type(path: &syn::Path) -> Option<String> {
        let p = path_to_string(path);

        if path.segments.len() == 1 || Self::clap_pb_is_rust_type(&p) {
            return Some(p);
        }

        let rust_ty = {
            if p.starts_with(PROST_OPTION_STR) {
                let options_vec = p.split('<').collect::<Vec<&str>>();
                if options_vec.len() == 2 {
                    Some(options_vec[1].split('>').collect::<Vec<&str>>()[0].to_string())
                } else if options_vec.len() == 3 && options_vec[1] == "::prost::alloc::vec::Vec" {
                    Some(options_vec[2].split('>').collect::<Vec<&str>>()[0].to_string())
                } else {
                    None
                }
            } else if p.starts_with("::prost::alloc::vec::Vec<") {
                let options_vec = p.split('<').collect::<Vec<&str>>();
                if options_vec.len() == 2 {
                    Some(options_vec[1].split('>').collect::<Vec<&str>>()[0].to_string())
                } else {
                    None
                }
            } else if p.starts_with("::std::collections::HashMap<") {
                Some("HashMap".to_string())
            } else {
                None
            }
        };
        rust_ty
    }

    /// these are all NamedFields
    pub fn fq_option_to_just_option(fields: syn::Fields) -> Vec<syn::Field> {
        fields
            .iter()
            .map(|in_field| {
                let in_field = in_field.clone();
                let syn_path = parse_single_path(in_field.ty.to_token_stream());
                let tpath = path_to_string(&syn_path);
                PrintDebug::debugify(&format!("tpath: {tpath}"));
                if tpath.starts_with(PROST_OPTION_STR) {
                    let field_name = in_field.ident;
                    let attrs = in_field.attrs;
                    let vis = in_field.vis;
                    let base_type_ident = format_ident!(
                        "{}",
                        Self::clap_pb_get_rust_type(&syn_path).unwrap_or_else(|| {
                            panic!("Can't determine field type");
                        })
                    );

                    let nfts = quote! {
                        #(#attrs)*
                        #vis #field_name : Option<#base_type_ident>
                    };
                    match syn::Field::parse_named.parse2(nfts.clone()) {
                        Ok(new_field) => {
                            PrintDebug::debugify(&format!(
                                "\nWriting new field:\n    =>{:?}\n---",
                                nfts.to_string()
                            ));
                            new_field
                        }
                        _ => {
                            panic!("Could not re-write the field");
                        }
                    }
                } else {
                    in_field
                }
            })
            .collect()
    }

    /// clap can handle `Option<T>` but seems to have issues when fully
    /// qualified, such as `core::option::Option<T>`. Tonic, perhaps
    /// rightly so, generated `::core::option::Option<T>`. This
    /// code re-writes the fully qualified type to just `Option<T>`
    /// # panics
    /// - if it sees a Union
    pub fn fix_tonic_clap(item: syn::DeriveInput) -> TokenStream {
        let data = item.data.clone();
        let attrs = item.attrs.clone();
        let vis = item.vis;
        let ident = item.ident;
        PrintDebug::debugify_separator();
        match data {
            syn::Data::Struct(syn::DataStruct {
                struct_token,
                fields,
                semi_token,
            }) => {
                let new_fields = Self::fq_option_to_just_option(fields);
                quote! {
                    #(#attrs)*
                    #vis #struct_token #ident {
                        #(#new_fields),*
                    }
                    #semi_token
                }
            }

            // enums OK
            syn::Data::Enum(syn::DataEnum {
                enum_token,
                brace_token: _,
                variants,
            }) => quote! {
                    #(#attrs)*
                    #vis #enum_token #ident {
                        #variants
                    }
            },

            // no unions
            syn::Data::Union(syn::DataUnion {
                union_token: _,
                fields: _,
            }) => {
                panic!("Didn't expect a Union")
            }
        }
    }
}
