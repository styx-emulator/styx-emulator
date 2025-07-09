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
use crate::path_to_string;
use proc_macro2::TokenStream;
use quote::{format_ident, quote, ToTokens};
use syn::punctuated::Punctuated;
use syn::Token;

use crate::parse_single_path;

#[allow(dead_code)]
pub struct NamedFieldEx {
    pub name: String,
    pub field: syn::Field,
    pub arg_type: ArgType,
    pub prost_enum_ref: Option<String>,
    pub ftype: syn::Path,
}

impl NamedFieldEx {
    pub fn new(field: syn::Field, arg_type: ArgType) -> Self {
        let ftype = parse_single_path(field.ty.clone().to_token_stream());
        // let type_path = parse_single_path(named_field.ty.to_token_stream());
        let mut prost_enum_ref: Option<String> = None;
        let name = field.clone().ident.unwrap();
        for a in field.attrs.iter() {
            if let Some(e) = Self::get_prost_enum(a) {
                prost_enum_ref = Some(e.to_string());
            }
        }
        Self {
            name: name.to_string(),
            field,
            arg_type,
            prost_enum_ref,
            ftype,
        }
    }

    pub fn type_as_string(&self) -> String {
        path_to_string(&self.ftype)
            .replace("::core::option::Option", "Option")
            .replace("::prost::alloc::vec::Vec", "Vec")
            .replace("::prost::alloc::string::String", "String")
    }

    pub fn get_prost_enum(a: &syn::Attribute) -> Option<String> {
        let mut enum_of: Option<String> = None;
        if a.path().is_ident("prost") {
            let nested = a
                .parse_args_with(Punctuated::<syn::Meta, Token![,]>::parse_terminated)
                .unwrap();

            for meta in nested {
                if let syn::Meta::NameValue(syn::MetaNameValue {
                    path,
                    eq_token: _,
                    value,
                }) = meta
                {
                    if path.is_ident("enumeration") {
                        if let syn::Expr::Lit(v) = value {
                            let v = v.to_token_stream().to_string().replace('"', "");
                            enum_of = Some(v);
                        }
                    }
                }
            }
        }

        enum_of
    }

    /// generate getter methods for all fields by prepending `get_` to the
    /// field name.
    /// - If the field type is `prost::alloc::string::String`, treat
    ///   it as a rust String.
    /// - If the field type is a prost enumeration, use the prost generated
    ///   method to return the enumeration vs the i32 value
    pub fn getters(&self) -> Option<TokenStream> {
        if let Some(per) = &self.prost_enum_ref {
            // for prost enumerations, return the Enum definition vs the i32
            // psost takes care of the function definition
            let return_type_ident: proc_macro2::TokenStream = per.parse().unwrap();
            let function_name = format_ident!("get_{}", self.name);
            let field_name_ident = format_ident!("{}", self.name);
            Some(quote!(
                pub fn #function_name(&self) -> #return_type_ident {
                    self. #field_name_ident ()
                }
            ))
        } else if let ArgType::Arg(s) = &self.arg_type {
            // use 'String' for 'prost::alloc::string::String'
            let return_type = if s.eq("::prost::alloc::string::String") {
                "String".to_string()
            } else {
                s.to_string()
            };

            let function_name = format_ident!("get_{}", self.name);
            let return_type_ident = format_ident!("{}", return_type);
            let field_name_ident = format_ident!("{}", self.name);

            Some(quote!(
                pub fn #function_name(&self) -> #return_type_ident {
                    self. #field_name_ident.clone()
                }
            ))
        } else if let ArgType::Composite(_) = &self.arg_type {
            let function_name = format_ident!("get_{}", self.name);
            let return_type_ident = self.field.ty.clone();
            let field_name_ident = format_ident!("{}", self.name);
            Some(quote!(
                pub fn #function_name(&self) -> #return_type_ident {
                    self. #field_name_ident .clone()
                }
            ))
        } else {
            None
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ArgType {
    Arg(String),
    Composite(String),
    Unhandled(String),
    Unsupported(String),
}
