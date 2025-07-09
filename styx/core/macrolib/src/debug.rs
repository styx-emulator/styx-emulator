// SPDX-License-Identifier: BSD-2-Clause
use crate::{parse_single_path, path_to_string};
use quote::{quote, ToTokens};
use styx_sync::{
    lazy_static,
    sync::atomic::{AtomicBool, Ordering},
};

lazy_static! {
    static ref DEBUG: AtomicBool = AtomicBool::new(false);
}

pub fn is_dbg() -> bool {
    DEBUG.load(Ordering::Acquire)
}

pub fn set_dbg(val: bool) {
    DEBUG.store(val, Ordering::Release)
}

pub struct PrintDebug {}

impl PrintDebug {
    /// Wrap all lines so that they are prefixed with "DEBUG: "
    pub fn debugify(item: &str) {
        if is_dbg() {
            let fmted = item.replace('\n', "\nDEBUG: ");
            eprintln!("DEBUG: {fmted}")
        }
    }

    /// Return a string version of the [syn::Field]
    /// Include the attributes, type, and field name
    pub fn field_to_string(field: &syn::Field) -> String {
        let name = if let Some(ref name) = field.ident {
            name.to_string()
        } else {
            "<None>".to_string()
        };
        let path = path_to_string(&parse_single_path(field.ty.to_token_stream()));
        let attr_str = field
            .attrs
            .iter()
            .map(|a| a.to_token_stream().to_string())
            .collect::<Vec<String>>()
            .join("\n");

        format!("{attr_str}\n    {name}: {path}")
    }

    /// print n black lines
    pub fn debugify_blanks(n: usize) {
        if is_dbg() {
            for _ in 0..n {
                eprintln!();
            }
        }
    }

    /// print a distinguising separator for _print debugging_
    pub fn debugify_separator() {
        if is_dbg() {
            let mut dline = String::from("DEBUG: ");
            for _ in 1..80 {
                dline.push('-');
            }
            eprintln!("{dline}");
        }
    }

    /// display the struct fields
    pub fn debug_struct_fields(fields: syn::Fields) {
        if is_dbg() {
            let named = if let syn::Fields::Named(fields) = &fields {
                fields.named.iter().cloned().collect::<Vec<syn::Field>>()
            } else {
                vec![]
            };
            let unnamed = if let syn::Fields::Unnamed(fields) = &fields {
                fields.unnamed.iter().cloned().collect::<Vec<syn::Field>>()
            } else {
                vec![]
            };

            PrintDebug::debugify(&format!(
                "Fields: Named={}, Unnamed={}",
                named.len(),
                unnamed.len()
            ));

            for named_field in named.iter() {
                let type_path = parse_single_path(named_field.ty.to_token_stream());
                if let Some(fident) = &named_field.ident {
                    let name = fident.to_string();
                    let f = format!("    {}: {}", name, path_to_string(&type_path));
                    PrintDebug::debugify(&f);
                }
            }
        }
    }

    /// display the item
    pub fn debug_item(item: syn::DeriveInput) {
        if is_dbg() {
            let orig_item = item.clone();
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
                    PrintDebug::debug_struct_fields(fields.clone());

                    let s = quote! {
                        #(#attrs)*
                        #vis #struct_token #ident
                            #fields
                        #semi_token
                    };
                    PrintDebug::debugify(&s.to_string());
                }

                syn::Data::Enum(syn::DataEnum {
                    enum_token,
                    brace_token: _,
                    variants,
                }) => {
                    let s = quote! {
                            #(#attrs)*
                            #vis #enum_token #ident {
                                #variants
                            }
                    };
                    PrintDebug::debugify(&s.to_string());
                }

                _ => {
                    let _ = orig_item;
                }
            }
        }
    }
}
