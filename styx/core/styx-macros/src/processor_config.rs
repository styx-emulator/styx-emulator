// SPDX-License-Identifier: BSD-2-Clause
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::DeriveInput;

pub fn derive_processor_config(input: TokenStream) -> TokenStream {
    let input: DeriveInput =
        syn::parse2(input).expect("ProcessorConfig can only be applied to structs");
    let name = &input.ident;

    let mut trait_path = crate::styx_manifest::StyxManifest::shared(|m| m.get_processor_path());
    trait_path.segments.push(format_ident!("processor").into());
    trait_path.segments.push(format_ident!("config").into());
    trait_path
        .segments
        .push(format_ident!("ProcessorConfig").into());

    quote! {
        impl #trait_path for #name {}
    }
}
