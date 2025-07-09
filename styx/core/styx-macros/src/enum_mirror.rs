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
use proc_macro2::{Span, TokenStream};
use syn::{parse::Parse, Error, ItemEnum, LitStr, Token, Type};

pub(crate) fn enum_mirror(attr: TokenStream, item: TokenStream) -> Result<TokenStream, Error> {
    let item: ItemEnum = syn::parse2(item)?;
    let args: EnumArgs = syn::parse2(attr)?;

    let mut ignored_variants = Vec::new();
    let mut new_item = item.clone();
    let mut filtered_variant_args = Vec::new();
    let mut ignored_variant_args = Vec::new();
    for pair in std::mem::take(&mut new_item.variants).into_pairs() {
        let (variant, punct) = pair.into_tuple();
        let variant_args: VariantOptions = variant
            .attrs
            .iter()
            .find(|attr| attr.path().is_ident("enum_mirror"))
            .map(|attr| attr.parse_args())
            .transpose()?
            .unwrap_or_else(Default::default);

        if variant_args.ignore.is_some() {
            ignored_variants.push(variant);
            ignored_variant_args.push(variant_args);
            continue;
        }

        new_item.variants.push_value(variant);
        if let Some(punct) = punct {
            new_item.variants.push_punct(punct);
        }
        filtered_variant_args.push(variant_args);
    }

    let enum_name = &item.ident;
    let parent_type = &args.parent;

    let from_impl = {
        let match_arms = new_item.variants.iter().map(|variant| {
            let variant_name = &variant.ident;
            quote::quote! {
                #parent_type::#variant_name => Self::#variant_name
            }
        });

        let ignored_match_arms = ignored_variants.iter().enumerate().map(|(i, variant)| {
            let variant_name = &variant.ident;
            let variant_args = &ignored_variant_args[i];
            let error_msg = LitStr::new(
                &format!("the variant '{variant_name}' is ignored and cannot be converted"),
                variant_name.span(),
            );

            let match_extra = match variant_args.style.as_ref() {
                Some((_, VariantStyle::Struct)) => quote::quote!({ .. }),
                Some((_, VariantStyle::Tuple)) => quote::quote!((..)),
                _ => quote::quote!(),
            };
            quote::quote! {
                #parent_type::#variant_name #match_extra => unimplemented!(#error_msg)
            }
        });

        ::quote::quote! {
            impl From<#parent_type> for #enum_name {
                fn from(v: #parent_type) -> Self {
                    match v {
                        #(#match_arms,)*
                        #(#ignored_match_arms,)*
                        // this will compile-error if there are more variants
                    }
                }
            }
        }
    };

    let into_impl = {
        let match_arms = new_item.variants.iter().map(|variant| {
            let variant_name = &variant.ident;
            quote::quote! {
                #enum_name::#variant_name => Self::#variant_name
            }
        });

        ::quote::quote! {
            impl From<#enum_name> for #parent_type {
                fn from(v: #enum_name) -> Self {
                    match v {
                        #(#match_arms,)*
                    }
                }
            }
        }
    };

    Ok(quote::quote! {
        #new_item

        #from_impl
        #into_impl
    })
}

#[derive(Default)]
struct VariantOptions {
    ignore: Option<kw::ignore>,
    style: Option<(kw::style, VariantStyle)>,
}

enum VariantOption {
    Ignore(kw::ignore),
    Style(kw::style, VariantStyle),
}

impl Parse for VariantOption {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        if let Ok(kw) = input.parse::<kw::ignore>() {
            Ok(Self::Ignore(kw))
        } else if let Ok(kw) = input.parse::<kw::style>() {
            input.parse::<Token![=]>()?;
            let item = input.parse()?;
            Ok(Self::Style(kw, item))
        } else {
            Err(Error::new(
                input.span(),
                "invalid variant option, expected 'ignore', or 'style'",
            ))
        }
    }
}

macro_rules! set_option {
    ($out:ident.$field:ident = $val:expr) => {{
        if $out.$field.is_some() {
            return Err(Error::new(
                Span::call_site(),
                concat!("option ", stringify!($field), " already set"),
            ));
        }
        $out.$field = Some($val);
    }};
}

impl Parse for VariantOptions {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let items: syn::punctuated::Punctuated<VariantOption, syn::token::Comma> =
            input.parse_terminated(VariantOption::parse, Token![,])?;

        let mut out = Self::default();
        for item in items.into_iter() {
            match item {
                VariantOption::Ignore(kw) => set_option!(out.ignore = kw),
                VariantOption::Style(kw, style) => set_option!(out.style = (kw, style)),
            }
        }

        if let Some((kw, _)) = out.style.as_ref().filter(|_| out.ignore.is_none()) {
            return Err(Error::new(
                kw.span,
                "'style' cannot be set without 'ignore'",
            ));
        }

        Ok(out)
    }
}

enum VariantStyle {
    Struct,
    Tuple,
    Unit,
}

impl Parse for VariantStyle {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        if input.parse::<Token![struct]>().is_ok() {
            Ok(Self::Struct)
        } else if input.parse::<kw::tuple>().is_ok() {
            Ok(Self::Tuple)
        } else if input.parse::<kw::unit>().is_ok() {
            Ok(Self::Unit)
        } else {
            Err(Error::new(
                input.span(),
                "VariantStyle: expected 'struct', 'tuple', or 'unit'",
            ))
        }
    }
}

struct EnumArgs {
    parent: Type,
}

impl Parse for EnumArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let parent = input.parse()?;
        Ok(Self { parent })
    }
}

mod kw {
    syn::custom_keyword!(ignore);
    syn::custom_keyword!(style);
    syn::custom_keyword!(tuple);
    syn::custom_keyword!(unit);
}
