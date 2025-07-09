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
use proc_macro2::TokenStream;
use quote::quote;
use syn::{Error, Ident, ImplItemFn, Pat, PatType, Receiver, Result, Type, TypeReference};

pub(crate) fn build_with(_attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    let item: ImplItemFn = syn::parse2(item)?;

    let set_name = &item.sig.ident;
    let set_name_str = set_name.to_string();
    let Some(set_name_str) = strip_prefix(set_name_str.as_str()) else {
        return Err(Error::new(
            set_name.span(),
            "expected function to be named 'set_...' or 'add_...'",
        ));
    };

    let mut out = item.clone();
    out.sig.ident = Ident::new(&format!("with_{set_name_str}"), out.sig.ident.span());

    if out.sig.inputs.len() != 2 {
        return Err(Error::new_spanned(
            out.sig.inputs,
            "function must have signature (&mut self, arg: Ty)",
        ));
    }

    match out.sig.inputs.first_mut().unwrap() {
        syn::FnArg::Receiver(Receiver {
            reference: reference @ Some(_),
            mutability: Some(_),
            colon_token: None,
            ty,
            ..
        }) => {
            *reference = None;
            *ty = match &**ty {
                Type::Reference(TypeReference { elem, .. }) => elem.clone(),
                _ => unreachable!(),
            };
        }
        item => {
            return Err(Error::new_spanned(
                item,
                "function must have signature (&mut self, arg: Ty)",
            ))
        }
    };

    match out.sig.inputs.get_mut(1).unwrap() {
        syn::FnArg::Typed(PatType { pat, .. }) => {
            **pat = Pat::Path(syn::parse2(quote! { value }).unwrap());
        }
        _ => unreachable!(),
    }

    out.sig.output = syn::parse2(quote! { -> Self }).unwrap();

    out.block = syn::parse2(quote! {{
        self.#set_name(value);
        self
    }})
    .unwrap();

    Ok(quote! {
        #item
        #out
    })
}

fn strip_prefix(source: &str) -> Option<&str> {
    if let Some(stripped) = source.strip_prefix("set_") {
        return Some(stripped);
    }
    if let Some(stripped) = source.strip_prefix("add_") {
        return Some(stripped);
    }
    None
}
