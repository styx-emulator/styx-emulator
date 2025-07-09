// SPDX-License-Identifier: BSD-2-Clause
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
