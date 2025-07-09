// SPDX-License-Identifier: BSD-2-Clause
//! proc macros
//!
//! `TyphunixPyo3` derives `__str__` and `__repr__` implementations for
//! typhunix python bindings.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(TyphunixPyo3)]
pub fn derive_pyo3(item: TokenStream) -> TokenStream {
    let name = parse_macro_input!(item as DeriveInput).ident;
    quote! {
        #[cfg(feature = "pyo3_bindings")]
        #[pyo3::pymethods]
        impl #name {
            fn __repr__(&self) -> String {
                format!("{:?}", &self)
            }

            fn __str__(&self) -> String {
                format!("{:?}", &self)
            }

        }
    }
    .into()
}
