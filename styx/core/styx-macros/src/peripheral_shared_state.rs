// SPDX-License-Identifier: BSD-2-Clause
// Assisted-by: Claude Code:claude-opus-4-8[1m]
//! Implementation of the [`peripheral_shared_state`](macro@crate::peripheral_shared_state)
//! attribute macro.
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Error, Field, Fields, Result};

/// Extract the `#[shared]`-marked fields of a struct into a generated state struct.
///
/// Given a struct `Foo`, this:
/// - collects every field marked `#[shared]` into a new `FooState` struct,
/// - removes those fields from `Foo` and replaces them with a single
///   `inner: Arc<Mutex<FooState>>` field — the unmarked fields stay on `Foo`
///   untouched,
/// - generates a getter and `set_*` setter on `Foo` for each shared field,
///   each locking `inner` and delegating through the guard.
///
/// For example:
///
/// ```ignore
/// #[peripheral_shared_state]
/// pub struct Uart {
///     #[shared]
///     pub baud: u32,
///     pub id: u32,
///     #[shared]
///     pub status: u32,
/// }
/// ```
///
/// becomes (roughly):
///
/// ```ignore
/// pub struct Uart {
///     pub id: u32,                                    // unmarked field kept in place
///     inner: ::std::sync::Arc<::std::sync::Mutex<UartState>>, // shared fields moved here
/// }
///
/// pub struct UartState {
///     pub baud: u32,
///     pub status: u32,
/// }
///
/// impl Uart {
///     pub fn baud(&self) -> u32 { self.inner.lock().unwrap().baud.clone() }
///     pub fn set_baud(&self, value: u32) { self.inner.lock().unwrap().baud = value; }
///     pub fn status(&self) -> u32 { self.inner.lock().unwrap().status.clone() }
///     pub fn set_status(&self, value: u32) { self.inner.lock().unwrap().status = value; }
/// }
/// ```
///
/// The `#[shared]` markers are consumed by the macro and never appear in the
/// emitted code. Getters return a clone of the field (so the field type must be
/// [`Clone`]); accessor visibility mirrors the field's own visibility. Because
/// the shared state lives behind an [`Arc`](std::sync::Arc)`<`[`Mutex`](std::sync::Mutex)`<_>>`,
/// the setters take `&self`.
pub(crate) fn peripheral_shared_state(
    _attr: TokenStream,
    item: TokenStream,
) -> Result<TokenStream> {
    let input: DeriveInput = syn::parse2(item)?;

    // Only named-field structs are supported: we need field identifiers to
    // generate accessors and to build the state struct.
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return Err(Error::new_spanned(
                    &input,
                    "`peripheral_shared_state` requires a struct with named fields",
                ))
            }
        },
        _ => {
            return Err(Error::new_spanned(
                &input,
                "`peripheral_shared_state` can only be applied to structs",
            ))
        }
    };

    let name = &input.ident;
    let vis = &input.vis;
    // The struct keeps its own attributes (derives, docs, etc.); only its
    // `#[shared]` fields are relocated.
    let attrs = &input.attrs;
    let state_name = format_ident!("{}SharedState", name);
    // Forward generics onto both the wrapper and the state struct.
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    // Partition the fields by the `#[shared]` marker. Shared fields move into
    // the state struct; the rest stay on the original struct beside `inner`.
    // The `#[shared]` marker is internal to this macro and is stripped from
    // every emitted field so the compiler never sees an unknown attribute.
    let mut shared_fields: Vec<Field> = Vec::new();
    let mut kept_fields: Vec<Field> = Vec::new();
    for field in fields {
        let mut field = field.clone();
        let is_shared = field.attrs.iter().any(|a| a.path().is_ident("shared"));
        field.attrs.retain(|a| !a.path().is_ident("shared"));
        if is_shared {
            shared_fields.push(field);
        } else {
            kept_fields.push(field);
        }
    }

    // A getter and setter on the wrapper for each shared field, each inheriting
    // the field's own visibility and delegating through `inner`.
    /*let accessors = shared_fields.iter().map(|field| {
        let field_name = field.ident.as_ref().expect("named field has an ident");
        let field_vis = &field.vis;
        let field_ty = &field.ty;
        let setter_name = format_ident!("set_{}", field_name);

        let getter_doc = format!("Returns a clone of the shared `{field_name}` field.");
        let setter_doc = format!("Sets the shared `{field_name}` field.");

        quote! {
            #[doc = #getter_doc]
            #field_vis fn #field_name(&self) -> #field_ty {
                self.inner.lock().unwrap().#field_name.clone()
            }

            #[doc = #setter_doc]
            #field_vis fn #setter_name(&self, value: #field_ty) {
                self.inner.lock().unwrap().#field_name = value;
            }
        }
    });*/

    let state_doc = format!("Shared state extracted from [`{name}`].");

    Ok(quote! {
        #(#attrs)*
        #vis struct #name #ty_generics #where_clause {
            #(#kept_fields,)*
            inner: ::std::sync::Arc<::std::sync::Mutex<#state_name #ty_generics>>,
        }

        #[doc = #state_doc]
        #vis struct #state_name #ty_generics #where_clause {
            #(#shared_fields,)*
        }

        impl #impl_generics #name #ty_generics #where_clause {
            fn lock(&self) -> ::std::sync::MutexGuard<'_, #state_name> {
                self.inner.lock().expect("Couldn't get inner peripheral state")
            }
        }
    })
}
