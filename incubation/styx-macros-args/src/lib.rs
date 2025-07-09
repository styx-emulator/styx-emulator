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
//! styx procedural macro definitions for deriving args from tonic proto messages
//!
//! Derive clap args for structs and enums, if they are _clappable_. The item is
//!_clappable_ if it does not contain a map, which [clap] does not support.
//!
//! The macro is doing the following:
//!
//! - For proto messages, adds `#[derive(clap::Args)]`
//! - For proto message fields, adds `#[arg(long)]` for simple data types, adds
//!   `#[flatten(field)]` if the type is another message.
//! - For proto enum, adds `#[derive(clap::ValueEnum)]`
//!
//! Note: to implement [clap::ValueEnum], the `#[derive(clap::ValueEnum)]` is
//! added to the `enum`, and `#[clap(value_enum)]` is added to any fields that
//! reference the proto `enum`. This is not currently working because of the way
//! tonic generated enums ... (todo)

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};
extern crate clap;
extern crate macrolib;
extern crate serde;
extern crate serde_yaml;

/// styx_args is used to derive clap parsers and args for google protobuf `message`
/// and `enum` items.
///
/// For messages:
/// - Adds `#[arg(long)]` for simple data types,
/// - Adds `#[flatten(field)]` if the type is another message
///
/// For enums:
/// - Adds `#[derive(clap::ValueEnum)]`
/// - Adds proto enum references, `#[clap(value_enum)]`
#[proc_macro_attribute]
pub fn styx_args(_args: TokenStream, item: TokenStream) -> TokenStream {
    macrolib::debug::PrintDebug::debugify_blanks(1);
    macrolib::debug::PrintDebug::debugify("== Start proc_macro #[styx_args] ==");
    macrolib::debug::PrintDebug::debugify("vvv Item Code ");
    macrolib::debug::PrintDebug::debugify(&item.to_string());
    macrolib::debug::PrintDebug::debugify("^^^ --- ");
    let orig_item = item;
    let input = parse_macro_input!(orig_item as DeriveInput);
    let token_stream = macrolib::ClapPbHelper::fix_tonic_clap(input);
    macrolib::derive_clap(token_stream).into()
}

#[proc_macro_attribute]
pub fn styx_app_args(_args: TokenStream, item: TokenStream) -> TokenStream {
    let orig_item = item;
    let input = parse_macro_input!(orig_item as DeriveInput);
    let token_stream = macrolib::ClapPbHelper::fix_tonic_clap(input);
    macrolib::derive_styx_app_args(token_stream).into()
}

#[proc_macro_derive(HasTarget)]
pub fn derive_has_target(item: TokenStream) -> TokenStream {
    let ident = parse_macro_input!(item as DeriveInput).ident;
    quote! {
        impl styx_core::grpc::args::HasTarget for #ident {
            fn target(&self) -> styx_core::grpc::args::Target {
                self.target.clone()
            }
        }
    }
    .into()
}

#[proc_macro_derive(HasEmulationOptArgs)]
pub fn derive_has_firmware_path(item: TokenStream) -> TokenStream {
    let ident = parse_macro_input!(item as DeriveInput).ident;
    quote! {
        impl styx_core::grpc::args::HasEmulationOptArgs for #ident {
            fn firmware_path(&self) -> String {
                self.firmware_path.clone()
            }

            fn ipc_port(&self) -> Option<u16> {
                if self.ipc_port < 0 {
                    None
                } else {
                    Some(self.ipc_port as u16)
                }
            }
        }
    }
    .into()
}

#[proc_macro_derive(HasTracePluginArgs)]
pub fn derive_has_trace_plugin_args(item: TokenStream) -> TokenStream {
    let ident = parse_macro_input!(item as DeriveInput).ident;
    quote! {
        impl ::styx_core::grpc::args::HasTracePluginArgs for #ident {
            fn trace_plugin_args_or_default(&self) -> styx_core::grpc::args::TracePluginArgs {
                self.trace_plugin_args.clone().unwrap_or_default()
            }

            fn trace_plugin_args(&self) -> Option<styx_core::grpc::args::TracePluginArgs> {
                self.trace_plugin_args.clone()
            }

            fn has_trace_plugin_args(&self) -> bool {
                self.trace_plugin_args.is_some()
            }

            fn expect_trace_plugin_args(&self) ->
                Result<styx_core::grpc::args::TracePluginArgs, styx_core::errors::styx_grpc::ApplicationError> {
                if let Some(args) = &self.trace_plugin_args {
                    Ok(args.clone())
                } else {
                    Err(styx_core::errors::styx_grpc::ApplicationError::MissingRequiredArgs(
                        "emulation_args: expected trace_plugin_args".into(),
                    ))
                }
            }
        }
    }
    .into()
}

#[proc_macro_derive(HasRawLoaderArgs)]
pub fn derive_has_raw_loader_args(item: TokenStream) -> TokenStream {
    let ident = parse_macro_input!(item as DeriveInput).ident;
    quote! {
        impl ::styx_core::grpc::args::HasRawLoaderArgs for #ident {
            fn raw_loader_args(&self) -> styx_core::grpc::args::RawLoaderArgs {
                self.raw_loader_args.clone().unwrap_or_default()
            }

            fn has_raw_loader_args(&self) -> bool {
                self.raw_loader_args.is_some()
            }
        }
    }
    .into()
}

#[proc_macro_derive(HasEmuRunLimits)]
pub fn derive_has_emu_run_limits(item: TokenStream) -> TokenStream {
    let ident = parse_macro_input!(item as DeriveInput).ident;
    quote! {
        impl styx_core::grpc::args::HasEmuRunLimits for #ident {
            fn emu_run_limits(&self) -> styx_core::grpc::args::EmuRunLimits {
                self.emu_run_limits.clone().unwrap_or_default()
            }

            fn has_emu_run_limits(&self) -> bool {
                self.emu_run_limits.is_some()
            }
        }
    }
    .into()
}
