// SPDX-License-Identifier: BSD-2-Clause
//! Rust interface for Ghidra's Sleigh compiler and translator.
//!
//! This crate interfaces with the libsleigh ffi bindings to allow rust use of
//! libsleigh without fii interaction. It has a collection of safe wrappers
//! around the C++ classes and functions found in Ghidra's Sleigh
//! implementation. They are provided as ergonmic rust wrappers.
mod compile;
mod context_internal;
mod dom;
mod load_image;
mod pcode_emit;
mod sleigh;
mod sleigh_obj;

pub use compile::compile;
pub use dom::DocumentStorage;
pub use load_image::{Loader, VectorLoader};
pub use sleigh::{NewSleighError, Sleigh, SleighTranslateError, UserOpInfo};
