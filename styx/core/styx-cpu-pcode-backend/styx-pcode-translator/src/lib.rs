// SPDX-License-Identifier: BSD-2-Clause
//! Provides a pcode translator.
//!
//! The three main components of the translator are the [PcodeTranslator], the
//! [sla], and the [Loader].
//!
//! The [Loader] defines how the translator gets bytes to translate. The [sla]
//! provides a specification for the processor. With both of these you can
//! create a [PcodeTranslator] and create pcodes with
//! [PcodeTranslator::get_pcode()].
mod translator;

pub use styx_pcode_sleigh_backend::{Loader, LoaderRequires, SleighTranslateError, VectorLoader};
pub use translator::{ContextOption, PcodeTranslator, PcodeTranslatorError};
pub mod sla {
    pub use styx_sla::*;
}
