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
use derive_more::Display;
use enum_dispatch::enum_dispatch;

pub mod gdb_targets;
mod registers;
pub mod variants;

pub use registers::{HexagonRegister, SpecialHexagonRegister};

use super::ArchitectureDef;
use variants::*;

#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, PartialEq, Eq, Clone, Display, Copy, serde::Deserialize)]
#[serde(from = "HexagonVariants")]
pub enum HexagonMetaVariants {
    QDSP6V4,
    QDSP6V5,
    QDSP6V55,
    QDSP6V60,
    QDSPV61,
    QDSP6V62,
    QDSP6V65,
    QDSP6V66,
    QDSP6V67,
    QDSP6V67T,
    QDSP6V69,
    QDSP6V71,
    QDSP6V73,
    QDSP6V77,
    QDPS6V79,
}

impl From<HexagonMetaVariants> for crate::arch::backends::ArchVariant {
    fn from(value: HexagonMetaVariants) -> Self {
        crate::arch::backends::ArchVariant::Hexagon(value)
    }
}

impl From<HexagonMetaVariants> for Box<dyn ArchitectureDef> {
    fn from(value: HexagonMetaVariants) -> Self {
        let inner = value;
        Box::new(inner)
    }
}
/// The ergonomic enum implementation, should mirror *exactly*
/// [`HexagonMetaVariants`]
#[derive(Debug, Display, PartialEq, Eq, Clone, serde::Deserialize)]
pub enum HexagonVariants {
    QDSP6V4,
    QDSP6V5,
    QDSP6V55,
    QDSP6V60,
    QDSPV61,
    QDSP6V62,
    QDSP6V65,
    QDSP6V66,
    QDSP6V67,
    QDSP6V67T,
    QDSP6V69,
    QDSP6V71,
    QDSP6V73,
    QDSP6V77,
    QDPS6V79,
}

impl From<HexagonVariants> for HexagonMetaVariants {
    fn from(value: HexagonVariants) -> Self {
        match value {
            HexagonVariants::QDSP6V4 => QDSP6V4 {}.into(),
            HexagonVariants::QDSP6V5 => QDSP6V5 {}.into(),
            HexagonVariants::QDSP6V55 => QDSP6V55 {}.into(),
            HexagonVariants::QDSP6V60 => QDSP6V60 {}.into(),
            HexagonVariants::QDSPV61 => QDSPV61 {}.into(),
            HexagonVariants::QDSP6V62 => QDSP6V62 {}.into(),
            HexagonVariants::QDSP6V65 => QDSP6V65 {}.into(),
            HexagonVariants::QDSP6V66 => QDSP6V66 {}.into(),
            HexagonVariants::QDSP6V67 => QDSP6V67 {}.into(),
            HexagonVariants::QDSP6V67T => QDSP6V67T {}.into(),
            HexagonVariants::QDSP6V69 => QDSP6V69 {}.into(),
            HexagonVariants::QDSP6V71 => QDSP6V71 {}.into(),
            HexagonVariants::QDSP6V73 => QDSP6V73 {}.into(),
            HexagonVariants::QDSP6V77 => QDSP6V77 {}.into(),
            HexagonVariants::QDPS6V79 => QDPS6V79 {}.into(),
        }
    }
}

impl From<HexagonVariants> for crate::arch::backends::ArchVariant {
    fn from(value: HexagonVariants) -> Self {
        let tmp: HexagonMetaVariants = value.into();
        tmp.into()
    }
}
