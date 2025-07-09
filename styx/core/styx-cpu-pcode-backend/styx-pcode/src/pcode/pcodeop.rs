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
use super::{Opcode, SpaceName, VarnodeData};
use smallvec::SmallVec;
use std::fmt::{Debug, Display};

/// A single p-code operation.
#[derive(PartialEq, Eq)]
pub struct Pcode {
    /// Opcode of p-code operation.
    pub opcode: Opcode,
    /// Input varnodes, 0 or more.
    pub inputs: SmallVec<[VarnodeData; 3]>, // Avoid heap allocation
    /// Optional output varnode.
    pub output: Option<VarnodeData>,
}

impl Pcode {
    /// Returns true if pcode is an absolute branch (branches to a new address)
    ///
    /// Excludes pcode relative branches.
    pub fn is_absolute_branch(&self) -> bool {
        self.opcode.is_branch_indirect()
            || (self.opcode.is_branch()
                && self
                    .inputs
                    .first()
                    .expect("branch pcode must have at least one input varnode")
                    .space
                    == SpaceName::Constant)
    }

    pub fn is_branch(&self) -> bool {
        self.opcode.is_branch_indirect() || self.opcode.is_branch()
    }
}

impl Debug for Pcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} ", self.opcode)?;

        for (i, var) in self.inputs.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{var:?}")?;
        }

        if let Some(out) = &self.output {
            write!(f, " -> {out:?}")?;
        }

        Ok(())
    }
}

impl Display for Pcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut comma_separated = String::new();
        for var in self.inputs.iter().take(self.inputs.len() - 1) {
            comma_separated.push_str(&var.to_string());
            comma_separated.push_str(", ");
        }
        comma_separated.push_str(
            &self
                .inputs
                .last()
                .map(ToString::to_string)
                .unwrap_or_default(),
        );

        write!(f, "{:?}\t{}", self.opcode, comma_separated)?;
        if let Some(out) = &self.output {
            write!(f, " -> {out}")?;
        }

        Ok(())
    }
}
