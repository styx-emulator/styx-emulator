// SPDX-License-Identifier: BSD-2-Clause
use super::{Opcode, SpaceName, VarnodeData};
use smallvec::SmallVec;
use std::fmt::{Debug, Display};

/// A single p-code operation.
#[derive(PartialEq, Eq, Clone)]
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
