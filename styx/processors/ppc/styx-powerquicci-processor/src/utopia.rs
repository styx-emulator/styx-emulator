// SPDX-License-Identifier: BSD-2-Clause
//! (TODO) Implements the UTOPIA Hardware Block as defined by
//! the MPC8XX Family Reference Manual
use super::Mpc8xxVariants;
use styx_core::prelude::Peripheral;
use tracing::trace;

#[derive(Debug, Default)]
pub struct UtopiaBlock;

impl UtopiaBlock {
    pub fn new(variant: Mpc8xxVariants) -> Self {
        trace!("UtopiaBlock::new({})", variant);

        Self {}
    }
}

impl Peripheral for UtopiaBlock {
    fn init(
        &mut self,
        _proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), styx_core::errors::UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "Utopia Block"
    }
}
