// SPDX-License-Identifier: BSD-2-Clause
//! Implements the Fast Ethernet Controller (FEC) as defined
//! by the MPC8XX Family Reference Manual.
use super::Mpc8xxVariants;
use styx_core::prelude::Peripheral;
use tracing::trace;

#[derive(Debug, Default)]
pub struct FastEthernetController;

impl FastEthernetController {
    pub fn new(variant: Mpc8xxVariants) -> Self {
        trace!("FastEthernetController::new({})", variant);
        Self {}
    }
}

impl Peripheral for FastEthernetController {
    fn init(
        &mut self,
        _proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), styx_core::errors::UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "Fast Ethernet Controller"
    }
}
