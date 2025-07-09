// SPDX-License-Identifier: BSD-2-Clause
#![allow(dead_code, unused_variables)]
use super::super::communications_processor::CpmPeripheral;
use styx_core::{errors::UnknownError, prelude::*};

#[derive(Debug)]
pub struct SystemControlClock;

impl Peripheral for SystemControlClock {
    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "System Control Clock"
    }
}

impl CpmPeripheral for SystemControlClock {
    fn process_cpm_opcode(
        &self,
        opcode: crate::communications_processor::CpmOpcode,
    ) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn process_event(
        &self,
        evt: crate::communications_processor::CpmEventType,
    ) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn reset(&self) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn new_arc(
        variant: crate::Mpc8xxVariants,
        cpm: Weak<crate::communications_processor::CommunicationsProcessorModule>,
        idx: Option<usize>,
    ) -> Result<Arc<Self>, crate::communications_processor::CpmError>
    where
        Self: Sized,
    {
        Ok(Arc::new_cyclic(|me| Self {}))
    }
}

#[derive(Debug)]
pub struct PllClock;

impl Peripheral for PllClock {
    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "Pll Clock"
    }
}

impl CpmPeripheral for PllClock {
    fn process_cpm_opcode(
        &self,
        opcode: crate::communications_processor::CpmOpcode,
    ) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn process_event(
        &self,
        evt: crate::communications_processor::CpmEventType,
    ) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn reset(&self) -> Result<(), crate::communications_processor::CpmError> {
        Ok(())
    }

    fn new_arc(
        variant: crate::Mpc8xxVariants,
        cpm: Weak<crate::communications_processor::CommunicationsProcessorModule>,
        idx: Option<usize>,
    ) -> Result<Arc<Self>, crate::communications_processor::CpmError>
    where
        Self: Sized,
    {
        Ok(Arc::new_cyclic(|me| Self {}))
    }
}
