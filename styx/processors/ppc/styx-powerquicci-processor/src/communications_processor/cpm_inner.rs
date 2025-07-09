// SPDX-License-Identifier: BSD-2-Clause
use super::{CommunicationsProcessorModule, CpmError, CpmEvent, CpmPeripheral};
use crate::Mpc8xxVariants;
use derive_more::Display;
use styx_core::errors::UnknownError;
use styx_core::prelude::Peripheral;
use styx_core::sync::sync::{Arc, Weak};

/// Event abstraction for IMMR related IPC for the CPM Interrupt
/// Controller
#[derive(PartialEq, Eq, Debug, Display)]
pub struct CpmCicrEvent {}

impl CpmEvent for CpmCicrEvent {
    fn to_bytes(&self) -> Vec<u8> {
        todo!()
    }
}

impl CpmCicrEvent {
    pub fn from_data(data: &[u8]) -> Result<Self, CpmError> {
        _ = data;
        Ok(Self {})
    }
}

/// Event abstraction for IMMR related IPC for the CPM proper
#[derive(PartialEq, Eq, Debug, Display)]
pub struct CpmCpEvent {}

impl CpmEvent for CpmCpEvent {
    fn to_bytes(&self) -> Vec<u8> {
        todo!()
    }
}

impl CpmCpEvent {
    pub fn from_data(data: &[u8]) -> Result<Self, CpmError> {
        _ = data;
        Ok(Self {})
    }
}

/// Event abstraction for IMMR related IPC for the CPM General-Purpose
/// Timers
#[derive(PartialEq, Eq, Debug, Display)]
pub struct CpmGpTimerEvent {}

impl CpmEvent for CpmGpTimerEvent {
    fn to_bytes(&self) -> Vec<u8> {
        todo!()
    }
}

impl CpmGpTimerEvent {
    pub fn from_data(data: &[u8]) -> Result<Self, CpmError> {
        _ = data;
        Ok(Self {})
    }
}

/// This struct manages the main subsystems of the Communications
/// Processor Module
///
/// Namely:
/// - Communication Processor Interrupt Controller
/// - CPM General Purpose Timers
/// - CPM proper
///
/// All IMMR events to the above systems are routed through this
/// struct as it implements the actual inner state machine of the
/// communications processor
///
/// To obtain this struct you can do something like:
///
/// ```rust
/// use styx_core::sync::sync::Arc;
/// use styx_core::cpu::arch::ppc32::variants::Mpc8xxVariants;
/// use styx_powerquicci_processor::communications_processor::CommunicationsProcessorModule;
/// use styx_powerquicci_processor::communications_processor::{CommunicationsProcessorInner, CpmPeripheral};
///
/// let cpm = CommunicationsProcessorModule::new_arc(Mpc8xxVariants::Mpc860).unwrap();
/// let weak_cpm = Arc::downgrade(&cpm);
/// let cpi = CommunicationsProcessorInner::new_arc(Mpc8xxVariants::Mpc860, weak_cpm, None).unwrap();
/// ```
#[allow(dead_code)]
#[derive(Debug)]
pub struct CommunicationsProcessorInner {
    weak_ref: Weak<Self>,
    cpm: Weak<CommunicationsProcessorModule>,
}

impl CpmPeripheral for CommunicationsProcessorInner {
    fn new_arc(
        _variant: Mpc8xxVariants,
        cpm: Weak<CommunicationsProcessorModule>,
        idx: Option<usize>,
    ) -> Result<Arc<Self>, CpmError>
    where
        Self: Sized,
    {
        // must be none
        if let Some(idx_value) = idx {
            return Err(CpmError::BadInitIdx(idx_value));
        }

        Ok(Arc::new_cyclic(|me| Self {
            weak_ref: me.clone(),
            cpm: cpm.clone(),
        }))
    }

    fn process_event(&self, _evt: super::CpmEventType) -> Result<(), CpmError> {
        todo!()
    }

    fn reset(&self) -> Result<(), CpmError> {
        todo!()
    }

    fn process_cpm_opcode(&self, _opcode: super::CpmOpcode) -> Result<(), CpmError> {
        todo!()
    }
}

impl Peripheral for CommunicationsProcessorInner {
    fn init(
        &mut self,
        _proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn name(&self) -> &str {
        "Communications Processor Inner"
    }
}
