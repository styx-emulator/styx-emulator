// SPDX-License-Identifier: BSD-2-Clause
use styx_core::prelude::*;

use super::{id::DmaId, state::DmaState, DmaPeripheralMapping};
use enum_map::EnumMap;

use crate::core_event_controller::SicHandle;

/// Holds all dma channels and provides helper methods to organize channels.
pub(super) struct DmaContainer {
    pub(super) dma: EnumMap<DmaId, DmaState>,
}

impl DmaContainer {
    pub(super) fn new(system: SicHandle) -> Self {
        let dma = EnumMap::from_fn(|id| DmaState::new(id, system.clone()));
        Self { dma }
    }

    /// Pass incoming data from peripherals to be handled by the chip's dma channels.
    pub(super) fn pipe_new_data(
        &mut self,
        mmu: &mut Mmu,
        ev: &mut dyn EventControllerImpl,
        peripheral: DmaPeripheralMapping,
        data: u8,
    ) {
        // send data to proper dma channel
        let state = self.state_from_peripheral_mapping(peripheral);
        state.pipe_new_data(mmu, ev, data)
    }

    fn state_from_peripheral_mapping(&mut self, p: DmaPeripheralMapping) -> &mut DmaState {
        self.dma
            .values_mut()
            .find(|state| state.mapping() == p)
            .unwrap()
    }
}
