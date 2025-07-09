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
