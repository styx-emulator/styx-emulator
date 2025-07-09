// SPDX-License-Identifier: BSD-2-Clause

use super::container::DmaContainer;
use super::id::DmaId;
use super::mmr_offsets;
use super::DmaPeripheralMapping;

use crate::core_event_controller::SicHandle;
use arbitrary_int::u4;
use derivative::Derivative;
use futures::stream::BoxStream;
use futures::FutureExt;
use styx_core::prelude::*;
use tokio_stream::{StreamExt, StreamMap};
use tracing::warn;

use styx_blackfin_sys::bf512 as sys;

/// Main [Peripheral] for DMA.
///
/// Handles the hooking of registers and passes on state management to a locked [DmaContainer].
#[derive(Derivative)]
pub(crate) struct DmaController {
    dma: Mutex<DmaContainer>,

    /// Stream sources that must be polled to pass on to DMA channels.
    mapping: DmaSources,
}

impl DmaController {
    pub fn new(system: SicHandle, mapping_sources: DmaSources) -> Self {
        Self {
            dma: Mutex::new(DmaContainer::new(system)),
            mapping: mapping_sources,
        }
    }
}

pub type DmaStream = BoxStream<'static, u8>;

#[derive(Default)]
pub struct DmaSources {
    mapping: StreamMap<DmaPeripheralMapping, DmaStream>,
}

impl DmaSources {
    pub fn set(&mut self, mapping: DmaPeripheralMapping, source: DmaStream) -> Option<DmaStream> {
        self.mapping.insert(mapping, source)
    }
    fn get_next_data2(&mut self) -> Option<(DmaPeripheralMapping, u8)> {
        self.mapping.next().now_or_never().expect("stream ended!")
    }
}

impl Peripheral for DmaController {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        proc.core.cpu.mem_write_hook(
            sys::DMA0_NEXT_DESC_PTR as u64,
            sys::DMA11_CURR_Y_COUNT as u64,
            Box::new(dma_register_write_hook),
        )?;

        Ok(())
    }

    fn name(&self) -> &str {
        "DmaController"
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        ev: &mut dyn EventControllerImpl,
        _delta: &styx_core::prelude::Delta,
    ) -> Result<(), UnknownError> {
        let incoming_data = self.mapping.get_next_data2();

        if let Some((dma, data)) = incoming_data {
            self.dma.lock().unwrap().pipe_new_data(mmu, ev, dma, data);
        }

        Ok(())
    }

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }
}

fn get_data_u16(data: &[u8]) -> u16 {
    assert_eq!(
        data.len(),
        std::mem::size_of::<u16>(),
        "register write data is not the right number of bytes"
    );
    let mut buf = [0u8; 2];
    buf.copy_from_slice(data);
    u16::from_le_bytes(buf)
}
fn get_data_u32(data: &[u8]) -> u32 {
    assert_eq!(
        data.len(),
        std::mem::size_of::<u32>(),
        "register write data is not the right number of bytes"
    );
    let mut buf = [0u8; 4];
    buf.copy_from_slice(data);
    u32::from_le_bytes(buf)
}

fn dma_register_write_hook(
    proc: CoreHandle,
    address: u64,
    _size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let controller = proc
        .event_controller
        .peripherals
        .get_expect::<DmaController>()?;

    // dma channel for this register write
    let dma_id = DmaId::from_mmr_address(address).unwrap_or_else(|_| {
        panic!("dma register write hook caught non dma mmr write at address 0x{address:X}")
    });

    let mmr_offset = address as u32 - dma_id.mmr_base_address();

    let mut dma_container = controller.dma.lock().unwrap();
    let dma_channel = &mut dma_container.dma[dma_id];
    match mmr_offset {
        mmr_offsets::CONFIG_OFFSET => dma_channel.set_config(get_data_u16(data)),
        mmr_offsets::X_COUNT_OFFSET => dma_channel.set_x_count(proc.mmu, get_data_u16(data)),
        mmr_offsets::Y_COUNT_OFFSET => dma_channel.set_y_count(proc.mmu, get_data_u16(data)),
        mmr_offsets::X_MODIFY_OFFSET => dma_channel.set_x_modify(get_data_u16(data)),
        mmr_offsets::Y_MODIFY_OFFSET => dma_channel.set_y_modify(get_data_u16(data)),
        mmr_offsets::START_ADDR_OFFSET => dma_channel.set_start_address(get_data_u32(data)),
        mmr_offsets::IRQ_STATUS_OFFSET => dma_channel.write_status(proc.mmu, u4::new(data[0])),

        _ => warn!("dma write to 0x{address:X} not handled!"),
    }

    Ok(())
}
