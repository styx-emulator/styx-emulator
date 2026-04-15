// SPDX-License-Identifier: BSD-2-Clause

//! Hexagon clade

use std::process::exit;

use arbitrary_int::*;
use bitbybit::{bitenum, bitfield};
use styx_core::{
    arch::{
        hexagon::{
            register_fields::{Ipendad, Ssr},
            HexagonRegister,
        },
        RegisterValue,
    },
    cpu::{CpuBackend, CpuBackendExt, HexagonInterruptType},
    errors::UnknownError,
    event_controller::{ActivateIRQnError, InterruptExecuted, Peripherals},
    hooks::CoreHandle,
    memory::Mmu,
    prelude::{
        log::{error, info, trace, warn},
        ArchRegister, BasicArchRegister, Context, EventControllerImpl, ExceptionNumber, Peripheral,
    },
};

const CLADE_BASE: u64 = 0x57d0000;
const CLADE2_BASE: u64 = 0x55b0000;

fn clade_mmio_write_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    warn!(
        "clade base writing at 0x{address:x} and size 0x{size:x} with data {data:x?}, pc is {:x?}",
        proc.cpu.pc()
    );

    Ok(())
}

fn clade_mmio_read_hook(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    // stupid hack that hexagon-sim seems to do.
    if address == CLADE2_BASE && size == 4 {
        data.fill(0);
    }

    warn!(
        "clade base reading at 0x{address:x} and size 0x{size:x} with data {data:x?}, pc is {:x?}",
        proc.cpu.pc()
    );

    Ok(())
}

#[derive(Default)]
pub struct Clade {}

impl Peripheral for Clade {
    fn name(&self) -> &str {
        "Qualcomm Clade Decompression Engine"
    }

    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), styx_core::prelude::UnknownError> {
        proc.core
            .cpu
            .mem_write_hook(
                CLADE_BASE,
                CLADE_BASE + 0x8000,
                Box::new(clade_mmio_write_hook),
            )
            .with_context(|| "couldn't add MMIO hooks for clade")?;
        proc.core
            .cpu
            .mem_write_hook(
                CLADE2_BASE,
                CLADE2_BASE + 0x8000,
                Box::new(clade_mmio_write_hook),
            )
            .with_context(|| "couldn't add MMIO hooks for clade")?;

        proc.core
            .cpu
            .mem_read_hook(
                CLADE_BASE,
                CLADE_BASE + 0x8000,
                Box::new(clade_mmio_read_hook),
            )
            .with_context(|| "couldn't add MMIO hooks for clade")?;
        proc.core
            .cpu
            .mem_read_hook(
                CLADE2_BASE,
                CLADE2_BASE + 0x8000,
                Box::new(clade_mmio_read_hook),
            )
            .with_context(|| "couldn't add MMIO hooks for clade")?;
        Ok(())
    }
}
