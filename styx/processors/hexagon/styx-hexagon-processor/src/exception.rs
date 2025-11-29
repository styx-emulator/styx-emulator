// SPDX-License-Identifier: BSD-2-Clause
use styx_core::{
    arch::hexagon::{register_fields::Ssr, HexagonRegister},
    cpu::{CpuBackendExt, HexagonInterruptCause},
    errors::anyhow::Result,
    memory::TlbProcessor,
    prelude::{log::info, Context},
};

/// When a page fault occurs, Hexagon requires the BADVA registers to be set appropriately.
///
/// The load parameter is set to true if the memory operation is a load.
/// It is set to false if it is a store.
pub fn update_badva(proc: &mut TlbProcessor, va: u32) -> Result<()> {
    Ok(proc
        .cpu
        .write_register(HexagonRegister::BadVa, va)
        .with_context(|| "couldn't write BadVa in page fault")?)
}

pub fn ssr_set_cause(processor: &mut TlbProcessor, cause: HexagonInterruptCause) -> Result<()> {
    let mut ssr = Ssr::new_with_raw_value(
        processor
            .cpu
            .read_register::<u32>(HexagonRegister::Ssr)
            .with_context(|| "couldn't read ssr")?,
    );

    ssr.set_cause(cause as u8);
    ssr.set_ex(true);

    info!("setting ssr to {:x}", ssr.raw_value());
    processor
        .cpu
        .write_register(HexagonRegister::Ssr, ssr.raw_value())
        .with_context(|| "couldn't write ssr")?;
    Ok(())
}
