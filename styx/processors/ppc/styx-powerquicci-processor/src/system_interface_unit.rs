// SPDX-License-Identifier: BSD-2-Clause
//! Implements the System Interface Unit as defined by
//! the MPC8XX Family Reference Manual.
use super::communications_processor::CommunicationsProcessorModule;
use super::immr;
use super::Mpc8xxVariants;

use styx_core::errors::UnknownError;
use styx_core::hooks::CoreHandle;
use styx_core::hooks::HookToken;
use styx_core::hooks::StyxHook;
use styx_core::prelude::CpuBackend;
use styx_core::prelude::Peripheral;
use styx_core::sync::sync::{Arc, Mutex};
use tracing::{debug, trace, warn};

mod mtspr_manager;

use mtspr_manager::*;

#[derive(Debug)]
pub struct SystemInterfaceUnit {
    _family_variant: Mpc8xxVariants,
    /// State shared with the IMMR/mtspr hooks.
    inner: Arc<Mutex<SystemInterfaceUnitInner>>,
    _cpm: Arc<CommunicationsProcessorModule>,
}

/// Internal state of the [`SystemInterfaceUnit`] shared with its register hooks.
#[derive(Debug)]
pub(crate) struct SystemInterfaceUnitInner {
    pub(crate) mtspr_mgr: MtsprStateManager,
    immr_proxy_hooks: Vec<HookToken>,
    immr_base_address: u64,
}

/// Set the global IMMR region hook fn to route to the proper handle
pub(crate) fn set_immr_hooks(
    inner: &Arc<Mutex<SystemInterfaceUnitInner>>,
    cpu: &mut dyn CpuBackend,
    base_address: u64,
) -> Result<(), UnknownError> {
    let end = immr::IMMR_REGION_LEN.saturating_add(base_address as usize) as u64;

    {
        let mut state = inner.lock().unwrap();

        // make sure we're not setting duplicate hooks
        if !state.immr_proxy_hooks.is_empty() {
            trace!(
                "Already set IMMR proxy hooks, changing IMMR base to: {:#x}",
                base_address
            );

            // remove all the hooks that were previosly set
            while let Some(hook) = state.immr_proxy_hooks.pop() {
                if let Err(err) = cpu.delete_hook(hook) {
                    warn!("Error removing hook: {:?}, UB ahead", err);
                }
            }
        }

        // store new base address
        state.immr_base_address = base_address;
    }

    // catch-all read hook
    let read_inner = inner.clone();
    let read_hook = cpu.mem_read_hook(
        base_address,
        end,
        Box::new(
            move |_core: CoreHandle, address: u64, size: u32, value: &mut [u8]| {
                read_inner
                    .lock()
                    .unwrap()
                    .read_memory_hook(address, size, value);
                Ok(())
            },
        ),
    )?;

    // catch-all write hook
    let write_inner = inner.clone();
    let write_hook = cpu.mem_write_hook(
        base_address,
        end,
        Box::new(
            move |_core: CoreHandle, address: u64, size: u32, value: &[u8]| {
                write_inner
                    .lock()
                    .unwrap()
                    .write_memory_hook(address, size, value);
                Ok(())
            },
        ),
    )?;

    let mut state = inner.lock().unwrap();
    state.immr_proxy_hooks.push(read_hook);
    state.immr_proxy_hooks.push(write_hook);
    Ok(())
}

impl SystemInterfaceUnit {
    pub fn new(variant: Mpc8xxVariants) -> Self {
        Self {
            _family_variant: variant,
            inner: Arc::new(Mutex::new(SystemInterfaceUnitInner {
                mtspr_mgr: MtsprStateManager::new(),
                immr_proxy_hooks: Default::default(),
                immr_base_address: 0,
            })),
            _cpm: CommunicationsProcessorModule::new_arc(variant).expect("Bad MPC8xx variant"),
        }
    }
}

impl SystemInterfaceUnitInner {
    fn read_memory_hook(&self, address: u64, size: u32, value: &[u8]) {
        let offset = address - self.immr_base_address;

        // get the range being read from
        if let Ok(register) = immr::register_search(offset as u32, size) {
            trace!(
                " [READ] ImmrRegister{{name: `{}`, value: `{:?}`, address: {:#x}}}",
                register.abbreviation(),
                &value[..size as usize],
                address,
            );

            // now send the data to the proper peripherals
        } else {
            warn!(
                "Failed to find IMMR register at {:#x}, size: {:#x}",
                address, size
            );
        }
    }

    fn write_memory_hook(&self, address: u64, size: u32, value: &[u8]) {
        let offset = address - self.immr_base_address;

        // get the range being written to
        if let Ok(register) = immr::register_search(offset as u32, size) {
            if register.name() == "DPRAM" {
                trace!(
                    "[WRITE] ImmrRegister{{name: `{}`, value: `{:?}`, address: {:#x}}}",
                    register.abbreviation(),
                    &value[..size as usize],
                    address,
                );
            } else {
                trace!(
                    "[WRITE] ImmrRegister{{name: `{}`, value: `{:?}`}}",
                    register.abbreviation(),
                    &value[..size as usize],
                );
            }

            // now send the data to the proper peripherals
        } else {
            warn!(
                "Failed to find IMMR register at {:#x}, size: {:#x}",
                address, size
            );
        }
    }
}

impl Peripheral for SystemInterfaceUnit {
    fn init(
        &mut self,
        proc: &mut styx_core::prelude::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        set_immr_hooks(
            &self.inner,
            proc.vcpus[0].cpu.as_mut(),
            immr::DEFAULT_BASE_ADDRESS,
        )?;

        // Registers the hook that will hook *every* instruction and handle the
        // stores to mtspr since those are hidden / abstracted away from us in
        // the backend
        let inner = self.inner.clone();
        proc.vcpus[0]
            .cpu
            .add_hook(StyxHook::code(.., move |core: CoreHandle| {
                mtspr_proxy(core, &inner)
            }))?;

        debug!("Set the SIU memory hooks");

        Ok(())
    }

    fn name(&self) -> &str {
        "System Interface Unit"
    }
}
