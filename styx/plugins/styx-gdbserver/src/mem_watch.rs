// SPDX-License-Identifier: BSD-2-Clause
//! Utilities used to support based watch points

use gdbstub::common::Tid;
use std::collections::{HashMap, VecDeque};
use styx_core::{
    core::VcpuCore,
    errors::UnknownError,
    hooks::{CoreHandle, HookToken, MemoryWriteHook},
    processor::PerVcpuSlice,
    sync::sync::{Arc, Mutex},
};
use tracing::{debug, error, trace, warn};

use crate::event_loop::index_to_tid;

type MemHookAddress = u64;
type MemHookValue = u64;

#[derive(Debug)]
pub(crate) struct WatchpointHit {
    pub(crate) address: MemHookAddress,
    // Unused :/
    #[allow(dead_code)]
    value: MemHookValue,
    pub(crate) tid: Tid,
}

/// Tracks the watchpoints requested by the `gdb` client.
///
/// This is the source of truth for addresses that are watched.
/// [`tracked`](Self::tracked) holds one [`HookToken`] for per vCPU.
/// [`add_write_watchpoint()`](Self::add_write_watchpoint) and [`remove_watchpoint`](Self::remove_watchpoint)
/// install/remove those hooks across every vCPU.
///
/// ### NOTE
/// - The actual DSL-address-resolution occurs client-side,
///   and that only the final address is sent from the client
///   to the server, which then adds an entry here.
/// - We currently only track write-memory events
#[derive(Default)]
pub(crate) struct Watchpoints {
    /// Addresses and value written for which we have received a write callback
    /// but not yet reported to the gdb client.
    ///
    /// Drained when stepping to handle watchpoint hits.
    pending: Mutex<VecDeque<WatchpointHit>>,

    /// The watched addresses, each mapped to one [`HookToken`] per vCPU (in
    /// vCPU order). Membership here defines what is watched.
    tracked: Mutex<HashMap<MemHookAddress, Vec<HookToken>>>,
}

impl Watchpoints {
    /// Create an empty set of watchpoints.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Install a write watchpoint at `addr` by adding a memory write hook on every vCPU.
    ///
    /// Idempotent: if `addr` is already watched this returns `true` without
    /// installing duplicate hooks. If a hook fails to install on some vCPU, the
    /// hooks already installed on prior vCPUs are rolled back so no orphaned
    /// hooks remain, and `false` is returned.
    ///
    /// Returns `true` on success, `false` otherwise.
    pub(crate) fn add_write_watchpoint(
        self: &Arc<Self>,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
        addr: MemHookAddress,
    ) -> bool {
        let mut tracked = self.tracked.lock().unwrap();
        if tracked.contains_key(&addr) {
            return true;
        }

        let mut tokens = Vec::with_capacity(vcpus.len());
        // index loop so we can re-borrow `vcpus` mutably for rollback below
        for i in 0..vcpus.len() {
            match vcpus[i].cpu.mem_write_virtual_hook(
                addr,
                addr,
                Box::new(MemWrittenHook(self.clone(), index_to_tid(i))),
            ) {
                Ok(token) => tokens.push(token),
                Err(error) => {
                    warn!("Failed to add watchpoint for {addr:#x}: {error}");
                    for (vcpu, token) in vcpus.iter_mut().zip(tokens) {
                        if let Err(e) = vcpu.cpu.delete_hook(token) {
                            error!("Failed to roll back watchpoint hook at {addr:#x}: {e}");
                        }
                    }
                    return false;
                }
            }
        }

        tracked.insert(addr, tokens);
        true
    }

    /// Remove the watchpoint at `addr`.
    ///
    /// Deleting its hook on every vCPU and drops any pending hit for it.
    ///
    /// Returns `true` if a watchpoint was removed, `false` if `addr` was not
    /// being watched.
    pub(crate) fn remove_watchpoint(
        &self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
        addr: MemHookAddress,
    ) -> bool {
        let Some(tokens) = self.tracked.lock().unwrap().remove(&addr) else {
            return false;
        };
        self.pending.lock().unwrap().retain(|h| h.address != addr);
        for (vcpu, token) in vcpus.iter_mut().zip(tokens) {
            if let Err(e) = vcpu.cpu.delete_hook(token) {
                error!("Failed to delete watchpoint hook at {addr:#x}: {e}");
            }
        }
        true
    }

    /// Are there any watchpoints?
    pub(crate) fn any_watchpoints(&self) -> bool {
        !self.tracked.lock().unwrap().is_empty()
    }

    /// Take one pending watchpoint hit, removing it from the pending set.
    ///
    /// `None` if no pending hits.
    pub(crate) fn pop_hit(&self) -> Option<WatchpointHit> {
        self.pending.lock().unwrap().pop_front()
    }

    /// How many addresses are being watched?
    pub(crate) fn tracked_len(&self) -> usize {
        self.tracked.lock().unwrap().len()
    }

    /// How many hits are pending (received but not yet reported)?
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Record a write callback for `addr`. Ignored and warn if `addr` is not watched.
    fn record_write(&self, address: MemHookAddress, value: MemHookValue, tid: Tid) {
        if !self.tracked.lock().unwrap().contains_key(&address) {
            warn!("Received watchpoint callback for untracked address: 0x{address:#x} tid: {tid}");
            return;
        }

        let hit = WatchpointHit {
            address,
            value,
            tid,
        };

        self.pending.lock().unwrap().push_back(hit);
    }
}

/// Memory write callback for watchpoint support.
///
/// Installed on every vCPU by [`Watchpoints::add_write_watchpoint()`]. When a watched address is
/// written, the access is recorded so [`step`](crate::target_impl) can later
/// report it to the gdb client.
struct MemWrittenHook(Arc<Watchpoints>, Tid);
impl MemoryWriteHook for MemWrittenHook {
    fn call(
        &mut self,
        _proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        let tid = self.1;
        debug!("Got mem write event in tid {tid} for watchpoint size `{size}` @ {address:#08x?}");
        let access = Access::from_target_write(address, size, data);
        self.0.record_write(address, access.val, tid);
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub(crate) enum AccessKind {
    // we currently only track write-memory
    #[allow(dead_code)]
    Read,
    Write,
}

impl std::fmt::Display for AccessKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let x = match self {
            Self::Read => String::from("Read"),
            Self::Write => String::from("Write"),
        };
        write!(f, "{x}")
    }
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub(crate) struct Access {
    pub kind: AccessKind,
    pub addr: MemHookAddress,
    pub val: MemHookValue,
    pub len: usize,
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {:#010x} [{}] {:#010x}",
            self.kind, self.addr, self.len, self.val
        )
    }
}
impl Access {
    pub fn from_target_write(address: MemHookAddress, size: u32, data: &[u8]) -> Self {
        debug_assert!(data.len() >= size as usize);
        let val: MemHookValue = match size {
            1 => u8::from_le_bytes(data[0..1].try_into().unwrap()) as MemHookValue,
            2 => u16::from_le_bytes(data[0..2].try_into().unwrap()) as MemHookValue,
            4 => u32::from_le_bytes(data[0..4].try_into().unwrap()) as MemHookValue,
            8 => u64::from_le_bytes(data[0..8].try_into().unwrap()) as MemHookValue,
            _ => {
                warn!(
                    "Can't handle memory hook on {:#x} size: {}, using size 4",
                    address, size
                );
                u32::from_le_bytes(data[0..4].try_into().unwrap()) as MemHookValue
            }
        };

        let access_obj = Self {
            kind: AccessKind::Write,
            addr: address as MemHookAddress,
            len: size as usize,
            val,
        };

        trace!(
            "Callback: Watch: hook received: {} => {:?}",
            access_obj,
            data
        );
        access_obj
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_xxx() {
        let mut hs: HashSet<Access> = HashSet::new();
        let a1 = Access::from_target_write(0x1, 4, &[1, 0, 0, 0]);
        let a2 = Access::from_target_write(0x1, 4, &[1, 0, 0, 0]);
        {
            hs.insert(a1);
        }
        assert!(hs.contains(&a2));
    }
}
