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
//! Utilities used to support based watch points

use std::collections::HashMap;
use styx_core::{
    errors::{anyhow::anyhow, UnknownError},
    hooks::HookToken,
    sync::sync::{Arc, Mutex},
};
use tracing::{trace, warn};

type MemHookAddress = u64;
type MemHookValue = u64;

/// Stores the addresses and values that the `gdb` client has
/// requested the backend to watch for changes in.
///
/// ### NOTE
/// - The actual DSL-address-resolution occurs client-side,
///   and that only the final address is sent from the client
///   to the server, which then adds an entry here.
/// - We currently only track write-memory events
pub(crate) struct MemHookCache {
    /// Addresses for which we have actually received callbacks
    /// The entry is removed when its processed
    pending: Arc<Mutex<HashMap<MemHookAddress, MemHookValue>>>,

    /// The addresses for which we have installed hooks
    tracked: Arc<Mutex<HashMap<MemHookAddress, HookToken>>>,
}

unsafe impl Send for MemHookCache {}
unsafe impl Sync for MemHookCache {}

impl MemHookCache {
    /// create an empty cache
    pub(crate) fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            tracked: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Removes the hook from internal tracking and returns the
    /// corresponding [`HookToken`]
    pub(crate) fn remove_hook(&self, addr: u64) -> Result<HookToken, UnknownError> {
        if let Some(item) = self.tracked.lock().unwrap().remove(&addr) {
            Ok(item)
        } else {
            Err(anyhow!("No watchpoint to remove for addr: `{addr:#08x}"))
        }
    }

    /// Does the addr have a hook installed?
    pub(crate) fn tracked(&self, addr: MemHookAddress) -> bool {
        self.tracked.lock().unwrap().contains_key(&addr)
    }

    pub(crate) fn tracked_len(&self) -> usize {
        self.tracked.lock().unwrap().len()
    }

    /// We have installed a hook for this address
    pub fn track(&self, addr: MemHookAddress, token: HookToken) {
        if !self.tracked(addr) {
            self.tracked.lock().unwrap().insert(addr, token);
        }
    }

    /// A callback was received
    pub(crate) fn add(&self, addr: MemHookAddress, value: MemHookValue) {
        if !self.tracked(addr) {
            warn!(
                "Received watchpoint callback for untracked address: {:#x}",
                addr
            );
            return;
        }

        // if we already have a pending value for this address, overwrite it,
        // else just set it
        self.pending
            .lock()
            .unwrap()
            .entry(addr)
            .and_modify(|x| *x = value)
            .or_insert(value);
    }

    /// Return the address and remove it from the map
    pub(crate) fn take(&self, addr: MemHookAddress) -> Option<MemHookAddress> {
        if let Some(entry) = self.pending.lock().unwrap().remove_entry(&addr) {
            return Some(entry.0);
        }
        None
    }

    /// How many hooks are not yet processed?
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

#[derive(Debug, Eq, PartialEq, Hash)]
pub(crate) enum AccessKind {
    // we currently only track write-memorys
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
        write!(f, "{}", x)
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
            8 => u64::from_le_bytes(data[0..4].try_into().unwrap()) as MemHookValue,
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
