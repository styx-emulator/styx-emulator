// SPDX-License-Identifier: BSD-2-Clause
use styx_processor::hooks::{AddressRange, HookToken};

use std::fmt::Debug;
use std::ops::RangeBounds;

pub struct AddrHookContainer<H> {
    range: AddressRange,
    pub callback: H,
    pub token: HookToken,
}
impl<T> Debug for AddrHookContainer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hook({:X?}, {:?})", self.range, self.token)
    }
}

#[derive(derive_more::Debug)]
pub struct AddrHookBucket<H>(Vec<AddrHookContainer<H>>);
impl<H> Default for AddrHookBucket<H> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<H> AddrHookBucket<H> {
    /// Iterate over the hooks in this bucket if `address` falls in their address range.
    pub fn activate(&mut self, address: u64) -> impl Iterator<Item = &mut AddrHookContainer<H>> {
        self.0
            .iter_mut()
            .filter(move |hook_container| hook_container.range.contains(&address))
    }

    /// Returns Some if was deleted.
    pub fn delete_hook(&mut self, token_to_delete: HookToken) -> Option<()> {
        let maybe_match = self
            .0
            .iter()
            .enumerate()
            .find(|(_idx, hook)| hook.token == token_to_delete);

        if let Some((idx, _hook)) = maybe_match {
            self.0.remove(idx);
            Some(())
        } else {
            None
        }
    }

    /// Add a hook to this bucket that that is activated when a given address is in `address_range`.
    pub fn add_hook(&mut self, token: HookToken, address_range: AddressRange, callback: H) {
        let new_hook = AddrHookContainer {
            range: address_range,
            callback,
            token,
        };
        self.0.push(new_hook);
    }
}
