// SPDX-License-Identifier: BSD-2-Clause
use styx_processor::hooks::HookToken;

use std::fmt::Debug;

pub struct HookContainer<H> {
    pub callback: H,
    pub token: HookToken,
}
#[derive(derive_more::Debug)]
pub(crate) struct HookBucket<H>(Vec<HookContainer<H>>);
impl<H> Default for HookBucket<H> {
    fn default() -> Self {
        Self(Vec::new())
    }
}
impl<T> Debug for HookContainer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hook({:?})", self.token)
    }
}

impl<H> HookBucket<H> {
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
    /// Iterate over the hooks in this bucket if `address` falls in their address range.
    pub fn activate(&mut self) -> impl Iterator<Item = &mut HookContainer<H>> {
        self.0.iter_mut()
    }

    /// Add a hook to this bucket that that is activated when a given address is in `address_range`.
    pub fn add_hook(&mut self, token: HookToken, callback: H) {
        let new_hook = HookContainer { callback, token };
        self.0.push(new_hook);
    }

    pub(crate) fn num_hooks(&self) -> usize {
        self.0.len()
    }
}
