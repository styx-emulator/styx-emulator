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
