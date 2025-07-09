// SPDX-License-Identifier: BSD-2-Clause
use styx_cpu_type::arch::backends::ArchRegister;
use styx_processor::hooks::HookToken;

use std::fmt::Debug;

pub struct RegisterHookContainer<H> {
    register: ArchRegister,
    pub callback: H,
    pub token: HookToken,
}
impl<T> Debug for RegisterHookContainer<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hook({:X?}, {:?})", self.register, self.token)
    }
}

#[derive(derive_more::Debug)]
pub struct RegisterHookBucket<H>(Vec<RegisterHookContainer<H>>);
impl<H> Default for RegisterHookBucket<H> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<H> RegisterHookBucket<H> {
    /// Iterate over the hooks in this bucket if `address` falls in their address range.
    pub fn activate(
        &mut self,
        register: ArchRegister,
    ) -> impl Iterator<Item = &mut RegisterHookContainer<H>> {
        self.0.iter_mut().filter(move |r| r.register == register)
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

    pub fn add_hook(&mut self, token: HookToken, register: ArchRegister, callback: H) {
        let new_hook = RegisterHookContainer {
            register,
            callback,
            token,
        };
        self.0.push(new_hook);
    }
}
