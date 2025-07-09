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
//! HookToken:
//!     a unique identifier for an installed hook
//! HookTypeMap:
//!     a hashtable that uses HookToken as a key, stores installed hook meta-data
//! HookDescriptor:
//!     holds hook meta-data needed for executing callbacks, etc.
//!
//! Adding a hook to a CPU backend returns a HookToken
//! Removing a hook takes a HookToken as input
use derivative::Derivative;
use std::collections::HashMap;
use std::fmt::Debug;
use styx_errors::{anyhow::anyhow, UnknownError};
use styx_processor::hooks::{DeleteHookError, HookToken, StyxHook};

use crate::CorePointers;

/// Holds necessary info about installed hook to handle callbacks
#[derive(Derivative)]
#[derivative(Debug)]
pub struct StyxHookDescriptor {
    #[derivative(Debug = "ignore")]
    pub styx_hook: StyxHook,
    pub core: *mut CorePointers,
}

/// This is a map that works off of the generated [`HookToken`]'s provided by a cpu engine when
/// installing target runtime hooks. This map is a store that allows the runtime to hold the
/// requisite metadata required to route and handle the hook callbacks, and be able to fetch and
/// delete hooks as needed.
///
/// For examples, see [crate::UnicornBackend]'s implementation of `code_hook()` or related methods.
#[derive(Debug, Default)]
pub struct StyxHookMap {
    /// A [`HashMap<HookToken, Box<StyxHookDescriptor>>`] of the token returned
    /// from adding the target hook, and the actual [`StyxHookDescriptor`]
    /// that contains all relevant proxy jumps and metadata about the
    /// specified hook.
    inner: HashMap<HookToken, Box<StyxHookDescriptor>>,
}

// note that this is actually really unsafe, and is only "safe"
// because the usage is wrapped in an `Arc<Mutex<>>`
unsafe impl Send for StyxHookMap {}
unsafe impl Sync for StyxHookMap {}

impl StyxHookMap {
    /// Simple pass-through method to check if a hook is included in
    /// the map
    #[inline]
    pub fn contains_hook(&self, token: HookToken) -> bool {
        self.inner.contains_key(&token)
    }

    /// Adds a new hook to the inner map. The hook token must be a non null
    /// pointer type that is not in the hook map yet, otherwise an unknown error will be thrown.
    pub fn add_hook(
        &mut self,
        token: HookToken,
        entry: Box<StyxHookDescriptor>,
    ) -> Result<(), UnknownError> {
        valid_hook(token)?;

        // if `entry` is  in self.map.keys then bail
        if self.contains_hook(token) {
            return Err(anyhow!("token pointer must be unique in the hook map"));
        }

        // we don't have this hook already, so add it
        _ = self.inner.insert(token, entry);

        Ok(())
    }

    /// Given a hook with a [`HookToken`], delete the hook from the map
    ///
    /// Returns an error if hook wasn't in the map or if the inner pointer is null.
    pub fn delete_hook(&mut self, token: HookToken) -> Result<(), DeleteHookError> {
        valid_hook(token)?;

        // return bool if item was removed (previously in the map)
        if self.inner.remove_entry(&token).is_none() {
            return Err(DeleteHookError::HookDoesNotExist);
        }
        Ok(())
    }
}

/// Is the hook valid for use in the unicorn backend?
///
/// The hook must be:
///   - Pointer type
///   - non null
///
/// Otherwise an error is returned;
fn valid_hook(token: HookToken) -> Result<(), UnknownError> {
    let HookToken::Pointer(ptr) = token else {
        return Err(anyhow!("token must be a pointer"));
    };
    // if inner pointer is null return error
    if ptr.is_null() {
        return Err(anyhow!("token pointer must not be null"));
    }
    Ok(())
}
