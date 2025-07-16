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
use super::PCodeStateChange;
use crate::{arch_spec::ArchPcManager, PcodeBackend};
use handlers::EmptyCallback;
use log::{trace, warn};
use std::{collections::HashMap, fmt::Debug, marker::PhantomData, str::FromStr};
use styx_pcode::{
    pcode::VarnodeData,
    sla::{SlaUserOps, UserOps},
};
use styx_processor::{event_controller::EventController, memory::Mmu};
use tap::TapFallible;
use thiserror::Error;

pub mod handlers;

#[derive(Error, Debug)]
pub enum CallOtherHandleError {
    #[error("generic error: {0}")]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Error, Debug)]
pub enum CallOtherTriggerError {
    #[error(transparent)]
    CallOtherHandleError(#[from] CallOtherHandleError),
    #[error("handle does not exist {0}")]
    HandleDoesNotExist(HandlerIndex),
}

type HandlerIndex = u64;
pub trait CallOtherCallback: Debug + Send + Sync {
    fn handle(
        &mut self,
        cpu: &mut PcodeBackend,
        mmu: &mut Mmu,
        ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError>;
}

/// Convenience new type for a Arc'd [CallOtherCallback].
#[derive(Debug)]
pub struct CallOtherHandler(Box<dyn CallOtherCallback>);
impl<T: CallOtherCallback + 'static> From<T> for CallOtherHandler {
    fn from(value: T) -> Self {
        CallOtherHandler(Box::new(value))
    }
}

impl Default for CallOtherHandler {
    fn default() -> Self {
        EmptyCallback.into()
    }
}

#[derive(Debug)]
pub struct CallOtherManager {
    handlers: HashMap<HandlerIndex, CallOtherHandler>,
}

/// Handler store for [CallOtherHandler]s that can be triggered.
///
/// Handles can be triggered and added but not deleted.
#[derive(Debug)]
pub struct UninitCallOtherManager<Sla> {
    handlers: HashMap<HandlerIndex, CallOtherHandler>,
    sla: PhantomData<Sla>,
}

impl<Sla> Default for UninitCallOtherManager<Sla> {
    fn default() -> Self {
        Self {
            handlers: Default::default(),
            sla: PhantomData,
        }
    }
}

impl<S: SlaUserOps> UninitCallOtherManager<S> {
    pub fn init(self) -> CallOtherManager {
        CallOtherManager {
            handlers: self.handlers,
        }
    }

    pub fn add_handler(
        &mut self,
        user_op: S::UserOps,
        callback: impl Into<CallOtherHandler>,
    ) -> Result<(), AddCallOtherHandlerError> {
        let new_idx = user_op.index();
        match self.handlers.get(&new_idx) {
            Some(_) => return Err(AddCallOtherHandlerError::HandlerAlreadyExists(new_idx)),
            None => {
                let handler = callback.into();
                trace!("Adding CallOtherHandler {handler:?} as index {user_op:?}");
                self.handlers.insert(new_idx, handler);
            }
        };

        Ok(())
    }
}

impl<S: SlaUserOps<UserOps: FromStr>> UninitCallOtherManager<S> {
    /// The same as [`Self::add_handler()`] but accepts a string `user_op`.
    ///
    /// This is used to allow `add_handler` code to be reusable across multiple sla specs while
    /// still maintaining *most* of the safety. It will find the [`UserOps`] that matches the passed
    /// string.
    ///
    /// The recommended way to use this is to pass a [`UserOps`] from a different sla (they
    /// implement [`ToString`]) which inherits the same sinc with the user op.
    pub fn add_handler_other_sla(
        &mut self,
        user_op: impl ToString,
        callback: impl Into<CallOtherHandler>,
    ) -> Result<(), AddCallOtherHandlerStrError> {
        let user_op = user_op.to_string();
        let value = S::UserOps::from_str(&user_op)
            .map_err(|_| AddCallOtherHandlerStrError::CallOtherNotFound(user_op.to_owned()))?;
        Ok(self.add_handler(value, callback)?)
    }
}

impl CallOtherManager {
    /// Activate a CallOther handler with a specific index.
    ///
    /// `inputs` should be all the Varnodes excluding the first input denoting the CallOther index.
    ///
    /// The returned Option should be written to the output varnode in the CallOther operation.
    pub fn trigger(
        cpu: &mut PcodeBackend,
        mmu: &mut Mmu,
        ev: &mut EventController,
        index: HandlerIndex,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherTriggerError> {
        trace!("Triggering CallOther index {index} with inputs {inputs:?}.");

        let handler_ptr = cpu.call_other_manager
            .handlers
            .get_mut(&index) .ok_or(CallOtherTriggerError::HandleDoesNotExist(index))
            .tap_err(|_| {
                let name = cpu.pcode_generator.user_op_name(index as u32);
                warn!(
                    "Handle index {index} (name: {name:?}) does not exist. Called with: {inputs:?} -> {output:?} @ 0x{:x}",
                    cpu.pc_manager.as_ref().unwrap().isa_pc()
                )
            })?;
        let mut handle = std::mem::take(handler_ptr);

        let res = handle.0.handle(cpu, mmu, ev, inputs, output);
        let handler_ptr = cpu
            .call_other_manager
            .handlers
            .get_mut(&index)
            .expect("how is it gone now");
        *handler_ptr = handle;
        Ok(res?)
    }
}
#[derive(Error, Debug)]
pub enum AddCallOtherHandlerError {
    #[error("handler already exists at index {0}")]
    HandlerAlreadyExists(HandlerIndex),
}

#[derive(Error, Debug)]
pub enum AddCallOtherHandlerStrError {
    #[error("call other name not found {0}")]
    CallOtherNotFound(String),
    #[error(transparent)]
    AddCallOtherHandlerError(#[from] AddCallOtherHandlerError),
}
