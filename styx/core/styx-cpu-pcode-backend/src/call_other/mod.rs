// SPDX-License-Identifier: BSD-2-Clause
use super::PCodeStateChange;
use crate::{
    arch_spec::HexagonPcodeBackend, memory::space_manager::HasSpaceManager,
    pcode_gen::HasPcodeGenerator, PcodeBackend,
};
use handlers::EmptyCallback;
use log::{trace, warn};
use std::{collections::HashMap, fmt::Debug, marker::PhantomData, str::FromStr};
use styx_pcode::{
    pcode::VarnodeData,
    sla::{SlaUserOps, UserOps},
};
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};
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

pub trait CallOtherCpu<T: CpuBackend>:
    CpuBackend + HasSpaceManager + HasPcodeGenerator<InnerCpuBackend = T>
{
}
impl CallOtherCpu<PcodeBackend> for PcodeBackend {}
impl CallOtherCpu<HexagonPcodeBackend> for HexagonPcodeBackend {}

type HandlerIndex = u64;

pub trait CallOtherCallback<T: CpuBackend>: Debug + Send + Sync {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError>;
}

/// Convenience new type for a Arc'd [CallOtherCallback].
#[derive(Debug)]
pub struct CallOtherHandler<T: CpuBackend>(Box<dyn CallOtherCallback<T>>);
impl<Q: CallOtherCallback<PcodeBackend> + 'static> From<Q> for CallOtherHandler<PcodeBackend> {
    fn from(value: Q) -> Self {
        CallOtherHandler(Box::new(value))
    }
}
impl<Q: CallOtherCallback<HexagonPcodeBackend> + 'static> From<Q>
    for CallOtherHandler<HexagonPcodeBackend>
{
    fn from(value: Q) -> Self {
        CallOtherHandler(Box::new(value))
    }
}

impl<T: CpuBackend> Default for CallOtherHandler<T> {
    fn default() -> Self {
        CallOtherHandler(Box::new(EmptyCallback))
    }
}

#[derive(Debug)]
pub struct CallOtherManager<Cpu: CpuBackend> {
    handlers: HashMap<HandlerIndex, CallOtherHandler<Cpu>>,
}

/// Handler store for [CallOtherHandler]s that can be triggered.
///
/// Handles can be triggered and added but not deleted.
#[derive(Debug)]
pub struct UninitCallOtherManager<Sla, Cpu: CpuBackend> {
    handlers: HashMap<HandlerIndex, CallOtherHandler<Cpu>>,
    sla: PhantomData<Sla>,
}

impl<Sla, Cpu: CpuBackend> Default for UninitCallOtherManager<Sla, Cpu> {
    fn default() -> Self {
        Self {
            handlers: Default::default(),
            sla: PhantomData,
        }
    }
}

impl<S: SlaUserOps, Cpu: CpuBackend> UninitCallOtherManager<S, Cpu> {
    pub fn init(self) -> CallOtherManager<Cpu> {
        CallOtherManager {
            handlers: self.handlers,
        }
    }

    pub fn add_handler(
        &mut self,
        user_op: S::UserOps,
        callback: impl Into<CallOtherHandler<Cpu>>,
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

impl<S: SlaUserOps<UserOps: FromStr>, Cpu: CpuBackend> UninitCallOtherManager<S, Cpu> {
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
        callback: impl Into<CallOtherHandler<Cpu>>,
    ) -> Result<(), AddCallOtherHandlerStrError> {
        let user_op = user_op.to_string();
        let value = S::UserOps::from_str(&user_op)
            .map_err(|_| AddCallOtherHandlerStrError::CallOtherNotFound(user_op.to_owned()))?;
        Ok(self.add_handler(value, callback)?)
    }
}

impl<Cpu: CpuBackend + 'static> CallOtherManager<Cpu> {
    /// Activate a CallOther handler with a specific index.
    ///
    /// `inputs` should be all the Varnodes excluding the first input denoting the CallOther index.
    ///
    /// The returned Option should be written to the output varnode in the CallOther operation.
    #[allow(clippy::too_many_arguments)]
    pub fn trigger(
        cpu: &mut dyn CallOtherCpu<Cpu>,
        call_other_manager: &mut CallOtherManager<Cpu>,
        isa_pc: u64,
        mmu: &mut Mmu,
        ev: &mut EventController,
        index: HandlerIndex,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherTriggerError> {
        trace!("Triggering CallOther index {index} with inputs {inputs:?}.");

        let handler_ptr = call_other_manager
            .handlers
            .get_mut(&index) .ok_or(CallOtherTriggerError::HandleDoesNotExist(index))
            .tap_err(|_| {
                let name = cpu.pcode_generator().user_op_name(index as u32);
                warn!(
                    "Handle index {index} (name: {name:?}) does not exist. Called with: {inputs:?} -> {output:?} @ 0x{isa_pc:x}"
                )
            })?;
        let mut handle = std::mem::take(handler_ptr);

        let res = handle.0.handle(cpu, mmu, ev, inputs, output);
        let handler_ptr = call_other_manager
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
