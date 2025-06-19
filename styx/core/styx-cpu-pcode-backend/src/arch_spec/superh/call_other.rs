// SPDX-License-Identifier: BSD-2-Clause
use styx_pcode::pcode::VarnodeData;

use log::debug;
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange,
};

/// `Sleep_Standby` instruction
///
/// Used by SH1 SH2 and SH2A
#[derive(Debug)]
pub struct SleepStandby;

impl<T: CpuBackend> CallOtherCallback<T> for SleepStandby {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("Sleep_Standby called");

        Ok(PCodeStateChange::Fallthrough)
    }
}

//
// ALL CALLOTHERS BELOW THIS LINE ARE FOR SUPERH4 (As of this writing)
//
#[derive(Debug)]
pub struct SinHandler;

impl<T: CpuBackend> CallOtherCallback<T> for SinHandler {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        todo!("Sin Handler")
    }
}

#[derive(Debug)]
pub struct CosHandler;

impl<T: CpuBackend> CallOtherCallback<T> for CosHandler {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        todo!("Cos Handler")
    }
}

#[derive(Debug)]
pub struct InvalidateCacheBlock;

impl<T: CpuBackend> CallOtherCallback<T> for InvalidateCacheBlock {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("InvalidateCacheBlock");

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct LoadTranslationLookasideBuffer;

impl<T: CpuBackend> CallOtherCallback<T> for LoadTranslationLookasideBuffer {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("LoadTranslationLookasideBuffer");

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct Macl0pHandler;

impl<T: CpuBackend> CallOtherCallback<T> for Macl0pHandler {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        todo!("Macl0p Handler")
    }
}

#[derive(Debug)]
pub struct Macw0pHandler;

impl<T: CpuBackend> CallOtherCallback<T> for Macw0pHandler {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        todo!("Macw0p Handler")
    }
}

#[derive(Debug)]
pub struct CacheBlockInvalidate;

impl<T: CpuBackend> CallOtherCallback<T> for CacheBlockInvalidate {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("CacheBlockInvalidate");

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct CacheBlockPurge;

impl<T: CpuBackend> CallOtherCallback<T> for CacheBlockPurge {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("CacheBlockPurge");

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct CacheBlockWriteBack;

impl<T: CpuBackend> CallOtherCallback<T> for CacheBlockWriteBack {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("CacheBlockWriteBack");

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct SynchronizeDataOperation;

impl<T: CpuBackend> CallOtherCallback<T> for SynchronizeDataOperation {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("SynchronizeDataOperation");

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct TrapAlways;

impl<T: CpuBackend> CallOtherCallback<T> for TrapAlways {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        todo!("SuperH4: TrapAlways pcodeop")
    }
}
