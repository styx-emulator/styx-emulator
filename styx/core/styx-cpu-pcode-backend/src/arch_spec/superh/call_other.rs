// SPDX-License-Identifier: BSD-2-Clause
use styx_pcode::pcode::VarnodeData;

use log::debug;
use styx_processor::{event_controller::EventController, memory::Mmu};

use crate::{
    call_other::{CallOtherCallback, CallOtherHandleError},
    PCodeStateChange, PcodeBackend,
};

/// `Sleep_Standby` instruction
///
/// Used by SH1 SH2 and SH2A
#[derive(Debug)]
pub struct SleepStandby;

impl CallOtherCallback for SleepStandby {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for SinHandler {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for CosHandler {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for InvalidateCacheBlock {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for LoadTranslationLookasideBuffer {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for Macl0pHandler {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for Macw0pHandler {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for CacheBlockInvalidate {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for CacheBlockPurge {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for CacheBlockWriteBack {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for SynchronizeDataOperation {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
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

impl CallOtherCallback for TrapAlways {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        todo!("SuperH4: TrapAlways pcodeop")
    }
}
