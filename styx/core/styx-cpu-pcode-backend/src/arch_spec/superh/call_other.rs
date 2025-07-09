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
