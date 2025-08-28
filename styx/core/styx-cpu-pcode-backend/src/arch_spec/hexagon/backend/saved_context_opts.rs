// SPDX-License-Identifier: BSD-2-Clause
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
use log::trace;
use smallvec::{smallvec, SmallVec};
use styx_pcode_translator::ContextOption;

use crate::{arch_spec::generator_helper::CONTEXT_OPTION_LEN, pcode_gen::GeneratePcodeError};

use super::{PacketLocation, PktState};
#[derive(Debug)]
pub struct SavedContextOpts {
    start: Vec<ContextOption>,
    end: Vec<ContextOption>,
    next_instr: Vec<ContextOption>,
    now: Vec<ContextOption>,

    setup_context_opts: Option<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>>,
}

impl Default for SavedContextOpts {
    fn default() -> Self {
        Self {
            start: Vec::with_capacity(20),
            end: Vec::with_capacity(20),
            next_instr: Vec::with_capacity(20),
            now: Vec::with_capacity(20),
            setup_context_opts: None,
        }
    }
}

impl SavedContextOpts {
    // Move next instruction context options to the current
    pub fn advance_instr(&mut self) {
        // This prevents now instructions set previously from being re-used later
        self.now.clear();

        self.now.extend_from_slice(&self.next_instr);
        self.next_instr.clear();
    }

    pub fn update_context(&mut self, when: PacketLocation, what: ContextOption) {
        match when {
            PacketLocation::Now => self.now.push(what),
            PacketLocation::NextInstr => self.next_instr.push(what),
            PacketLocation::PktStart => self.start.push(what),
            PacketLocation::PktEnd => self.end.push(what),
        }
    }

    pub fn setup_context_opts(&mut self, decode_location: &PktState) {
        trace!("current context opts saved are {self:?}");
        self.setup_context_opts = Some(smallvec![]);
        match decode_location {
            PktState::PktStartedFirstDuplex(_) | PktState::PktStarted(_) => {
                self.setup_context_opts
                    .as_mut()
                    .unwrap()
                    .extend_from_slice(&self.start);
                self.start.clear();
            }
            PktState::PktEnded(_) => {
                self.setup_context_opts
                    .as_mut()
                    .unwrap()
                    .extend_from_slice(&self.end);
                self.end.clear();
            }
            PktState::PktStandalone(_) => {
                let ctxopts = self.setup_context_opts.as_mut().unwrap();
                ctxopts.extend_from_slice(&self.start);
                ctxopts.extend_from_slice(&self.end);
                self.start.clear();
                self.end.clear();
            }
            _ => {}
        }
    }

    pub fn get_context_opts(
        &mut self,
    ) -> Result<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>, GeneratePcodeError> {
        // self.now is cleared later, in order to avoid
        // stuff set past post-fetch from making it to the next instruction
        let mut immediate_context_opts = self
            .setup_context_opts
            .take()
            .expect("You cannot use this API without calling setup_context_opts first!");
        immediate_context_opts.extend_from_slice(&self.now);
        Ok(immediate_context_opts)
    }
}
