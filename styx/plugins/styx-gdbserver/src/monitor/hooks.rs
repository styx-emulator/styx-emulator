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
use super::common::*;

/// View and list hooks.
///
/// Example:
///
/// ```console
///     (gdb) watch *(int *)0x2000fffc == 0xffffffff
///     Hardware watchpoint 1: *(int *)0x2000fffc == 0xffffffff
///     (gdb) watch *(int *)0x2000fff0
///     Hardware watchpoint 2: *(int *)0x2000fff0
///     (gdb) monitor hooks
///     Mem Hooks: 0
///     Pending:   0
/// ```
#[derive(Parser, Clone)]
#[command(name = "hooks", verbatim_doc_comment)]
pub(super) struct HooksCommand;

impl SubcommandRunnable for HooksCommand {
    fn run<GdbArchImpl>(
        &self,
        target: &mut TargetImpl<'_, GdbArchImpl>,
        out: &mut ConsoleOutput<'_>,
    ) -> Result<(), UnknownError>
    where
        GdbArchImpl: gdbstub::arch::Arch,
        GdbArchImpl::Registers: GdbRegistersHelper,
        GdbArchImpl::RegId: GdbArchIdSupportTrait,
    {
        let mut s = format!("Mem Hooks: {}\n", target.mem_hook_cache.tracked_len());
        s.push_str(&format!(
            "Pending:   {}\n",
            target.mem_hook_cache.pending_len()
        ));
        outputln!(out, "{}", s);
        Ok(())
    }
}
