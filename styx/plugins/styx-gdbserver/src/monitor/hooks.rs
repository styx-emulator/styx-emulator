// SPDX-License-Identifier: BSD-2-Clause
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
