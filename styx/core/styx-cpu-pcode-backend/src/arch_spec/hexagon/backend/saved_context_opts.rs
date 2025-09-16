// SPDX-License-Identifier: BSD-2-Clause
use log::trace;
use smallvec::{smallvec, SmallVec};
use styx_pcode_translator::ContextOption;

use crate::arch_spec::generator_helper::CONTEXT_OPTION_LEN;

use super::{HexagonFetchDecodeError, PacketLocation, PktState};

const SAVED_OPTION_LEN: usize = 20;

/// A helper for context options. This is useful for architectures where we may know what
/// context options to set for a future instruction _now_. This structure allows you to effectively
/// annotate "when" a context option should be set relative to right now, and SavedContextOpts will
/// make sure the context option you indicated now will be set later.
///
/// An example of this in Hexagon: a packet that terminates a hardware loop in Hexagon must have certain
/// Parse bits set to indicate which type of hardware loop is terminated (Table 10-7). We know what type of
/// hardware loop (hwloop0, hwloop1, see section 8.2) is at the beginning of the packet (first instruction), but
/// the context option corresponding to this information should only be set for the last instruction in
/// the packet. As such, we can indicate to SavedContextOpts at the time of the _first_ instruction in the packet
/// that the _last_ instruction in the packet should have the "endloop" context option set. When we finally get
/// around to the end of the packet, SavedContextOpts will make sure to indicate the "endloop" instruction
/// we marked at the beginning of the packet is set now.
///
/// There are four "times" that a caller can specify to set a context option:
///
/// **Now** - when we retreive context options for the _current_ instruction, this context option will be set.
///
/// **Next instruction** - this context option will be set for the next instruction. See example above.
///
/// **Packet start** - this context option will be set when at the next time a packet ends.
/// If this is set in the middle of a packet, then this will be set at the start of the next packet.
///
/// **Packet end** - this context option will be set when at the next time a packet ends
///
/// The caller first sets context options with `SavedContextOpts::update_context`. Then the caller indicates
/// a point in execution with `SavedContextOpts::setup_context_opts`. This flushes out the values stored in the buffers
/// `start`, `end`, `next_instr`, and `now` to the `setup_context_opts` variable, which is the buffer of aggregate
/// context options that will ultimately be fed into Sleigh.
///
/// Once `SavedContextOpts::setup_context_opts` is called, the caller is free to retrieve the aggregate context options
/// with `SavedContextOpts::get_context_opts`. These functions are separated because we might want to call `setup_context_opts`
/// to flush out the various context option buffers (start/end/next_instr/etc.) before calling hooks that update these four buffers.
///
/// For example, calling `setup_context_opts` at the start of a packet will move the start of packet context options to
/// `setup_context_opts`, but then based on information at the start of the packet we may want to set information
/// for the _next_ start of packet (but at the same time keep adding to context options for *now*). Separating `setup_context_opts`
/// and `get_context_opts` achieves this.
#[derive(Debug)]
pub struct SavedContextOpts {
    start: SmallVec<[ContextOption; SAVED_OPTION_LEN]>,
    end: SmallVec<[ContextOption; SAVED_OPTION_LEN]>,
    next_instr: SmallVec<[ContextOption; SAVED_OPTION_LEN]>,
    now: SmallVec<[ContextOption; SAVED_OPTION_LEN]>,

    setup_context_opts: Option<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>>,
}

impl Default for SavedContextOpts {
    fn default() -> Self {
        Self {
            start: SmallVec::new(),
            end: SmallVec::new(),
            next_instr: SmallVec::new(),
            now: SmallVec::new(),
            setup_context_opts: None,
        }
    }
}

impl SavedContextOpts {
    /// If instruction 1 sets a context option that should take effect for instruction 2,
    /// when `advance_instr` is called, the context options explicitly stored for
    /// the next instruction (instruction 2) will be moved to the context options
    /// for the current instruction.
    ///
    /// This is useful for instructions like duplexes, where we know both the first sub-instruction's
    /// sub-instruction type and the second sub-instructions' sub-instruction type, so we can
    /// set both the current sub-instruction type and the next instruction's sub-instruction type
    /// context option.
    pub fn advance_instr(&mut self) {
        // This prevents now instructions set previously from being re-used later
        self.now.clear();
        self.now.append(&mut self.next_instr);
    }

    /// Allows the caller to indicate that a certain context option `what `should be set
    /// when execution reaches the point specified by `when`.
    pub fn update_context(&mut self, when: PacketLocation, what: ContextOption) {
        match when {
            PacketLocation::Now => self.now.push(what),
            PacketLocation::NextInstr => self.next_instr.push(what),
            PacketLocation::PktStart => self.start.push(what),
            PacketLocation::PktEnd => self.end.push(what),
        }
    }

    /// Populates the setup context ops based on current packet state.
    ///
    /// Clears the context ops of the state retrieved from.
    pub fn setup_context_opts(&mut self, decode_location: &PktState) {
        trace!("current context opts saved are {self:?}");
        self.setup_context_opts = Some(smallvec![]);
        match decode_location {
            PktState::PktStartedFirstDuplex(_) | PktState::PktStarted(_) => {
                self.setup_context_opts
                    .as_mut()
                    .unwrap()
                    .append(&mut self.start);
            }
            PktState::PktEnded(_) => {
                self.setup_context_opts
                    .as_mut()
                    .unwrap()
                    .append(&mut self.end);
            }
            PktState::PktStandalone(_) => {
                let ctxopts = self.setup_context_opts.as_mut().unwrap();
                ctxopts.append(&mut self.start);
                ctxopts.append(&mut self.end);
            }
            _ => {}
        }
    }

    /// Gets stored context ops staged by setup_context_ops, including reminaing context options
    /// that are set to take effect for the current instruction
    pub fn get_context_opts(
        &mut self,
    ) -> Result<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>, HexagonFetchDecodeError> {
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
