
.. _parallel_execution_backend__rfc:

3. Parallel Execution Backend
###############################

Parallel Execution Backend
============================

Status: Draft

Summary
=======

In order to support proper Hexagon ISA instruction emulation, we need a new parallel / packet based pcode execution backend. Currently we revolve around the more traditional serial based execution patterns.
As this is the vast majority of emulation targets we have experience with, a lot of decisions may have unintentionally backed us into a corner in our prior designs. This attempts to rectify that through a new parallel pcode backend.

Motivation
==========

Packet based Instruction Set Architectures (ISA's) require extensive support to perform instruction reordering
and register banking + committing like real parallel execution pipelines. These architectures have packets
submitted to the execution engine and have all side effects committed *after* the packet is completed.

We currently only support serial instruction execution, even in the Blackfin case which has concurrent
instruction execution support, there is not a consistent need to re-order and commit register state that
could be overridden mid-"packet" or instruction execution. Hexagon (and others eg. TMS320Cxxx) require
this ability.

We want to make supporting these ISA's straightforward, so we need a new Pcode backend, otherwise we would
be forced to pay extensive performance hits across all architecture implementations.


Details
=======

TLDR; Move from a PcodeBackend to ParallelPcodeBackend, which aggregates pcodes till the end of a packet, then calls a sequence hook to generate the correct re-ordered sequence, and finally execute the pcodes in the order provided.

We have combined the hooks from GeneratorHelper and PcManager in order to simplify complexities with previous shared state. However, we could keep them separate and require that a ParallelExecutionHelper implement both the PcManager and GeneratorHelper traits. A DecodeReport used in post_insn_fetch is useful for dotnew, which requires us to know and keep track of the output registers for each instruction.

A major change is how context registers get set with this. Oftentimes in Hexagon decoding we need to look at a current instruction in and make a change based on this later. In order to deal with this, we now allow hooks to indicate when a context register should be set. An example of when this is useful is dealing with hardware loops. For hardware loops, at the beginning of a packet, we look at the current and next instruction, and then depending on the "parse" bits, we wish to set the Hasloop and Endloop context variables explicitly at the end of the packet. This would now look like backend.update_context(PacketLocation::PktEnd, ContextOption::HexagonHasloop...) at the beginning of the packet: no need to deal with storing this statefully till the end of the packet and such.

There are likely many other places where this is useful, such as with duplex instructions, where we can signal backend.update_context(PacketLocation::NextInsn, ContextOption::HexagonSubinsn(next_subinsn)) and not have to store the duplex instruction in a HashMap.


Potential example pseudocode follows:

.. code:: rust

    pub enum PktState {
        PktStarted,
        InsidePacket
        PktEnded
    }

    pub enum PacketLocation {
        PktStart,
        PktEnd,
        NextInstr,
        Now
    }

    struct SavedContextOpts {
        start: Vec<ContextOption>,
        end: Vec<ContextOption>,
        next_instr: Vec<ContextOption>,
        now: Vec<ContextOption>,
    }

    impl SavedContextOpts {
        // Move next instruction context options to the current
        pub fn advance_instr(&mut self) {
            // This prevents now instructions set previously from being re-used later
            self.now.clear();

            self.now.extend_from_slice(self.next_insn);
            self.next_instr.clear();
        }

        pub fn get_context_opts(&self, decode_location: PktState) {
            let mut immediate_context_opts = vec![];
            match decode_state {
                PktState::PktStarted => {
                    immediate_context_opts.extend_from_slice(self.start);
                    self.start.clear();
                }
                PktState::PktEnded => {
                    immediate_context_opts.extend_from_slice(self.end);
                    self.end.clear();
                }
                _ => {}
            }

            // self.now is cleared later, in order to avoid
            // stuff set past post-fetch from making it to the next instruction
            immediate_context_opts.extend_from_slice(self.now);
        }

        pub fn update_context(&mut self, when: PacketLocation, what: ContextOption) {
            match when {
                PacketLocation::Now => self.now.push(what),
                PacketLocation::NextInstr => self.next_instr.push(what),
                PacketLocation::PktStart => self.start.push(what),
                PacketLocation::PktEnd => self.end.push(what),
            }
        }

    }

    pub struct HexagonPcodeBackend {
        internal_backend: PcodeBackend,
        execution_state: PktState,
        hook_state: HookState

        saved_context_opts: SavedContextOpts,
        regs_written: Vec<HexagonRegister>,

        pcodes: Vec<Vec<Pcode>>,
        ordering: Vec<usize>,
        ordering_location: usize,
    }

    impl HexagonPcodeBackend {
        // Indicate when we should update the context reg
        // and what the new value should be
        fn update_context(&mut self, when: PacketLocation, what: ContextOption) {
            // TODO: what to do when Now is set outside of prefetch?
            // current functionality is to clear all unset now instructions out.
            self.saved_context_opts.update_context(when, what);
        }
        pub fn execute_single(&mut self, pcodes: &mut Vec<Pcodes>) {
              match execute_pcode::execute_pcode(current_pcode, self.internal_backend, mmu, ev, &mut regs_written) {
                 /* Stuff goes here */
              }
        }
        // This is for debugging packet bounaries and such.
        // A whole packet is parsed, and then execute_instrs is called.
        // If this is called at a packet boundary, a fully packet will be parsed
        pub fn execute_instrs(&mut self, instrs: usize) {
            for i in 0..instrs {
                // If we have exhausted all the instructions, then move on to the next
                // packet
                if self.ordering_location >= self.ordering.len() {
                    self.execution_helper.post_packet_execute(self);
                    self.fetch_decode_packet();
                }

                let i_instrs = self.ordering[self.ordering_location];
                let instrs = self.pcodes[i_instrs];

                self.execute_single(instrs);
                self.ordering_location += 1;
            }

            self.ordering_location = 0;
        }

        pub fn execute_packets(&mut self, pkts: usize) {
            // Can't start executing packets after a packet has started or whatnot.
            for i in 0..pkts {
                    self.fetch_decode_packet();
                    // We update this in case of an error?
                    for i_pcode in ordering {
                        self.execute_single(self.pcodes[i_pcode])?;
                        self.ordering_location += 1;
                    }
                    self.execution_helper.post_packet_execute(self);
            }
        }

        fn fetch_decode_packet(&mut self) {
            assert_eq!(self.ordering_location, 0);

            self.regs_written.clear();
            self.pcodes.clear();

            let mut decode_state = PktState::PktStarted;
            while decode_state != PktStart::PktEnded {
                // Pseudocode
                decode_state = self.execution_helper.pre_insn_fetch(self)?;

                match decode_state {
                    PktState::PktStarted => self.execution_helper.pkt_started(self)
                    PktState::InsidePacket => self.execution_helper.pkt_inside(self)
                    PktState::PktEnded => self.execution_helper.pkt_ended(self)
                }

                // The immediate_context_opts should be applied after this from
                // self.saved_context_opts.get_context_opts(decode_state) or something.

                let pcodes = vec![];

                // TODO: Apply context options that were set across this. Because this uses the PcodeBackend behind
                // the scenes, we might need some sort of dummy generator helper/pc manager implementation that
                // that internally accesses/uses the current context opts
                //
                // Somehow we need to modify this stuff to take in the context options we care about.
                let bytes_consumed = match fetch_pcode(self, &mut pcodes, mmu, ev, self.saved_context_opts.get_context_opts(decode_state))? {
                    Ok(success) => success,
                    Err(exit) => return Ok(Err(exit)),
                };

                self.pcodes.push(pcodes);
                self.execution_helper.post_insn_fetch(bytes_consumed, self.internal_backend)?;
                self.saved_context_opts.advance_instr();
            }

            // This hook may be useful for register flushing/banking
            self.execution_helper.post_packet_fetch(self);
            self.ordering = self.execution_helper.sequence(&self.pcodes);
            self.ordering_location = 0;
        }
    }

    pub trait ParallelExecutionHelper {
        // This is only called during execution, not decoding.
        fn isa_pc(&self) -> u64 {}
        fn internal_pc(&self) -> u64 {}
        fn set_isa_pc(&mut self, value: u64, backend: &mut HexagonPcodeBackend) {}
        fn set_internal_pc(&mut self, value: u64, backend: &mut HexagonPcodeBackend, from_branch: bool) {}
        fn post_packet_execute(
            &mut self,
            _backend: &mut HexagonPcodeBackend,
        ) -> Result<(), PcOverflow> {}

        // During decoding
        fn pre_insn_fetch(&mut self, _backend: &mut HexagonPcodeBackend, mmu: &mut Mmu) -> Result<PktState, GeneratePcodeError> {}
        fn post_insn_fetch(&mut self,
            _bytes_consumed: u64,
            _backend: &mut HexagonPcodeBackend) {}

        fn post_packet_fetch(&mut self, backend: &mut HexagonPcodeBackend) {}
        fn pkt_started(&mut self, backend: &mut HexagonPcodeBackend) {}
        fn pkt_inside(&mut self, backend: &mut HexagonPcodeBackend) {}
        fn pkt_ended(&mut self, backend: &mut HexagonPcodeBackend) {}

        // Returns indices in the order of execution
        fn sequence(&mut self, pkt: &Vec<Vec<Pcodes>>) -> Vec<usize>;

    }



A few points:

* Added a post packet fetch instruction. I don't know what the point of this is, but maybe this is a location where the pcodes could be modified to add the register flushing afterwards (slaspec will never know exactly which registers were written, and indiscriminately copying all dest regs to regular regs every end of packet is super inefficient). However, the backend itself could do this without needing this hook, so we can remove this.
* Having single instruction execution is useful for intricate testing and debugging, and that is sometimes exploited in the test cases. I think keeping this would be good, at the cost of a small amount of complexity. This complexity is presented in the ``ordering_location`` variable that keeps track of where we are in the order array. Once the ``ordering_location`` goes past the current stored ordering, a new packet is fetched and decoded. You can see this in ``execute_insns``.
* The ``execute_packets`` instruction just executes packets by executing the pcodes in order that was determined by the sequencer. There's a case to be made of just concatenating the pcodes into one gigantic vec in the right order and executing the whole thing at once, but not clear.
* Re-implementing the functionality in ``styx/core/styx-cpu-pcode-backend/src/{get_pcode.rs,execute_pcode.rs}`` sounds like a lot of extra work that I think should be avoided. I'm wondering if maybe either the functions in there can be decoupled from the default ``PcodeBackend``, or if I can just store a separate ``PcodeBackend`` in this backend and call on it where necessary, or genericize/decouple the ``PcodeBackend`` in these two files so we can drop in ours. Right now I'm storing a ``PcodeBackend`` in this structure.
* This may have some implementation detail differences for setting ContextOptions, but hopefully some conclusion can be made from this.
* The ``fetch_decode_packet`` in human terms is supposed to just clear out any state used for decoding a packet, then call prefetch hooks, set context options, get pcodes, call more hooks, then setup any context options (that use ``PacketLocation::NextInsn``) for the next packet, and repeat till we reach the end of the packet. Then, call sequence and the post fetch instruction, and done.


Other Thoughts:
---------------

* I don't understand  `execute_insns` (change to `instr` btw). It takes a number of instructions to execute but it's unclear if this is total instructions or per packet instructions.
* `saved_context_opts` should probably be a struct with members `start`, `end`, etc. The hashmap thing is unintuitive to use and should probably be reworked
* Instead of `execute_pkts` with a number of packets, I would stick number of instructions. so executing 1000 instructions might be 1003 instructions if instruction 1000 is a 4 instr packet for example.
* Hooks can set the PC. What's the behavior if a hook in the middle of a packet sets the pc outside of the current packet?
* the more and more I think about the CoreHandle the more I want it separate from the CpuBackend. I.e. I want the CpuBackend to be owned by the Processor, then in a hook, the CoreHandle is given a "proxy" implementation of the CpuBackend that has custom logic to interact with the true CpuBackend. In this case it could error on Pc write for instance, or maybe it could buffer register reads/writes until after the packet. Either way, I find myself wishing that the hooks don't require full mutable access to the whole cpu.
* Is it possible to move most of the execution state inside some of these methods instead of on the struct? This way there could be less state to manage between calls to `execute` and you don't have to worry about sharing mutable access to Cpu. You could also put them in an Ordering struct or similar with helper methods. This could also make a nice Debug print to show the state of the packet
* nit: I suspect the `sequence` method would be more performant if you reordered the instructions in place. This would be 16 byte copies instead of an allocation every packet. Allocations in the hot loop are incredibly slow I have found

get_pcode / execute_pcode
-------------------------

I have tried to decouple execute_pcode_inner using traits as I can but Rust does not make it easy.

* The two options I see are either Traits, as I have tried in execute_pcode_inner, or by composition. The reason I didn't try composition is that we have a lot of components in the pcode backend so function signatures would get very unwieldy. The solution to that I think is to reorganize into better structures that can be separated.

PC semantics with internal/ISA pc
---------------------------------

*currently* the internal pc is updated every time an instruction within a packet has finished executing (in the post execute hook), and the ISA pc is updated at packet boundaries. To be more clear, say we start at 0x1000 and have packet sequence `{ A; B; C; D }`. If there are no duplexes, the PCs are currently going to look like:::

    Before A: 0x1000 (internal) 0x1000 (isa)
    After A: 0x1004 (internal) 0x1000 (isa)
    After B: 0x1008 (internal) 0x1000 (isa)
    After C: 0x100C (internal) 0x1000 (isa)
    After D: 0x1010 (internal) 0x1010 (isa)

The PC updating right now is in `post_execute`, which is a hook running at the end of every instruction's execution. In the new RFC, there won't be a post-instruction execution hook, but a post-packet execution hook.

Since we're fetching and decoding whole packets at a time and sequencing, updating the internal pc after each instruction is nonsensical (also nonsensical from the viewpoint of the fact that packets execute atomically), I think we should just keep the internal and isa pc in sync. The new pcodebackend already keeps track of where we are within a packet anyway _if we care about execution stopping in the middle of a packet. The idea then would be to update the internal/isa pc once at the end of a packet, as opposed to every instruction. This can be done in the `post_packet_execute` hook. Now we have:::

    Before A: 0x1000 (internal) 0x1000 (isa)
    After A: 0x1000 (internal) 0x1000 (isa)
    After B: 0x1000 (internal) 0x1000 (isa)
    After C: 0x1000 (internal) 0x1000 (isa)
    After D: 0x1010 (internal) 0x1010 (isa)

Setting pc in the middle of a packet
------------------------------------

About setting the PC in the middle of a packet, I'll talk about this mostly in the context of a unified internal PC.
- If you set the PC in the middle of a packet, it should only take effect at the end of the packet. Currently the logic in `set_internal_pc` if you call it with `from_branch=true` parameter does this. It saves the PC you wanted to set in a separate variable in the struct, and updates the ISA and internal PC at the end of the packet. Since this PC is only updated at the end, if someone tries to read the ISA PC in the middle of the packet, it'll return the PC of the start of current packet, until after the last instruction in the packet has executed, at which point it will return the new PC.
- So IMO we just need to remove the whole from_branch thing and make the logic that runs when `from_branch=true` be the logic that always runs when you set the internal/ISA PC (won't matter which since we unified them)
- The reason why there was a `from_branch` in the first place was because we wanted to set the internal PC to move forward after every instruction, but since we decode all instructions within a packet at once now, there is no reason to set PCs at any granularity finer than the packet-boundary.

.. code:: rust

    fn set_isa_pc(&mut self, value: u64, backend: &mut HexagonPcodeBackend) {}
    fn set_internal_pc(&mut self, value: u64, backend: &mut HexagonPcodeBackend) {}

- With the ISA/internal PC unified, and the `from_branch=true` logic being the logic that always runs for PCs being set, here's an example. If you have your `{A;B;C;D}` packet, and B is actually a branching instruction that branches to ``0x2000``::

    Before A: 0x1000 (internal) 0x1000 (isa) `saved_set_pc: None`
    After A: 0x1000 (internal) 0x1000 (isa) `saved_set_pc: None`
    After B: 0x1000 (internal) 0x1000 (isa) `saved_set_pc: Some(0x2000)`
    After C: 0x1000 (internal) 0x1000 (isa) `saved_set_pc: Some(0x2000)`
    After D: (after post_packet_execute): 0x2000  (internal) 0x2000 (isa) `saved_set_pc: None`

Stopping execution mid-packet
-----------------------------

Regarding whether or not we should stop execution mid packet, I think the case to be made for why having it stop mid packet is useful is explicitly for testing and debugging. Execution should never stop in the middle of the packet in any other case (because as you said and as the manual says, packet execution is atomic), and stuff that uses this backend should always be using `execute_packets`; if we kept `execute_instrs` it should probably be `pub(crate)` or something.

The idea is that it would be good to write test cases to ensure that registers written to the "bank" are written to the bank correctly. Additionally, we would be able to single step through a packet that maybe requires reordering and ensure the order is exactly what we expect by looking for specific effects after each instruction has executed within a packet. It's probably reasonable to not have this as well, but I think in its absence we would want to provide detailed info in an execution report about the pcode ordering. Even then, it would be hard to check specific banked registers and make sure banking is working properly.

Execute packets method having a count/number of packets to execute
------------------------------------------------------------------

In line with this, the `execute_packets` method can also be used in test cases to simplify many of them by specifying the right number of packets to execute as opposed to individual instructions, which is why there's a number of packets argument in the method.


Drawbacks/Alternatives
======================

* This is very complicated, and hasn't been done in a generic fashion before, so there will be a lot of lessons learned
* So far most of the ideas are a balance of tradeoffs trying to minimize the damage, ideas welcome

Future Work
===========

* Reduce the duplicated code between the parallel / non-parallel pcode backends
* Come up with a set of rules / guidelines for making new parallel packet based ISA ghidra plugins for emulation / ghidra use
* For now we should limit the current implementation to Hexagon as that is the immediate usecase. We should expand to a generic parallel / packet based execition in a later revision
