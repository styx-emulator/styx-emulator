
.. _mmu_rfc:

2. Mmu
######

Mmu
===

Status: Proposed

Currently being implemented as part of the holy trinity refactor.

Summary
=======

Implementation of a software based MMU for Styx to allow for the emulation of virtual memory.


Motivation
==========

A MMU is a critical piece of hardware that is necessary to accurately emulate systems that rely on virtual memory or related concepts (like Linux).  An MMU provides a single point for all memory transactions to flow through, allowing for precise control over things like memory permissions, physical memory schemes, and virtual memory.  Additionally, we need to support a logical split between instruction and data memory in order to support harvard architectures (like AVR8), and a MMU will make supporting these much simpler.

Details
=======

The MMU should become the main interface for reading, writing, and managing memory.  The MMU should own both a physical memory implementation as well as a processor specific TLB implementation.  The TLB will be purely responsible for translating virtual addresses to physical addresses, the physical memory implementation will be responsible for performing memory transactions over physical addresses, and the MMU will be responsible for coordinating memory operations.

MMU API
-------

The MMU should expose the following functionality:
 - Reading and writing memory

   * It should support many different input or output data types, for example ``read_u32`` or ``write_u8``
   * It should support both big and little endian reads/writes
   * It should support a logical split between code and data memory, i.e. ``read_code(x)`` may have a different meaning from ``read_data(x)``
   * It should support bypassing memory permission checks

 - Creating memory regions (for physical memory implementations that support it)

   * This should effectively just be a pass through to the physical memory implementation.

TLB API
-------

The TLB should expose the following functionality:
 - Translating virtual addresses to physical addresses
 - Enabling and disabling address translation
 - Reading and writing to the TLB
 - Invalidating TLB records

Physical Memory API
-------------------

The physical memory implementation should expose the following functionality:
 - Reading and writing memory

   - At this point, all addresses should be physical

 - Creating memory regions (if applicable)

Memory Permissions
------------------

There are two separate areas where memory permissions can exist.  The first is at a page level and in our scenario would be enforced by the TLB implementation, and the second is on the physical memory itself.  I like to think of the second as an analogue to the physical memory map for a processor, where various physical memory regions are defined with specific permissions for each region.  For example, the ARMv7m spec defines 8, 0.5 GB memory regions of which 4 are marked as XN (execute never).

Essentially, this allows for both hardware specific/controlled memory region permissions as well as software managed memory permissions like you would get in a system with virtual memory.

High Level Process Example
--------------------------

Goal: Target program wants to write to memory.

 #. Cpu backend calls mmu write data, passing in the address and data to be written.
 #. The MMU assumes a virtual address and calls the TLB implementation to translate virtual address to physical.

    * Depending on the current TLB state, it will either try to translate the address and check permissions, or just return the address with no changes.
    * if translation isn't in TLB, raise fault.
    * if permissions are violated, raise fault.

 #. MMU calls the physical memory implementation to write data, using the now physical address.

    * the return from this function should be a result that communicates other errors back to the Cpu backend if needed (writing out of bounds, violating system level permissions, misaligned write, etc.),


Implementation Details
----------------------

MMU would be a struct that holds a TLB implementation and a physical memory backend implementation. the only way the MMU would interact with the TLB directly would be for translating addresses, all of the other logic (inserting tlb records, invalidating stuff, searching for tlb entry, etc.) can happen via cpu hooks or in pcode call-other implementations.

Example for how this could look in code:

.. code-block:: rust

  struct Mmu {
      tlb: Box<dyn TlbImpl>,
      mem: Box<dyn MemBackend>,
  }

  trait TlbImpl {
      // add any needed hooks, setup initial state
      fn init(&mut self, cpu: &mut Box<dyn Cpu>);
      // turn a virtual address into a physical address
      fn translate_va(&self, addr: u64) -> Result<u64, TLBError>;
  }

  trait MemBackend {
      fn read_data(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryError>;
      fn read_code(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryError>;
      fn write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryError>;
      fn write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryError>;
      /// also have functions for creating regions, assigning permissions, etc.
  }

  impl Mmu {
      fn read_u32_le_phys_data() -> Result<u32, MmuError>;
      fn write_u16_be_virt_code() -> Result<(), MmuError>;
      ... etc
      // basically just generate a function for all combinations of this
      fn {read,write}_{u8, u16, u32, etc.}_{le,be}_{physical, virtual}_{data,code}();
  }

This would address the AVR8 issue of separate instruction and data memory, i.e. the MemBackend implementation would be responsible for routing {read,write}_{code,data} calls to the respective structure (or in most cases they would point to the same thing).  And on the Mmu struct we define a bunch of functions using macros probably to read and write various sizes of data.

Drawbacks/Alternatives
======================

 - The TLB will add overhead to every memory operation for processors that use it, there's not really any way around this but we can explore SIMD approaches to speed things up.

Future Work
===========

- This will lay the groundwork to allow for future support for memory caching, which is a greatly desired feature
- To make the TLB fully featured we will likely need to add support for special purpose register hooks, at least for writes, to properly catch state changes (e.g. writes to the MSR in powerpc to enable or disable address translation)

Thoughts about Caching
----------------------

I don't know how much of the caching stuff would be controlled through guest code (probably just flushing and marking pages as not cacheable, everything else (replacement, etc.) is probably hardware).  i think we can probably get away with just a single separate generic instruction and data cache with a configurable size at least for now, but having multiple layers of caching will be needed to see the more fun/exotic behavior/bugs.

A decent test of our caching implementation would need to accurately illustrate the following 2 scenarios:

**Scenario A**

 1. shellcode gets written to the heap
 2. cpu jumps to shellcode address
 3. cpu executes garbage, non-shellcode instructions because shellcode is stuck in data cache and hasn't been propagated back to memory

**Scenario B**

 1. shellcode gets written to heap
 2. cpu does isync, dsync instruction to flush caches, sleeps for some amount of time, or whatever is needed to cause shellcode in data cache to be written to memory
 3. cpu jumps to shellcode address
 4. profit
