.. _backends:

Available Backends
==================

Styx provides two main CPU execution backends that implement the ``CpuBackend`` trait. Both backends support the same hook system, memory interface, and processor integration, allowing you to choose based on your specific needs for performance, architecture support, and extensibility.

Overview
--------

.. list-table:: Backend Comparison
   :header-rows: 1
   :widths: 20 40 40

   * - Feature
     - Unicorn Backend
     - Pcode Backend
   * - **Crate**
     - ``styx-cpu-unicorn-backend``
     - ``styx-cpu-pcode-backend``
   * - **Performance**
     - High (native JIT compilation)
     - Moderate (interpreted Pcode)
   * - **Architecture Support**
     - Limited to Unicorn (ARM, AArch64, x86, x86_64, MIPS, PowerPC, SPARC, M68K)
     - Extensive (40+ architectures via Ghidra SLEIGH specs)
   * - **Extensibility**
     - Difficult (requires Unicorn/QEMU changes)
     - Easy (add SLEIGH spec)
   * - **Maturity**
     - Very mature (based on QEMU/Unicorn), multiple footguns
     - Stable, with probable SLEIGH patching required for new architectures
   * - **License**
     - GPL-2.0 (Unicorn -> QEMU dependency)
     - BSD-2-Clause

Unicorn Backend
---------------

The Unicorn backend (``styx-cpu-unicorn-backend``) provides CPU emulation via by the `Unicorn Engine <https://www.unicorn-engine.org/>`_, which uses QEMU TCG for instruction emulation. While the focus
of Styx is to support things that aren't supported by these mainstream tools, they offer a robust
and familiar experience to many people familiar with the emulation space.

Architecture
^^^^^^^^^^^^

The Unicorn backend wraps the Unicorn Engine C library and provides compatibility layers between Styx abstractions and Unicorn's interface:

- **arch_compat.rs** - Architecture translation between Styx and Unicorn
- **register_compat.rs** - Register mapping and special register handling
- **hook_compat.rs** - Hook system integration
- **hooks.rs** - Styx hook management

Supported Architectures
^^^^^^^^^^^^^^^^^^^^^^^

The Unicorn backend supports the following architectures (note that Styx does not yet support all of these, see :ref:`architecture_support` for the actual support list):

- ARM (32-bit) - ARMv7 and earlier
- AArch64 (ARM 64-bit)
- x86 (32-bit)
- x86_64 (64-bit)
- MIPS (32-bit and 64-bit)
- PowerPC (32-bit and 64-bit)
- SPARC (32-bit and 64-bit)
- M68K (Motorola 68000)

Advantages
^^^^^^^^^^

**Maturity**: Built on QEMU, one of the most mature and widely-used emulation engines, with extensive testing and correctness guarantees.

**Standard**: Unicorn is widely used in security research, fuzzing, and binary analysis tooling. While it has
some easily accessible footguns it is the standard for a reason.

Limitations
^^^^^^^^^^^

**Licensing**: The Unicorn dependency is GPL-2.0, which may not be suitable for all projects. Note that Styx source code itself remains BSD-2-Clause licensed.

**Extensibility**: Modifying instruction semantics or adding custom operations requires changes to the Unicorn codebase. Good luck.

When to Use
^^^^^^^^^^^

Choose the Unicorn backend when:

- Working with mainstream architectures (ARM, x86, etc.)
- Your target is not supported by another backend
- GPL licensing is acceptable

Pcode Backend
-------------

The Pcode backend (``styx-cpu-pcode-backend``) executes programs by interpreting Ghidra Pcode, a processor-independent intermediate language that gets lifted from machine code by parsers created using the Ghidra SLEIGH specification language. This backend focuses on supporting diverse and exotic architectures.

Architecture
^^^^^^^^^^^^

The Pcode backend translates machine code to Pcode operations and executes them:

- **get_pcode.rs** - Fetch and translate instructions to Pcode
- **execute_pcode.rs** - Pcode interpreter and execution engine
- **register_manager.rs** - Register state management
- **arch_spec/** - Architecture-specific handlers and customizations
- **memory/** - Memory spaces and storage (blob_store, hash_store, space_manager)

The backend uses SLEIGH processor specifications (compiled to ``.sla`` files) from the ``styx-sla`` crate to perform instruction lifting.

Supported Architectures
^^^^^^^^^^^^^^^^^^^^^^^

The Pcode backend supports 40+ architectures through Ghidra SLEIGH specifications, with the following enabled by default:

- ARM (32-bit)
- AArch64 (ARM 64-bit)
- Blackfin (arch_bfin)
- M32R (arch_m32r)
- MIPS (32-bit and 64-bit)
- PowerPC
- SuperH

Additional architectures available (not enabled by default):

- 6502, 68000, 8048, 8051, 8085
- Atmel AVR
- BPF and eBPF
- CR16, CP1600
- Hexagon
- JVM bytecode
- Loongarch
- PA-RISC
- PIC
- RISC-V
- SPARC
- TI MSP430
- V850
- x86 and x86_64
- Xtensa
- Z80
- And many more...

See ``styx-sla/processors/ghidra/`` for the complete list.

Advantages
^^^^^^^^^^

**Architecture Support**: Trivial to add new architectures - just provide a SLEIGH specification. No need to modify the backend implementation (beyond adding the glue code and the ``CALLOTHER`` implementations)

**Flexibility**: Easy to extend with custom instructions, analyze instruction semantics, or implement custom Pcode operations via CallOther handlers.

Limitations
^^^^^^^^^^^

**Performance**: Interpreted execution is slower than JIT-compiled native code. Typically 10-100x slower than the Unicorn backend depending on workload. While it is "slow," its more than enough for fuzzing and other related tasks. However, please create an issue if performance becomes abysmal for a specific workload.

**SLEIGH Dependencies**: Requires correct SLEIGH specifications. Some obscure architectures may have incomplete or inaccurate specs, we maintain a set of patches in our ``styx-sla`` crate.

When to Use
^^^^^^^^^^^

Choose the Pcode backend when:

- Working with exotic or embedded architectures not supported by Unicorn
- You need to add custom architecture support
- Sane default, start here to encounter less footguns

Choosing a Backend
------------------

Styx processors can be configured to use either backend through the processor builder:

.. code-block:: rust

    use styx_emulator::prelude::*;

    // Unicorn backend
    let proc_unicorn = ProcessorBuilder::default()
        .with_backend(Backend::Unicorn)
        .with_target_program("firmware.bin")
        ...
        .build()?;

    // Pcode backend
    let proc_pcode = ProcessorBuilder::default()
        .with_backend(Backend::Pcode)
        .with_target_program("firmware.bin")
        ...
        .build()?;

Both backends implement the same ``CpuBackend`` trait, so switching between them should be transparent to your code.

Custom Backends
---------------

For specialized needs beyond what the built-in backends provide, Styx allows you to implement custom backends. See :ref:`custom_backends` for details on implementing your own ``CpuBackend``.

See Also
--------

- :ref:`custom_backends` - Implementing custom execution backends
- :ref:`new_architecture_pcode` - Adding architectures to the Pcode backend
- :ref:`processors` - Processor implementation guide
- ``styx/core/styx-cpu-unicorn-backend/`` - Unicorn backend source
- ``styx/core/styx-cpu-pcode-backend/`` - Pcode backend source
