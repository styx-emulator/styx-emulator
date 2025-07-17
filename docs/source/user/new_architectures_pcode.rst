.. _new_architecture_pcode:

Adding a New Architecture (Pcode Backend)
#########################################

One of the key features of Styx is its ability to add new processor
architectures.

Styx has two CPU backends, the Unicorn backend powered by the `Unicorn Engine
<https://www.unicorn-engine.org/>`_ and the Pcode backend powered by emulating
Ghidra Pcode. The Unicorn backend benefits from the maturity of the Unicorn
engine, including superior performance. The Pcode backend is trivial to extend
with new architecture, provided it's supported by Ghidra.


Steps For Experienced Users
===========================

Here is a checklist to perform in order to add a new architecture to the pcode
backend. It doesn't include all necessary details so be sure to read the rest
of this page if this is your first architecture port.

.. task-list::
    :custom:

    #. [ ] Add SLEIGH spec to Styx, see :ref:`sla-specification`

       .. task-list::
           :custom:

           #. [ ] Put in ``styx-sla`` custom folder or find in ghidra collection
           #. [ ] Add feature flag ``arch_<arch name>`` to Cargo.toml,
              including add to the default feature flags (more info in the
              `features rust docs`_)
           #. [ ] Add ``ArchFeature`` for your arch in ``styx-sla``'s `build.rs`_
           #. [ ] Add SLEIGH spec path to ``build.rs`` under correct ``ArchFeature`` guard
           #. [ ] Perform a build of ``styx-sla`` to check correctness up to this point
           #. [ ] Add module for arch in ``lib.rs`` with ``SlaRegisters`` impl
           #. [ ] Another build of ``styx-sla`` to finish

    #. [ ] Add the ``arch_<arch name>`` feature flag to the ``Cargo.toml`` of
       ``styx-pcode-translator`` and ``styx-cpu-pcode-backend`` crates

       .. task-list::
           :custom:

           #. [ ] Guard arch specific code, e.g. for ARM: ``#[cfg(feature = "arch_arm")]``
           #. [ ] Use :ref:`xtask feature-add <xtask-feature-add>` to automate

    #. [ ] Add the arch spec to the pcode backend, see :ref:`arch-spec`

       .. task-list::
           :custom:

           #. [ ] Create a new module with your arch name, feature gated by the
              arch feature   flag
           #. [ ] Create a "StandardPcManager" for your arch and add it to the
              PcManagerenum_dispatch enum, see :ref:`pc-manager`
           #. [ ] Add your arch to the ``build_arch_spec()`` match
           #. [ ] Add :ref:`CallOtherHandlers <call-other-handlers>` and
              :ref:`RegisterHandlers <register-handlers>` as encountered

.. _features rust docs: https://doc.rust-lang.org/cargo/reference/features.html
.. _build.rs: https://doc.rust-lang.org/cargo/reference/build-scripts.html


Styx Architecture Description
=============================

The Architecture description is common for all Styx backends and is how Styx
users will interface with the ISA.


.. _sla-specification:

SLEIGH Specification
====================

To add a custom architecture, you will need a processor specification. The
processor specification file provides the definitions to generate Pcodes from
the architecture's machine code.

.. info:: More about SLEIGH

    The SLEIGH processor specification language was developed for the GHIDRA
    project to define the translation between machine and assembly instructions
    and aid data-flow and decompilation analysis.

    Processor specifications are written in the SLEIGH language (filename
    ``.slaspec``) and compiled into sla files (``.sla``). A SLEIGH compiler is
    included in GHIDRA as a part of ``libsleigh``.

    More information can be found in the `GHIDRA's SLEIGH documentation`_.

    .. _GHIDRA's SLEIGH documentation: https://github.com/NationalSecurityAgency/ghidra/blob/1a1cdefc14323e3957fab9dfdb778df0af7bfed3/GhidraDocs/languages/html/sleigh.html

The GHIDRA project has `SLEIGH specifications for many common processors`_
that can be used as-is for pcode emulation or modified. These are included in
``styx`` for convenience under the ``styx-sla`` crate in
``processors/ghidra/``. Alternatively, custom SLEIGH specifications can be
added under ``processors/custom/``. SLEIGH specifications in these locations
will be combined to ``.sla`` files automatically during build.

.. _SLEIGH specifications for many common processors: https://github.com/NationalSecurityAgency/ghidra/tree/1a1cdefc14323e3957fab9dfdb778df0af7bfed3/Ghidra/Processors

Next, add your new architecture to
``incubation/styx-pcode-sleigh-backend/src/sla.rs``. This will include an
implementation of ``SlaRegisters``. ``SlaRegisters`` defines the translation
from Styx's register nomenclature to the SLEIGH spec's nomenclature. Usually, Styx
register names are uppercase while SLEIGH spec registers are lowercase. There may
also be some registers with exclusive mappings.

Registers are defined in
``styx/core/styx-cpu-type/src/arch/[ARCH]/registers.rs``. Your arch's register
types probably don't exist yet, in which case you'll have to add them. See
:ref:`new_architectures` learn how to add the ISA types to Styx.


.. _arch-spec:

Architecture Specification
==========================

The Arch Spec is a behavior specification specific to the Pcode backend. Pcode
emulation doesn't have all the information needed to properly emulate the
target; the Arch Spec fills in these gaps.

There are four parts to the Arch Spec:

- CallOther handlers - Execute Pcode "userops"
- Register handlers - Custom logic for complex registers
- PcManager - Define program counter semantics
- GeneratorHelper - Pre-instruction fetch hook


.. _call-other-handlers:

CallOther Handlers
------------------

Pcode has a special `USERDEFINED opcode`_
for defining instructions that are not implemented in the SLEIGH spec. In
mature SLEIGH specs, these are instructions with side effects beyond changing
memory and register values. For example, the ARM SLEIGH spec has a
``SoftwareInterruptCallOther``. In other SLEIGH specs, there may be more
CallOthers for complex instructions that are hard to implement in Pcode.

.. _USERDEFINED opcode: https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pseudo-ops.html

USERDEFINED opcodes take the form of ``define pcodeop <name>`` in the SLEIGH spec.

The best way to implement userdefined opcodes correctly is to look through the
SLEIGH spec to find in what instructions they are used, what arguments are passed
to them, and if their output varnode is used. This should be done while
cross-referencing the processor manual.

.. code-block:: rust

    #[derive(Debug, Default)]
    pub struct SoftwareInterruptCallOther;
    impl CallOtherCallback for SoftwareInterruptCallOther {
        fn handle(
            &self,
            backend: &PcodeBackend,
            inputs: &[VarnodeData],
            _output: Option<&VarnodeData>,
        ) -> Result<PCodeStateChange, CallOtherHandleError> {
            let input_value = backend.read(&inputs[0]).unwrap();
            let interrupt_number = input_value.to_u64().unwrap();
            let interrupt_number: i32 = interrupt_number.try_into().unwrap();
            trace!("Interrupt no: {interrupt_number}");
            assert_eq!(interrupt_number, 0);
            Ok(PCodeStateChange::DelayedInterrupt(SVC_IRQN))
        }
    }



.. _register-handlers:

Register Handlers
-----------------

Register handlers are used to hook register reads and writes at the CPU backend
level. This is used to implement additional logic beyond the SLEIGH spec.

Register handlers implement a ``read(..)`` and ``write(..)`` function that
define behavior when a Styx user tries to interface with the register. When a
register is read from and written to in the emulated core the underlying
Register Space is queried. The Register Space is *just* a memory store with no
behavior unless the pcode generated has behavior.

In contrast if the register is read from or written to over the register API
(``cpu.read_register(..)``, ``cpu.write_register(..)``, then the
RegisterManager first checks if a Register Handler is associated with the
queried register. If so, the Register Handler is called and the value read from
the handler is used. If no handler is associated with the register then the
``DefaultRegisterHandler`` is used. The ``DefaultRegisterHandler`` reads the
value in the Register Pcode space. This is the "correct" behavior for trivial
value registers.

An example of a register that needs a Register Handler is Armv7-M's ``XPSR``
handler. ``XPSR`` is combination of the ``APSR``, ``IPSR``, and ``EPSR``
registers.

.. code-block:: rust

    #[derive(Debug, Default)]
    pub struct XpsrHandler;
    impl RegisterCallback for XpsrHandler {
        fn read(
            &self,
            register: ArchRegister,
            backend: &PcodeBackend,
        ) -> Result<SizedValue, RegisterHandleError> {
            let apsr = backend.read_register::<u32>(ArmRegister::Apsr).unwrap();
            let ipsr = backend.read_register::<u32>(ArmRegister::Ipsr).unwrap();
            let epsr = backend.read_register::<u32>(ArmRegister::Epsr).unwrap();

            let xpsr = apsr | ipsr | epsr;
            Ok(SizedValue::from_u64(xpsr as u64, 4))
        }

        fn write(
            &self,
            register: ArchRegister,
            value: SizedValue,
            backend: &PcodeBackend,
        ) -> Result<(), RegisterHandleError> {
            let xpsr = value.to_u64().unwrap() as u32;

            backend.write_register(ArmRegister::Apsr, xpsr).unwrap();
            backend.write_register(ArmRegister::Ipsr, xpsr).unwrap();
            backend.write_register(ArmRegister::Epsr, xpsr).unwrap();

            Ok(())
        }
    }


.. warning::

    Pcode emulation **does not** use the Register Handlers.

    If the register is used in generated pcode then that value comes from the
    Pcode Register Space. To solve this make sure to keep register space in
    sync with the value written to the Register Handler. An example of this is
    in the ``DefaultRegisterHandler``.


.. _pc-manager:

PC Manager
----------

The PC Manager is used to define the Program Counter of the processor. To
properly abstract the ISA from the Pcode backend, two PC definitions are used:

.. code-block:: rust

    pub trait ArchPcManager {
        /// Value of Program Counter as defined by the Instruction Set Architecture.
        ///
        /// This is the pc that is read inside machine instructions like `mov r0, pc`. This is also the
        /// pc that is returned from [CpuEngine::pc()](styx_cpu_engine_trait::CpuEngine::pc()).
        fn isa_pc(&self) -> u64;
        /// Value of Program Counter for internal backend use. Used to track the next instruction to
        /// translate and execute.
        ///
        /// This pc must hold the following: before execution the PC points to the next instruction,
        /// during fetch and execution this is set to the current instruction. After execution the PC is
        /// set to the next instruction to be executed.
        ///
        /// This pc is to track the next instruction to translate and execute.
        fn internal_pc(&self) -> u64 {
            self.isa_pc()
        }
        ...
    }

Blackfin implements a ``StandardPcManager``, which may be stabilized to be used
for any architecture and may be the PC manager correct for your implementation.
The main exception and justification for the PC manager's existence is ARM's
unique PC, which is two instructions ahead of the current executed instruction.
The PcManager could also be used to help implement instruction packets for
architectures that use them (i.e. hexagon, itanium, and tms320).

The PcManager has several hooks that are called during execution to allow the
PcManager to have the correct state.


.. _generator-helper:

Generator Helper
----------------

The Generator Helper is an optional part of the arch spec that provides a
prefetch hook to assist Pcode generation. E.g. this is needed in ARM Pcode
generation, as thumb mode must be tracked during emulation, and cannot be known
statically. The Generator Helper prefetch allows the architecture implementer
to read the system state and apply context options as needed.
