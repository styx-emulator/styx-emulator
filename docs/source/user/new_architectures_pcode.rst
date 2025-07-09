.. _new_architectures:

Implementing new architectures (pcode backend)
##############################################

One of the key features of Styx is its ability to add new processor architectures.

Styx has two CPU backends, the Unicorn backend powered by the `Unicorn Engine <https://www.unicorn-engine.org/>`_ and the Pcode backend powered by emulating Ghidra Pcode. The Unicorn backend benefits from the maturity of the Unicorn engine, including superior performance. The Pcode backend is trivial to extend with new architecture, provided it's supported by Ghidra.

Styx Architecture Description
=============================

The Architecture description is common for all Styx backends and is how Styx users will interface with the ISA.

SLA Specification
=================

To add a custom architecture, you will need an SLA file. The SLA file provides the definitions to generate Pcodes from the architecture's machine code.

You can obtain these from any Ghidra release. The Ghidra sources have heme in ``ghidra/Ghidra/Processors/[ARCH]/data/languages`` (for example, `ARM specs <https://github.com/NationalSecurityAgency/ghidra/tree/30ef757d81c88c5fc413d9136127cfeb4c6fbf81/Ghidra/Processors/ARM/data/languages>`_).
Compile these sources to an SLA file using Ghidra's SLEIGH utility and add this file to ``incubation/styx-pcode-sleigh-backend/data/sla``.

Next, add your new architecture to ``incubation/styx-pcode-sleigh-backend/src/sla.rs``. This will include an implementation of ``SlaRegisters``. ``SlaRegisters`` defines the translation from Styx's register nomenclature to the SLA spec's nomenclature. Usually, Styx register names are uppercase while SLA spec registers are lowercase. There may also be some registers with exclusive mappings.

Registers are defined in ``styx/core/styx-cpu-type/src/arch/[ARCH]/registers.rs``. Your arch's register types probably don't exist yet, in which case you'll have to add them.

Architecture Specification
==========================

The Arch Spec is a behavior specification specific to the Pcode backend. Pcode emulation doesn't have all the information needed to properly emulate the target; the Arch Spec fills in these gaps.

There are four parts to the Arch Spec:

- CallOther handlers - Execute Pcode "userops"
- Register handlers - Custom logic for complex registers
- PcManager - Define program counter semantics
- GeneratorHelper - Pre-instruction fetch hook

CallOther Handlers
------------------

Pcode has a special `USERDEFINED <https://spinsel.dev/assets/2020-06-17-ghidra-brainfuck-processor-1/ghidra_docs/language_spec/html/pseudo-ops.html>`_ opcode for defining instructions that are not implemented in the SLA spec. In mature SLA specs, these are instructions with side effects beyond changing memory and register values. For example, the ARM SLA spec has a ``SoftwareInterruptCallOther``. In other SLA specs, there may be more CallOthers for complex instructions that are hard to implement in Pcode.

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

Register Handlers
-----------------

Register handlers are used to hook register reads and writes at the CPU backend level. This is used to implement additional logic beyond the SLA spec.

Register handlers implement a ``read(..)`` and ``write(..)`` function that define behavior when a Styx user tries to interface with the register.
When a register is read from and written to in the emulated core the underlying Register Space is queried. The Register Space is *just* a memory store with no behavior unless the pcode generated has behavior.

In contrast if the register is read from or written to over the register API (``cpu.read_register(..)``, ``cpu.write_register(..)``, then the RegisterManager first checks if a Register Handler is associated with the queried register. If so, the Register Handler is called and the value read from the handler is used. If no handler is associated with the register then the ``DefaultRegisterHandler`` is used. The ``DefaultRegisterHandler`` reads the value in the Register Pcode space. This is the "correct" beavior for trivial value registers.

An example of a register that needs a Register Handler is Armv7-M's ``XPSR`` handler. ``XPSR`` is combination of the ``APSR``, ``IPSR``, and ``EPSR`` registers.

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
    If the register is used in generated pcode then that value comes from the Pcode Register Space. To solve this make sure to keep register space in sync with the value written to the Register Handler. An example of this is in the ``DefaultRegisterHandler``.

PC Manager
----------

The PC Manager is used to define the Program Counter of the processor. To properly abstract the ISA from the Pcode backend, two PC definitions are used:

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

Blackfin implements a ``StandardPcManager``, which may be stabilized to be used for any architecture and may be the PC manager correct for your implementation. The main exception and justification for the PC manager's existence is ARM's unique PC, which is two instructions ahead of the current executed instruction.

The PcManager has several hooks that are called during execution to allow the PcManager to have the correct state.

Generator Helper
----------------

The Generator Helper provides a prefetch hook to assist Pcode generation. E.g. this is needed in ARM Pcode generation, as thumb mode must be tracked during emulation, and cannot be known statically. The Generator Helper prefetch allows the architecture implementer to read the system state and apply context options as needed.
