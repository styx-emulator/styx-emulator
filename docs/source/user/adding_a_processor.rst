.. _adding_processor:

Adding a Processor
##################

In general the goal for emulation is to provide an accurate representation of hardware (as seen
by the software AKA the ``TargetProgram`` as we call it). But at the end of the day the goal is
to be able to run or debug your ``TargetProgram``, so practically you only need the peripheral
support required to run and debug said ``TargetProgram``.

Thankfully, ``styx`` provides a defined structure for your custom emulation by supplying a collection
of interfaces to build on. One of the hardest parts of emulating a ``TargetProgram`` is knowing
what you need to do, and in what order to do it. (The :strike:`problem` best part with providing a
realistic hardware emulation is that you really don't know the minimum set of things you need
to emulated until you *need* it *now*).

The Process
***********

In ``styx`` (and in general) by and large emulating every new processor follows the same process,
with a little context-dependent flair tossed in for each new chip. Unlike most other frameworks,
there is not only a checklist, but a solidified set of generic interfaces that together provide
adequate flexibility to implement most any type of computation engine. This in turn, should allow
you to be able to get away with following this checklist to add processor support for any processor
that the codebase already provides the "foundational support" for.

In our terms, "foundational support" is:

* the ISA is known by, and supported by ``styx``
* the ``GdbArchSupport`` trait is implemented for your processor variant
* any of the ``CpuBackend``'s support executing instructions for your ISA

Once the foundational support is present in ```styx``, then any contributor (along with their
nearest CPU reference manual) should be able to add support for emulating a Processor, and in
turn, build that into a picture perfect emulated digital twin of their target machine.


Quick Reference Frequently Asked Questions
==========================================

What files do I need to touch to add Gdb Support
------------------------------------------------

Create or modify ``styx/core/styx-cpu-type/src/arch/<arch>/gdb_targets.rs``.
This provides the mapping from gdb register index to styx register. This is
assuming you have the TargetDescription struct which includes the register map
and gdb xml specification. You may need to add your gdb xml to
``styx/core/styx-util/src/gdb_xml.rs``

How do I add a Processor Variant
--------------------------------

Add your variant to ``styx/core/styx-cpu-type/src/arch/<arch>/variants.rs``.
You may need to add your variant to the cpu backend you want to use. If a
similar variant exists in Styx already then this will be easy. If your
processor variant is not supported by Styx or Unicorn then you will have to do
some work to add it to the pcode backend.

Backend Support
---------------

Unicorn Support
"""""""""""""""

If unicorn supports your processor/variant then it should Just Work if you
instantiate a UnicornBackend, but be sure to check
``styx/core/styx-cpu-type/src/backend_compat/unicorn.rs`` to add the styx ->
unicorn processor conversion.

If unicorn does not support your processor variant you could use a similar
supported one or add it to unicorn yourself. Your best bet is to instead use
the pcode backend.

Pcode Backend Support
"""""""""""""""""""""

If your processor has the same ISA as another processor already implemented in
the pcode backend then just use the already supported variant or add your
variant to ``styx/core/styx-cpu-pcode-backend/src/arch_spec/mod.rs``
``build_arch_spec()`` and map to the correct arch spec.

If you need to add a new ISA entirely then check out
:ref:`new_architecture_pcode` for detailed instructions on adding new
architectures to the pcode backend.

To modify architecture specific behavior in the pcode backend, check out its
architecture specification in
``styx/core/styx-cpu-pcode-backend/src/arch_spec/<arch>/mod.rs``. Here there is
the PcManager, user op handlers, and register handlers that can be changed.

Special Register vs Styx Abstraction
------------------------------------

Most CPU registers are easily represented as a simple data store that can be
read or written to without side effects. The most challenging registers to
model are ones with external state side effects or are not statically defined,
also known as model specific registers.

Examples of registers controlling external state include PowerPC MSR, ARM CPSR,
and PowerQuicc IMMR registers. Writes to these register may change processor
behavior.

Examples of model specific registers are ARM's coprocessor registers and
PowerPC's special registers (SPRs).

External state registers should be modeled as normal cpu registers (i.e. in
ArmRegister, Ppc32Register, etc) and external behavior should be modeled
through Styx features. There are several ones to do this including register
hooks (pcode backend only), register handlers (pcode backend internal),
interrupt hooks (i.e. event controller sets a "saved machine state"
register), and the PcManager (pcode backend internal, e.g. thumb mode state).

Model specific registers should be modeled as a SpecialRegister variant in
Styx. This allows them to be defined by variable parameters, i.e. for PowerPC
the Special Registers can be modeled as a struct with a single integer
representing the SPR number it is.


The Complete Processor Checklist (ARM Example)
==============================================

.. task-list::
    :name: Processor Checklist
    :custom:

    1. [x] ``styx-cpu`` ISA support
    2. [x] ``styx-cpu::GdbArchSupport`` ISA support
    3. [x] A ``CpuBackend`` supports your ISA
    4. [ ] Implement ``ProcessorImpl`` trait inside your new processor definition crate
    5. [ ] Interrupt Controller (``EventController`` in ``styx``-terms) implemented

        We have implemented a couple common ARM interrupt controllers, namely
        support for ``ARM Cortex-M`` (``NVIC``), and some ``ARM Cortex-A/R`` (``GIC``).

        .. task-list::
            :custom:

            + [x] ``NVIC``
            + [x] ``GICv1``
            + [ ] ``GICv2``
            + [ ] ``GICv3``
            + [ ] ``GICv4``
            + [ ] ``VIC`` (aka ``PrimeCell VIC``)


    6. [ ] Create new baseline End to End (E2E) tests in ``styx-integration-tests/tests``
    7. [ ] Create behavior tests for the E2E test suite

        TBD integration + e2e test guide (see ``./styx-integration-tests`` in the interim)

        .. task-list::
            :custom:

            + [ ] Simple ``while (true);`` spinning.

            This tests that input files can load, and that ``styx-trace`` events can be emitted

            + [ ] More as needed + peripherals are implemented

    8. [ ] Implement peripherals (TBD peripherals + devices guide)

        This step is definitely the most arduous, and ill-defined of all the steps.
        In general you don't want to waste time emulating hardware you aren't going to need,
        and you are going to take some liberties with emulation because ``styx`` is not
        real hardware and is confined by the same constraints.

        As ``styx`` continues to mature we will unify peripheral events for ``styx-trace``
        in order to provide a cleaner, more auto-magic test suite generation for peripherals
        and interactions between them. For now, make sure that the process for peripheral
        emulation is documented to reference which manuals and specification sections are
        referenced for which part, and reasoning behind omitting emulated behavior for
        one feature or another.

        **IN GENERAL**, the order of peripherals you want to implement is:

        - Clocks/Timers
        - GPIO
        - I2C
        - UART
        - SPI
        - any others needed

        This roughly follows "least complex first," and also generally follows many RTOS/OS
        boot patterns. So in theory you will be able to emulate your target program further
        and further as you emulate more.

        It will also significantly help you (and your sanity) if you create test binaries
        to utilize your emulated hardware as you go along. See (TDB ref link) "adding test
        binaries" for more information.
