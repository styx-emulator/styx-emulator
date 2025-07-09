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
