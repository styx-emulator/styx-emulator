
.. _workflows:

Workflow Overviews
##################

``styx`` is a "composable emulation framework," meaning that the overarching purpose is to provide the
necessary building blocks that create a straightforward avenue to emulate your target device, provided
it's actually possible (worst-case you'll need to have access to the CPU manual, but hopefully not). A
"target" is just the representative term for "the thing you need to emulate."


While ``styx`` is technically a "composable emulation framework," and can technically perform an arbitrary
amount of emulation tasks, ``styx`` was designed with a few different workflows in mind which are (hopefully)
reflected in the developed extensions and libraries that are a part of ``styx``, as they should all attempt
to adhere to one or more of the intended workflows. Because the term "emulation" itself is pretty overloaded,
and the usecases can vary wildly, we instead try to frame the usecases as what ``styx`` can do, as opposed to
"emulation".

The main use cases we try to fulfill are:

* :ref:`debuggable`
* :ref:`traceable`
* :ref:`interactive`
* :ref:`fuzzable`
* :ref:`testable`
* :ref:`integrated`

One of the big goals in maintaining a "composable emulation framework" is that all of the workflows can
work off of the same interfaces / infrastructure created for the framework, meaning that all tracing or
debugging capability added to support one target can work for all targets. At the cost of some start-up
development time in the micro-scale, this gives ``styx`` the ability to rapidly advance the feature-set
of the entire project at once.

Want to add ``gdb`` support? Create a plugin that connects our ``Architecture`` interface with the
``CpuBackend`` trait, and now all targets can utilize the new plugin. Want to add a new ``GPS`` device
that talks over ``UART``? Now any machine can also import that created peripheral. ``styx`` seeks to
advance the state of the art of emulation through common interfaces, "write-once" peripherals, and
a shared ``Rust`` core that creates a solid architecture driven by our main workflows:

.. _traceable:

Traceable Emulation
===================

One of the most common questions when running software under emulation is "what is happening", via
``styx-trace`` and the intrinsic target tracing capabilities, all targets should have first-class
support for retrieving an exact ordered record of events of emulation, down to the instruction,
memory, register, DMA, and interrupt level.

Currently supported frontends for tracing:

* command line tool to filter on events as they occur

Currently incubating frontends for tracing:

* web application to control, monitor, and analyze executing emulator

Potential frontends for tracing:

* Ghidra integration
* IDE integration

.. _debuggable:

Debuggable Emulation
====================

While tracing is a great approach to figuring out "what happened," it often requires a lot of tooling
and infrastructure to create the filtering layers necessary to get useful information out of it, and
sometimes you want to be able to debug your code running on an emulated target and step through
code. While this behavior can be replicated via tracing, debugging implies the ability to manually
tweak execution as it happens, which can be instrumental in reasoning about target behavior.

Currently supported frontends for debugging include:

* ``gdb`` plugin supporting ``gdb-remote`` serial protocol over TCP + Unix Domain Socket

Potential frontends for debugging:

* Web application
* Debug adapter protocol (DAP)
* IDE integration plugins


.. _interactive:

Interactive Emulation
=====================

Sometimes the need for emulation is to test and verify that the tool you're making can correctly
interoperate with another. Interactive emulation is a little more complicated in that real life
nuances can affect the development and behavior of developed emulator. Interactive emulation can
be as simple as a console that ``pong``'s to your ``ping`` message, or emulates an entire vehicle
based on artificial stimuli.

Each Interactive Emulation project has largely application specific frontends, but many core
utilities are shared across the developed tools.

.. _fuzzable:

Fuzzable Emulation
==================

The concept of "fuzzable emulation" is emulation that is accurate and fast enough to reasonably
execute many iterations of target software while being able to find inputs that crash the system
under test.

Potential frontends for fuzzing:

* Make a ``styx`` ``AFL++`` backend
* Make a ``styx`` ``libAFL`` backend
* Automatically generate fuzzing harnesses for devices and peripheral interfaces

.. _testable:

Testable Emulation
==================

One of the lesser-publicized but more "useful" use-cases for emulation is to verify the code
you wrote did what is was supposed to. By creating a library around the remote emulation control
API's and the tracing API's you can create a library for use in development or CI that can provide
a way to create temporal unit tests to "make sure this thing happened", or "make sure this thing
happened after I executed this code that did something else"

Potential frontends for testing:

* ``styx`` as a CI-harness to emulate firmware
* ``styx`` as a python script to quickly test your binary patches still maintain the same behaviors
  as before, and the the patch corrected the previous mistakes or correctly performs its new task

.. _integrated:

Integrated Emulation
====================

The purpose of creating an integrated emulation tool is to embed the target emulator in something else.
In general this usually ends up being connecting and interacting with another emulator (here being arbitrarily referred to as :ref:`connected`),
or creating a cycle-accurate emulator that can be embedded or hooked up to a higher level multi-physics simulation
(here being arbitrarily referred to as :ref:`simulated`).

.. _connected:

Connected Emulation
-------------------

In many cases the smaller DSP or microcontroller is a sub-component of a larger system, which has
an already supported emulation for something like ``AARCH64`` or ``PowerPC 64`` etc., instead of needing
to scrap all your work using one emulation platform or another, use each emulation framework where they
excel, and implement the communication + synchronization between them.

Potential frontends for connected emulation libraries:

* Integrate ``styx`` ethernet PHY peripherals with host PHY layer
* Integrate ``styx`` serial PHY peripherals with host PHY layer
* Create a ``QEMU`` IPC library that communicates to the ``QEMU`` emulators

.. _simulated:

Simulation Embedding
--------------------

Largely explored in academia and hardware development / verification, creating cycle-accurate
emulation that can be integrated into a larger simulation framework. This requires great attention
to correctness of event controller emulation and instruction cycle annotation, and orchestrating
the inputs to attached peripherals and devices for the systems being emulated.

Potential frontends for simulated embedding of emulation:

* Simulink plugin models to interface with ``styx`` emulators
* Automatically generate ``SystemC`` component libraries for ``styx-peripheral`` devices
* Create custom interface modules between simulation libraries and ``styx`` emulators to verify
  emulated target behavior
