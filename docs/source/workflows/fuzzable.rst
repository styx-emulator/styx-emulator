.. _fuzzable_workflow:

Fuzzable Emulation
##################

Styx supports fuzzing single vcpu targets with `LibAFL <https://aflplus.plus/libafl-book/>`_

Building a Fuzzing Capable Processor in Styx
============================================

Two components are required for fuzzing to work.  First, the ``FuzzerExecutor`` needs to be assigned as the executor for your processor.  The ``FuzzerExecutor`` requires a configuration struct upon creation, the configuration options are covered in another section.

Second, the trace plugin with basic block events needs to be enabled.  The trace plugin is how the fuzzer gets coverage data from emulation.

.. literalinclude:: ../../../examples/fuzzer-plugin/src/main.rs
   :start-after: // BEGIN-FUZZABLE-PROC
   :end-before: // END-FUZZABLE-PROC
   :language: rust
   :dedent:

Code Coverage
-------------

Styx measures code coverage at the basic block level, keeping track of how many times each basic block is hit.  To achieve this, when building your processor you need to provide a file containing the addresses of each basic block in your firmware.  We provide a Ghidra script that can generate this file, ``styx/plugins/styx-fuzzer/GetBranches.java``.


Fuzzer Config
=============

The ``StyxFuzzerConfig`` struct defines important configuration options for fuzzing, explained below.


.. literalinclude:: ../../../styx/plugins/styx-fuzzer/src/lib.rs
   :start-after: // BEGIN-FUZZER-CONFIG
   :end-before: // END-FUZZER-CONFIG
   :language: rust
   :dedent:

There are a few functions that need to be defined to handle certain actions.

**setup**

A function that takes a mutable reference to the processor core and to the
slice of vcpu cores. This should do everything required to get the program
ready to fuzz.  This could include doing things like emulating your firmware up
to a certain point, setting registers/memory to some desired initial state, or
receiving an external input from a peripheral.

**input_hook**

A function that takes a mutable reference to a vcpu core and a reference to the
data to be inserted for an execution. This will most likely be just writing
data to memory, but could do other things like setting a register to a certain
value.

**context_save/context_restore**

These functions are responsible for producing a snapshot of the cpu state
to restore from, as well as reseting the cpu state after an execution.
``context_restore`` will be called very frequently, so make sure you are doing
only necessary actions to make fuzzing as fast as possible.
