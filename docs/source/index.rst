.. styx-emulator documentation master file, created by
   sphinx-quickstart on Wed Mar  8 11:01:48 2023.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

:hero: A Composable Emulation Framework.

Welcome to Styx's documentation!
=========================================


The ``styx`` software emulation suite exists to provide a viable, easy to use
emulation platform for non-standard architectures. Current approaches cobble
together tooling from mainstream architectures and hand rolled application-specific
implementations that differ wildly from emulator to emulator.

``styx`` seeks to change the status quo of turning software emulation of DSP,
embedded and non-standard processors from a research task into a much simpler
software engineering task.

What is ``styx``
----------------

``styx`` is a monolithic rust project built in a workspace and is intended to be
consumed as a library. Styx packages many in-tree processor, peripheral, and device
implementations that anyone can use to create their own new processor definition, or
a machine definition that packages multiple processors together in a heterogeneous
system-of-systems emulation to create a *real* digital twin.

The goal is to have a demo template application that you can use to quickly get
off the ground with ``cargo-generate``.

``styx`` approaches the problem of emulating a new target as a *system emulation*
problem instead of just a *processor* emulation problem, with a decision tree
that any engineer can follow and fill out the checklist to create a fully supported
emulation that the ``styx`` tool suite can instrument, analyze and debug automatically.

The biggest difference is that the targets ``styx`` is intended to emulate often
require many peripherals and external devices emulated properly to run let alone boot.
The ``styx`` approach utilizes the ``Rust`` type-system and metaprogramming capabilities
to create building-block style emulation pieces that can be individually implemented,
tested and verified before integrating into an emulation solution.

Documentation Contents
----------------------

.. toctree::
   :caption: About
   :maxdepth: 1

   concepts
   installing
   quickstart
   examples
   faq

.. toctree::
   :caption: Supported Workflows
   :maxdepth: 1

   workflows
   workflows/debuggable
   workflows/traceable
   workflows/interactive
   workflows/fuzzable
   workflows/testable
   workflows/integrated

.. toctree::
   :caption: User Documentation
   :maxdepth: 1

   user/bindings
   user/unicorn_replacement
   user/processors
   user/styx_trace
   user/using_a_processor
   user/adding_a_processor
   user/using_multiple_processors
   user/backends
   user/new_architectures
   user/new_architectures_pcode
   user/adding_test_binaries
   user/migration

.. toctree::
   :caption: API Documentation + Coverage

   TODO C API Documentation <./c-api/index.html#http://>
   TODO Python API Documentation <./py-api/index.html#http://>
   api-docs/rust-api-docs
   api-docs/rust-coverage

.. toctree::
   :caption: Styx Extensions
   :maxdepth: 1

   extensions/dt_stats
   extensions/ghidra
   extensions/trace
   extensions/webapp

.. toctree::
   :caption: Developer Documentation

   developer/contributing
   developer/conventions
   developer/repository_tasks
   developer/async_rust
   developer/updating_bindings
   developer/adding_new_hook_types
   developer/layout
   developer/benchmarks
   developer/integration_tests
   developer/ci
   developer/releases
   adrs


Indices and tables
==================

* :ref:`genindex`
* :ref:`search`
