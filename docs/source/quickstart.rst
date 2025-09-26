.. _quickstart:

Quickstart
==========

.. card:: Get Started in Minutes
   :class-header: sd-bg-primary sd-text-white sd-font-weight-bold
   :class-card: sd-border-0

   Follow this guide to create your first Styx emulator after :ref:`installing` Styx.

.. tab-set::

   .. tab-item:: Linux

      .. code-block:: bash

         # make a new example
         cargo new examples/my-new-example

         # build the codebase
         just build

   .. tab-item:: Docker Setup

      .. code-block:: bash

         # Build the Docker container
         just build-docker

         # make a new example
         cargo new examples/my-new-example

         # Run commands in Docker
         just docker build

.. _quickstart_raw_processor:

RawProcessor
------------

.. admonition:: Simple Start
   :class: note

   The RawProcessor is perfect for quick prototyping and testing. It provides a flexible
   processor without peripherals or event controllers.

After completing the :ref:`installing` of ``Styx`` as a dependency of your crate, here's a simple quickstart:


.. literalinclude:: ../../examples/raw-processor/src/main.rs
    :lines: 2-
    :linenos:
    :language: rust

Note that plugins are optional, where the ``ProcessorTracingPlugin``
provides easy avenues to get output from processors, and the ``[**]MemoryFaultPlugins``
provide an easy ability to stop when a memory related error occurs in the
``TargetProgram``.

The parameterized loader is a convenient way to layer input data into ``Styx``,
and provides an approachable way to use all of the other loaders eg. ELF, binary
blob, empty memory, proprietary BFIN loaders etc.

Note that this example is not using a real processor, just a ``RawProcessor``. This
means it cannot use any ``Peripheral``'s or ``EventController``'s, and is effectively
a more flexible version of ``Unicorn``.

.. _quickstart_full_processor:

Full Processor
##############

Using a pre-built processor is also easy, you can get away with even less code
in many cases:

.. code-block:: rust
    :linenos:

    use styx_emulator::core::processor::executor::Executor;
    use styx_emulator::prelude::*;
    use styx_emulator::processors::arm::kinetis21::*;
    use tracing::info;

    /// path to yaml description, see [`ParameterizedLoader`] for more
    const LOAD_YAML: &str = "load.yaml";

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        let proc = ProcessorBuilder::default()
            .with_backend(Backend::Pcode)
            .with_loader(ParameterizedLoader::default())
            .with_executor(Executor::default())
            .with_plugin(ProcessorTracingPlugin)
            .with_target_program(LOAD_YAML)
            .build::<Kinetis21Builder>()?;

        info!("Starting emulator");

        proc.start()?;

        Ok(())
    }

.. _quickstart_python:

Python Processor
################

And a similar use via the python API:

.. literalinclude:: ../../styx/bindings/styx-py-api/examples/simple-stm32f107/main.py
    :language: python
    :linenos:
    :lines: 26-
