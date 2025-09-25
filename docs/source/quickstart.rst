.. _quickstart:

Quickstart
==========

.. _quickstart_raw_processor:

RawProcessor
############

After completing the :ref:`installing` of ``Styx`` as a dependency of your crate, the simplest quickstart in Rust is probably the following:


.. literalinclude:: ../../examples/raw-processor/src/main.rs
    :lines: 2-
    :linenos:
    :language: rust

Note that line 20,21,22 are optional plugins, where the ``ProcessorTracingPlugin``
provides easy avenues to get output from processors, and the ``*MemoryFaultPlugins``
provide an easy ability to stop when a memory releated error occurs in the
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
