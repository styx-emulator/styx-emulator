.. _unified_configuration:

Unified Configuration (styx-uconf)
###################################

Unified Configuration provides a configuration interface to declaratively
construct processors and connect their peripherals. It is currently in
incubation and should not be considered stable.

Styx allows for fine grained configuration of emulators (Processors) using its
Rust, C, and Python APIs, if you know how to use them. While the programmatic
APIs are useful for testing and developing Styx, security researchers would be
better off with a simpler, more declarative emulator configuration framework.

Supplementary to this, there is an increased demand to use Styx as a service
for creating emulators as opposed to a tool to create emulators. To enable
this, there is a need for a declarative method of creating, storing, and
sharing processor configurations.

Here is an example styx.yaml file.

.. code-block:: yaml

    version: 1
    processors:
    - name: FreeRTOS Processor
      processor: ppc_4xx
      backend: Pcode
      executor:
        id: gdb
        config:
          connection: 127.0.0.1:9999
          arch: Ppc405
          verbose: true
      program:
      - !FileRaw
        base: 0xfff00000
        file: ../../data/test-binaries/ppc/ppc405/bin/freertos.bin
        perms: !AllowAll
      - !RegisterImmediate
        register: pc
        value: 0xfffffffc


The styx.yaml can be ran using the ``styx-uconf`` library or using the
``styx-uconf-cli``, both of which are in incubation.

.. code-block:: console

    $ cargo run --manifest-path path/to/incubation/styx-uconf-cli/Cargo.toml -- --help
    Usage: styx-uconf-cli [COMMAND]

    Commands:
    list  Lists available components
    run   Runs a configuration file
    help  Print this message or the help of the given subcommand(s)

    Options:
    -h, --help     Print help
    -V, --version  Print version

In the ``styx.yaml`` configuration, at the top level there is a ``version`` and
``processors`` mappings. ``version`` specifies the schema version ensuring
future styx-uconf invocations work with previous schemas. ``processors``
contains a list of processors in this definition.

An item in the ``processors`` list corresponds to a ``ProcessorBuilder`` in
styx. The concepts are largely the same and most options have reasonable
defaults. The largest difference is how custom plugins, executors, and
processors are defined, collectively referred to as **components**.

Components
==========

Components are non-trivial, functional, and user-defined configuration of the
processor. Currently, the complete set of components classes are plugins,
executors, and processor impls.

Components are non-trivial and functional so they are represented as traits in
styx and passed to/stored in the ``ProcessorBuilder`` as a ``Box<dyn trait>``.
In the unified configuration we handle this by **registering** components in
the styx-uconf build and referring to these components by id. Additionally,
because they are non-trivial, there is an method to provide arbitrary yaml
configuration to the component.

A component declaration in a processor configuration has an ``id`` and a
``config``.

.. code-block:: yaml

    executor:
      id: gdb
      config:
        connection: 127.0.0.1:9999
        arch: Ppc405
        verbose: true

The ``config`` schema is entirely defined by the component so refer to your
component reference for more information on its config.

The ``config`` can be omitted and ``id`` flattened to provided a less verbose
declaration.

.. code-block:: yaml

    executor: gdb

Components that are registered in the build can be found using the
styx-uconf-cli command ``list``. Refer to the ``styx-uconf`` crate
documentation for details on registering additional components.


Other Parameters in Processor
=============================

``name`` is purely cosmetic and for debugging and displaying the processor.

``backend`` corresponds to the ``Backend`` struct.

``executor`` refers to the ``ExecutorImpl``.

``program`` is a ``ParameterizedLoader`` input to provide firmware files,
initial registers, and memory regions.

``plugins`` is a list of plugin components that will be added to the
processors.
