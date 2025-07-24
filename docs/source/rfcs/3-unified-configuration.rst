.. _unified_configuration_rfc:

3. Unified Configuration
########################

Unified Configuration
=====================

Status: Accepted

Summary
=======

Present a declarative configuration for spawning Styx processors (Unified
Configuration/UConf) and a declarative configuration for connecting peripherals
of Styx devices (Peripheral Communication System/PCS).

Motivation
==========

Styx allows for fine grained configuration of emulators (Processors) using its
Rust, C, and Python APIs, if you know how to use them. While the programmatic
APIs are useful for testing and developing Styx, security researchers would be
better off with a simpler, more declarative emulator configuration framework.

Supplementary to this, There is an increased demand to use Styx as a service
for creating emulators as opposed to a tool to create emulators. To enable
this, there is a need for a declarative method of creating, storing, and
sharing processor configurations.

Similarly, there exists a need for emulators to be able to connect compatible
peripherals to each other (e.g. SPI <-> SPI, DMA <-> DMA, I2C <-> I2C). The low
level IPC is present (using gRPC) but connections are facilitated manually, and
there are no methods of introspecting a processor's peripheral capabilities.

Details
=======

Unified Configuration
---------------------

The meat and gravy of the work here is providing a "batteries included" list of
configuration options to choose from.

First, the configuration is deserialized into a structure, the
:ref:`ProcessorBuilderConfig`. This includes all static information and
represents a "valid configuration" but does not guarantee that it is able to be
emulated. Builder items that are rust objects (e.g. ProcessorImpl and Executor)
are passed as an ID for the processor implementation. More on this in
:ref:`custom-implementations`.

It's at this point that configurations are in a native Rust structure and can
be stored or modified by external sources. For example, a CLI tool may override
processor configuration options.

Second, a :ref:`WorkspaceConfigMap` is constructed and additional
:ref:`ProcessorImplSpec`, ExecutorSpec, and PluginSpec can be registered here.

Finally, the :ref:`ProcessorBuilderConfig` is combined with the
:ref:`WorkspaceConfigMap` to create a ProcessorBuilder and then Processor.

.. code:: Rust

    fn main() {
        // processor config in yaml format
        let config_yaml = "...";
        let config: ProcessorBuilderConfig = serde_yaml::from_str(config_yaml).unwrap();

        let mut mapper = WorkspaceConfigMap::default();

        // register included and custom processors
        mapper.register_processor_impl(ProcessorImplSpec {
            name: "Powerpc 405".to_owned(),
            id: "ppc405".to_owned(),
            implementation: todo("powerpc impl"),
        });

        // create the builder and use as normal from there
        let builder = mapper.create(&config);
        let proc = builder.build();
    }


.. _custom-implementations:

Arbitrary Implementations
^^^^^^^^^^^^^^^^^^^^^^^^^

The naive approach to selecting a processor to use would be an enum with all
available processors to choose from. This would work but would require changes
to the unified configuration crate to implement. Instead, we propose a way of
registering these arbitrary implementations.

Components requiring "arbitrary implementations":

1. ProcessorImpl, this is the example used in this document.
   - See :ref:`ProcessorImplSpec` and :ref:`ProcessorImplConfig`
2. Plugins
3. Executors
4. Cpu Backends

Notably loader is absent. We can use the Parameterized loader for this. See
:ref:`program-loading`.

Registration would occur using either :ref:`register-inventory` or
:ref:`register-object`. I think that we could support both methods.

.. code:: Rust

    struct ProcessorImplConfig {
        name: String,
        id: String,
        implementation: Box<dyn ProcessorImpl>,
    }


Configuration of Backends, Plugins, etc.
""""""""""""""""""""""""""""""""""""""""

Configuration of plugins, backends, executors, and processor impls is
important. The current Styx bindings lack configuration just because it is hard
to implement in a language agnostic way without taking lots of developer time.

For our Unified Configuration, we propose a `config` item next to the `id` that
can be optionally supplied to provide arbitrary config data. Then, when
registering with the config mapper, each arbitrary impl will be configured via
this config structure.

The implementation should log the config passed to an arbitrary impl to aid in
debugging.

.. _register-inventory:

Register Using Inventory
""""""""""""""""""""""""

To make adding plugins easier, we will use the `Inventory`_ crate to allow
linking to styx-unified-configuration and register their arbitrary impl
components (processors, plugins, executors, cpu backends). External crates
would register/submit their :ref:`ProcessorImplSpec` via Inventory and
consumers of the spec would simply include the crate in their Cargo.toml.

.. _Inventory: https://docs.rs/inventory/latest/inventory/

.. _register-object:

Register Using Normal Object
""""""""""""""""""""""""""""

This would simply be a method on the :ref:`WorkspaceConfigMap` to register
specs, the Inventory method would use this.


.. _program-loading:

Loading Programs
^^^^^^^^^^^^^^^^

We will use the ParametrizedLoader to load programs.

One concern is that the ParametrizedLoader uses file paths to specify programs
to load, if the yaml config is delivered remotely in the future this wouldn't
make sense.

Listed under :ref:`declarative-programs`, there could be a way of defining and
registering loadable programs similar to :ref:`custom-implementations` and then
referencing via ID but this is not required for the scope of this RFC/feature
set.


Core Structures
^^^^^^^^^^^^^^^

Below are some of the core structures used in the implementation.

.. _ProcessorBuilderConfig:

ProcessorBuilderConfig
""""""""""""""""""""""
.. code:: Rust

    #[derive(Deserialize)]
    struct ProcessorBuilderConfig {
        name: String,
        processor: ProcessorImplConfig,
        executor: ExecutorConfig,
        plugins: Vec<PluginConfig>,
        cpu_backend: BackendConfig,

        port: IPCPort,
        exception_behavior: ExceptionBehavior,
        /// from parameterized loader
        program: LoadRecords,
    }

.. _ProcessorImplSpec:

ProcessorImplSpec
"""""""""""""""""
.. code:: Rust

    type ArbitraryImplConfig = Option<serde_yaml::Value>;

    type ProcessorImplCreateFn = Box<dyn FnOnce(&ArbitraryImplConfig) -> Box<dyn ProcessorImpl>>;

    struct ProcessorImplSpec {
        name: String,
        id: String,
        implementation: ProcessorImplCreateFn,
    }

.. _ProcessorImplConfig:

ProcessorImplConfig
"""""""""""""""""""
.. code:: Rust

    #[derive(Deserialize)]
    struct ProcessorImplConfig {
        /// ID referencing the processor it's referring to
        ///
        /// Must match the ID given from [`ProcessorImplSpec`]
        id: String
        /// Optional arbitrary configuration
        config: Option<serde_yaml::Value>,
    }


.. _WorkspaceConfigMap:

WorkspaceConfigMap
""""""""""""""""""
.. code:: Rust

    struct WorkspaceConfigMap {
        processor_impl_specs: Vec<ProcessorImplSpec>,
        executor_specs: Vec<ExecutorSpec>,
        plugin_specs: Vec<PluginSpec>,
    }

    impl WorkspaceConfigMap {
        pub fn register_processor_impl(&mut self, spec: ProcessorImplSpec) {
            todo!()
        }

        /// Collects from Inventory
        pub fn collect_specs(&mut self) {
            todo!()
        }

        pub fn create(&self, config: &ProcessorBuilderConfig) -> ProcessorBuilder {
            todo!()
        }
    }


Spec Example
^^^^^^^^^^^^

Here is what a spec would look like.

.. code:: yaml

    - name: My PPC405 Processor
      processor:
        id: ppc405
      backend:
        id: pcode
        config:
          register_hooks: false
          cache: true
      # could be omitted because it is the default
      executor:
        id: default
      plugins:
        - id: trace
          config:
            pc_trace: true
            write_memory: true
            read_memory: false
            block_trace: false
        - id: another_plugin
      port: 1337
      exception_behavior: panic
      program:
        - !FileElf
          base: 0x10000
          file: foo.elf
        # other parameterized loader items here

Peripheral Communication
------------------------

The peripheral communication service (PCS) will be implemented as an application run
side-by-side to emulators that need to be connected. After spawning the
emulators, a user would run the peripheral communication service with a config
that specifies processors available to communicate with as well as connections
between them.

The PCS acts as a gRPC client of both processors.

Protocols
^^^^^^^^^

UART
""""

Uart connections are one to one. The Tx and Rx of the ``from`` processor's uart
port are connected to the Rx and Tx of the ``to`` processor's uart port. The
PCS subscribes to the ``from`` processor's ``BytesMessage`` stream and will
route Tx messages on the ``from`` processor port into ``Receive`` calls in the
``to`` processor's port.

Direction is referred to from the ``from`` processor's perspective. I.e.
``direction: tx`` would mean the ``from(tx) -> to(rx)`` connection is made by
the reverse connection is not made.

SPI
"""

Spi connections are not one to one, all slaves connect to a master. Like Uart,
a processor can have multiple spi ports that are connected independently.

In a tradition spi setup, there is one chip select wire per slave connected to
a pin on the master. The wiring is simulated in the PCS. The PCS configuration
contains a chip_select_id per slave which will be stored and used to map
packets emitted from the master to the correct slave.

.. code::

    Processor 1 (Master) ---> PCS (grpc client) ---> Processor 2 (Slave, grpc server)
                      |         |
                      |         ---> Spi Client (new code, grpc server)
     Spi Client  <-----
    (existing grpc client, minimal changes)


I2C
"""

TODO: So does i2c


Devices
^^^^^^^

Devices in context of the PCS are gRPC servers that the PCS can communicate
with.

There are two types of devices, :ref:`Remote Devices` and :ref:`Spawn Devices`.

Both devices resolve to a gRPC server with a ``host:port`` to attach to busses.

Devices are configured under the top level ``device`` list and referenced by
string id primarily. Devices can also be declared inside the ``device`` field
of protocols by instead passing a structure that matches the items of the
device array.

.. _Remote Devices:

Remote Devices
""""""""""""""

Remote devices are remote gRPC servers that the PCS proxies traffic to and
from. PCS configuration defines Remote Devices with a host and port. These
devices are expected to run without orchestration from the PCS.

.. _Spawn Devices:

Spawn Devices
"""""""""""""

Remote devices are gRPC servers that the PCS creates and proxies traffic to and
from. PCS configuration defines Spawn Devices by its type and model. It is then
the PCS's responsibility to construct the device with the given configuration
parameters, provide connection arguments when connected to busses, and destroy
the device on PCS close.


Configuration
^^^^^^^^^^^^^

The PCS is configured primarily via the :ref:`yaml-specification` but it should
also be configurable via


.. _yaml-specification:

Yaml Specification
^^^^^^^^^^^^^^^^^^

This is an example of the Peripheral Communication config.

.. code:: yaml

  devices:
    - !Remote
      id: processor_1
      # used for name attribute in service registration
      name: Processor 1
      host: localhost
      port: 18000
    - !Remote
      id: processor_2
      name: Processor 2
      host: localhost
      port: 18001
    - !Spawn
      id: my_rtc
      name: My Rtc
      type: RTC
        device_type: Rtc1022A
        config:
          - arg1: val1
          - arg2: val2

  connections:
    - !Uart
      from:
        device: processor_1
        # name override
        name: Processor 1 Uart0
        # ports are strings
        port: "0"
      to:
        device: processor_2
        port: 1
      # in the `both` case, you could flip the from and to processors
      direction: both
    - !Spi
      master:
        device: processor_1
        port: 1
      slaves:
        - device: processor_2
          # refers to chip select id of master, usually gpio number
          chip_select: 0
          port: 1
        # from ad-hoc device declaration
        - device: my_rtc
          chip_select: 1
          port: 1
        # new ad-hoc device declaration
        - chip_select: 2
          port: 1
          device:
            !Spawn
            id: my_rtc_2
            name: My Rtc
            type: RTC
              device_type: Rtc1022A
              config:
                - arg1: val1
                - arg2: val2
    - !I2C
      master:
        processor: processor_1
        port: 1
      slaves:
        - processor: processor_2
          port: 1

TODO: I feel like the processor should define the i2c device address somehow,
not the peripheral communication config.


Drawbacks/Alternatives
======================

Future Work
===========

.. _declarative-programs:

Declarative Target Programs
---------------------------

A better way of defining target programs would be to have a configuration of
available programs with their own IDs. The available programs can have any
backing data storage e.g. local, remote, repo, or cloud/S3. Additionally, this
allows multiple emulators to reference the same target program.
