.. _processors:

**NOTE:** This is OBE and needs to be rewritten

Processor Implementation Details
################################

Most individual "units" of emulation in ``Styx`` are centered around a :ref:`concepts_processor`.


The implementation of an emulatable processor lives inside ``styx-machines``, but uses
loaders from ``styx-loader``, cpu instruction emulation from ``styx-cpu``, and backing
memory implementations from ``styx-memory``. All references to ``cpu`` on this page are
referring to a usage of a ``CpuBackend`` with a selected architecture from
``styx-cpu``.

Components of a ``Processor``
=============================

The implementation of a processor is split into three separate categories
of actual definition. This is because there are some things needed for
the creator of the ``Processor`` to make a decision on, some things that
are simple enough to have an assumed default and provide a utility macro,
and there are other things whose entire functionality can be automatically
derived from the definition of the two previous options.

These are split into three respective traits that live under ``styx-machines``:

* ``Processor`` - user defined behavior
* ``ProcessorGlue`` - simple enough defaults
* ``ProcessorImpl`` - automatic implementation from the previous traits


User-defined behavior
^^^^^^^^^^^^^^^^^^^^^

The processor trait looks something like:

.. code-block:: rust

    #[async_trait]
    pub trait Processor: std::fmt::Debug + 'static + Send + Sync {
        fn initialize(&self) -> Result<(), StyxMachineError>;
        fn cpu_start(&self, insns: Option<u64>) -> Result<TargetExitReason, StyxMachineError>;
        fn cpu_stop(&self) -> Result<(), StyxMachineError>;
        fn cpu(&self) -> CpuBackend;
        fn event_controller(&self) -> Arc<dyn EventController>;
        fn async_runtime(&self) -> Handle;
    }

Where these are the most-likely-to-change methods, and have no feasible
default as a lot of the possible choices do not work for a sizable majority.

The intention here is to give the implementer / implementation specific freedom
to handle the startup / shutdown of a processor, and to have freedom in the
creation, handling and storing of the more complicated ``async`` runtime
objects (in this case: ``Handle`` and ``EventController``).

This trait additionally allows implemented abstractions over ``EventController``,
and ``CpuBackend`` (which both work off of an abstracted ``Memory`` interface),
so that the entire suite of plugins, trace analysis, and other automated
analysis tooling only needs to work off of the specific interface and allows
room for specialized implementations that are more advantageous for one
target over another.

Macro-defined behavior
^^^^^^^^^^^^^^^^^^^^^^

The ``ProcessorGlue`` looks something like:

.. code-block:: rust

    pub trait ProcessorGlue {
        fn add_plugin(&mut self, plugin: Arc<dyn ProcessorPlugin>);
        fn set_executor(&mut self, plugin: Arc<dyn ExecutorPlugin>);
        fn executor(&self) -> Option<Arc<dyn ExecutorPlugin>>;
        fn weak_ref_set(&self, weak_ref: Weak<impl Processor>);
        fn weak_ref(&self) -> Weak<dyn Processor>;
        fn plugins(&self) -> &Vec<Arc<dyn ProcessorPlugin>>;
    }

And makes mildly sane defaults that can be automatically generated with a
provided ``processor_glue!()`` macro.

Because these methods simply get or set attributes needed by other utilities
this is a simple enough macro and implementation that it is trivial to
replace it.

Automagic defined behavior
^^^^^^^^^^^^^^^^^^^^^^^^^^

Based on the above two trait definitions, there is a provided default
where all you need to do is add a one line:

.. code-block:: rust

    impl ProcessorImpl for NewProcessorName {}

And will have automatic defaults for all the utility operations of the
``Processor``. These include managing inner plugin state, starting the
processor, and enabling the builder-pattern creation style for adding
plugins and setting the global ``ExecutorPlugin``. See the specific
module documentation for more details.
