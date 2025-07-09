.. _fuzzable_workflow:

Fuzzable Emulation
##################

Styx supports fuzzing with `LibAFL <https://aflplus.plus/libafl-book/>`_

Building a Fuzzing Capable Processor in Styx
============================================

Two components are required for fuzzing to work.  First, the ``FuzzerExecutor`` needs to be assigned as the executor for your processor.  The ``FuzzerExecutor`` requires a configuration struct upon creation, the configuration options are covered in another section.

Second, the trace plugin with basic block events needs to be enabled.  The trace plugin is how the fuzzer gets coverage data from emulation.

.. code-block:: rust

    let proc = ProcessorBuilder::default()
            .with_endian(ArchEndian::LittleEndian)
            .with_variant(ArmVariants::ArmCortexM4)
            .with_executor(Executor::new_unlimited(Arc::new(FuzzerExecutor::new(
                COVERAGE_MAP_SIZE,
                StyxFuzzerConfig {
                    timeout: Duration::from_secs(1),
                    branches_filepath: String::from("./branches.txt"),
                    exits: vec![0xba2],
                    max_input_len: MAX_INPUT_LEN,
                    input_hook: Box::new(insert_input),
                    setup: Box::new(pre_fuzzing_setup),
                    context_restore: Box::new(context_restore),
                    context_save: Box::new(context_save),
                },
            ))))
            .with_plugin(StyxTracePlugin::new(false, false, false, true))
            .with_loader(RawLoader)
            .with_target_program(get_firmware_path())
            .build::<Kinetis21Cpu>()?;

Code Coverage
-------------

Styx measures code coverage at the basic block level, keeping track of how many times each basic block is hit.  To achieve this, when building your processor you need to provide a file containing the addresses of each basic block in your firmware.  We provide a Ghidra script that can generate this file, ``styx/plugins/styx-fuzzer/GetBranches.java``.


Fuzzer Config
=============

The ``StyxFuzzerConfig`` struct defines important configuration options for fuzzing, explained below.

.. code-block:: rust

    pub struct StyxFuzzerConfig {
        /// timeout for fuzzing executions
        pub timeout: Duration,
        /// path to file containing branch information, after running GetBranches.java in ghidra
        pub branches_filepath: String,
        /// addresses at which to exit emulation
        pub exits: Vec<u64>,
        // max input length
        pub max_input_len: usize,
        /// By default the fuzzer just writes inputs into memory at the location specified
        /// in this config.  If other target specific actions need to be taken when inserting
        /// inputs (like setting the value of a register) then a custom function should be
        /// provided.
        #[derivative(Debug = "ignore")]
        pub input_hook: InputCallbackType,
        /// Pre-fuzzing setup
        #[derivative(Debug = "ignore")]
        pub setup: SetupCallbackType,
        /// functions for saving and restoring context
        #[derivative(Debug = "ignore")]
        pub context_save: ContextSaveCallbackType,
        #[derivative(Debug = "ignore")]
        pub context_restore: ContextRestoreCBType,
    }

There are a few functions that need to be defined to handle certain actions.

**setup**
 * A function that takes a reference to a processor.  This should do everything required to get the program ready to fuzz.  This could include doing things like emulating your firmware up to a certain point, setting registers/memory to some desired initial state, or receiving an external input from a peripheral.

**input_hook**
 * A function that takes a reference to a cpu backend and a reference to the data to be inserted for an execution.  This will most likely be just writing data to memory, but could do other things like setting a register to a certain value.

**context_save/context_restore**
 * These functions are responsible for producing a snapshot of the cpu state to restore from, as well as reseting the cpu state after an execution.  ``context_restore`` will be called very frequently, so make sure you are doing only necessary actions to make fuzzing as fast as possible.
