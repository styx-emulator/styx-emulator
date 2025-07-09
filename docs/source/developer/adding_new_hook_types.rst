.. _adding_new_hook_types:


Adding New Hook Types
#####################


This quick tutorial will guide you through adding new hook types used to instrument
the emulated target program runtime. Hooks are some of the foundational pieces that
enable the emulation of hardware peripherals, interrupts, and DMA. While their effects
can seem *magic*, they're actually just a couple key types and traits that our entire
emulation stack sits on top of. Let's get started! We'll use the addition of the
memory fault types and implementation inside the unicorn backend as a real world
example.

The overall hook process can get broken down into a few different implementation sites:

* Callback type definition
* Hook type definition
* HookCallback conversion implementation
* ``CpuEngine`` addition
* Cpu backend implementations

  * Unicorn's ``hook_compat`` layer implementation

* Cpu backend test implementations

Memory Fault Specifics
**********************

Before diving in to the implementation, it's good to think about what the actual purpose of
the new feature/capability is going to be. The goal of these new hooks is to provide a
way for ``styx`` to hook on and notify any instrumentation when there is a "memory fault."

| In this case a "memory fault" is either going to be a memory protection fault or a
| memory unmapped fault.
|
| Memory Protection faults being be a mechanism that CPU backends can emit when
| a target program attempts to access code it does not have permissions to eg.
| write to a read only section, execute a read-write section etc.
|
| Memory Unmapped faults being a mechanism that CPU backends can emit when a
| target program attempts to access or manipulate memory that hasn't been mapped
| into hardware.
|

So we're going to add 2 new hook types, ``ProtectionFault`` and ``UnmappedFault``,
that are emitted on Memory Protection and Memory Unmapped faults respectively.

Callback Type Definitions
*************************

The callback typedef is the place to start, and where things can get real hairy
and hard to debug very quickly. Due to current limitations, the typedef's of each
hook **must be unique** from all of the other hooks. Otherwise it is undefined
behavior on which hooktype it will resolve at. So make sure the typedef is **unique**!

That aside, the definitions of our callbacks are pretty simple:

**Memory Protection Faults**:

.. code-block:: rust

    /// Callback fn type for Memory Protection Faults, arguments are:
    /// - `&CpuBackend`
    /// - `address: u64`
    /// - `size: u32`
    /// - `permissions: MemoryPermissions` <- permissions of the region
    /// - `fault_data: MemFaultData`
    ///
    /// Returns: bool if fault has been safely handled and target can continue
    pub type ProtectionFaultHookCBType =
        Box<dyn FnMut(&CpuBackend, u64, u32, MemoryPermissions, MemFaultData) -> bool>;

    /// Callback fn type for Memory Protection Faults, arguments are:
    /// - `&CpuBackend`
    /// - `address: u64`
    /// - `size: u32`
    /// - `permissions: MemoryPermissions` <- permissions of the region
    /// - `fault_data: MemFaultData`
    /// - `userdata: HookUserData`
    ///
    /// Returns: bool if fault has been safely handled and target can continue
    pub type ProtectionFaultHookDataCBType =
        Box<dyn FnMut(&CpuBackend, u64, u32, MemoryPermissions, MemFaultData, HookUserData) -> bool>;

    /// The type of memory fault that occurred, and any necessary metadata
    /// needed to properly handle it
    #[derive(Debug, PartialEq, Eq, Clone)]
    pub enum MemFaultData<'a> {
        Read,
        Write { data: &'a [u8] },
    }

**Unmapped Memory Faults**:

Using the above ``MemFaultData``.

.. code-block:: rust

    /// Callback fn type for Memory Protection Faults, arguments are:
    /// - `&CpuBackend`
    /// - `address: u64`
    /// - `size: u32`
    /// - `fault_data: MemFaultData`
    ///
    /// Returns: bool if fault has been safely handled and target can continue
    pub type UnmappedFaultHookCBType = Box<dyn FnMut(&CpuBackend, u64, u32, MemFaultData) -> bool>;

    /// Callback fn type for Memory Protection Faults, arguments are:
    /// - `&CpuBackend`
    /// - `address: u64`
    /// - `size: u32`
    /// - `permissions: MemoryPermissions` <- permissions of the region
    /// - `userdata: HookUserData`
    ///
    /// Returns: bool if fault has been safely handled and target can continue
    pub type UnmappedFaultHookDataCBType =
        Box<dyn FnMut(&CpuBackend, u64, u32, MemFaultData, HookUserData) -> bool>;

After which we need to add to the ``HookCallback`` enum:

.. code-block:: diff

    /// Common callback type, gets around dynamic typing issues.
    pub enum HookCallback {
        CodeCB(CodeHookCBType),
        CodeDataCB(CodeHookDataCBType),
        MemWriteCB(MemWriteCBType),
        MemWriteDataCB(MemWriteDataCBType),
        MemReadCB(MemReadCBType),
        MemReadDataCB(MemReadDataCBType),
        InterruptCB(InterruptCBType),
        InterruptDataCB(InterruptDataCBType),
        BlockCB(BlockHookCBType),
        BlockDataCB(BlockHookDataCBType),
    +    ProtectionFaultCB(ProtectionFaultHookCBType),
    +    ProtectionFaultDataCB(ProtectionFaultHookDataCBType),
    +    UnmappedFaultCB(UnmappedFaultHookCBType),
    +    UnmappedFaultDataCB(UnmappedFaultHookDataCBType),
    }


Hook Type Definition
************************

Adding the actual hook type definition really just means that you extend the
``StyxHook`` enum type to include your new hook type. Note that you should
add 2 different types, a type with, and without ``userdata``.


.. code-block:: diff

    #[derive(Derivative)]
    #[derivative(Debug)]
    pub enum StyxHook {
       // ...
    +    /// Hook on memory protection faults in a given range
    +    ProtectionFault {
    +        start: u64,
    +        end: u64,
    +        #[derivative(Debug = "ignore")]
    +        callback: ProtectionFaultHookCBType,
    +    },
    +    /// Hook on memory protection faults in a given range, with user data
    +    ProtectionFaultData {
    +        start: u64,
    +        end: u64,
    +        #[derivative(Debug = "ignore")]
    +        callback: ProtectionFaultHookDataCBType,
    +        userdata: HookUserData,
    +    },
    +    /// Hook unmapped memory accesses in a given raneg
    +    UnmappedFault {
    +        start: u64,
    +        end: u64,
    +        #[derivative(Debug = "ignore")]
    +        callback: UnmappedFaultHookCBType,
    +    },
    +    /// Hook unmapped memory accesses in a given range, with user data
    +    UnmappedFaultData {
    +        start: u64,
    +        end: u64,
    +        #[derivative(Debug = "ignore")]
    +        callback: UnmappedFaultHookDataCBType,
    +        userdata: HookUserData,
    +    },
    }


HookCallback Conversion Implementation
**************************************

This step just creates the automagic glue needed to convert from the enum variant into
the parent enum. Quick and easy (and saves a lot of code you'd want to explain later!).

.. code-block:: rust

    impl From<ProtectionFaultHookCBType> for HookCallback {
    fn from(value: ProtectionFaultHookCBType) -> Self {
        HookCallback::ProtectionFaultCB(value)
    }
    }
    impl From<ProtectionFaultHookDataCBType> for HookCallback {
        fn from(value: ProtectionFaultHookDataCBType) -> Self {
            HookCallback::ProtectionFaultDataCB(value)
        }
    }
    impl From<UnmappedFaultHookCBType> for HookCallback {
        fn from(value: UnmappedFaultHookCBType) -> Self {
            HookCallback::UnmappedFaultCB(value)
        }
    }
    impl From<UnmappedFaultHookDataCBType> for HookCallback {
        fn from(value: UnmappedFaultHookDataCBType) -> Self {
            HookCallback::UnmappedFaultDataCB(value)
        }
    }



CpuEngine Addition
******************

This step adds methods signatures to the top level ``CpuEngine`` trait that will add
the ability to add the hooks, which will actually involve changing a default method
implementation as well (don't worry if you forget -- the compiler won't let you |:slight_smile:|).

At this point before you even modify the ``CpuEngine`` trait you should have a compile
error in the implementation of ``CpuEngine::add_hook`` due to the now incomplete enum
match statement. So let's fix that first:

.. code-block:: rust

    StyxHook::ProtectionFault {
        start,
        end,
        callback,
    } => self.protection_fault_hook(start, end, callback),
    StyxHook::ProtectionFaultData {
        start,
        end,
        callback,
        userdata,
    } => self.protection_fault_hook_data(start, end, callback, userdata),
    StyxHook::UnmappedFault {
        start,
        end,
        callback,
    } => self.unmapped_fault_hook(start, end, callback),
    StyxHook::UnmappedFaultData {
        start,
        end,
        callback,
        userdata,
    } => self.unmapped_fault_hook_data(start, end, callback, userdata),

Note that we just added stub method calls following the same hook pattern naming scheme
that all the other hooks already use. More compiler errors!

Lets follow the new errors we just added and add new methods to the ``CpuEngine`` trait.

.. code-block:: rust

    fn protection_fault_hook(
        &self,
        start: u64,
        end: u64,
        callback: ProtectionFaultHookCBType,
    ) -> Result<HookToken, StyxCpuBackendError>;
    fn protection_fault_hook_data(
        &self,
        start: u64,
        end: u64,
        callback: ProtectionFaultHookDataCBType,
        userdata: HookUserData,
    ) -> Result<HookToken, StyxCpuBackendError>;
    fn unmapped_fault_hook(
        &self,
        start: u64,
        end: u64,
        callback: UnmappedFaultHookCBType,
    ) -> Result<HookToken, StyxCpuBackendError>;
    fn unmapped_fault_hook_data(
        &self,
        start: u64,
        end: u64,
        callback: UnmappedFaultHookDataCBType,
        userdata: HookUserData,
    ) -> Result<HookToken, StyxCpuBackendError>;


(Documentation comments are omitted for brevity, but make sure to add those and the
corresponding doc-test examples that all the other hook types have!)

CpuEngine Backend Test Implementation
*************************************

Before actually making the implementation (and because this task is pretty well defined),
we're going to make the tests first. This step is probably the most important step
in the entire process. Good and thorough testing of the hooks is essential,
since the rest of the emulation stack is going to be built on top of it!

In general you should always have the testing of hooks utilize a simple ``TestMachine``
that is easy to follow. And then make some simple assembler code that directly
performs behavior that will emit the event. It's not worth it to attempt to do
anything fancy at first. While this is a unit-test for the hook code we're adding,
there's a **lot** going on under the hood that can make things go wrong.


.. code-block:: rust

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_unmapped_read_hooks() {
        // tests that the hook gets called when we read from an unmapped address

        // (1) test fixture will attempt to read from address `0x9999`
        let machine = TestMachine::with_code("movw r1, #0x9999;ldr r4, [r1];");

        // create the callback variant without userdata
        let cb = |cpu: &CpuBackend, addr: u64, size: u32, fault_data: MemFaultData| {
            println!(
                "unmapped fault: 0x{:x} of size: {}, type: {:?}",
                addr, size, fault_data
            );

            cpu.write_register(ArmRegister::R2, 1u32).unwrap();


            false
        };

        // create the callback variant with userdata
        let cb_data = |cpu: &CpuBackend,
                       addr: u64,
                       size: u32,
                       fault_data: MemFaultData,
                       userdata: HookUserData| {
            let value = userdata.downcast_ref::<String>().unwrap();

            println!(
                "unmapped fault: 0x{:x} of size: {}, type: {:?}",
                addr, size, fault_data
            );
            println!("\twith userdata: {:?}", value);

            cpu.write_register(ArmRegister::R3, 1u32).unwrap();

            false
        };

        // (2) insert hooks and collect tokens for removal later
        let token1 = machine
            .proc
            .unmapped_fault_hook(0, u64::MAX, Box::new(cb))
            .unwrap();
        let token2 = machine
            .proc
            .unmapped_fault_hook_data(
                0,
                u64::MAX,
                Box::new(cb_data),
                Arc::new(String::from("userdata!")),
            )
            .unwrap();

        // (3) run the code, and assert that the exit condition is our unmapped read
        machine.run_and_assert_exit_reason(TargetExitReason::UnmappedMemoryRead);

        let end_pc = machine.proc.pc().unwrap();

        // (4) basic assertions are correct
        assert_eq!(
            0x4004u64, end_pc,
            "Stopped at incorrect instruction: {:#x}",
            end_pc,
        );
        assert_eq!(
            0x9999,
            machine.proc.read_register::<u32>(ArmRegister::R1).unwrap(),
            "r1 is incorrect immediate value",
        );

        // (5) assertions to test that the hooks we successfully called
        assert_eq!(
            1,
            machine.proc.read_register::<u32>(ArmRegister::R2).unwrap(),
            "normal hook failed"
        );
        assert_eq!(
            1,
            machine.proc.read_register::<u32>(ArmRegister::R3).unwrap(),
            "userdata hook failed"
        );

        // removal of hooks is correct
        machine.proc.delete_hook(token1).unwrap();
        machine.proc.delete_hook(token2).unwrap();

.. code-annotations::
   1. .. admonition:: Test Machine fixture
        :class: note

        In this case we re-use the in-tree ``TestMachine``, but you could also
        make your own, use a ``CpuBackendBuilder``, ``ProcessorBuilder`` etc.

   2. .. admonition:: HookToken management
        :class: note

        Here we make sure to keep track of the ``HookToken``'s so we can ensure
        that the backend can remove them later. It's important to ensure things
        cleanup nicely

   3. .. admonition:: Behavior Assertion
        :class: note

        This method is probably not the best practice, but it's going to spot
        implementation errors fast and its pretty self explanatory what's going on.

   4. .. admonition:: Simple Assertions
        :class: note

        Some might argue these aren't helpful, but this is testing and abstracting
        over an entire other codebase, so it's nice to ensure that it's doing
        what we assume it is, think of it like an integration test

   5. .. admonition:: Test Assertions
        :class: note

        These assertions are the ones actually asserting that our hooks were called,
        and able to execute our code correctly.

Now that we have the basic read implementation for the unmapped fault, we can extrapolate
the remaining 3 tests we need to write, and knock them out! The only difference for the
write case is changing the ``ldr`` instruction to a ``str``, and the difference from the
unmapped fault to the protection fault is to change the protection of the region, and
then read + write from the region.


CpuEngine Backend Specific Implementation
*****************************************

Now that the test specification is complete, the next step is to make the backend
specific logic of our hooks, in the case of the Unicorn backend our job is very
easy since these hooks are already implemented, so all that's needed is for us
to register the hooks with the inner Unicorn runtime and then to provide all the
necessary glue.

The actual "``CpuEngine``" level backend implementation is pretty boiler-plate,
just copying from the other hook code in the backend, marshaling the data into the
callback struct, and then registering the ``CallbackBody`` with the unicorn backend.

**NOTE**: This definition will use a proxy method declaration that isn't defined yet,
but we will implement this next, for explanation sake it makes much more sense to
introduce this first

.. code-block:: rust

    fn protection_fault_hook(
        &self,
        start: u64,
        end: u64,
        callback: ProtectionFaultHookCBType,
    ) -> Result<HookToken, StyxCpuBackendError> {
        // create the entire `CallbackBody`
        let mut callback_meta = Box::new(StyxHookDescriptor {
            func: callback.into(),
            backend: self.weak_ref.clone(),
            userdata: None, // (1) userdata
            start,
            end,
        });

        // make ptr for output token
        let mut hook_token = HookToken::default();

        // call the unicorn ffi to add the hook
        let err = unsafe {
            ffi::uc_hook_add(
                self.inner().get_handle(),
                hook_token.inner(),
                // we use MEM_PROT which technically is three different types:
                // - MEM_READ_PROT
                // - MEM_WRITE_PROT
                // - MEM_FETCH_PROT
                //
                // but in the proxy we map the fetch to the read error
                unicorn_engine::unicorn_const::HookType::MEM_PROT, // (2) hook type
                protection_fault_hook_proxy as _, // (3) proxy method
                callback_meta.as_mut() as *mut _ as _,
                start,
                end,
            )
        };

        if hook_token.inner().is_null() {
            return Err(StyxCpuBackendError::FFIFailure(String::from(
                "Unicorn failed to write hook pointer",
            )));
        }

        if err == unicorn_const::uc_error::OK {
            // pass ownership to the inner struct
            // add the callback to UnicornInner
            self.hook_map.add_hook(hook_token, callback_meta)?;

            // return the index item
            Ok(hook_token)
        } else {
            Err(err.into())
        }
    }


.. code-annotations::
   1. ..admonition:: Userdata
      :class: note

      Make sure that for the ``_data`` variant of this method you pass ``Some(userdata)``
      to the hook so that the userdata gets stored and later passed to the proxy + callback

   2. ..admonition:: Hook Type
      :class: note

      Make sure that the hook type is updated from implementation to implementation.
      In our case for the ``ProtectionFault`` we use ``MEM_PROT`` and for the
      ``UnmappedFault`` we use ``MEM_UNMAPPED``

   3. ..admonition:: Proxy Method
      :class: note

      Make sure that the proxy method being referred to here is updated from implementation
      to implementation, otherwise you'll get some very confusing runtime panics!

Unicorn Specific hook_compat Layer
==================================

And last but not least, we need to add the plumbing methods in the ``hook_compat``
module in the unicorn backend. These methods are used to route from the C-callback
and prep the arguments and rust-objects to be invoked properly.

For the vast majority of the code we can (again) copy another implementation, and
then touch up the comments, and arrange the relevant arguments necessary for the
actual invocation of the rust callback, final stretch!


.. code-block:: rust

    // Used in `protection_fault_hook_proxy` to ensure that the received
    // hook type is correct (1)
    const PROT_MEM_TYPE: [unicorn_const::MemType; 3] = [
        unicorn_const::MemType::READ_PROT,
        unicorn_const::MemType::WRITE_PROT,
        unicorn_const::MemType::FETCH_PROT,
    ];

    pub fn protection_fault_hook_proxy(
        _uc: unicorn_engine::ffi::uc_handle,
        mem_type: unicorn_const::MemType,
        address: u64,
        size: usize,
        value: i64, // always 0 when `mem_type` is a `READ_PROT`
        hook: *mut StyxHookDescriptor,
    ) -> bool {
        let hook = unsafe { &mut *hook };

        // match on the signature of the callback to avoid
        // ugly generic's everywhere (2)
        let callback = match &mut hook.func {
            HookCallback::ProtectionFaultCB(cb) => cb,
            _ => panic!(
                "Invalid hook type called on protection_fault_hook_proxy, got: {:?}",
                hook
            ),
        };

        // validate
        debug_assert!(
            PROT_MEM_TYPE.contains(&mem_type), // (3) make sure the event is correct
            "Invalid MemType provided to protection_fault_hook_proxy"
        );
        debug_assert!(
            address >= hook.start,
            "Trigger address: 0x{:x} is not >= hook.start(0x{:x})",
            address,
            hook.start
        );
        debug_assert!(
            address <= hook.end,
            "Trigger address: 0x{:x} is not <= hook.end(0x{:x})",
            address,
            hook.end
        );

        // (4) get the fault data for the callback
        let fault_bytes = value.to_le_bytes();
        let fault_data = match mem_type {
            unicorn_const::MemType::WRITE_PROT => MemFaultData::Write { data: &fault_bytes },
            // we map both the fetch and the read variant into `READ`
            _ => MemFaultData::Read,
        };

        let backend = hook.backend.upgrade().unwrap();

        // (5) get the permissions of the underlying memory region
        let perms = backend
            .memory_manager()
            .unwrap()
            .containing_region_perms(address, size as u64)
            .unwrap();

        // (6) call callback
        callback(&backend, address, size as u32, perms, fault_data)
    }

.. code-annotations::
    1. .. admonition:: Helper Type
        :class: note

        Here we need a simple helper type to ensure that the event we are getting
        from the unicorn C runtime is the correct sub-type that we are supposed to
        be receiving.

    2. .. admonition:: Match on the callback type
        :class: note

        Those extra impl's we did earlier? This is where we use them. This allows
        for quick n easy conversions from and into the meta-callback-enum-type
        to get the handle to the callback function without a disgusting mess of both
        ``unsafe`` **and** generic's everywhere.

    3. .. admonition:: Input validation
        :class: note

        Here we validate the input against our helper type we made

    4. .. admonition:: Getting the Memory Write data
        :class: note

        Here we get the data from the memory write operation that the target program
        was attempting to write, in case this information is helpful to either the
        hook as a part of mapping in the memory, or to the person lucky enough to
        debug this error in the target program

    5. .. admonition:: Getting necessary metadata for the callback
        :class: note

        We need to get the current memory permissions for the ``ProtectionFault``,
        this is just an example of using the handle to the ``CpuBackend`` to
        get the required information

    6. .. admonition:: Calling the callback
        :class: note

        Finally we have all the information needed by the callback, and we have validated
        the data from the ``CpuBackend`` to ensure its not bad data
