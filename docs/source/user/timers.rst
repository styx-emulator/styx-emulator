Timers
======

Timers are fundamental components commonly found in processors. A timer operates
by periodically generating an interrupt request (IRQ) after a specified number
of instructions have executed. These IRQs can typically be masked or configured
to control their trigger frequency. In real-time operating systems (RTOS),
timers are essential for task switching, while in general-purpose operating
systems, they are used for time tracking and scheduling.

Styx provides several approaches for implementing timers, each with different
trade-offs between accuracy, performance, and implementation complexity.

We distinuquish between target timer registers being **memory mapped I/O**
for peripherals (e.g. arm) or **CPU registers** (e.g. PowerPC's ``TBL`` and
``TBU``).

A naive implementation of a timer IRQ may use an asyncronous timer that triggers
every 100ms, or other constant duration. However, you will find that most of
these implementations listed here rely on triggering timer IRQs after a constant
number of instructions, rather than duration of time. This is to ensure target
emulation is **deterministic** across executions. This is becase instruction
cycles are not linked to a specific timestep so the host machines CPU speed and
load will change how many instructions are executed in a given 100ms wall clock
time interval from one run to the next. What this materializes into is that a
bug may occur if a timer is triggered at a specific instruction type or in a
critical point in a task. To investigate further, you rerun the test and the
next run, your host machine is slightly faster and instead of triggering at the
critical point, the timer is triggered at a benign instruction, thus missing
the bug.

Without deterministic execution, debugging becomes
difficult. It is recommended your timer implementation follows this advice.

See more about the :ref:`async-implementation` and the example processor that uses it below.

Code Hook Implementation
------------------------

The first approach to implementing a timer in Styx is to use a Code Hook on
every address. Code Hooks execute before the instruction at their registered
address. By creating a code hook on every address using ``StyxHook::code(..,
my_hook)``, the hook will trigger on every instruction. This hook can increment
an internal counter and/or update a register (either memory-mapped or CPU
register) to maintain the timer state. When the timer condition is met, the
code hook has access to the ``EventController`` to latch the appropriate timer
IRQ.

**Pros:**

1. Timer state is updated every instruction, ensuring hardware accuracy.
2. Simple to implement.
3. Works with all timer implementations (memory-mapped registers, CPU registers).

**Cons:**

1. Significant performance cost.

**Examples:**

1. ``ppc4xx`` / ``styx/processors/ppc/styx-ppc4xx-processor/src/timers.rs``

Tick-Based Implementation
-------------------------

The second approach is to update timers in the ``tick()`` function of a
peripheral or event controller. This method is similar to the code hook approach
but executes less frequently, usually once every 1000 instructions [#note1]_.
At every ``tick()``, the Event Controller or Peripheral will write the CPU or
Memory Mapped timer register with the current timer state. Then, the same system
of code can trigger the timer IRQ as configured.

In order to configure the timer, this method may involve reading timer
configuration registers periodically or creating a Memory Write hook on the
MMIO registers used to configure the timers. The ``tick()`` function reduces
the performance penalties compared to the Code Hook method (though not entirely)
while maintaining reasonably accurate emulated state.

Critically, the ``tick()`` function supplies the number of instructions executed
in the previous stride. This can be used to properly calculate the progress
to the next timer trigger ensuring each timer interrupt latches after the same
number of instructions.

Optionally, this method can be used without writing to the register, if the
target program doesn't read from the timer and only operates off of the IRQs.

**Pros:**

1. Hardware accuracy is maintained to a reasonable degree (registers are updated).
2. Works with all timer implementations (memory-mapped registers, CPU registers).
3. More performant than the code hook approach.

**Cons:**

1. Performance cost from register/memory operations approximately every 1000 instructions.
2. Target timer state not up to date between ticks.
3. Requires scaling logic for tick-based implementation.


**Examples:**

1. ``kinetis21`` / ``styx/processors/arm/styx-kinetis21-processor/src/systick.rs``
    1. Note: this implementation does not write to the actual register, it only triggers IRQs.

.. [#note1]
   The number of instructions between ``tick()`` is called the "stride
   length". It is constant throughout emulation and statically defined in
   the ``ExecutorImpl::get_stride_length()``. This value is 1000 for the
   ``DefaultExecutor``. The exeception is the ``GdbExecutor`` which uses custom
   stride lengths depending on if there are memory watch events. The stride
   length for the ``GdbExecutor`` is configurable via ``GDBOptions``.

Memory Read Hook Implementation
--------------------------------

Another approach is to use ``tick()`` to maintain an internal counter of the
target timer status and create a Memory Read Hook on the timer register for
target operations. This method only works with timers that have memory-mapped
registers. It offers better performance than writing to memory/registers on
every ``tick()`` since updates occur only when the target actually reads the
register. The timer IRQ can be latched at the appropiate time in the ``tick()``
implementation.

**Pros:**

1. Good performance, as memory/register is written only when needed by the target.

**Cons:**

1. Only applicable to memory-mapped registers.
2. Target timer state may not be up to date between ticks.
3. Requires scaling logic for tick-based implementation.
4. Timers are only updated via memory hooks, so GDB and Styx ``read_memory()`` operations will not reflect current timer register status.

Register Read Hook Implementation
----------------------------------

This approach adds a Register Read hook to the timer register. It is similar to
the Memory Read Hook solution but relies upon the Register Read Hook, which is
currently exclusive to the Pcode Backend. This method has similar advantages and
disadvantages to the Memory Read Hook approach. The timer IRQ can be latched at
the appropiate time in the ``tick()`` implementation.

**Pros:**

1. Good performance, as memory/register is written only when needed by the target.

**Cons:**

1. Only applicable to CPU timer registers.
2. System status may not be up to date between ticks.
3. Requires scaling logic for tick-based implementation.
4. Timers are only updated via memory hooks, so GDB and Styx ``read_memory()`` operations will not reflect current timer register status.
5. Requires the Pcode Backend.

PC Manager Implementation
--------------------------

Another approach is to add timer logic directly in the PC manager of the Pcode
Backend. This is a specialized solution that requires your processor to use
the Pcode Backend. It offers good performance since the PC manager is already
executing (no additional hooks or branches required). This method updates every
instruction and can leverage RegisterHandlers to provide completely accurate
timer register values for CPU registers. Memory-mapped registers will require
either a memory read hook or direct memory writes.

**Pros:**

1. Good performance.
2. Target emulation accurate (updated every instruction).
3. CPU and Memory Mapped registers.

**Cons:**

1. Strongly tied to the Pcode Backend.
2. Memory-mapped registers still require a memory write.

.. _async-implementation:
Async Implementation
--------------------

In this approach we use the available async runtime to run a timer that is
triggered after a duration. Once the async timer is triggered, a syncronization
method is used (``AtomicBool``, channel, etc.) to latch the IRQ on the next
``tick()``.

This method is not recommended because IRQs will not be triggered
deterministrically which makes debugging difficult. This also causes certain
plugins/executors to alter emulation by slowing emulation down, thus increasing
timer IRQ frequency.

With a sufficently stable processor, async based timer implementations may be a
useful alternative in performance critical testing.

**Pros:**

1. Easy to implement.
2. Performant.

**Cons:**

1. Indeterministic execution.

**Examples:**

1. ``bfin`` / ``styx/processors/bfin/styx-blackfin-processor/src/timers/mod.rs``
