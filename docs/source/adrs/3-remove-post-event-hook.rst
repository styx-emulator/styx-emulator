
.. _remove_post_event_hook_adr:

3. Remove Post Event Hook
#########################

Remove Post Event Hook
**********************

Status: Valid

Overview
========

Styx previously exposed a ``post_event_hook`` callback that notified a
peripheral once the firmware had finished handling an interrupt that the
peripheral originally raised. This mechanism was architecture specific, fragile,
and had no meaningful users that couldn't function without this functionality.

The UART peripheral was the only user of this functionality and it only used it
to recheck recieve buffers, something that could be done at the next tick.

We have decided to remove ``post_event_hook`` and all related "peripheral event
done" callbacks.

Context
=======

The ``EventDispatcher`` handles events, or interrupts, from
peripherals. Each event is either serviced or ignored, depending on the
event controller's state and the control flow determined by the processor.

A typical flow proceeds as follows. First, a peripheral encounters an
interrupt-triggering event. For example, a character arrives on the UART
bus. The UART peripheral then raises an interrupt. The event
dispatcher sees that the interrupt is pending and decides that it should be
handled by core 0. Core 0 jumps to the interrupt handler, probably reads
from the UART rx MMIO register, and then returns from the interrupt to
resume execution.

At this point, previously, Styx would call ``post_event_hook`` on the UART
peripheral that originally raised the interrupt in order to clean up the
peripheral state post-interrupt or recheck state to send another event.

Decision
========

The decision comes down to the fact that this design has large implementation
challenges and provides questionable value to helping write peripherals.

First, detecting interrupt completion is architecture specific and fragile.
Different architectures signal a return-from-interrupt in different ways
(for example, magic ``EXC_RETURN`` values on ARM's NVIC versus an
invalid-instruction trampoline on ppc4xx), and completion detection is not a
feature in the design of processor event controllers at all.

Second, the assumption that are interrupts are "returned from" is untrue, or
at best needs more context. "Returning from an interrupt" involves several
components such as restoring the register file, resuming execution from the pc
that was present at the time of interrupt, a status bit in a system registers,
and probably a couple other things. Which of these heuristics is the correct for
"return from interrupt" changes depending on the context in which the interrupt
is taken. The burden of determining the interrupt state is too complex for the
event controller to be expected to parse through.

As an example FreeRTOS on PPC takes an interrupt and then never returns to the
same address from it; this is simply the kernel continuing to run in privileged
execution mode.

Beyond the implementation challenges, it is unclear how the callback would help
peripherals operate. Real processor hardware should only drive interrupt lines
high. The signal that an interrupt has been handled comes from the firmware
reading state or writing a status to an MMIO register. In other words, it is not
reported by the event controller or over a separate line.

Finally, the callback has essentially no meaningful users; the only
non-trivial one is the UART implementation. This is discussed further in the
Consequences section below.

We have decided to remove ``post_event_hook`` and any related "peripheral
event done" callbacks from Styx. This includes the callbacks in the
``Peripheral`` trait as well as the UART and SPI implementations.

Consequences
============

The primary user of this callback was the UART implementation
(`styx/peripherals/styx-uart`). There, the peripheral waited for
``post_event_hook`` after raising the interrupt with an rx byte ready. The
``post_event_hook`` signaled to the peripheral that the firmware had handled the
rx byte, prompting it to check its queues for another rx byte. In practice this
is a minor, inconsequential change, since the incoming rx buffer is checked on
the next tick anyway.

Notes
=====

Users who need post interrupt hook functionality for their peripheral should use
a combination of read/write memory hooks on mmio registers for their peripheral,
or use `tick()` to run peripheral logic outside of mmio hooks to check async
state or other non-mmio related logic.

CPU implementors can still (and will need to) implement return from interrupt
instructions to perform the context restore.
