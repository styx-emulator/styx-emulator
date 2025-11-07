
.. _memory_write_hooks_cannot_modify_the_written_bytes_adr:

2. Memory Write Hooks Cannot Modify The Written Bytes
#####################################################

Memory Write Hooks Cannot Modify The Written Bytes
==================================================

Status: Valid

Overview
========

Memory write hooks are not able to modify the data that is being written. We
are keeping this behavior to stay compatible with Unicorn's memory write hook
behavior.


Context
=======

Memory write hooks are triggered on a target memory write instruction, but
before the instruction writes the data to memory. The footgun effect of this is
that data written to the address that triggered the callback will not persist
after the callback.

This is the behavior of Unicorn's memory write hooks.

There is a workaround is to add a read callback on the same address
and modify the read value from the target address there.

Decision
========

We will keep this behavior to keep compatibility with Unicorn.


Consequences
============

This makes it slightly harder to modify memory writes.

Notes
=====

This behavior is documented in ``StyxHook``` documentation.
