.. _unicorn_replacement:

Styx as a Replacement for Unicorn
#################################

Styx can be used as a replacement for Unicorn i.e. purely as a CPU emulator.  The following examples show how to emulate 32 bit Arm code using either Rust or Python.  Both examples produce identical results.

Rust Example
============

Run this example with ``cargo run -p unicorn-replacement``.

.. literalinclude:: ../../../examples/unicorn-replacement/src/main.rs
    :lines: 2-
    :linenos:
    :language: rust

Python Example
==============

Run this example with ``python3 main.py`` from
``styx/bindings/styx-py-api/examples/unicorn-replacement``.

.. literalinclude:: ../../../styx/bindings/styx-py-api/examples/unicorn-replacement/main.py
    :lines: 3-
    :linenos:
    :language: python
