.. _faq:

Frequently Asked Question's (FAQ's)
===================================

Is there a snapshot fuzzer?
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Yes! See :ref:`fuzzable_workflow` for more information |:slight_smile:|

Does this work on [non-linux operating system name]?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Nope! This is not supported, though the list of things that are linux-specific
are:
- ``styx-trace``: using THP on linux and mmaping a shared memory ring buffer
- ``tokio-timerfd``: using linux timerfd

On windows please use WSL2 or docker / podman to run ``Styx``, on anything else
please use docker / podman. There is also a `devcontainer <https://code.visualstudio.com/docs/devcontainers/containers>`_
provided in the source tree to help with this.
