.. _installing:

Installing
##########


Rust Install
************

You can install Styx as a normal rust dependency.

Styx is not on crates.io (yet) so it must be added as a **local path** or via **git**.

If Styx is already checked out locally you can `specify the dependency as a path <https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-path-dependencies>`_. Use ``cargo add`` at the root of your crate that will use the Styx library.

.. code-block:: console

    $ cargo add --path ../path/to/styx-emulator/styx

.. note::

    Be sure to point to the `styx/` subdirectory of the source tree. This is the home of the styx-emulator crate.


You can also `install the crate from the remote git repo <https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#specifying-dependencies-from-git-repositories>`_ using ssh or http authentication.

.. code-block:: console

    $ cargo add --git ssh://git@github.com/styx-emulator/styx-emulator.git styx-emulator
    $ cargo add --git https://github.com/styx-emulator/styx-emulator.git styx-emulator


Python Bindings
***************

You have two paths, either installing pre-built artifacts, or installing from source

Remember that we *only support linux targets*.

Installing Pre-Built Artifacts
==============================

Note that we currently only ship pre-made pip wheels, on the roadmap are the following additional premade artifacts:

C library:

* ubuntu/debian ``.deb```'s
* RHEL based ``.rpm``'s

Linux binary executables:

* ubuntu/debian ``.deb``'s
* RHEL based ``.rpm``'s
* Appimage

Docker containers:

* binary executable
* userspace emulation daemon

We are also working on adding builtin artifact signing + SBOM generation to ensure smooth approvals for using ``Styx`` in secure/audited environments.

pip installing Styx python bindings
-----------------------------------


.. code-block:: bash
    :substitutions:

    |pip-index-command|

See |pip-install-help| for more information.

.. _install_from_source:

Installing from Source
======================

**NOTE**: ensure you install the dependencies before building the project from source:

* ``Rust`` |rust-version|
* ``Python`` > 3.9
* ``python3-virtualenv``
* ``python3-pip``
* ``protobuf-compiler`` (ensure that the lib is included, sometimes called eg. ``libprotobuf-dev`` on ubuntu based systems)
* ``cmake``
* ``gdb-multiarch`` (``gdb`` on RHEL systems)

.. code-block:: bash
    :substitutions:

    git clone |repository_url|
    cargo install just
    just setup

    # install python api into local virtual env
    . venv/bin/activate
    pip install styx/bindings/styx-py-api

    # now use the python api
    $ python
    Python 3.12.8 (main, Dec  6 2024, 00:00:00) [GCC 14.2.1 20240912 (Red Hat 14.2.1-3)] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import styx_emulator
    >>>
