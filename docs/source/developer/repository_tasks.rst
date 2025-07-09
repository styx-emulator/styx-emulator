.. _repository_tasks:

Repository Tasks (xtask)
========================

We heavily utilize the `cargo-xtask <https://github.com/matklad/cargo-xtask>`_ pattern.
This allows us to have a larger more uniform codebase in a single
programming language, and to have a single tool all our CI tasks
etc can use. If you end up doing an action often, consider making
a new generalized ``xtask``!

Current xtasks
##############

.. code:: console

    $ cargo xtask --help
        Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.19s
         Running `target/debug/xtask --help`
    Usage: xtask [OPTIONS] [COMMAND]

    Commands:
      license              Checks that the LICENSE file is present and modifies files recursively within the working directory to prepend applicable license content
      hakari               Updates the workspace-hack configuration
      feature-add          Add features to a DAG of crates at a time
      rust-version-update  Used for updating the version of rust in the codebase
      adr                  Generate a template file for a new ADR
      rfc                  Generate a template file for a new RFC
      help                 Print this message or the help of the given subcommand(s)

    Options:
      -v, --verbose  Verbose logging
      -h, --help     Print help
      -V, --version  Print version


.. _xtask_license:

License
^^^^^^^

This xtask is used to enforce license checks in all source code files.
It uniformly applies the license based on the comment structure for the
given text file format and can be extended to include new files types
easily.

Hakari
^^^^^^

This xtask helps automate the ``workspace-hack`` pattern described in the
`cargo-hakari <https://github.com/guppy-rs/guppy/tree/main/tools/cargo-hakari>`_
documentation. Now its impossible to mess up |:smile:|, and will print user
instructions when CI jobs fail.

Feature Add
^^^^^^^^^^^

A small utility to add a feature to a crate and all its dependents. Doesn't seem
very useful until its about to save you from updating 80 crate definitions
by hand.

Rust Version Update
^^^^^^^^^^^^^^^^^^^

Updates the required Rust version to the provided version. This centralizes
the logic needed to correctly update the Rust version as the workspace, the
containers, and anything else all rely on it and it's easy to get out of sync.


RFC / ADR
^^^^^^^^^

These generate files for creating a new RFC or ADR, and use a template to do so.
