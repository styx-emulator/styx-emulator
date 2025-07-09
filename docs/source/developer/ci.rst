.. _ci:

CI Pipeline
===========

Unused Dependency Check
^^^^^^^^^^^^^^^^^^^^^^^

We use `cargo-udeps <https://crates.io/crates/cargo-udeps>`_ to find unused dependencies. A known shortcoming of ``cargo-udeps`` is that it cannot detect usage of crates that are only used in doc-tests.  Follow the link to see examples of how to ignore unused dependency errors within a crate.
