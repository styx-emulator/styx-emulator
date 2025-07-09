.. _rust_api_docs:

Rust API Docs
=============

Due to the size of the generated Rust API Documentation, users must build their own copy
of the docs. After following the :ref:`install_from_source` guide, continue with the
following instructions:

.. code-block:: bash

    $ just rust-docs
    # ...
    # a lot of output
    # ...
    The Rust API docs are located at ./target/doc/index.html

Then just open the generated ``index.html`` file in your web-browser (you can do so
automagically from the web-browser via ``xdg-open ./target/doc/index.html``) and you
should get dropped straight into our top-level API docs |:smile:|.
