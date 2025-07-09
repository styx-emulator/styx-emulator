.. _rust_coverage:

Rust Test Coverage
==================

Due to the size of the generated Rust Coverage documentation, users must generate run
their own coverage output generation. After following the :ref:`install_from_source` guide,
continue with the following instructions:

.. code-block:: bash

    $ just coverage
    # ...
    # a lot of output
    # ...
    The Rust API Coverage information is located at ./target/llvm-cov/html/index.html

Then just open the generated ``index.html`` file in your web-browser (you can do so
automagically from the web-browser via ``xdg-open ./target/llvm-cov/index.html``) and you
should get dropped straight into our Rust Coverage docs |:smile:|.
