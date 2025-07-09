.. _testable_workflow:

####################
 Testable Emulation
####################

Styx allows you to assert runtime behaviors of emulation using existing
tools like pytest.

Using the Styx Python bindings, we can create a processor, run a
firmware and assert runtime behaviors before, during, and after
emulation.

We will follow the example found in
``styx/bindings/styx-py-api/examples/uart-integration-test/main.py``.

*************
 Test Design
*************

We want to construct a test to run under pytest. Let's create an outline
of our test:

.. code:: Python

   def test_uart():
       proc = build_processor()
       # nonblocking, uart client will stop processor when message is received
       uart_recv = start_uart_client(proc)

       # blocking, processor will stop when uart message received
       proc.start()

       # assert our received message is correct
       assert uart_recv == bytearray(b"Hello world.\r\n")

Now let's have to build out these components.

************************
 Building the Processor
************************

To build our processor we first have to start by defining our test
binary. Since we are running through the pytest script which will be
located in ``venv/bin``, our path will be located relative to that.

.. code:: python

   # pytest is located in venv/bin so out target program is relative to that.
   TARGET_PROGRAM = "../../data/test-binaries/arm/kinetis_21/bin/freertos_hello/freertos_hello_debug.bin"


   def get_script_path() -> Path:
       """Get directory of this script."""
       return Path(sys.argv[0]).resolve().parent


   def target_program_path() -> Path:
       """Get absolute target firmware path"""
       return get_script_path() / TARGET_PROGRAM

Next we design ``build_processor()`` to easily construct our processor
in our tests. Our target is a Kinetis21 that runs ARM Cortex M4. The
options here are documented. See the Styx ``ProcessorBuilder``
documentation for more information on the possible configuration.

.. code:: python

   def build_processor(backend: Backend):
       """
       Builds Kinetis21 processor

       LittleEndian
       firmware: FreeRTOS "hello world" (RawLoader)
       cpu: ArmCortexM4 variant on chosen backend
       plugins:
           - ProcessorTracingPlugin
       """
       # builder pattern for configuring a new processor
       builder = ProcessorBuilder()

       # define the path to our firmware image
       builder.target_program = str(target_program_path())
       # select an open port for ipc
       builder.ipc_port = 0
       # firmware image is a raw memory dump, no mapping needed
       builder.loader = RawLoader()
       # default executor is okay
       builder.executor = DefaultExecutor()
       # set our chosen backend
       builder.backend = backend
       # plugin for capturing and printing logs (traces)
       builder.add_plugin(ProcessorTracingPlugin())
       # cpu info
       builder.variant = ArmVariant.ArmCortexM4
       builder.endian = ArchEndian.LittleEndian
       return builder.build(Target.Kinetis21)

Now that we have a processor, we must build a UART client to send it
data over UART.

*************
 UART Client
*************

Below is the outline for ``start_uart_client()``. The idea is that we
create a UART client that communicates with the given processor and send
the client to a separate thread that monitors for incoming data and
appends to a buffer of all received UART data. The caller of
``start_uart_client()`` then receives a reference to the growing
bytearray of received UART data.

The caller can use this bytearrary to see incoming UART data or analyze
it after emulation to check for correctness.

.. code:: python

   def start_uart_client(proc: Processor) -> bytearray:
       """
       Connect UART client to processor and return bytearray with all received data.

       The UART client connects to the UART server started by the processor. In this example, it
       receives the "Hello World" message from the target after which it stops the processor.

       A bytearray is created and sent to the UART thread as well as returned to the caller. The
       bytearray will be updated with all received UART data.
       """
       # create received bytes bytearray

       # create uart client

       # start uart monitor thread

       # return received bytes bytearray
       pass

Styx conveniently provides a ``UartClient`` that allows us to send and
receive UART data to the target through the processor's IPC mechanisms.

The ``UartClient`` can be instantiated like so, where ``ipc_port`` is
the port opened by the processor to facilitate ipc and
``DEBUG_UART_PORT`` is hardware specific, defined by the firmware.

.. code:: python

   from styx.peripherals import UartClient

   client = UartClient(f"http://127.0.0.1:{ipc_port}", DEBUG_UART_PORT)

Assuming we have the UART monitoring logic in function ``uart_thread``,
the starting of the UART client looks like the following.

.. code:: python

   def start_uart_client(proc: Processor) -> bytearray:
       """
       Connect UART client to processor and return bytearray with all received data.

       The UART client connects to the UART server started by the processor. In this example, it
       receives the "Hello World" message from the target after which it stops the processor.

       A bytearray is created and sent to the UART thread as well as returned to the caller. The
       bytearray will be updated with all received UART data.
       """
       # create received bytes bytearray
       recv_bytes = bytearray()

       # create uart client
       # defined by the firmware, uses uart port 5
       DEBUG_UART_PORT = 5
       # ipc port of processor to connect to
       ipc_port = proc.resolved_ipc_port
       client = UartClient(f"http://127.0.0.1:{ipc_port}", DEBUG_UART_PORT)

       # start uart monitor thread
       # daemon mode allows this thread to be killed if the main thread is killed
       thread = threading.Thread(
           target=uart_thread, args=(client, proc, recv_bytes), daemon=True
       )
       thread.start()

       # return received bytes bytearray
       return recv_bytes

Last thing to do is define the UART monitoring logic.

.. code:: python

   def uart_thread(client: UartClient, proc: Processor, total_recv_bytes: bytearray):
       """
       Function for uart receive thread.

       Repeatedly checks for received data using client.recv_nonblocking() and
       stops the processor when the whole message has been received, indicated
       by receiving a newline.

       UART data received is added by mutating the total_recv_bytes.
       """
       while True:
           # check for new UART data

           if uart_data:
               # add to our list of received bytes

               # newline indicates end of message
               if uart_data == b"\n":
                   print("got newline, shutting down")
                   proc.shutdown()
                   break
           else:
               # wait in between checks for new UART data
               time.sleep(0.01)

The UartClient's ``recv_nonblocking(n)`` method checks for n available
received bytes and returns None if they aren't found.

Filling in the missing parts for ``uart_thread()``:

.. code:: python

   def uart_thread(client: UartClient, proc: Processor, total_recv_bytes: bytearray):
       """
       Function for uart receive thread.

       Repeatedly checks for received data using client.recv_nonblocking() and
       stops the processor when the whole message has been received, indicated
       by receiving a newline.

       UART data received is added by mutating the total_recv_bytes.
       """
       while True:
           # check for new UART data
           # bytes or None if no bytes are available
           current_recv_bytes = client.recv_nonblocking(1)
           if current_recv_bytes:
               # we got a byte, add to our list of received bytes
               total_recv_bytes.extend(current_recv_bytes)

               # newline indicates end of message
               if current_recv_bytes == b"\n":
                   print("got newline, shutting down")
                   print(f'received message: "{total_recv_bytes.decode().strip()}"')
                   proc.shutdown()
                   break
           else:
               # wait in between checks for new UART data
               time.sleep(0.01)

***************
 Final Touches
***************

Finally we can write our tests:

.. code:: python

   def test_uart():
       proc = build_processor(backend)
       uart_recv = start_uart_client(proc)
       # give time for processor and uart to connect, otherwise a race occurs
       # between sending uart data and receiving.
       time.sleep(0.1)

       start_timeout(proc, 5)

       proc.start()

I added a small timeout feature to stop the processor after 5 seconds in
case anything goes awry.

.. code:: python

   def start_timeout(proc: Processor, seconds: float):
       """Stop processor after seconds passed."""

       def timeout(proc: Processor):
           time.sleep(seconds)
           proc.shutdown()

       thread = threading.Thread(target=timeout, args=(proc,), daemon=True)
       thread.start()

Additionally we can use pytest features to test more effectively. Here I
parametrize on the cpu backends.

.. code:: python

   @pytest.mark.parametrize("backend", backends)
   def test_uart(backend: Backend):
       proc = build_processor(backend)
       uart_recv = start_uart_client(proc)
       # give time for processor and uart to connect, otherwise a race occurs
       # between sending uart data and receiving.
       time.sleep(0.1)

       start_timeout(proc, 5)

       proc.start()
       assert uart_recv == bytearray(b"Hello world.\r\n")

Let's also add another test for processor initialization.

.. code:: python

   @pytest.mark.parametrize("backend", backends)
   def test_build_proc(backend: Backend):
       proc = build_processor(backend)
       ipc_port = proc.resolved_ipc_port
       assert ipc_port != 0
       assert proc.processor_state == ProcessorState.Initialized

Perfect! Now we can run using pytest.

.. code:: console

   $ pytest /path/to/your/main.py
   === test session starts ===
   platform linux -- Python 3.13.1, pytest-8.3.4, pluggy-1.5.0
   rootdir: /path/to/your/
   configfile: pyproject.toml
   collected 4 items

   /path/to/your/main.py ....                                                                                                                                                       [100%]

   === 4 passed in 0.76s ===
