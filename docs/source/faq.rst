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

On windows please use WSL2 or docker / podman to run ``Styx``, on anything else
please use docker / podman. There is also a `devcontainer <https://code.visualstudio.com/docs/devcontainers/containers>`_
provided in the source tree to help with this.

Supported Targets
^^^^^^^^^^^^^^^^^

Styx supports multiple backends, architectures, and processor configurations. The tables below show the current support matrix.

.. _architecture_support:

Backend Support by Architecture
""""""""""""""""""""""""""""""""

**Legend:**
  - ``✓ Supported (Default)`` - Default backend if none is provided
  - ``✓ Supported`` - At least one processor is enabled and is able to use this backend
  - ``✓ Available`` - Available but may require "flipping switches" / glue code in Styx to enable
  - ``✗ Not Available`` - Not supported by this backend, no easy path to enable

.. list-table:: Backend x Architecture Support Matrix
   :header-rows: 1
   :widths: 25 20 20 35

   * - Architecture
     - Unicorn Backend
     - Pcode Backend
     - Notes
   * - **ARM (32-bit)**
     - ✓ Supported
     - ✓ Supported (Default)
     - ARMv6+, no banked register support at this time
   * - **AArch64 (64-bit)**
     - ✓ Supported
     - ✓ Supported (Default)
     - ARMv8 only, ARMv9 (and later) support is untested
   * - **x86 (32-bit)**
     - ✓ Available
     - ✓ Available
     - Unicorn recommended for performance
   * - **x86_64 (64-bit)**
     - ✓ Available
     - ✓ Available
     - Unicorn recommended for performance
   * - **MIPS 32**
     - ✓ Available
     - ✓ Available
     -
   * - **MIPS 64**
     - ✓ Available
     - ✓ Available
     -
   * - **PowerPC (32/64-bit)**
     - ✓ Supported
     - ✓ Supported (Default)
     - Pcode backend has PPC4xx-specific features
   * - **SPARC (32/64-bit)**
     - ✓ Available
     - ✓ Available
     -
   * - **M68K (Motorola 68000)**
     - ✓ Available
     - ✓ Available
     -
   * - **Tricore**
     - ✓ Available
     - ✓ Available
     -
   * - **SuperH (SH2/SH2A/SH4)**
     - ✗ Not Available
     - ✓ Supported (Default)
     -
   * - **Blackfin**
     - ✗ Not Available
     - ✓ Supported (Default)
     -
   * - **M32R**
     - ✗ Not Available
     - ✓ Supported (Default)
     -
   * - **6502**
     - ✗ Not Available
     - ✓ Available
     -
   * - **8051**
     - ✗ Not Available
     - ✓ Available
     -
   * - **Atmel AVR**
     - ✗ Not Available
     - ✓ Available
     -
   * - **RISC-V**
     - ✓ Available
     - ✓ Available
     -
   * - **Xtensa**
     - ✗ Not Available
     - ✓ Available
     -
   * - **Z80**
     - ✗ Not Available
     - ✓ Available
     -
   * - **V850**
     - ✗ Not Available
     - ✓ Available
     -
   * - **Hexagon**
     - ✗ Not Available
     - ✓ Available
     -
   * - **TI MSP430**
     - ✗ Not Available
     - ✓ Available
     -
   * - **Loongarch**
     - ✗ Not Available
     - ✓ Available
     -
   * - **Others**
     -
     -
     - See ``styx-sla/processors/ghidra/`` for complete list (40+ architectures)

Pre-built Processor Implementations
""""""""""""""""""""""""""""""""""""

Styx includes several ready-to-use processor implementations with some level of peripheral support:

.. list-table:: Available Processor Implementations
   :header-rows: 1
   :widths: 25 50 25

   * - Processor
     - Architecture / Architecture Variant
     - Default Backend
   * - **STM32F107**
     - ARM Cortex-M3
     - Unicorn
   * - **STM32F405**
     - ARM Cortex-M4
     - Unicorn
   * - **Kinetis K21**
     - ARM Cortex-M4
     - Unicorn
   * - **Cyclone V SoC**
     - ARM Cortex-A9
     - Unicorn/Pcode
   * - **AArch64 Generic**
     - ARM 64-bit
     - Unicorn/Pcode
   * - **PowerPC 4xx**
     - PowerPC 32-bit
     - Pcode
   * - **PowerQUICC I**
     - PowerPC 32-bit
     - Pcode
   * - **Blackfin**
     - Blackfin DSP
     - Pcode
   * - **SuperH SH2A**
     - SuperH 32-bit
     - Pcode

Supported Peripherals
^^^^^^^^^^^^^^^^^^^^^^

Styx provides generic peripheral models for a variety of common embedded system peripherals that can be used in the in-tree processor implementations or combined in custom user-defined processors.

Common Peripherals
""""""""""""""""""

The following peripherals are available across multiple processor implementations and have dedicated `gRPC` services designed to be reused across the Styx codebase:

.. list-table:: Common Peripheral Support
   :header-rows: 1
   :widths: 25 75

   * - Peripheral
     - Description
   * - **UART**
     - Universal Asynchronous Receiver/Transmitter for serial communication
   * - **GPIO**
     - General Purpose Input/Output pins
   * - **SPI**
     - Serial Peripheral Interface
   * - **I2C**
     - Inter-Integrated Circuit bus
   * - **Clocks**
     - Peripherals that "track time" and keep the context of the system moving
   * - **Timers**
     - General purpose hardware timers
   * - **DMA**
     - Direct Memory Access controller
   * - **USB**
     - USB / USB-OTG
   * - **Ethernet**
     - Ethernet MAC controllers
   * - **Flash**
     - Flash memory controllers and storage

**TBD**: Matrix peripheral to processors that have supported peripherals

Supported External Devices
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Styx includes implementations for common external devices that can be connected to peripheral buses (SPI, I2C, etc.) in your emulated systems. These devices are available in the ``styx-devices`` crate and can be connected to processor peripherals via client interfaces.

SPI Devices
"""""""""""

The following SPI-based devices are currently supported:

.. list-table:: SPI Device Support
   :header-rows: 1
   :widths: 25 25 50

   * - Device
     - Type
     - Description
   * - **AT25HP512**
     - EEPROM
     - 512Kbit (64KB) Serial EEPROM with SPI interface. Supports read/write operations, status register, write protection
   * - **ADS7866**
     - ADC
     - 12-bit Analog-to-Digital Converter from Texas Instruments. Reads analog signals and converts to digital values
   * - **RHRDAC121**
     - DAC
     - 12-bit Digital-to-Analog Converter. Converts digital values to analog output voltage (0 to VCC)

All devices implement the ``SPIDevice`` trait and can be connected to SPI peripherals using the ``SPISimpleClient`` interface. See the ``examples/styx-devices`` directory for usage examples.
