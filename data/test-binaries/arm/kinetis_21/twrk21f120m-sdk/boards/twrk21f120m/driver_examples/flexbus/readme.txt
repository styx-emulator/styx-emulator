Overview
========

The FLEXBUS (External Bus Interface) example show how to write/read to external memories (MRAM)
by using FLEXBUS driver.

In this example, FLEXBUS driver is configured with  some specific parameter:
    - 1 byte port size of transfer
    - Wait 2 states
    - MRAM address for using FlexBus
    - 512 Kbytes memory size

Toolchain supported
===================
- IAR embedded Workbench 8.11.3
- Keil MDK 5.23
- GCC ARM Embedded 6-2017-q2
- Kinetis Development Studio IDE 3.2.0
- MCUXpresso10.1.0

Hardware requirements
=====================
- Mini/micro USB cable
- TWR-K21F120M board
- Personal Computer
- TWR-MEM board
- TWR-ELEV primary

Board settings
==============
No special is needed.

Prepare the Demo
================
1. Connect a USB cable between the PC host and the OpenSDA USB port on board.
2. Open a serial terminal on PC for OpenSDA serial device with these settings:
   - 115200 baud rate
   - 8 data bits
   - No parity
   - One stop bit
   - No flow control
3. Download the program to the target board.
4. Either press the reset button on your board or launch the debugger in your IDE to begin running the demo.

Running the demo
================

When the example runs successfully, you can see the similar information from the terminal as below.

~~~~~~~~~~~~~~~~~~~~~
FLEXBUS Example.

Initialize FLEXBUS.

Start write/read MRAM.

FLEXBUS (MRAM) test: succeed.
~~~~~~~~~~~~~~~~~~~~~
Customization options
=====================
