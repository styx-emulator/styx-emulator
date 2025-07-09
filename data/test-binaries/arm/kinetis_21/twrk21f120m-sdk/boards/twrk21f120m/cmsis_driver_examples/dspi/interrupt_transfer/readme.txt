Overview
========
CMSIS-Driver defines generic peripheral driver interfaces for middleware making it reusable across a wide
range of supported microcontroller devices. The API connects microcontroller peripherals with middleware
that implements for example communication stacks, file systems, or graphic user interfaces.
More information and usage methord please refer to http://www.keil.com/pack/doc/cmsis/Driver/html/index.html.

The cmsis_dspi_interrupt_transfer example shows how to use CMSIS DSPI driver in interrupt way:

In this example , one dspi instance used as master and another dspi instance used as slave in the same board.
1. DSPI master send/received data to/from DSPI slave in edma . (DSPI Slave using edma to receive/send the data)


Toolchain supported
===================
- IAR embedded Workbench 8.11.3
- Keil MDK 5.23
- GCC ARM Embedded 6-2017-q2
- Kinetis Development Studio IDE 3.2.0
- MCUXpresso10.1.0

Hardware requirements
=====================
- Micro USB cable
- TWR-K21F120M board
- Personal Computer
- Elevator Tower

Board settings
==============
SPI one board:
Transfer data from instance0 to instance 1 of SPI interface.
SPI0 pins are connected with SPI1 pins of board
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
INSTANCE0(SPI0)     CONNECTS TO         INSTANCE1(SPI1)
Pin Name   Board Location     Pin Name  Board Location
SIN        A77                SOUT      B68
SOUT       A76                SIN       B67
SCK        B48                SCK       B69
PCS0       B46                PCS0      B70
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Prepare the Demo
================
1.  Connect a USB cable between the host PC and the OpenSDA USB port on the target board.
2.  Open a serial terminal with the following settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control
3.  Download the program to the target board.
4.  Either press the reset button on your board or launch the debugger in your IDE to begin running the demo.

Running the demo
================
When the example runs successfully, you can see the similar information from the terminal as below.

CMSIS DSPI interrupt transfer example start.
This example use one dspi instance as master and another as slave on one board.
Master and slave are both use interrupt way.
Please make sure you make the correct line connection. Basically, the connection is:
DSPI_master -- DSPI_slave
   CLK      --    CLK
   PCS      --    PCS
   SOUT     --    SIN
   SIN      --    SOUT
This is SlaveSignalEvent.

DSPI transfer all data matched!

Customization options
=====================
