Overview
========
The flexcan_interrupt example shows how to use FlexCAN driver in none-blocking interrupt way:

In this example, 2 boards are connected through CAN bus. Endpoint A(board A) send a CAN Message to
Endpoint B(board B) when user press space key in terminal. Endpoint B receive the message, print
the message content to terminal and echo back the message. Endpoint A will increase the received
message and waiting for the next transmission of the user initiated.

Toolchain supported
===================
- IAR embedded Workbench 8.11.3
- Keil MDK 5.23
- GCC ARM Embedded 6-2017-q2
- Kinetis Development Studio IDE 3.2.0
- MCUXpresso10.1.0

Hardware requirements
=====================
- Two Mini/micro USB cables
- Two TWR-K21F120M boards
- Two TWR-SER boards
- Two TWR-ELEV Primary boards
- Three wires
- Personal Computer

Board settings
==============
TWR-SER Tower System module configuration (only FlexCAN interrupt example):
- Short J5(1-2), J5(3-4), J5(5-6), J5(7-8), and J5(9-10) to enable CAN connection.
- Connect the two TWR-SER modules through the CAN port (J7):

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      PINS NAME        TWR-SER1     CONNECTS TO    TWR_SER2
      CANL            J7 PIN 1                     J7 PIN 1
      GND             J7 PIN 2                     J7 PIN 2
      CANH            J7 PIN 3                     J7 PIN 3
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Although not required, the recommendation is to leave the development board jumper settings and configurations in
default state when running this example.

Prepare the Demo
================
1. Connect a USB cable between the PC host and the OpenSDA USB on the board.
2. Open a serial terminal on PC for OpenSDA serial device with these settings:
   - 115200 baud rate
   - 8 data bits
   - No parity
   - One stop bit
   - No flow control
3. Download the program to the target board.
4. Either press the reset button on your board or launch the debugger in your IDE to begin running
   the example.

Running the demo
================
After connecting the two boards, these instructions display on each terminal window.
One board must be chosen as node A and the other board as node B. (Note: Node B should start first)
Data is sent continuously between the node A and the node B.

This message displays on the node A terminal:

~~~~~~~~~~~~~~~~~~~~~

********* FLEXCAN Interrupt EXAMPLE *********

    Message format: Standard (11 bit id)

    Message buffer 9 used for Rx.

    Message buffer 8 used for Tx.

    Interrupt Mode: Enabled

    Operation Mode: TX and RX --> Normal

*********************************************



Please select local node as A or B:

Note: Node B should start first.

Node:a

Press any key to trigger one-shot transmission



Rx MB ID: 0x123, Rx MB data: 0x0

Press any key to trigger the next transmission!



Rx MB ID: 0x123, Rx MB data: 0x1

Press any key to trigger the next transmission!
~~~~~~~~~~~~~~~~~~~~~

This message displays on the node B terminal:

********* FLEXCAN Interrupt EXAMPLE *********

    Message format: Standard (11 bit id)

    Message buffer 9 used for Rx.

    Message buffer 8 used for Tx.

    Interrupt Mode: Enabled

    Operation Mode: TX and RX --> Normal

*********************************************



Please select local node as A or B:

Note: Node B should start first.

Node:b

Start to Wait data from Node A



Rx MB ID: 0x321, Rx MB data: 0x0

Wait Node A to trigger the next transmission!



Rx MB ID: 0x321, Rx MB data: 0x1

Wait Node A to trigger the next transmission!
~~~~~~~~~~~~~~~~~~~~~
Customization options
=====================
