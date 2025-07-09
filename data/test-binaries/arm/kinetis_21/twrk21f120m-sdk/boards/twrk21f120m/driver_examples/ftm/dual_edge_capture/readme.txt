Overview
========
The FTM project is a demonstration program of the SDK FTM driver's dual-edge capture feature.
This feature is available only on certain SoC's.
The example sets up a FTM channel-pair for dual-edge capture. Once the input signal is received,
this example will print the capture values and period of the input signal on the terminal window.

Note:
This feature gets a valid pulse width value only in one FTM counting cycle. The dual-edge of input signal must be captured in one FTM counting cycle.
In other words, The period of the Input cycle is less than the FTM counting cycle. This capture feature don't support FTM counter overflow.
If FTM counter overflow when capturing dual-edge of input signal. The pulse width value may be ambiguity.

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
- Primary Elevator board

Board settings
==============
- Plug the board to the primary
- Connect input signal to A38

Prepare the Demo
================
1. Connect a USB cable between the PC host and the OpenSDA USB port on the board.
2. Open a serial terminal with these settings:
    - 115200 baud rate
    - 8 data bits
    - No parity
    - One stop bit
    - No flow control
3. Download the program to the target board.
4. Either press the reset button on your board or launch the debugger in your IDE to begin running the example.

Running the demo
================
These instructions are displayed/shown on the terminal window:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
FTM dual-edge capture example
Once the input signal is received the input capture values are printed
The input signal's pulse width is calculated from the capture values & printed

Capture value C(n)V=3

Capture value C(n+1)V=5a8

Input signals pulse width=24 us
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Customization options
=====================
