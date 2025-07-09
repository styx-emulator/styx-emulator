Overview
========
The MMCCARD FATFS project is a demonstration program that uses the SDK software. Tt mounts a file
system based on a MMC card then does "creat directory/read directory/create file/write file/read
file" operation. The file sdhc_config.h has default SDHC configuration which can be adjusted to let
card driver has different performance. The purpose of this example is to show how to use MMCCARD
driver based FATFS disk in SDK software.

Note:
User can use MMC plus card or emmc(on board IC, but not recommand use emmc socket,due to high speed timing restriction)

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

Board settings
==============
The example is configured to use SDHC0 with PTE0, PTE1, PTE2, PTE3, PTE4, PTE5 pins
and use PTD10 pin as card detection pin. It doesn't detetet write protect switch state so don't open
the write protect switch on the SD card socket.

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

When the example runs successfully, you can see the similar information from the terminal as below:

FATFS example to demonstrate how to use FATFS with MMC card.

Make file system......The time may be long if the card capacity is big.

Create directory......

Create a file in that directory......

List the file in that directory......
General file : F_1.DAT.

 Write/read file until encounters error......

Write to above created file.
Read from above created file.
Compare the read/write content.
The read/write content is consistent.

Input 'q' to quit read/write.
Input other char to read/write file again.
Customization options
=====================
