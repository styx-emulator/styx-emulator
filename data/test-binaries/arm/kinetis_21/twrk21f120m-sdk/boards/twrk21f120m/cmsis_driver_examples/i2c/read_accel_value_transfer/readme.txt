Overview
========
CMSIS-Driver defines generic peripheral driver interfaces for middleware making it reusable across a wide
range of supported microcontroller devices. The API connects microcontroller peripherals with middleware
that implements for example communication stacks, file systems, or graphic user interfaces.
More information and usage methord please refer to http://www.keil.com/pack/doc/cmsis/Driver/html/index.html.

The cmsis_i2c_read_accel_value example shows how to use CMSIS I2C driver to communicate with an i2c device:

 1. How to use the i2c driver to read a i2c device who_am_I register.
 2. How to use the i2c driver to write/read the device registers.

In this example, the values of three-axis accelerometer print to the serial terminal on PC through
the virtual serial port on board.

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

Board settings
==============
No special settings are required.

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
When the demo runs successfully, the log would be seen on the OpenSDA terminal like:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
I2C example -- Read Accelerometer Value
Found an MMA8451 on board , the device address is 0x1c .
The accel values:
status_reg = 0xff , x =   118 , y =  1475 , z =  1366
status_reg = 0xff , x =    97 , y =  1496 , z =  1303
status_reg = 0xff , x =   100 , y =  1498 , z =  1410
status_reg = 0xff , x =    97 , y =  1509 , z =  1404
status_reg = 0xff , x =    30 , y =  1508 , z =  1388
status_reg = 0xff , x =    95 , y =  1554 , z =  1284
status_reg = 0xff , x =    72 , y =  1528 , z =  1533
status_reg = 0xff , x =   139 , y =  1530 , z =  1390
status_reg = 0xff , x =    65 , y =  1605 , z =  1423
status_reg = 0xff , x =   105 , y =  1644 , z =  1340

End of I2C example .
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Customization options
=====================
