Overview
========
This document explains the freertos_tickless example. It shows the CPU enter at sleep mode and then
it is waked up by expired time delay that using LPTMR module or occur any a hardware interrupt.





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
This example project does not call for any special hardware configurations.
Although not required, the recommendation is to leave the development board's jumper settings
and configurations in default state when running this example.
Prepare the Demo
================

Running the demo
================
After the board is flashed the Tera Term will start periodically printing number tick count when the CPU
is running.

When the CPU is running and get tick count number, press button on board that suggest message display on
console screen ("eg:Press SW3 <or SW1,SW2> to wake up the CPU") to wake up CPU then Tera Term
will printing “CPU waked up by EXT interrupt” message.

Example output:

Tickless Demo example
Press SW3 to wake up the CPU
Tick count :
1
5001
CPU waked up by EXT interrupt
10001
CPU waked up by EXT interrupt
15001
CPU waked up by EXT interrupt
CPU waked up by EXT interrupt
20001
25001
30001

Explanation of the example
The example application will get tick count number after every period time delay vTaskDelay(time)
When this function called the CPU enter to sleep mode a period of time that called by vTaskDelay
function.

While the CPU is sleeping, if press SW3 button once or several time on board then CPU waked up
by external interrupt and continuous enter sleep mode after complete interrupt service.
The period of time delay is not change after occur external interrupt.
Customization options
=====================
