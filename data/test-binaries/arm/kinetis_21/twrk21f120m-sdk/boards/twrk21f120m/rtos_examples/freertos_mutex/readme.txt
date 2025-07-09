Overview
========
This document explains the freertos_mutex example. It shows how mutex manage access to common
resource (terminal output).

The example application creates two identical instances of write_task. Each task will lock the mutex
before printing and unlock it after printing to ensure that the outputs from tasks are not mixed
together.

The test_task accept output message during creation as function parameter. Output message have two
parts. If xMutex is unlocked, the write_task_1 acquire xMutex and print first part of message. Then
rescheduling is performed. In this moment scheduler check if some other task could run, but second
task write_task+_2 is blocked because xMutex is already locked by first write task. The first
write_task_1 continue from last point by printing of second message part. Finaly the xMutex is
unlocked and second instance of write_task_2 is executed.




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
After the board is flashed the Tera Term will start periodically printing strings synchronized by
mutex.

Example output:
"ABCD | EFGH"
"1234 | 5678"
"ABCD | EFGH"
"1234 | 5678"
Customization options
=====================
