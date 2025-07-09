Overview
========
The wolfssl_benchmark demo application demonstrates cryptographic acceleration on supported platforms that have MMCAU,
LTC or similar accelerator peripheral. The hardware acceleration is enabled by default, and can be configured at build time in
the middleware/wolfssl/wolfssl/wolfcrypt/settings.h header file. FREESCALE_USE_MMCAU, FREESCALE_USE_LTC, FREESCALE_USE_LPC_AES
and FREESCALE_USE_LPC_SHA macros can be used to compile the wolfssl_benchmark project source code with support for
the Freescale hardware cryptographic accelerator, or when none of these macros is defined, all algorithms are implemented in software only.


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
No special settings are required.
Prepare the Demo
================
Connect a serial cable from the debug UART port of the board to the PC. Start TeraTerm
(http://ttssh2.osdn.jp) and make a connection to the virtual serial port.

1. Start TeraTerm.

2. New connection -> Serial.

3. Set the appropriate COMx port (where x is port number) in the port context menu. The number is provided by the operation
   system, and could be different from computer to computer. Select the COM number related to virtual
   serial port. Confirm the selected port by clicking the "OK" button.

4. Set following connection parameters in menu Setup -> Serial port
        Baud rate:    115200
        Data:         8
        Parity:       none
        Stop:         1
        Flow control: none

5.  Confirm selected parameters by clicking the "OK" button.

Running the demo
================
The demo prints the system clock frequency and actual hardware acceleration configuration to the terminal,
then executes cryptographic algorithms. The results are printed to the terminal.
Actual result times may vary significantly depending on the device, its available hardware acceleration modules,
system clock frequency and the compiler used.
Below are example outputs produced on three different development boards.

FRDM-K64F:

fsys=120000000
Using following implementations:
  SHA: MMCAU HW accelerated
  AES: MMCAU HW accelerated
  AES GCM: MMCAU HW accelerated
  DES: MMCAU HW accelerated
  Asymmetric encryption: Software implementation

RNG      25 kB took 0.033 seconds,    0.736 MB/s
AES enc  25 kB took 0.014 seconds,    1.732 MB/s
AES dec  25 kB took 0.014 seconds,    1.708 MB/s
AES-GCM  25 kB took 0.144 seconds,    0.170 MB/s
AES-CTR  25 kB took 0.011 seconds,    2.283 MB/s
AES-CCM  25 kB took 0.023 seconds,    1.064 MB/s
3DES     25 kB took 0.032 seconds,    0.756 MB/s

MD5      25 kB took 0.004 seconds,    5.865 MB/s
SHA      25 kB took 0.007 seconds,    3.434 MB/s
SHA-256  25 kB took 0.010 seconds,    2.357 MB/s

RSA 2048 encryption took 127.712 milliseconds, avg over 1 iterations
RSA 2048 decryption took 2121.931 milliseconds, avg over 1 iterations
DH  2048 key generation  954.829 milliseconds, avg over 1 iterations
DH  2048 key agreement   959.273 milliseconds, avg over 1 iterations

ECC  256 key generation  419.483 milliseconds, avg over 5 iterations
EC-DHE   key agreement   417.120 milliseconds, avg over 5 iterations
EC-DSA   sign   time     424.719 milliseconds, avg over 5 iterations
EC-DSA   verify time     835.282 milliseconds, avg over 5 iterations

FRDM-KL81Z:

fsys=72000000
Using following implementations:
  SHA: LTC HW accelerated
  AES: LTC HW accelerated
  AES GCM: LTC HW accelerated
  DES: LTC HW accelerated
  Asymmetric encryption: LTC HW accelerated

RNG      25 kB took 0.054 seconds,    0.455 MB/s
AES enc  25 kB took 0.010 seconds,    2.476 MB/s
AES dec  25 kB took 0.010 seconds,    2.469 MB/s
AES-GCM  25 kB took 0.010 seconds,    2.348 MB/s
AES-CTR  25 kB took 0.011 seconds,    2.300 MB/s
AES-CCM  25 kB took 0.011 seconds,    2.227 MB/s
3DES     25 kB took 0.010 seconds,    2.465 MB/s

MD5      25 kB took 0.011 seconds,    2.211 MB/s
SHA      25 kB took 0.008 seconds,    3.167 MB/s
SHA-256  25 kB took 0.008 seconds,    3.084 MB/s
SHA-512  25 kB took 0.249 seconds,    0.098 MB/s

RSA 2048 encryption took 30.046 milliseconds, avg over 1 iterations
RSA 2048 decryption took 285.885 milliseconds, avg over 1 iterations
DH  2048 key generation  122.453 milliseconds, avg over 1 iterations
DH  2048 key agreement   127.467 milliseconds, avg over 1 iterations

ECC  256 key generation  37.692 milliseconds, avg over 5 iterations
EC-DHE   key agreement   32.212 milliseconds, avg over 5 iterations
EC-DSA   sign   time     44.746 milliseconds, avg over 5 iterations
EC-DSA   verify time     71.144 milliseconds, avg over 5 iterations

CURVE25519 256 key generation 30.269 milliseconds, avg over 5 iterations
CURVE25519 key agreement      30.157 milliseconds, avg over 5 iterations

ED25519  key generation  32.269 milliseconds, avg over 5 iterations
ED25519  sign   time     44.990 milliseconds, avg over 5 iterations
ED25519  verify time     68.437 milliseconds, avg over 5 iterations

LPCXpresso54S608:

fsys=96000000
Using following implementations:
  SHA: LPC HW accelerated
  AES: LPC HW accelerated
  AES GCM: LPC HW accelerated
  DES: Software implementation
  Asymmetric encryption: Software implementation

RNG      25 kB took 0.022 seconds,    1.100 MB/s
AES enc  25 kB took 0.005 seconds,    5.226 MB/s
AES dec  25 kB took 0.005 seconds,    5.219 MB/s
AES-GCM  25 kB took 0.005 seconds,    4.846 MB/s
AES-CTR  25 kB took 0.005 seconds,    5.219 MB/s
AES-CCM  25 kB took 0.033 seconds,    0.736 MB/s
3DES     25 kB took 0.305 seconds,    0.080 MB/s

MD5      25 kB took 0.008 seconds,    3.251 MB/s
SHA      25 kB took 0.001 seconds,   21.602 MB/s
SHA-256  25 kB took 0.001 seconds,   21.544 MB/s

RSA 2048 encryption took 160.586 milliseconds, avg over 1 iterations
RSA 2048 decryption took 2698.775 milliseconds, avg over 1 iterations
DH  2048 key generation  1199.249 milliseconds, avg over 1 iterations
DH  2048 key agreement   1205.080 milliseconds, avg over 1 iterations

ECC  256 key generation  557.645 milliseconds, avg over 5 iterations
EC-DHE   key agreement   554.486 milliseconds, avg over 5 iterations
EC-DSA   sign   time     564.837 milliseconds, avg over 5 iterations
EC-DSA   verify time     1109.984 milliseconds, avg over 5 iterations
Customization options
=====================
