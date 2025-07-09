# Talking to Peripherals

This example defines two devices and connects them to the I2C interface of a running emulator.  

The devices are the `DS3231` real-time clock and the `TC74` serial, digital thermal sensor.  Both devices implement the `I2CDevice` trait which includes methods for reading/writing data to the device as well as methods for processing signals on the bus in case they have some special behavior and need to track when these events happen.  Both devices currently only implement a subset of their actual features because this is just used to test the I2C interface for an emulator and I'm being a bit lazy here.

This example needs an emulated target with an I2C bus.

## Quick Start

```console
cd examples/talking-to-peripherals
cargo run
```
