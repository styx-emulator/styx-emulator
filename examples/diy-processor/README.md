# DIY Processor

This binary is an example use of [`styx-emulator`] to emulate an ARMv7 chip.

The example firmware "blinks" and LED by toggling a GPIO pin. The GPIO pin operations are logged to
the console.

## Quick Start

Run the `blink_flash` example.

```console
$ cd examples/diy-processor
$ cargo run
...
 INFO     => BSSR: Sets port C pin 12
 INFO     => CRH: Configures port C pin 12
 INFO     => BRR: Resets port C pin 12
 INFO     => BSSR: Sets port C pin 12
 INFO     => BRR: Resets port C pin 12
 INFO     => BSSR: Sets port C pin 12
 INFO     => BRR: Resets port C pin 12
 INFO     => BSSR: Sets port C pin 12
```
