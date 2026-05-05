# Data

Binaries for testing Styx's Hexagon support. Binaries here are built using the Docker container build process. See `build.rs` for more information on this process.

## Contents

### Data

There is some miscellaneous data that is in this crate.

- `Makefile-nosdk`: work-in-progress Makefile that builds some (but not all) of the tests in qemu-hexagon-testing.
- `build_ci.sh`: a shell script that fetches `qemu-hexagon-testing` and builds it. Used in the process of building the Docker container with the test binaries.
- `hexagon-builder.Containerfile`: the file that specifies how to build the container image.

### qemu-hexagon-testing

See https://github.com/qualcomm/qemu-hexagon-testing. The tests here test hexagon system functionality (eg. multithreading, MMU, semihosting, and more) along with peripherals (timer, interrupt controller, UART).
