# Blackfin Unit Tests

These tests were taken from binutils-gdb. All files are unmodified except for `testutils.inc` which
was modified to not print text when pass/fail and to put `13` in R0 when exiting successfully.
Changing the success code from `0` to `13` was done to prevent false passes.

## Building

Run `just blackfin-testdata` to build.

The makefile assembles and links the test binaries statically loaded at `0x1000`.

## Debug Asserts

There are debug asserts (`DBGA`, `DBGAL`, `DBGAH`) scattered throughout the tests. The source code
to decode these is in `binutils-gdb/sim/bfin/bfin-sim.c` in function `decode_psedodbg_assert_0`. A
partial implementation with asserts is in the blackfin tests in this crate.
