# gdb-multicore-ppc

A custom **two-core PowerPC 405** processor that exercises the Styx GDB plugin
against a multi-vCPU target. Each core runs its own copy of a unified firmware
that keeps a per-core private counter (written through `r3`), calls a private
`incr_private` subroutine, and increments a single shared counter in memory.

This example doubles as a test for gdb on a multi-vCPU target and nexti
functionality with styx as a remote target.

## Run it interactively

Run the dual core firmware in GDB to get a feel for Styx multi-vCPU debugging.
Reference the `lib.rs` for a starting point in creating a multi-vCPU processor.

```sh
cd examples/gdb-multicore-ppc/
cargo run
```

The binary prints the path of the assembled firmware object file, which you need
to load as a symbol file so GDB can resolve function boundaries for `nexti`.

Then, in another terminal:

```sh
gdb-multiarch -ex 'set endian big' -ex 'target remote :9999'
(gdb) info threads              # two threads -> the two PPC405 cores
(gdb) thread 2                  # switch to core 1
(gdb) p/x $r3                   # 0x40000 on core 0, 0x50000 on core 1
(gdb) break *0x20034            # core 1's private stw (CODE_BASE_1 + 0x34) -> only stops thread 2
(gdb) continue
(gdb) x/x 0x30000               # shared counter, climbing
(gdb) delete                    # clear breakpoints before the nexti demo
(gdb) add-symbol-file <printed path> 0x10000
(gdb) break *0x10010            # the `bl incr_private` on core 0
(gdb) continue
(gdb) nexti                     # steps OVER the call -> lands at 0x10014
(gdb) watch *0x40000            # watchpoint on core 0's private word;
(gdb) continue                  # `continue` then stops on the next private write
```

## Memory layout

| Address     | Meaning                         |
|-------------|---------------------------------|
| `0x10000`   | core 0 firmware copy / PC       |
| `0x20000`   | core 1 firmware copy / PC       |
| `0x30000`   | shared counter                  |
| `0x40000`   | core 0 private counter (`r3`)   |
| `0x50000`   | core 1 private counter (`r3`)   |

### Key offsets within each firmware copy

| Offset  | Instruction                          |
|---------|--------------------------------------|
| `0x10`  | `bl incr_private` |
| `0x14`  | return address after `bl` |
| `0x34`  | `stw` private counter write |

## Editing the firmware

The firmware lives in `firmware/firmware.S`. `build.rs` assembles it with
clang's integrated assembler at build time and embeds the raw `.text` bytes via
`include_bytes!` as the `FIRMWARE` constant in `src/lib.rs`. Building needs a
`clang` that can target PowerPC (no separate PowerPC cross-binutils required).

To change it, just edit `firmware/firmware.S` and rebuild the crate.

If you change the instruction layout, also update the offset constants in
`src/lib.rs` (`PRIV_STW_OFFSET`, `BL_OFFSET`, `RETURN_OFFSET`) and the
breakpoint addresses in this README to match. The `firmware_layout_invariants`
test asserts these offsets and the firmware size and will catch drift.

For inspecting the encoding while editing, `firmware/Makefile` has `make -C
firmware dis` (disassembly), which need a big-endian PowerPC `as`/`objdump`
(a local `powerpc-linux-gnu-*` toolchain, or the repo's podman image via
`RUN='…'`. More info at the top of the Makefile). The podman image can
be built from `styx/processors/ppc/styx-ppc4xx-processor/test-data/Makefile`.

If you're lazy, just run `make -C styx/processors/ppc/styx-ppc4xx-processor/test-data/ container` to make the podman toolchain image.
