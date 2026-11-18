/* SPDX-License-Identifier: BSD-2-Clause */
/* Two-core PowerPC 405 firmware for the GDB multicore example.
 *
 * The firmware runs two cores (vCPUs) at the same time. Each core loops and increments
 * two counters. One counter is private to the core. The other counter is shared
 * between the two cores.
 *
 * Both cores run a separate copy of the same .text bytes, at different base
 * addresses. The builder gives each core its own values in these registers:
 *
 *   r3 = the private counter of this core (PRIV_BASE_0 / PRIV_BASE_1)
 *   r1 = the stack top of this core       (STACK_BASE_0 / STACK_BASE_1)
 *   PC = the code copy of this core       (CODE_BASE_0  / CODE_BASE_1)
 *
 * The loop calls two subroutines:
 *   incr_private - increments the private word of this core at 0(r3).
 *   incr_shared  - increments the shared word at SHARED_COUNTER.
 *
 * Both subroutines obey the PowerPC SysV stack conventions. They write a NULL
 * back-chain terminator and they allocate their frames with `stwu`. The gdb
 * client needs these conventions to unwind the call stack.
 *
 * The read-modify-write of the shared word is not atomic (lwz/addi/stw). The
 * PPC sleigh spec does not implement lwarx/stwcx. As a result, the two cores
 * can lose an update when their writes overlap in time.
 *
 * ../build.rs assembles this file at build time. The crate embeds the `.text`
 * bytes as FIRMWARE. The nexti tests load the object file that holds the symbols
 * (FIRMWARE_OBJ_FILE). The `firmware_layout_invariants` test pins the offsets
 * that the example uses. `make dis` (see Makefile) shows the encoding.
 */
    .section .text
    .globl _start
_start:
    li     %r0, 0
    stw    %r0, 0(%r1)           /* NULL back chain terminator at stack top        */
    stwu   %r1, -32(%r1)         /* Allocate the _start stack frame (SysV)         */
    lis    %r5, 0x0003           /* r5 = SHARED_COUNTER base (0x0003_0000)         */
1:                               /* This numeric local label emits no symbol. The  */
                                 /* `bl` below thus stays inside the `_start`      */
                                 /* symbol. A named label here would make a secon  */
                                 /* function that has no frame, and `nexti` would  */
                                 /* then behave as `stepi`.                        */
    bl     incr_private
    nop                          /* the bl returns here. nexti stops here.         */
    bl     incr_shared
    b      1b                    /* loop                                           */
incr_private:
    mflr   %r0                   /* standard SysV sack frame prologue              */
    stwu   %r1, -16(%r1)
    stw    %r0, 20(%r1)
    lwz    %r4, 0(%r3)           /* r4 = *priv. Each core has its own r3.          */
    addi   %r4, %r4, 1           /* increment the private counter                  */
    stw    %r4, 0(%r3)           /* *priv = r4  (PRIV_STW_OFFSET)                  */
    lwz    %r0, 20(%r1)
    mtlr   %r0
    addi   %r1, %r1, 16
    blr                          /* return to call+4, that is, the nop             */
incr_shared:
    mflr   %r0                   /* Stack prologue                                 */
    stwu   %r1, -16(%r1)
    stw    %r0, 20(%r1)
    lwz    %r6, 0(%r5)           /* r6 = *shared. This sequence is not atomic.     */
    addi   %r6, %r6, 1
    stw    %r6, 0(%r5)           /* *shared = r6                                   */
    lwz    %r0, 20(%r1)
    mtlr   %r0
    addi   %r1, %r1, 16
    blr
