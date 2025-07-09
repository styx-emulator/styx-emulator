/************************************************************************
 *
 * asm_sprt.h
 *
 * (c) Copyright 2001-2003 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Support for Blackfin Assembly Language Subroutines Called From C/C++ */

#ifndef __ASM_SPRT_DEFINED
#define __ASM_SPRT_DEFINED

#ifndef _LANGUAGE_C  /* DON'T parse if Compiler is parsing this file */

/* Perform all ENTRY tasks for a Leaf function) */
#define leaf_entry     /* Nothing to do */

/* Make A new Frame and Perform all ENTRY tasks for a non-Leaf function */
#define full_entry(FRAME_SIZE_)     LINK FRAME_SIZE_

#define entry                       full_entry(0)

/* (Perform all EXIT tasks for a Leaf function) */
#define leaf_exit                   RTS

/* Perform all EXIT tasks for a non-Leaf function */
#define full_exit                   P0 = [FP + 0x4]; UNLINK; JUMP (P0)

#define exit                        full_exit

/* Get the next Stack value */
#define pops(x)                     x = [SP++]

/* Get the next Stack value */
#define and_pops(x)                 x = [SP++]

/* Store onto next stack location */
#define puts                        [--SP]

/* A Better interface for "Store onto next stack location" */
#define pushs(x)                    [--SP] = x

/* Reserve space on the Stack for locals */
#define alter(x)                    SP += x

#endif /* _LANGUAGE_C */
#endif /* __ASM_SPRT_DEFINED */
