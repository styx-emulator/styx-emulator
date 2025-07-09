#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* ccblkfn.h */
#endif
/************************************************************************
 *
 * ccblkfn.h
 *
 * (c) Copyright 2001-2009 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* ccblkfn definitions */

#ifndef _CCBLKFN_H
#define _CCBLKFN_H

#include <stdlib.h>
  /* include builtins.h to define prototype all compiler builtins (intrinsics)
  ** and define shortnames inline functions for each
  */
#include <builtins.h>
#include <sys/anomaly_macros_rtl.h>

  /* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_8_1:"ADI header uses inline functions")
#pragma diag(suppress:misra_rule_8_5:"ADI header uses inline functions")
#pragma diag(suppress:misra_rule_11_2: "ADI header allows conversions between pointer types")
#pragma diag(suppress:misra_rule_11_3: "ADI header allows conversions between pointer types")
#pragma diag(suppress:misra_rule_11_4: "ADI header allows conversions between pointer types")
#pragma diag(suppress:misra_rule_11_5: "ADI header allows conversions between pointer types")
#pragma diag(suppress:misra_rule_19_1:"ADI header macro parameters do not require parentheses")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution text")
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function macros")
#pragma diag(suppress:misra_rule_19_14:"ADI header allows non-misra use of defined() macro")
#endif /* _MISRA_RULES */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __NO_BUILTIN

/* These are provided for backwards compatibility, but the
** definitions in builtins.h should be used in preference.
*/

#define __lvitmax2x16(A, B, C, D, E) { \
  (D) = __builtin_lvitmax2x16_r1((A), (B), (C)); \
  (E) = __builtin_lvitmax2x16_r2(D); \
}

#define __rvitmax2x16(A, B, C, D, E) { \
  (D) = __builtin_rvitmax2x16_r1((A), (B), (C)); \
  (E) = __builtin_rvitmax2x16_r2(D); \
}

#define __lvitmax1x16(A, B, C, D) { \
  (C) = __builtin_lvitmax1x16_r1((A), (B)); \
  (D) = __builtin_lvitmax1x16_r2(C); \
}

#define __rvitmax1x16(A,B,C,D) { \
  (C) = __builtin_rvitmax1x16_r1((A),(B)); \
  (D) = __builtin_rvitmax1x16_r2(C); \
}

#define __builtin_lvitmax2x16 __lvitmax2x16
#define __builtin_rvitmax2x16 __rvitmax2x16
#define __builtin_lvitmax1x16 __lvitmax1x16
#define __builtin_rvitmax1x16 __rvitmax1x16

/* halt() and abort() operations are no longer supported by the simulators.
** Invoke the _Exit() system call, which circumvents exit()'s clean-up.
*/

#define sys_halt() _Exit()

#if !defined(abort)

#define sys_abort() _Exit()

#endif

#endif /* !__NO_BUILTIN */

/* Copy from L1 Instruction memory */
void *_l1_memcpy(void *datap, const void *instrp, size_t n);

/* Copy to L1 Instruction memory */
void *_memcpy_l1(void *instrp, const void *datap, size_t n);

/*
** Routines for set/unsetting atomic access bit in value pointed to.
** These routines use the TESTSET instruction to gain exclusive access
** to a flag variable.
**
** Obtaining the flag provides atomic access for the core that claims
** the flag that is passed in.
**
** NOTE: It is assumed that the routines will be called in a lock/unlock
**       order.  No checking is performed in the unlock routine to ensure
**       that the current core has the lock.  As long as the routines
**       are used correctly there is no need for this functionality.
**
** For Multi-Core Processors Only
*/

#include <sys/mc_typedef.h>
#ifndef __NO_BUILTIN

#pragma inline
#pragma always_inline
static void adi_acquire_lock(testset_t *_t) {
  csync();
  while(__builtin_testset((char *) _t)==0) {
    csync();
  }
}

#pragma inline
#pragma always_inline
static int adi_try_lock(testset_t *_t) {
  int rtn;
  csync();
  rtn = __builtin_testset((char *) _t);
  return rtn;
}

#pragma inline
#pragma always_inline
static void adi_release_lock(testset_t *_t) {
  __builtin_untestset((char *) _t);
  ssync();
}

/* Legacy routines - will be deprecated */

#pragma inline
#pragma always_inline
static void claim_atomic_access(testset_t *_t) {
  adi_acquire_lock(_t);
}

#pragma inline
#pragma always_inline
static void release_atomic_access(testset_t *_t) {
  adi_release_lock(_t);
}

#else

/* Out-of-line versions of atomic access functions are in libc561,
** prototypes below.
*/
void adi_acquire_lock(testset_t *_t);
int adi_try_lock(testset_t *_t);
void adi_release_lock(testset_t *_t);

#endif /* !__NO_BUILTIN */

#if __NUM_CORES__ > 1

#if defined(__ADSPBF561__)

#include <cdefBF561.h>

#pragma inline
#pragma always_inline
static int adi_core_id(void) {
  /* Return the core ID: 0 for core A, 1 for core B.
   * (The SRAM base is 0xFF800000 for core A and 0xFF400000 for core B.)
   */
  unsigned int sram_base = *(volatile unsigned int *)SRAM_BASE_ADDRESS;
  int id = (sram_base & 0x400000u) != 0u;
  return id;
}

#pragma inline
#pragma always_inline
static void adi_core_b_enable(void) {
  /* Clearing bit 5 allows core B to run. */
  *pSICA_SYSCR &= (unsigned short)(~(1ul<<5));
  /* Setting it again releases it from its waiting loop in the CRT. */
  *pSICA_SYSCR |= (unsigned short)(1ul<<5);
}

#endif /* defined(__ADSPBF561__) */

#else  /* __NUM_CORES__ > 1 */

/* NULL versions, for when the Core-A part of an application
** is run on a single-core system.
*/

#pragma inline
#pragma always_inline
static int adi_core_id(void) {
  return 0;
}

#pragma inline
#pragma always_inline
static void adi_core_b_enable(void)
{
  /* do nothing */
}

#endif /* __NUM_CORES__ > 1 */

#ifdef __cplusplus
} /* extern "C" */
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* _CCBLKFN_H */
