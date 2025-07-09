#pragma once /* Lets MISRA know rule 19.15 not being violated */

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_4:"Anomaly Header, example code in comments")
#pragma diag(suppress:misra_rule_6_3:"Anomaly header allows use of basic types")
#pragma diag(suppress:misra_rule_19_4:"Anomaly header allows any substitution")
#pragma diag(suppress:misra_rule_19_7:"Anomaly header requires function-like macros")
#pragma diag(suppress:misra_rule_19_10:"Anomaly header macro function parameters not parenthesised")
#endif /* _MISRA_RULES */

/* Copyright (C) 2007 Analog Devices, Inc. All Rights Reserved.
**
** Support for avoidance of silicon anomaly 05-00-0323:
** Erroneous GPIO Flag Pin Operations under Specific Sequences.
**
** To protect against the anomaly in C or C++ source files,
** use the macros defined in this header file when reading or
** writing one of the GPIO memory-mapped registers (MMRs).
** A group of macros are defined for reading and writing the
** MMRs; if the anomaly applies for the current value of the
** silicon revision of your target, the macro will ensure that
** the read or write is safe against the anomaly.
**
** To access FIOx_FLAG_D, FIOx_FLAG_C, FIOx_FLAG_S or FIOx_FLAG_T,
**   use FIOx_ANOM_0323_FLAG_R(var, addr) to read the MMR
**   use FIOx_ANOM_0323_FLAG_W(val, addr) to write to the MMR
**
** To access FIOx_MASKA_D, FIO_MASKA_C, FIO_MASKA_S or FIO_MASKA_T,
**   use FIOx_ANOM_0323_MASKA_R(var, addr) to read the MMR
**   use FIOx_ANOM_0323_MASKA_W(val, addr) to write to the MMR
**
** To access FIOx_MASKB_D, FIO_MASKB_C, FIO_MASKB_S or FIO_MASKB_T,
**   use FIOx_ANOM_0323_MASKB_R(var, addr) to read the MMR
**   use FIOx_ANOM_0323_MASKB_W(val, addr) to write to the MMR
**
** To access FIOx_DIR,
**   use FIOx_ANOM_0323_DIR_R(var, addr) to read the MMR
**   use FIOx_ANOM_0323_DIR_W(val, addr) to write the MMR
**
** To access FIOx_POLAR,
**   use FIOx_ANOM_0323_POLAR_R(var, addr) to read the MMR
**   use FIOx_ANOM_0323_POLAR_W(val, addr) to write the MMR
**
** To access FIOx_EDGE,
**   use FIOx_ANOM_0323_EDGE_R(var, addr) to read the MMR
**   use FIOx_ANOM_0323_EDGE_W(val, addr) to write the MMR
**
** To access FIOx_BOTH,
**   use FIOx_ANOM_0323_BOTH_R(var, addr) to read the MMR
**   use FIOx_ANOM_0323_BOTH_W(val, addr) to write the MMR
**
** To access FIOx_INEN,
**   use FIOx_ANOM_0323_INEN_R(var, addr) to read the MMR
**   use FIOx_ANOM_0323_INEN_W(val, addr) to write the MMR
**
** For reads, "var" is the variable to receive the value from
** the MMR, and "addr" is the address of the MMR, if required.
*
** For writes, "val" is the value (or variable) to be written
** to the MMR, and "addr" is the address of the MMR, if required.
**
** For example, if your original code is:
**
** unsigned short w, x, y, z;
** x = *pFIO0_FLAG_D;
** y = *pFIO0_MASKA_D;
** z = x & y;
** *pFIO0_FLAG_C = z;
** w = *pFIO0_EDGE;
** *pFIO0_DIR = 0;
**
** then the anomaly-safe code would be:
**
** unsigned short w, x, y, z;
** FIOx_ANOM_0323_FLAG_R(x, pFIO0_FLAG_D);
** FIOx_ANOM_0323_MASKA_R(y, pFIO0_MASKA_D);
** z = x & y;
** FIOx_ANOM_0323_FLAG_W(z, pFIO0_FLAG_C);
** FIOx_ANOM_0323_EDGE_R(w, pFIO0_EDGE);
** FIOx_ANOM_0323_DIR_W(0, pFIO0_DIR);
*/

#ifndef _DEF_05000323_H
#define _DEF_05000323_H

#if defined(_LANGUAGE_C)

#include <sys/platform.h>

#if defined(__WORKAROUND_FLAGS_MMR_ANOM_323)

/* Define read and write macros to support the anomaly workaround. */

#define __0323_R(_v,_mmr,_safe) \
  do { \
    unsigned __mask = __builtin_cli(); \
    _v = __builtin_mmr_read16(_mmr); \
    (void)__builtin_mmr_read16(_safe); \
    __builtin_sti(__mask); \
  } while (0)

#define __0323_W(_v,_mmr,_safe) \
  do { \
    unsigned __mask = __builtin_cli(); \
    __builtin_mmr_write16(_mmr, _v); \
    (void)__builtin_mmr_read16(_safe); \
    __builtin_sti(__mask); \
  } while (0)

#else

/* Define read and write macros that don't apply the workaround because it
** is not enabled.
*/

#define __0323_R(_v,_mmr,_safe)         (_v = __builtin_mmr_read16(_mmr))
#define __0323_W(_v,_mmr,_safe)         (__builtin_mmr_write16(_mmr, _v))

#endif /* __WORKAROUND_FLAGS_MMR_ANOM_323 */

/* read macros */
#define FIOx_ANOM_0323_FLAG_R(_v,_mmr)   __0323_R(_v,_mmr,pSICA_SYSCR)
#define FIOx_ANOM_0323_MASKA_R(_v,_mmr)  __0323_R(_v,_mmr,pUART_SCR)
#define FIOx_ANOM_0323_MASKB_R(_v,_mmr)  __0323_R(_v,_mmr,pUART_GCTL)
#define FIOx_ANOM_0323_DIR_R(_v,_mmr)    __0323_R(_v,_mmr,pSPORT0_STAT)
#define FIOx_ANOM_0323_POLAR_R(_v,_mmr)  __0323_R(_v,_mmr,pSPORT0_STAT)
#define FIOx_ANOM_0323_EDGE_R(_v,_mmr)   __0323_R(_v,_mmr,pSPORT0_STAT)
#define FIOx_ANOM_0323_BOTH_R(_v,_mmr)   __0323_R(_v,_mmr,pSPORT0_STAT)
#define FIOx_ANOM_0323_INEN_R(_v,_mmr)   __0323_R(_v,_mmr,pDMA1_1_CONFIG)

/* write macros */
#define FIOx_ANOM_0323_FLAG_W(_v,_mmr)   __0323_W(_v,_mmr,pSICA_SYSCR)
#define FIOx_ANOM_0323_MASKA_W(_v,_mmr)  __0323_W(_v,_mmr,pUART_SCR)
#define FIOx_ANOM_0323_MASKB_W(_v,_mmr)  __0323_W(_v,_mmr,pUART_GCTL)
#define FIOx_ANOM_0323_DIR_W(_v,_mmr)    __0323_W(_v,_mmr,pSPORT0_STAT)
#define FIOx_ANOM_0323_POLAR_W(_v,_mmr)  __0323_W(_v,_mmr,pSPORT0_STAT)
#define FIOx_ANOM_0323_EDGE_W(_v,_mmr)   __0323_W(_v,_mmr,pSPORT0_STAT)
#define FIOx_ANOM_0323_BOTH_W(_v,_mmr)   __0323_W(_v,_mmr,pSPORT0_STAT)
#define FIOx_ANOM_0323_INEN_W(_v,_mmr)   __0323_W(_v,_mmr,pDMA1_1_CONFIG)

#endif /* _LANGUAGE_C */
#endif /* !_DEF_05000323_H */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */
