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
** Support for avoidance of silicon anomaly 05-00-0311:
** non-predicted flow control may affect the value of GPIO
** flag pins. See TAR32344 for more details.
**
** To protect against the anomaly in C or C++ source files,
** use the macros defined in this header file when reading or
** writing one of the GPIO memory-mapped registers (MMRs).
** A group of macros are defined for reading and writing the
** MMRs; if the anomaly applies for the current value of the
** silicon revision of your target, the macro will ensure that
** the read or write is safe against the anomaly.
**
** To access FIO_FLAG_D, FIO_FLAG_C, FIO_FLAG_S or FIO_FLAG_T,
**   use FIO_ANOM_0311_FLAG_R(var, addr) to read the MMR
**   use FIO_ANOM_0311_FLAG_W(val, addr) to write to the MMR
**
** To access FIO_MASKA_D, FIO_MASKA_C, FIO_MASKA_S or FIO_MASKA_T,
**   use FIO_ANOM_0311_MASKA_R(var, addr) to read the MMR
**   use FIO_ANOM_0311_MASKA_W(val, addr) to write to the MMR
**
** To access FIO_MASKB_D, FIO_MASKB_C, FIO_MASKB_S or FIO_MASKB_T,
**   use FIO_ANOM_0311_MASKB_R(var, addr) to read the MMR
**   use FIO_ANOM_0311_MASKB_W(val, addr) to write to the MMR
**
** To access FIO_DIR,
**   use FIO_ANOM_0311_DIR_R(var) to read the MMR
**   use FIO_ANOM_0311_DIR_W(val) to write the MMR
**
** To access FIO_POLAR,
**   use FIO_ANOM_0311_POLAR_R(var) to read the MMR
**   use FIO_ANOM_0311_POLAR_W(val) to write the MMR
**
** To access FIO_EDGE,
**   use FIO_ANOM_0311_EDGE_R(var) to read the MMR
**   use FIO_ANOM_0311_EDGE_W(val) to write the MMR
**
** To access FIO_BOTH,
**   use FIO_ANOM_0311_BOTH_R(var) to read the MMR
**   use FIO_ANOM_0311_BOTH_W(val) to write the MMR
**
** To access FIO_INEN,
**   use FIO_ANOM_0311_INEN_R(var) to read the MMR
**   use FIO_ANOM_0311_INEN_W(val) to write the MMR
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
** x = *pFIO_FLAG_D;
** y = *pFIO_MASKA_D;
** z = x & y;
** *pFIO_FLAG_C = z;
** w = *pFIO_EDGE;
** *pFIO_DIR = 0;
**
** then the anomaly-safe code would be:
**
** unsigned short w, x, y, z;
** FIO_ANOM_0311_FLAG_R(x, pFIO_FLAG_D);
** FIO_ANOM_0311_MASKA_R(y, pFIO_MASKA_D);
** z = x & y;
** FIO_ANOM_0311_FLAG_W(z, pFIO_FLAG_C);
** FIO_ANOM_0311_EDGE_R(w);
** FIO_ANOM_0311_DIR_W(0);
*/

#ifndef _DEF_05000311_H
#define _DEF_05000311_H

#if defined(_LANGUAGE_C)

#include <sys/platform.h>

#if defined(__WORKAROUND_FLAGS_MMR_ANOM_311)



#define __0311_R(_v,_mmr,_safe) \
  do { \
    unsigned __mask = __builtin_cli(); \
    _v = __builtin_mmr_read16(_mmr); \
    (void)__builtin_mmr_read16(_safe); \
    __builtin_sti(__mask); \
  } while (0)

#define __0311_W(_v,_mmr,_safe) \
  do { \
    unsigned __mask = __builtin_cli(); \
    __builtin_mmr_write16(_mmr, _v); \
    (void)__builtin_mmr_read16(_safe); \
    __builtin_sti(__mask); \
  } while (0)

#define FIO_ANOM_0311_FLAG_R(_v,_mmr)   __0311_R(_v,_mmr,pSYSCR)
#define FIO_ANOM_0311_MASKA_R(_v,_mmr)  __0311_R(_v,_mmr,pTIMER1_CONFIG)
#define FIO_ANOM_0311_MASKB_R(_v,_mmr)  __0311_R(_v,_mmr,pTIMER2_CONFIG)
#define FIO_ANOM_0311_DIR_R(_v)         __0311_R(_v,pFIO_DIR,pSPORT0_STAT)
#define FIO_ANOM_0311_POLAR_R(_v)       __0311_R(_v,pFIO_POLAR,pSPORT0_STAT)
#define FIO_ANOM_0311_EDGE_R(_v)        __0311_R(_v,pFIO_EDGE,pSPORT0_STAT)
#define FIO_ANOM_0311_BOTH_R(_v)        __0311_R(_v,pFIO_BOTH,pSPORT0_STAT)
#define FIO_ANOM_0311_INEN_R(_v)        __0311_R(_v,pFIO_INEN,pTIMER_STATUS)

#define FIO_ANOM_0311_FLAG_W(_v,_mmr)   __0311_W(_v,_mmr,pSYSCR)
#define FIO_ANOM_0311_MASKA_W(_v,_mmr)  __0311_W(_v,_mmr,pTIMER1_CONFIG)
#define FIO_ANOM_0311_MASKB_W(_v,_mmr)  __0311_W(_v,_mmr,pTIMER2_CONFIG)
#define FIO_ANOM_0311_DIR_W(_v)         __0311_W(_v,pFIO_DIR,pSPORT0_STAT)
#define FIO_ANOM_0311_POLAR_W(_v)       __0311_W(_v,pFIO_POLAR,pSPORT0_STAT)
#define FIO_ANOM_0311_EDGE_W(_v)        __0311_W(_v,pFIO_EDGE,pSPORT0_STAT)
#define FIO_ANOM_0311_BOTH_W(_v)        __0311_W(_v,pFIO_BOTH,pSPORT0_STAT)
#define FIO_ANOM_0311_INEN_W(_v)        __0311_W(_v,pFIO_INEN,pTIMER_STATUS)

#else

/* Define null versions of the macros, as workarounds are not
** needed on this platform.
*/

#define __0311_R(_v,_mmr,_safe)         (_v = __builtin_mmr_read16(_mmr))
#define __0311_W(_v,_mmr,_safe)         (__builtin_mmr_write16(_mmr, _v))

#define FIO_ANOM_0311_FLAG_R(_v,_mmr)   __0311_R(_v,_mmr,pSYSCR)
#define FIO_ANOM_0311_MASKA_R(_v,_mmr)  __0311_R(_v,_mmr,pTIMER1_CONFIG)
#define FIO_ANOM_0311_MASKB_R(_v,_mmr)  __0311_R(_v,_mmr,pTIMER2_CONFIG)
#define FIO_ANOM_0311_DIR_R(_v)         __0311_R(_v,pFIO_DIR,pSPORT0_STAT)
#define FIO_ANOM_0311_POLAR_R(_v)       __0311_R(_v,pFIO_POLAR,pSPORT0_STAT)
#define FIO_ANOM_0311_EDGE_R(_v)        __0311_R(_v,pFIO_EDGE,pSPORT0_STAT)
#define FIO_ANOM_0311_BOTH_R(_v)        __0311_R(_v,pFIO_BOTH,pSPORT0_STAT)
#define FIO_ANOM_0311_INEN_R(_v)        __0311_R(_v,pFIO_INEN,pTIMER_STATUS)

#define FIO_ANOM_0311_FLAG_W(_v,_mmr)   __0311_W(_v,_mmr,pSYSCR)
#define FIO_ANOM_0311_MASKA_W(_v,_mmr)  __0311_W(_v,_mmr,pTIMER1_CONFIG)
#define FIO_ANOM_0311_MASKB_W(_v,_mmr)  __0311_W(_v,_mmr,pTIMER2_CONFIG)
#define FIO_ANOM_0311_DIR_W(_v)         __0311_W(_v,pFIO_DIR,pSPORT0_STAT)
#define FIO_ANOM_0311_POLAR_W(_v)       __0311_W(_v,pFIO_POLAR,pSPORT0_STAT)
#define FIO_ANOM_0311_EDGE_W(_v)        __0311_W(_v,pFIO_EDGE,pSPORT0_STAT)
#define FIO_ANOM_0311_BOTH_W(_v)        __0311_W(_v,pFIO_BOTH,pSPORT0_STAT)
#define FIO_ANOM_0311_INEN_W(_v)        __0311_W(_v,pFIO_INEN,pTIMER_STATUS)

#endif /* __WORKAROUND_FLAGS_MMR_ANOM_311 */
#endif /* _LANGUAGE_C */
#endif /* !_DEF_05000311_H */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */
