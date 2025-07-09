/************************************************************************
 *
 * pll.h
 *
 * (c) Copyright 2003-2010 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#ifdef _LANGUAGE_C
#pragma once
#pragma system_header
#endif

#ifndef _PLL_H
#define _PLL_H

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#endif /* _MISRA_RULES */

#ifdef _LANGUAGE_C

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ADSPLPBLACKFIN__)

/* Sets SSEL and CSEL bits in PLL_DIV to passed values.
** Returns -1 on failure.
*/
int pll_set_system_clocks(int _csel, int _ssel);

/*
** Sets MSEL and DF bits in PLL_CTL and LOCKCNT in PLL_LOCKCNT.
** Returns -1 on failure.
*/
int pll_set_system_vco(int _msel, int _df, int _lockcnt);

#endif /* __ADSPLPBLACKFIN__ */

#ifdef __cplusplus
}
#endif

#endif /* _LANGUAGE_C */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _PLL_H */
