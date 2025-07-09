#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* stdarg.h */
#endif
/************************************************************************
 *
 * stdarg.h
 *
 * (c) Copyright 2001-2003 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* stdarg.h standard header */
#ifndef _STDARG
#define _STDARG
#ifndef _YVALS
#include <yvals.h>
#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_19_10)
#pragma diag(suppress:misra_rule_20_1)
#endif /* _MISRA_RULES */

_C_STD_BEGIN
		/* type definitions */
/*_Va_list and va_list are both defined within yvals.h */
		/* macros */
#define va_arg(ap, T)	\
	(*(T *)(((ap) += _Bnd(T, _AUPBND)) - _Bnd(T, _ADNBND)))
#define va_end(ap)		(void)((ap) = 0)
#define va_start(ap, A) \
	(void)((ap) = (va_list)__builtin_va_start((void*)&(A), _Bnd(A, _AUPBND)))
#define _Bnd(X, bnd)	(sizeof (X) + (bnd) & ~(bnd))

_C_STD_END

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _STDARG */
