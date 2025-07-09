/* setjmp.h standard header */
#ifndef _SETJMP
#define _SETJMP
#ifndef _YVALS
#include <yvals.h>

#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_6)
#pragma diag(suppress:misra_rule_5_7)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_20_1)
#pragma diag(suppress:misra_rule_20_2)
#endif /* _MISRA_RULES */

_C_STD_BEGIN

		/* type definitions */
typedef int jmp_buf[_NSETJMP];
		/* macros */
_C_LIB_DECL
#pragma linkage_name __Setjmp
#pragma misra_func(jmp)
int setjmp(jmp_buf _env);
#pragma misra_func(jmp)
#pragma noreturn
void longjmp(jmp_buf _env, int _val);
_END_C_LIB_DECL
_C_STD_END

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _SETJMP */

/*
 * Copyright (c) 1994-1998 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V2.3:1134 */
