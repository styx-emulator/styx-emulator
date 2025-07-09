#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* stdbool.h */
#endif
/************************************************************************
 *
 * stdbool.h
 *
 * (c) Copyright 2008 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/
/* stdbool.h standard header */
#ifndef _STDBOOL
#define _STDBOOL
#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

_C_STD_BEGIN

 #define __bool_true_false_are_defined	1

 #ifndef __cplusplus
		/* TYPES */

#if defined(_MISRA_RULES)
/* should be able to test __ANALOG_EXTENSIONS to see if _Bool defined but can't */

/* for true and false not to give a misra error must be signed char */
/* front end defines _Bool to be same as char (i.e. signedness can switch) */
typedef signed char _Bool;

#endif /*!defined(_bool)*/

		/* MACROS */

#if !defined(_ADI_BOOL_TYPE_DEFINED)
 #if defined(_MISRA_RULES)
  typedef _Bool bool;
 #else
  #define bool	_Bool
 #endif
 #define _ADI_BOOL_TYPE_DEFINED 1
#endif

 #define false	0
 #define true	1
 #endif /* __cplusplus */

_C_STD_END
#endif /* _STDBOOL */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
