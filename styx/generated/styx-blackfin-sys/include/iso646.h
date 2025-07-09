/* iso646.h standard header */
#if defined (_ADI_COMPILER)
/************************************************************************
 *
 * iso646.h
 *
 * (c) Copyright 2002-2009 Analog Devices, Inc.  All rights reserved.
 * (c) Copyright 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * $Revision: 3522 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* iso646.h */
#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_19_4)
#endif /* _MISRA_RULES */
#endif /* _ADI_COMPILER */

#ifndef _ISO646
#define _ISO646

 #if !defined(__cplusplus) || defined(__GNUC__) && __GNUC__ < 3 \
	|| defined(__BORLANDC__)
  #define and	&&
  #define and_eq	&=
  #define bitand	&
  #define bitor	|
  #define compl	~
  #define not	!
  #define not_eq	!=
  #define or		||
  #define or_eq	|=
  #define xor	^
  #define xor_eq	^=
 #endif /* !defined(__cplusplus) || defined(__GNUC__) && __GNUC__ < 3 */

#endif /* _ISO646 */

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
