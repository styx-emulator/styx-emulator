/************************************************************************
 *
 * errno.h: $Revision: 3522 $
 *
 * (c) Copyright 2001-2010 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

 /* errno.h standard header */
#ifndef _ERRNO
#define _ERRNO

#ifndef _LANGUAGE_ASM

#ifndef __NO_BUILTIN
#pragma system_header /* errno.h */
#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3:"System Header uses basic types")
#pragma diag(suppress:misra_rule_8_8:"System Header allows re-declaration")
#pragma diag(suppress:misra_rule_19_4:"System Header allows non-MISRA compliant text for macro definition")
#pragma diag(suppress:misra_rule_20_1:"System Header declares standard identifiers")
#pragma diag(suppress:misra_rule_20_2:"System Header defines standard macros")
#endif /* _MISRA_RULES */

#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

#endif /* _LANGUAGE_ASM */

		/* ERROR CODES */
#define EDOM           0x0021
#define EFAULT         0x000E
#define EFBIG          0x001B
#define EFPOS          0x0098
#define EMLINK         0x001F
#define ENFILE         0x0017
#define ENOENT         0x0002
#define ENOSPC         0x001C
#define ENOTTY         0x0019
#define EPIPE          0x0020
#define ERANGE         0x0022
#define EROFS          0x001E
#define ESPIPE         0x001D

#define EBADMSG       0x004D
#define ECANCELED     0x002F
#define EDEADLK       0x002D
#define EILSEQ        0x0058
#define EINPROGRESS   0x0096
#define EMSGSIZE      0x0061
#define ENAMETOOLONG  0x004E
#define ENOLCK        0x002E
#define ENOSYS        0x0059
#define ENOTEMPTY     0x005D
#define ENOTSUP       0x0030
#define ETIMEDOUT     0x0091

#ifndef _LANGUAGE_ASM

_C_STD_BEGIN

		/* DECLARATIONS */
_C_LIB_DECL

#if _MULTI_THREAD
	void *adi_rtl_get_tls_ptr(void);
	#define errno (*(int *)adi_rtl_get_tls_ptr())
#else
	extern int errno;
#endif

int *_Geterrno(void);

_END_C_LIB_DECL
_C_STD_END

#ifdef _STD_USING
using std::errno;
#endif /* _STD_USING */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _LANGUAGE_ASM */

#endif /* _ERRNO */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
