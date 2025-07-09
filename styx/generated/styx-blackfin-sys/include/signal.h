/************************************************************************
 *
 * signal.h
 *
 * (c) Copyright 2001-2003 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2001 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 * V3.10:1134
 *
 ************************************************************************/

/* signal.h standard header */
#ifndef _SIGNAL
#define _SIGNAL

/* Analog extensions to signal.h are located in a platform specific include
 * file.
 * Use the compile option -D__NO_ANSI_EXTENSIONS__ to exclude any such
 * extensions.
 */
# if !defined(__NO_ANSI_EXTENSIONS__)
#  if defined(__ADSPBLACKFIN__)
#    include "sys/signal_bf.h"
#  endif
# endif

#ifndef _YVALS
 #include <yvals.h>
#endif

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_20_1)
#pragma diag(suppress:misra_rule_20_2)
#endif /* _MISRA_RULES */

_C_STD_BEGIN

		/* type definitions */
typedef int sig_atomic_t;
typedef void _Sigfun(int);

		/* signal codes */
/* Real machine interrupts first */
#define SIGEMU	0	/* emulation traps */
#define SIGRSET	1	/* machine reset */
#define SIGNMI	2	/* non-maskable interrupt */
#define SIGEVNT	3	/* event vectoring */
#define SIGGLOB	4	/* global enabling */
#define SIGHW   5	/* hardware errors => SIGIOT */
#define SIGTIMR 6	/* timer events => SIGALRM */
#define SIGIVG7	7	/* misc interrupts */
#define SIGIVG8	8
#define SIGIVG9	9
#define SIGIVG10 10
#define SIGIVG11 11
#define SIGIVG12 12
#define SIGIVG13 13
#define SIGIVG14 14
#define SIGIVG15 15
#define _MAX_REAL_SIG SIGIVG15
#define SIGINT	16
#define SIGILL	17
#define SIGBUS	18
#define SIGFPE	19
#define SIGUSR1	SIGIVG15
#define SIGUSR2	SIGIVG14
#define SIGALRM	SIGTIMR
#define SIGSEGV	20
#define SIGTERM	21
#define SIGABRT	_SIGABRT
#define _NSIG	_SIGMAX	/* one more than last code */

		/* signal return values */
#define SIG_DFL	((_CSTD _Sigfun *)0)
#define SIG_ERR	((_CSTD _Sigfun *)-1)
#define SIG_IGN	((_CSTD _Sigfun *)1)

_EXTERN_C		/* low-level functions */
#pragma misra_func(handler)
_Sigfun * signal(int _which, _Sigfun *_fn);
_END_EXTERN_C

_C_LIB_DECL		/* declarations */
#pragma misra_func(handler)
int raise(int _which);
_END_C_LIB_DECL
_C_STD_END

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _SIGNAL */

#ifdef _STD_USING
using std::sig_atomic_t; using std::raise; using std::signal;
#endif /* _STD_USING */

/*
* Copyright (c) 1992-2001 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V3.10:1134 */
