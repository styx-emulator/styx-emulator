#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* signal_bf.h */
#endif
/************************************************************************
 *
 * signal_bf.h
 *
 * (c) Copyright 2002-2003 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/*
   This header file contains all ADSP Blackfin specific
   Analog extensions to the ANSI header file signal.h.

   The header file is included by signal.h by default.
   To disable the extensions, compile with the option:
        -D__NO_ANSI_EXTENSIONS__
 */


#ifndef _SIGNAL_BF_H
#define _SIGNAL_BF_H

#include <yvals.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_19_4)
#endif /* _MISRA_RULES */

_C_STD_BEGIN
_EXTERN_C      /* low-level functions */
#pragma misra_func(handler)
void (*interrupt(int which, void (*fn)(int))) (int);
_END_EXTERN_C
_C_STD_END

#ifdef _STD_USING
using std::interrupt;
#endif /* _STD_USING */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _SIGNAL_BF_H */
