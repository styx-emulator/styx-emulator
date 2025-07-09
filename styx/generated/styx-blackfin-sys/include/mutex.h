/****************************************************************************
 *
 * mutex.h : $Revision: 3522 $
 *
 * This is an obsolete implementation header file.
 * Please do not include it and do not use the internal
 * interfaces declared here. These will be removed
 * in the next major release of VisualDSP++.
 *
 * (c) Copyright 2010 Analog Devices, Inc.  All rights reserved.
 *
 ****************************************************************************/

#ifndef _MUTEX_H
#define _MUTEX_H

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3:"Allow typedefs without size")
#pragma diag(suppress:misra_rule_19_7:"Allow function-like macros")
#endif

#if _MULTI_THREAD

#include <xsyslock.h>

#define _PUSH_UNSCHEDULED_REGION() (adi_rtl_lock_globals())
#define _POP_UNSCHEDULED_REGION() (adi_rtl_unlock_globals())

#define _PUSH_C_IO_ATOMIC_SECTION() \
  (__check_and_acquire_mutex(&_Files_mutex, 1))

#define _POP_C_IO_ATOMIC_SECTION() \
  (adi_rtl_release_mutex(&_Files_mutex))

#else /* _MULTI_THREAD */

#define _PUSH_UNSCHEDULED_REGION() ((void)0)
#define _POP_UNSCHEDULED_REGION() ((void)0)
#define _PUSH_C_IO_ATOMIC_SECTION() ((void)0)
#define _POP_C_IO_ATOMIC_SECTION() ((void)0)

#endif /* _MULTI_THREAD */

#define _Lockfileatomic(x) (_PUSH_C_IO_ATOMIC_SECTION())
#define _Unlockfileatomic(x) (_PUSH_C_IO_ATOMIC_SECTION())

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif

#endif /* _MUTEX_H */
