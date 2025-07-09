/****************************************************************************
 *
 * adi_rtl_sync.h : $Revision: 1.4.2.2 $
 *
 * (c) Copyright 2009 Analog Devices, Inc.  All rights reserved.
 *
 * The runtime libraries' threading abstraction layer.
 *
 ****************************************************************************/

#ifndef _ADI_RTL_SYNC_H
#define _ADI_RTL_SYNC_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_1)
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_8_8)
#endif /* _MISRA_RULES */

_EXTERN_C

/* The globals lock */

void adi_rtl_lock_globals(void);
void adi_rtl_unlock_globals(void);


/* Mutexes */

typedef intptr_t adi_rtl_mutex;

enum { ADI_RTL_INVALID_MUTEX = -1 };

bool adi_rtl_init_mutex(adi_rtl_mutex *mutex_p, bool io);
void adi_rtl_deinit_mutex(adi_rtl_mutex *mutex_p);

void adi_rtl_acquire_mutex(adi_rtl_mutex *mutex_p);
void adi_rtl_release_mutex(adi_rtl_mutex *mutex_p);


/* The thread-local storage block */

enum { ADI_RTL_TLS_LEN = 12 };

#pragma const
void *adi_rtl_get_tls_ptr(void);

void adi_rtl_destroy_tls_cb(void *block);

_END_EXTERN_C

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
