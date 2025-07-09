/****************************************************************************
 *
 * mc_data.h : $Revision: 3522 $
 *
 * (c) Copyright 2004-2009 Analog Devices, Inc.  All rights reserved.
 *
 ****************************************************************************/

#ifndef _MC_DATA_H
#define _MC_DATA_H

#include <limits.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3:"Allow int in prototypes")
#pragma diag(suppress:misra_rule_19_4:"Allow macros to map to other macros")
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* _MC_NO_OF_CORES is deprecated. Use __NUM_CORES__ instead. */
#define _MC_NO_OF_CORES __NUM_CORES__

#define _MC_NO_OF_SLOTS 10
#define adi_mc_unallocated INT_MIN

int adi_obtain_mc_slot(int *key, void (*dtor)(void *));
int adi_free_mc_slot(int key);
int adi_set_mc_value(int key, void *val);
void *adi_get_mc_value(int key);

#ifdef __cplusplus
} /* extern */
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif

#endif /* _MC_DATA_H */
