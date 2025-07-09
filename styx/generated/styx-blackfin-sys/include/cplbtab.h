#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* cplbtab.h */
#endif
/************************************************************************
 *
 * cplbtab.h
 *
 * (c) Copyright 2002-2007 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Define structures for the CPLB tables. */

#ifndef _CPLBTAB_H
#define _CPLBTAB_H

#include <cplb.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_12)
#endif /* _MISRA_RULES */

typedef struct {
  unsigned long addr;
  unsigned long flags;
} cplb_entry;

extern cplb_entry dcplbs_table[];
extern cplb_entry icplbs_table[];
extern int __cplb_ctrl;

#ifdef __cplusplus
 extern "C" {
#endif

void cplb_init(int _enable_cpls_caches);
int cplb_mgr(int _is_data_miss, int _enable_cache);
void cplb_hdr(void);
void cache_invalidate(int _caches);
void icache_invalidate(void);
void dcache_invalidate(int _caches);
void dcache_invalidate_both(void);
void flush_data_cache(void);
void flush_data_buffer(void *_start, void *_end, int _invalidate);
void disable_data_cache(void);
void enable_data_cache(int _cplb_ctrl);

#ifdef __cplusplus
 }
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _CPLBTAB_H */
