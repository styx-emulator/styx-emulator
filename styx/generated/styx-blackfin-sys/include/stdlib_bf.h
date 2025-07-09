#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* stdlib_bf.h */
#endif
/************************************************************************
 *
 * stdlib_bf.h
 *
 * (c) Copyright 2002-2008 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/*
   This header file contains all ADSP Blackfin specific
   Analog extensions to the ANSI header file stdlib.h.

   The header file is included by stdlib.h by default.
   To disable the extensions, compile with the option:
        -D__NO_ANSI_EXTENSIONS__
 */


#ifndef  _STDLIB_BF_H
#define  _STDLIB_BF_H

#include <yvals.h>

#include <stdlib.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_6)
#pragma diag(suppress:misra_rule_5_7)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_1)
#pragma diag(suppress:misra_rule_8_5)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#endif /* _MISRA_RULES */
_C_STD_BEGIN

_C_LIB_DECL
#pragma misra_func(heap)
void * _heap_calloc(int _heapid, size_t _nelem, size_t _size);
#pragma misra_func(heap)
void _heap_free(int _heapid, void *_ptr);
#pragma misra_func(heap)
void * _heap_malloc(int _heapid, size_t _size_arg);
#pragma misra_func(heap)
void * _heap_realloc(int _heapid, void *_ptr, size_t _size_arg);
#pragma misra_func(heap)
int _heap_init(int _idx);
#pragma misra_func(heap)
int _heap_install(void *_base, size_t _length, int _userid);
#pragma misra_func(heap)
int _heap_install_impl(void *_base, size_t _length, int _userid, int _in_init);
#pragma misra_func(heap)
int _heap_lookup(int _userid);
#pragma misra_func(heap)
void *_heap_address_from_index(int _idx);
#pragma misra_func(heap)
int _space_unused(void);
#pragma misra_func(heap)
int _heap_space_unused(int _idx);

_END_C_LIB_DECL

_C_STD_END
/* Macro params should be enclosed in brackets to avoid unexpected evaluations. (GA) MISRA Rule 19.10 */
#define heap_calloc(X,Y,Z) _heap_calloc((X),(Y),(Z))
#define heap_free(X,Y) _heap_free((X),(Y))
#define heap_malloc(X,Y) _heap_malloc((X),(Y))
#define heap_realloc(X,Y,Z) _heap_realloc((X),(Y),(Z))
#define heap_init(X) _heap_init((X))
#define heap_install(X,Y,Z) _heap_install((X),(Y),(Z))
#define heap_lookup(X) _heap_lookup(X)
#define heap_address_from_index(X) _heap_address_from_index(X)
#define space_unused() _space_unused()
#define heap_space_unused(X) _heap_space_unused(X)

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif   /* _STDLIB_BF_H */
