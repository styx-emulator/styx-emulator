#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* xalloc.h */
#endif
/************************************************************************
 *
 * xalloc.h
 *
 * (c) Copyright 2001-2010 Analog Devices, Inc.  All rights reserved.
 *
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

/* xalloc.h internal header */
#ifdef __ADSP21XX__
#error Should not be used
#endif

#ifndef _XALLOC
#define _XALLOC
#include <stddef.h>
#include <stdlib.h>
#ifndef _YVALS
 #include <yvals.h>
#endif /* _YVALS */

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution")
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function macros")
#endif /* _MISRA_RULES */

_C_STD_BEGIN

#define MAXHEAPS  4
		/* macros */
#if defined(_ADI_COMPILER)
/* MISRA safe */
#define M_MASK          ((unsigned int)((unsigned int)1u << _MEMBND) - 1u) /* rounds all sizes */
#define CELL_OFF        (offsetof(_Cell, _Next) + M_MASK & (unsigned int)(~(unsigned int)M_MASK))
#else
#define M_MASK	((1 << _MEMBND) - 1)	/* rounds all sizes */
#define CELL_OFF	(offsetof(_Cell, _Next) + M_MASK & ~M_MASK)
#endif /* _ADI_COMPILER */
#define SIZE_BLOCK	512	/* minimum block size, power of 2 */
#define SIZE_CELL	(sizeof (_Cell) + M_MASK & ~M_MASK)

/*If we define FAST_MULTI_HEAPS then we will use a free list for each heap*/
#ifdef __ADSPBLACKFIN__
# define _FAST_MULTI_HEAPS
#endif

		/* type definitions */
typedef struct _Cell
	{	/* heap item */
	size_t _Size;	/* CELL_OFF <= SIZE_CELL <= _Size */
#ifdef _FAST_MULTI_HEAPS
	int _Id;	/* Heap from which Cell was allocated */
#endif
	struct _Cell *_Next;	/* reused if CELL_OFF < SIZE_CELL */
	} _Cell;

typedef struct
	{	/* heap control information */
	_Cell **_Plast;	/* null, or where to resume malloc scan */
	_Cell *_Head;	/* null, or lowest addressed free cell */
	} _Altab;

		/* declarations */
_C_LIB_DECL
#if defined(_ADI_COMPILER)
void * _Getmem(int _heapid, size_t _size);	/* heapid, amount */
#ifdef _FAST_MULTI_HEAPS
extern _Altab _Aldata[MAXHEAPS];	/* free list initially empty */
#else
extern _Altab _Aldata;	/* free list initially empty */
#endif /* _FAST_MULTI_HEAPS */
#else
void * _Getmem(size_t);
extern _Altab _Aldata;	/* free list initially empty */
#endif /* defined(_ADI_COMPILER) */
_END_C_LIB_DECL

 #ifdef _INTELx86
/* #define _PTR_NORM(p) (void __huge *)(p) should have worked */
  #define _PTR_NORM(p) \
	( (((unsigned long)(p) & 0xFFFF0000L)>>12) \
	+ ((unsigned long)(p) & 0xFFFFL) )

 #else /* _INTELx86 */
  #define _PTR_NORM(p) (p)
 #endif /* _INTELx86 */

#ifdef DEBUG
 #include <assert.h>
 #define ASSERT(e) assert(e)
_C_LIB_DECL
int _OK_Cell(_Cell *_p);
int _OK_Altab(_Altab *_p);
void _UPD_Altab(size_t _d_heap, size_t _d_alloc, size_t _d_free);
_END_C_LIB_DECL

#else /* is NDEBUG */
 #define ASSERT(e) (void)0
 #define _OK_Cell(p) (void)0
 #define _OK_Altab(p) (void)0
 #define _UPD_Altab(d_heap, d_alloc, d_free) (void)0
#endif /*DEBUG*/

_C_STD_END

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _XALLOC */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
