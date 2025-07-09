/************************************************************************
 *
 * cycle_count.h
 *
 * (c) Copyright 2004-2007 Analog Devices, Inc.  All rights reserved.
 * $Revision: 4 $
 ************************************************************************/

/*
   Generic low level interface to measure cycles counts
 */

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* cycle_count.h */
#endif

#ifndef __CYCLE_COUNT_DEFINED
#define __CYCLE_COUNT_DEFINED

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution")
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function macros")
#pragma diag(suppress:misra_rule_19_10:"ADI header macro parameters allowed for backwards compatability ")
#endif /* _MISRA_RULES */

/* Include low level support */
#include <xcycle_count.h>


typedef  _cycle_t    cycle_t;


/* The following low level macros are defined, operating on type cycle_t

      START_CYCLE_COUNT( S )    - Set S to the current value
                                  in the cycle count register(s)

      STOP_CYCLE_COUNT( X, S )  - Return in X the elapsed cycle count
                                  since start counting
                                  X =   current count
                                      - S (=start count)
                                      - measurement overhead
      PRINT_CYCLES( STRG, X )   - Print string STRG followed by X
 */


#if defined( DO_CYCLE_COUNTS )

#define  START_CYCLE_COUNT( _S )     _START_CYCLE_COUNT( _S ) __TRAILING_SC__
#define  STOP_CYCLE_COUNT( _X, _S )  _STOP_CYCLE_COUNT( _X, _S ) __TRAILING_SC__
#define  PRINT_CYCLES( _STRG, _X )   _PRINT_CYCLES( _STRG, _X )__TRAILING_SC__

#else    /* DO_CYCLE_COUNTS */
/* Replace macros with empty statements if no cycle count facility required */

#define  START_CYCLE_COUNT( _S )
#define  STOP_CYCLE_COUNT( _X, _S )
#define  PRINT_CYCLES( _STRG, _X )

#endif   /* DO_CYCLE_COUNTS */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif   /* __CYCLE_COUNT_DEFINED */
