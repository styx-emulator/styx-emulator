/************************************************************************
 *
 * cycles.h
 *
 * (c) Copyright 2004-2007 Analog Devices, Inc.  All rights reserved.
 * $Revision: 4 $
 ************************************************************************/

/*
   Generic top level interface to measure cycles counts
 */

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* cycles.h */
#endif


#ifndef __CYCLES_DEFINED
#define __CYCLES_DEFINED

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_2_4)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_1)
#pragma diag(suppress:misra_rule_8_5)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_19_10)
#endif /* _MISRA_RULES */

/* Include low level support */
#include <xcycle_count.h>

typedef struct
{
#if defined(__ADSPBLACKFIN__)
  _cycle_t  _start_cycles;
#endif
  _cycle_t  _cycles, _max_cycles, _min_cycles, _total_cycles;
  long      _num_calls;
} cycle_stats_t;



#if defined( DO_CYCLE_COUNTS )

  /* Cycle count macros, operating on type cycle_stats_t

        CYCLES_INIT  - Zeros statistics

        CYCLES_START - Starts measuring cycles

        CYCLES_STOP  - Stops measuring cycles and accumulates statistics

        CYCLES_RESET - Re-zeros statistics

        CYCLES_PRINT - Print summary of the accumulated statistics
  */

#define CYCLES_INIT( _X )  _cycles_init( &(_X) ) __TRAILING_SC__

#if defined(__ADSPBLACKFIN__)
#define CYCLES_START( _X ) _START_CYCLE_COUNT( _X._start_cycles ) __TRAILING_SC__
#else
#define CYCLES_START( _X ) _START_CYCLE_COUNT( _X._cycles ) __TRAILING_SC__
#endif

#if defined(__ADSPBLACKFIN__)
#define CYCLES_STOP( _X )  do {                                \
                             _STOP_CYCLE_COUNT( _X._cycles, _X._start_cycles );\
                             if (_X._cycles > _X._max_cycles)  \
                                 _X._max_cycles = _X._cycles;  \
                             if (_X._cycles < _X._min_cycles)  \
                                 _X._min_cycles = _X._cycles;  \
                             _X._total_cycles += _X._cycles;   \
                             _X._num_calls++;                  \
                           } while(0) __TRAILING_SC__
#else
#define CYCLES_STOP( _X )  do {                                \
                             _STOP_CYCLE_COUNT( _X._cycles, _X._cycles ); \
                             if (_X._cycles > _X._max_cycles)  \
                                 _X._max_cycles = _X._cycles;  \
                             if (_X._cycles < _X._min_cycles)  \
                                 _X._min_cycles = _X._cycles;  \
                             _X._total_cycles += _X._cycles;   \
                             _X._num_calls++;                  \
                           } while(0) __TRAILING_SC__
#endif

#define CYCLES_RESET( _X ) do {                                \
                             _X._max_cycles = 0;               \
                             _X._min_cycles = _CYCLES_T_MAX;   \
                             _X._total_cycles = 0;             \
                             _X._num_calls = 0;                \
                           } while(0) __TRAILING_SC__

#define CYCLES_PRINT( _X ) do {                                \
                             if (_X._num_calls > 1) {          \
                                 _PRINT_CYCLES("\t AVG   : ",  \
                                           (_X._total_cycles / _X._num_calls)); \
                                 _PRINT_CYCLES("\t MIN   : ", _X._min_cycles);  \
                                 _PRINT_CYCLES("\t MAX   : ", _X._max_cycles);  \
                                 _PRINT_CYCLES("\t CALLS : ",  \
                                           ((_cycle_t) _X._num_calls)); \
                             } else { \
                                 _PRINT_CYCLES("\t CYCLES : ", _X._total_cycles);\
                             }        \
                           } while(0) __TRAILING_SC__

#else   /* CYCLE_COUNTS */
/* Replace macros with empty statements if no cycle count facility required */

#define CYCLES_INIT( _X )
#define CYCLES_START( _X )
#define CYCLES_STOP( _X )
#define CYCLES_RESET( _X )
#define CYCLES_PRINT( _X )

#endif  /* CYCLE_COUNTS */


#pragma inline
#pragma always_inline
static  void _cycles_init(cycle_stats_t *_data)
{
  _data->_max_cycles = (unsigned int)0;
  _data->_min_cycles = _CYCLES_T_MAX;

  _data->_total_cycles = (unsigned int)0;

  _data->_num_calls = 0;

#if defined(__ADSPBLACKFIN__)
  _data->_start_cycles = (unsigned int)0;
  _data->_cycles = (unsigned int)0;
#endif
}

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __CYCLES_DEFINED */
