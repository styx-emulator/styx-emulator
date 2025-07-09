/************************************************************************
 *
 * btc.h
 *
 * (c) Copyright 2003 Analog Devices, Inc.  All rights reserved.
 *
 *
 *  This header file contains Background Telemetry Channel (BTC)
 *  function definitions.
 ************************************************************************/

#ifndef _BTC_H_
#define _BTC_H_

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution text")
#pragma diag(suppress:misra_rule_19_7:"ADI header allows function macros")
#pragma diag(suppress:misra_rule_19_10:"ADI header parameter of function macros not required to be parenthesised")
#endif /* _MISRA_RULES */


	#ifdef __ECC__		/* C or C++ */

		#include "btc_struct.h"

		#define BTC_MAP_BEGIN			_BTC_MAP_DATA  _btc_map[] = {
		#define BTC_MAP_ENTRY(N,A,L)	{ N, (A), (L) },
		#define BTC_MAP_END				}; \
										int _btc_nNumBtcMapEntries = sizeof(_btc_map)/sizeof(_BTC_MAP_DATA);

		#define BTC_CHANNEL_ADDR(I)		_btc_map[(I)].address
		#define BTC_CHANNEL_LEN(I)		_btc_map[(I)].length

		extern "C" void btc_init(void);
		extern "C" void btc_poll(void);
		extern "C" void btc_write_array(unsigned short chan, unsigned int* address, unsigned int size);
		extern "C" void btc_write_value(unsigned short chan, unsigned int* address, unsigned int size);

	#else				/* assembly */

		.import "btc_struct.h";

		#define BTC_MAP_BEGIN			.align 4; .struct _BTC_MAP_DATA __btc_map[] = {
		#define BTC_MAP_ENTRY(N,A,L)    { N, (A), (L) },
		#define BTC_MAP_END				}; \
										.var __btc_nNumBtcMapEntries = sizeof(__btc_map)/sizeof(_BTC_MAP_DATA);

		/* dst MUST be either a P register or a DAG I register */
		#define BTC_CHANNEL_ADDR(index, dst)	\
				[--sp] = r0;			\
				dst.h  = __btc_map + (index*sizeof(_BTC_MAP_DATA)) + offsetof(_BTC_MAP_DATA, address);	\
				dst.l  = __btc_map + (index*sizeof(_BTC_MAP_DATA)) + offsetof(_BTC_MAP_DATA, address);	\
				r0     = [dst];			\
		 		dst    = r0;			\
		 		r0     = [sp++];		\
		 		nop;					\
		 		nop

		 /* dst CANNOT be R0 or P0 */
		 #define BTC_CHANNEL_LEN(index, dst)	\
		 		[--sp] = r0;			\
		 		[--sp] = p0;			\
		 		p0.h   = __btc_map + (index*sizeof(_BTC_MAP_DATA)) + offsetof(_BTC_MAP_DATA, length);	\
				p0.l   = __btc_map + (index*sizeof(_BTC_MAP_DATA)) + offsetof(_BTC_MAP_DATA, length);	\
				r0     = [p0];			\
		 		dst    = r0;			\
		 		p0     = [sp++];		\
		 		r0     = [sp++];		\
		 		nop

		/* global functions */
		.extern _btc_init;
		.extern _btc_poll;
		.extern	_btc_write_array;
		.extern _btc_write_value;
		.extern _BTC_CHANNEL_ADDR;
		.extern _BTC_CHANNEL_LEN;

		/* global variables */
		.extern	__btc_nNumBtcMapEntries;
		.extern __btc_map;

	#endif	/* end #ifdef __ECC__ */
#endif  	/* end #ifndef _BTC_H_ */
