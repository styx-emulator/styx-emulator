/************************************************************************
 *
 * btc_struct.h
 *
 * (c) Copyright 2003 Analog Devices, Inc.  All rights reserved.
 *
 *
 *  This header file contains Background Telemetry Channel (BTC)
 *  structure definitions.
 ************************************************************************/

#ifndef _BTC_STRUCT_H_
#define _BTC_STRUCT_H_

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#endif /* _MISRA_RULES */

#define NAME_LEN  32

typedef struct
{
	char name[NAME_LEN];
	long address;
	long length;
} _BTC_MAP_DATA;

#endif /* _BTC_STRUCT_H_ */
