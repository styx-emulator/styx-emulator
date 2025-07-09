#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* video.h */
#endif
/************************************************************************
 *
 * video.h
 *
 * (c) Copyright 2002-2007 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#ifndef _VIDEO_H
#define _VIDEO_H

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_19_6)
#pragma diag(suppress:misra_rule_19_7)
#endif /* _MISRA_RULES */

#define __SPECIFIC_NAMES
#define __ENABLE_ALIGN8
#define __ENABLE_ALIGN16
#define __ENABLE_ALIGN24
#define __ENABLE_BYTEPACK
#define __ENABLE_COMPOSE_I64
#define __ENABLE_LOADBYTES
#define __ENABLE_ADDCLIP_LO
#define __ENABLE_ADDCLIP_HI
#define __ENABLE_ADDCLIP_LOR
#define __ENABLE_ADDCLIP_HIR
#define __ENABLE_AVG_I4X8
#define __ENABLE_AVG_I4X8_T
#define __ENABLE_AVG_I4X8_R
#define __ENABLE_AVG_I4X8_TR
#define __ENABLE_AVG_I2X8_LO
#define __ENABLE_AVG_I2X8_LOT
#define __ENABLE_AVG_I2X8_LOR
#define __ENABLE_AVG_I2X8_LOTR
#define __ENABLE_AVG_I2X8_HI
#define __ENABLE_AVG_I2X8_HIT
#define __ENABLE_AVG_I2X8_HIR
#define __ENABLE_AVG_I2X8_HITR
#include <builtins.h>
#undef __SPECIFIC_NAMES

#define byteunpack(_src,_ptr,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_byteunpack_r1((_src),(_ptr)); \
		int __t2 = __builtin_byteunpack_r2(__t1); \
		(_dst1) = __t1; \
		(_dst2) = __t2; \
	} while (0)

#define byteunpackr(_src,_ptr,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_byteunpackr_r1((_src),(_ptr)); \
		int __t2 = __builtin_byteunpackr_r2(__t1); \
		(_dst1) = __t1; \
		(_dst2) = __t2; \
	} while (0)

#define add_i4x8(_src1,_ptr1,_src2,_ptr2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_add_i4x8_r1((_src1),(_ptr1),(_src2),(_ptr2)); \
		int __t2 = __builtin_add_i4x8_r2(__t1); \
		(_dst1) = __t1; \
		(_dst2) = __t2; \
	} while (0)

#define add_i4x8r(_src1,_ptr1,_src2,_ptr2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_add_i4x8_r_r1((_src1),(_ptr1),(_src2),(_ptr2)); \
		int __t2 = __builtin_add_i4x8_r_r2(__t1); \
		(_dst1) = __t1; \
		(_dst2) = __t2; \
	} while (0)

#define sub_i4x8(_src1,_ptr1,_src2,_ptr2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_sub_i4x8_r1((_src1),(_ptr1),(_src2),(_ptr2)); \
		int __t2 = __builtin_sub_i4x8_r2(__t1); \
		(_dst1) = __t1; \
		(_dst2) = __t2; \
	} while (0)

#define sub_i4x8r(_src1,_ptr1,_src2,_ptr2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_sub_i4x8_r_r1((_src1),(_ptr1),(_src2),(_ptr2)); \
		int __t2 = __builtin_sub_i4x8_r_r2(__t1); \
		(_dst1) = __t1; \
		(_dst2) = __t2; \
	} while (0)

#define extract_and_add(_src1,_src2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_extract_and_add_r1((_src1),(_src2)); \
		int __t2 = __builtin_extract_and_add_r2(__t1); \
		(_dst1) = __t1; \
		(_dst2) = __t2; \
	} while (0)

#define saa(_src1,_ptr1,_src2,_ptr2,_sum1,_sum2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_saa_r1((_src1),(_ptr1),(_src2),(_ptr2),(_sum1),(_sum2)); \
		int __t2 = __builtin_saa_r2(__t1); \
		(_dst1) = __t1; \
		(_dst2) = __t2; \
	} while (0)

#define saar(_src1,_ptr1,_src2,_ptr2,_sum1,_sum2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_saa_r_r1((_src1),(_ptr1),(_src2),(_ptr2),(_sum1),(_sum2)); \
		int __t2 = __builtin_saa_r_r2(__t1); \
		(_dst1) = __t1; \
		(_dst2) = __t2; \
	} while (0)

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _VIDEO_H */
