/************************************************************************
 *
 * services_types.h
 *
 * Description:
 *      Integer typedefs in use in existing code such as System Services,
 *      Boot ROM kernels and some examples / applications.
 *
 * (c) Copyright 2008 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#ifndef _SERVICES_TYPES_H
#define _SERVICES_TYPES_H

#if defined(__ECC__)
#pragma system_header
#endif

/* integer typedefs */

#if defined(_LANGUAGE_C)

typedef unsigned short u16;
typedef unsigned long u32;
typedef unsigned long long u64;
typedef unsigned char u8;
typedef short s16;
typedef long s32;
typedef long long s64;
typedef signed char s8;

#endif

#endif /* _SERVICES_TYPES_H */
