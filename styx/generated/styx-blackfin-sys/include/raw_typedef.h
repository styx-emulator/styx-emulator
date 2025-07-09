#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* raw_typedef.h */
#endif
/************************************************************************
 *
 * raw_typedef.h
 *
 * (c) Copyright 2000-2003 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* raw type definitions */

#ifndef _RAW_TYPEDEF_H
#define _RAW_TYPEDEF_H

#if defined(__ADSPBLACKFIN__)

typedef char  _raw8;
typedef short _raw16;
typedef int   _raw32;

#elif defined(__ADSPTS__)

/* All TS types are at least 32 bits, but we pretend with these. */
typedef int    _raw32;
typedef _raw32 _raw8;
typedef _raw32 _raw16;

#endif

#endif /* _RAW_TYPEDEF_H */
