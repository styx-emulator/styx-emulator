#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* r2x16_typedef.h */
#endif
/************************************************************************
 *
 * r2x16_typedef.h
 *
 * (c) Copyright 2000-2003 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Defines two 16-bit values packed into a single 32-bit word.  */

#ifndef _R2x16_TYPEDEF_H
#define _R2x16_TYPEDEF_H

#if defined(__ADSPBLACKFIN__) || defined(__ADSPTS__)

#include <raw_typedef.h>

typedef _raw32	raw2x16;

#endif

#endif /* _R2x16_TYPEDEF_H */
