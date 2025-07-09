#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* r4x16_typedef.h */
#endif
/************************************************************************
 *
 * r4x16_typedef.h
 *
 * (c) Copyright 2000-2008 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Defines type for handling four 16-bit values in one. */

#ifndef _R4x16_TYPEDEF_H
#define _R4x16_TYPEDEF_H

#include <raw_typedef.h>

#if defined(__ADSPTS__)

typedef _raw64	raw4x16;

#elif defined(__ADSPBLACKFIN__)

#include <r2x16_typedef.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_6)
#pragma diag(suppress:misra_rule_5_7)
#endif /* _MISRA_RULES */

typedef struct { raw2x16 l; raw2x16 h; } raw4x16;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif

#endif /* _R4x16_TYPEDEF_H */
