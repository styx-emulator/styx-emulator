#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* fr2x16_typedef.h */
#endif
/************************************************************************
 *
 * fr2x16_typedef.h
 *
 * (c) Copyright 2000-2004 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Two packed fractional values in one. */

#ifndef _FR2x16_TYPEDEF_H
#define _FR2x16_TYPEDEF_H

#if defined(__ADSPBLACKFIN__)

#include <r2x16_typedef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef raw2x16   fract2x16;
typedef fract2x16	fr2x16;		/* for convenience */

#ifdef __cplusplus
}
#endif

#endif /* __ADSPBLACKFIN__ */

#endif /* _FR2x16_TYPEDEF_H */
