/************************************************************************
 *
 * adi_types.h
 *
 * (c) Copyright 2007-2010 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/
/*   Generic Type Definitions  */

/*       Type definitions for fixed width integer types
 *       Type definitions for floating-point types
 *       Type definition for a Boolean type
 *
 *       These are type definitions that also comply with MISRA Rule 6.3.
 *       (this file is used as the basis for misra_types.h)
 */

#ifndef __ADI_TYPES_H__
#define __ADI_TYPES_H__

#ifndef __NO_BUILTIN
#pragma system_header /* adi_types.h */
#endif

#if defined(_LANGUAGE_C)

/* obtain integer types ... */
#include <stdint.h>

/* obtain boolean types ... */
#include <stdbool.h>

/* define required types that are not provided by stdint.h or stdbool.h ... */
typedef char                char_t;
typedef float               float32_t;
#if !defined(__NO_FLOAT64)
typedef long double         float64_t;
#endif

#endif /* _LANGUAGE_C */

#endif /* __ADI_TYPES_H__ */
