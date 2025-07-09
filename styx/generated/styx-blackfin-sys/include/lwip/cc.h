//
// cc.h
//
// Contains compiler-specific definitions and typedefs for lwIP on ADSP-BF535.
// (Actually, only the PACK_* definitions are compiler-specific, all the rest
//  should be in sys_arch.h, I think.)
//
#ifndef _ARCH_CC_H_
#define _ARCH_CC_H_

// lwIP requires memset
#include <string.h>

// Define platform endianness
#undef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN

// Define basic types used in lwIP
typedef unsigned   char    u8_t;
typedef signed     char    s8_t;
typedef unsigned   short   u16_t;
typedef signed     short   s16_t;
typedef unsigned   long    u32_t;
typedef signed     long    s32_t;

// addresses are 32-bits long
typedef u32_t mem_ptr_t;

// Compiler hints for packing structures
// (Note: this packs the struct layouts but doesn't modify compiler
//        access to the members - we're on our own for avoiding
//        alignment exceptions.)
#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT
#define PACK_STRUCT_BEGIN _Pragma("pack(1)")
#define PACK_STRUCT_END   _Pragma("pack()")

// prototypes for printf(), fflush() and abort()
#include <stdio.h>
#include <stdlib.h>

// supply a version of (non-ANSI) isascii()
// #define isascii(i) ((int)(i) > 0 && (int)(i) < 128)

// Plaform specific diagnostic output
#ifdef LWIP_DEBUG
#define LWIP_PLATFORM_DIAG(x)	\
  do {printf x;} while(0)
#else
#define LWIP_PLATFORM_DIAG(x)
#endif

#ifndef LWIP_NOASSERT
#define LWIP_PLATFORM_ASSERT(x) \
  do {printf("Assertion \"%s\" failed at line %d in %s\n", \
             x, __LINE__, __FILE__); fflush(NULL); abort();} while(0)
#else
#define LWIP_PLATFORM_ASSERT(x)
#endif

#endif // _ARCH_CC_H_
