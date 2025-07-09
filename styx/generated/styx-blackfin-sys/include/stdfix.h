/*
** stdfix.h
**
** Copyright (c) 2008 Analog Devices, Inc.
**
*/

#ifndef _STDFIX
#define _STDFIX

#if defined(__cplusplus)
#error stdfix.h and the native fixed-point types _Fract and _Accum cannot be used in C++.
#endif

#if defined(_MISRA_RULES)
#error stdfix.h is incompatible with MISRA
#endif

#pragma system_header

#ifdef _MISRA_RULES
/* use of stdfix.h is incompatible with MISRA as MISRA does not allow the
** _Fract and _Accum extensions. However if it were to permit these keywords,
** we would need to also suppress the following rules to make this header
** MISRA-compliant.
*/
#pragma diag(push)
#pragma diag(suppress:misra_rule_8_5)
#pragma diag(suppress:misra_rule_11_4)
#pragma diag(suppress:misra_rule_19_4)
#pragma diag(suppress:misra_rule_19_7)
#pragma diag(suppress:misra_rule_19_15)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_5_6)
#endif

#define fract _Fract
#define accum _Accum
#define sat _Sat

#define SFRACT_FBIT      15
#define SFRACT_MIN       (-0.5HR-0.5HR)
#define SFRACT_MAX       0X1.FFFCP-1HR
#define SFRACT_EPSILON   0X1P-15HR
#define USFRACT_FBIT     16
#define USFRACT_MAX      0X1.FFFEP-1UHR
#define USFRACT_EPSILON  0X1P-16UHR
#define FRACT_FBIT       15
#define FRACT_MIN        (-0.5R-0.5R)
#define FRACT_MAX        0X1.FFFCP-1R
#define FRACT_EPSILON    0X1P-15R
#define UFRACT_FBIT      16
#define UFRACT_MAX       0X1.FFFEP-1UR
#define UFRACT_EPSILON   0X1P-16UR
#define LFRACT_FBIT      31
#define LFRACT_MIN       (-0.5LR-0.5LR)
#define LFRACT_MAX       0X1.FFFFFFFCP-1LR
#define LFRACT_EPSILON   0X1P-31LR
#define ULFRACT_FBIT     32
#define ULFRACT_MAX      0X1.FFFFFFFEP-1ULR
#define ULFRACT_EPSILON  0X1P-32ULR
#define SACCUM_FBIT      31
#define SACCUM_IBIT      8
#define SACCUM_MIN       (-128.0HK-128.0HK)
#define SACCUM_MAX       (0X1.FFFFFFFCP-1HK + 255.0HK)
#define SACCUM_EPSILON   0X1P-31HK
#define USACCUM_FBIT     32
#define USACCUM_IBIT     8
#define USACCUM_MAX      (0X1.FFFFFFFEP-1UHK + 255.0UHK)
#define USACCUM_EPSILON  0X1P-32UK
#define ACCUM_FBIT       31
#define ACCUM_IBIT       8
#define ACCUM_MIN        (-128.0K-128.0K)
#define ACCUM_MAX        (0X1.FFFFFFFCP-1K + 255.0K)
#define ACCUM_EPSILON    0X1P-31K
#define UACCUM_FBIT      32
#define UACCUM_IBIT      8
#define UACCUM_MAX       (0X1.FFFFFFFEP-1UK + 255.0UK)
#define UACCUM_EPSILON   0X1P-32UK
#define LACCUM_FBIT      31
#define LACCUM_IBIT      8
#define LACCUM_MIN       (-128.0LK-128.0LK)
#define LACCUM_MAX       (0X1.FFFFFFFCP-1LK + 255.0LK)
#define LACCUM_EPSILON   0X1P-31LK
#define ULACCUM_FBIT     32
#define ULACCUM_IBIT     8
#define ULACCUM_MAX      (0X1.FFFFFFFEP-1ULK + 255.0ULK)
#define ULACCUM_EPSILON  0X1P-32ULK

/* typedefs for integer types big enough to contain the fixed-point types.
*/
typedef short int_hr_t;
typedef short int_r_t;
typedef int int_lr_t;
typedef long long int_hk_t;
typedef long long int_k_t;
typedef long long int_lk_t;
typedef unsigned short uint_uhr_t;
typedef unsigned short uint_ur_t;
typedef unsigned int uint_ulr_t;
typedef unsigned long long uint_uhk_t;
typedef unsigned long long uint_uk_t;
typedef unsigned long long uint_ulk_t;

/* convert a fixed-point value to integer by multiplying by
** 2^(#fractional bits).
*/

#pragma const
static int_hr_t bitshr(short fract _f);
#pragma inline
#pragma always_inline
static int_hr_t bitshr(short fract _f) {
  return *((int_hr_t *)&_f);
}

#pragma const
static int_r_t bitsr(fract _f);
#pragma inline
#pragma always_inline
static int_r_t bitsr(fract _f) {
  return *((int_r_t *)&_f);
}

#pragma const
static int_lr_t bitslr(long fract _f);
#pragma inline
#pragma always_inline
static int_lr_t bitslr(long fract _f) {
  return *((int_lr_t *)&_f);
}

#pragma const
static uint_uhr_t bitsuhr(unsigned short fract _f);
#pragma inline
#pragma always_inline
static uint_uhr_t bitsuhr(unsigned short fract _f) {
  return *((uint_uhr_t *)&_f);
}

#pragma const
static uint_ur_t bitsur(unsigned fract _f);
#pragma inline
#pragma always_inline
static uint_ur_t bitsur(unsigned fract _f) {
  return *((uint_ur_t *)&_f);
}

#pragma const
static uint_ulr_t bitsulr(unsigned long fract _f);
#pragma inline
#pragma always_inline
static uint_ulr_t bitsulr(unsigned long fract _f) {
  return *((uint_ulr_t *)&_f);
}

#pragma const
static int_hk_t bitshk(short accum _a);
#pragma inline
#pragma always_inline
static int_hk_t bitshk(short accum _a) {
  return __builtin_sext_k(_a);
}

#pragma const
static int_k_t bitsk(accum _a);
#pragma inline
#pragma always_inline
static int_k_t bitsk(accum _a) {
  return __builtin_sext_k(_a);

}

#pragma const
static int_lk_t bitslk(long accum _a);
#pragma inline
#pragma always_inline
static int_lk_t bitslk(long accum _a) {
  return __builtin_sext_k(_a);
}

#pragma const
static uint_uhk_t bitsuhk(unsigned short accum _a);
#pragma inline
#pragma always_inline
static uint_uhk_t bitsuhk(unsigned short accum _a) {
  return __builtin_zext_k(_a);
}

#pragma const
static uint_uk_t bitsuk(unsigned accum _a);
#pragma inline
#pragma always_inline
static uint_uk_t bitsuk(unsigned accum _a) {
  return __builtin_zext_k(_a);
}

#pragma const
static uint_ulk_t bitsulk(unsigned long accum _a);
#pragma inline
#pragma always_inline
static uint_ulk_t bitsulk(unsigned long accum _a) {
  return __builtin_zext_k(_a);
}

/* convert an integer to a fixed-point number by division by
** 2^(#fractional bits).
*/

/* for the fract versions, the size of the int container is the same
** as the size of the fract, so no saturation is possible.
*/

#pragma const
static short fract hrbits(int_hr_t _n);
#pragma inline
#pragma always_inline
static short fract hrbits(int_hr_t _n) {
  return *((short fract *)&_n);
}

#pragma const
static fract rbits(int_r_t _n);
#pragma inline
#pragma always_inline
static fract rbits(int_r_t _n) {
  return *((fract *)&_n);
}

#pragma const
static long fract lrbits(int_lr_t _n);
#pragma inline
#pragma always_inline
static long fract lrbits(int_lr_t _n) {
  return *((long fract *)&_n);
}

#pragma const
static unsigned short fract uhrbits(uint_uhr_t _n);
#pragma inline
#pragma always_inline
static unsigned short fract uhrbits(uint_uhr_t _n) {
  return *((unsigned short fract *)&_n);
}

#pragma const
static unsigned fract urbits(uint_ur_t _n);
#pragma inline
#pragma always_inline
static unsigned fract urbits(uint_ur_t _n) {
  return *((unsigned fract *)&_n);
}

#pragma const
static unsigned long fract ulrbits(uint_ulr_t _n);
#pragma inline
#pragma always_inline
static unsigned long fract ulrbits(uint_ulr_t _n) {
  return *((unsigned long fract *)&_n);
}

/* for the accum versions, the int container is bigger than the accum,
** so saturation is possible.
*/

#pragma const
static short accum hkbits(int_hk_t _n);
#pragma inline
#pragma always_inline
static short accum hkbits(int_hk_t _n) {
  return __builtin_sat_llk(_n);
}

#pragma const
static accum kbits(int_k_t _n);
#pragma inline
#pragma always_inline
static accum kbits(int_k_t _n) {
  return __builtin_sat_llk(_n);
}

#pragma const
static long accum lkbits(int_lk_t _n);
#pragma inline
#pragma always_inline
static long accum lkbits(int_lk_t _n) {
  return __builtin_sat_llk(_n);
}

#pragma const
static unsigned short accum uhkbits(uint_uhk_t _n);
#pragma inline
#pragma always_inline
static unsigned short accum uhkbits(uint_uhk_t _n) {
  return __builtin_sat_ulluk(_n);
}

#pragma const
static unsigned accum ukbits(uint_uk_t _n);
#pragma inline
#pragma always_inline
static unsigned accum ukbits(uint_uk_t _n) {
  return __builtin_sat_ulluk(_n);
}

#pragma const
static unsigned long accum ulkbits(uint_ulk_t _n);
#pragma inline
#pragma always_inline
static unsigned long accum ulkbits(uint_ulk_t _n) {
  return __builtin_sat_ulluk(_n);
}

/* multiply integer by fixed-point type to produce integer.
*/

#pragma const
static int mulir(int _a, fract _b);
#pragma inline
#pragma always_inline
static int mulir(int _a, fract _b) {
  return __builtin_mulir(_a, _b);
}

#pragma const
static long int mulilr(long int _a, long fract _b);
#pragma inline
#pragma always_inline
static long int mulilr(long int _a, long fract _b) {
  return __builtin_mulilr(_a, _b);
}

#pragma const
static unsigned int muliur(unsigned int _a, unsigned fract _b);
#pragma inline
#pragma always_inline
static unsigned int muliur(unsigned int _a, unsigned fract _b) {
  return __builtin_muliur(_a, _b);
}

#pragma const
static unsigned long int muliulr(unsigned long int _a,
                                 unsigned long fract _b);
#pragma inline
#pragma always_inline
static unsigned long int muliulr(unsigned long int _a,
                                 unsigned long fract _b) {
  return __builtin_muliulr(_a, _b);
}

#pragma const
#pragma regs_clobbered "A0,A1,R0-R3,P0-P1"
int mulik(int _a, accum _b);

#pragma const
static long int mulilk(long int _a, long accum _b);
#pragma inline
#pragma always_inline
static long int mulilk(long int _a, long accum _b) {
  return (long int)mulik((int)_a, (accum)_b);
}

#pragma const
#pragma regs_clobbered "A0,A1,R0-R3,P0-P1"
unsigned int muliuk(unsigned int _a, unsigned accum _b);

#pragma const
static unsigned long int muliulk(unsigned long int _a,
                                 unsigned long accum _b);
#pragma inline
#pragma always_inline
static unsigned long int muliulk(unsigned long int _a,
                                 unsigned long accum _b) {
  return (unsigned long int)muliuk((unsigned int)_a, (unsigned accum)_b);
}

/* divide integer by fixed-point type to produce integer
*/

#pragma const
int divik(int _dividend, accum _divisor);

#pragma const
static long int divilk(long int _dividend, long accum _divisor);
#pragma inline
#pragma always_inline
static long int divilk(long int _dividend, long accum _divisor) {
  return (long int)divik((int)_dividend, (accum)_divisor);
}

#pragma const
unsigned int diviuk(unsigned int _dividend, unsigned accum _divisor);

#pragma const
static unsigned long int diviulk(unsigned long int _dividend,
                                 unsigned long accum _divisor);
#pragma inline
#pragma always_inline
static unsigned long int diviulk(unsigned long int _dividend,
                                 unsigned long accum _divisor) {
  return (unsigned long int)diviuk((unsigned int)_dividend,
                                   (unsigned accum)_divisor);
}

#pragma const
static int divir(int _dividend, fract _divisor);
#pragma inline
#pragma always_inline
static int divir(int _dividend, fract _divisor) {
  return divik(_dividend, (accum)_divisor);
}

#pragma const
static long int divilr(long int _dividend, long fract _divisor);
#pragma inline
#pragma always_inline
static long int divilr(long int _dividend, long fract _divisor) {
  return divik((int)_dividend, (accum)_divisor);
}

#pragma const
static unsigned int diviur(unsigned int _dividend, unsigned fract _divisor);
#pragma inline
#pragma always_inline
static unsigned int diviur(unsigned int _dividend, unsigned fract _divisor) {
  return diviuk(_dividend, (unsigned accum)_divisor);
}

#pragma const
static unsigned long int diviulr(unsigned long int _dividend,
                                 unsigned long fract _divisor);
#pragma inline
#pragma always_inline
static unsigned long int diviulr(unsigned long int _dividend,
                                 unsigned long fract _divisor) {
  return diviuk(_dividend, (unsigned accum)_divisor);
}

/* divide integer by integer to produce fixed-point type
*/

#pragma const
fract rdivi(int _dividend, int _divisor);

#ifdef __SYSCALL_INFO__
%syscall
%notes "Divide 32-bit integer by 32-bit integer to give 1.31 fractional result."
#endif
#pragma const
#pragma regs_clobbered "R0-R3,P0-P2,LC0,LT0,LB0,CCset"
#pragma linkage_name ___lrdivi
long fract lrdivi(long int _dividend, long int _divisor);

#pragma const
unsigned fract urdivi(unsigned int _dividend, unsigned int _divisor);

#ifdef __SYSCALL_INFO__
%syscall
%notes "Divide 32-bit unsigned integer by 32-bit unsigned integer to give 0.32 fractional result."
#endif
#pragma const
#pragma regs_clobbered "R0-R3,P0-P2,LC0,LT0,LB0,CCset"
#pragma linkage_name ___ulrdivi
unsigned long fract ulrdivi(unsigned long int _dividend,
                            unsigned long int _divisor);

#pragma const
static accum kdivi(int _dividend, int _divisor);
#pragma inline
#pragma always_inline
static accum kdivi(int _dividend, int _divisor) {
  /* exploit fact that long int and long fract are both 32-bits,
  ** so that we can pretend that the long ints are just
  ** long fracts, and extend them to accum.
  */
  accum dividend = (accum)lrbits(_dividend);
  accum divisor = (accum)lrbits(_divisor);
  return __builtin_kdivn(dividend, divisor);
}

#pragma const
static long accum lkdivi(long int _dividend, long int _divisor);
#pragma inline
#pragma always_inline
static long accum lkdivi(long int _dividend, long int _divisor) {
  /* exploit fact that long int and long fract are both 32-bits,
  ** so that we can pretend that the long ints are just
  ** long fracts, and extend them to accum.
  */
  long accum dividend = (long accum)lrbits(_dividend);
  long accum divisor = (long accum)lrbits(_divisor);
  return __builtin_kdivn(dividend, divisor);
}

#pragma const
static unsigned accum ukdivi(unsigned int _dividend, unsigned int _divisor);
#pragma inline
#pragma always_inline
static unsigned accum ukdivi(unsigned int _dividend, unsigned int _divisor) {
  /* exploit fact that unsigned long int and unsigned long fract are both
  ** 32-bits, so that we can pretend that the unsigned long ints are just
  ** unsigned long fracts, and extend them to accum.
  */
  unsigned accum dividend = (unsigned accum)ulrbits(_dividend);
  unsigned accum divisor = (unsigned accum)ulrbits(_divisor);
  return __builtin_ukdivn(dividend, divisor);
}

#pragma const
static unsigned long accum ulkdivi(unsigned long int _dividend,
                                   unsigned long int _divisor);
#pragma inline
#pragma always_inline
static unsigned long accum ulkdivi(unsigned long int _dividend,
                                   unsigned long int _divisor) {
  /* exploit fact that unsigned long int and unsigned long fract are both
  ** 32-bits, so that we can pretend that the unsigned long ints are just
  ** unsigned long fracts, and extend them to accum.
  */
  unsigned long accum dividend = (unsigned long accum)ulrbits(_dividend);
  unsigned long accum divisor = (unsigned long accum)ulrbits(_divisor);
  return __builtin_ukdivn(dividend, divisor);
}

/* divide fixed-point by fixed-point type to produce integer
*/

#pragma const
static int idivr(fract _dividend, fract _divisor);
#pragma inline
#pragma always_inline
static int idivr(fract _dividend, fract _divisor) {
  int_r_t i_dividend = bitsr(_dividend);
  int_r_t i_divisor = bitsr(_divisor);
  return (int)i_dividend / (int)i_divisor;
}

#pragma const
static long int idivlr(long fract _dividend, long fract _divisor);
#pragma inline
#pragma always_inline
static long int idivlr(long fract _dividend, long fract _divisor) {
  int_lr_t i_dividend = bitslr(_dividend);
  int_lr_t i_divisor = bitslr(_divisor);
  return (long int)i_dividend / (long int)i_divisor;
}

#pragma const
static int idivk(accum _dividend, accum _divisor);
#pragma inline
#pragma always_inline
static int idivk(accum _dividend, accum _divisor) {
  int_k_t i_dividend = bitsk(_dividend);
  int_k_t i_divisor = bitsk(_divisor);
  return (int)(i_dividend / i_divisor);
}

#pragma const
static long int idivlk(long accum _dividend, long accum _divisor);
#pragma inline
#pragma always_inline
static long int idivlk(long accum _dividend, long accum _divisor) {
  int_lk_t i_dividend = bitslk(_dividend);
  int_lk_t i_divisor = bitslk(_divisor);
  return (long int)(i_dividend / i_divisor);
}

#pragma const
static unsigned int idivur(unsigned fract _dividend, unsigned fract _divisor);
#pragma inline
#pragma always_inline
static unsigned int idivur(unsigned fract _dividend, unsigned fract _divisor) {
  uint_ur_t i_dividend = bitsur(_dividend);
  uint_ur_t i_divisor = bitsur(_divisor);
  return (unsigned int)i_dividend / (unsigned int)i_divisor;
}

#pragma const
static unsigned long int idivulr(unsigned long fract _dividend,
                                 unsigned long fract _divisor);
#pragma inline
#pragma always_inline
static unsigned long int idivulr(unsigned long fract _dividend,
                                 unsigned long fract _divisor) {
  uint_ulr_t i_dividend = bitsulr(_dividend);
  uint_ulr_t i_divisor = bitsulr(_divisor);
  return (unsigned long int)i_dividend / (unsigned long int)i_divisor;
}

#pragma const
static unsigned int idivuk(unsigned accum _dividend, unsigned accum _divisor);
#pragma inline
#pragma always_inline
static unsigned int idivuk(unsigned accum _dividend, unsigned accum _divisor) {
  uint_uk_t i_dividend = bitsuk(_dividend);
  uint_uk_t i_divisor = bitsuk(_divisor);
  return (unsigned int)(i_dividend / i_divisor);
}

#pragma const
static unsigned long int idivulk(unsigned long accum _dividend,
                                 unsigned long accum _divisor);
#pragma inline
#pragma always_inline
static unsigned long int idivulk(unsigned long accum _dividend,
                                 unsigned long accum _divisor) {
  uint_ulk_t i_dividend = bitsulk(_dividend);
  uint_ulk_t i_divisor = bitsulk(_divisor);
  return (unsigned long int)(i_dividend / i_divisor);
}

/* compute absolute value of fixed-point value.
*/

#pragma const
static short fract abshr(short fract _f);
#pragma inline
#pragma always_inline
static short fract abshr(short fract _f) {
  return __builtin_absr(_f);
}

#pragma const
static fract absr(fract _f);
#pragma inline
#pragma always_inline
static fract absr(fract _f) {
  return __builtin_absr(_f);
}

#pragma const
static long fract abslr(long fract _f);
#pragma inline
#pragma always_inline
static long fract abslr(long fract _f) {
  return __builtin_abslr(_f);
}

#pragma const
static short accum abshk(short accum _a);
#pragma inline
#pragma always_inline
static short accum abshk(short accum _a) {
  return __builtin_absk(_a);
}

#pragma const
static accum absk(accum _a);
#pragma inline
#pragma always_inline
static accum absk(accum _a) {
  return __builtin_absk(_a);
}

#pragma const
static long accum abslk(long accum _a);
#pragma inline
#pragma always_inline
static long accum abslk(long accum _a) {
  return __builtin_absk(_a);
}

#if defined(_C99) /* type-generic macros only available in -c99 mode */

#if !defined(__DISABLE_ABSFX)

#define absfx(x) \
  __genericfx((x), \
              abshr, 0, \
              absr, 0, \
              abslr, 0, \
              abshk, 0, \
              absk, 0, \
              abslk, 0)((x))

#endif /* __DISABLE_ABSFX */

#endif /* _C99 */

/* round fixed-point number to specified precision
*/

#pragma const
static short fract roundhr(short fract _f, int _num_fract_bits);
#pragma inline
#pragma always_inline
static short fract roundhr(short fract _f, int _num_fract_bits) {
  return __builtin_rndr(_f, SFRACT_FBIT - _num_fract_bits);
}

#if !defined(__DISABLE_ROUNDR)

#pragma const
static fract roundr(fract _f, int _num_fract_bits);
#pragma inline
#pragma always_inline
static fract roundr(fract _f, int _num_fract_bits) {
  return __builtin_rndr(_f, FRACT_FBIT - _num_fract_bits);
}

#else

#pragma const
#pragma linkage_name ___roundr
#pragma regs_clobbered "R0-R3,P0-P2,CCset"
fract roundr(fract _f, int _num_fract_bits);

#endif /* __DISABLE_ROUNDR */

#if !defined(__DISABLE_ROUNDLR)

#pragma const
static long fract roundlr(long fract _f, int _num_fract_bits);
#pragma inline
#pragma always_inline
static long fract roundlr(long fract _f, int _num_fract_bits) {
  return __builtin_rndlr(_f, LFRACT_FBIT - _num_fract_bits);
}

#else

#ifdef __SYSCALL_INFO__
%syscall
%notes "Round a 1.31 fractional number to a specified precision."
#endif
#pragma const
#pragma linkage_name ___roundlr
#pragma regs_clobbered "R0-R3,P0-P2,CCset"
long fract roundlr(long fract _f, int _num_fract_bits);

#endif /* __DISABLE_ROUNDLR */

#pragma const
static short accum roundhk(short accum _a, int _num_fract_bits);
#pragma inline
#pragma always_inline
static short accum roundhk(short accum _a, int _num_fract_bits) {
  return __builtin_rndk(_a, SACCUM_FBIT - _num_fract_bits);
}

#if !defined(__DISABLE_ROUNDK)

#pragma const
static accum roundk(accum _a, int _num_fract_bits);
#pragma inline
#pragma always_inline
static accum roundk(accum _a, int _num_fract_bits) {
  return __builtin_rndk(_a, ACCUM_FBIT - _num_fract_bits);
}

#else

#ifdef __SYSCALL_INFO__
%syscall
%notes "Round a 40-bit accum to a specified precision."
#endif
#pragma const
#pragma linkage_name ___roundk
#pragma regs_clobbered "R0-R3,P0-P2,CCset"
accum roundk(accum _a, int _num_fract_bits);

#endif /* __DISABLE_ROUNDK */

#pragma const
static long accum roundlk(long accum _a, int _num_fract_bits);
#pragma inline
#pragma always_inline
static long accum roundlk(long accum _a, int _num_fract_bits) {
  return __builtin_rndk(_a, LACCUM_FBIT - _num_fract_bits);
}

#pragma const
static unsigned short fract rounduhr(unsigned short fract _f,
                                     int _num_fract_bits);
#pragma inline
#pragma always_inline
static unsigned short fract rounduhr(unsigned short fract _f,
                                     int _num_fract_bits) {
  return __builtin_rndur(_f, USFRACT_FBIT - _num_fract_bits);
}

#if !defined(__DISABLE_ROUNDUR)

#pragma const
static unsigned fract roundur(unsigned fract _f, int _num_fract_bits);
#pragma inline
#pragma always_inline
static unsigned fract roundur(unsigned fract _f, int _num_fract_bits) {
  return __builtin_rndur(_f, UFRACT_FBIT - _num_fract_bits);
}

#else

#pragma const
#pragma linkage_name ___roundur
#pragma regs_clobbered "R0-R3,P0-P2,CCset"
unsigned fract roundur(unsigned fract _f, int _num_fract_bits);

#endif /* __DISABLE_ROUNDUR */

#if !defined(__DISABLE_ROUNDULR)

#pragma const
static unsigned long fract roundulr(unsigned long fract _f,
                                    int _num_fract_bits);
#pragma inline
#pragma always_inline
static unsigned long fract roundulr(unsigned long fract _f,
                                    int _num_fract_bits) {
  return __builtin_rndulr(_f, ULFRACT_FBIT - _num_fract_bits);
}

#else

#ifdef __SYSCALL_INFO__
%syscall
%notes "Round a 0.32 fractional number to a specified precision."
#endif
#pragma const
#pragma linkage_name ___roundulr
#pragma regs_clobbered "R0-R3,P0-P2,CCset"
unsigned long fract roundulr(unsigned long fract _f, int _num_fract_bits);

#endif /* __DISABLE_ROUNDULR */

#pragma const
static unsigned short accum rounduhk(unsigned short accum _a,
                                     int _num_fract_bits);
#pragma inline
#pragma always_inline
static unsigned short accum rounduhk(unsigned short accum _a,
                                     int _num_fract_bits) {
  return __builtin_rnduk(_a, USACCUM_FBIT - _num_fract_bits);
}

#if !defined(__DISABLE_ROUNDUK)

#pragma const
static unsigned accum rounduk(unsigned accum _a, int _num_fract_bits);
#pragma inline
#pragma always_inline
static unsigned accum rounduk(unsigned accum _a, int _num_fract_bits) {
  return __builtin_rnduk(_a, UACCUM_FBIT - _num_fract_bits);
}

#else

#ifdef __SYSCALL_INFO__
%syscall
%notes "Round a 40-bit unsigned accum to a specified precision."
#endif
#pragma const
#pragma linkage_name ___rounduk
#pragma regs_clobbered "R0-R3,P0-P2,CCset"
unsigned accum rounduk(unsigned accum _a, int _num_fract_bits);

#endif /* __DISABLE_ROUNDUK */

#pragma const
static unsigned long accum roundulk(unsigned long accum _a,
                                    int _num_fract_bits);
#pragma inline
#pragma always_inline
static unsigned long accum roundulk(unsigned long accum _a,
                                    int _num_fract_bits) {
  return __builtin_rnduk(_a, ULACCUM_FBIT - _num_fract_bits);
}

#if defined(_C99) /* type-generic macros only available in -c99 mode */

#if !defined(__DISABLE_ROUNDFX)

#define roundfx(x, y) \
  __genericfx((x), \
              roundhr, rounduhr, \
              roundr, roundur, \
              roundlr, roundulr, \
              roundhk, rounduhk, \
              roundk, rounduk, \
              roundlk, roundulk)((x), (y))

#endif /* __DISABLE_ROUNDFX */

#endif /* _C99 */

/* count the leading bits in a signed fixed-point value that are the same as
** the sign-bit.
*/

#pragma const
static int countlshr(short fract _f);
#pragma inline
#pragma always_inline
static int countlshr(short fract _f) {
  const short fract f = _f;
  int signbits = (int)__builtin_norm_fr1x16(bitshr(f));
  if (f == 0.0hr) {
    signbits++;
  }
  return signbits;
}

#pragma const
static int countlsr(fract _f);
#pragma inline
#pragma always_inline
static int countlsr(fract _f) {
  return countlshr((short fract)_f);
}

#pragma const
static int countlslr(long fract _f);
#pragma inline
#pragma always_inline
static int countlslr(long fract _f) {
  const long fract f = _f;
  int signbits = (int)__builtin_norm_fr1x32(bitslr(f));
  if (f == 0.0lr) {
    signbits++;
  }
  return signbits;
}

#pragma const
static int countlshk(short accum _a);
#pragma inline
#pragma always_inline
static int countlshk(short accum _a) {
  const short accum a = _a;
  int signbits = (int)__builtin_A_signbits(bitshk(a)) + 8;
  if (a == 0.0hk) {
    signbits = 40;
  }
  return signbits;
}

#pragma const
static int countlsk(accum _a);
#pragma inline
#pragma always_inline
static int countlsk(accum _a) {
  return countlshk((short accum)_a);
}

#pragma const
static int countlslk(long accum _a);
#pragma inline
#pragma always_inline
static int countlslk(long accum _a) {
  return countlshk((short accum)_a);
}

/* count the leading zeros in an unsigned fixed-point value.
*/

#pragma const
static int countlsuhr(unsigned short fract _f);
#pragma inline
#pragma always_inline
static int countlsuhr(unsigned short fract _f) {
  const unsigned short fract f = _f;
  uint_uhr_t f_i = bitsuhr(f);
  int signbits;
  f_i >>= 1U;
  signbits = (int)__builtin_norm_fr1x16((short)f_i);
  if (f == 0.0uhr) {
    signbits++;
  }
  return signbits;
}

#pragma const
static int countlsur(unsigned fract _f);
#pragma inline
#pragma always_inline
static int countlsur(unsigned fract _f) {
  return countlsuhr((unsigned short fract)_f);
}

#pragma const
static int countlsulr(unsigned long fract _f);
#pragma inline
#pragma always_inline
static int countlsulr(unsigned long fract _f) {
  const unsigned long fract f = _f;
  uint_ulr_t f_i = bitsulr(f);
  int signbits;
  f_i >>= 1U;
  signbits = (int)__builtin_norm_fr1x32((int)f_i);
  if (f == 0.0ulr) {
    signbits++;
  }
  return signbits;
}

#pragma const
static int countlsuhk(unsigned short accum _a);
#pragma inline
#pragma always_inline
static int countlsuhk(unsigned short accum _a) {
  const unsigned short accum a = _a;
  int_hk_t a_i = (int_hk_t)bitsuhk(a);
  int signbits;
  a_i = __builtin_A_lshift(a_i, -1);
  signbits = (int)__builtin_A_signbits(a_i) + 8;
  if (a == 0.0uhk) {
    signbits = 40;
  }
  return signbits;
}

#pragma const
static int countlsuk(unsigned accum _a);
#pragma inline
#pragma always_inline
static int countlsuk(unsigned accum _a) {
  return countlsuhk((unsigned short accum)_a);
}

#pragma const
static int countlsulk(unsigned long accum _a);
#pragma inline
#pragma always_inline
static int countlsulk(unsigned long accum _a) {
  return countlsuhk((unsigned short accum)_a);
}

#if defined(_C99) /* type-generic macros only available in -c99 mode */

#if !defined(__DISABLE_COUNTLSFX)

#define countlsfx(x) \
  __genericfx((x), \
              countlshr, countlsuhr, \
              countlsr, countlsur, \
              countlslr, countlsulr, \
              countlshk, countlsuhk, \
              countlsk, countlsuk, \
              countlslk, countlsulk)((x))

#endif /* __DISABLE_COUNTLSFX */

#endif /* _C99 */

/* convert a string to a fixed-point value.
*/

fract strtofxr(const char * __restrict _nptr,
               char ** __restrict _endptr);

long fract strtofxlr(const char * __restrict _nptr,
                     char ** __restrict _endptr);

accum strtofxk(const char * __restrict _nptr,
               char ** __restrict _endptr);

unsigned fract strtofxur(const char * __restrict _nptr,
                         char ** __restrict _endptr);

unsigned long fract strtofxulr(const char * __restrict _nptr,
                               char ** __restrict _endptr);

unsigned accum strtofxuk(const char * __restrict _nptr,
                         char ** __restrict _endptr);

static short fract strtofxhr(const char * __restrict _nptr,
                             char ** __restrict _endptr);
#pragma inline
#pragma always_inline
static short fract strtofxhr(const char * __restrict _nptr,
                             char ** __restrict _endptr) {
  return (short fract)strtofxr(_nptr, _endptr);
}

static short accum strtofxhk(const char * __restrict _nptr,
                             char ** __restrict _endptr);
#pragma inline
#pragma always_inline
static short accum strtofxhk(const char * __restrict _nptr,
                             char ** __restrict _endptr) {
  return (short accum)strtofxk(_nptr, _endptr);
}

static long accum strtofxlk(const char * __restrict _nptr,
                            char ** __restrict _endptr);
#pragma inline
#pragma always_inline
static long accum strtofxlk(const char * __restrict _nptr,
                            char ** __restrict _endptr) {
  return (long accum)strtofxk(_nptr, _endptr);
}

static unsigned short fract strtofxuhr(const char * __restrict _nptr,
                                       char ** __restrict _endptr);
#pragma inline
#pragma always_inline
static unsigned short fract strtofxuhr(const char * __restrict _nptr,
                                       char ** __restrict _endptr) {
  return (unsigned short fract)strtofxur(_nptr, _endptr);
}

static unsigned short accum strtofxuhk(const char * __restrict _nptr,
                                       char ** __restrict _endptr);
#pragma inline
#pragma always_inline
static unsigned short accum strtofxuhk(const char * __restrict _nptr,
                                       char ** __restrict _endptr) {
  return (unsigned short accum)strtofxuk(_nptr, _endptr);
}

static unsigned long accum strtofxulk(const char * __restrict _nptr,
                                      char ** __restrict _endptr);
#pragma inline
#pragma always_inline
static unsigned long accum strtofxulk(const char * __restrict _nptr,
                                      char ** __restrict _endptr) {
  return (unsigned long accum)strtofxuk(_nptr, _endptr);
}

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif

#endif
