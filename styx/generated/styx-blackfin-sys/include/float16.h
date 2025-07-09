/************************************************************************
 *
 * float16.h
 *
 * (c) Copyright 1996-2008 Analog Devices, Inc.  All rights reserved.
 * $Revision: 3522 $
 ************************************************************************/

/*
** C prototype functions for C++ float16 class.
** float16 is a 32-bit type. Exponent is low-half.
** Mantissa is high half:
** s mmm mmmm mmmm mmmm s eee eeee eeee eeee
** Exponent is unbiased, and there is no hidden bit,
** numbers are normalised to 0.x, not 1.x.
*/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* float16.h */
#endif

#ifndef _FLOAT16_H
#define _FLOAT16_H

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_8_1:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_8_5:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_8_10:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_10_1_a:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_10_1_b:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_10_1_d:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_12_1:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_12_6:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_12_7:"ADI header - use of inline function")
#pragma diag(suppress:misra_rule_12_12:"ADI header uses float in union")
#pragma diag(suppress:misra_rule_16_3:"ADI header, identifiers not needed on all parameters")
#pragma diag(suppress:misra_rule_18_4:"ADI header allows unions")
#pragma diag(suppress:misra_rule_19_1:"ADI header allows includes after statements")
#endif /* _MISRA_RULES */

#include <fract.h>
#include <fract2float_conv.h>

#define PlusInf_fl16  0x7fffffff
#define NegInf_fl16   0x8000ffff
#define NaN_fl16      0x00008000

#ifdef _FLOAT16_NO_INLINE

typedef long float16;

#ifdef __cplusplus
extern "C" {
#endif

float16 fr16_to_fl16(fract16);
fract16 fl16_to_fr16(float16);
float16 norm_fl16(float16 fl);
float16 add_fl16(float16, float16);
float16 sub_fl16(float16, float16);
float16 mul_fl16(float16, float16);
float16 div_fl16(float16, float16);
float16 negate_fl16(float16);
float16 abs_fl16(float16);
int cmp_fl16(float16, float16);
float16 fl_to_fl16(float);
int fits_in_fl16(float);
float fl16_to_fl(float16);

#ifdef __cplusplus
}
#endif

#else

typedef union {
      long l;           /* for simple initialisations  */
      unsigned long u;  /* for conversions             */
      struct {
         short e;       /* low half                    */
         short m;       /* high half                   */
      } s;
      float f;          /* for conversions             */
} float16;

static float16 fr16_to_fl16(fract16);
static fract16 fl16_to_fr16(float16);
static float16 norm_fl16(float16 fl);
static float16 add_fl16(float16, float16);
static float16 sub_fl16(float16, float16);
static float16 mul_fl16(float16, float16);
static float16 div_fl16(float16, float16);
static float16 negate_fl16(float16);
static float16 abs_fl16(float16);
static int cmp_fl16(float16, float16);
static float16 fl_to_fl16(float);
static int fits_in_fl16(float);
static float fl16_to_fl(float16);

#pragma inline
#pragma always_inline
static float16 fr16_to_fl16(fract16 fr)
{
  return fl_to_fl16(fr16_to_float(fr));
}

#pragma inline
#pragma always_inline
static fract16 fl16_to_fr16(float16 fl)
{
   fract16 fraction = fl.s.m;
   short exponent = fl.s.e;

   return shl_fr1x16(fraction, exponent);
}

#pragma inline
#pragma always_inline
static float16 norm_fl16(float16 fl)
{
   if (fl.s.m != 0) {
      short exponent = (short)norm_fr1x16(fl.s.m);
      fl.s.m <<= exponent;
      fl.s.e -= exponent;
   } else {
      fl.s.e = 0;
   }
   return fl;
}

#pragma inline
#pragma always_inline
static float16 add_fl16(float16 x, float16 y)
{
  float16 fl; /* Result */
  short ie;   /* Intermediate exponent */
  int im;     /* Intermediate mantissa */
  short n;    /* Normalization distance */

  /* Extract mantissa and exponents from the inputs.  This is an optimization\
     . */
  int xe = x.s.e, ye = y.s.e;
  int xm = x.s.m, ym = y.s.m;

  /* Zero is a tiny number, so make it have a tiny exponent. */
  if (xm == 0) {
    xe = -32768;
  }

  if (ym == 0) {
    ye = -32768;
  }

  /* Do the add.  Note that the shift might be larger than 31 bits,
     but the Blackfin handles it correctly. */
  ie = max(xe, ye);
  im = (int)(xm >> (ie - xe)) + (ym >> (ie - ye));

  /* Normalize the result in 32-bit int. */
  n = norm_fr1x32(im);
  fl.l = im << n;                     /* Keep only the upper 16 bits */
  fl.s.e = sub_fr1x16(ie, (n - 16));  /* Exponent is 16-bit saturated */

  /* Convert "zero" to standard form. */
  if (fl.s.m == 0) {
    fl.s.e = 0;
  }

  return fl;
}

#pragma inline
#pragma always_inline
static float16 sub_fl16(float16 x, float16 y)
{
  return add_fl16(x, negate_fl16(y));
}

#pragma inline
#pragma always_inline
static float16 mul_fl16(float16 x, float16 y)
{
   float16 fl;

   fl.s.e  = x.s.e + y.s.e;
   fl.s.m = mult_fr1x16(x.s.m, y.s.m);
   if (fl.s.m != 0) {
      short exponent = (short)norm_fr1x16(fl.s.m);
      fl.s.m <<= exponent;
      fl.s.e -= exponent;
   } else {
      fl.s.e = 0;
   }
   return fl;
}

#pragma inline
#pragma always_inline
static float16 div_fl16(float16 x, float16 y)
{
   int i;
   int niters = 15;
   const long one = 0x40000001;
   float16 fl;
   int xneg = x.l < 0;
   int yneg = y.l < 0;
   unsigned short r = 0u;
   unsigned short d = (unsigned short)x.s.m;
   unsigned short q = (unsigned short)y.s.m;
   signed short tmp;
   if (y.l == 0) {
      fl.l=NaN_fl16;
   } else if (y.l == one) {
      fl = x;
   } else if (x.l == y.l) {
      fl.l = one;
   } else {
     fl.s.e = x.s.e - y.s.e;
     if (xneg != 0) {
        tmp = -(short)d;
        d = (unsigned short)tmp;
     }
     if (yneg != 0) {
        tmp = -(short)q;
        q = (unsigned short)tmp;
     }
     for (i = 0; i < niters; i++) {
        if (q <= d) {
           d -= q;
           r |= 1u;
        }
        d <<= 1;
        r <<= 1;
     }
     d = r;
     if ((d & 0x8000u) != 0) {
        /* overflow */
        d >>= 1;
        fl.s.e++;
     }
     if (xneg != yneg) {
        tmp = -(short)d;
        d = (unsigned short)tmp;
     }
     fl.s.m = (short)d;       /* truncation  */
     if (fl.s.m != 0) {
        short exponent = (short)norm_fr1x16(fl.s.m);
        fl.s.m <<= exponent;
        fl.s.e -= exponent;
     } else {
        fl.s.e = 0;
     }
   }
   return fl;
}

#pragma inline
#pragma always_inline
static float16 negate_fl16(float16 fl)
{
   fl.s.m = negate_fr1x16(fl.s.m);
   return fl;
}

#pragma inline
#pragma always_inline
static float16 abs_fl16(float16 fl)
{
   fl.s.m = abs_fr1x16(fl.s.m);
   return fl;
}

#pragma inline
#pragma always_inline
static int cmp_fl16(float16 x, float16 y)
{
  /* x < y  => negative
       x == y =>  0
       x > y  => positive */

  short ie;   /* Intermediate exponent */
  int im;     /* Intermediate mantissa */

  /* Extract mantissa and exponents from the inputs.  This is an optimization. \
   */
  int xe = x.s.e, ye = y.s.e;
  int xm = x.s.m, ym = y.s.m;

  /* Zero is a tiny number, so make it have a tiny exponent. */
  if (xm == 0) {
    xe = -32768;
  }
  if (ym == 0) {
    ye = -32768;
  }

  /* Do the compare.  Note that the shift might be larger than 31 bits,
     but the Blackfin handles it correctly. */
  ie = max(xe, ye);
  return (int)(xm >> (ie - xe)) - (ym >> (ie - ye));
}

#pragma inline
#pragma always_inline
static float16 fl_to_fl16(float f)
{
   float16 fl;
   unsigned long sign, uexp;
   long exponent;
   fl.f = f;
   if ((fl.u << 1) == 0) {
      /* -0.0 or +0.0 - needs special handling */
      fl.u = 0ul;
   } else {
     sign = (fl.u >> 31) << 31;
     uexp = (fl.u << 1) >> 24;
     uexp = uexp - 127u;
     exponent = (long)uexp;
     exponent += 1;   /* because we have to include the hidden bit */
     fl. u |= (unsigned int)1<<23;   /* add the hidden bit */
     fl.u <<= 8;   /* move 24-bit mantissa to top, to remove exp & sign */
     fl.u >>= 1;   /* back one space, for sign */
#ifdef DEBUG
     if (fl.s.e) {
        printf("Warning: precision lost %08x\n", fl.s.e);
     }
#endif
     fl.s.e = (short)exponent;
     if (sign != 0) {
        fl.s.m = -fl.s.m;
     }
   }
   return fl;
}

#pragma inline
#pragma always_inline
static int fits_in_fl16(float f)
{
   float16 fl;
   fl.f = f;
   return (fl.u & 0xffu) == 0;
}

#pragma inline
#pragma always_inline
static float fl16_to_fl(float16 fl)
{
   unsigned long exponent, sign;
   if (fl.u != 0) {
     short temp;
     sign = (fl.u >> 31) << 31;
     temp = fl.s.e + 127 - 1;   /* remove one, for hidden bit */
     exponent = (unsigned long)temp;
     if (((unsigned short)fl.s.m & 0xffffu) == 0x8000u) {
        fl.s.m = 0x4000;
        exponent++;
     } else if (sign != 0) {
        fl.s.m = -fl.s.m;
     } else {
        ; /* required by MISRA */
     }
     fl.s.e = 0;
     fl.u <<= 2;   /* remove sign bit and hidden bit*/
     fl.u >>= 9;
     exponent <<= 23;
     fl.u = sign | exponent | fl.u;
   }
   return fl.f;
}

#endif /*  _FLOAT16_NO_INLINE */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _FLOAT16_H */
