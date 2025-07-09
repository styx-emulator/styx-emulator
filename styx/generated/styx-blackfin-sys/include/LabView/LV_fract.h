/************************************************************************
 *
 * LV_fract.h
 *
 * (c) Copyright 2005-2006 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

#ifndef __LV_FRACT_DEFINED
#define __LV_FRACT_DEFINED

#if !defined(ETSI_SOURCE)
#define ETSI_SOURCE
#endif

#include <fract_math.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__DOCUMENTATION__)

    This header file defines wrapper functions under LabVIEW that
    provide access to routines that perform manipulations and
    basic arithmetic on data of type fract16 and fract32.

    The wrapper functions provided are based on the set of support
    routines defined by the European Telecommunications Standards
    Institute (ETSI) and are augmented by some of the built-in
    functions supported by the Blackfin compiler. The routines
    provide bit-accurate calculations for common operations.

    Several of the functions provided by ETSI support a Carry and
    Overflow flag - this feature is not supported by the functions
    defined by this header file.

#endif

/*
 -----------------------------------------------------------
  Conversion
  fract16 <-> fract32
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline void
fr16_to_fr32_LV (fract16 _hi, fract16 _lo, fract32 *_result)
{
   *_result = L_deposit_h( _hi );
   *_result |= L_deposit_l( _lo );
}

#pragma always_inline
static __inline void
fr32_to_fr16_LV (fract32 _x, fract16 *_x_hi, fract16 *_x_lo)
{
   *_x_hi = extract_h( _x );
   *_x_lo = extract_l( _x );
}


/*
 -----------------------------------------------------------
  	VI: BF Fract32 HiLo to fract32

	based on L_Comp (ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline void
HiLo_to_fr32_LV (fract16 _hi, fract16 _lo, fract32 *_result)
{
   *_result = L_Comp (_hi,_lo);
}

/*
 -----------------------------------------------------------
  	VI: BF fract32 to fract32 HiLo

	based on L_Extract (ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline void
fr32_to_HiLo_LV (fract32 _x, fract16 *_x_hi, fract16 *_x_lo)
{
   L_Extract (_x,_x_hi,_x_lo);
}


/*
 -----------------------------------------------------------
 Polymorphic VI: abs_fr

       based on: abs_s	(ETSI)
	       : L_abs	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
abs_fr16_LV (fract16 _x)
{
   return __builtin_abs_fr2x16(_x);
}

#pragma always_inline
static __inline fract32
abs_fr32_LV (fract32 _x)
{
   return __builtin_abs_fr1x32(_x);
}

/*
 -----------------------------------------------------------
 Polymorphic VI: add_fr

       based on: add	(ETSI)
	       : L_add	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
add_fr16_LV (fract16 _x, fract16 _y)
{
   return __builtin_add_fr2x16(_x,_y);
}

#pragma always_inline
static __inline fract32
add_fr32_LV (fract32 _x, fract32 _y)
{
   return __builtin_add_fr1x32(_x,_y);
}

/*
 -----------------------------------------------------------
 Polymorphic VI: div_fr16

       based on: div_l	(ETSI)
	       : div_s	(ETSI)
 -----------------------------------------------------------
*/

extern fract16 div_l (fract32 _x, fract16 _y);
extern fract16 div_s (fract16 _x, fract16 _y);

/*
 -----------------------------------------------------------
             VI: div_fr32

       based on: Div_32	(ETSI)
 -----------------------------------------------------------
*/

extern fract32 Div_32 (fract32 _dividend,
                       fract16 _denominator_hi,
                       fract16 _denominator_lo);

/*
 -----------------------------------------------------------
             VI: mac_32_16_fr16

       based on: mac_r	(ETSI)
 -----------------------------------------------------------
*/

extern fract16 mac_r (fract32 _acc, fract16 _x, fract16 _y);

/*
 -----------------------------------------------------------
             VI: mac_32_16_fr32

       based on: L_mac	(ETSI)
 -----------------------------------------------------------
*/

extern fract32 L_mac (fract32 _acc, fract16 _x, fract16 _y);

/*
 -----------------------------------------------------------
             VI: mac_nosat_fr32

       based on: L_macNs	(ETSI)
 -----------------------------------------------------------
*/

extern fract32 L_macNs (fract32 _acc, fract16 _x, fract16 _y);

/*
 -----------------------------------------------------------
 Polymorphic VI: max_fr

       based on: max_fr16	(Compiler Built-in Function)
	       : max_fr1x32	(Compiler Built-in Function)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
max_fr16_LV (fract16 _x, fract16 _y)
{
   return __builtin_max_fr2x16(_x,_y);
}

#pragma always_inline
static __inline fract32
max_fr32_LV (fract32 _x, fract32 _y)
{
   return __builtin_max_fr1x32(_x,_y);
}

/*
 -----------------------------------------------------------
 Polymorphic VI: min_fr

       based on: min_fr16	(Compiler Built-in Function)
	       : min_fr1x32	(Compiler Built-in Function)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
min_fr16_LV (fract16 _x, fract16 _y)
{
   return __builtin_min_fr2x16(_x,_y);
}

#pragma always_inline
static __inline fract32
min_fr32_LV (fract32 _x, fract32 _y)
{
   return __builtin_min_fr1x32(_x,_y);
}

/*
 -----------------------------------------------------------
             VI: mls_fr32

       based on: L_mls	(ETSI)
 -----------------------------------------------------------
*/

extern fract32 L_mls (fract32 _Lx, fract16 _y);

/*
 -----------------------------------------------------------
             VI: msu_32_16_fr16

       based on: msu_r	(ETSI)
 -----------------------------------------------------------
*/

extern fract16 msu_r (fract32 _acc, fract16 _x, fract16 _y);

/*
 -----------------------------------------------------------
             VI: msu_32_16_fr32

       based on: L_msu	(ETSI)
 -----------------------------------------------------------
*/

extern fract32 L_msu (fract32 _acc, fract16 _x, fract16 _y);

/*
 -----------------------------------------------------------
             VI: mls_nosat_fr32

       based on: L_msuNs	(ETSI)
 -----------------------------------------------------------
*/

extern fract32 L_msuNs (fract32 _acc, fract16 _x, fract16 _y);

/*
 -----------------------------------------------------------
 Polymorphic VI: mul_fr

       based on: mult		(ETSI)
	       : mult_fr1x32x32	(Compiler Built-in Function)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
mul_fr16_LV (fract16 _x, fract16 _y)
{
   return __builtin_mult_fr2x16(_x, _y);
}

#pragma always_inline
static __inline fract32
mul_fr32_LV (fract32 _x, fract32 _y)
{
   return __builtin_mult_fr1x32x32(_x, _y);
}

/*
 -----------------------------------------------------------
             VI: mul_nosat_fr32

       based on: mult_fr1x32x32NS	(Compiler Built-in Function)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract32
mul_nosat_fr32_LV (fract32 _x, fract32 _y)
{
   return __builtin_mult_fr1x32x32NS(_x,_y);
}

/*
 -----------------------------------------------------------
             VI: mul_round_fr16

       based on: mult_r	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
mul_round_fr16_LV (fract16 _x, fract16 _y)
{
   return __builtin_multr_fr2x16(_x,_y);
}

/*
 -----------------------------------------------------------
             VI: mul_32_fr32

       based on: Mpy_32	(ETSI)
 -----------------------------------------------------------
*/

extern fract32 Mpy_32 (fract16 _x_hi,
                       fract16 _x_lo, fract16 _y_hi, fract16 _y_lo);

/*
 -----------------------------------------------------------
             VI: mul_16_16_fr32

       based on: L_mult	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract32
mul_16_16_fr32_LV (fract16 _x, fract16 _y)
{
   return __builtin_mult_fr1x32(_x,_y);
}

/*
 -----------------------------------------------------------
             VI: mul_32_16_fr32

       based on: Mpy_32_16	(ETSI)
 -----------------------------------------------------------
*/

extern fract32 Mpy_32_16(fract16 _x_hi, fract16 _x_lo, fract16 _y);

/*
 -----------------------------------------------------------
 Polymorphic VI: neg_fr

       based on: negate		(ETSI)
	       : L_negate	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
neg_fr16_LV (fract16 _x)
{
   return __builtin_negate_fr2x16(_x);
}

#pragma always_inline
static __inline fract32
neg_fr32_LV (fract32 _x)
{
   return __builtin_sub_fr1x32(0, _x);
}

/*
 -----------------------------------------------------------
 Polymorphic VI: norm_fr

       based on: norm_s	(ETSI)
	       : norm_l	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline int
norm_fr16_LV (fract16 _x)
{
   return norm_s(_x);
}

static __inline int
norm_fr32_LV (fract32 _x)
{
   return norm_l(_x);
}

/*
 -----------------------------------------------------------
             VI: round_fr32

       based on: round	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
round_fr32_LV (fract32 _x)
{
   return __builtin_round_fr1x32(_x);
}

/*
 -----------------------------------------------------------
             VI: sat_fr16

       based on: saturate	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
sat_fr16_LV (fract32 _x)
{
   return shl_fr1x32(_x,16) >> 16;
}

/*
 -----------------------------------------------------------
 Polymorphic VI: shl_fr

       based on: shl	(ETSI)
	       : L_shl	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
shl_fr16_LV (fract16 _x, short _shift_positions)
{
   return __builtin_shl_fr2x16_clip(_x,_shift_positions);
}

#pragma always_inline
static __inline fract32
shl_fr32_LV (fract32 _x, short _shift_positions)
{
   return __builtin_shl_fr1x32_clip(_x,_shift_positions);
}

/*
 -----------------------------------------------------------
 Polymorphic VI: shr_fr

       based on: shr	(ETSI)
	       : L_shr	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
shr_fr16_LV (fract16 _x, short _shift_positions)
{
   return __builtin_shr_fr2x16_clip(_x,_shift_positions);
}

#pragma always_inline
static __inline fract32
shr_fr32_LV (fract32 _x, short _shift_positions)
{
   return __builtin_shr_fr1x32_clip(_x,_shift_positions);
}

/*
 -----------------------------------------------------------
             VI: lshr_fr16

       based on: shrl_fr1x16_clip	(Compiler Built-in Function)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
lshr_fr16_LV (fract16 _x, short _shift_positions)
{
   return __builtin_shrl_fr2x16_clip(_x,_shift_positions);
}

/*
 -----------------------------------------------------------
 Polymorphic VI: shr_round_fr

       based on: shr_r		(ETSI)
	       : L_shr_r	(ETSI)
 -----------------------------------------------------------
*/

extern fract16 shr_r (fract16 _x, fract16 _shift_positions);
extern fract32 L_shr_r (fract32 _x, fract16 _shift_positions);

/*
 -----------------------------------------------------------
 Polymorphic VI: sub_fr

       based on: sub	(ETSI)
	       : L_sub	(ETSI)
 -----------------------------------------------------------
*/

#pragma always_inline
static __inline fract16
sub_fr16_LV (fract16 _x, fract16 _y)
{
   return __builtin_sub_fr2x16(_x,_y);
}

#pragma always_inline
static __inline fract32
sub_fr32_LV (fract32 _x, fract32 _y)
{
   return __builtin_sub_fr1x32(_x,_y);
}

#ifdef __cplusplus
}
#endif

#endif  /* __LV_FRACT_DEFINED */
