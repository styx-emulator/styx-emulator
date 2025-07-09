/************************************************************************
 *
 * LV_complex.h
 *
 * (c) Copyright 2005-2006 Analog Devices, Inc.  All rights reserved.
 * $Revision: 4 $
 ************************************************************************/

#ifndef __LV_COMPLEX_DEFINED
#define __LV_COMPLEX_DEFINED

#include <complex.h>
#include <fract2float_conv.h>

#ifdef __cplusplus
  extern "C" {
#endif


/*
 ------------------------------------------------------
  Conversion
  floating point <-> fractional
 ------------------------------------------------------
*/

#pragma always_inline
static __inline void
cplxfr16_to_cplxfloat_LV( const complex_fract16 *_a, complex_float *_x )
{
   _x->re = fr16_to_float( _a->re );
   _x->im = fr16_to_float( _a->im );
}

#pragma always_inline
static __inline void
cplxfloat_to_cplxfr16_LV( const complex_float *_x, complex_fract16 *_a )
{
   _a->re = float_to_fr16( _x->re );
   _a->im = float_to_fr16( _x->im );
}



/*
 ------------------------------------------------------
  Conversion
  complex number <-> scalars
 ------------------------------------------------------
*/

#pragma always_inline
static __inline void
cplxldouble_to_ldouble_LV( const complex_long_double *_a,
                           long double *_a_real, long double *_a_imag )
{
   *_a_real = _a->re;
   *_a_imag = _a->im;
}

#pragma always_inline
static __inline void
ldouble_to_cplxldouble_LV( const long double *_a_real,
                           const long double *_a_imag,
                           complex_long_double *_a )
{
   _a->re = *_a_real;
   _a->im = *_a_imag;
}

#pragma always_inline
static __inline void
cplxfloat_to_float_LV( const complex_float *_a,
                       float *_a_real, float *_a_imag )
{
   *_a_real = _a->re;
   *_a_imag = _a->im;
}

#pragma always_inline
static __inline void
float_to_cplxfloat_LV( const float *_a_real, const float *_a_imag,
                       complex_float *_a )
{
   _a->re = *_a_real;
   _a->im = *_a_imag;
}

#pragma always_inline
static __inline void
cplxfr16_to_fr16_LV( const complex_fract16 *_a,
                     fract16 *_a_real, fract16 *_a_imag )
{
   *_a_real = _a->re;
   *_a_imag = _a->im;
}

#pragma always_inline
static __inline void
fr16_to_cplxfr16_LV( const fract16 *_a_real, const fract16 *_a_imag,
                     complex_fract16 *_a )
{
   _a->re = *_a_real;
   _a->im = *_a_imag;
}


/*
 ------------------------------------------------------
  LibDSP wrappers
 ------------------------------------------------------
*/

#pragma always_inline
static __inline void
cabsf_LV (const complex_float *_a, float *_absolute)
{
   *_absolute = cabsf( *_a );
}

#pragma always_inline
static __inline void
conjf_LV (const complex_float *_a, complex_float *_conjugate)
{
   *_conjugate = conjf( *_a );
}

#pragma always_inline
static __inline void
caddf_LV (const complex_float *_a, const complex_float *_b,
          complex_float *_sum)
{
   *_sum = caddf( *_a, *_b );
}

#pragma always_inline
static __inline void
csubf_LV (const complex_float *_a, const complex_float *_b,
          complex_float *_difference)
{
   *_difference = csubf( *_a, *_b );
}

#pragma always_inline
static __inline void
cmltf_LV (const complex_float *_a, const complex_float *_b,
          complex_float *_product)
{
   *_product = cmltf( *_a, *_b );
}

#pragma always_inline
static __inline void
cdivf_LV (const complex_float *_a, const complex_float *_b,
          complex_float *_quotient)
{
   *_quotient = cdivf( *_a, *_b );
}

#pragma always_inline
static __inline void
normf_LV (const complex_float *_a, complex_float *_norm_a)
{
   *_norm_a = normf( *_a );
}

#pragma always_inline
static __inline void
cexpf_LV (float _exponent, complex_float *_a)
{
   *_a = cexpf( _exponent );
}

#pragma always_inline
static __inline void
argf_LV  (const complex_float *_a, float *_phase)
{
   *_phase = argf( *_a );
}

#pragma always_inline
static __inline void
polarf_LV (float _magnitude, float _phase,
           complex_float *_a)
{
   *_a = polarf( _magnitude, _phase );
}

#pragma always_inline
static __inline void
cartesianf_LV (const complex_float *_a,
               float *_phase, float *_magnitude)
{
   *_magnitude = cartesianf( *_a, _phase );
}


#pragma always_inline
static __inline void
cabsd_LV (const complex_long_double *_a, long double *_absolute)
{
   *_absolute = cabsd( *_a );
}

#pragma always_inline
static __inline void
conjd_LV (const complex_long_double *_a, complex_long_double *_conjugate)
{
   *_conjugate = conjd( *_a );
}

#pragma always_inline
static __inline void
caddd_LV (const complex_long_double *_a, const complex_long_double *_b,
          complex_long_double *_sum)
{
   *_sum = caddd( *_a, *_b );
}

#pragma always_inline
static __inline void
csubd_LV (const complex_long_double *_a, const complex_long_double *_b,
          complex_long_double *_difference)
{
   *_difference = csubd( *_a, *_b );
}

#pragma always_inline
static __inline void
cmltd_LV (const complex_long_double *_a, const complex_long_double *_b,
          complex_long_double *_product)
{
   *_product = cmltd( *_a, *_b );
}

#pragma always_inline
static __inline void
cdivd_LV (const complex_long_double *_a, const complex_long_double *_b,
          complex_long_double *_quotient)
{
   *_quotient = cdivd( *_a, *_b );
}

#pragma always_inline
static __inline void
normd_LV (const complex_long_double *_a, complex_long_double *_norm_a)
{
   *_norm_a = normd( *_a );
}

#pragma always_inline
static __inline void
cexpd_LV (long double _exponent, complex_long_double *_a)
{
   *_a = cexpd( _exponent );
}

#pragma always_inline
static __inline void
argd_LV  (const complex_long_double *_a, long double *_phase)
{
   *_phase = argd( *_a );
}

#pragma always_inline
static __inline void
polard_LV (long double _magnitude, long double _phase,
           complex_long_double *_a)
{
   *_a = polard( _magnitude, _phase );
}

#pragma always_inline
static __inline void
cartesiand_LV (const complex_long_double *_a,
               long double *_phase, long double *_magnitude)
{
   *_magnitude = cartesiand( *_a, _phase );
}


#pragma always_inline
static __inline void
cabs_fr16_LV (const complex_fract16 *_a, fract16 *_absolute)
{
   *_absolute = cabs_fr16( *_a );
}

#pragma always_inline
static __inline void
conj_fr16_LV (const complex_fract16 *_a, complex_fract16 *_conjugate)
{
   *_conjugate = conj_fr16( *_a );
}

#pragma always_inline
static __inline void
cadd_fr16_LV (const complex_fract16 *_a, const complex_fract16 *_b,
              complex_fract16 *_sum)
{
   *_sum = cadd_fr16( *_a, *_b );
}

#pragma always_inline
static __inline void
csub_fr16_LV (const complex_fract16 *_a, const complex_fract16 *_b,
              complex_fract16 *_difference)
{
   *_difference = csub_fr16( *_a, *_b );
}

#pragma always_inline
static __inline void
cmlt_fr16_LV (const complex_fract16 *_a, const complex_fract16 *_b,
              complex_fract16 *_product)
{
   *_product = cmlt_fr16( *_a, *_b );
}

#pragma always_inline
static __inline void
cdiv_fr16_LV (const complex_fract16 *_a, const complex_fract16 *_b,
              complex_fract16 *_quotient)
{
   *_quotient = cdiv_fr16( *_a, *_b );
}

#pragma always_inline
static __inline void
arg_fr16_LV  (const complex_fract16 *_a, fract16 *_phase)
{
   *_phase = arg_fr16( *_a );
}

#pragma always_inline
static __inline void
polar_fr16_LV (fract16 _magnitude, fract16 _phase,
               complex_fract16 *_a)
{
   *_a = polar_fr16( _magnitude, _phase );
}

#pragma always_inline
static __inline void
cartesian_fr16_LV (const complex_fract16 *_a,
                   fract16 *_phase, fract16 *_magnitude)
{
   *_magnitude = cartesian_fr16( *_a, _phase );
}


#ifdef __cplusplus
  }
#endif
#endif  /* __LV_COMPLEX_DEFINED */
