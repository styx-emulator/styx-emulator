/************************************************************************
 *
 * window.h
 *
 * (c) Copyright 1996-2010 Analog Devices, Inc.  All rights reserved.
 * $Revision: 3948 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* window.h */
#endif

#ifndef __WINDOW_DEFINED
#define __WINDOW_DEFINED

#include <fract_typedef.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#endif /* _MISRA_RULES */

#ifdef __cplusplus
 extern "C" {
#endif


/* * * *        gen_bartlett      * * * *
 *
 *    Generate bartlett Window
 *
 */

#pragma linkage_name __gen_bartlett_fr16
        void gen_bartlett_fr16 (fract16 _bartlett_window[],
                                int _window_stride,
                                int _window_size);

#pragma linkage_name __gen_bartlett_fr32
        void gen_bartlett_fr32 (fract32 _bartlett_window[],
                                int _window_stride,
                                int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_bartlett_fr16
        void gen_bartlett_fx16 (_Fract _bartlett_window[],
                                int _window_stride,
                                int _window_size);

#pragma linkage_name __gen_bartlett_fr32
        void gen_bartlett_fx32 (long _Fract _bartlett_window[],
                                int _window_stride,
                                int _window_size);
#endif


/* * * *        gen_blackman      * * * *
 *
 *    Generate blackman Window
 *
 */

#pragma linkage_name __gen_blackman_fr16
        void gen_blackman_fr16 (fract16 _blackman_window[],
                                int _window_stride,
                                int _window_size);

#pragma linkage_name __gen_blackman_fr32
        void gen_blackman_fr32 (fract32 _blackman_window[],
                                int _window_stride,
                                int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_blackman_fr16
        void gen_blackman_fx16 (_Fract _blackman_window[],
                                int _window_stride,
                                int _window_size);

#pragma linkage_name __gen_blackman_fr32
        void gen_blackman_fx32 (long _Fract _blackman_window[],
                                int _window_stride,
                                int _window_size);
#endif


/* * * *        gen_gaussian      * * * *
 *
 *    Generate gaussian Window
 *
 */

#pragma linkage_name __gen_gaussian_fr16
        void gen_gaussian_fr16 (fract16 _gaussian_window[],
                                float _alpha,
                                int _window_stride,
                                int _window_size);

#pragma linkage_name __gen_gaussian_fr32
        void gen_gaussian_fr32 (fract32 _gaussian_window[],
                                long double _alpha,
                                int _window_stride,
                                int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_gaussian_fr16
        void gen_gaussian_fx16 (_Fract _gaussian_window[],
                                float _alpha,
                                int _window_stride,
                                int _window_size);

#pragma linkage_name __gen_gaussian_fr32
        void gen_gaussian_fx32 (long _Fract _gaussian_window[],
                                long double _alpha,
                                int _window_stride,
                                int _window_size);
#endif



/* * * *        gen_hamming      * * * *
 *
 *    Generate hamming Window
 *
 */

#pragma linkage_name __gen_hamming_fr16
        void gen_hamming_fr16 (fract16 _hamming_window[],
                               int _window_stride,
                               int _window_size);

#pragma linkage_name __gen_hamming_fr32
        void gen_hamming_fr32 (fract32 _hamming_window[],
                               int _window_stride,
                               int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_hamming_fr16
        void gen_hamming_fx16 (_Fract _hamming_window[],
                               int _window_stride,
                               int _window_size);

#pragma linkage_name __gen_hamming_fr32
        void gen_hamming_fx32 (long _Fract _hamming_window[],
                               int _window_stride,
                               int _window_size);
#endif



/* * * *        gen_hanning      * * * *
 *
 *    Generate hanning Window
 *
 */

#pragma linkage_name __gen_hanning_fr16
        void gen_hanning_fr16 (fract16 _hanning_window[],
                               int _window_stride,
                               int _window_size);

#pragma linkage_name __gen_hanning_fr32
        void gen_hanning_fr32 (fract32 _hanning_window[],
                               int _window_stride,
                               int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_hanning_fr16
        void gen_hanning_fx16 (_Fract _hanning_window[],
                               int _window_stride,
                               int _window_size);

#pragma linkage_name __gen_hanning_fr32
        void gen_hanning_fx32 (long _Fract _hanning_window[],
                               int _window_stride,
                               int _window_size);
#endif



/* * * *        gen_harris      * * * *
 *
 *    Generate harris Window
 *
 */

#pragma linkage_name __gen_harris_fr16
        void gen_harris_fr16 (fract16 _harris_window[],
                              int _window_stride,
                              int _window_size);

#pragma linkage_name __gen_harris_fr32
        void gen_harris_fr32 (fract32 _harris_window[],
                              int _window_stride,
                              int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_harris_fr16
        void gen_harris_fx16 (_Fract _harris_window[],
                              int _window_stride,
                              int _window_size);

#pragma linkage_name __gen_harris_fr32
        void gen_harris_fx32 (long _Fract _harris_window[],
                              int _window_stride,
                              int _window_size);
#endif



/* * * *        gen_kaiser      * * * *
 *
 *    Generate kaiser Window
 *
 */

#pragma linkage_name __gen_kaiser_fr16
        void gen_kaiser_fr16 (fract16 _kaiser_window[],
                              float _beta,
                              int _window_stride,
                              int _window_size);

#pragma linkage_name __gen_kaiser_fr32
        void gen_kaiser_fr32 (fract32 _kaiser_window[],
                              long double _beta,
                              int _window_stride,
                              int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_kaiser_fr16
        void gen_kaiser_fx16 (_Fract _kaiser_window[],
                              float _beta,
                              int _window_stride,
                              int _window_size);

#pragma linkage_name __gen_kaiser_fr32
        void gen_kaiser_fx32 (long _Fract _kaiser_window[],
                              long double _beta,
                              int _window_stride,
                              int _window_size);
#endif



/* * * *        gen_rectangular      * * * *
 *
 *    Generate rectangular Window
 *
 */

#pragma linkage_name __gen_rectangular_fr16
        void gen_rectangular_fr16 (fract16 _rectangular_window[],
                                   int _window_stride,
                                   int _window_size);

#pragma linkage_name __gen_rectangular_fr32
        void gen_rectangular_fr32 (fract32 _rectangular_window[],
                                   int _window_stride,
                                   int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_rectangular_fr16
        void gen_rectangular_fx16 (_Fract _rectangular_window[],
                                   int _window_stride,
                                   int _window_size);

#pragma linkage_name __gen_rectangular_fr32
        void gen_rectangular_fx32 (long _Fract _rectangular_window[],
                                   int _window_stride,
                                   int _window_size);
#endif



/* * * *        gen_triangle      * * * *
 *
 *    Generate triangle Window
 *
 */

#pragma linkage_name __gen_triangle_fr16
        void gen_triangle_fr16 (fract16 _triangle_window[],
                                int _window_stride,
                                int _window_size);

#pragma linkage_name __gen_triangle_fr32
        void gen_triangle_fr32 (fract32 _triangle_window[],
                                int _window_stride,
                                int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_triangle_fr16
        void gen_triangle_fx16 (_Fract _triangle_window[],
                                int _window_stride,
                                int _window_size);

#pragma linkage_name __gen_triangle_fr32
        void gen_triangle_fx32 (long _Fract _triangle_window[],
                                int _window_stride,
                                int _window_size);
#endif



/* * * *        gen_vonhann      * * * *
 *
 *    Generate vonhann Window
 *
 */

#pragma linkage_name __gen_vonhann_fr16
        void gen_vonhann_fr16 (fract16 _vonhann_window[],
                               int _window_stride,
                               int _window_size);

#pragma linkage_name __gen_hanning_fr32
        void gen_vonhann_fr32 (fract32 _vonhann_window[],
                               int _window_stride,
                               int _window_size);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __gen_vonhann_fr16
        void gen_vonhann_fx16 (_Fract _vonhann_window[],
                               int _window_stride,
                               int _window_size);

#pragma linkage_name __gen_hanning_fr32
        void gen_vonhann_fx32 (long _Fract _vonhann_window[],
                               int _window_stride,
                               int _window_size);
#endif


#ifdef __cplusplus
 }	/* end extern "C" */
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __WINDOW_DEFINED  (include guard) */
