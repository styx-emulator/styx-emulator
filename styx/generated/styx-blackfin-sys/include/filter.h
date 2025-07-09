/************************************************************************
 *
 * filter.h
 *
 * (c) Copyright 1996-2012 Analog Devices, Inc.  All rights reserved.
 * $Revision: 14738 $
 ************************************************************************/
#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* filter.h */
#endif

#ifndef  __FILTER_DEFINED
#define  __FILTER_DEFINED


#include <fract_typedef.h>
#include <complex.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution")
#pragma diag(suppress:misra_rule_19_7:"ADI header requires function macros")
#endif /* _MISRA_RULES */


#ifdef __cplusplus
 extern "C" {
#endif

typedef struct
{
    fract16 *h;     /*  filter coefficients            */
    fract16 *d;     /*  start of delay line            */
    fract16 *p;     /*  read/write pointer             */
    int k;          /*  number of coefficients         */
    int l;          /*  interpolation/decimation index */
} _fir_fr16_state;

typedef struct
{
    fract32 *h;     /*  filter coefficients            */
    fract32 *d;     /*  start of delay line            */
    fract32 *p;     /*  read/write pointer             */
    int k;          /*  number of coefficients         */
    int l;          /*  interpolation/decimation index */
} _fir_fr32_state;

typedef struct
{
    fract16 *c;     /* coefficients                   */
    fract16 *d;     /* start of delay line            */
    int k;          /* number of bi-quad stages       */
} _iir_fr16_state;

typedef struct
{
    fract32 *c;     /* coefficients                   */
    fract32 *d;     /* start of delay line            */
    int k;          /* number of bi-quad stages       */
} _iir_fr32_state;

typedef struct
{
    fract16 *c;     /* coefficients                  */
    fract16 *d;     /* start of delay line           */
    fract16 *p;     /* read/write pointer            */
    int k;          /* 2*number of stages + 1        */
} _iirdf1_fr16_state;

typedef struct
{
    fract32 *c;     /* coefficients                  */
    fract32 *d;     /* start of delay line           */
    fract32 *p;     /* read/write pointer            */
    int k;          /* 2*number of stages + 1        */
} _iirdf1_fr32_state;

typedef struct
{
    int k;
    complex_fract16 *h;
    complex_fract16 *d;
    complex_fract16 *p;
} _cfir_fr16_state;

typedef struct
{
    int k;
    complex_fract32 *h;
    complex_fract32 *d;
    complex_fract32 *p;
} _cfir_fr32_state;

#ifdef __FIXED_POINT_ALLOWED
typedef struct
{
    _Fract *h;      /*  filter coefficients            */
    _Fract *d;      /*  start of delay line            */
    _Fract *p;      /*  read/write pointer             */
    int k;          /*  number of coefficients         */
    int l;          /*  interpolation/decimation index */
} _fir_fx16_state;

typedef struct
{
    long _Fract *h; /*  filter coefficients            */
    long _Fract *d; /*  start of delay line            */
    long _Fract *p; /*  read/write pointer             */
    int k;          /*  number of coefficients         */
    int l;          /*  interpolation/decimation index */
} _fir_fx32_state;

typedef struct
{
    _Fract *c;      /* coefficients                   */
    _Fract *d;      /* start of delay line            */
    int k;          /* number of bi-quad stages       */
} _iir_fx16_state;

typedef struct
{
    long _Fract *c; /* coefficients                   */
    long _Fract *d; /* start of delay line            */
    int k;          /* number of bi-quad stages       */
} _iir_fx32_state;

typedef struct
{
    _Fract *c;      /* coefficients                  */
    _Fract *d;      /* start of delay line           */
    _Fract *p;      /* read/write pointer            */
    int k;          /* 2*number of stages + 1        */
} _iirdf1_fx16_state;

typedef struct
{
    long _Fract *c; /* coefficients                  */
    long _Fract *d; /* start of delay line           */
    long _Fract *p; /* read/write pointer            */
    int k;          /* 2*number of stages + 1        */
} _iirdf1_fx32_state;
#endif /*__FIXED_POINT_ALLOWED */


/* Macros */

#define fir_init(state, coeffs, delay, ncoeffs, index) \
    do {                      \
       (state).h = (coeffs);  \
       (state).d = (delay);   \
       (state).p = (delay);   \
       (state).k = (ncoeffs); \
       (state).l = (index);   \
    } while (0)

#define iir_init(state, coeffs, delay, stages) \
    do {                      \
       (state).c = (coeffs);  \
       (state).d = (delay);   \
       (state).k = (stages);  \
    } while (0)

#define iirdf1_init(state, coeffs, delay, stages) \
    do {                           \
       (state).c = (coeffs);       \
       (state).d = (delay);        \
       (state).p = (delay);        \
       (state).k = (2*(stages)+1); \
    } while (0)

#define cfir_init(state, coeffs, delay, ncoeffs) \
    do {                      \
       (state).h = (coeffs);  \
       (state).d = (delay);   \
       (state).p = (delay);   \
       (state).k = (ncoeffs); \
    } while (0)

typedef _fir_fr16_state fir_state_fr16;
typedef _fir_fr32_state fir_state_fr32;
typedef _iir_fr16_state iir_state_fr16;
typedef _iir_fr32_state iir_state_fr32;
typedef _iirdf1_fr16_state iirdf1_state_fr16;
typedef _iirdf1_fr32_state iirdf1_state_fr32;
#ifdef __FIXED_POINT_ALLOWED
typedef _fir_fx16_state fir_state_fx16;
typedef _fir_fx32_state fir_state_fx32;
typedef _iir_fx16_state iir_state_fx16;
typedef _iir_fx32_state iir_state_fx32;
typedef _iirdf1_fx16_state iirdf1_state_fx16;
typedef _iirdf1_fx32_state iirdf1_state_fx32;
#endif
typedef _cfir_fr16_state cfir_state_fr16;
typedef _cfir_fr32_state cfir_state_fr32;


/* * * *        fir      * * * *
 *
 *    finite impulse response filter
 *
 */

#pragma linkage_name __fir_fr16
        void fir_fr16 (const fract16 _input[],
                       fract16 _output[], int _length,
                       fir_state_fr16 *_filter_state);

#pragma linkage_name __fir_fr32
        void fir_fr32 (const fract32 _input[],
                       fract32 _output[], int _length,
                       fir_state_fr32 *_filter_state);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __fir_fr16
        void fir_fx16 (const _Fract _input[],
                       _Fract _output[], int _length,
                       fir_state_fx16 *_filter_state);

#pragma linkage_name __fir_fr32
        void fir_fx32 (const long _Fract _input[],
                       long _Fract _output[], int _length,
                       fir_state_fx32 *_filter_state);
#endif

/* * * *        iir      * * * *
 *
 *    Direct Form II Infinite Impulse Response filter
 *
 */

#pragma linkage_name __iir_fr16
        void iir_fr16 (const fract16 _input[],
                       fract16 _output[], int _length,
                       iir_state_fr16 *_filter_state);

#pragma linkage_name __iir_fr32
        void iir_fr32 (const fract32 _input[],
                       fract32 _output[], int _length,
                       iir_state_fr32 *_filter_state);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __iir_fr16
        void iir_fx16 (const _Fract _input[],
                       _Fract _output[], int _length,
                       iir_state_fx16 *_filter_state);

#pragma linkage_name __iir_fr32
        void iir_fx32 (const long _Fract _input[],
                       long _Fract _output[], int _length,
                       iir_state_fx32 *_filter_state);
#endif


/* * * *        iirdf1      * * * *
 *
 *    Direct Form I Infinite Impulse Response filter
 *
 */

#pragma linkage_name __iirdf1_fr16
        void iirdf1_fr16 (const fract16 _input[],
                          fract16 _output[], int _length,
                          iirdf1_state_fr16 *_filter_state);

#pragma linkage_name __iirdf1_fr32
        void iirdf1_fr32 (const fract32 _input[],
                          fract32 _output[], int _length,
                          iirdf1_state_fr32 *_filter_state);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __iirdf1_fr16
        void iirdf1_fx16 (const _Fract _input[],
                          _Fract _output[], int _length,
                          iirdf1_state_fx16 *_filter_state);

#pragma linkage_name __iirdf1_fr32
        void iirdf1_fx32 (const long _Fract _input[],
                          long _Fract _output[], int _length,
                          iirdf1_state_fx32 *_filter_state);
#endif


#pragma linkage_name __coeff_iirdf1_fr16
        void coeff_iirdf1_fr16 (const float _acoeff[],
                                const float _bcoeff[],
                                fract16 _coeff[], int _nstages);


#pragma linkage_name __coeff_iirdf1_fr32
        void coeff_iirdf1_fr32 (const long double _acoeff[],
                                const long double _bcoeff[],
                                fract32 _coeff[], int _nstages);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __coeff_iirdf1_fr16
        void coeff_iirdf1_fx16 (const float _acoeff[],
                                const float _bcoeff[],
                                _Fract _coeff[], int _nstages);

#pragma linkage_name __coeff_iirdf1_fr32
        void coeff_iirdf1_fx32 (const long double _acoeff[],
                                const long double _bcoeff[],
                                long _Fract _coeff[], int _nstages);
#endif


/* * * *        cfir      * * * *
 *
 *    complex finite impulse response filter
 *
 */

#pragma linkage_name __cfir_fr16
        void cfir_fr16 (const complex_fract16 _input[],
                        complex_fract16 _output[], int _length,
                        cfir_state_fr16 *_filter_state);

#pragma linkage_name __cfir_fr32
        void cfir_fr32 (const complex_fract32 _input[],
                        complex_fract32 _output[], int _length,
                        cfir_state_fr32 *_filter_state);


/* * * *        fir_decimation      * * * *
 *
 *    FIR decimation filter
 *
 */

#pragma linkage_name __fir_decima_fr16
        void fir_decima_fr16 (const fract16 _input[],
                              fract16 _output[], int _nsamples,
                              fir_state_fr16 *_filter_state);

#pragma linkage_name __fir_decima_fr32
        void fir_decima_fr32 (const fract32 _input[],
                              fract32 _output[], int _nsamples,
                              fir_state_fr32 *_filter_state);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __fir_decima_fr16
        void fir_decima_fx16 (const _Fract _input[],
                              _Fract _output[], int _nsamples,
                              fir_state_fx16 *_filter_state);

#pragma linkage_name __fir_decima_fr32
        void fir_decima_fx32 (const long _Fract _input[],
                              long _Fract _output[], int _nsamples,
                              fir_state_fx32 *_filter_state);
#endif


/* * * *        fir_interp      * * * *
 *
 *    FIR interpolation filter
 *
 */

#pragma linkage_name __fir_interp_fr16
        void fir_interp_fr16 (const fract16 _input[],
                              fract16 _output[], int _nsamples,
                              fir_state_fr16 *_filter_state);

#pragma linkage_name __fir_interp_fr32
        void fir_interp_fr32 (const fract32 _input[],
                              fract32 _output[], int _nsamples,
                              fir_state_fr32 *_filter_state);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __fir_interp_fr16
        void fir_interp_fx16 (const _Fract _input[],
                              _Fract _output[], int _nsamples,
                              fir_state_fx16 *_filter_state);

#pragma linkage_name __fir_interp_fr32
        void fir_interp_fx32 (const long _Fract _input[],
                              long _Fract _output[], int _nsamples,
                              fir_state_fx32 *_filter_state);
#endif


/* * * *        convolve      * * * *
 *
 *    Convolution 1D
 *
 */

#pragma linkage_name __convolve_fr16
        void convolve_fr16 (const fract16 _input_x[], int _length_x,
                            const fract16 _input_y[], int _length_y,
                            fract16 _output[]);

#pragma linkage_name __convolve_fr32
        void convolve_fr32 (const fract32 _input_x[], int _length_x,
                            const fract32 _input_y[], int _length_y,
                            fract32 _output[]);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __convolve_fr16
        void convolve_fx16 (const _Fract _input_x[], int _length_x,
                            const _Fract _input_y[], int _length_y,
                            _Fract _output[]);

#pragma linkage_name __convolve_fr32
        void convolve_fx32 (const long _Fract _input_x[], int _length_x,
                            const long _Fract _input_y[], int _length_y,
                            long _Fract _output[]);
#endif


/* * * *        conv2d      * * * *
 *
 *    2D convolution
 *
 */

#pragma linkage_name __conv2d_fr16
        void conv2d_fr16 (const fract16 _input_x[],
                          int _rows_x, int _columns_x,
                          const fract16 _input_y[],
                          int _rows_y, int _columns_y,
                          fract16 _output[]);

#pragma linkage_name __conv2d_fr32
        void conv2d_fr32 (const fract32 _input_x[],
                          int _rows_x, int _columns_x,
                          const fract32 _input_y[],
                          int _rows_y, int _columns_y,
                          fract32 _output[]);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __conv2d_fr16
        void conv2d_fx16 (const _Fract _input_x[],
                          int _rows_x, int _columns_x,
                          const _Fract _input_y[],
                          int _rows_y, int _columns_y,
                          _Fract _output[]);

#pragma linkage_name __conv2d_fr32
        void conv2d_fx32 (const long _Fract _input_x[],
                          int _rows_x, int _columns_x,
                          const long _Fract _input_y[],
                          int _rows_y, int _columns_y,
                          long _Fract _output[]);
#endif


/* * * *        conv2d3x3      * * * *
 *
 *    2D convolution with 3x3 matrix
 *
 */

#pragma linkage_name __conv2d3x3_fr16
        void conv2d3x3_fr16 (const fract16 _input_x[],
                             int _rows_x, int _columns_x,
                             const fract16 _input_y[],
                             fract16 _output[]);

#pragma linkage_name __conv2d3x3_fr32
        void conv2d3x3_fr32 (const fract32 _input_x[],
                             int _rows_x, int _columns_x,
                             const fract32 _input_y[],
                             fract32 _output[]);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __conv2d3x3_fr16
        void conv2d3x3_fx16 (const _Fract _input_x[],
                             int _rows_x, int _columns_x,
                             const _Fract _input_y[],
                             _Fract _output[]);

#pragma linkage_name __conv2d3x3_fr32
        void conv2d3x3_fx32 (const long _Fract _input_x[],
                             int _rows_x, int _columns_x,
                             const long _Fract _input_y[],
                             long _Fract _output[]);
#endif


/* * * *      fft_magnitude     * * * *
 *
 *    FFT magnitude
 *
 */

#pragma linkage_name __fft_magnitude_fr16
        void fft_magnitude_fr16 (const complex_fract16 _input[],
                                 fract16 _output[], int _fft_size,
                                 int _block_exponent, int _mode);

#pragma linkage_name __fft_magnitude_fr32
        void fft_magnitude_fr32 (const complex_fract32 _input[],
                                 fract32 _output[], int _fft_size,
                                 int _block_exponent, int _mode);


/* * * *        twidfft      * * * *
 *
 *    twiddle functions
 *
 *    twidfftrad2_fr16 1/2 n sized twiddle table (use in Radix2 FFT) <cos/-sin>
 *    twidfftrad2_fr32 1/2 n sized twiddle table (use in Radix2 FFT) <cos/-sin>
 *    twidfft2d_fr16       n sized twiddle table (use in 2D-FFT)     <cos/-sin>
 *    twidfft2d_fr32   3/4 n sized twiddle table (use in 2D-FFT)     <cos/-sin>
 *    twidfftf_fr16    3/4 n sized twiddle table (use in Radix4 FFTF <cos/-sin>
 *    twidfftf_fr32    3/4 n sized twiddle table (use in FFTF        <cos/-sin>
 */

#pragma linkage_name __twidfftrad2_fr16
        void twidfftrad2_fr16 (complex_fract16 _twiddle_table[],
                               int _fft_size);

#pragma linkage_name __twidfftrad2_fr32
        void twidfftrad2_fr32 (complex_fract32 _twiddle_table[],
                               int _fft_size);

#pragma linkage_name __twidfft2d_fr16
        void twidfft2d_fr16 (complex_fract16 _twiddle_table[],
                             int _fft_size);

#pragma linkage_name __twidfftf_fr32
        void twidfft2d_fr32 (complex_fract32 _twiddle_table[],
                             int _fft_size);

#pragma linkage_name __twidfftf_fr16
        void twidfftf_fr16 (complex_fract16 _twiddle_table[],
                            int _fft_size);

#pragma linkage_name __twidfftf_fr32
        void twidfftf_fr32 (complex_fract32 _twiddle_table[],
                            int _fft_size);


/* * * *        cfftf_fr16      * * * *
 *
 *    Fast N point radix 4 complex input FFT
 *
 */
#pragma linkage_name __cfftf_fr16
        void cfftf_fr16(const complex_fract16 _input[],
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[],
                        int _twiddle_stride, int _fft_size);


/* * * *  Mixed-Radix FFT Prototypes  * * * *
 *
 */

#pragma linkage_name __cfftf_fr32
        void cfftf_fr32(const complex_fract32 _input[],
                        complex_fract32 _output[],
                        const complex_fract32 _twiddle_table[],
                        int _twiddle_stride, int _fft_size);


#pragma linkage_name __ifftf_fr32
        void ifftf_fr32(const complex_fract32 _input[],
                        complex_fract32 _output[],
                        const complex_fract32 _twiddle_table[],
                        int _twiddle_stride, int _fft_size);


#pragma linkage_name __rfftf_fr32
        void rfftf_fr32(const fract32 _input[],
                        complex_fract32 _output[],
                        const complex_fract32 _twiddle_table[],
                        int _twiddle_stride, int _fft_size);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __rfftf_fr32
        void rfftf_fx_fr32 (const long _Fract _input[],
                            complex_fract32 _output[],
                            const complex_fract32 _twiddle_table[],
                            int _twiddle_stride, int _fft_size);
#endif

/*
 * Radix-2 FFT Prototypes
 *
 * The prototypes of the radix-2 FFT functions have been modified since the
 * VisualDSP4.5 release. The functions affected are:
 *
 *   cfft_fr16
 *   ifft_fr16
 *   rfft_fr16
 *
 * Existing code that makes use of any of these functions will require to be
 * either modified to use the new implementations _or built with the
 * compile-time macro __USE_FFT_REL45__ defined to enable legacy support.
 *
 * To modify existing calls the following should be undertaken:
 *
 * 1) Delete passing the temp array parameter from all calls to
 *    cftt_fr16, ifft_fr16 and rfft_fr16.
 * 2) Modify the block_exponent parameter to be a pointer to an integer in
 *    all calls. The new functions return the scaling steps performed
 *    using this parameter.
 * 3) Ensure that the scale method parameter scale_method is correct.
 *    Setting scale_method to 1 selects static scaling for minimal behaviour
 *    changes. A scale_method of 2 selects dynamic scaling and 3 for no
 *    scaling.
 *
 * Note that any existing compiled code that calls the FFT routines will use
 * the legacy implementations.
 */

/* * * *        cfftN      * * * *
 *
 *    N point radix 2 complex input FFT
 *
 */

#if defined __USE_FFT_REL45__
#pragma linkage_name __cfftN_fr16
        void cfft_fr16 (const complex_fract16 _input[],
                        complex_fract16 _temp[],
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int _block_exponent, int _scale_method);
#else
#pragma linkage_name __cfftN_scaling_fr16
        void cfft_fr16 (const complex_fract16 _input[],
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int* _block_exponent, int _scale_method);
#endif /* __USE_FFT_REL45__ */


#pragma linkage_name __cfft_fr32
        void cfft_fr32 (const complex_fract32 _input[],
                        complex_fract32 _output[],
                        const complex_fract32 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int* _block_exponent, int _scale_method);


/* * * *        rfftN      * * * *
 *
 *    N point radix 2 real input FFT
 *
 */

#if defined __USE_FFT_REL45__
#pragma linkage_name __rfftN_fr16
        void rfft_fr16 (const fract16 _input[],
                        complex_fract16 _temp[],
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int _block_exponent, int _scale_method);
#else
#pragma linkage_name __rfftN_scaling_fr16
        void rfft_fr16 (const fract16 _input[],
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int* _block_exponent, int _scale_method);
#endif  /* __USE_FFT_REL45__ */

#pragma linkage_name __rfft_fr32
        void rfft_fr32 (const fract32 _input[],
                        complex_fract32 _output[],
                        const complex_fract32 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int* _block_exponent, int _scale_method);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __rfftN_scaling_fr16
        void rfft_fx_fr16 (const _Fract _input[],
                           complex_fract16 _output[],
                           const complex_fract16 _twiddle_table[],
                           int _twiddle_stride, int _fft_size,
                           int *_block_exponent, int _scale_method);

#pragma linkage_name __rfft_fr32
        void rfft_fx_fr32 (const long _Fract _input[],
                           complex_fract32 _output[],
                           const complex_fract32 _twiddle_table[],
                           int _twiddle_stride, int _fft_size,
                           int* _block_exponent, int _scale_method);
#endif


/* * * *        ifftN      * * * *
 *
 *    N point radix 2 inverse FFT
 *
 */

#if defined __USE_FFT_REL45__
#pragma linkage_name __ifftN_fr16
        void ifft_fr16 (const complex_fract16 _input[],
                        complex_fract16 _temp[],
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int _block_exponent, int _scale_method);

#else
#pragma linkage_name __ifftN_scaling_fr16
        void ifft_fr16 (const complex_fract16 _input[],
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int* _block_exponent, int _scale_method);
#endif /* __USE_FFT_REL45__ */


#pragma linkage_name __ifft_fr32
        void ifft_fr32 (const complex_fract32 _input[],
                        complex_fract32 _output[],
                        const complex_fract32 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int* _block_exponent, int _scale_method);


/* * * *        cfft2d      * * * *
 *
 *    NxN point 2 dimensional complex input
 *
 */

#pragma linkage_name __cfft2d_fr16
        void cfft2d_fr16 (const complex_fract16 *_input,
                          complex_fract16 *_temp,
                          complex_fract16 *_output,
                          const complex_fract16 _twiddle_table[],
                          int _twiddle_stride, int _fft_size,
                          int _block_exponent, int _scale_method);


#pragma linkage_name __cfft2d_fr32
        void cfft2d_fr32 (const complex_fract32 *_input,
                          complex_fract32 *_temp,
                          complex_fract32 *_output,
                          const complex_fract32 _twiddle_table[],
                          int _twiddle_stride, int _fft_size);


/* * * *        rfft2d      * * * *
 *
 *    NxN point 2 dimensional real input FFT
 *
 */

#pragma linkage_name __rfft2d_fr16
        void rfft2d_fr16 (const fract16 *_input,
                          complex_fract16 *_temp,
                          complex_fract16 *_output,
                          const complex_fract16 _twiddle_table[],
                          int _twiddle_stride, int _fft_size,
                          int _block_exponent, int _scale_method);

#pragma linkage_name __rfft2d_fr32
        void rfft2d_fr32 (const fract32 *_input,
                          complex_fract32 *_temp,
                          complex_fract32 *_output,
                          const complex_fract32 _twiddle_table[],
                          int _twiddle_stride, int _fft_size);

#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __rfft2d_fr16
        void rfft2d_fx_fr16 (const _Fract *_input,
                             complex_fract16 *_temp,
                             complex_fract16 *_output,
                             const complex_fract16 _twiddle_table[],
                             int _twiddle_stride, int _fft_size,
                             int _block_exponent, int _scale_method);

#pragma linkage_name __rfft2d_fr32
        void rfft2d_fx_fr32 (const long _Fract *_input,
                             complex_fract32 *_temp,
                             complex_fract32 *_output,
                             const complex_fract32 _twiddle_table[],
                             int _twiddle_stride, int _fft_size);
#endif


/* * * *        ifft2d      * * * *
 *
 *    NxN point 2 dimensional inverse FFT
 *
 */

#pragma linkage_name __ifft2d_fr16
        void ifft2d_fr16 (const complex_fract16 *_input,
                          complex_fract16 *_temp,
                          complex_fract16 *_output,
                          const complex_fract16 _twiddle_table[],
                          int _twiddle_stride, int _fft_size,
                          int _block_exponent, int _scale_method);


#pragma linkage_name __ifft2d_fr32
        void ifft2d_fr32 (const complex_fract32 *_input,
                          complex_fract32 *_temp,
                          complex_fract32 *_output,
                          const complex_fract32 _twiddle_table[],
                          int _twiddle_stride, int _fft_size);


/* * * *        a_compress      * * * *
 *
 *    A-law compression
 *
 */

#pragma linkage_name __a_compress
        void a_compress (const short _input[], short _output[], int _length);


/* * * *        a_expand      * * * *
 *
 *    A-law expansion
 *
 */

#pragma linkage_name __a_expand
        void a_expand (const short _input[], short _output[], int _length);


/* * * *        mu_compress      * * * *
 *
 *    mu compression
 *
 */

#pragma linkage_name __mu_compress
        void mu_compress (const short _input[], short _output[], int _length);


/* * * *        mu_expand        * * * *
 *
 *    mu expansion
 *
 */

#pragma linkage_name __mu_expand
        void mu_expand (const short _input[], short _output[], int _length);



/* * * *      Legacy support     * * * *
 *
 * The following function declarations are given for backwards compatability
 * only. They should not be used when writing new applications. Instead, the
 * following functions should be used:
 *
 *     cfftrad4_fr16, twidfftrad4_fr16 => cfft_fr16, twidfftrad2_fr16
 *     rfftrad4_fr16, twidfftrad4_fr16 => rfft_fr16, twidfftrad2_fr16
 *     ifftrad4_fr16, twidfftrad4_fr16 => ifft_fr16, twidfftrad2_fr16
 *
 */

      /* * * *        twidfft    * * * *
       *
       *    twiddle functions
       *
       *    twidfft_fr16
       *        3/4 n sized twiddle table (use in Radix4 FFT) <cos/sin>
       *    twidfftrad4_fr16
       *        3/4 n sized twiddle table (use in Radix4 FFT) <cos/sin>
       */

#pragma linkage_name __twidfft_fr16
        void twidfft_fr16 (complex_fract16 _twiddle_table[],
                           int _fft_size);

#pragma linkage_name __twidfftrad4_fr16
        void twidfftrad4_fr16 (complex_fract16 _twiddle_table[],
                               int _fft_size);


      /* * * *        radix-4 ffts   * * * *
       *
       *    N point radix-4FFTs
       *
       */

#pragma linkage_name __cfftrad4_fr16
        void cfftrad4_fr16 (const complex_fract16 _input[],
                            complex_fract16 _temp[],
                            complex_fract16 _output[],
                            const complex_fract16 _twiddle_table[],
                            int _twiddle_stride, int _fft_size,
                            int _block_exponent, int _scale_method);

#pragma linkage_name __rfftrad4_fr16
        void rfftrad4_fr16 (const fract16 _input[],
                            complex_fract16 _temp[],
                            complex_fract16 _output[],
                            const complex_fract16 _twiddle_table[],
                            int _twiddle_stride, int _fft_size,
                            int _block_exponent, int _scale_method);

#pragma linkage_name __ifftrad4_fr16
        void ifftrad4_fr16 (const complex_fract16 _input[],
                            complex_fract16 _temp[],
                            complex_fract16 _output[],
                            const complex_fract16 _twiddle_table[],
                            int _twiddle_stride, int _fft_size,
                            int _block_exponent, int _scale_method);

#ifdef __cplusplus
 }      /* end extern "C" */
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif   /* __FILTER_DEFINED  (include guard) */
