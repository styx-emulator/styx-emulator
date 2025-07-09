/************************************************************************
 *
 * vector.h
 *
 * (c) Copyright 1996-2010 Analog Devices, Inc.  All rights reserved.
 * $Revision: 3524 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* vector.h */
#endif

#ifndef  __VECTOR_DEFINED
#define  __VECTOR_DEFINED

#include <fract_typedef.h>
#include <complex.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_19_4)
#endif /* _MISRA_RULES */

#ifdef __cplusplus
 extern "C" {
#endif



/* * * *        vecsadd      * * * *
 *
 *    real vector + real scalar addition
 *
 */

#pragma linkage_name __vecsaddf
        void vecsaddf (const float _vector[], float _scalar,
                       float _sum[], int _length);

#pragma linkage_name __vecsaddd
        void vecsaddd (const long double _vector[], long double _scalar,
                       long double _sum[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecsaddf
#else
#pragma linkage_name __vecsaddd
#endif
        void vecsadd (const double _vector[], double _scalar,
                      double _sum[], int _length);


#pragma linkage_name __vecsadd_fr16
        void vecsadd_fr16 (const fract16 _vector[], fract16 _scalar,
                           fract16 _sum[], int _length);

#pragma linkage_name __vecsadd_fr32
        void vecsadd_fr32 (const fract32 _vector[], fract32 _scalar,
                           fract32 _sum[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecsadd_fr16
        void vecsadd_fx16 (const _Fract _vector[], _Fract _scalar,
                           _Fract _sum[], int _length);

#pragma linkage_name __vecsadd_fr32
        void vecsadd_fx32 (const long _Fract _vector[], long _Fract _scalar,
                           long _Fract _sum[], int _length);
#endif



/* * * *        vecssub      * * * *
 *
 *    real vector - real scalar subtraction
 *
 */

#pragma linkage_name __vecssubf
        void vecssubf (const float _vector[], float _scalar,
                       float _difference[], int _length);

#pragma linkage_name __vecssubd
        void vecssubd (const long double _vector[], long double _scalar,
                       long double _difference[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecssubf
#else
#pragma linkage_name __vecssubd
#endif
        void vecssub (const double _vector[], double _scalar,
                      double _difference[], int _length);


#pragma linkage_name __vecssub_fr16
        void vecssub_fr16 (const fract16 _vector[], fract16 _scalar,
                           fract16 _difference[], int _length);

#pragma linkage_name __vecssub_fr32
        void vecssub_fr32 (const fract32 _vector[], fract32 _scalar,
                           fract32 _difference[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecssub_fr16
        void vecssub_fx16 (const _Fract _vector[], _Fract _scalar,
                           _Fract _difference[], int _length);

#pragma linkage_name __vecssub_fr32
        void vecssub_fx32 (const long _Fract _vector[], long _Fract _scalar,
                           long _Fract _difference[], int _length);
#endif



/* * * *        vecsmlt      * * * *
 *
 *    real vector * real scalar multiplication
 *
 */

#pragma linkage_name __vecsmltf
        void vecsmltf (const float _vector[], float _scalar,
                       float _product[], int _length);

#pragma linkage_name __vecsmltd
        void vecsmltd (const long double _vector[], long double _scalar,
                       long double _product[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecsmltf
#else
#pragma linkage_name __vecsmltd
#endif
        void vecsmlt (const double _vector[], double _scalar,
                      double _product[], int _length);


#pragma linkage_name __vecsmlt_fr16
        void vecsmlt_fr16 (const fract16 _vector[], fract16 _scalar,
                           fract16 _product[], int _length);

#pragma linkage_name __vecsmlt_fr32
        void vecsmlt_fr32 (const fract32 _vector[], fract32 _scalar,
                           fract32 _product[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecsmlt_fr16
        void vecsmlt_fx16 (const _Fract _vector[], _Fract _scalar,
                           _Fract _product[], int _length);

#pragma linkage_name __vecsmlt_fr32
        void vecsmlt_fx32 (const long _Fract _vector[], long _Fract _scalar,
                           long _Fract _product[], int _length);
#endif



/* * * *        vecvadd      * * * *
 *
 *    real vector + real vector addition
 *
 */

#pragma linkage_name __vecvaddf
        void vecvaddf (const float _vector_x[],
                       const float _vector_y[],
                       float _sum[], int _length);

#pragma linkage_name __vecvaddd
        void vecvaddd (const long double _vector_x[],
                       const long double _vector_y[],
                       long double _sum[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecvaddf
#else
#pragma linkage_name __vecvaddd
#endif
        void vecvadd (const double _vector_x[],
                      const double _vector_y[],
                      double _sum[], int _length);


#pragma linkage_name __vecvadd_fr16
        void vecvadd_fr16 (const fract16 _vector_x[],
                           const fract16 _vector_y[],
                           fract16 _sum[], int _length);

#pragma linkage_name __vecvadd_fr32
        void vecvadd_fr32 (const fract32 _vector_x[],
                           const fract32 _vector_y[],
                           fract32 _sum[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecvadd_fr16
        void vecvadd_fx16 (const _Fract _vector_x[],
                           const _Fract _vector_y[],
                           _Fract _sum[], int _length);

#pragma linkage_name __vecvadd_fr32
        void vecvadd_fx32 (const long _Fract _vector_x[],
                           const long _Fract _vector_y[],
                           long _Fract _sum[], int _length);
#endif



/* * * *        vecvsub      * * * *
 *
 *    real vector - real vector subtraction
 *
 */

#pragma linkage_name __vecvsubf
        void vecvsubf (const float _vector_x[],
                       const float _vector_y[],
                       float _difference[], int _length);

#pragma linkage_name __vecvsubd
        void vecvsubd (const long double _vector_x[],
                       const long double _vector_y[],
                       long double _difference[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecvsubf
#else
#pragma linkage_name __vecvsubd
#endif
        void vecvsub (const double _vector_x[],
                      const double _vector_y[],
                      double _difference[], int _length);


#pragma linkage_name __vecvsub_fr16
        void vecvsub_fr16 (const fract16 _vector_x[],
                           const fract16 _vector_y[],
                           fract16 _difference[], int _length);

#pragma linkage_name __vecvsub_fr32
        void vecvsub_fr32 (const fract32 _vector_x[],
                           const fract32 _vector_y[],
                           fract32 _difference[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecvsub_fr16
        void vecvsub_fx16 (const _Fract _vector_x[],
                           const _Fract _vector_y[],
                           _Fract _difference[], int _length);

#pragma linkage_name __vecvsub_fr32
        void vecvsub_fx32 (const long _Fract _vector_x[],
                           const long _Fract _vector_y[],
                           long _Fract _difference[], int _length);
#endif



/* * * *        vecvmlt      * * * *
 *
 *    real vector * real vector multiplication
 *
 */

#pragma linkage_name __vecvmltf
        void vecvmltf (const float _vector_x[],
                       const float _vector_y[],
                       float _product[], int _length);

#pragma linkage_name __vecvmltd
        void vecvmltd (const long double _vector_x[],
                       const long double _vector_y[],
                       long double _product[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecvmltf
#else
#pragma linkage_name __vecvmltd
#endif
        void vecvmlt (const double _vector_x[],
                      const double _vector_y[],
                      double _product[], int _length);


#pragma linkage_name __vecvmlt_fr16
        void vecvmlt_fr16 (const fract16 _vector_x[],
                           const fract16 _vector_y[],
                           fract16 _product[], int _length);

#pragma linkage_name __vecvmlt_fr32
        void vecvmlt_fr32 (const fract32 _vector_x[],
                           const fract32 _vector_y[],
                           fract32 _product[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecvmlt_fr16
        void vecvmlt_fx16 (const _Fract _vector_x[],
                           const _Fract _vector_y[],
                           _Fract _product[], int _length);

#pragma linkage_name __vecvmlt_fr32
        void vecvmlt_fx32 (const long _Fract _vector_x[],
                           const long _Fract _vector_y[],
                           long _Fract _product[], int _length);
#endif



/* * * *        vecdot      * * * *
 *
 *    real vector dot product
 *
 */

#pragma linkage_name __vecdotf
        float vecdotf (const float _vector_x[],
                       const float _vector_y[],
                       int _length);

#pragma linkage_name __vecdotd
        long double vecdotd (const long double _vector_x[],
                             const long double _vector_y[],
                             int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecdotf
#else
#pragma linkage_name __vecdotd
#endif
        double vecdot (const double _vector_x[],
                       const double _vector_y[],
                       int _length);


#pragma linkage_name __vecdot_fr16
        fract16 vecdot_fr16 (const fract16 _vector_x[],
                             const fract16 _vector_y[],
                             int _length);

#pragma linkage_name __vecdot_fr32
        fract32 vecdot_fr32 (const fract32 _vector_x[],
                             const fract32 _vector_y[],
                             int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecdot_fr16
        _Fract vecdot_fx16 (const _Fract _vector_x[],
                            const _Fract _vector_y[],
                            int _length);

#pragma linkage_name __vecdot_fr32
        long _Fract vecdot_fx32 (const long _Fract _vector_x[],
                                 const long _Fract _vector_y[],
                                 int _length);
#endif



/* * * *        vecmax      * * * *
 *
 *    Maximum value of vector elements
 *
 */

#pragma linkage_name __vecmaxf
        float vecmaxf (const float _vector[], int _length);

#pragma linkage_name __vecmaxd
        long double vecmaxd (const long double _vector[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecmaxf
#else
#pragma linkage_name __vecmaxd
#endif
        double vecmax (const double _vector[], int _length);


#pragma linkage_name __vecmax_fr16
        fract16 vecmax_fr16 (const fract16 _vector[], int _length);

#pragma linkage_name __vecmax_fr32
        fract32 vecmax_fr32 (const fract32 _vector[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecmax_fr16
        _Fract vecmax_fx16 (const _Fract _vector[], int _length);

#pragma linkage_name __vecmax_fr32
        long _Fract vecmax_fx32 (const long _Fract _vector[], int _length);
#endif



/* * * *        vecmin      * * * *
 *
 *    Minimum value of vector elements
 *
 */

#pragma linkage_name __vecminf
        float vecminf (const float _vector[], int _length);

#pragma linkage_name __vecmind
        long double vecmind (const long double _vector[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecminf
#else
#pragma linkage_name __vecmind
#endif
        double vecmin (const double _vector[], int _length);


#pragma linkage_name __vecmin_fr16
        fract16 vecmin_fr16 (const fract16 _vector[], int _length);

#pragma linkage_name __vecmin_fr32
        fract32 vecmin_fr32 (const fract32 _vector[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecmin_fr16
        _Fract vecmin_fx16 (const _Fract _vector[], int _length);

#pragma linkage_name __vecmin_fr32
        long _Fract vecmin_fx32 (const long _Fract _vector[], int _length);
#endif



/* * * *        vecmaxloc      * * * *
 *
 *    Index of maximum value of vector elements
 *
 */

#pragma linkage_name __vecmaxlocf
        int vecmaxlocf (const float _vector[], int _length);

#pragma linkage_name __vecmaxlocd
        int vecmaxlocd (const long double _vector[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecmaxlocf
#else
#pragma linkage_name __vecmaxlocd
#endif
        int vecmaxloc (const double _vector[], int _length);


#pragma linkage_name __vecmaxloc_fr16
        int vecmaxloc_fr16 (const fract16 _vector[], int _length);

#pragma linkage_name __vecmaxloc_fr32
        int vecmaxloc_fr32 (const fract32 _vector[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecmaxloc_fr16
        int vecmaxloc_fx16 (const _Fract _vector[], int _length);

#pragma linkage_name __vecmaxloc_fr32
        int vecmaxloc_fx32 (const long _Fract _vector[], int _length);
#endif



/* * * *        vecminloc      * * * *
 *
 *    Index of minimum value of vector elements
 *
 */

#pragma linkage_name __vecminlocf
        int vecminlocf (const float _vector[], int _length);

#pragma linkage_name __vecminlocd
        int vecminlocd (const long double _vector[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __vecminlocf
#else
#pragma linkage_name __vecminlocd
#endif
        int vecminloc (const double _vector[], int _length);


#pragma linkage_name __vecminloc_fr16
        int vecminloc_fr16 (const fract16 _vector[], int _length);

#pragma linkage_name __vecminloc_fr32
        int vecminloc_fr32 (const fract32 _vector[], int _length);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __vecminloc_fr16
        int vecminloc_fx16 (const _Fract _vector[], int _length);

#pragma linkage_name __vecminloc_fr32
        int vecminloc_fx32 (const long _Fract _vector[], int _length);
#endif



/* * * *        cvecsadd      * * * *
 *
 *    complex vector + complex scalar addition
 *
 */

#pragma linkage_name __cvecsaddf
        void cvecsaddf (const complex_float _vector[],
                        complex_float _scalar,
                        complex_float _sum[], int _length);

#pragma linkage_name __cvecsaddd
        void cvecsaddd (const complex_long_double _vector[],
                        complex_long_double _scalar,
                        complex_long_double _sum[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cvecsaddf
#else
#pragma linkage_name __cvecsaddd
#endif
        void cvecsadd (const complex_double _vector[],
                       complex_double _scalar,
                       complex_double _sum[], int _length);


#pragma linkage_name __cvecsadd_fr16
        void cvecsadd_fr16 (const complex_fract16 _vector[],
                            complex_fract16 _scalar,
                            complex_fract16 _sum[], int _length);

#pragma linkage_name __cvecsadd_fr32
        void cvecsadd_fr32 (const complex_fract32 _vector[],
                            complex_fract32 _scalar,
                            complex_fract32 _sum[], int _length);



/* * * *        cvecssub      * * * *
 *
 *    complex vector - complex scalar subtraction
 *
 */

#pragma linkage_name __cvecssubf
        void cvecssubf (const complex_float _vector[],
                        complex_float _scalar,
                        complex_float _difference[], int _length);

#pragma linkage_name __cvecssubd
        void cvecssubd (const complex_long_double _vector[],
                        complex_long_double _scalar,
                        complex_long_double _difference[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cvecssubf
#else
#pragma linkage_name __cvecssubd
#endif
        void cvecssub (const complex_double _vector[],
                       complex_double _scalar,
                       complex_double _difference[], int _length);


#pragma linkage_name __cvecssub_fr16
        void cvecssub_fr16 (const complex_fract16 _vector[],
                            complex_fract16 _scalar,
                            complex_fract16 _difference[], int _length);

#pragma linkage_name __cvecssub_fr32
        void cvecssub_fr32 (const complex_fract32 _vector[],
                            complex_fract32 _scalar,
                            complex_fract32 _difference[], int _length);



/* * * *        cvecsmlt      * * * *
 *
 *    complex vector * complex scalar multiplication
 *
 */

#pragma linkage_name __cvecsmltf
        void cvecsmltf (const complex_float _vector[],
                        complex_float _scalar,
                        complex_float _product[], int _length);

#pragma linkage_name __cvecsmltd
        void cvecsmltd (const complex_long_double _vector[],
                        complex_long_double _scalar,
                        complex_long_double _product[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cvecsmltf
#else
#pragma linkage_name __cvecsmltd
#endif
        void cvecsmlt (const complex_double _vector[],
                       complex_double _scalar,
                       complex_double _product[], int _length);


#pragma linkage_name __cvecsmlt_fr16
        void cvecsmlt_fr16 (const complex_fract16 _vector[],
                            complex_fract16 _scalar,
                            complex_fract16 _product[], int _length);

#pragma linkage_name __cvecsmlt_fr32
        void cvecsmlt_fr32 (const complex_fract32 _vector[],
                            complex_fract32 _scalar,
                            complex_fract32 _product[], int _length);



/* * * *        cvecvadd      * * * *
 *
 *    complex vector + complex vector addition
 *
 */

#pragma linkage_name __cvecvaddf
        void cvecvaddf (const complex_float _vector_a[],
                        const complex_float _vector_b[],
                        complex_float _sum[], int _length);

#pragma linkage_name __cvecvaddd
        void cvecvaddd (const complex_long_double _vector_a[],
                        const complex_long_double _vector_b[],
                        complex_long_double _sum[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cvecvaddf
#else
#pragma linkage_name __cvecvaddd
#endif
        void cvecvadd (const complex_double _vector_a[],
                       const complex_double _vector_b[],
                       complex_double _sum[], int _length);


#pragma linkage_name __cvecvadd_fr16
        void cvecvadd_fr16 (const complex_fract16 _vector_a[],
                            const complex_fract16 _vector_b[],
                            complex_fract16 _sum[], int _length);

#pragma linkage_name __cvecvadd_fr32
        void cvecvadd_fr32 (const complex_fract32 _vector_a[],
                            const complex_fract32 _vector_b[],
                            complex_fract32 _sum[], int _length);



/* * * *        cvecvsub      * * * *
 *
 *    complex vector - complex vector subtraction
 *
 */

#pragma linkage_name __cvecvsubf
        void cvecvsubf (const complex_float _vector_a[],
                        const complex_float _vector_b[],
                        complex_float _difference[], int _length);

#pragma linkage_name __cvecvsubd
        void cvecvsubd (const complex_long_double _vector_a[],
                        const complex_long_double _vector_b[],
                        complex_long_double _difference[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cvecvsubf
#else
#pragma linkage_name __cvecvsubd
#endif
        void cvecvsub (const complex_double _vector_a[],
                       const complex_double _vector_b[],
                       complex_double _difference[], int _length);


#pragma linkage_name __cvecvsub_fr16
        void cvecvsub_fr16 (const complex_fract16 _vector_a[],
                            const complex_fract16 _vector_b[],
                            complex_fract16 _difference[], int _length);

#pragma linkage_name __cvecvsub_fr32
        void cvecvsub_fr32 (const complex_fract32 _vector_a[],
                            const complex_fract32 _vector_b[],
                            complex_fract32 _difference[], int _length);



/* * * *        cvecvmlt      * * * *
 *
 *    complex vector * complex vector multiplication
 *
 */

#pragma linkage_name __cvecvmltf
        void cvecvmltf (const complex_float _vector_a[],
                        const complex_float _vector_b[],
                        complex_float _product[], int _length);

#pragma linkage_name __cvecvmltd
        void cvecvmltd (const complex_long_double _vector_a[],
                        const complex_long_double _vector_b[],
                        complex_long_double _product[], int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cvecvmltf
#else
#pragma linkage_name __cvecvmltd
#endif
        void cvecvmlt (const complex_double _vector_a[],
                       const complex_double _vector_b[],
                       complex_double _product[], int _length);


#pragma linkage_name __cvecvmlt_fr16
        void cvecvmlt_fr16 (const complex_fract16 _vector_a[],
                            const complex_fract16 _vector_b[],
                            complex_fract16 _product[], int _length);

#pragma linkage_name __cvecvmlt_fr32
        void cvecvmlt_fr32 (const complex_fract32 _vector_a[],
                            const complex_fract32 _vector_b[],
                            complex_fract32 _product[], int _length);



/* * * *        cvecdot      * * * *
 *
 *    complex vector dot product
 *
 */

#pragma linkage_name __cvecdotf
        complex_float cvecdotf (const complex_float _vector_a[],
                                const complex_float _vector_b[],
                                int _length);

#pragma linkage_name __cvecdotd
        complex_long_double cvecdotd (const complex_long_double _vector_a[],
                                      const complex_long_double _vector_b[],
                                      int _length);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cvecdotf
#else
#pragma linkage_name __cvecdotd
#endif
        complex_double cvecdot (const complex_double _vector_a[],
                                const complex_double _vector_b[],
                                int _length);


#pragma linkage_name __cvecdot_fr16
        complex_fract16 cvecdot_fr16 (const complex_fract16 _vector_a[],
                                      const complex_fract16 _vector_b[],
                                      int _length);

#pragma linkage_name __cvecdot_fr32
        complex_fract32 cvecdot_fr32 (const complex_fract32 _vector_a[],
                                      const complex_fract32 _vector_b[],
                                      int _length);


#ifdef __cplusplus
 }      /* end extern "C" */
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif   /* __VECTOR_DEFINED  (include guard) */
