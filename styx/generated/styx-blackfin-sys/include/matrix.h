/************************************************************************
 *
 * matrix.h
 *
 * (c) Copyright 1996-2010 Analog Devices, Inc.  All rights reserved.
 * $Revision: 3522 $
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* matrix.h */
#endif

#ifndef __MATRIX_DEFINED
#define __MATRIX_DEFINED

#include <fract_typedef.h>
#include <complex.h>
#include <vector.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_6_3)
#pragma diag(suppress:misra_rule_8_1)
#pragma diag(suppress:misra_rule_8_5)
#endif /* _MISRA_RULES */


#ifdef __cplusplus
 extern "C" {
#endif


/* * * *        matsadd      * * * *
 *
 *    real matrix + real scalar addition
 *
 */

#pragma inline
#pragma always_inline
        static void matsaddf (const float _matrix[],
                              float _scalar,
                              int _rows, int _columns,
                              float _sum[])
        {vecsaddf (_matrix, _scalar, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matsadd (const double _matrix[],
                             double _scalar,
                             int _rows, int _columns,
                             double _sum[])
        {vecsadd (_matrix, _scalar, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matsaddd (const long double _matrix[],
                              long double _scalar,
                              int _rows, int _columns,
                              long double _sum[])
        {vecsaddd (_matrix, _scalar, _sum, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void matsadd_fr16 (const fract16 _matrix[],
                                  fract16 _scalar,
                                  int _rows, int _columns,
                                  fract16 _sum[])
        {vecsadd_fr16 (_matrix, _scalar, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matsadd_fr32 (const fract32 _matrix[],
                                  fract32 _scalar,
                                  int _rows, int _columns,
                                  fract32 _sum[])
        {vecsadd_fr32 (_matrix, _scalar, _sum, _rows*_columns);}


#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
        static void matsadd_fx16 (const _Fract _matrix[],
                                  _Fract _scalar,
                                  int _rows, int _columns,
                                  _Fract _sum[])
        {vecsadd_fx16 (_matrix, _scalar, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matsadd_fx32 (const long _Fract _matrix[],
                                  long _Fract _scalar,
                                  int _rows, int _columns,
                                  long _Fract _sum[])
        {vecsadd_fx32 (_matrix, _scalar, _sum, _rows*_columns);}
#endif



/* * * *        matssub      * * * *
 *
 *    real matrix - real scalar subtraction
 *
 */

#pragma inline
#pragma always_inline
        static void matssubf (const float _matrix[],
                              float _scalar,
                              int _rows, int _columns,
                              float _difference[])
        {vecssubf (_matrix, _scalar, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matssub (const double _matrix[],
                             double _scalar,
                             int _rows, int _columns,
                             double _difference[])
        {vecssub (_matrix, _scalar, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matssubd (const long double _matrix[],
                              long double _scalar,
                              int _rows, int _columns,
                              long double _difference[])
        {vecssubd (_matrix, _scalar, _difference, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void matssub_fr16 (const fract16 _matrix[],
                                  fract16 _scalar,
                                  int _rows, int _columns,
                                  fract16 _difference[])
        {vecssub_fr16 (_matrix, _scalar, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matssub_fr32 (const fract32 _matrix[],
                                  fract32 _scalar,
                                  int _rows, int _columns,
                                  fract32 _difference[])
        {vecssub_fr32 (_matrix, _scalar, _difference, _rows*_columns);}


#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
        static void matssub_fx16 (const _Fract _matrix[],
                                  _Fract _scalar,
                                  int _rows, int _columns,
                                  _Fract _difference[])
        {vecssub_fx16 (_matrix, _scalar, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matssub_fx32 (const long _Fract _matrix[],
                                  long _Fract _scalar,
                                  int _rows, int _columns,
                                  long _Fract _difference[])
        {vecssub_fx32 (_matrix, _scalar, _difference, _rows*_columns);}
#endif



/* * * *        matsmlt      * * * *
 *
 *    real matrix * real scalar multiplication
 *
 */

#pragma inline
#pragma always_inline
        static void matsmltf (const float _matrix[],
                              float _scalar,
                              int _rows, int _columns,
                              float _product[])
        {vecsmltf (_matrix, _scalar, _product, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matsmlt (const double _matrix[],
                             double _scalar,
                             int _rows, int _columns,
                             double _product[])
        {vecsmlt (_matrix, _scalar, _product, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matsmltd (const long double _matrix[],
                              long double _scalar,
                              int _rows, int _columns,
                              long double _product[])
        {vecsmltd (_matrix, _scalar, _product, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void matsmlt_fr16 (const fract16 _matrix[],
                                  fract16 _scalar,
                                  int _rows, int _columns,
                                  fract16 _product[])
        {vecsmlt_fr16 (_matrix, _scalar, _product, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matsmlt_fr32 (const fract32 _matrix[],
                                  fract32 _scalar,
                                  int _rows, int _columns,
                                  fract32 _product[])
        {vecsmlt_fr32 (_matrix, _scalar, _product, _rows*_columns);}


#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
        static void matsmlt_fx16 (const _Fract _matrix[],
                                  _Fract _scalar,
                                  int _rows, int _columns,
                                  _Fract _product[])
        {vecsmlt_fx16 (_matrix, _scalar, _product, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matsmlt_fx32 (const long _Fract _matrix[],
                                  long _Fract _scalar,
                                  int _rows, int _columns,
                                  long _Fract _product[])
        {vecsmlt_fx32 (_matrix, _scalar, _product, _rows*_columns);}
#endif



/* * * *        matmadd      * * * *
 *
 *    real matrix + real matrix addition
 *
 */

#pragma inline
#pragma always_inline
        static void matmaddf (const float _matrix_x[],
                              const float _matrix_y[],
                              int _rows, int _columns,
                              float _sum[])
        {vecvaddf (_matrix_x, _matrix_y, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matmadd (const double _matrix_x[],
                             const double _matrix_y[],
                             int _rows, int _columns,
                             double _sum[])
        {vecvadd (_matrix_x, _matrix_y, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matmaddd (const long double _matrix_x[],
                              const long double _matrix_y[],
                              int _rows, int _columns,
                              long double _sum[])
        {vecvaddd (_matrix_x, _matrix_y, _sum, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void matmadd_fr16 (const fract16 _matrix_x[],
                                  const fract16 _matrix_y[],
                                  int _rows, int _columns,
                                  fract16 _sum[])
        {vecvadd_fr16 (_matrix_x, _matrix_y, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matmadd_fr32 (const fract32 _matrix_x[],
                                  const fract32 _matrix_y[],
                                  int _rows, int _columns,
                                  fract32 _sum[])
        {vecvadd_fr32 (_matrix_x, _matrix_y, _sum, _rows*_columns);}


#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
        static void matmadd_fx16 (const _Fract _matrix_x[],
                                  const _Fract _matrix_y[],
                                  int _rows, int _columns,
                                  _Fract _sum[])
        {vecvadd_fx16 (_matrix_x, _matrix_y, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matmadd_fx32 (const long _Fract _matrix_x[],
                                  const long _Fract _matrix_y[],
                                  int _rows, int _columns,
                                  long _Fract _sum[])
        {vecvadd_fx32 (_matrix_x, _matrix_y, _sum, _rows*_columns);}
#endif



/* * * *        matmsub      * * * *
 *
 *    real matrix - real matrix subtraction
 *
 */

#pragma inline
#pragma always_inline
        static void matmsubf (const float _matrix_x[],
                              const float _matrix_y[],
                              int _rows, int _columns,
                              float _difference[])
        {vecvsubf (_matrix_x, _matrix_y, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matmsub (const double _matrix_x[],
                             const double _matrix_y[],
                             int _rows, int _columns,
                             double _difference[])
        {vecvsub (_matrix_x, _matrix_y, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matmsubd (const long double _matrix_x[],
                              const long double _matrix_y[],
                              int _rows, int _columns,
                              long double _difference[])
        {vecvsubd (_matrix_x, _matrix_y, _difference, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void matmsub_fr16 (const fract16 _matrix_x[],
                                  const fract16 _matrix_y[],
                                  int _rows, int _columns,
                                  fract16 _difference[])
        {vecvsub_fr16 (_matrix_x, _matrix_y, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matmsub_fr32 (const fract32 _matrix_x[],
                                  const fract32 _matrix_y[],
                                  int _rows, int _columns,
                                  fract32 _difference[])
        {vecvsub_fr32 (_matrix_x, _matrix_y, _difference, _rows*_columns);}


#ifdef __FIXED_POINT_ALLOWED
#pragma inline
#pragma always_inline
        static void matmsub_fx16 (const _Fract _matrix_x[],
                                  const _Fract _matrix_y[],
                                  int _rows, int _columns,
                                  _Fract _difference[])
        {vecvsub_fx16 (_matrix_x, _matrix_y, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void matmsub_fx32 (const long _Fract _matrix_x[],
                                  const long _Fract _matrix_y[],
                                  int _rows, int _columns,
                                  long _Fract _difference[])
        {vecvsub_fx32 (_matrix_x, _matrix_y, _difference, _rows*_columns);}
#endif



/* * * *        matmmlt      * * * *
 *
 *    real matrix * real matrix multiplication
 *
 */

#pragma linkage_name __matmmltf
        void matmmltf (const float _matrix_x[],
                       int _rows_x, int _columns_x,
                       const float _matrix_y[],
                       int _columns_y,
                       float _product[]);

#pragma linkage_name __matmmltd
        void matmmltd (const long double _matrix_x[],
                       int _rows_x, int _columns_x,
                       const long double _matrix_y[],
                       int _columns_y,
                       long double _product[]);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __matmmltf
#else
#pragma linkage_name __matmmltd
#endif
        void matmmlt (const double _matrix_x[],
                      int _rows_x, int _columns_x,
                      const double _matrix_y[],
                      int _columns_y,
                      double _product[]);


#pragma linkage_name __matmmlt_fr16
        void matmmlt_fr16 (const fract16 _matrix_x[],
                           int _rows_x, int _columns_x,
                           const fract16 _matrix_y[],
                           int _columns_y,
                           fract16 _product[]);

#pragma linkage_name __matmmlt_fr32
        void matmmlt_fr32 (const fract32 _matrix_x[],
                           int _rows_x, int _columns_x,
                           const fract32 _matrix_y[],
                           int _columns_y,
                           fract32 _product[]);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __matmmlt_fr16
        void matmmlt_fx16 (const _Fract _matrix_x[],
                           int _rows_x, int _columns_x,
                           const _Fract _matrix_y[],
                           int _columns_y,
                           _Fract _product[]);

#pragma linkage_name __matmmlt_fr32
        void matmmlt_fx32 (const long _Fract _matrix_x[],
                           int _rows_x, int _columns_x,
                           const long _Fract _matrix_y[],
                           int _columns_y,
                           long _Fract _product[]);
#endif



/* * * *        cmatsadd      * * * *
 *
 *    complex matrix + complex scalar addition
 *
 */

#pragma inline
#pragma always_inline
        static void cmatsaddf (const complex_float _matrix[],
                               complex_float _scalar,
                               int _rows, int _columns,
                               complex_float _sum[])
        {cvecsaddf (_matrix, _scalar, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatsadd (const complex_double _matrix[],
                              complex_double _scalar,
                              int _rows, int _columns,
                              complex_double _sum[])
        {cvecsadd (_matrix, _scalar, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatsaddd (const complex_long_double _matrix[],
                               complex_long_double _scalar,
                               int _rows, int _columns,
                               complex_long_double _sum[])
        {cvecsaddd (_matrix, _scalar, _sum, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void cmatsadd_fr16 (const complex_fract16 _matrix[],
                                   complex_fract16 _scalar,
                                   int _rows, int _columns,
                                   complex_fract16 _sum[])
        {cvecsadd_fr16 (_matrix, _scalar, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatsadd_fr32 (const complex_fract32 _matrix[],
                                   complex_fract32 _scalar,
                                   int _rows, int _columns,
                                   complex_fract32 _sum[])
        {cvecsadd_fr32 (_matrix, _scalar, _sum, _rows*_columns);}



/* * * *        cmatssub      * * * *
 *
 *    complex matrix - complex scalar
 *
 */

#pragma inline
#pragma always_inline
        static void cmatssubf (const complex_float _matrix[],
                               complex_float _scalar,
                               int _rows, int _columns,
                               complex_float _difference[])
        {cvecssubf (_matrix, _scalar, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatssub (const complex_double _matrix[],
                              complex_double _scalar,
                              int _rows, int _columns,
                              complex_double _difference[])
        {cvecssub (_matrix, _scalar, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatssubd (const complex_long_double _matrix[],
                               complex_long_double _scalar,
                               int _rows, int _columns,
                               complex_long_double _difference[])
        {cvecssubd (_matrix, _scalar, _difference, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void cmatssub_fr16 (const complex_fract16 _matrix[],
                                   complex_fract16 _scalar,
                                   int _rows, int _columns,
                                   complex_fract16 _difference[])
        {cvecssub_fr16 (_matrix, _scalar, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatssub_fr32 (const complex_fract32 _matrix[],
                                   complex_fract32 _scalar,
                                   int _rows, int _columns,
                                   complex_fract32 _difference[])
        {cvecssub_fr32 (_matrix, _scalar, _difference, _rows*_columns);}



/* * * *        cmatsmlt      * * * *
 *
 *    complex matrix * complex scalar multiplication
 *
 */

#pragma inline
#pragma always_inline
        static void cmatsmltf (const complex_float _matrix[],
                               complex_float _scalar,
                               int _rows, int _columns,
                               complex_float _product[])
        {cvecsmltf (_matrix, _scalar, _product, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatsmlt (const complex_double _matrix[],
                              complex_double _scalar,
                              int _rows, int _columns,
                              complex_double _product[])
        {cvecsmlt (_matrix, _scalar, _product, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatsmltd (const complex_long_double _matrix[],
                               complex_long_double _scalar,
                               int _rows, int _columns,
                               complex_long_double _product[])
        {cvecsmltd (_matrix, _scalar, _product, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void cmatsmlt_fr16 (const complex_fract16 _matrix[],
                                   complex_fract16 _scalar,
                                   int _rows, int _columns,
                                   complex_fract16 _product[])
        {cvecsmlt_fr16 (_matrix, _scalar, _product, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatsmlt_fr32 (const complex_fract32 _matrix[],
                                   complex_fract32 _scalar,
                                   int _rows, int _columns,
                                   complex_fract32 _product[])
        {cvecsmlt_fr32 (_matrix, _scalar, _product, _rows*_columns);}



/* * * *        cmatmadd      * * * *
 *
 *    complex matrix + complex matrix addition
 *
 */

#pragma inline
#pragma always_inline
        static  void cmatmaddf (const complex_float _matrix_a[],
                                const complex_float _matrix_b[],
                                int _rows, int _columns,
                                complex_float _sum[])
        {cvecvaddf (_matrix_a, _matrix_b, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatmadd (const complex_double _matrix_a[],
                              const complex_double _matrix_b[],
                              int _rows, int _columns,
                              complex_double _sum[])
        {cvecvadd (_matrix_a, _matrix_b, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatmaddd (const complex_long_double _matrix_a[],
                               const complex_long_double _matrix_b[],
                               int _rows, int _columns,
                               complex_long_double _sum[])
        {cvecvaddd (_matrix_a, _matrix_b, _sum, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void cmatmadd_fr16 (const complex_fract16 _matrix_a[],
                                   const complex_fract16 _matrix_b[],
                                   int _rows, int _columns,
                                   complex_fract16 _sum[])
        {cvecvadd_fr16 (_matrix_a, _matrix_b, _sum, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatmadd_fr32 (const complex_fract32 _matrix_a[],
                                   const complex_fract32 _matrix_b[],
                                   int _rows, int _columns,
                                   complex_fract32 _sum[])
        {cvecvadd_fr32 (_matrix_a, _matrix_b, _sum, _rows*_columns);}



/* * * *        cmatmsub      * * * *
 *
 *    complex matrix - complex matrix subtraction
 *
 */

#pragma inline
#pragma always_inline
        static void cmatmsubf (const complex_float _matrix_a[],
                               const complex_float _matrix_b[],
                               int _rows, int _columns,
                               complex_float _difference[])
        {cvecvsubf (_matrix_a, _matrix_b, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatmsub (const complex_double _matrix_a[],
                              const complex_double _matrix_b[],
                              int _rows, int _columns,
                              complex_double _difference[])
        {cvecvsub (_matrix_a, _matrix_b, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatmsubd (const complex_long_double _matrix_a[],
                               const complex_long_double _matrix_b[],
                               int _rows, int _columns,
                               complex_long_double _difference[])
        {cvecvsubd (_matrix_a, _matrix_b, _difference, _rows*_columns);}


#pragma inline
#pragma always_inline
        static void cmatmsub_fr16 (const complex_fract16 _matrix_a[],
                                   const complex_fract16 _matrix_b[],
                                   int _rows, int _columns,
                                   complex_fract16 _difference[])
        {cvecvsub_fr16 (_matrix_a, _matrix_b, _difference, _rows*_columns);}

#pragma inline
#pragma always_inline
        static void cmatmsub_fr32 (const complex_fract32 _matrix_a[],
                                   const complex_fract32 _matrix_b[],
                                   int _rows, int _columns,
                                   complex_fract32 _difference[])
        {cvecvsub_fr32 (_matrix_a, _matrix_b, _difference, _rows*_columns);}



/* * * *        cmatmmlt      * * * *
 *
 *    complex matrix multiplication
 *
 */

#pragma linkage_name __cmatmmltf
        void cmatmmltf (const complex_float _matrix_a[],
                        int _rows_a, int _columns_a,
                        const complex_float _matrix_b[],
                        int _columns_b,
                        complex_float _product[]);

#pragma linkage_name __cmatmmltd
        void cmatmmltd (const complex_long_double _matrix_a[],
                        int _rows_a, int _columns_a,
                        const complex_long_double _matrix_b[],
                        int _columns_b,
                        complex_long_double _product[]);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __cmatmmltf
#else
#pragma linkage_name __cmatmmltd
#endif
        void cmatmmlt (const complex_double _matrix_a[],
                       int _rows_a, int _columns_a,
                       const complex_double _matrix_b[],
                       int _columns_b,
                       complex_double _product[]);


#pragma linkage_name __cmatmmlt_fr16
        void cmatmmlt_fr16 (const complex_fract16 _matrix_a[],
                            int _rows_a, int _columns_a,
                            const complex_fract16 _matrix_b[],
                            int _columns_b,
                            complex_fract16 _product[]);

#pragma linkage_name __cmatmmlt_fr32
        void cmatmmlt_fr32 (const complex_fract32 _matrix_a[],
                            int _rows_a, int _columns_a,
                            const complex_fract32 _matrix_b[],
                            int _columns_b,
                            complex_fract32 _product[]);



/* * * *        transpm      * * * *
 *
 *    Transpose Matrix
 *
 */

#pragma linkage_name __transpm32
        void transpmf (const float _matrix[],
                       int _rows, int _columns,
                       float _transpose[]);

#pragma linkage_name __transpm64
        void transpmd (const long double _matrix[],
                       int _rows, int _columns,
                       long double _transpose[]);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __transpm32
#else
#pragma linkage_name __transpm64
#endif
        void transpm (const double _matrix[],
                      int _rows, int _columns,
                      double _transpose[]);


#pragma linkage_name __transpm16
        void transpm_fr16 (const fract16 _matrix[],
                           int _rows, int _columns,
                           fract16 _transpose[]);

#pragma linkage_name __transpm32
        void transpm_fr32 (const fract32 _matrix[],
                           int _rows, int _columns,
                           fract32 _transpose[]);


#ifdef __FIXED_POINT_ALLOWED
#pragma linkage_name __transpm16
        void transpm_fx16 (const _Fract _matrix[],
                           int _rows, int _columns,
                           _Fract _transpose[]);

#pragma linkage_name __transpm32
        void transpm_fx32 (const long _Fract _matrix[],
                           int _rows, int _columns,
                           long _Fract _transpose[]);
#endif



/* * * *        ctranspm      * * * *
 *
 *    Complex Transpose Matrix
 *
 */

#pragma linkage_name __transpm64
        void ctranspmf (const complex_float _matrix[],
                            int _rows, int _columns,
                            complex_float _transpose[]);

#pragma linkage_name __transpm128
        void ctranspmd (const complex_long_double _matrix[],
                            int _rows, int _columns,
                            complex_long_double _transpose[]);

#ifdef __DOUBLES_ARE_FLOATS__
#pragma linkage_name __transpm64
#else
#pragma linkage_name __transpm128
#endif
        void ctranspm (const complex_double _matrix[],
                       int _rows, int _columns,
                       complex_double _transpose[]);

#pragma linkage_name __transpm32
        void ctranspm_fr16 (const complex_fract16 _matrix[],
                            int _rows, int _columns,
                            complex_fract16 _transpose[]);

#pragma linkage_name __transpm64
        void ctranspm_fr32 (const complex_fract32 _matrix[],
                            int _rows, int _columns,
                            complex_fract32 _transpose[]);


#ifdef __cplusplus
 }      /* end extern "C" */
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif   /* __MATRIX_DEFINED  (include guard) */
