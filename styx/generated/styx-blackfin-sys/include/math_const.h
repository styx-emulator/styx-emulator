/************************************************************************
 *
 * math_const.h
 *
 * (c) Copyright 2002-2008 Analog Devices, Inc.  All rights reserved.
 * $Revision: 3522 $
 ************************************************************************/

#ifndef _MATH_CONST_H
#define _MATH_CONST_H

/* WARNING:
 *
 * The header file math_const.h is used to build the mathematical functions
 * of the C and DSP run-time libraries and may therefore be modified without
 * warning. Analog therefore recommends that users do not include this header
 * file in their projects or applications.
 *
*/

#include <float.h>

#ifdef _MISRA_RULES
#pragma diag(push)
#pragma diag(suppress:misra_rule_19_4:"ADI header allows any substitution")
#pragma diag(suppress:misra_rule_19_7:"ADI header requires function macros")
#endif /* _MISRA_RULES */


/* definitions */
#define TWO_PI              ( 6.283185307179586476925286766559L)
#define FOUR_PI             (12.566370614359172953850573533118L)
#define SIX_PI              (18.849555921538759430775860299677L)
#define PI                  ( 3.1415926535897932384626433832795L)
#define PI_2                ( 1.5707963267948966192313216916398L)
#define PI_3                ( 1.0471975511965977461542144610932L)
#define PI_4                ( 0.78539816339744830961566084581988L)
#define PI_6                ( 0.52359877559829887307710723054658L)

#define INV_PI              ( 0.31830988618379067153776752674503L)
#define INV_PI_2            ( 0.63661977236758134307553505349006L)

/* 9 bit accurate PI  */
#define PI_C1               ( 3.140625F)
#define PI_C2               ( 9.670257568359375e-4F)
#define PI_C3               ( 6.27832957300962643383279502884e-7F)

/* 25 bit accurate PI */
#define PI_DC1              ( 3.1416015625L)
#define PI_DC2              (-8.90891033122898079454898834228e-6L)
#define PI_DC3              ( 1.2446744343793226784516935341e-13L)

/* 9-bit accurate pi/2 */
#define PI_2_C1             ( 1.5703125F)
#define PI_2_C2             ( 4.84466552734375e-4F)
#define PI_2_C3             (-6.39757837755768678308360248557e-7F)

/* 25 bit accurate PI/2 */
#define PI_2_DC1            ( 1.57080078125L)
#define PI_2_DC2            (-4.45445516561449039727449417114e-6L)
#define PI_2_DC3            ( 6.2233721718966133922584676705e-14L)

#define LN2                 ( 0.69314718055994530941723212145818L)
#define INV_LN2             ( 1.4426950408889634073599246810019L)

#define LN2_C1              ( 0.6875F)
#define LN2_C2              ( 5.647180560e-3F)

#define LN2_DC1             ( 0.693359375L)
#define LN2_DC2             (-2.121944400e-4L)
#define LN2_DC3             (-5.46905827678e-14L)

#define LN_V                ( 0.6931610107421875000L)
#define V_2_MINUS1          ( 1.3830277879601902638e-5L)

#define LN3_2               ( 0.54930614433405484569762261846126L)

#define LN_E                ( 0.43429448190325182765112891891661L)

#define LOG2E_MINUS1        ( 0.44269504088896340735992468100189L)

#define LOGE_10             ( 2.302585092994046e+0L)

#define TWO_MINUS_ROOT3     ( 0.26794919243112270647255365849413L)
#define SQRT3_MINUS_1       ( 0.73205080756887729352744634150587L)
#define SQRT3               ( 1.7320508075688772935274463415059L)
#define ROOT_HALF           ( 0.70710678118654752440084436210485F)
#define ROOTDOUBLE_HALF     ( 0.70710678118654752440084436210485L)

#define EPS_FLOAT           (+3.452669830012e-4F)
#define EPS_DOUBLE          (+1.490116119385e-8L)
#define X_MAX               (+9.099024257348e3L)
#define X_MAX_EXP           (+88.722839F)
#define X_MIN_EXP           (-87.336544F)
#define XDOUBLE_MAX_EXP     (+709.7827128934L)
#define XDOUBLE_MIN_EXP     (-708.3964185323L)
#define TANH_BIGNUM         (+8.317766166719F)
#define TANHDOUBLE_BIGNUM   (+18.36840028484L)
#define POW_BIGNUM          (+2046.0F)
#define POW_SMALLNUM        (-2015.0F)
#define POWDOUBLE_BIGNUM    (+16382.0L)
#define POWDOUBLE_SMALLNUM  (-16350.0L)

#define SIN32_X_MAX         (   102940.0F)       /* 2^15 * PI */
#define SIN40_X_MAX         (  1647095.0F)       /* 2^19 * PI */
#define SIN64_X_MAX         (843314852.0L)       /* 2^28 * PI */
#define COS32_X_MAX         (SIN32_X_MAX)
#define COS40_X_MAX         (SIN40_X_MAX)
#define COS64_X_MAX         (SIN64_X_MAX)
#define TAN32_X_MAX         (    51471.0F)       /* 2^15 * PI/2 */
#define TAN40_X_MAX         (  6588397.0F)       /* 2^22 * PI/2 */
#define TAN64_X_MAX         (421657424.0L)       /* 2^28 * PI/2 */
#define COT32_X_MAX         (TAN32_X_MAX)
#define COT40_X_MAX         (TAN40_X_MAX)
#define COT64_X_MAX         (TAN64_X_MAX)


/* coefficients used for sin/cos */

#define SINF_COEF1    (-0.1666665668e+0F)
#define SINF_COEF2    (+0.8333025139e-2F)
#define SINF_COEF3    (-0.1980741872e-3F)
#define SINF_COEF4    (+0.2601903036e-5F)

#define SIND_COEF1    (-1.6666666666666665052e-1L)
#define SIND_COEF2    (+8.3333333333331650314e-3L)
#define SIND_COEF3    (-1.9841269841201840457e-4L)
#define SIND_COEF4    (+2.7557319210152756119e-6L)
#define SIND_COEF5    (-2.5052106798274584544e-8L)
#define SIND_COEF6    (+1.6058936490371589114e-10L)
#define SIND_COEF7    (-7.6429178068910467734e-13L)
#define SIND_COEF8    (+2.7204790957888846175e-15L)

/* coefficients used for tan/cot */

#define TANP_COEF1    (-1.113614403566e-1F)
#define TANP_COEF2    (+1.075154738488e-3F)
#define TANQ_COEF0    (+1.000000000000F)
#define TANQ_COEF1    (-4.446947720281e-1F)
#define TANQ_COEF2    (+1.597339213300e-2F)

#define TANDP_COEF1   (-1.3338350006421960681e-1L)
#define TANDP_COEF2   (+3.4248878235890589960e-3L)
#define TANDP_COEF3   (-1.7861707342254424711e-5L)
#define TANDQ_COEF0   (+1.0000000000000000000L)
#define TANDQ_COEF1   (-4.6671683339755294240e-1L)
#define TANDQ_COEF2   (+2.5663832289440112864e-2L)
#define TANDQ_COEF3   (-3.1181531907010027307e-4L)
#define TANDQ_COEF4   (+4.9819433993786512270e-7L)

/* Coefficients used for asin/acos */
#define ASINP_COEF1   (-2.7516555290596F)
#define ASINP_COEF2   (+2.9058762374859F)
#define ASINP_COEF3   (-5.9450144193246e-1F)
#define ASINQ_COEF0   (-1.6509933202424e+1F)
#define ASINQ_COEF1   (+2.4864728969164e+1F)
#define ASINQ_COEF2   (-1.0333867072113e+1F)

#define ASINDP_COEF1  (-2.7368494524164255994e+1L)
#define ASINDP_COEF2  (+5.7208227877891731407e+1L)
#define ASINDP_COEF3  (-3.9688862997504877339e+1L)
#define ASINDP_COEF4  (+1.0152522233806463645e+1L)
#define ASINDP_COEF5  (-6.9674573447350646411e-1L)
#define ASINDQ_COEF0  (-1.6421096714498560795e+2L)
#define ASINDQ_COEF1  (+4.1714430248260412556e+2L)
#define ASINDQ_COEF2  (-3.8186303361750149284e+2L)
#define ASINDQ_COEF3  (+1.5095270841030604719e+2L)
#define ASINDQ_COEF4  (-2.3823859153670238830e+1L)

/* Coefficients used for atan/atan2 */
#define ATANP_COEF0   (-1.44008344874F)
#define ATANP_COEF1   (-7.20026848898e-1F)
#define ATANQ_COEF0   (+4.32025038919F)
#define ATANQ_COEF1   (+4.75222584599F)

#define ATANDP_COEF0  (-1.3688768894191926929e1L)
#define ATANDP_COEF1  (-2.0505855195861651981e1L)
#define ATANDP_COEF2  (-8.4946240351320683534L)
#define ATANDP_COEF3  (-8.3758299368150059274e-1L)
#define ATANDQ_COEF0  (+4.1066306682575781263e1L)
#define ATANDQ_COEF1  (+8.6157349597130242515e1L)
#define ATANDQ_COEF2  (+5.9578436142597344465e1L)
#define ATANDQ_COEF3  (+1.5024001160028576121e1L)

/* Coefficients used for exp */
#define EXPP_COEF0    (+2.4999999999992e-1F)
#define EXPP_COEF1    (+5.9504254977591e-3F)
#define EXPQ_COEF0    (+5.0000000000000e-1F)
#define EXPQ_COEF1    (+5.3567517645222e-2F)
#define EXPQ_COEF2    (+2.9729363682238e-4F)

#define EXPDP_COEF0   (+2.5000000000000000000e-1L)
#define EXPDP_COEF1   (+7.5753180159422776666e-3L)
#define EXPDP_COEF2   (+3.1555192765684646356e-5L)
#define EXPDQ_COEF0   (+5.0000000000000000000e-1L)
#define EXPDQ_COEF1   (+5.6817302698551221787e-2L)
#define EXPDQ_COEF2   (+6.3121894374398503557e-4L)
#define EXPDQ_COEF3   (+7.5104028399870046114e-7L)

/* Coefficients used for sinh / cosh */
#define SINHP_COEF0   (+1.0622288837151e3F)
#define SINHP_COEF1   (+3.1359756456058e1F)
#define SINHP_COEF2   (+3.4364140358506e-1F)
#define SINHQ_COEF0   (+6.3733733021822e3F)
#define SINHQ_COEF1   (-1.3051012509199e2F)

#define SINHDP_COEF0  (-3.5181283430177117881e5L)
#define SINHDP_COEF1  (-1.1563521196851768270e4L)
#define SINHDP_COEF2  (-1.6375798202630751372e2L)
#define SINHDP_COEF3  (-7.8966127417357099479e-1L)
#define SINHDQ_COEF0  (-2.1108770058106271242e6L)
#define SINHDQ_COEF1  (+3.6162723109421836460e4L)
#define SINHDQ_COEF2  (-2.7773523119650701667e2L)

/* Coefficients used for sqrt */
#define SQRTD_COEF1   ( 0.41731e0F)
#define SQRTD_COEF2   ( 0.59016e0F)

/* Coefficients used for tanh */
#define TANHP_COEF0   (-2.1063958000245e1F)
#define TANHP_COEF1   (-9.3363475652401e-1F)
#define TANHQ_COEF0   (+6.3191874015582e1F)
#define TANHQ_COEF1   (+2.8077653470471e1F)

#define TANHDP_COEF0  (-1.6134119023996228053e3L)
#define TANHDP_COEF1  (-9.9225929672236083313e1L)
#define TANHDP_COEF2  (-9.6437492777225469787e-1L)
#define TANHDQ_COEF0  (+4.8402357071988688686e3L)
#define TANHDQ_COEF1  (+2.2337720718962312926e3L)
#define TANHDQ_COEF2  (+1.1274474380534949335e2L)

/* Coefficients used for log/log10 */
#define LOGA_COEF0    (-4.649062303464e-1F)
#define LOGA_COEF1    (+1.360095468621e-2F)
#define LOGB_COEF0    (-5.578873750242F)

#define LOGDA_COEF0   (-6.4124943423745581147e1L)
#define LOGDA_COEF1   (+1.6383943563021534222e1L)
#define LOGDA_COEF2   (-7.8956112887491257267e-1L)
#define LOGDB_COEF0   (-7.6949932108494879777e2L)
#define LOGDB_COEF1   (+3.1203222091924532844e2L)
#define LOGDB_COEF2   (-3.5667977739034646171e1L)

/* Coefficients used for pow */
#define POWP_COEF1    (+8.33333286245e-2F)
#define POWP_COEF2    (+1.25064850052e-2F)

#define POWDP_COEF1   (+8.3333333333333211405e-2L)
#define POWDP_COEF2   (+1.2500000000503799174e-2L)
#define POWDP_COEF3   (+2.2321421285924258967e-3L)
#define POWDP_COEF4   (+4.3445775672163119635e-4L)

#define POWQ_COEF1    (+6.93147180556341e-1F)
#define POWQ_COEF2    (+2.40226506144710e-1F)
#define POWQ_COEF3    (+5.55040488130765e-2F)
#define POWQ_COEF4    (+9.61620659583789e-3F)
#define POWQ_COEF5    (+1.30525515942810e-3F)

#define POWDQ_COEF1   (+6.9314718055994529629e-1L)
#define POWDQ_COEF2   (+2.4022650695909537056e-1L)
#define POWDQ_COEF3   (+5.5504108664085595326e-2L)
#define POWDQ_COEF4   (+9.6181290595172416964e-3L)
#define POWDQ_COEF5   (+1.3333541313585784703e-3L)
#define POWDQ_COEF6   (+1.5400290440989764601e-4L)
#define POWDQ_COEF7   (+1.4928852680595608186e-5L)

/* macros */
#define REDUCE_FLOAT1(x, y, tmpflt, tmpint)     \
 do {                                           \
        (tmpflt) = MPY(16.0F, (x));             \
        (tmpint) = TO_LONG(tmpflt);             \
        (tmpflt) = TO_FLOAT(tmpint);            \
        (y) = MPY((tmpflt), 0.0625F);           \
    } while(0)

#define REDUCE_FLOAT2(x, y, tmpflt, tmpint)     \
 do {                                           \
        (tmpflt) = MPY(16.0F, (x));             \
        modff((tmpflt), &(y));                  \
        (y) = MPY((y), 0.0625F);                \
    } while(0)

#define REDUCE_FLOAT(x, y)                      \
 do {                                           \
        modff(MPY(16.0F, (x)), &(y));           \
        (y) = MPY((y), 0.0625F);                \
    } while(0)

#define REDUCE_DOUBLE(x, y)                     \
 do {                                           \
        modfd(MPYD(16.0L, (x)), &(y));          \
        (y) = MPYD((y), 0.0625L);               \
    } while(0)

#define REDUCE_DOUBLE1(x, y)                    \
    do {                                        \
        DOUBLE tmpd;                            \
        LONG tmpl;                              \
        tmpd = MPYD(16.0L, (x));                \
        tmpl = TO_LONG(tmpd);                   \
        tmpd = TO_DOUBLE(tmpl);                 \
        (y) = MPYD(tmpd, 0.0625L);              \
    } while(0)

#define REDUCE_DOUBLE1(x, y)                    \
    do {                                        \
        DOUBLE tmpd;                            \
        LONG tmpl;                              \
        tmpd = MPYD(16.0L, (x));                \
        tmpl = TO_LONG(tmpd);                   \
        tmpd = TO_DOUBLE(tmpl);                 \
        (y) = MPYD(tmpd, 0.0625L);              \
    } while(0)


#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _MATH_CONST_H */
