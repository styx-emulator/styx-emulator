/* ymath.h internal header */
#if defined (_ADI_COMPILER)
/************************************************************************
 *
 * ymath.h
 *
 * (c) Copyright 2002-2009 Analog Devices, Inc.  All rights reserved.
 * (c) Copyright 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * $Revision: 3524 $
 ************************************************************************/
#endif /* _ADI_COMPILER */

#ifndef _YMATH
#define _YMATH
#include <yvals.h>

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(push)
#pragma diag(suppress:misra_rule_5_2:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_3:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_4:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_5:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_6:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_8_8:"ADI header- prototypes defined twice")
#pragma diag(suppress:misra_rule_12_2:"ADI header use of union with float")
#pragma diag(suppress:misra_rule_12_12:"ADI header use of union with float")
#pragma diag(suppress:misra_rule_16_3:"Dinkumware header, identifiers not needed on all parameters")
#pragma diag(suppress:misra_rule_18_4)
#pragma diag(suppress:misra_rule_19_4)
#endif /* _ADI_COMPILER && _MISRA_RULES */

_C_STD_BEGIN
_C_LIB_DECL

		/* MACROS FOR _FPP_TYPE */
#define _FPP_NONE	0	/* software emulation of FPP */
#define _FPP_X86	1	/* Intel Pentium */
#define _FPP_SPARC	2	/* Sun SPARC */
#define _FPP_MIPS	3	/* SGI MIPS */
#define _FPP_S390	4	/* IBM S/390 */
#define _FPP_PPC	5	/* Motorola PowerPC */
#define _FPP_HPPA	6	/* Hewlett-Packard PA-RISC */
#define _FPP_ALPHA	7	/* Compaq Alpha */
#define _FPP_ARM	8	/* ARM ARM */
#define _FPP_M68K	9	/* Motorola 68xxx */
#define _FPP_SH4	10	/* Hitachi SH4 */
#define _FPP_IA64	11	/* Intel IA64 */
#define _FPP_WIN	12	/* Microsoft Windows */

		/* MACROS FOR _Dtest RETURN (0 => ZERO) */
#define _DENORM		(-2)	/* C9X only */
#define _FINITE		(-1)
#define _INFCODE	1
#define _NANCODE	2

		/* MACROS FOR _Feraise ARGUMENT */

#if defined (_ADI_COMPILER)
  /* Removed all other platform specific _Feraise macro settings
   * except for the Pentium setting which the ADI targets will also
   * use.
   */
  #define _FE_DIVBYZERO	0x04	/* dummy same as Pentium */
  #define _FE_INEXACT	0x20
  #define _FE_INVALID	0x01
  #define _FE_OVERFLOW	0x08
  #define _FE_UNDERFLOW	0x10
#endif /* _ADI_COMPILER */

		/* TYPE DEFINITIONS */
typedef union
	{	/* pun float types as integer array */
#if defined (_ADI_COMPILER) && defined(__ADSP21000__)
        unsigned int   _Word[2];

#elif defined (_ADI_COMPILER) && defined(__ADSPBLACKFIN__)
                /* Use short to match Dinkum sources    */
        unsigned short _Word[4];
#else
	unsigned short _Word[8];
#endif /* _ADI_COMPILER */
	float _Float;
	double _Double;
	long double _Long_double;
	} _Dconst;

		/* ERROR REPORTING */
void _Feraise(int);

		/* double DECLARATIONS */
#if defined (_ADI_COMPILER) && defined(__DOUBLES_ARE_FLOATS__) \
                            && !defined(__ADSPBLACKFIN__)
#pragma linkage_name __FCosh
#endif
double _Cosh(double, double);
#if defined (_ADI_COMPILER) && defined(__DOUBLES_ARE_FLOATS__)
#pragma linkage_name __FDtest
#else
#pragma linkage_name __LDtest
#endif
short _Dtest(double *);
short _Exp(double *, double, long);
#if defined (_ADI_COMPILER) && defined(__DOUBLES_ARE_FLOATS__) \
                            && !defined(__ADSPBLACKFIN__)
#pragma linkage_name __FLog
#endif
double _Log(double, int);
#if defined (_ADI_COMPILER) && defined(__DOUBLES_ARE_FLOATS__) \
                            && !defined(__ADSPBLACKFIN__)
#pragma linkage_name __FSin
#endif
double _Sinh(double, double);
#if defined (_ADI_COMPILER) && defined(__DOUBLES_ARE_FLOATS__) \
                            && !defined(__ADSPBLACKFIN__)
#pragma linkage_name __FSinh
#endif
double _Sinh(double _d1, double _d2);

extern /* const */ _Dconst _Denorm, _Hugeval, _Inf,
	_Nan, _Snan;

		/* float DECLARATIONS */
float _FCosh(float, float);
short _FDtest(float *);
short _FExp(float *, float, long);
float _FLog(float, int);
float _FSin(float, unsigned int);
float _FSinh(float, float);
#if defined (_ADI_COMPILER)
/* Make these explicitly const */
extern const _Dconst _FDenorm, _FHugeval, _FInf, _FNan, _FSnan;
#else
extern /* const */ _Dconst _FDenorm, _FInf, _FNan, _FSnan;
#endif

		/* long double DECLARATIONS */
long double _LCosh(long double, long double);
short _LDtest(long double *);
short _LExp(long double *, long double, long);
long double _LLog(long double, int);
long double _LSin(long double, unsigned int);
long double _LSinh(long double, long double);
#if defined (_ADI_COMPILER)
/* Make these explicitly const */
extern const _Dconst _LDenorm, _LHugeval, _LInf, _LNan, _LSnan;
#else
extern /* const */ _Dconst _LDenorm, _LInf, _LNan, _LSnan;
#endif

 #if defined(__SUNPRO_CC)	/* compiler test */
float fmodf(float, float);
long double fmodl(long double, long double);
 #endif /* defined(__SUNPRO_CC) */

 #if defined(__BORLANDC__)	/* compiler test */
float fmodf(float, float);
float logf(float);
 #endif /* defined(__BORLANDC__) */

_END_C_LIB_DECL
_C_STD_END

#if defined (_ADI_COMPILER) && defined (_MISRA_RULES)
#pragma diag(pop)
#endif /* _ADI_COMPILER && _MISRA_RULES */

#endif /* _YMATH */

/*
 * Copyright (c) 1992-2008 by P.J. Plauger.  ALL RIGHTS RESERVED.
 * Consult your license regarding permissions and restrictions.
V5.03:1134 */
