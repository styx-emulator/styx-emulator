/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: services.h,v $
$Revision: 3682 $
$Date: 2010-11-01 16:56:32 -0400 (Mon, 01 Nov 2010) $

Description:
            This is the include file for the System Services Library

*********************************************************************************/


#ifndef __SERVICES_H__
#define __SERVICES_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Identify processor core by family

*********************************************************************/

#if defined(__ADSPBF531__) || defined(__ADSPBF532__) || defined(__ADSPBF533__)

#ifndef __ADSP_EDINBURGH__
#define __ADSP_EDINBURGH__
#endif

#elif defined(__ADSPBF534__) || defined(__ADSPBF536__) || defined(__ADSPBF537__)
#ifndef __ADSP_BRAEMAR__
#define __ADSP_BRAEMAR__
#endif

#elif defined(__ADSPBF538__) || defined(__ADSPBF539__)

#ifndef __ADSP_STIRLING__
#define __ADSP_STIRLING__
#endif

#elif defined(__ADSPBF542__) || defined(__ADSPBF544__) || defined(__ADSPBF547__) || defined(__ADSPBF548__) || defined(__ADSPBF549__) \
|| defined(__ADSPBF542M__) || defined(__ADSPBF544M__) || defined(__ADSPBF547M__) || defined(__ADSPBF548M__) || defined(__ADSPBF549M__)



#ifndef __ADSP_MOAB__
#define __ADSP_MOAB__
#endif

#elif defined(__ADSPBF523__) || defined(__ADSPBF525__) || defined(__ADSPBF527__)

#ifndef __ADSP_KOOKABURRA__
#define __ADSP_KOOKABURRA__
#endif

#elif defined(__ADSPBF522__) || defined(__ADSPBF524__) || defined(__ADSPBF526__)

#ifndef __ADSP_MOCKINGBIRD__
#define __ADSP_MOCKINGBIRD__
#endif

#elif defined(__ADSPBF512__) || defined(__ADSPBF514__) || defined(__ADSPBF516__) || defined(__ADSPBF518__)

#ifndef __ADSP_BRODIE__
#define __ADSP_BRODIE__
#endif

#elif defined(__ADSPBF504__) || defined(__ADSPBF504F__) || defined(__ADSPBF506F__)

#ifndef __ADSP_MOY__
#define __ADSP_MOY__
#endif

#elif defined(__ADSPBF590__) || defined(__ADSPBF592__)

#ifndef __ADSP_DELTA__
#define __ADSP_DELTA__
#endif

#elif defined(__ADSPBF561__)

#ifndef __ADSP_TETON__
#define __ADSP_TETON__
#endif

#endif

/*********************************************************************

Insure the services support the given processor family

*********************************************************************/

#if defined(__ADSP_EDINBURGH__)     ||\
    defined(__ADSP_BRAEMAR__)       ||\
    defined(__ADSP_TETON__)         ||\
    defined(__ADSP_STIRLING__)      ||\
    defined(__ADSP_MOAB__)          ||\
    defined(__ADSP_KOOKABURRA__)    ||\
    defined(__ADSP_MOCKINGBIRD__)   ||\
    defined(__ADSP_BRODIE__)        ||\
    defined(__ADSP_MOY__)           ||\
    defined(__ADSP_DELTA__)

#else
#error "*** System Services do not yet support this processor ***"
#endif


/*********************************************************************

Set up typedefs and common use macros

*********************************************************************/

/* integer typedefs - for all modules */
#include <services_types.h>

/* TRUE, FALSE and NULL */

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#if !defined(_LANGUAGE_ASM)

#include <stdbool.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

#endif


/*********************************************************************

create macros to determine which core we're on for Teton

*********************************************************************/

#if defined(__ADSP_TETON__)

#define ADI_COREA (0xFF800000)
#define ADI_COREB (0xFFF00000)
#if !defined(_LANGUAGE_ASM)
#define ADI_SRAM_BASE_ADDR_MMR ((u32 *)0xFFE00000)
#else
#define ADI_SRAM_BASE_ADDR_MMR (0xFFE00000)
#endif
#endif




#if !defined(_LANGUAGE_ASM)

#include <sys/exception.h>          /* interrupt handler defines */
#include <stddef.h>

#endif

#if defined(__ECC__) || defined(_LANGUAGE_ASM)

#if defined(__ADSP_EDINBURGH__)
#if defined(_LANGUAGE_ASM)
#include <defBF532.h>
#else
#include <cdefBF532.h>
#include <ccblkfn.h>
#endif

#elif defined(__ADSP_BRAEMAR__)
#if defined(_LANGUAGE_ASM)
#include <defBF537.h>
#else
#include <cdefBF537.h>
#include <ccblkfn.h>
#endif

#elif defined(__ADSP_STIRLING__)
#if defined(_LANGUAGE_ASM)
#if defined(__ADSPBF538__)
#include <defBF538.h>
#endif
#if defined(__ADSPBF539__)
#include <defBF539.h>
#endif
#else   /* end of assembly */
#if defined(__ADSPBF538__)
#include <cdefBF538.h>
#endif
#if defined(__ADSPBF539__)
#include <cdefBF539.h>
#endif
#include <ccblkfn.h>
#endif

#elif defined(__ADSP_MOAB__)

#if defined(_LANGUAGE_ASM)

#if defined(__ADSPBF542__)
#include <defBF542.h>
#endif
#if defined(__ADSPBF544__)
#include <defBF544.h>
#endif
#if defined(__ADSPBF547__)
#include <defBF547.h>
#endif
#if defined(__ADSPBF548__)
#include <defBF548.h>
#endif
#if defined(__ADSPBF549__)
#include <defBF549.h>
#endif
#if defined(__ADSPBF542M__)
#include <defBF542M.h>
#endif
#if defined(__ADSPBF544M__)
#include <defBF544M.h>
#endif
#if defined(__ADSPBF547M__)
#include <defBF547M.h>
#endif
#if defined(__ADSPBF548M__)
#include <defBF548M.h>
#endif
#if defined(__ADSPBF549M__)
#include <defBF549M.h>
#endif

#else

#if defined(__ADSPBF542__)
#include <cdefBF542.h>
#endif
#if defined(__ADSPBF544__)
#include <cdefBF544.h>
#endif
#if defined(__ADSPBF547__)
#include <cdefBF547.h>
#endif
#if defined(__ADSPBF548__)
#include <cdefBF548.h>
#endif
#if defined(__ADSPBF549__)
#include <cdefBF549.h>
#endif
#if defined(__ADSPBF542M__)
#include <cdefBF542M.h>
#endif
#if defined(__ADSPBF544M__)
#include <cdefBF544M.h>
#endif
#if defined(__ADSPBF547M__)
#include <cdefBF547M.h>
#endif
#if defined(__ADSPBF548M__)
#include <cdefBF548M.h>
#endif
#if defined(__ADSPBF549M__)
#include <cdefBF549M.h>
#endif
#include <ccblkfn.h>
#endif

#elif defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)
#if defined(_LANGUAGE_ASM)
#if defined(__ADSPBF522__)
#include <defBF522.h>
#endif
#if defined(__ADSPBF523__)
#include <defBF523.h>
#endif
#if defined(__ADSPBF524__)
#include <defBF524.h>
#endif
#if defined(__ADSPBF525__)
#include <defBF525.h>
#endif
#if defined(__ADSPBF526__)
#include <defBF526.h>
#endif
#if defined(__ADSPBF527__)
#include <defBF527.h>
#endif
#else
#if defined(__ADSPBF522__)
#include <cdefBF522.h>
#endif
#if defined(__ADSPBF523__)
#include <cdefBF523.h>
#endif
#if defined(__ADSPBF524__)
#include <cdefBF524.h>
#endif
#if defined(__ADSPBF525__)
#include <cdefBF525.h>
#endif
#if defined(__ADSPBF526__)
#include <cdefBF526.h>
#endif
#if defined(__ADSPBF527__)
#include <cdefBF527.h>
#endif
#include <ccblkfn.h>
#endif

#elif defined(__ADSP_BRODIE__)
#if defined(_LANGUAGE_ASM)
#if defined(__ADSPBF512__)
#include <defBF512.h>
#endif
#if defined(__ADSPBF514__)
#include <defBF514.h>
#endif
#if defined(__ADSPBF516__)
#include <defBF516.h>
#endif
#if defined(__ADSPBF518__)
#include <defBF518.h>
#endif
#else
#if defined(__ADSPBF512__)
#include <cdefBF512.h>
#endif
#if defined(__ADSPBF514__)
#include <cdefBF514.h>
#endif
#if defined(__ADSPBF516__)
#include <cdefBF516.h>
#endif
#if defined(__ADSPBF518__)
#include <cdefBF518.h>
#endif
#include <ccblkfn.h>
#endif

#elif defined(__ADSP_MOY__)
#if defined(_LANGUAGE_ASM)
#if defined(__ADSPBF504__)
#include <defBF504.h>
#endif
#if defined(__ADSPBF504F__)
#include <defBF504F.h>
#endif
#if defined(__ADSPBF506F__)
#include <defBF506F.h>
#endif
#else
#if defined(__ADSPBF504__)
#include <cdefBF504.h>
#endif
#if defined(__ADSPBF504F__)
#include <cdefBF504F.h>
#endif
#if defined(__ADSPBF506F__)
#include <cdefBF506F.h>
#endif
#include <ccblkfn.h>
#endif

#elif defined(__ADSP_DELTA__)
#if defined(_LANGUAGE_ASM)
#if defined(__ADSPBF592__)
#include <defBF592-A.h>
#endif
#else
#if defined(__ADSPBF592__)
#include <cdefBF592-A.h>
#endif
#include <ccblkfn.h>
#endif

#elif defined(__ADSPBF561__)
#if defined(_LANGUAGE_ASM)
#include <defBF561.h>
#else
#include <cdefBF561.h>
#include <ccblkfn.h>
#endif
#endif

#elif defined(__ghs__)
#include <bf/cdefBF533.h>
#include <bf/ccblkfn.h>
/* macros for certain ops */
#define idle()  asm("IDLE;")
#define ssync() asm("SSYNC;")
#define csync() asm("CSYNC;")
#elif defined(__GNUC__)
#include <cdefBF533.h>
#include <ccblkfn.h>
#else
#error "System Services Library is not supported for this compiler"
#endif


/*********************************************************************

Define the starting points for enumerations within the services.  This
insures that the enumeration values for each of the services do not
overlap with one another.  This only applies to items such as command IDs,
event IDs, and return codes.  Note that the return code from each service
for generic success is always 0, while the return code from each service
for generic failure is always 1, regardless of the enumeration starting
point.

*********************************************************************/

/* Physical Device Drivers Enumeration start */
#define ADI_DEV_ENUMERATION_START           (0x40000000)
/* Device Class Drivers Enumeration start */
#define ADI_DEV_CLASS_ENUMERATION_START     (0x50000000)

/* Deferred Callkback Manager Enumeration start */
#define ADI_DCB_ENUMERATION_START           (0x00020000)
/* DMA Manager Enumeration start */
#define ADI_DMA_ENUMERATION_START           (0x00030000)
/* EBIU Manager Enumeration start */
#define ADI_EBIU_ENUMERATION_START          (0x00040000)
/* Interrupt Manager Enumeration start */
#define ADI_INT_ENUMERATION_START           (0x00050000)
/* Power Service Enumeration start */
#define ADI_PWR_ENUMERATION_START           (0x00060000)
/* Timer Service Enumeration start */
#define ADI_TMR_ENUMERATION_START           (0x00070000)
/* Flag Control Service Enumeration start */
#define ADI_FLAG_ENUMERATION_START          (0x00080000)
/* Port Control Service Enumeration start */
#define ADI_PORTS_ENUMERATION_START         (0x00090000)
/* Real Time Clock Service Enumeration start */
#define ADI_RTC_ENUMERATION_START           (0x000a0000)
/* File System Service Enumeration start */
#define ADI_FSS_ENUMERATION_START           (0x000b0000)
/* Semaphore Service Enumeration start */
#define ADI_SEM_ENUMERATION_START           (0x000c0000)
/* Reserved Enumeration start */
#define ADI_RES1_ENUMERATION_START          (0x000d0000)
/* Reserved Enumeration start */
#define ADI_RES2_ENUMERATION_START          (0x000e0000)
/* Reserved Enumeration start */
#define ADI_RES3_ENUMERATION_START          (0x000f0000)
/* PWM Module Enumeration start */
#define ADI_PWM_ENUMERATION_START           (0x00100000)
/* ACM Module Enumeration start */
#define ADI_ACM_ENUMERATION_START           (0x00110000)
/* STDIO Module Enumeration start */
#define ADI_STDIO_ENUMERATION_START         (0x00120000)

/*********************************************************************

Pull in the individual include files.

*********************************************************************/

/* Guard to prevent adi_types.h to include the definition of float64_t because
   of an conflict with a definition in the SW modules. This is temporary and
   should be removed when the modules have upgraded to use adi_types.h */
#define __NO_FLOAT64

#include <services/int/adi_int.h>
#include <services/dcb/adi_dcb.h>
#include <services/dma/adi_dma.h>

#if !defined(__ADSP_MOY__) || !defined(__ADSP_DELTA__)
#include <services/ebiu/adi_ebiu.h>
#include <services/rtc/adi_rtc.h>
#endif

#include <services/pwr/adi_pwr.h>
#include <services/tmr/adi_tmr.h>
#include <services/flag/adi_flag.h>
#include <services/ports/adi_ports.h>
#include <services/sem/adi_sem.h>
#if defined(__ADSP_BRODIE__)  || defined(__ADSP_MOY__)
#include <services/pwm/adi_pwm.h>
#endif

#if defined(__ADSP_MOY__)
#include <services/acm/adi_acm.h>
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __SERVICES_H__ */
