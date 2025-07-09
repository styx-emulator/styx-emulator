/*********************************************************************************

Copyright(c) 2005 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            This is the include file for the AD1871 ADC SPI driver.

*********************************************************************************/

#ifndef __ADI_AD1871_H__
#define __ADI_AD1871_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* ****************************************************************************
 *
 *
 * (c) Copyright Analog Devices Inc 2005
 *
 * ****************************************************************************
 */
#define SLEN_24 0x0017              // SPORT word length
/* ****************************************************************************
 * RESULT CODES
 * ****************************************************************************
 */
enum {
    ADI_AD1871_RESULT_START=ADI_AD1871_ENUMERATION_START // insure this order remains
};


/* ****************************************************************************
 * COMMAND CODES
 * ****************************************************************************
 */

enum {
    ADI_AD1871_CMD_START=ADI_AD1871_ENUMERATION_START,
    ADI_AD1871_CMD_SET_I2S_MODE                     //I2S Mode
};

// entry point
#ifndef ADI_AD1871_MODULE
extern ADI_DEV_PDD_ENTRY_POINT ADI_AD1871_EntryPoint;
#endif

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD1871_H__ */
