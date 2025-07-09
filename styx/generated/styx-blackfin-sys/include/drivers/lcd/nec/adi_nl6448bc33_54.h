/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
            This is the include file for the ADI_NL6448BC33_54 LCD driver.

*********************************************************************************/

#ifndef __ADI_NL6448BC33_54_H__
#define __ADI_NL6448BC33_54_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */


/* ****************************************************************************
 *
 *
 * (c) Copyright Analog Devices Inc 2006
 *
 * ****************************************************************************
 */

/* ****************************************************************************
 * RESULT CODES
 * ****************************************************************************
 */
enum {
    ADI_NL6448BC3354_RESULT_START=ADI_NL6448BC3354_ENUMERATION_START,// insure this order remains
    ADI_NL6448BC3354_RESULT_BAD_PPI_DEVICE
};


/* ****************************************************************************
 * COMMAND CODES
 * ****************************************************************************
 */

enum {
    ADI_NL6448BC3354_CMD_START=ADI_NL6448BC3354_ENUMERATION_START,
    ADI_NL6448BC3354_CMD_OPEN_PPI,
    ADI_NL6448BC3354_GET_TOP_PADDING
};

// entry point

extern ADI_DEV_PDD_ENTRY_POINT ADI_NL6448BC3354_EntryPoint;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
