/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_atapi.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the ATA/ATAPI IDE PID driver .

*********************************************************************************/

#ifndef __ADI_ATAPI_H__
#define __ADI_ATAPI_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <services/services.h>
#include <drivers/adi_dev.h>
#include <services/fss/adi_fss.h>
#include <drivers/pid/adi_ata.h>
#include <string.h>

/* The following is omitted when included in the driver source module */
#if !defined(__ADI_ATAPI_C__)

/* entry point to the device driver */
extern ADI_DEV_PDD_ENTRY_POINT ADI_ATAPI_EntryPoint;


/*******************************************************************
* The following is the default configuration for the ATAPI IDE
* driver. To use, define the _ADI_ATAPI_ATAPI_DEFAULT_DEF_
* macro in the enclosing file
*******************************************************************/
#if defined(_ADI_ATAPI_DEFAULT_DEF_)

/*******************************************************************
* definition structure for the ATA/ATAPI driver
*******************************************************************/
static ADI_FSS_DEVICE_DEF ADI_ATAPI_Def = {
    0,                                      /* Not Applicable                           */
    &ADI_ATAPI_EntryPoint,                  /* Entry Points for Driver                  */
    NULL,                                   /* Command Table to configure EZ-LAN Driver */
    NULL,                                   /* Critical region data                     */
    ADI_DEV_DIRECTION_BIDIRECTIONAL,        /* Direction (RW media)                     */
    NULL                                    /* Device Handle                            */
};
#endif /* _ADI_ATAPI_DEFAULT_DEF_ */

#endif /* __ADI_ATAPI_C__ */


/*******************************************************************
* Device Specific control commands
*******************************************************************/
enum {
    ADI_ATAPI_CMD_START = ADI_PID_CUSTOM_CMD_START,   /* (0x000AA000) */
    ADI_ATAPI_CMD_FORCE_MDMA,                         /* (0x000AA001) Override UDMA mode with MDMA         */
    ADI_ATAPI_CMD_FORCE_PIO,                          /* (0x000AA002) Override UDMA and MDMA with PIO DMA  */
    ADI_ATAPI_CMD_RUN_POST
};

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_ATAPI_H__ */
