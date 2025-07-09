/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the include file for the ADI USB Host mass storage class PID

***********************************************************************/

#ifndef __ADI_USB_H__
#define __ADI_USB_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* The following is omitted when included in the driver source module */
#if !defined(__ADI_USB_HOST_C__)

/*********************************************************************

Entry point to the USB PID

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADI_USB_Entrypoint;

/*********************************************************************

The following is the default configuration for the USB driver.
To use, define the _ADI_USB_DEFAULT_DEF_ macro in the enclosing file

*********************************************************************/
#if defined(_ADI_USB_DEFAULT_DEF_)

static ADI_FSS_DEVICE_DEF ADI_USB_Def = {
    0,                                          /* Not Applicable                           */
    &ADI_USB_Entrypoint,                        /* Entry Points for Driver                  */
    NULL,                                       /* Command Table to configure USB Driver    */
    NULL,                                       /* Critical region data                     */
    ADI_DEV_DIRECTION_BIDIRECTIONAL,            /* Direction (RW media)                     */
    NULL                                        /* Device Handle                            */
};

#endif /* _ADI_USB_DEFAULT_DEF_ */

#endif /* __ADI_USB_HOST_C__ */

/*********************************************************************

USB Driver specific control commands

*********************************************************************/

enum {
    ADI_USB_CMD_START = ADI_PID_CUSTOM_CMD_START,       /* (0x000AA000) */
    ADI_USB_CMD_SET_MEMDMA_HANDLE,
    ADI_USB_CMD_SET_CONTROLLER_DRIVER_HANDLE,
    ADI_USB_CMD_SET_CLASS_DRIVER_HANDLE,
    ADI_USB_CMD_SET_MEDIA_DETECTION_CALLBACK
    /* USB Host I/O related commands - to be added in future */
};

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif      /* __ADI_USB_H__   */
