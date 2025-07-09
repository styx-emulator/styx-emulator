/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ramdisk.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the include file for the ADI RAM Disk PID

***********************************************************************/

#ifndef __ADI_RAMDISK_H__
#define __ADI_RAMDISK_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* The following is omitted when included in the driver source module */
#if !defined(__ADI_RAMDISK_C__)

/*********************************************************************
Entry point to the RAM Disk PID
*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADI_RAMDISK_Entrypoint;


#endif /* __ADI_RAMDISK_C__ */

/*********************************************************************
RAM Disk Driver specific control commands
*********************************************************************/

enum {
    ADI_RAMDISK_CMD_START = ADI_PID_CUSTOM_CMD_START,       /* (0x000AA000) */
    ADI_RAMDISK_CMD_SET_RAMDISK_START_LOCATION,             /* (0x000AA001) */
    ADI_RAMDISK_CMD_SET_SIZE,                               /* (0x000AA002) */
    ADI_RAMDISK_CMD_SET_USB_DELAY                           /* (0x000AA003) */
};

/*********************************************************************
Prototype for configuration function.

    Pass the pointer returned by this function to the FSS with the
    adi_fss_RegisterDevice() function, or the ADI_FSS_REGISTER_DEVICE
    command.

*********************************************************************/

ADI_FSS_DEVICE_DEF *ConfigRamDiskFssDeviceDef(
                            u8                      *pRamDiskFrame,     /* Pointer to memory to use as RAM */
                            u32                     nRamDiskSize,       /* Size (bytes) of RAM Disk array  */
                            ADI_DEV_MANAGER_HANDLE  hDevMgrHandle,      /* Device Manager Handle */
                            ADI_DCB_HANDLE          hDcbHandle,         /* DCB Queue handle */
                            u32                     nUsbDelay           /* Delay (microseconds) for USB connectivity */
);

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif      /* __ADI_RAMDISK_H__   */
