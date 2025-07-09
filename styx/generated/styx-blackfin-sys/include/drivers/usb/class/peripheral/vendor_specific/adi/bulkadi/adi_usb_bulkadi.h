/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_bulkadi.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            Provides the core functions of the usb bulk driver.

*********************************************************************************/

#ifndef _ADI_USB_BULKADI_H_
#define _ADI_USB_BULKADI_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* entry point to the device driver */
extern ADI_DEV_PDD_ENTRY_POINT ADI_USB_VSBulk_Entrypoint;

typedef struct ObjectInfo
{
  int ID;
  void *pObj;
}OBJECT_INFO,*POBJECT_INFO;

typedef struct VendorSpecificDeviceData {
ADI_DEV_DEVICE_HANDLE   DeviceHandle;
ADI_DMA_MANAGER_HANDLE  DMAHandle;
ADI_DCB_CALLBACK_FN     DMCallback;
ADI_DCB_HANDLE          DCBHandle;
ADI_DEV_DIRECTION       Direction;
bool                    Open;
bool                    Started;
void                    *CriticalData;
ADI_DEV_DEVICE_HANDLE   PeripheralDevHandle;
int                     DeviceID;
OBJECT_INFO             ConfigObject;
OBJECT_INFO             InterfaceObjects[3];
OBJECT_INFO             AltInterfaceObjects[2];
OBJECT_INFO             EndPointObjects[2];
OBJECT_INFO             OtherSpeedConfigObject;
OBJECT_INFO             OtherSpeedInterfaceObjects[3];
OBJECT_INFO             OtherSpeedEndPointObjects[2];
bool                    IsClassConfigured;
int                     busSpeed;
}VENDORSPECIFIC_DEV_DATA;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_BULKADI_H_ */
