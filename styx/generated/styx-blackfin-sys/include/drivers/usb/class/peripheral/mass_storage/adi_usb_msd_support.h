/*********************************************************************************

Copyright(c) 2007 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_msd_support.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:

    This is the support code for the USB Mass
    Storage Class driver.

*********************************************************************************/

#ifndef _ADI_USB_MSD_SUPPORT_H_
#define _ADI_USB_MSD_SUPPORT_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#define BUFFER_RSVD_BUFFER_TYPE     5
#define BUFFER_TYPE_STATUS          1

#define LOBYTE(a) ((u8)a)
#define HIBYTE(a) ((u8)(a >> 8))

#define LOWORD(a) ((u16)a)
#define HIWORD(a) ((u16)(a >> 16))

bool adi_msd_IsTransferActive;
static bool adi_msd_IsDeviceConfigured = false;

COMMAND_STATUS_STATE  adi_msd_CommandStatusState;
CBW adi_msd_CurrentCBW;

u32 adi_msd_RemainingDataToComeIn;
u32 adi_msd_RemainingDataToShipUp;
u32 adi_msd_host_device_Residue;
u32 adi_msd_device_host_Residue;

#if defined(ADI_MSD_TEST)
pUSBcb  adi_msd_usbcb;
bool    adi_EP0_Done;
#endif

ADI_DEV_1D_BUFFER * adi_msd_pDataToShipUp;

static bool ProcessCBW (PCBW pCBW, ADI_DEV_1D_BUFFER * pBuffer);
static bool IsCBWMeaningful (PCBW pCBW);
static void SendDataToHost (void);
static bool ExtractCBW (PCBW pCBW, u8 *pBuffer);
static void BuildCSW (u8 *pBuffer, u32 tag, u32 dataResidue, u8 status);
static void MSReset (void);

void EndpointZeroCompleteCallback( void *Handle, u32 Event, void *pArg);
void EndpointCompleteCallback(void *Handle, u32 Event, void *pArg);
void Device_To_Host_TransferComplete(void *Handle, u32 Event, void *pBuf);
void Host_To_Device_TransferComplete(void *Handle, u32 Event, void *pBuf);


/* USB setup packet (USB spec: 9.3) */
typedef struct _USB_SETUP_PACKET
{
    u8 bmRequestType;
    u8 bRequest;
    u16 wValue;
    u16 wIndex;
    u16 wLength;
} USB_SETUP_PACKET, * PUSB_SETUP_PACKET;

#define USB_CONTROL_REQUEST_TYPE_DIRECTION_MASK 0x80
#define USB_CONTROL_REQUEST_TYPE_DIRECTION_BITSHIFT 7
#define USB_CONTROL_REQUEST_TYPE_TYPE_MASK 0x60
#define USB_CONTROL_REQUEST_TYPE_TYPE_BITSHIFT 5
#define USB_CONTROL_REQUEST_TYPE_RECIPIENT_MASK 0x1f
#define USB_CONTROL_REQUEST_TYPE_RECIPIENT_BITSHIFT 0

#define USB_CONTROL_REQUEST_GET_DIRECTION(a) ((a & USB_CONTROL_REQUEST_TYPE_DIRECTION_MASK) >> USB_CONTROL_REQUEST_TYPE_DIRECTION_BITSHIFT)
#define USB_CONTROL_REQUEST_GET_TYPE(a) ((a & USB_CONTROL_REQUEST_TYPE_TYPE_MASK) >> USB_CONTROL_REQUEST_TYPE_TYPE_BITSHIFT)
#define USB_CONTROL_REQUEST_GET_RECIPIENT(a) (a & USB_CONTROL_REQUEST_TYPE_RECIPIENT_MASK)


#define USB_CONTROL_REQUEST_TYPE_OUT 0
#define USB_CONTROL_REQUEST_TYPE_IN 1
#define USB_CONTROL_REQUEST_TYPE_STANDARD 0x00
#define USB_CONTROL_REQUEST_TYPE_CLASS 0x01
#define USB_CONTROL_REQUEST_TYPE_VENDOR 0x02
#define USB_CONTROL_REQUEST_TYPE_DEVICE 0x00
#define USB_CONTROL_REQUEST_TYPE_INTERFACE 0x01
#define USB_CONTROL_REQUEST_TYPE_ENDPOINT 0x02
#define USB_CONTROL_REQUEST_TYPE_OTHER 0x03

#define USB_GET_DESCRIPTOR 6
#define USB_SET_DESCRIPTOR 7


/* Externals */
extern ADI_DEV_DEVICE_HANDLE   adi_msd_PeripheralDevHandle;

extern USB_EP_INFO *pOUTEPInfo;
extern USB_EP_INFO *pINEPInfo;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_MSD_SUPPORT_H_ */
