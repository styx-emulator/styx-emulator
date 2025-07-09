/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_ids.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
             Contains the USB vendor and device IDs defined by ADI.

*********************************************************************************/

#ifndef _ADI_USB_IDS_H_
#define _ADI_USB_IDS_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/***********************************************************************
 * USB Vendor ID (VID)

 * VIDs belong to the company that has secured the right to use it by the USB-IF.
 * You may not use another company's VID    without their permission.  Some vendors
 * allow you to use their VID if you are using their USB device.  Contact USB-IF
 * or your USB device vendor for more information on obtaining a VID.

 * You must not use ADI's VID in your released product!
 ***********************************************************************/

#define USB_VID_ADI_TOOLS   0x064B  /* ADI's Development Tools USB VID, must not be
                                        used in anyone else's product */


/***********************************************************************
 * USB Product ID (PID)

 * PIDs are assigned by the vendor to distinguish their product.  A VID/PID combination
 * should be unique to a particular product (hardware/firmware combination).  The following
 * PIDs have been assigned by ADI to specific systems.
 ***********************************************************************/

#define USB_PID_ADI_UNDEFINED                           0x0000  /* PID initially used by core, client must change it */
#define USB_PID_BF537KIT_NET2272EXT_BULK                0x0187  /* bulk peripheral on BF537 EZ-KIT and NET2272 EZ-EXTENDER combo */
#define USB_PID_BF533KIT_NET2272EXT_BULK                0x1187  /* bulk peripheral on BF533 EZ-KIT and NET2272 EZ-EXTENDER combo */
#define USB_PID_BF533KIT_NET2272EXT_AUDIO_CLASS         0x2187  /* audio class peripheral on BF533 EZ-KIT and NET2272 EZ-EXTENDER combo */
#define USB_PID_BF561KIT_NET2272EXT_BULK                0x3187  /* bulk peripheral on BF561 EZ-KIT and NET2272 EZ-EXTENDER combo */
#define USB_PID_BF533KIT_NET2272EXT_MASSSTORAGE_CLASS   0x4187  /* mass storage class peripheral on BF533 EZ-KIT and NET2272 EZ-EXTENDER combo */

#define USB_PID_BF518KIT_NET2272EXT_BULK                 0x0224  /* bulk class peripheral on BF518 EZ-KIT and NET2272 EZ-EXTENDER combo */
#define USB_PID_BF518KIT_NET2272EXT_AUDIO_CLASS          0x1224  /* audio class peripheral on BF518 EZ-KIT and NET2272 EZ-EXTENDER combo */
#define USB_PID_BF518KIT_NET2272EXT_MASSSTORAGE_CLASS    0x2224  /* mass storage class peripheral on BF518 EZ-KIT and NET2272 EZ-EXTENDER combo */

#define USB_PID_BF548KIT_BULK                   0x1206  /* bulk peripheral on BF548 EZ-KIT using on-chip USB */
#define USB_PID_BF548KIT_MASSSTORAGE_CLASS      0x2206  /* mass storage class peripheral on BF548 EZ-KIT using on-chip USB */
#define USB_PID_BF548KIT_AUDIO_CLASS            0x3206  /* audio class peripheral on BF548 EZ-KIT using on-chip USB */

#define USB_PID_BF527KIT_BULK                   0x1208  /* bulk peripheral on BF527 EZ-KIT using on-chip USB */
#define USB_PID_BF527KIT_MASSSTORAGE_CLASS      0x2208  /* mass storage class peripheral on BF527 EZ-KIT using on-chip USB */
#define USB_PID_BF527KIT_AUDIO_CLASS            0x3208  /* audio class peripheral on BF527 EZ-KIT using on-chip USB */

#define USB_PID_BF526KIT_BULK                   0x1212  /* bulk peripheral on BF526 EZ-KIT using on-chip USB */
#define USB_PID_BF526KIT_MASSSTORAGE_CLASS      0x2212  /* mass storage class peripheral on BF526 EZ-KIT using on-chip USB */
#define USB_PID_BF526KIT_AUDIO_CLASS            0x3207  /* audio class peripheral on BF526 EZ-KIT using on-chip USB */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* _ADI_USB_IDS_H_ */
