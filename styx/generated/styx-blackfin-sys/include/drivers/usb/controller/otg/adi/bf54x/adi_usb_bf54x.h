/*********************************************************************************

Copyright(c) 2007 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_bf54x.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
             Header file for the ADSP-BF54x based USB Dual Role device driver.

*********************************************************************************/

#ifndef _ADI_USB_BF54X_H_
#define _ADI_USB_BF54X_H_

#warning adi_usb_bf54x.h is deprecated, please use adi_usb_hdrc.h instead

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers\usb\controller\otg\adi\hdrc\adi_usb_hdrc.h>


/* Configure the USB Interrupt levels */
typedef struct adi_usb_bf54x_ivg_levels
{
 interrupt_kind IvgUSBINT0;
 interrupt_kind IvgUSBINT1;
 interrupt_kind IvgUSBINT2;
 interrupt_kind IvgUSBDMAINT;
}ADI_USB_BF54x_IVG_LEVELS;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_BF54X_H_ */
