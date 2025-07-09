/*********************************************************************************

Copyright(c) 2007 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_msd_debug.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

*********************************************************************************/

#ifndef _ADI_USB_MSD_DEBUG_H_
#define _ADI_USB_MSD_DEBUG_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#define _CONSOLE_DEBUG_

#define MSD_DEBUG_PRINT(module, msg) do{printf("%s : %s\r\n",module, msg);}while(0)
#define MSD_DEBUG_PRINT_BYTE(module, msg, value) do{printf("%s : %s 0x%x\r\n",module, msg, (value &0xff));}while(0)
#define MSD_DEBUG_PRINT_SHORT(module, msg, value) do{printf("%s : %s 0x%x\r\n", module, msg,(value&0xffff));}while(0)
#define MSD_DEBUG_PRINT_LONG(module, msg, value) do{printf("%s : %s 0x%x\r\n",module, msg, value));}while(0)

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
