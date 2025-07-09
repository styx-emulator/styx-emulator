/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_msd_type.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:

*********************************************************************************/

#ifndef _ADI_USB_MSD_TYPE_H_
#define _ADI_USB_MSD_TYPE_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#define CHAR    char
#define PCHAR   char *

#define ULONG   unsigned long
#define UINT    unsigned int
#define USHORT  unsigned short
#define UCHAR   unsigned char

#define PULONG  unsigned long   *
#define PUINT   unsigned int    *
#define PUSHORT unsigned short  *
#define PUCHAR  unsigned char   *

#define LOBYTE(a) ((UCHAR)a)
#define HIBYTE(a) ((UCHAR)(a >> 8))

#define LOWORD(a) ((USHORT)a)
#define HIWORD(a) ((USHORT)(a >> 16))

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_MSD_TYPE_H_ */
