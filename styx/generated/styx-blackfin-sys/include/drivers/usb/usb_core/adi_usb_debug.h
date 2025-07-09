/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_debug.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
             Contains the debug and assert macros.

*********************************************************************************/

#ifndef _ADI_USB_DEBUG_H_
#define _ADI_USB_DEBUG_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#ifdef ADI_DEV_DEBUG
/* default options */
#define USB_DEBUG_FLAGS  USB_DEBUG_FLAGS_ALL
#define USB_DEBUG
#define USB_ASSERT_ENABLED
#endif

#define USB_DEBUG_FLAGS_ALL (USB_DEVICE_DEBUG |     \
                            USB_CONFIG_DEBUG |      \
                            USB_INTERFACE_DEBUG |   \
                            USB_EP_DEBUG)

#define USB_DEVICE_DEBUG    (1 << 0)
#define USB_CONFIG_DEBUG    (1 << 1)
#define USB_INTERFACE_DEBUG (1 << 2)
#define USB_EP_DEBUG        (1 << 3)

#ifdef  USB_ASSERT_ENABLED
#include <stdio.h>
#define USB_ASSERT(x) do {                                                  \
            if(x) {                                                         \
            printf("Assertion Failed at line %d in %s\n",                   \
                __LINE__,__FILE__); fflush(NULL); asm("emuexcpt;"); }       \
            }while(0)
/*
#define USB_ASSERT(x) do {                                          \
            if(x) {                                                 \
            printf("Assertion Failed at line %d in %s\n",   \
                __LINE__,__FILE__); fflush(NULL); abort(); }        \
            }while(0)
*/

#else
#define USB_ASSERT(x)
#endif /* USB_ASSERT_ENABLED */

#ifdef USB_DEBUG
#define USB_DEBUG_PRINT(msg,flags,cond) do{         \
            if((flags) && (cond)){                  \
             printf("%s\n",msg); }                  \
                      }while(0)

#define PRINT_BYTE(msg,value) do{           \
    printf("%s 0x%x\n",msg,(value &0xff));      \
}while(0)

#define PRINT_SHORT(msg,value) do{          \
    printf("%s 0x%x\n",msg,(value&0xffff)); \
}while(0)
#else
#define USB_DEBUG_PRINT(msg,cond,flags) do{  }while(0)
#endif /* USB_DEBUG */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_DEBUG_H_ */
