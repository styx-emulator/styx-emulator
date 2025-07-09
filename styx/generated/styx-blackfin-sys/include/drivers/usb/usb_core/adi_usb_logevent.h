/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_logevent.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
             Logs USB events if logging is enabled.

*********************************************************************************/

#ifndef _ADI_USB_LOGEVENT_H_
#define _ADI_USB_LOGEVENT_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#ifdef ADI_DEV_DEBUG
#define _USB_LOGEVENT_ENABLE_   /* logging enabled by default */
#endif

#define MAX_EVENT_STRING 255
#define NUM_MAX_EVENTS   255
#if defined(_USB_LOGEVENT_ENABLE_)

/* Host to Device macros */
#define HSD(x)  HTD_STD_RD_ ## x
#define HSI(x)  HTD_STD_RI_ ## x
#define HSE(x)  HTD_STD_RE_ ## x
#define HCD(x)  HTD_CLS_RD_ ## x
#define HCI(x)  HTD_CLS_RI_ ## x
#define HCE(x)  HTD_CLS_RE_ ## x

/* Device to host macros */
#define DSD(x)  DTH_STD_RD_ ## x
#define DSI(x)  DTH_STD_RI_ ## x
#define DSE(x)  DTH_STD_RE_ ## x
#define DCD(x)  DTH_CLS_RD_ ## x
#define DCI(x)  DTH_CLS_RI_ ## x
#define DCE(x)  DTH_CLS_RE_ ## x

/* Various USB Events */
typedef enum UsbLogEvents
{
    /* Host to Device Standard Events */
    HSD(GET_STATUS),
    HSD(CLEAR_FEATURE),
    HSD(SET_FEATURE),
    HSD(SET_ADDRESS),
    HSD(GET_DESCRIPTOR),
    HSD(SET_DESCRIPTOR),
    HSD(GET_CONFIGURATION),
    HSD(SET_CONFIGURATION),
    HSD(GET_INTERFACE),
    HSD(SET_INTERFACE),
    HSD(SYNCH_FRAME),

    HSI(GET_STATUS),
    HSI(CLEAR_FEATURE),
    HSI(SET_FEATURE),
    HSI(SET_ADDRESS),
    HSI(GET_DESCRIPTOR),
    HSI(SET_DESCRIPTOR),
    HSI(GET_CONFIGURATION),
    HSI(SET_CONFIGURATION),
    HSI(GET_INTERFACE),
    HSI(SET_INTERFACE),
    HSI(SYNCH_FRAME),

    HSE(GET_STATUS),
    HSE(CLEAR_FEATURE),
    HSE(SET_FEATURE),
    HSE(SET_ADDRESS),
    HSE(GET_DESCRIPTOR),
    HSE(SET_DESCRIPTOR),
    HSE(GET_CONFIGURATION),
    HSE(SET_CONFIGURATION),
    HSE(GET_INTERFACE),
    HSE(SET_INTERFACE),
    HSE(SYNCH_FRAME),

    /* Host to Device Class Events */
    HCD(GET_STATUS),
    HCD(CLEAR_FEATURE),
    HCD(SET_FEATURE),
    HCD(SET_ADDRESS),
    HCD(GET_DESCRIPTOR),
    HCD(SET_DESCRIPTOR),
    HCD(GET_CONFIGURATION),
    HCD(SET_CONFIGURATION),
    HCD(GET_INTERFACE),
    HCD(SET_INTERFACE),
    HCD(SYNCH_FRAME),

    HCI(GET_STATUS),
    HCI(CLEAR_FEATURE),
    HCI(SET_FEATURE),
    HCI(SET_ADDRESS),
    HCI(GET_DESCRIPTOR),
    HCI(SET_DESCRIPTOR),
    HCI(GET_CONFIGURATION),
    HCI(SET_CONFIGURATION),
    HCI(GET_INTERFACE),
    HCI(SET_INTERFACE),
    HCI(SYNCH_FRAME),

    HCE(GET_STATUS),
    HCE(CLEAR_FEATURE),
    HCE(SET_FEATURE),
    HCE(SET_ADDRESS),
    HCE(GET_DESCRIPTOR),
    HCE(SET_DESCRIPTOR),
    HCE(GET_CONFIGURATION),
    HCE(SET_CONFIGURATION),
    HCE(GET_INTERFACE),
    HCE(SET_INTERFACE),
    HCE(SYNCH_FRAME),


    /* Device to Host Standard Events */
    DSD(GET_STATUS),
    DSD(CLEAR_FEATURE),
    DSD(SET_FEATURE),
    DSD(SET_ADDRESS),
    DSD(GET_DESCRIPTOR),
    DSD(SET_DESCRIPTOR),
    DSD(GET_CONFIGURATION),
    DSD(SET_CONFIGURATION),
    DSD(GET_INTERFACE),
    DSD(SET_INTERFACE),
    DSD(SYNCH_FRAME),

    DSI(GET_STATUS),
    DSI(CLEAR_FEATURE),
    DSI(SET_FEATURE),
    DSI(SET_ADDRESS),
    DSI(GET_DESCRIPTOR),
    DSI(SET_DESCRIPTOR),
    DSI(GET_CONFIGURATION),
    DSI(SET_CONFIGURATION),
    DSI(GET_INTERFACE),
    DSI(SET_INTERFACE),
    DSI(SYNCH_FRAME),

    DSE(GET_STATUS),
    DSE(CLEAR_FEATURE),
    DSE(SET_FEATURE),
    DSE(SET_ADDRESS),
    DSE(GET_DESCRIPTOR),
    DSE(SET_DESCRIPTOR),
    DSE(GET_CONFIGURATION),
    DSE(SET_CONFIGURATION),
    DSE(GET_INTERFACE),
    DSE(SET_INTERFACE),
    DSE(SYNCH_FRAME),

    /* Device to Host Class Events */
    DCD(GET_STATUS),
    DCD(CLEAR_FEATURE),
    DCD(SET_FEATURE),
    DCD(SET_ADDRESS),
    DCD(GET_DESCRIPTOR),
    DCD(SET_DESCRIPTOR),
    DCD(GET_CONFIGURATION),
    DCD(SET_CONFIGURATION),
    DCD(GET_INTERFACE),
    DCD(SET_INTERFACE),
    DCD(SYNCH_FRAME),

    DCI(GET_STATUS),
    DCI(CLEAR_FEATURE),
    DCI(SET_FEATURE),
    DCI(SET_ADDRESS),
    DCI(GET_DESCRIPTOR),
    DCI(SET_DESCRIPTOR),
    DCI(GET_CONFIGURATION),
    DCI(SET_CONFIGURATION),
    DCI(GET_INTERFACE),
    DCI(SET_INTERFACE),
    DCI(SYNCH_FRAME),

    DCE(GET_STATUS),
    DCE(CLEAR_FEATURE),
    DCE(SET_FEATURE),
    DCE(SET_ADDRESS),
    DCE(GET_DESCRIPTOR),
    DCE(SET_DESCRIPTOR),
    DCE(GET_CONFIGURATION),
    DCE(SET_CONFIGURATION),
    DCE(GET_INTERFACE),
    DCE(SET_INTERFACE),
    DCE(SYNCH_FRAME)

}USB_LOG_EVENTS;

typedef struct UsbLogEventStruct
{
    int dwEvent;
    int dwValue;
    char pEventString[MAX_EVENT_STRING];
}USB_LOGEVENT_STRUCT;

#define USB_LOG_EVENT(_event,_value,_str)  adi_usb_LogEvent(_event,_value,_str)
#define USB_SHOW_LOG() adi_usb_ShowEventLog()
#else
#define USB_LOG_EVENT(_event,_value,_str)
#define USB_SHOW_LOG
#endif /* _USB_LOGEVENT_ENABLE_ */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_LOGEVENT_ */
