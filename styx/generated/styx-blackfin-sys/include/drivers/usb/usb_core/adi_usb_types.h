/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_types.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
             Contains the common types and macros used by other source or header files.

*********************************************************************************/

#ifndef _ADI_USB_TYPES_H_
#define _ADI_USB_TYPES_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

typedef unsigned char  u8_t;
typedef unsigned short u16_t;
typedef unsigned long  u32_t;

typedef signed char  s8_t;
typedef signed short s16_t;
typedef signed long  s32_t;

/* Descriptor Types */
#define TYPE_DEVICE_DESCRIPTOR                  0x01
#define TYPE_CONFIGURATION_DESCRIPTOR               0x02
#define TYPE_STRING_DESCRIPTOR                  0x03
#define TYPE_INTERFACE_DESCRIPTOR               0x04
#define TYPE_ENDPOINT_DESCRIPTOR                0x05
#define TYPE_DEVICEQUALIFIER_DESCRIPTOR             0x06
#define TYPE_OTHER_SPEED_CONFIGURATION_DESCRIPTOR       0x07
#define TYPE_INTERFACE_POWER_DESCRIPTOR             0x08
#define TYPE_OTG_DESCRIPTOR                     0x09
#define TYPE_INTERFACEASSOCIATION_DESCRIPTOR            0x0B
#define TYPE_VENDOR_SPECIFIC_DESCRIPTOR             0xFF

/* Length (in bytes) of high level descriptors */
#define DEVICE_DESCRIPTOR_LEN                          18
#define CONFIGURATION_DESCRIPTOR_LEN                    9
#define INTERFACE_DESCRIPTOR_LEN                        9
#define ENDPOINT_DESCRIPTOR_LEN                         7
#define SETUP_PACKET_LEN                                8
#define OTG_DESCRIPTOR_LEN                              3

/* USB Spec in BCD */
#define USB_SPEC_1_0    0x0100
#define USB_SPEC_1_1    0x0110
#define USB_SPEC_2_0    0x0200

/* Maximum packet size for EP0:
    low-speed devices must use 8
    full-speed devices may use 8, 16, 32, or 64
    high-speed devices must use 64 */
#define EP0_MAX_PACKET_SIZE_LOW8    8
#define EP0_MAX_PACKET_SIZE_FULL8   8
#define EP0_MAX_PACKET_SIZE_FULL16  16
#define EP0_MAX_PACKET_SIZE_FULL32  32
#define EP0_MAX_PACKET_SIZE_FULL64  64
#define EP0_MAX_PACKET_SIZE_HIGH64  64

/* Class Codes */
#define USB_AUDIO_CLASS_CODE                 0x01
#define USB_COMMDEV_COMM_IFCE_CLASS_CODE     0x02
#define USB_HID_CLASS_CODE                   0x03
#define USB_PHYSICAL_CLASS_CODE              0x05
#define USB_IMAGE_CLASS_CODE                 0x06
#define USB_PRINTER_CLASS_CODE               0x07
#define USB_MASS_STORAGE_CLASS_CODE          0x08
#define USB_HUB_CLASS_CODE                   0x09
#define USB_COMMDEV_DATA_IFCE_CLASS_CODE     0x0A
#define USB_SMART_CARD_CLASS_CODE            0x0B
#define USB_CONTENT_SECURITY_CLASS_CODE      0x0D
#define USB_VIDEO_CLASS_CODE                 0x0E
#define USB_DIAGNOSTIC_DEV_CLASS_CODE        0xDC
#define USB_WIRELESS_CONTROLLER_CLASS_CODE   0xE0
#define USB_APP_SPECIFIC_CLASS_CODE          0xFE
#define USB_VENDOR_SPECIFIC_CLASS_CODE       0xFF


/* USB Standard device requests */


/* Endpoint */
#define EP_DIR_IN       0x80
#define EP_DIR_OUT      0x00
#define USB_BULK_MODE   0x02

/*
 * Configuration descriptor attributes
 * by default 7th bit has to be 1 and bits 0-5 must be zero
 * Bit-5 - Remote wakeup, Bit-6 - Selfpowered.
 */
#define USB_CFG_DESC_ATTR_REMOTE_WAKEUP  ( (0x80) | (1 << 5) )
#define USB_CFG_DESC_ATTR_SELF_POWERED   ( (0x80) | (1 << 6) )

/* Setup Device Request Types 2.0 specification pg 248
 * below macros define the bits of bmRequestType */
#define USB_DIR_HOST_TO_DEVICE (0 << 7) /* 7th bit is 0 */
#define USB_DIR_DEVICE_TO_HOST (1 << 7) /* 7th bit is 1 */

#define USB_TYPE_STANDARD      ((0 << 5) | (0<<6)) /* 0 (5th,6th bit positions) */
#define USB_TYPE_CLASS         ((1 << 5) | (0<<6)) /* 1 (5th,6th bit positions) */
#define USB_TYPE_VENDOR        ((0 << 5) | (1<<6)) /* 2 (5th,6th bit positions) */
#define USB_TYPE_RESERVED      ((1 << 5) | (1<<6)) /* 3 (5th,6th bit positions) */

#define USB_RECIPIENT_DEVICE      (0)              /* bits 0-4)  */
#define USB_RECIPIENT_INTERFACE   (1 << 0)         /* bits 0-4)  */
#define USB_RECIPIENT_ENDPOINT    (1 << 1)         /* bits 0-4)  */
#define USB_RECIPIENT_OTHER       ((1 << 1) | (1<< 0))  /* bits 0-4)  */

/* Request types (bRequest of Setup Packet)  pg 250 & 251 of USB 2.0 specification */

#define USB_STD_RQST_GET_STATUS         0x00
#define USB_STD_RQST_CLEAR_FEATURE      0x01
#define USB_STD_RQST_SET_FEATURE        0x03   /* 0x2 is reserved */
#define USB_STD_RQST_SET_ADDRESS        0x05   /* 0x4 is reserved */
#define USB_STD_RQST_GET_DESCRIPTOR     0x06
#define USB_STD_RQST_SET_DESCRIPTOR     0x07
#define USB_STD_RQST_GET_CONFIGURATION      0x08
#define USB_STD_RQST_SET_CONFIGURATION      0x09
#define USB_STD_RQST_GET_INTERFACE      0x0A
#define USB_STD_RQST_SET_INTERFACE      0x0B
#define USB_STD_RQST_SYNCH_FRAME        0x0C

/* Standard feature selectors */
#define USB_STANDARD_FEATURE_ENDPOINT_HALT         0
#define USB_STANDARD_FEATURE_DEVICE_REMOTE_WAKEUP  1   /* not the RemoteWakeup in the bmAttributes */
#define USB_STANDARD_FEATURE_TEST_MODE             2

/* Byte access macros */
#define LOW_BYTE_LW(x)      (x & 0xFF)
#define HIGH_BYTE_LW(x)     ((x >> 8)  & 0xFF)
#define LOW_BYTE_HW(x)      ((x >> 16) & 0xFF)
#define HIGH_BYTE_HW(x)     ((x >> 24) & 0xFF)

/* Usb Test mode selectors, pg 259 of USB 2.0 Specification */
#define USB_TMODE_TEST_J                        0x01   /* Test_J */
#define USB_TMODE_TEST_K                        0x02   /* Test_K */
#define USB_TMODE_TEST_SE0_NAK                  0x03   /* Test_SE0_NAK */
#define USB_TMODE_TEST_PACKET                   0x04   /* Test_PACKET */
#define USB_TMODE_TEST_FORCE_ENABLE             0x05   /* Test_Force_Enable */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_TYPES_H_ */
