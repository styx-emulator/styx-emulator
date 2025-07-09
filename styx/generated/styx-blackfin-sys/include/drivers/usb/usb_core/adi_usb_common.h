/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_common.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            Contains the common data structures that are used by a usb device or
            primitive OTG host.

*********************************************************************************/

#ifndef _ADI_USB_COMMON_H_
#define _ADI_USB_COMMON_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers\usb\usb_core\adi_usb_types.h>

/* Device Descriptor -Size 18 Bytes - 14 fields */
typedef struct UsbDeviceDescriptor
{
  u8_t   bLength;          /* Descriptor size in bytes */
  u8_t   bDescriptorType;  /* Descriptor type DEVICE 01h  */
  u16_t  wBcdUSB;          /* USB Specification Release Number (BCD) */
  u8_t   bDeviceClass;     /* Class code */
  u8_t   bDeviceSubClass;  /* Subclass code */
  u8_t   bDeviceProtocol;  /* Protocol code */
  u8_t   bMaxPacketSize0;  /* Maximum packet size for Endpoint 0 */
  u16_t  wIdVendor;        /* Vendor ID */
  u16_t  wIdProduct;       /* Product ID */
  u16_t  wBcdDevice;       /* Device release number */
  u8_t   bIManufacturer;   /* Index of string descriptor for manufacturer */
  u8_t   bIProduct;        /* Index of string descriptor for product */
  u8_t   bISerialNumber;   /* Index of string descriptor contains serial no# */
  u8_t   bNumConfigurations; /* Number of possible configurations */
}DEVICE_DESCRIPTOR, *PDEVICE_DESCRIPTOR;

/* Device Qualifier Descriptor -Size 10 bytes - 9 fields */
typedef struct DeviceQualifierDescriptor
{
  u8_t   bLength;          /* Descriptor size in bytes */
  u8_t   bDescriptorType;  /* Descriptor type DEVICE 06h  */
  u16_t  wBcdUSB;          /* USB Specification Release Number (BCD) */
  u8_t   bDeviceClass;     /* Class code */
  u8_t   bDeviceSubClass;  /* Subclass code */
  u8_t   bDeviceProtocol;  /* Protocol code */
  u8_t   bMaxPacketSize0;  /* Maximum packet size for Endpoint 0 */
  u8_t   bNumConfigurations; /* Number of possible configurations */
  u8_t   bReserved;        /* Reserved for future use */
}DEVICE_QUALIFIER_DESCRIPTOR,*PDEVICE_QUALIFIER_DESCRIPTOR;


/* Configuration Descriptor -Size 9 bytes - 8 fields */
typedef struct ConfigurationDescriptor
{
  u8_t  bLength;          /* Descriptor size in bytes */
  u8_t  bDescriptorType;  /* Descriptor type CONFIGURATION 02h */
  u16_t wTotalLength;     /* Total Length of configuration descriptor and all
               *  of its subordinate descriptors */
  u8_t  bNumInterfaces;   /* Number of interfaces in the configuration */
  u8_t  bConfigurationValue; /* Identifier for Set/Get configuration requests */
  u8_t  bIConfiguration;  /* Index of string descriptor for the configuration */
  u8_t  bAttributes;      /* Self/bus power and remote wakeup settings */
  u8_t  bMaxPower;        /* Bus power required,expressed as max-miili-amps/2 */
}CONFIGURATION_DESCRIPTOR,*PCONFIGURATION_DESCRIPTOR;


/* Interface Descriptor -Size 9 bytes - 9 fields */
typedef struct InterfaceDescriptor
{
  u8_t  bLength;            /* Descriptor size in bytes */
  u8_t  bDescriptorType;    /* Descriptor type INTERFACE 04h */
  u8_t  bInterfaceNumber;   /* Number identifying this interface */
  u8_t  bAlternateSetting;  /* Value used to select Alternate setting */
  u8_t  bNumEndpoints;      /* Identifier for Set/Get configuration requests */
  u8_t  bInterfaceClass;    /* Class code */
  u8_t  bInterfaceSubClass; /* Subclass code */
  u8_t  bInterfaceProtocol; /* Protocol code */
  u8_t  bIInterface;        /* Index of string descriptor for the interface */
}INTERFACE_DESCRIPTOR,*PINTERFACE_DESCRIPTOR;

/* Interface Association Descriptor -Size 8 bytes - 8 fields */
typedef struct InterfaceAssociationDescriptor
{
  u8_t  bLength;            /* Descriptor size in bytes */
  u8_t  bDescriptorType;    /* Descriptor type INTERFACE ASSOCIATION 0Bh */
  u8_t  bFirstInterface;    /* Number identifying first interface associated */
  u8_t  bInterfaceCount;    /* Number of contiguous interfaces associated */
  u8_t  bFunctionClass;     /* Class code */
  u8_t  bFunctionSubClass;  /* Sub class code */
  u8_t  bFunctionProtocol;  /* Protocol code */
  u8_t  bIFunction;         /* Index of string descriptor for the function */
}INTERFACE_ASSOCIATION_DESCRIPTOR, *PINTERFACE_ASSOCIATION_DESCRIPTOR;

/* Endpoint Descriptor -Size 7 bytes - 6 fields */
typedef struct EndPointDescriptor
{
  u8_t  bLength;            /* Descriptor size in bytes */
  u8_t  bDescriptorType;    /* Descriptor type ENDPOINT 05h */
  u8_t  bEndpointAddress;   /* Endpoint Address */
  u8_t  bAttributes;        /* Transfer type supported */
  u16_t  wMaxPacketSize;     /* Maximum packet size supported */
  u8_t  bInterval;          /* Maximum latency/polling /NACK rate */
}ENDPOINT_DESCRIPTOR, *PENDPOINT_DESCRIPTOR;

/* String Descriptor */
typedef struct StringDescriptor
{
  u8_t bLength;           /* Descriptor size in bytes */
  u8_t bDescriptorType;   /* Descriptor type STRING 03h */

  /* The last field is bString which is an unknown length. For string 0 it's
     an array of one or more language ID codes, for other strings this is a
     Unicode string */

}STRING_DESCRIPTOR,*PSTRING_DESCRIPTOR;

/* Setup packet USB 2.0 specification pg:248 */
typedef struct SetupPacket
{
  u8_t  bmRequestType;   /* characteristics of request */
  u8_t  bRequest;        /* specific request */
  u16_t wValue;          /* Word-sized field that varies according to the request */
  u16_t wIndex;          /* Word-sized field that varies according to the request */
  u16_t wLength;         /* Number of bytes to transfer if there is a data stage  */
}SETUP_PACKET,*PSETUP_PACKET;

/* OTG descriptor */
typedef struct OTGDescriptor
{
  u8_t bLength;                 /* Size of OTG descriptor 3-bytes     */
  u8_t bDescriptorType;         /* TYPE_OTG_DESCRIPTOR value: 09h */
  u8_t bmAttributes;            /* Bitmap attributes Bit0: SRP Bit1:HNP */
}OTG_DESCRIPTOR,*POTG_DESCRIPTOR;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* _ADI_USB_COMMON_H_ */
