/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 - 2018 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted (subject to the limitations in the disclaimer below) provided
 * that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this list
 *   of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice, this
 *   list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_class.h"

#include "usb_device_descriptor.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
/* msc endpoint information */
usb_device_endpoint_struct_t g_UsbDeviceMscEndpoints[USB_MSC_ENDPOINT_COUNT] = {
    /* msc bulk in endpoint */
    {
        USB_MSC_BULK_IN_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT), USB_ENDPOINT_BULK,
        FS_MSC_BULK_IN_PACKET_SIZE,
    },
    /* msc bulk out endpoint */
    {
        USB_MSC_BULK_OUT_ENDPOINT | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT), USB_ENDPOINT_BULK,
        FS_MSC_BULK_OUT_PACKET_SIZE,
    }};
/* msc interface information */
usb_device_interface_struct_t g_UsbDeviceMscInterface[] = {{
    /* The alternate setting of the interface */
    0U,
    {
        USB_MSC_ENDPOINT_COUNT,  /* Endpoint count */
        g_UsbDeviceMscEndpoints, /* Endpoints handle */
    },
    NULL,
}};

usb_device_interfaces_struct_t g_UsbDeviceMscInterfaces[USB_MSC_INTERFACE_COUNT] = {
    {
        USB_MSC_CLASS,           /* msc class code */
        USB_MSC_SUBCLASS,        /* msc subclass code */
        USB_MSC_PROTOCOL,        /*msc protocol code */
        USB_MSC_INTERFACE_INDEX, /* The interface number of the msc */
        g_UsbDeviceMscInterface, /* Interfaces handle */
        sizeof(g_UsbDeviceMscInterface) / sizeof(usb_device_interfaces_struct_t),
    },
};

usb_device_interface_list_t g_UsbDeviceMscInterfaceList[USB_CONFIGURE_COUNT] = {
    {
        USB_MSC_INTERFACE_COUNT,  /* The interface count of the msc */
        g_UsbDeviceMscInterfaces, /* The interfaces handle */
    },
};

usb_device_class_struct_t g_UsbDeviceMscConfig = {
    g_UsbDeviceMscInterfaceList, /* The interface list of the msc */
    kUSB_DeviceClassTypeMsc,     /* The msc class type */
    USB_CONFIGURE_COUNT,         /* The configuration count */
};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceDescriptor[] = {

    USB_DESCRIPTOR_LENGTH_DEVICE, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_DEVICE,   /* DEVICE Descriptor Type */
    USB_SHORT_GET_LOW(USB_DEVICE_SPECIFIC_BCD_VERSION),
    USB_SHORT_GET_HIGH(USB_DEVICE_SPECIFIC_BCD_VERSION), /* USB Specification Release Number in
                                                            Binary-Coded Decimal (i.e., 2.10 is 210H). */
    USB_DEVICE_CLASS,                                    /* Class code (assigned by the USB-IF). */
    USB_DEVICE_SUBCLASS,                                 /* Subclass code (assigned by the USB-IF). */
    USB_DEVICE_PROTOCOL,                                 /* Protocol code (assigned by the USB-IF). */
    USB_CONTROL_MAX_PACKET_SIZE,                         /* Maximum packet size for endpoint zero
                                                            (only 8, 16, 32, or 64 are valid) */
    0xC9U, 0x1FU,                                        /* Vendor ID (assigned by the USB-IF) */
    0x93U, 0x00U,                                        /* Product ID (assigned by the manufacturer) */
    USB_SHORT_GET_LOW(USB_DEVICE_DEMO_BCD_VERSION),
    USB_SHORT_GET_HIGH(USB_DEVICE_DEMO_BCD_VERSION), /* Device release number in binary-coded decimal */
    0x01U,                                           /* Index of string descriptor describing manufacturer */
    0x02U,                                           /* Index of string descriptor describing product */
    0x03U,               /* Index of string descriptor describing the device's serial number */
    USB_CONFIGURE_COUNT, /* Number of possible configurations */
};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceConfigurationDescriptor[] = {
    USB_DESCRIPTOR_LENGTH_CONFIGURE, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_CONFIGURE,   /* CONFIGURATION Descriptor Type */
    USB_SHORT_GET_LOW(USB_DESCRIPTOR_LENGTH_CONFIGURE + USB_DESCRIPTOR_LENGTH_INTERFACE +
                      USB_DESCRIPTOR_LENGTH_ENDPOINT + USB_DESCRIPTOR_LENGTH_ENDPOINT),
    USB_SHORT_GET_HIGH(USB_DESCRIPTOR_LENGTH_CONFIGURE + USB_DESCRIPTOR_LENGTH_INTERFACE +
                       USB_DESCRIPTOR_LENGTH_ENDPOINT +
                       USB_DESCRIPTOR_LENGTH_ENDPOINT), /* Total length of data returned for this configuration. */
    USB_MSC_INTERFACE_COUNT,                            /* Number of interfaces supported by this configuration */
    USB_MSC_CONFIGURE_INDEX,                            /* Value to use as an argument to the
                                                                SetConfiguration() request to select this configuration */
    0U,                                                 /* Index of string descriptor describing this configuration */
    (USB_DESCRIPTOR_CONFIGURE_ATTRIBUTE_D7_MASK) |
        (USB_DEVICE_CONFIG_SELF_POWER << USB_DESCRIPTOR_CONFIGURE_ATTRIBUTE_SELF_POWERED_SHIFT) |
        (USB_DEVICE_CONFIG_REMOTE_WAKEUP << USB_DESCRIPTOR_CONFIGURE_ATTRIBUTE_REMOTE_WAKEUP_SHIFT),
    /* Configuration characteristics
 D7: Reserved (set to one)
 D6: Self-powered
 D5: Remote Wakeup
 D4...0: Reserved (reset to zero)
*/
    USB_DEVICE_MAX_POWER,            /* Maximum power consumption of the USB
                                     * device from the bus in this specific
                                     * configuration when the device is fully
                                     * operational. Expressed in 2 mA units
                                     *  (i.e., 50 = 100 mA).
                                     */
    USB_DESCRIPTOR_LENGTH_INTERFACE, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_INTERFACE,   /* INTERFACE Descriptor Type */
    USB_MSC_INTERFACE_INDEX,         /* Number of this interface. */
    0x00U,                           /* Value used to select this alternate setting
                                                            for the interface identified in the prior field */
    USB_MSC_ENDPOINT_COUNT,          /* Number of endpoints used by this
                                                              interface (excluding endpoint zero). */

    USB_MSC_CLASS,    /* Class code (assigned by the USB-IF). */
    USB_MSC_SUBCLASS, /* Subclass code (assigned by the USB-IF). */
    USB_MSC_PROTOCOL, /* Protocol code (assigned by the USB). */
    0x00U,            /* Index of string descriptor describing this interface */

    USB_DESCRIPTOR_LENGTH_ENDPOINT, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_ENDPOINT,   /* ENDPOINT Descriptor Type */
    USB_MSC_BULK_IN_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
    /* The address of the endpoint on the USB device
                             described by this descriptor. */
    USB_ENDPOINT_BULK, /* This field describes the endpoint's attributes */
    USB_SHORT_GET_LOW(FS_MSC_BULK_IN_PACKET_SIZE),
    USB_SHORT_GET_HIGH(FS_MSC_BULK_IN_PACKET_SIZE), /* Maximum packet size this endpoint is capable of sending or
                                                       receiving when this configuration is selected. */
    0x00U,                                          /*Useless for bulk in endpoint*/

    USB_DESCRIPTOR_LENGTH_ENDPOINT, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_ENDPOINT,   /* ENDPOINT Descriptor Type */
    USB_MSC_BULK_OUT_ENDPOINT | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
    /* The address of the endpoint on the USB device
                         described by this descriptor. */
    USB_ENDPOINT_BULK, /* This field describes the endpoint's attributes */
    USB_SHORT_GET_LOW(FS_MSC_BULK_OUT_PACKET_SIZE), USB_SHORT_GET_HIGH(FS_MSC_BULK_OUT_PACKET_SIZE),
    0x00U /*For high-speed bulk/control OUT endpoints, the bInterval must specify the
         maximum NAK rate of the endpoint. refer to usb spec 9.6.6*/
};
#if (defined(USB_DEVICE_CONFIG_CV_TEST) && (USB_DEVICE_CONFIG_CV_TEST > 0U))
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceQualifierDescriptor[] = {
    USB_DESCRIPTOR_LENGTH_DEVICE_QUALITIER, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_DEVICE_QUALITIER,   /* DEVICE Descriptor Type */
    USB_SHORT_GET_LOW(USB_DEVICE_SPECIFIC_BCD_VERSION),
    USB_SHORT_GET_HIGH(USB_DEVICE_SPECIFIC_BCD_VERSION), /* USB Specification Release Number in
                                                            Binary-Coded Decimal (i.e., 2.10 is 210H). */
    USB_DEVICE_CLASS,                                    /* Class code (assigned by the USB-IF). */
    USB_DEVICE_SUBCLASS,                                 /* Subclass code (assigned by the USB-IF). */
    USB_DEVICE_PROTOCOL,                                 /* Protocol code (assigned by the USB-IF). */
    USB_CONTROL_MAX_PACKET_SIZE,                         /* Maximum packet size for endpoint zero
                                                            (only 8, 16, 32, or 64 are valid) */
    0x00U,                                               /* Number of Other-speed Configurations */
    0x00U,                                               /* Reserved for future use, must be zero */
};
#endif
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString0[] = {
    2U + 2U, USB_DESCRIPTOR_TYPE_STRING, 0x09U, 0x04U,
};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString1[] = {
    2U + 2U * 18U, USB_DESCRIPTOR_TYPE_STRING,
    'N',           0x00U,
    'X',           0x00U,
    'P',           0x00U,
    ' ',           0x00U,
    'S',           0x00U,
    'E',           0x00U,
    'M',           0x00U,
    'I',           0x00U,
    'C',           0x00U,
    'O',           0x00U,
    'N',           0x00U,
    'D',           0x00U,
    'U',           0x00U,
    'C',           0x00U,
    'T',           0x00U,
    'O',           0x00U,
    'R',           0x00U,
    'S',           0x00U,
};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString2[] = {2U + 2U * 16U, USB_DESCRIPTOR_TYPE_STRING,
                                'M',           0x00U,
                                'C',           0x00U,
                                'U',           0x00U,
                                ' ',           0x00U,
                                'M',           0x00U,
                                'A',           0x00U,
                                'S',           0x00U,
                                'S',           0x00U,
                                ' ',           0x00U,
                                'S',           0x00U,
                                'T',           0x00U,
                                'O',           0x00U,
                                'R',           0x00U,
                                'A',           0x00U,
                                'G',           0x00U,
                                'E',           0x00U};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString3[] = {2U + 2U * 16U, USB_DESCRIPTOR_TYPE_STRING,
                                '0',           0x00U,
                                '1',           0x00U,
                                '2',           0x00U,
                                '3',           0x00U,
                                '4',           0x00U,
                                '5',           0x00U,
                                '6',           0x00U,
                                '7',           0x00U,
                                '8',           0x00U,
                                '9',           0x00U,
                                'A',           0x00U,
                                'B',           0x00U,
                                'C',           0x00U,
                                'D',           0x00U,
                                'E',           0x00U,
                                'F',           0x00U};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceStringN[] = {2U + 2U * 16U, USB_DESCRIPTOR_TYPE_STRING,
                                'B',           0x00U,
                                'A',           0x00U,
                                'D',           0x00U,
                                ' ',           0x00U,
                                'S',           0x00U,
                                'T',           0x00U,
                                'R',           0x00U,
                                'I',           0x00U,
                                'N',           0x00U,
                                'G',           0x00U,
                                ' ',           0x00U,
                                'I',           0x00U,
                                'N',           0x00U,
                                'D',           0x00U,
                                'E',           0x00U,
                                'X',           0x00U};

uint32_t g_UsbStringDescriptorSize[USB_DEVICE_STRING_COUNT + 1] = {
    sizeof(g_UsbDeviceString0), sizeof(g_UsbDeviceString1), sizeof(g_UsbDeviceString2),
    sizeof(g_UsbDeviceString3), sizeof(g_UsbDeviceStringN),
};

uint8_t *g_UsbStringDescriptors[USB_DEVICE_STRING_COUNT + 1] = {
    g_UsbDeviceString0, g_UsbDeviceString1, g_UsbDeviceString2, g_UsbDeviceString3, g_UsbDeviceStringN,
};

usb_language_t g_UsbLanguage[USB_DEVICE_LANGUAGE_COUNT] = {{
    g_UsbStringDescriptors, g_UsbStringDescriptorSize, (uint16_t)0x0409U,
}};

usb_language_list_t g_UsbDeviceLanguageList = {
    g_UsbDeviceString0, sizeof(g_UsbDeviceString0), g_UsbLanguage, USB_DEVICE_LANGUAGE_COUNT,
};
/*******************************************************************************
 * Code
 ******************************************************************************/
/* Get device descriptor request */
usb_status_t USB_DeviceGetDeviceDescriptor(usb_device_handle handle,
                                           usb_device_get_device_descriptor_struct_t *deviceDescriptor)
{
    deviceDescriptor->buffer = g_UsbDeviceDescriptor;
    deviceDescriptor->length = USB_DESCRIPTOR_LENGTH_DEVICE;
    return kStatus_USB_Success;
}
#if (defined(USB_DEVICE_CONFIG_CV_TEST) && (USB_DEVICE_CONFIG_CV_TEST > 0U))
/* Get device qualifier descriptor request */
usb_status_t USB_DeviceGetDeviceQualifierDescriptor(
    usb_device_handle handle, usb_device_get_device_qualifier_descriptor_struct_t *deviceQualifierDescriptor)
{
    deviceQualifierDescriptor->buffer = g_UsbDeviceQualifierDescriptor;
    deviceQualifierDescriptor->length = USB_DESCRIPTOR_LENGTH_DEVICE_QUALITIER;
    return kStatus_USB_Success;
}

#endif
/* Get device configuration descriptor request */
usb_status_t USB_DeviceGetConfigurationDescriptor(
    usb_device_handle handle, usb_device_get_configuration_descriptor_struct_t *configurationDescriptor)
{
    if (USB_MSC_CONFIGURE_INDEX > configurationDescriptor->configuration)
    {
        configurationDescriptor->buffer = g_UsbDeviceConfigurationDescriptor;
        configurationDescriptor->length = USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL;
        return kStatus_USB_Success;
    }
    return kStatus_USB_InvalidRequest;
}
/* Get device string descriptor request */
usb_status_t USB_DeviceGetStringDescriptor(usb_device_handle handle,
                                           usb_device_get_string_descriptor_struct_t *stringDescriptor)
{
    if (stringDescriptor->stringIndex == 0U)
    {
        stringDescriptor->buffer = (uint8_t *)g_UsbDeviceLanguageList.languageString;
        stringDescriptor->length = g_UsbDeviceLanguageList.stringLength;
    }
    else
    {
        uint8_t languageId = 0U;
        uint8_t languageIndex = USB_DEVICE_STRING_COUNT;

        for (; languageId < USB_DEVICE_LANGUAGE_COUNT; languageId++)
        {
            if (stringDescriptor->languageId == g_UsbDeviceLanguageList.languageList[languageId].languageId)
            {
                if (stringDescriptor->stringIndex < USB_DEVICE_STRING_COUNT)
                {
                    languageIndex = stringDescriptor->stringIndex;
                }
                break;
            }
        }

        if (USB_DEVICE_STRING_COUNT == languageIndex)
        {
            return kStatus_USB_InvalidRequest;
        }
        stringDescriptor->buffer = (uint8_t *)g_UsbDeviceLanguageList.languageList[languageId].string[languageIndex];
        stringDescriptor->length = g_UsbDeviceLanguageList.languageList[languageId].length[languageIndex];
    }
    return kStatus_USB_Success;
}

/* Due to the difference of HS and FS descriptors, the device descriptors and configurations need to be updated to match
* current speed.
* As the default, the device descriptors and configurations are configured by using FS parameters for both EHCI and
* KHCI.
* When the EHCI is enabled, the application needs to call this function to update device by using current speed.
* The updated information includes endpoint max packet size, endpoint interval, etc. */
usb_status_t USB_DeviceSetSpeed(usb_device_handle handle, uint8_t speed)
{
    usb_descriptor_union_t *descriptorHead;
    usb_descriptor_union_t *descriptorTail;

    descriptorHead = (usb_descriptor_union_t *)&g_UsbDeviceConfigurationDescriptor[0];
    descriptorTail =
        (usb_descriptor_union_t *)(&g_UsbDeviceConfigurationDescriptor[USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL - 1]);

    while (descriptorHead < descriptorTail)
    {
        if (descriptorHead->endpoint.bDescriptorType == USB_DESCRIPTOR_TYPE_ENDPOINT)
        {
            if (USB_SPEED_HIGH == speed)
            {
                if (((descriptorHead->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                     USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_IN) &&
                    (USB_MSC_BULK_IN_ENDPOINT ==
                     (descriptorHead->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)))
                {
                    descriptorHead->endpoint.wMaxPacketSize[0] = USB_SHORT_GET_LOW(HS_MSC_BULK_IN_PACKET_SIZE);
                    descriptorHead->endpoint.wMaxPacketSize[1] = USB_SHORT_GET_HIGH(HS_MSC_BULK_IN_PACKET_SIZE);
                }
                else
                {
                    descriptorHead->endpoint.wMaxPacketSize[0] = USB_SHORT_GET_LOW(HS_MSC_BULK_OUT_PACKET_SIZE);
                    descriptorHead->endpoint.wMaxPacketSize[1] = USB_SHORT_GET_HIGH(HS_MSC_BULK_OUT_PACKET_SIZE);
                }
            }
            else
            {
                if (((descriptorHead->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                     USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_IN) &&
                    (USB_MSC_BULK_IN_ENDPOINT ==
                     (descriptorHead->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)))
                {
                    descriptorHead->endpoint.wMaxPacketSize[0] = USB_SHORT_GET_LOW(FS_MSC_BULK_IN_PACKET_SIZE);
                    descriptorHead->endpoint.wMaxPacketSize[1] = USB_SHORT_GET_HIGH(FS_MSC_BULK_IN_PACKET_SIZE);
                }
                else
                {
                    descriptorHead->endpoint.wMaxPacketSize[0] = USB_SHORT_GET_LOW(FS_MSC_BULK_OUT_PACKET_SIZE);
                    descriptorHead->endpoint.wMaxPacketSize[1] = USB_SHORT_GET_HIGH(FS_MSC_BULK_OUT_PACKET_SIZE);
                }
            }
        }
        descriptorHead = (usb_descriptor_union_t *)((uint8_t *)descriptorHead + descriptorHead->common.bLength);
    }

    for (int i = 0; i < USB_MSC_ENDPOINT_COUNT; i++)
    {
        if (USB_SPEED_HIGH == speed)
        {
            if ((USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT) ==
                (g_UsbDeviceMscEndpoints[i].endpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
            {
                g_UsbDeviceMscEndpoints[i].maxPacketSize = HS_MSC_BULK_IN_PACKET_SIZE;
            }
            else
            {
                g_UsbDeviceMscEndpoints[i].maxPacketSize = HS_MSC_BULK_OUT_PACKET_SIZE;
            }
        }
        else
        {
            if ((USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT) ==
                (g_UsbDeviceMscEndpoints[i].endpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
            {
                g_UsbDeviceMscEndpoints[i].maxPacketSize = FS_MSC_BULK_IN_PACKET_SIZE;
            }
            else
            {
                g_UsbDeviceMscEndpoints[i].maxPacketSize = FS_MSC_BULK_OUT_PACKET_SIZE;
            }
        }
    }

    return kStatus_USB_Success;
}
