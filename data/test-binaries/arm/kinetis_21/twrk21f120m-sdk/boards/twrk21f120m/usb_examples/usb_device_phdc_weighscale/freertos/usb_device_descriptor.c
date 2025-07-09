/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 , 2018 NXP
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
#include "usb_device_phdc.h"

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

/*! @brief PHDC weight scale endpoint information */
usb_device_endpoint_struct_t g_UsbDevicePhdcWeightScaleEndpoints[USB_PHDC_WEIGHT_SCALE_ENDPOINT_COUNT] = {
    {
        USB_PHDC_INTERRUPT_ENDPOINT_IN | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
        USB_ENDPOINT_INTERRUPT, FS_USB_PHDC_INTERRUPT_ENDPOINT_IN_PACKET_SIZE,
    },
    {
        USB_PHDC_BULK_ENDPOINT_OUT | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT), USB_ENDPOINT_BULK,
        FS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE,
    },
    {
        USB_PHDC_BULK_ENDPOINT_IN | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT), USB_ENDPOINT_BULK,
        FS_USB_PHDC_BULK_ENDPOINT_IN_PACKET_SIZE,
    },
};

/*! @brief PHDC weight scale interface entry */
usb_device_interface_struct_t g_UsbDevicePhdcWeightScaleInterface[] = {{
    0U, /* the alternate setting of the interface */
    {
        USB_PHDC_WEIGHT_SCALE_ENDPOINT_COUNT, /* the endpoint count */
        g_UsbDevicePhdcWeightScaleEndpoints,  /* the endpoint handle */
    },
    NULL,
}};

/*! @brief PHDC weight scale interface information */
usb_device_interfaces_struct_t g_UsbDevicePhdcWeightScaleInterfaces[USB_PHDC_WEIGHT_SCALE_INTERFACE_COUNT] = {{
    USB_PHDC_CLASS,                        /* the PHDC class code */
    USB_PHDC_SUBCLASS,                     /* the PHDC sub-class code */
    USB_PHDC_PROTOCOL,                     /* the PHDC protocol code */
    USB_PHDC_WEIGHT_SCALE_INTERFACE_INDEX, /* the interface number */
    g_UsbDevicePhdcWeightScaleInterface,   /* the interface handle */
    sizeof(g_UsbDevicePhdcWeightScaleInterface) / sizeof(usb_device_interfaces_struct_t),
}};

/*! @brief PHDC weight scale interface list */
usb_device_interface_list_t g_UsbDevicePhdcWeightScaleInterfaceList[USB_DEVICE_CONFIGURATION_COUNT] = {
    {
        USB_PHDC_WEIGHT_SCALE_INTERFACE_COUNT, /* the interface count */
        g_UsbDevicePhdcWeightScaleInterfaces,  /* the interface handle */
    },
};

/*! @brief PHDC class information */
usb_device_class_struct_t g_UsbDevicePhdcWeightScaleConfig = {
    g_UsbDevicePhdcWeightScaleInterfaceList, /* the interface list of PHDC */
    kUSB_DeviceClassTypePhdc,                /* the PHDC class type */
    USB_DEVICE_CONFIGURATION_COUNT,          /* the configuration count */
};

/*! @brief USB device descriptor */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceDescriptor[] = {
    USB_DESCRIPTOR_LENGTH_DEVICE, /* size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_DEVICE,   /* DEVICE descriptor type */
    USB_SHORT_GET_LOW(USB_DEVICE_SPECIFIC_BCD_VERSION), USB_SHORT_GET_HIGH(USB_DEVICE_SPECIFIC_BCD_VERSION),
    /* USB Specification Release Number in
       Binary-Coded Decimal (i.e., 2.10 is 210H). */
    USB_DEVICE_CLASS,            /* Class code (assigned by the USB-IF). */
    USB_DEVICE_SUBCLASS,         /* Subclass code (assigned by the USB-IF). */
    USB_DEVICE_PROTOCOL,         /* Protocol code (assigned by the USB-IF). */
    USB_CONTROL_MAX_PACKET_SIZE, /* Maximum packet size for endpoint zero
                                    (only 8, 16, 32, or 64 are valid) */
    0xC9U, 0x1FU,                /* Vendor ID (assigned by the USB-IF) */
    0x96U, 0x00U,                /* Product ID (assigned by the manufacturer) */
    USB_SHORT_GET_LOW(USB_DEVICE_DEMO_BCD_VERSION),
    USB_SHORT_GET_HIGH(USB_DEVICE_DEMO_BCD_VERSION), /* Device release number in binary-coded decimal */
    0x01U,                                           /* Index of string descriptor describing manufacturer */
    0x02U,                                           /* Index of string descriptor describing product */
    0x00U,                                           /* Index of string descriptor describing the
                                                        device's serial number */
    USB_DEVICE_CONFIGURATION_COUNT,                  /* Number of possible configurations */
};

/*! @brief PHDC configuration descriptor */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceConfigurationDescriptor[] = {
    USB_DESCRIPTOR_LENGTH_CONFIGURE, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_CONFIGURE,   /* CONFIGURATION Descriptor Type */
    USB_SHORT_GET_LOW(
        USB_DESCRIPTOR_LENGTH_CONFIGURE + USB_DESCRIPTOR_LENGTH_INTERFACE + USB_DESCRIPTOR_LENGTH_CLASS_FUNCTION +
        USB_DESCRIPTOR_LENGTH_FUNCTION_EXTENSION + USB_DESCRIPTOR_LENGTH_ENDPOINT + USB_DESCRIPTOR_LENGTH_QOS +
        USB_DESCRIPTOR_LENGTH_METADATA_BULK_IN + USB_DESCRIPTOR_LENGTH_ENDPOINT + USB_DESCRIPTOR_LENGTH_QOS +
        USB_DESCRIPTOR_LENGTH_METADATA_BULK_OUT + USB_DESCRIPTOR_LENGTH_ENDPOINT + USB_DESCRIPTOR_LENGTH_QOS),
    USB_SHORT_GET_HIGH(
        USB_DESCRIPTOR_LENGTH_CONFIGURE + USB_DESCRIPTOR_LENGTH_INTERFACE + USB_DESCRIPTOR_LENGTH_CLASS_FUNCTION +
        USB_DESCRIPTOR_LENGTH_FUNCTION_EXTENSION + USB_DESCRIPTOR_LENGTH_ENDPOINT + USB_DESCRIPTOR_LENGTH_QOS +
        USB_DESCRIPTOR_LENGTH_METADATA_BULK_IN + USB_DESCRIPTOR_LENGTH_ENDPOINT + USB_DESCRIPTOR_LENGTH_QOS +
        USB_DESCRIPTOR_LENGTH_METADATA_BULK_OUT + USB_DESCRIPTOR_LENGTH_ENDPOINT + USB_DESCRIPTOR_LENGTH_QOS),
    /* Total length of data returned for this configuration. */
    USB_PHDC_WEIGHT_SCALE_INTERFACE_COUNT, /* Number of interfaces supported by this configuration */
    USB_PHDC_WEIGHT_SCALE_CONFIGURE_INDEX, /* Value to use as an argument to the
                                              SetConfiguration() request to select this configuration */
    0U,                                    /* Index of string descriptor describing this configuration */
    (USB_DESCRIPTOR_CONFIGURE_ATTRIBUTE_D7_MASK) |
        (USB_DEVICE_CONFIG_SELF_POWER << USB_DESCRIPTOR_CONFIGURE_ATTRIBUTE_SELF_POWERED_SHIFT) |
        (USB_DEVICE_CONFIG_REMOTE_WAKEUP << USB_DESCRIPTOR_CONFIGURE_ATTRIBUTE_REMOTE_WAKEUP_SHIFT),
    /* Configuration characteristics
       D7: Reserved (set to one)
       D6: Self-powered
       D5: Remote Wakeup
       D4...0: Reserved (reset to zero) */
    USB_DEVICE_MAX_POWER,                  /* Maximum power consumption of the USB
                                              device from the bus in this specific
                                              configuration when the device is fully
                                              operational. Expressed in 2 mA units
                                              (i.e., 50 = 100 mA). */
    USB_DESCRIPTOR_LENGTH_INTERFACE,       /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_INTERFACE,         /* INTERFACE Descriptor Type */
    USB_PHDC_WEIGHT_SCALE_INTERFACE_INDEX, /* Number of this interface. */
    0x00U,                                 /* Value used to select this alternate setting
                                              for the interface identified in the prior field */
    USB_PHDC_WEIGHT_SCALE_ENDPOINT_COUNT,  /* Number of endpoints used by this
                                              interface (excluding endpoint zero). */
    USB_PHDC_CLASS,                        /* Class code (assigned by the USB-IF). */

    0x00U,                                            /* Subclass code (assigned by the USB-IF). */
    0x00U,                                            /* Protocol code (assigned by the USB). */
    0x00U,                                            /* Index of string descriptor describing this interface */
    USB_DESCRIPTOR_LENGTH_CLASS_FUNCTION,             /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_CLASS_FUNCTION,               /* Constant name specifying type of PHDC descriptor. */
    0x02U,                                            /* Data/Messaging format code */
    0x00U | (META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED), /* Message preamble implemented in the interface */

    USB_DESCRIPTOR_LENGTH_FUNCTION_EXTENSION, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_11073PHD_FUNCTION,    /* Constant name specifying type of PHDC descriptor. */
    0x00U,                                    /* Reserved byte */
    0x01U,                                    /* Number of of wDevSpecializations */
    0x34U, 0x12U,                             /* The device specialization */

    USB_DESCRIPTOR_LENGTH_ENDPOINT, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_ENDPOINT,   /* ENDPOINT Descriptor Type */
    USB_PHDC_BULK_ENDPOINT_IN | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
    /* The address of the endpoint on the USB device
       described by this descriptor. */
    USB_ENDPOINT_BULK, /* This field describes the endpoint's attributes */
    USB_SHORT_GET_LOW(FS_USB_PHDC_BULK_ENDPOINT_IN_PACKET_SIZE),
    USB_SHORT_GET_HIGH(FS_USB_PHDC_BULK_ENDPOINT_IN_PACKET_SIZE),
    /* Maximum packet size this endpoint is capable of
       sending or receiving when this configuration is
       selected. */
    0x00U, /* Interval for polling endpoint for data transfers. */

    USB_DESCRIPTOR_LENGTH_QOS,              /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_QOS,                /* Constant name specifying type of PHDC descriptor. */
    0x01U,                                  /* qos encoding version */
    USB_PHDC_WEIGHT_SCALE_BULK_IN_QOS,      /* latency/reliability bin */
    USB_DESCRIPTOR_LENGTH_METADATA_BULK_IN, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_METADATA,           /* Constant name specifying type of PHDC descriptor. */
    0xABU, 0xCDU, 0xEFU, 0x01U, 0x02U,      /* opaque data */
    USB_DESCRIPTOR_LENGTH_ENDPOINT,         /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_ENDPOINT,           /* ENDPOINT Descriptor Type */
    USB_PHDC_BULK_ENDPOINT_OUT | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
    /* The address of the endpoint on the USB device
       described by this descriptor. */
    USB_ENDPOINT_BULK, /* This field describes the endpoint's attributes */
    USB_SHORT_GET_LOW(FS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE),
    USB_SHORT_GET_HIGH(FS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE),
    /* Maximum packet size this endpoint is capable of
       sending or receiving when this configuration is
       selected. */
    0x00U,                                   /* Interval for polling endpoint for data transfers. */
    USB_DESCRIPTOR_LENGTH_QOS,               /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_QOS,                 /* Constant name specifying type of PHDC
                                                descriptor. */
    0x01U,                                   /* qos encoding version */
    USB_PHDC_WEIGHT_SCALE_BULK_OUT_QOS,      /* latency/reliability bin */
    USB_DESCRIPTOR_LENGTH_METADATA_BULK_OUT, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_METADATA,            /* Constant name specifying type of PHDC descriptor. */
    0xCCU, 0xDDU,                            /* opaque data */
    USB_DESCRIPTOR_LENGTH_ENDPOINT,          /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_ENDPOINT,            /* ENDPOINT Descriptor Type */
    USB_PHDC_INTERRUPT_ENDPOINT_IN | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
    USB_ENDPOINT_INTERRUPT, /* This field describes the endpoint's attributes */
    USB_SHORT_GET_LOW(FS_USB_PHDC_INTERRUPT_ENDPOINT_IN_PACKET_SIZE),
    USB_SHORT_GET_HIGH(FS_USB_PHDC_INTERRUPT_ENDPOINT_IN_PACKET_SIZE),
    /* Maximum packet size this endpoint is capable of
       sending or receiving when this configuration is
       selected. */
    FS_USB_PHDC_INTERRUPT_ENDPOINT_IN_INTERVAL, /* Interval for polling endpoint for data transfers. */
    USB_DESCRIPTOR_LENGTH_QOS,                  /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_QOS,                    /* Constant name specifying type of PHDC descriptor. */
    0x01U,                                      /* qos encoding version */
    USB_PHDC_WEIGHT_SCALE_INTERRUPT_IN_QOS,     /* latency/reliability bin */
};

/*! @brief PHDC string 0 descriptor */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString0[] = {2U + 2U, USB_DESCRIPTOR_TYPE_STRING, 0x09U, 0x04U};

/*! @brief PHDC string 1 descriptor */
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

/*! @brief PHDC string 2 descriptor */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString2[] = {2U + 2U * 15U, USB_DESCRIPTOR_TYPE_STRING,
                                ' ',           0x00U,
                                'U',           0x00U,
                                'S',           0x00U,
                                'B',           0x00U,
                                ' ',           0x00U,
                                'P',           0x00U,
                                'H',           0x00U,
                                'D',           0x00U,
                                'C',           0x00U,
                                ' ',           0x00U,
                                'D',           0x00U,
                                'E',           0x00U,
                                'M',           0x00U,
                                'O',           0x00U,
                                ' ',           0x00U};

/*! @brief PHDC string 3 descriptor */
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

/*! @brief PHDC string descriptor length */
uint32_t g_UsbDeviceStringDescriptorLength[USB_DEVICE_STRING_COUNT + 1U] = {
    sizeof(g_UsbDeviceString0), sizeof(g_UsbDeviceString1), sizeof(g_UsbDeviceString2), sizeof(g_UsbDeviceStringN)};

/*! @brief PHDC string descriptor array*/
uint8_t *g_UsbDeviceStringDescriptorArray[USB_DEVICE_STRING_COUNT + 1U] = {g_UsbDeviceString0, g_UsbDeviceString1,
                                                                           g_UsbDeviceString2, g_UsbDeviceStringN};

/*! @brief PHDC USB language */
usb_language_t g_UsbDeviceLanguage[USB_DEVICE_LANGUAGE_COUNT] = {{
    g_UsbDeviceStringDescriptorArray, g_UsbDeviceStringDescriptorLength, (uint16_t)0x0409U,
}};

/*! @brief PHDC USB language list */
usb_language_list_t g_UsbDeviceLanguageList = {
    g_UsbDeviceString0, sizeof(g_UsbDeviceString0), g_UsbDeviceLanguage, USB_DEVICE_LANGUAGE_COUNT,
};

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief USB device get device descriptor function.
 *
 * This function gets the device descriptor of the USB device.
 *
 * @param handle The USB device handle.
 * @param deviceDescriptor The pointer to the device descriptor structure.
 *
 * @return kStatus_USB_Success.
 */
usb_status_t USB_DeviceGetDeviceDescriptor(usb_device_handle handle,
                                           usb_device_get_device_descriptor_struct_t *deviceDescriptor)
{
    deviceDescriptor->buffer = g_UsbDeviceDescriptor;
    deviceDescriptor->length = USB_DESCRIPTOR_LENGTH_DEVICE;
    return kStatus_USB_Success;
}

/*!
 * @brief USB device get configuration descriptor function.
 *
 * This function gets the configuration descriptor of the USB device.
 *
 * @param handle The USB device handle.
 * @param configurationDescriptor The pointer to the configuration descriptor structure.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceGetConfigurationDescriptor(
    usb_device_handle handle, usb_device_get_configuration_descriptor_struct_t *configurationDescriptor)
{
    if (USB_PHDC_WEIGHT_SCALE_CONFIGURE_INDEX > configurationDescriptor->configuration)
    {
        configurationDescriptor->buffer = g_UsbDeviceConfigurationDescriptor;
        configurationDescriptor->length = USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL;
        return kStatus_USB_Success;
    }
    return kStatus_USB_InvalidRequest;
}

/*!
 * @brief USB device get string descriptor function.
 *
 * This function gets the string descriptor of the USB device.
 *
 * @param handle The USB device handle.
 * @param stringDescriptor The pointer to the string descriptor structure.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
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

/*!
 * @brief USB device set speed function.
 *
 * Due to the difference of HS and FS descriptors, the device descriptors and
 * configurations need to be updated to match current speed. As the default,
 * the device descriptors and configurations are configured by using FS parameters
 * for both EHCI and KHCI. When the EHCI is enabled, the application needs to call
 * this fucntion to update device by using current speed. The updated information
 * includes endpoint max packet size, endpoint interval, etc..
 *
 * @param handle The USB device handle.
 * @param speed Speed type. USB_SPEED_HIGH/USB_SPEED_FULL/USB_SPEED_LOW.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceSetSpeed(usb_device_handle handle, uint8_t speed)
{
    usb_descriptor_union_t *pDescStart;
    usb_descriptor_union_t *pDescEnd;

    pDescStart = (usb_descriptor_union_t *)(&g_UsbDeviceConfigurationDescriptor[0]);
    pDescEnd =
        (usb_descriptor_union_t *)(&g_UsbDeviceConfigurationDescriptor[USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL - 1U]);

    while (pDescStart < pDescEnd)
    {
        if (pDescStart->common.bDescriptorType == USB_DESCRIPTOR_TYPE_ENDPOINT)
        {
            if (USB_SPEED_HIGH == speed)
            {
                if (((pDescStart->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                     USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_IN) &&
                    (USB_PHDC_INTERRUPT_ENDPOINT_IN ==
                    (pDescStart->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)))
                {
                    pDescStart->endpoint.bInterval = HS_USB_PHDC_INTERRUPT_ENDPOINT_IN_INTERVAL;
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(HS_USB_PHDC_INTERRUPT_ENDPOINT_IN_PACKET_SIZE,
                                                       pDescStart->endpoint.wMaxPacketSize);
                }
                else if (((pDescStart->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                          USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_IN) &&
                         (USB_PHDC_BULK_ENDPOINT_IN ==
                          (pDescStart->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)))
                {
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(HS_USB_PHDC_BULK_ENDPOINT_IN_PACKET_SIZE,
                                                       pDescStart->endpoint.wMaxPacketSize);
                }
                else if (((pDescStart->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                          USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_OUT) &&
                         (USB_PHDC_BULK_ENDPOINT_OUT ==
                          (pDescStart->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)))
                {
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(HS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE,
                                                       pDescStart->endpoint.wMaxPacketSize);
                }
                else
                {
                }
            }
            else
            {
                if (((pDescStart->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                     USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_IN) &&
                    (USB_PHDC_INTERRUPT_ENDPOINT_IN ==
                    (pDescStart->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)))
                {
                    pDescStart->endpoint.bInterval = FS_USB_PHDC_INTERRUPT_ENDPOINT_IN_INTERVAL;
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(FS_USB_PHDC_INTERRUPT_ENDPOINT_IN_PACKET_SIZE,
                                                       pDescStart->endpoint.wMaxPacketSize);
                }
                else if (((pDescStart->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                          USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_IN) &&
                         (USB_PHDC_BULK_ENDPOINT_IN ==
                          (pDescStart->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)))
                {
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(FS_USB_PHDC_BULK_ENDPOINT_IN_PACKET_SIZE,
                                                       pDescStart->endpoint.wMaxPacketSize);
                }
                else if (((pDescStart->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                          USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_OUT) &&
                         (USB_PHDC_BULK_ENDPOINT_OUT ==
                          (pDescStart->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)))
                {
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(FS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE,
                                                       pDescStart->endpoint.wMaxPacketSize);
                }
                else
                {
                }
            }
        }
        pDescStart = (usb_descriptor_union_t *)((uint8_t *)pDescStart + pDescStart->common.bLength);
    }

    for (int i = 0U; i < USB_PHDC_WEIGHT_SCALE_ENDPOINT_COUNT; i++)
    {
        if (USB_SPEED_HIGH == speed)
        {
            if (USB_ENDPOINT_INTERRUPT == g_UsbDevicePhdcWeightScaleEndpoints[i].transferType)
            {
                g_UsbDevicePhdcWeightScaleEndpoints[i].maxPacketSize = HS_USB_PHDC_INTERRUPT_ENDPOINT_IN_PACKET_SIZE;
            }
            else if (g_UsbDevicePhdcWeightScaleEndpoints[i].endpointAddress &
                     USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK)
            {
                g_UsbDevicePhdcWeightScaleEndpoints[i].maxPacketSize = HS_USB_PHDC_BULK_ENDPOINT_IN_PACKET_SIZE;
            }
            else
            {
                g_UsbDevicePhdcWeightScaleEndpoints[i].maxPacketSize = HS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE;
            }
        }
        else
        {
            if (USB_ENDPOINT_INTERRUPT == g_UsbDevicePhdcWeightScaleEndpoints[i].transferType)
            {
                g_UsbDevicePhdcWeightScaleEndpoints[i].maxPacketSize = FS_USB_PHDC_INTERRUPT_ENDPOINT_IN_PACKET_SIZE;
            }
            else if (g_UsbDevicePhdcWeightScaleEndpoints[i].endpointAddress &
                     USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK)
            {
                g_UsbDevicePhdcWeightScaleEndpoints[i].maxPacketSize = FS_USB_PHDC_BULK_ENDPOINT_IN_PACKET_SIZE;
            }
            else
            {
                g_UsbDevicePhdcWeightScaleEndpoints[i].maxPacketSize = FS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE;
            }
        }
    }
    return kStatus_USB_Success;
}
