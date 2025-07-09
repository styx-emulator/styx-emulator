/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
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
#ifndef _USB_DEVICE_DESCRIPTOR_H_
#define _USB_DEVICE_DESCRIPTOR_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define USB_DEVICE_SPECIFIC_BCD_VERSION (0x0200U)
#define USB_DEVICE_DEMO_BCD_VERSION (0x0101U)
#define USB_DEVICE_MAX_POWER (0x32U)

/*! @brief USB device class code */
#define USB_DEVICE_CLASS (0x00U)
#define USB_DEVICE_SUBCLASS (0x00U)
#define USB_DEVICE_PROTOCOL (0x00U)

/*! @brief PHDC class code */
#define USB_PHDC_CLASS (0x0FU)
#define USB_PHDC_SUBCLASS (0x00U)
#define USB_PHDC_PROTOCOL (0x00U)

/*! @brief Size of descriptor in bytes */
#define USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL (sizeof(g_UsbDeviceConfigurationDescriptor))
#define USB_DESCRIPTOR_LENGTH_CLASS_FUNCTION (4U)
#define USB_DESCRIPTOR_LENGTH_QOS (4U)
#define USB_DESCRIPTOR_LENGTH_METADATA_BULK_OUT (4U)
#define USB_DESCRIPTOR_LENGTH_METADATA_BULK_IN (7U)
#define USB_DESCRIPTOR_LENGTH_FUNCTION_EXTENSION (6U)
#define USB_DESCRIPTOR_LENGTH_STRING0 (sizeof(g_UsbDeviceString0))
#define USB_DESCRIPTOR_LENGTH_STRING1 (sizeof(g_UsbDeviceString1))
#define USB_DESCRIPTOR_LENGTH_STRING2 (sizeof(g_UsbDeviceString2))
#define USB_DESCRIPTOR_LENGTH_STRING_ERROR (sizeof(g_UsbDeviceStringN))

/*! @brief PHDC descriptor types */
#define USB_DESCRIPTOR_TYPE_CLASS_FUNCTION (0x20U)
#define USB_DESCRIPTOR_TYPE_QOS (0x21U)
#define USB_DESCRIPTOR_TYPE_METADATA (0x22U)
#define USB_DESCRIPTOR_TYPE_11073PHD_FUNCTION (0x30U)

/*! @brief PHDC endpoint number */
#define USB_PHDC_WEIGHT_SCALE_ENDPOINT_COUNT (3U)
#define USB_PHDC_BULK_ENDPOINT_OUT (2U)
#define USB_PHDC_BULK_ENDPOINT_IN (3U)
#define USB_PHDC_INTERRUPT_ENDPOINT_IN (1U)

/*! @brief Max endpoint packet size */
#define HS_USB_PHDC_BULK_ENDPOINT_IN_PACKET_SIZE (64U)
#define HS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE (64U)
#define FS_USB_PHDC_BULK_ENDPOINT_IN_PACKET_SIZE (64U)
#define FS_USB_PHDC_BULK_ENDPOINT_OUT_PACKET_SIZE (64U)
#define HS_USB_PHDC_INTERRUPT_ENDPOINT_IN_PACKET_SIZE (8U)
#define FS_USB_PHDC_INTERRUPT_ENDPOINT_IN_PACKET_SIZE (8U)
#define HS_USB_PHDC_INTERRUPT_ENDPOINT_IN_INTERVAL (0x04U)
#define FS_USB_PHDC_INTERRUPT_ENDPOINT_IN_INTERVAL (0x01U)

/*! @brief Endpoint QoS */
#define USB_PHDC_WEIGHT_SCALE_BULK_OUT_QOS (0x08U)
#define USB_PHDC_WEIGHT_SCALE_BULK_IN_QOS (0x08U)
#define USB_PHDC_WEIGHT_SCALE_INTERRUPT_IN_QOS (0x01U)

/*! @brief Meta-data message preamble feature */
#define META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED (0U)

/*! @brief Number of USB device string descriptor */
#define USB_DEVICE_STRING_COUNT (3U)
/*! @brief Number of USB device language */
#define USB_DEVICE_LANGUAGE_COUNT (1U)

/*! @brief PHDC interface */
#define USB_PHDC_WEIGHT_SCALE_INTERFACE_COUNT (0x01U)
#define USB_PHDC_WEIGHT_SCALE_INTERFACE_INDEX (0x00U)

/*! @brief PHDC configuration */
#define USB_DEVICE_CONFIGURATION_COUNT (1U)
#define USB_PHDC_WEIGHT_SCALE_CONFIGURE_INDEX (1U)

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

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
 * @param speed Speed type. USB_SPEED_HIGH/USB_SPEED_FULL/USB_SPEED_LOW.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
extern usb_status_t USB_DeviceSetSpeed(uint8_t speed);

/*!
 * @brief device callback function.
 * This function handles the usb standard event. more information, please refer to usb spec chapter 9.
 *
 * @param handle          The USB device handle.
 * @param event           The USB device event type.
 * @param param           The parameter of the device specific request.
 *
 * @return kStatus_USB_Success or error.
 */
extern usb_status_t USB_DeviceCallback(usb_device_handle handle, uint32_t event, void *param);

#if defined(__cplusplus)
}
#endif
#endif /* _USB_DEVICE_DESCRIPTOR_H_ */
