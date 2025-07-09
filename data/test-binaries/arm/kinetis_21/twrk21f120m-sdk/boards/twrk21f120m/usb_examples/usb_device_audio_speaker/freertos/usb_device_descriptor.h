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

#ifndef __USB_DEVICE_DESCRIPTOR_H__
#define __USB_DEVICE_DESCRIPTOR_H__

/*******************************************************************************
* Definitions
******************************************************************************/

#define USB_DEVICE_SPECIFIC_BCD_VERSION (0x0200U)
#define USB_DEVICE_DEMO_BCD_VERSION (0x0101U)

#define USB_DEVICE_MAX_POWER (0x32U)

/* usb descritpor length */
#define USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL (sizeof(g_UsbDeviceConfigurationDescriptor))

#define USB_ENDPOINT_AUDIO_DESCRIPTOR_LENGTH (9)
#define USB_AUDIO_CLASS_SPECIFIC_ENDPOINT_LENGTH (8)
#define USB_AUDIO_STANDARD_AS_ISO_DATA_ENDPOINT_LENGTH (7)
#define USB_AUDIO_STANDARD_AS_ISO_FEEDBACK_ENDPOINT_LENGTH (7)
#define USB_AUDIO_CONTROL_INTERFACE_HEADER_LENGTH (9)
#define USB_DESCRIPTOR_LENGTH_AC_INTERRUPT_ENDPOINT (9)
#define USB_AUDIO_INPUT_TERMINAL_ONLY_DESC_SIZE (12)
#define USB_AUDIO_OUTPUT_TERMINAL_ONLY_DESC_SIZE (9)
#define USB_AUDIO_FEATURE_UNIT_ONLY_DESC_SIZE(ch, n) (0x07 + (ch + 1) * n)
#define USB_AUDIO_STREAMING_IFACE_DESC_SIZE (7)
#define USB_AUDIO_STREAMING_ENDP_DESC_SIZE (7)
#define USB_AUDIO_STREAMING_TYPE_I_DESC_SIZE (11)

/* Configuration, interface and endpoint. */
#define USB_DEVICE_CONFIGURATION_COUNT (1)
#define USB_DEVICE_STRING_COUNT (3)
#define USB_DEVICE_LANGUAGE_COUNT (1)

#define USB_AUDIO_SPEAKER_CONFIGURE_INDEX (1)
#define USB_AUDIO_CONTROL_INTERFACE_INDEX (0)
#define USB_AUDIO_STREAM_INTERFACE_INDEX (1)

#define USB_AUDIO_STREAM_ENDPOINT_COUNT (2)
#define USB_AUDIO_CONTROL_ENDPOINT_COUNT (1)

#define USB_AUDIO_SPEAKER_STREAM_ENDPOINT (2)
#define USB_AUDIO_CONTROL_ENDPOINT (1)
#define USB_AUDIO_SPEAKER_FEEDBACK_ENDPOINT (2)

#define USB_AUDIO_SPEAKER_INTERFACE_COUNT \
    (USB_AUDIO_SPEAKER_CONTROL_INTERFACE_COUNT + USB_AUDIO_SPEAKER_STREAM_INTERFACE_COUNT)
#define USB_AUDIO_SPEAKER_CONTROL_INTERFACE_COUNT (1)
#define USB_AUDIO_SPEAKER_STREAM_INTERFACE_COUNT (1)

/* Audio data format */
#define AUDIO_FORMAT_CHANNELS (0x02)
#define AUDIO_FORMAT_BITS (16)
#define AUDIO_FORMAT_SIZE (0x02)

/* Packet size and interval. */
#define HS_AUDIO_INTERRUPT_IN_PACKET_SIZE (8)
#define FS_AUDIO_INTERRUPT_IN_PACKET_SIZE (8)
#define HS_AUDIO_INTERRUPT_IN_INTERVAL (0x07U) /* 2^(7-1) = 8ms */
#define FS_AUDIO_INTERRUPT_IN_INTERVAL (0x08U)
#define HS_ISO_OUT_ENDP_PACKET_SIZE                    \
    (AUDIO_SAMPLING_RATE_KHZ * AUDIO_FORMAT_CHANNELS * \
     AUDIO_FORMAT_SIZE) /* This should be changed to 192 if sampling rate is 48k */
#define FS_ISO_OUT_ENDP_PACKET_SIZE (AUDIO_SAMPLING_RATE_KHZ * AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE)
#define HS_ISO_FEEDBACK_ENDP_PACKET_SIZE (4)
#define FS_ISO_FEEDBACK_ENDP_PACKET_SIZE (3)
#define HS_ISO_OUT_ENDP_INTERVAL (0x04)
#define HS_ISO_IN_ENDP_INTERVAL (0x04)
#define FS_ISO_OUT_ENDP_INTERVAL (0x01)
#define FS_ISO_IN_ENDP_INTERVAL (0x01)
#define ISO_OUT_ENDP_INTERVAL (0x01)

/* String descriptor length. */
#define USB_DESCRIPTOR_LENGTH_STRING0 (sizeof(g_UsbDeviceString0))
#define USB_DESCRIPTOR_LENGTH_STRING1 (sizeof(g_UsbDeviceString1))
#define USB_DESCRIPTOR_LENGTH_STRING2 (sizeof(g_UsbDeviceString2))

/* Class code. */
#define USB_DEVICE_CLASS (0x00)
#define USB_DEVICE_SUBCLASS (0x00)
#define USB_DEVICE_PROTOCOL (0x00)

#define USB_AUDIO_CLASS (0x01)
#define USB_SUBCLASS_AUDIOCONTROL (0x01)
#define USB_SUBCLASS_AUDIOSTREAM (0x02)
#define USB_AUDIO_PROTOCOL (0x00)

#define USB_AUDIO_FORMAT_TYPE_I (0x01)
#define USB_AUDIO_STREAM_ENDPOINT_DESCRIPTOR (0x25)
#define USB_AUDIO_EP_GENERAL_DESCRIPTOR_SUBTYPE (0x01)

#define USB_AUDIO_SPEAKER_CONTROL_INPUT_TERMINAL_ID (0x01)
#define USB_AUDIO_SPEAKER_CONTROL_FEATURE_UNIT_ID (0x02)
#define USB_AUDIO_SPEAKER_CONTROL_OUTPUT_TERMINAL_ID (0x03)

/*******************************************************************************
* API
******************************************************************************/
/*!
 * @brief USB device set speed function.
 *
 * This function sets the speed of the USB device.
 *
 * @param handle The USB device handle.
 * @param speed Speed type. USB_SPEED_HIGH/USB_SPEED_FULL/USB_SPEED_LOW.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
extern usb_status_t USB_DeviceSetSpeed(usb_device_handle handle, uint8_t speed);
/*!
 * @brief USB device get device descriptor function.
 *
 * This function gets the device descriptor of the USB device.
 *
 * @param handle The USB device handle.
 * @param deviceDescriptor The pointer to the device descriptor structure.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceGetDeviceDescriptor(usb_device_handle handle,
                                           usb_device_get_device_descriptor_struct_t *deviceDescriptor);
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
    usb_device_handle handle, usb_device_get_configuration_descriptor_struct_t *configurationDescriptor);

usb_status_t USB_DeviceGetStringDescriptor(usb_device_handle handle,
                                           usb_device_get_string_descriptor_struct_t *stringDescriptor);

#endif /* __USB_DESCRIPTOR_H__ */
