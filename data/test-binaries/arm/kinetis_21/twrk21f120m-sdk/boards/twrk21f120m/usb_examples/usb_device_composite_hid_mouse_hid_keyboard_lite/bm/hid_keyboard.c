/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
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

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_hid.h"

#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"

#include "composite.h"

#include "hid_keyboard.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static usb_status_t USB_DeviceHidKeyboardAction(void);
static usb_status_t USB_DeviceHidKeyboardInterruptIn(usb_device_handle handle,
                                                     usb_device_endpoint_callback_message_struct_t *message,
                                                     void *callbackParam);
/*******************************************************************************
 * Variables
 ******************************************************************************/

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_KeyboardBuffer[USB_HID_KEYBOARD_REPORT_LENGTH];
static usb_device_composite_struct_t *s_UsbDeviceComposite;
static usb_device_hid_keyboard_struct_t s_UsbDeviceHidKeyboard;

/*******************************************************************************
 * Code
 ******************************************************************************/

static usb_status_t USB_DeviceHidKeyboardAction(void)
{
    static int x = 0U;
    enum
    {
        DOWN,
        UP
    };
    static uint8_t dir = DOWN;

    s_UsbDeviceHidKeyboard.buffer[2] = 0x00U;
    switch (dir)
    {
        case DOWN:
            x++;
            if (x > 200U)
            {
                dir++;
                s_UsbDeviceHidKeyboard.buffer[2] = KEY_PAGEUP;
            }
            break;
        case UP:
            x--;
            if (x < 1U)
            {
                dir = DOWN;
                s_UsbDeviceHidKeyboard.buffer[2] = KEY_PAGEDOWN;
            }
            break;
        default:
            break;
    }
    return USB_DeviceSendRequest(s_UsbDeviceComposite->deviceHandle, USB_HID_KEYBOARD_ENDPOINT_IN,
                                 s_UsbDeviceHidKeyboard.buffer, USB_HID_KEYBOARD_REPORT_LENGTH);
}

static usb_status_t USB_DeviceHidKeyboardInterruptIn(usb_device_handle handle,
                                                     usb_device_endpoint_callback_message_struct_t *message,
                                                     void *callbackParam)
{
    if (s_UsbDeviceComposite->attach)
    {
        return USB_DeviceHidKeyboardAction();
    }

    return kStatus_USB_Error;
}

usb_status_t USB_DeviceHidKeyboardSetConfigure(usb_device_handle handle, uint8_t configure)
{
    usb_device_endpoint_init_struct_t epInitStruct;
    usb_device_endpoint_callback_struct_t epCallback;

    if (USB_COMPOSITE_CONFIGURE_INDEX == configure)
    {
        epCallback.callbackFn = USB_DeviceHidKeyboardInterruptIn;
        epCallback.callbackParam = handle;

        epInitStruct.zlt = 0U;
        epInitStruct.transferType = USB_ENDPOINT_INTERRUPT;
        epInitStruct.endpointAddress =
            USB_HID_KEYBOARD_ENDPOINT_IN | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
        if (USB_SPEED_HIGH == s_UsbDeviceComposite->speed)
        {
            epInitStruct.maxPacketSize = HS_HID_KEYBOARD_INTERRUPT_IN_PACKET_SIZE;
        }
        else
        {
            epInitStruct.maxPacketSize = FS_HID_KEYBOARD_INTERRUPT_IN_PACKET_SIZE;
        }

        USB_DeviceInitEndpoint(handle, &epInitStruct, &epCallback);

        return USB_DeviceHidKeyboardAction(); /* run the cursor movement code */
    }
    return kStatus_USB_Error;
}

usb_status_t USB_DeviceHidKeyboardClassRequest(usb_device_handle handle,
                                               usb_setup_struct_t *setup,
                                               uint8_t **buffer,
                                               uint32_t *length)
{
    usb_status_t error = kStatus_USB_InvalidRequest;

    if (setup->wIndex != USB_HID_KEYBOARD_INTERFACE_INDEX)
    {
        return error;
    }

    switch (setup->bRequest)
    {
        case USB_DEVICE_HID_REQUEST_GET_REPORT:
            break;
        case USB_DEVICE_HID_REQUEST_GET_IDLE:
            break;
        case USB_DEVICE_HID_REQUEST_GET_PROTOCOL:
            break;
        case USB_DEVICE_HID_REQUEST_SET_REPORT:
            break;
        case USB_DEVICE_HID_REQUEST_SET_IDLE:
            error = kStatus_USB_Success;
            s_UsbDeviceHidKeyboard.idleRate = 125U;
            break;
        case USB_DEVICE_HID_REQUEST_SET_PROTOCOL:
            break;
        default:
            break;
    }

    return error;
}

usb_status_t USB_DeviceHidKeyboardEndpointUnstall(usb_device_handle handle, uint8_t ep)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    USB_DeviceCancel(handle, ep);
    error = USB_DeviceUnstallEndpoint(handle, ep);
    USB_DeviceHidKeyboardAction(); /* run the cursor movement code */
    return error;
}

usb_status_t USB_DeviceHidKeyboardEndpointStall(usb_device_handle handle, uint8_t ep)
{
    USB_DeviceCancel(handle, ep);
    return USB_DeviceStallEndpoint(handle, ep);
}

usb_status_t USB_DeviceHidKeyboardInit(usb_device_composite_struct_t *deviceComposite)
{
    s_UsbDeviceComposite = deviceComposite;
    s_UsbDeviceHidKeyboard.buffer = s_KeyboardBuffer;
    return kStatus_USB_Success;
}
