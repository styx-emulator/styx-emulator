/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 - 2017 NXP
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
#include "fsl_device_registers.h"
#include "clock_config.h"
#include "board.h"

#include <stdio.h>
#include <stdlib.h>

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_cdc_acm.h"
#include "usb_device_ch9.h"
#include "fsl_debug_console.h"

#include "usb_device_descriptor.h"
#include "composite.h"
/*******************************************************************************
* Definitions
******************************************************************************/

/*******************************************************************************
* Variables
******************************************************************************/
/* Line codinig of cdc device */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_lineCoding[LINE_CODING_SIZE] = {
    /* E.g. 0x00,0xC2,0x01,0x00 : 0x0001C200 is 115200 bits per second */
    (LINE_CODING_DTERATE >> 0U) & 0x000000FFU,
    (LINE_CODING_DTERATE >> 8U) & 0x000000FFU,
    (LINE_CODING_DTERATE >> 16U) & 0x000000FFU,
    (LINE_CODING_DTERATE >> 24U) & 0x000000FFU,
    LINE_CODING_CHARFORMAT,
    LINE_CODING_PARITYTYPE,
    LINE_CODING_DATABITS};

/* Abstract state of cdc device */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_abstractState[COMM_FEATURE_DATA_SIZE] = {(STATUS_ABSTRACT_STATE >> 0U) & 0x00FFU,
                                                          (STATUS_ABSTRACT_STATE >> 8U) & 0x00FFU};

/* Country code of cdc device */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_countryCode[COMM_FEATURE_DATA_SIZE] = {(COUNTRY_SETTING >> 0U) & 0x00FFU,
                                                        (COUNTRY_SETTING >> 8U) & 0x00FFU};

/* CDC ACM information */
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static usb_cdc_acm_info_t s_usbCdcAcmInfo = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0, 0, 0, 0, 0};

/* Data buffer for receiving and sending*/
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_currRecvBuf[DATA_BUFF_SIZE];
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_currSendBuf[DATA_BUFF_SIZE];
volatile static uint32_t s_recvSize = 0;
volatile static uint32_t s_sendSize = 0;
static uint32_t s_usbBulkMaxPacketSize = FS_CDC_VCOM_BULK_OUT_PACKET_SIZE;
volatile static usb_device_composite_struct_t *g_deviceComposite;

/*******************************************************************************
* Code
******************************************************************************/
/*!
 * @brief Interrupt in pipe callback function.
 *
 * This function serves as the callback function for interrupt in pipe.
 *
 * @param handle The USB device handle.
 * @param message The endpoint callback message
 * @param callbackParam The parameter of the callback.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcAcmInterruptIn(usb_device_handle handle,
                                         usb_device_endpoint_callback_message_struct_t *message,
                                         void *callbackParam)
{
    usb_status_t error = kStatus_USB_Error;
    g_deviceComposite->cdcVcom.hasSentState = 0;
    return error;
}

/*!
 * @brief Bulk in pipe callback function.
 *
 * This function serves as the callback function for bulk in pipe.
 *
 * @param handle The USB device handle.
 * @param message The endpoint callback message
 * @param callbackParam The parameter of the callback.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcAcmBulkIn(usb_device_handle handle,
                                    usb_device_endpoint_callback_message_struct_t *message,
                                    void *callbackParam)
{
    usb_status_t error = kStatus_USB_Error;

    if ((message->length != 0) && (!(message->length % s_usbBulkMaxPacketSize)))
    {
        /* If the last packet is the size of endpoint, then send also zero-ended packet,
         ** meaning that we want to inform the host that we do not have any additional
         ** data, so it can flush the output.
         */
        USB_DeviceSendRequest(handle, USB_CDC_VCOM_DIC_BULK_IN_ENDPOINT, NULL, 0);
    }
    else if ((1 == g_deviceComposite->cdcVcom.attach) && (1 == g_deviceComposite->cdcVcom.startTransactions))
    {
        if ((message->buffer != NULL) || ((message->buffer == NULL) && (message->length == 0)))
        {
            /* User: add your own code for send complete event */
            /* Schedule buffer for next receive event */
            USB_DeviceRecvRequest(handle, USB_CDC_VCOM_DIC_BULK_OUT_ENDPOINT, s_currRecvBuf, s_usbBulkMaxPacketSize);
        }
    }
    else
    {
    }
    return error;
}

/*!
 * @brief Bulk out pipe callback function.
 *
 * This function serves as the callback function for bulk out pipe.
 *
 * @param handle The USB device handle.
 * @param message The endpoint callback message
 * @param callbackParam The parameter of the callback.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcAcmBulkOut(usb_device_handle handle,
                                     usb_device_endpoint_callback_message_struct_t *message,
                                     void *callbackParam)
{
    usb_status_t error = kStatus_USB_Error;

    if ((1 == g_deviceComposite->cdcVcom.attach) && (1 == g_deviceComposite->cdcVcom.startTransactions))
    {
        s_recvSize = message->length;

        if (!s_recvSize)
        {
            /* Schedule buffer for next receive event */
            USB_DeviceRecvRequest(handle, USB_CDC_VCOM_DIC_BULK_OUT_ENDPOINT, s_currRecvBuf, s_usbBulkMaxPacketSize);
        }
    }
    return error;
}

/*!
 * @brief USB configure endpoint function.
 *
 * This function configure endpoint status.
 *
 * @param handle The USB device handle.
 * @param ep Endpoint address.
 * @param status A flag to indicate whether to stall the endpoint. 1: stall, 0: unstall.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcVcomConfigureEndpointStatus(usb_device_handle handle, uint8_t ep, uint8_t status)
{
    usb_status_t error = kStatus_USB_Error;
    if (status)
    {
        if ((USB_CDC_VCOM_DIC_BULK_IN_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
            (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            error = USB_DeviceStallEndpoint(handle, ep);
        }
        else if ((USB_CDC_VCOM_DIC_BULK_OUT_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
                 (!(ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK)))
        {
            error = USB_DeviceStallEndpoint(handle, ep);
        }
        else
        {
        }
    }
    else
    {
        if ((USB_CDC_VCOM_DIC_BULK_IN_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
            (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            error = USB_DeviceUnstallEndpoint(handle, ep);
        }
        else if ((USB_CDC_VCOM_DIC_BULK_OUT_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
                 (!(ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK)))
        {
            error = USB_DeviceUnstallEndpoint(handle, ep);
        }
        else
        {
        }
    }
    return error;
}

/*!
 * @brief CDC class specific callback function.
 *
 * This function handles the CDC class specific requests.
 *
 * @param handle The USB device handle.
 * @param setup The pointer to the setup packet.
 * @param length The pointer to the length of the data buffer.
 * @param buffer The pointer to the address of setup packet data buffer.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcVcomClassRequest(usb_device_handle handle,
                                           usb_setup_struct_t *setup,
                                           uint32_t *length,
                                           uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;

    usb_cdc_acm_info_t *acmInfo = &s_usbCdcAcmInfo;
    uint32_t len;
    uint8_t *uartBitmap;
    if (setup->wIndex != USB_CDC_VCOM_CIC_INTERFACE_INDEX)
    {
        return error;
    }

    switch (setup->bRequest)
    {
        case USB_DEVICE_CDC_REQUEST_SEND_ENCAPSULATED_COMMAND:
            break;
        case USB_DEVICE_CDC_REQUEST_GET_ENCAPSULATED_RESPONSE:
            break;
        case USB_DEVICE_CDC_REQUEST_SET_COMM_FEATURE:
            if (USB_DEVICE_CDC_FEATURE_ABSTRACT_STATE == setup->wValue)
            {
                *buffer = s_abstractState;
            }
            else if (USB_DEVICE_CDC_FEATURE_COUNTRY_SETTING == setup->wValue)
            {
                *buffer = s_countryCode;
            }
            else
            {
            }
            error = kStatus_USB_Success;
            break;
        case USB_DEVICE_CDC_REQUEST_GET_COMM_FEATURE:
            if (USB_DEVICE_CDC_FEATURE_ABSTRACT_STATE == setup->wValue)
            {
                *buffer = s_abstractState;
                *length = COMM_FEATURE_DATA_SIZE;
            }
            else if (USB_DEVICE_CDC_FEATURE_COUNTRY_SETTING == setup->wValue)
            {
                *buffer = s_countryCode;
                *length = COMM_FEATURE_DATA_SIZE;
            }
            else
            {
            }
            error = kStatus_USB_Success;
            break;
        case USB_DEVICE_CDC_REQUEST_CLEAR_COMM_FEATURE:
            break;
        case USB_DEVICE_CDC_REQUEST_GET_LINE_CODING:
            *buffer = s_lineCoding;
            *length = LINE_CODING_SIZE;
            error = kStatus_USB_Success;
            break;
        case USB_DEVICE_CDC_REQUEST_SET_LINE_CODING:
            *buffer = s_lineCoding;
            error = kStatus_USB_Success;
            break;
        case USB_DEVICE_CDC_REQUEST_SET_CONTROL_LINE_STATE:
        {
            acmInfo->dteStatus = setup->wValue;
            /* activate/deactivate Tx carrier */
            if (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_CARRIER_ACTIVATION)
            {
                acmInfo->uartState |= USB_DEVICE_CDC_UART_STATE_TX_CARRIER;
            }
            else
            {
                acmInfo->uartState &= (uint16_t)~USB_DEVICE_CDC_UART_STATE_TX_CARRIER;
            }

            /* activate carrier and DTE */
            if (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_DTE_PRESENCE)
            {
                acmInfo->uartState |= USB_DEVICE_CDC_UART_STATE_RX_CARRIER;
            }
            else
            {
                acmInfo->uartState &= (uint16_t)~USB_DEVICE_CDC_UART_STATE_RX_CARRIER;
            }

            /* Indicates to DCE if DTE is present or not */
            acmInfo->dtePresent = (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_DTE_PRESENCE) ? true : false;

            /* Initialize the serial state buffer */
            acmInfo->serialStateBuf[0] = NOTIF_REQUEST_TYPE;                        /* bmRequestType */
            acmInfo->serialStateBuf[1] = USB_DEVICE_CDC_REQUEST_SERIAL_STATE_NOTIF; /* bNotification */
            acmInfo->serialStateBuf[2] = 0x00;                                      /* wValue */
            acmInfo->serialStateBuf[3] = 0x00;
            acmInfo->serialStateBuf[4] = 0x00; /* wIndex */
            acmInfo->serialStateBuf[5] = 0x00;
            acmInfo->serialStateBuf[6] = UART_BITMAP_SIZE; /* wLength */
            acmInfo->serialStateBuf[7] = 0x00;
            /* Notifiy to host the line state */
            acmInfo->serialStateBuf[4] = setup->wIndex;
            /* Lower byte of UART BITMAP */
            uartBitmap = (uint8_t *)&acmInfo->serialStateBuf[NOTIF_PACKET_SIZE + UART_BITMAP_SIZE - 2];
            uartBitmap[0] = acmInfo->uartState & 0xFFu;
            uartBitmap[1] = (acmInfo->uartState >> 8) & 0xFFu;
            len = (uint32_t)(NOTIF_PACKET_SIZE + UART_BITMAP_SIZE);
            if (0 == g_deviceComposite->cdcVcom.hasSentState)
            {
                error =
                    USB_DeviceSendRequest(handle, USB_CDC_VCOM_CIC_INTERRUPT_IN_ENDPOINT, acmInfo->serialStateBuf, len);
                if (kStatus_USB_Success != error)
                {
                    usb_echo("kUSB_DeviceCdcEventSetControlLineState error!");
                }
                g_deviceComposite->cdcVcom.hasSentState = 1;
            }
            /* Update status */
            if (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_CARRIER_ACTIVATION)
            {
                /*    To do: CARRIER_ACTIVATED */
            }
            else
            {
                /* To do: CARRIER_DEACTIVATED */
            }
            if (acmInfo->dteStatus & USB_DEVICE_CDC_CONTROL_SIG_BITMAP_DTE_PRESENCE)
            {
                /* DTE_ACTIVATED */
                if (1 == g_deviceComposite->cdcVcom.attach)
                {
                    g_deviceComposite->cdcVcom.startTransactions = 1;
                }
            }
            else
            {
                /* DTE_DEACTIVATED */
                if (1 == g_deviceComposite->cdcVcom.attach)
                {
                    g_deviceComposite->cdcVcom.startTransactions = 0;
                }
            }
        }
        break;
        case USB_DEVICE_CDC_REQUEST_SEND_BREAK:
            break;
        default:
            break;
    }

    return error;
}

/*!
 * @brief Application task function.
 *
 * This function runs the task for application.
 *
 * @return None.
 */
void USB_DeviceCdcVcomTask(void)
{
    usb_status_t error = kStatus_USB_Error;
    if ((1 == g_deviceComposite->cdcVcom.attach) && (1 == g_deviceComposite->cdcVcom.startTransactions))
    {
        /* User Code */
        if ((0 != s_recvSize) && (0xFFFFFFFFU != s_recvSize))
        {
            int32_t i;

            /* Copy Buffer to Send Buff */
            for (i = 0; i < s_recvSize; i++)
            {
                s_currSendBuf[s_sendSize++] = s_currRecvBuf[i];
            }
            s_recvSize = 0;
        }

        if (s_sendSize)
        {
            uint32_t size = s_sendSize;
            s_sendSize = 0;

            error = USB_DeviceSendRequest(g_deviceComposite->deviceHandle, USB_CDC_VCOM_DIC_BULK_IN_ENDPOINT,
                                          s_currSendBuf, size);

            if (error != kStatus_USB_Success)
            {
                /* Failure to send Data Handling code here */
            }
        }
    }
}

/*!
 * @brief Virtual COM device set configuration function.
 *
 * This function sets configuration for CDC class.
 *
 * @param handle The CDC ACM class handle.
 * @param configure The CDC ACM class configure index.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcVcomSetConfigure(usb_device_handle handle, uint8_t configure)
{
    usb_device_endpoint_init_struct_t epInitStruct;
    usb_device_endpoint_callback_struct_t epCallback;
    usb_status_t error = kStatus_USB_Error;

    if (g_deviceComposite->currentConfiguration == configure)
    {
        return error;
    }
    if (g_deviceComposite->currentConfiguration)
    {
        USB_DeviceDeinitEndpoint(
            g_deviceComposite->deviceHandle,
            (USB_CDC_VCOM_CIC_INTERRUPT_IN_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT)));
        USB_DeviceDeinitEndpoint(
            g_deviceComposite->deviceHandle,
            (USB_CDC_VCOM_DIC_BULK_IN_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT)));
        USB_DeviceDeinitEndpoint(
            g_deviceComposite->deviceHandle,
            (USB_CDC_VCOM_DIC_BULK_OUT_ENDPOINT | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT)));
    }

    if (USB_COMPOSITE_CONFIGURE_INDEX == configure)
    {
        g_deviceComposite->cdcVcom.attach = 1;

        /* Initiailize endpoint for interrupt pipe */
        epCallback.callbackFn = USB_DeviceCdcAcmInterruptIn;
        epCallback.callbackParam = handle;

        epInitStruct.zlt = 0;
        epInitStruct.transferType = USB_ENDPOINT_INTERRUPT;
        epInitStruct.endpointAddress =
            USB_CDC_VCOM_CIC_INTERRUPT_IN_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
        if (USB_SPEED_HIGH == g_deviceComposite->speed)
        {
            epInitStruct.maxPacketSize = HS_CDC_VCOM_INTERRUPT_IN_PACKET_SIZE;
        }
        else
        {
            epInitStruct.maxPacketSize = FS_CDC_VCOM_INTERRUPT_IN_PACKET_SIZE;
        }

        USB_DeviceInitEndpoint(handle, &epInitStruct, &epCallback);

        /* Initiailize endpoints for bulk pipe */
        epCallback.callbackFn = USB_DeviceCdcAcmBulkIn;
        epCallback.callbackParam = handle;

        epInitStruct.zlt = 0;
        epInitStruct.transferType = USB_ENDPOINT_BULK;
        epInitStruct.endpointAddress =
            USB_CDC_VCOM_DIC_BULK_IN_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
        if (USB_SPEED_HIGH == g_deviceComposite->speed)
        {
            epInitStruct.maxPacketSize = HS_CDC_VCOM_BULK_IN_PACKET_SIZE;
        }
        else
        {
            epInitStruct.maxPacketSize = FS_CDC_VCOM_BULK_IN_PACKET_SIZE;
        }

        USB_DeviceInitEndpoint(handle, &epInitStruct, &epCallback);

        epCallback.callbackFn = USB_DeviceCdcAcmBulkOut;
        epCallback.callbackParam = handle;

        epInitStruct.zlt = 0;
        epInitStruct.transferType = USB_ENDPOINT_BULK;
        epInitStruct.endpointAddress =
            USB_CDC_VCOM_DIC_BULK_OUT_ENDPOINT | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
        if (USB_SPEED_HIGH == g_deviceComposite->speed)
        {
            epInitStruct.maxPacketSize = HS_CDC_VCOM_BULK_OUT_PACKET_SIZE;
        }
        else
        {
            epInitStruct.maxPacketSize = FS_CDC_VCOM_BULK_OUT_PACKET_SIZE;
        }

        USB_DeviceInitEndpoint(handle, &epInitStruct, &epCallback);

        if (USB_SPEED_HIGH == g_deviceComposite->speed)
        {
            s_usbBulkMaxPacketSize = HS_CDC_VCOM_BULK_OUT_PACKET_SIZE;
        }
        else
        {
            s_usbBulkMaxPacketSize = FS_CDC_VCOM_BULK_OUT_PACKET_SIZE;
        }

        /* Schedule buffer for receive */
        USB_DeviceRecvRequest(handle, USB_CDC_VCOM_DIC_BULK_OUT_ENDPOINT, s_currRecvBuf, s_usbBulkMaxPacketSize);
    }
    return kStatus_USB_Success;
}

/*!
 * @brief Virtual COM device initialization function.
 *
 * This function initializes the device with the composite device class information.
 *
 * @param deviceComposite The pointer to the composite device structure.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceCdcVcomInit(usb_device_composite_struct_t *deviceComposite)
{
    g_deviceComposite = deviceComposite;
    return kStatus_USB_Success;
}
