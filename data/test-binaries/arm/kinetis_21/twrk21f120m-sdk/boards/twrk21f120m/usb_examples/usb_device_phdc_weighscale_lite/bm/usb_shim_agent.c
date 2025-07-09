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

#include "usb_device_phdc.h"

#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ieee11073_types.h"
#include "ieee11073_timer.h"
#include "ieee11073_agent.h"
#include "usb_shim_agent.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

#if META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED
/*! @brief the string used to give preamble verifiability */
static char metaDataMsgPreambleSignature[16U] = "PhdcQoSSignature";
#endif
extern usb_shim_agent_struct_t g_shimAgent;

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief USB shim agent receive data callback function.
 *
 * This function implements a queue to support receiving the PHDC data with length is more than
 * maximum of endpoint packet size. Then notify to upper layer when receiving is all completed.
 *
 * @param handle                The device handle.
 * @param param                 The param of receive callback function.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_ShimAgentRecvComplete(uint32_t handle, void *param)
{
    usb_device_endpoint_callback_message_struct_t *message = (usb_device_endpoint_callback_message_struct_t *)param;
    if ((!message->length) || (USB_UNINITIALIZED_VAL_32 == message->length))
    {
        /* Prepare for the next receiving */
        USB_DeviceRecvRequest((void *)g_shimAgent.deviceHandle, g_shimAgent.bulkOutData.epNumber,
                              g_shimAgent.recvDataBuffer, g_shimAgent.bulkOutData.epMaxPacketSize);
        return kStatus_USB_Success;
    }
#if META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED
    if (1U == g_shimAgent.isMetaDataMessagePreambleEnabled)
    {
        /* The meta-data message preamble feature is enabled, then all data transfers or sets
        of data transfers shall be preceded by a meta-data message preamble transfer. The
        numberTransferBulkOut is initialized as zero for receiving this message preamble data,
        then it is updated to the value of bNumTransfers field of message preamble data */
        if (g_shimAgent.numberTransferBulkOut)
        {
            /* When numberTransferBulkOut reduces to 0, a new meta-data message preamble shall
            be transferred */
            g_shimAgent.numberTransferBulkOut--;
            AGENT_Callback(handle, SHIM_AGENT_EVENT_RECV_OPAQUE_DATA, (uint8_t *)(message->buffer), message->length);
            return kStatus_USB_Success;
        }
        else
        {
            uint8_t preambleSignatureChecking = 1U;
            /* The received packet is meta-data message preamble */
            usb_shim_metadata_preamble_t *metaDataMsgPreamble = (usb_shim_metadata_preamble_t *)message->buffer;
            /* Meta-data message preamble signature checking */
            for (uint8_t i = 0U; i < METADATA_PREAMBLE_SIGNATURE; i++)
            {
                if ((metaDataMsgPreamble->aSignature[i]) != metaDataMsgPreambleSignature[i])
                {
                    preambleSignatureChecking = 0U;
                    break;
                }
            }
            if (preambleSignatureChecking)
            {
                /* Checks if the meta-data message preamble contains an invalid bmLatencyReliability value
                or bNumTransfers value */
                if ((!(metaDataMsgPreamble->bNumberTransfers)) ||            /* bNumTransfers shall never equal zero */
                    (metaDataMsgPreamble->bQosEncodingVersion != 0x01U) ||   /* Encoding version should be 0x01 */
                    ((metaDataMsgPreamble->bmLatencyReliability != 0x02U) && /* Medium.Good latency, reliability bin */
                     (metaDataMsgPreamble->bmLatencyReliability !=
                      0x04U) && /* Medium.Better latency, reliability bin */
                     (metaDataMsgPreamble->bmLatencyReliability != 0x08U) && /* Medium.Best latency, reliability bin */
                     (metaDataMsgPreamble->bmLatencyReliability != 0x10U) && /* High.Best latency, reliability bin */
                     (metaDataMsgPreamble->bmLatencyReliability != 0x20U) /* VeryHigh.Best latency, reliability bin */))
                {
                    /* The device shall stall subsequent transaction to the receiving endpoint */
                    return kStatus_USB_InvalidRequest;
                }
                else
                {
                    /* The meta-data message preamble data is correct, update the phdc status and numberTransferBulkOut
                     * value */
                    g_shimAgent.numberTransferBulkOut = metaDataMsgPreamble->bNumberTransfers;
                    AGENT_Callback(handle, SHIM_AGENT_EVENT_RECV_MESSAGE_PREAMBLE, (uint8_t *)(message->buffer),
                                   message->length);
                    return kStatus_USB_Success;
                }
            }
            else
            {
                /* The device shall stall subsequent transaction to the receiving endpoint */
                return kStatus_USB_InvalidRequest;
            }
        }
    }
#endif
    if (NULL == g_shimAgent.bulkOutData.recvData.buffer)
    {
        /* Save the length of the first received data block */
        g_shimAgent.bulkOutData.transferCount = message->length;
        g_shimAgent.bulkOutData.recvData.transferSize =
            (uint32_t)(USB_SHORT_FROM_BIG_ENDIAN(*((uint16_t *)message->buffer + 1U)) + 4U /* APDU header */);
        g_shimAgent.bulkOutData.recvData.buffer = &g_shimAgent.recvDataBuffer[0];
        /* Save the received data */
        memcpy(g_shimAgent.bulkOutData.recvData.buffer, message->buffer, message->length);
    }
    else
    {
        /* update the transferred data length */
        g_shimAgent.bulkOutData.transferCount += message->length;
    }
    if (g_shimAgent.bulkOutData.transferCount == g_shimAgent.bulkOutData.recvData.transferSize)
    {
        /* Receive all the data */
        AGENT_Callback(handle, SHIM_AGENT_EVENT_RECV_COMPLETE, g_shimAgent.bulkOutData.recvData.buffer,
                       g_shimAgent.bulkOutData.recvData.transferSize);
        g_shimAgent.bulkOutData.transferCount = 0;
        g_shimAgent.bulkOutData.recvData.transferSize = 0;
        g_shimAgent.bulkOutData.recvData.buffer = NULL;
        /* Prepare for the next receiving */
        USB_DeviceRecvRequest((void *)handle, g_shimAgent.bulkOutData.epNumber, g_shimAgent.recvDataBuffer,
                              g_shimAgent.bulkOutData.epMaxPacketSize);
    }
    else
    {
        /* The data is still pending for receiving */
        (void)USB_DeviceRecvRequest(
            (void *)handle, g_shimAgent.bulkOutData.epNumber,
            (uint8_t *)(g_shimAgent.bulkOutData.recvData.buffer + g_shimAgent.bulkOutData.transferCount),
            g_shimAgent.bulkOutData.epMaxPacketSize);
    }
    return kStatus_USB_Success;
}

/*!
 * @brief USB shim agent send data callback function.
 *
 * This function is the callback function of USB shim agent send function, it is implemented
 * to continue sending the data in sending queue if the queue is not empty.
 *
 * @param handle                he device handle.
 * @param param                 The param of receive callback function.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_ShimAgentSendComplete(uint32_t handle, uint32_t event, void *param)
{
    usb_device_endpoint_callback_message_struct_t *message = (usb_device_endpoint_callback_message_struct_t *)param;
    usb_shim_tx_data_struct_t *sentData = NULL;
    if (USB_PHDC_EVENT_INTERRUPT_IN_SEND_COMPLETE == event)
    {
        sentData = &g_shimAgent.interruptInData;
    }
    else
    {
        sentData = &g_shimAgent.bulkInData;
    }
    g_shimAgent.endpointsHaveData &= (uint16_t)(~(uint16_t)(1U << sentData->epNumber));
    /* notify the application of the send complete */
    AGENT_Callback(handle, SHIM_AGENT_EVENT_SENT_COMPLETE, (uint8_t *)message->buffer, message->length);
    /* de-queue the queue */
    sentData->buyer += 1U;
    if (sentData->buyer != sentData->seller)
    {
        /* Set bit map for the corresponding endpoint*/
        g_shimAgent.endpointsHaveData |= (uint16_t)(1U << sentData->epNumber);
        USB_DeviceSendRequest((void *)handle, sentData->epNumber,
                              sentData->sendData[sentData->buyer % SHIM_AGENT_MAX_QUEUE_NUMBER].buffer,
                              sentData->sendData[sentData->buyer % SHIM_AGENT_MAX_QUEUE_NUMBER].transferSize);
    }
    return kStatus_USB_Success;
}

/*!
 * @brief USB shim agent send data function.
 *
 * This function implements a queue to support sending multiple transfer request.
 *
 * @param handle                The device handle.
 * @param metaData              The flag to check the data to send is meta data or not.
 * @param numberTransfer        The number of transfer following the meta data message preamble
 *                              when sending data is meta data.
 * @param qos                   The current QoS of the transfer.
 * @param appBuffer             The data buffer.
 * @param size                  The length of the transfer.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_ShimAgentSendData(uint32_t handle, uint8_t qos, uint8_t *appBuffer, uint32_t size)
{
    usb_status_t status = kStatus_USB_Success;
    usb_shim_tx_data_struct_t *dataToSend = NULL;
    if (qos != 0x01U /* low latency/good reliability */)
    {
#if META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED
        if (1U == g_shimAgent.isMetaDataMessagePreambleEnabled)
        {
            /* The meta-data message preamble feature is enabled, then all data transfers or sets
            of data transfers shall be preceded by a meta-data message preamble transfer. The
            numberTransferBulkIn is initialized as zero for sending this message preamble data,
            then it is updated to the value of bNumTransfers field of message preamble data */
            if (g_shimAgent.numberTransferBulkOut)
            {
                /* When numberTransferBulkIn reduces to 0, a new meta-data message preamble shall
                be transferred */
                g_shimAgent.numberTransferBulkIn--;
            }
            {
                uint8_t latencyReliability = ((usb_shim_metadata_preamble_t *)appBuffer)->bmLatencyReliability;
                /* Latency reliability validity checking */
                if ((latencyReliability != 0x02U) && /* Medium.Good latency, reliability bin */
                    (latencyReliability != 0x04U) && /* Medium.Better latency, reliability bin */
                    (latencyReliability != 0x08U) && /* Medium.Best latency, reliability bin */
                    (latencyReliability != 0x10U) && /* High.Best latency, reliability bin */
                    (latencyReliability != 0x20U) /* VeryHigh.Best latency, reliability bin */)
                {
                    status = kStatus_USB_InvalidRequest;
                    usb_echo("USB_ShimAgentSendData: Error invalid LatencyReliability");
                }
                /* LatencyReliablity checking */
                if (0U == (USB_PHDC_WEIGHT_SCALE_BULK_IN_QOS & ~latencyReliability))
                {
                    status = kStatus_USB_Error;
                    usb_echo(
                        "USB_ShimAgentSendData: Error the latency reliability is not supported by Bulk IN endpoint");
                }
                if (0U == ((usb_shim_metadata_preamble_t *)appBuffer)->bNumberTransfers)
                {
                    status = kStatus_USB_Error;
                    usb_echo("USB_ShimAgentSendData: Error the numTransfer should never zero");
                }
                /* Update the number of bulk in transfer */
                g_shimAgent.numberTransferBulkIn = ((usb_shim_metadata_preamble_t *)appBuffer)->bNumberTransfers;
            }
        }
#endif
        /* Initialize the data to send */
        dataToSend = &g_shimAgent.bulkInData;
    }
    else
    {
        /* Initialize the data to send */
        dataToSend = &g_shimAgent.interruptInData;
    }
    if (kStatus_USB_Success == status)
    {
        /* Set bit map for the corresponding endpoint*/
        g_shimAgent.endpointsHaveData |= (uint16_t)(1U << dataToSend->epNumber);
        /* Add data to send to sending queue */
        if ((uint8_t)(dataToSend->seller - dataToSend->buyer) < (uint8_t)(SHIM_AGENT_MAX_QUEUE_NUMBER))
        {
            dataToSend->sendData[dataToSend->seller % SHIM_AGENT_MAX_QUEUE_NUMBER].transferSize = size;
            dataToSend->sendData[dataToSend->seller % SHIM_AGENT_MAX_QUEUE_NUMBER].buffer = appBuffer;
            /* increase queue number by 1 */
            dataToSend->seller += 1U;
            /* send the first entry of queue */
            if (1U == (uint32_t)(dataToSend->seller - dataToSend->buyer))
            {
                status = USB_DeviceSendRequest((void *)handle, dataToSend->epNumber, appBuffer, size);
            }
        }
        else
        {
            /* sending queue is full */
            status = kStatus_USB_Busy;
        }
    }
    return status;
}
