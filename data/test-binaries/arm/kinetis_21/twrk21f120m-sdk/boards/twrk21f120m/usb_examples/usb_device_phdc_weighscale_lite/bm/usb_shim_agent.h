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
#ifndef _USB_SHIM_AGENT_H_
#define _USB_SHIM_AGENT_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief QoS bin elements */
#define SHIM_AGENT_MAX_QUEUE_NUMBER (0x04U)

/*! @brief Shim event definition */
#define SHIM_AGENT_EVENT_RECV_MESSAGE_PREAMBLE (0x00U)
#define SHIM_AGENT_EVENT_RECV_OPAQUE_DATA (0x01U)
#define SHIM_AGENT_EVENT_RECV_COMPLETE (0x02U)
#define SHIM_AGENT_EVENT_SENT_COMPLETE (0x03U)

/*! @brief USB event */
#define USB_PHDC_EVENT_INTERRUPT_IN_SEND_COMPLETE (0x00U)
#define USB_PHDC_EVENT_BULK_IN_SEND_COMPLETE (0x01U)

#if META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED
#define METADATA_PREAMBLE_SIGNATURE (16U)
#endif
/*! @brief the application data structure */
typedef struct _usb_shim_application_data_struct
{
    uint32_t transferSize; /*!< Transfer size */
    uint8_t *buffer;       /*!< Data buffer */
} usb_shim_application_data_struct_t;

/*! @brief the TX data structure */
typedef struct _usb_shim_tx_data_struct
{
    uint8_t epNumber;                                                         /*!< Endpoint number */
    uint32_t seller;                                                          /*!< Number of queued transfers */
    uint32_t buyer;                                                           /*!< Number of dequeued transfers */
    usb_shim_application_data_struct_t sendData[SHIM_AGENT_MAX_QUEUE_NUMBER]; /*!< Data to send */
} usb_shim_tx_data_struct_t;

/*! @brief the RX data structure */
typedef struct _usb_shim_rx_data_struct
{
    uint8_t epNumber;                            /*!< Endpoint number */
    uint16_t epMaxPacketSize;                    /*!< Endpoint max packet size */
    uint32_t transferCount;                      /*!< Size of transferred data */
    usb_shim_application_data_struct_t recvData; /*!< Data to receive */
} usb_shim_rx_data_struct_t;

#if META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED
/*! @brief meta-data message preamble structure */
typedef struct _usb_shim_metadata_preamble
{
    uint8_t aSignature[METADATA_PREAMBLE_SIGNATURE]; /*!< constant used to give preamble verifiability */
    uint8_t bNumberTransfers;     /*!< count of following transfer to which the QoS setting applies */
    uint8_t bQosEncodingVersion;  /*!< version of QoS information encoding */
    uint8_t bmLatencyReliability; /*!< refer to latency/reliability bin for the QoS data */
    uint8_t bOpaqueDataSize;      /*!< opaque QoS data or meta-data size */
    uint8_t *bOpaqueData;         /*!< opaque meta-data */
} usb_shim_metadata_preamble_t;
#endif

/*! @brief USB Shim structure */
typedef struct _usb_shim_agent_struct
{
    usb_device_handle deviceHandle;               /*!< The device handle */
    uint8_t speed;                                /*!< Used to store the device speed */
    uint8_t attach;                               /*!< Used to store the attach event */
    uint8_t currentConfig;                        /*!< Current configuration */
    uint8_t currentInterfaceAlternateSetting[1U]; /*!< Current alternate setting of the interface*/
#if META_DATA_MESSAGE_PREAMBLE_IMPLEMENTED
    uint8_t isMetaDataMessagePreambleEnabled; /*!< Used to store whether meta-data feature is active or not */
    uint8_t numberTransferBulkOut;            /*!< the number of transfer that follow Meta-data Message Preamble */
    uint8_t numberTransferBulkIn;             /*!< the number of transfer that follow Meta-data Message Preamble */
#endif
    uint16_t endpointsHaveData;                /*!< Which endpoints on the device have data */
    usb_shim_rx_data_struct_t bulkOutData;     /*!< Receive data information */
    usb_shim_tx_data_struct_t bulkInData;      /*!< Send data information */
    usb_shim_tx_data_struct_t interruptInData; /*!< Send data information */
    uint8_t *recvDataBuffer;                   /*!< Receive data buffer */
    uint8_t *classBuffer;                      /*!< class specific transfer buffer */
} usb_shim_agent_struct_t;

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

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
extern usb_status_t USB_ShimAgentRecvComplete(uint32_t handle, void *param);

/*!
 * @brief USB shim agent send data callback function.
 *
 * This function is the callback function of USB shim agent send function, it is implemented
 * to continue sending the data in sending queue if the queue is not empty.
 *
 * @param handle                The device handle.
 * @param event                 The event code.
 * @param param                 The param of receive callback function.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
extern usb_status_t USB_ShimAgentSendComplete(uint32_t handle, uint32_t event, void *param);

/*!
 * @brief USB shim agent send data function.
 *
 * This function implements a queue to support sending multiple transfer request.
 *
 * @param handle                The device handle.
 * @param qos                   The current QoS of the transfer.
 * @param appBuffer             The data buffer.
 * @param size                  The length of the transfer.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
extern usb_status_t USB_ShimAgentSendData(uint32_t handle, uint8_t qos, uint8_t *appBuffer, uint32_t size);

/*!
 * @brief agent callback.
 *
 * This function is the callback function called by transport layer and then it
 * will call to proper agent functions.
 *
 * @param handle        the agent handle.
 * @param request       the callback request.
 * @param data          the callback data.
 * @param size          the callback data size.
 */
extern void AGENT_Callback(uint32_t handle, uint8_t request, uint8_t *data, uint32_t size);

#if defined(__cplusplus)
}
#endif
#endif /* _USB_SHIM_AGENT_H_ */
