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

#include "usb_host_config.h"
#include "usb_host.h"
#include "usb_host_cdc.h"
#include "host_cdc.h"
#include "fsl_debug_console.h"
#include "board.h"
#include "usb_serial_port.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define USB_KHCI_TASK_STACKSIZE 3500U
/*******************************************************************************
  * Prototypes
  ******************************************************************************/
/*******************************************************************************
  * Variables
  ******************************************************************************/

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t s_DataBuffer[USB_HOST_CDC_BUFFER_NUM * 2][USB_DATA_ALIGN_SIZE_MULTIPLE(USB_HOST_SEND_RECV_PER_TIME)];
usb_uart_buffer_struct_t g_EmptyBuffer[USB_HOST_CDC_BUFFER_NUM];
usb_uart_buffer_struct_t g_EmptySendBuffer[USB_HOST_CDC_BUFFER_NUM];

usb_uart_buffer_struct_t *g_EmptyQueue;
usb_uart_buffer_struct_t *g_EmptySendQueue;

usb_uart_buffer_struct_t *g_CurrentUartRecvNode;

usb_uart_buffer_struct_t *g_UsbSendQueue;
usb_uart_buffer_struct_t *g_UsbSendNode;
usb_uart_buffer_struct_t *g_CurrentUsbRecvNode;

usb_uart_buffer_struct_t *g_UartSendQueue;
usb_uart_buffer_struct_t *g_UartSendNode;

volatile uint8_t g_UsbSendBusy;

volatile uint8_t g_UartSendBusy;

usb_device_handle cdcDeviceHandle;
/*the data interface handle , this handle is init in the class init function*/
usb_host_class_handle cdcDataInterfaceHandle;
/*the control  interface handle , this handle is init in the class init function*/
usb_host_class_handle cdcControlIntfHandle;

cdc_instance_struct_t g_cdc;
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) usb_host_cdc_line_coding_struct_t g_LineCode;

char usbRecvUart[USB_HOST_CDC_UART_RX_MAX_LEN];

extern uint8_t g_AttachFlag;
extern usb_serial_port_handle_t g_UartHandle;
extern usb_serial_port_xfer_t g_xfer;
usb_serial_port_xfer_t g_txfer;

uint32_t g_UartActive;
/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief host cdc enter critical.
 *
 * This function is used to enter critical disable interrupt .
 *
 */
static void USB_BmEnterCritical(uint8_t *sr)
{
    *sr = DisableGlobalIRQ();
    __ASM("CPSID I");
}
/*!
 * @brief host cdc exit critical.
 *
 * This function is used to exit critical ,enable interrupt .
 *
 */
static void USB_BmExitCritical(uint8_t sr)
{
    EnableGlobalIRQ(sr);
}

/*!
 * @brief host cdc free buffer to queue.
 *
 * This function is used to get a buffer from memory queue .
 *
 * @param queue    buffer queue pointer.
 */
usb_uart_buffer_struct_t *getNodeFromQueue(usb_uart_buffer_struct_t **queue)
{
    usb_uart_buffer_struct_t *p;
    uint8_t usbOsaCurrentSr;

    USB_BmEnterCritical(&usbOsaCurrentSr);
    p = *queue;

    if (p)
    {
        *queue = p->next;
    }
    USB_BmExitCritical(usbOsaCurrentSr);
    return p;
}
/*!
 * @brief host cdc get buffer from queue.
 *
 * This function is used to get a buffer from memory queue .
 *
 * @param queue    buffer queue pointer.
  * @param p        the buffer pointer for free.
 */
void freeNodeToQueue(usb_uart_buffer_struct_t **queue, usb_uart_buffer_struct_t *p)
{
    uint8_t usbOsaCurrentSr;

    USB_BmEnterCritical(&usbOsaCurrentSr);
    if (p)
    {
        p->next = *queue;
        *queue = p;
        p->dataLength = 0;
    }
    USB_BmExitCritical(usbOsaCurrentSr);
}
/*!
 * @brief host cdc insert buffer to queue.
 *
 * This function is used to insert to usb send queue or uart send queue .
 *
 * @param queue    buffer queue pointer.
  * @param p        the buffer pointer for insert.
 */
void insertNodeToQueue(usb_uart_buffer_struct_t **queue, usb_uart_buffer_struct_t *p)
{
    usb_uart_buffer_struct_t *q;
    uint8_t usbOsaCurrentSr;

    USB_BmEnterCritical(&usbOsaCurrentSr);

    q = *queue;
    if (q)
    {
        while (q->next)
        {
            q = q->next;
        }
        q->next = p;
    }
    else
    {
        *queue = p;
    }
    p->next = NULL;
    USB_BmExitCritical(usbOsaCurrentSr);
}
/*!
 * @brief host cdc get buffer's corresponding state structure.
 *
 * This function is used to get the data buffer's state structure .
 * the buffer and state structure relation is init in init function.
  * @param p        the buffer pointer for data transfer.
 */
usb_uart_buffer_struct_t *getBufferNode(uint8_t *p)
{
    uint8_t(*temp)[(USB_DATA_ALIGN_SIZE_MULTIPLE(USB_HOST_SEND_RECV_PER_TIME))];
    temp = (uint8_t(*)[(USB_DATA_ALIGN_SIZE_MULTIPLE(USB_HOST_SEND_RECV_PER_TIME))])p;
    if (temp >= &s_DataBuffer[USB_HOST_CDC_BUFFER_NUM])
    {
        uint8_t number = (temp - &s_DataBuffer[USB_HOST_CDC_BUFFER_NUM]);
        if (temp < &s_DataBuffer[2 * USB_HOST_CDC_BUFFER_NUM])
        {
            return &g_EmptySendBuffer[number];
        }
        else
        {
            return NULL;
        }
    }
    else
    {
        if (temp >= &s_DataBuffer[0])
        {
            uint8_t number = (temp - &s_DataBuffer[0]);
            return &g_EmptyBuffer[number];
        }
        else
        {
            return NULL;
        }
    }
}

/*!
 * @brief host cdc data transfer callback.
 *
 * This function is used as callback function for bulk in transfer .
 *
 * @param param    the host cdc instance pointer.
 * @param data     data buffer pointer.
 * @param dataLength data length.
 * @status         transfer result status.
 */
void USB_HostCdcDataInCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    cdc_instance_struct_t *cdcInstance = (cdc_instance_struct_t *)param;

    usb_uart_buffer_struct_t *p;
    p = getBufferNode(data);

    if ((p) && (dataLength))
    {
        p->dataLength = dataLength;
        insertNodeToQueue(&g_UartSendQueue, p);

        if (cdcInstance->bulkInMaxPacketSize == dataLength)
        {
            /*host will send zero length packet after recvive one maxpacketsize */
            USB_HostCdcDataRecv(g_cdc.classHandle, NULL, 0, USB_HostCdcDataInCallback, &g_cdc);
        }
    }
}

/*!
* @brief host cdc data transfer callback.
*
* This function is used as callback function for bulk out transfer .
*
* @param param    the host cdc instance pointer.
* @param data     data buffer pointer.
* @param dataLength data length.
* @status         transfer result status.
*/
void USB_HostCdcDataOutCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    freeNodeToQueue(&g_EmptyQueue, g_UsbSendNode);

    g_CurrentUsbRecvNode = getNodeFromQueue(&g_EmptySendQueue);
    if (g_CurrentUsbRecvNode)
    {
        g_CurrentUsbRecvNode->next = NULL;
        g_CurrentUsbRecvNode->dataLength = USB_HOST_SEND_RECV_PER_TIME;
        USB_HostCdcDataRecv(g_cdc.classHandle, (uint8_t *)&g_CurrentUsbRecvNode->buffer[0],
                            g_CurrentUsbRecvNode->dataLength, USB_HostCdcDataInCallback, &g_cdc);
    }

    g_UsbSendNode = getNodeFromQueue(&g_UsbSendQueue);
    if (g_UsbSendNode)
    {
        USB_HostCdcDataSend(g_cdc.classHandle, (uint8_t *)&g_UsbSendNode->buffer[0], g_UsbSendNode->dataLength,
                            USB_HostCdcDataOutCallback, &g_cdc);
    }
    else
    {
        g_UsbSendBusy = 0;
    }
}

/*!
 * @brief uart callback function.
 *
 *This callback will be called if the uart has get specific num(USB_HOST_CDC_UART_RX_MAX_LEN) char.
 *
 * @param instance           instancehandle.
 * @param uartState           callback event code, please reference to enumeration host_event_t.
 *
 */
void UART_UserCallback(void *handle, status_t status, void *param)
{
    if ((usb_serial_port_status_t)status == kStatus_USB_SERIAL_PORT_RxIdle)
    {
        if (0 == g_AttachFlag)
        {
            /* prime the receive buffer for uart callback which is triggered the next time */
            USB_SerialPortRecv(&g_UartHandle, &g_xfer, NULL);
            return;
        }
        g_UartActive = 0;
        if (g_CurrentUartRecvNode)
        {
            g_CurrentUartRecvNode->buffer[g_CurrentUartRecvNode->dataLength++] = usbRecvUart[0];

            if (USB_HOST_SEND_RECV_PER_TIME <= g_CurrentUartRecvNode->dataLength)
            {
                insertNodeToQueue(&g_UsbSendQueue, g_CurrentUartRecvNode);
                g_CurrentUartRecvNode = getNodeFromQueue(&g_EmptyQueue);
                if (!g_CurrentUartRecvNode)
                {
                    /*buffer is run out and example could not work well */
                    /* usb_echo("Invalid buffer\r\n");*/
                }
            }
        }
        else
        {
            /*if code run to here, it means buffer has been run out once, some data has been lost*/
            g_CurrentUartRecvNode = getNodeFromQueue(&g_EmptyQueue);
        }
        USB_SerialPortRecv(&g_UartHandle, &g_xfer, NULL);
    }
    else if ((usb_serial_port_status_t)status == kStatus_USB_SERIAL_PORT_TxIdle)
    {
        freeNodeToQueue(&g_EmptySendQueue, g_UartSendNode);
        g_UartSendNode = getNodeFromQueue(&g_UartSendQueue);
        if (g_UartSendNode)
        {
            g_txfer.buffer = g_UartSendNode->buffer;
            g_txfer.size = g_UartSendNode->dataLength;
            USB_SerialPortSend(&g_UartHandle, &g_txfer);
        }
        else
        {
            g_UartSendBusy = 0;
        }
    }
    else
    {
    }
    return;
}
/* IRQ handler for uart */
/*FUNCTION*----------------------------------------------------------------
 *
 * Function Name  : UART_RX_TX_IRQHandler
 * Returned Value : none
 * Comments       :
 *     Implementation of UART handler.
 *
 *END*--------------------------------------------------------------------*/
void BOARD_UART_IRQ_HANDLER(void)
{
    USB_SerialPortIRQHandler(&g_UartHandle);
/* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate overlapping
  exception return operation might vector to incorrect interrupt */
#if defined __CORTEX_M && (__CORTEX_M == 4U)
    __DSB();
#endif
}

/*!
 * @brief USB_HostCdcInitBuffer function.
 *
 * Both send buffer and receive buffer are queue buffer, the data from the uart will be stored in send queue
 * the data from the usb device cdc will be stored in uart send queue . all the data will be stored by order, so as to
 * the data is output to the uart by its original sequence.
 *
 */
void USB_HostCdcInitBuffer(void)
{
    uint8_t usbOsaCurrentSr;
    uint8_t index;

    USB_BmEnterCritical(&usbOsaCurrentSr);
    for (index = 0; index < USB_HOST_CDC_BUFFER_NUM; ++index)
    {
        g_EmptyBuffer[index].buffer = &s_DataBuffer[index][0];
    }
    for (index = 0; index < USB_HOST_CDC_BUFFER_NUM; ++index)
    {
        g_EmptySendBuffer[index].buffer = &s_DataBuffer[USB_HOST_CDC_BUFFER_NUM + index][0];
    }

    g_EmptyQueue = &g_EmptyBuffer[0];
    usb_uart_buffer_struct_t *p;
    p = g_EmptyQueue;
    for (int m = 1; m < (sizeof(g_EmptyBuffer) / sizeof(usb_uart_buffer_struct_t)); m++)
    {
        p->next = &g_EmptyBuffer[m];
        p->dataLength = 0;
        p = p->next;
    }
    p->next = NULL;
    g_CurrentUartRecvNode = g_EmptyQueue;
    g_EmptyQueue = g_EmptyQueue->next;
    USB_BmExitCritical(usbOsaCurrentSr);

    USB_BmEnterCritical(&usbOsaCurrentSr);
    g_EmptySendQueue = &g_EmptySendBuffer[0];
    p = g_EmptySendQueue;
    for (int m = 1; m < (sizeof(g_EmptySendBuffer) / sizeof(usb_uart_buffer_struct_t)); m++)
    {
        p->next = &g_EmptySendBuffer[m];
        p->dataLength = 0;
        p = p->next;
    }
    p->next = NULL;

    USB_BmExitCritical(usbOsaCurrentSr);

    g_UsbSendQueue = NULL;
    g_UartSendQueue = NULL;
    g_UsbSendBusy = 0;
    g_UartSendBusy = 0;
    g_UartActive = 0;
}

/*!
 * @brief host cdc interrupt transfer callback.
 *
 * This function is used as callback function for interrupt transfer . Interrupt transfer is used to implement
 * asynchronous notification of UART status as pstn sepc. This callback suppose the device will return SerialState
 * notification. If there is need to suppose other notification ,please refer pstn spec 6.5 and cdc spec6.3.
 * @param param    the host cdc instance pointer.
 * @param data     data buffer pointer.
 * @param dataLength data length.
 * @status         transfer result status.
 */
void USB_HostCdcInterruptCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    usb_host_cdc_acm_state_struct_t *state = (usb_host_cdc_acm_state_struct_t *)data;

    if (status != kStatus_USB_Success)
    {
        if (status == kStatus_USB_TransferCancel)
        {
            usb_echo("cdc transfer cancel\r\n");
        }
        else
        {
            usb_echo("cdc control transfer error\r\n");
        }
    }
    else
    { /*more information about SerialState ,please pstn spec 6.5.4 */
        usb_echo("get serial state value = %d\r\n", state->bmstate);
    }
}
/*!
 * @brief host cdc control transfer callback.
 *
 * This function is used as callback function for control transfer .
 *
 * @param param    the host cdc instance pointer.
 * @param data     data buffer pointer.
 * @param dataLength data length.
 * @status         transfer result status.
 */
void USB_HostCdcControlCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    cdc_instance_struct_t *cdcInstance = (cdc_instance_struct_t *)param;

    if (status != kStatus_USB_Success)
    {
        usb_echo("data transfer error = %d , status \r\n");
        return;
    }

    if (cdcInstance->runWaitState == kRunWaitSetControlInterface)
    {
        cdcInstance->runState = kRunSetControlInterfaceDone;
    }
    else if (cdcInstance->runWaitState == kRunWaitSetDataInterface)
    {
        cdcInstance->runState = kRunSetDataInterfaceDone;
    }
    else if (cdcInstance->runWaitState == kRunWaitGetLineCode)
    {
        cdcInstance->runState = kRunGetLineCodeDone;
    }
#if USB_HOST_UART_SUPPORT_HW_FLOW
    else if (cdcInstance->runWaitState == kRunWaitSetCtrlState)
    {
        cdcInstance->runState = kRunSetCtrlStateDone;
    }
#endif
    else if (cdcInstance->runWaitState == kRunWaitGetState)
    {
        cdcInstance->runState = kRunGetStateDone;
    }
    else
    {
    }
}

/*!
 * @brief host cdc task function.
 *
 * This function implements the host cdc action, it is used to create task.
 *
 * @param param   the host cdc instance pointer.
 */
void USB_HosCdcTask(void *param)
{
    uint8_t usbOsaCurrentSr;
    usb_status_t status = kStatus_USB_Success;
    cdc_instance_struct_t *cdcInstance = (cdc_instance_struct_t *)param;
    /* device state changes */
    if (cdcInstance->deviceState != cdcInstance->previousState)
    {
        cdcInstance->previousState = cdcInstance->deviceState;
        switch (cdcInstance->deviceState)
        {
            case kStatus_DEV_Idle:
                break;
            case kStatus_DEV_Attached:
                cdcInstance->runState = kRunSetControlInterface;
                status = USB_HostCdcInit(cdcInstance->deviceHandle, &cdcInstance->classHandle);
                usb_echo("cdc device attached\r\n");
                break;
            case kStatus_DEV_Detached:
                cdcInstance->deviceState = kStatus_DEV_Idle;
                cdcInstance->runState = kRunIdle;
                USB_HostCdcDeinit(cdcInstance->deviceHandle, cdcInstance->classHandle);
                cdcInstance->dataInterfaceHandle = NULL;
                cdcInstance->classHandle = NULL;
                cdcInstance->controlInterfaceHandle = NULL;
                cdcInstance->deviceHandle = NULL;
                usb_echo("cdc device detached\r\n");
                break;
            default:
                break;
        }
    }

    /* run state */
    switch (cdcInstance->runState)
    {
        case kRunIdle:
            if (g_AttachFlag)
            {
                if (!g_UsbSendBusy)
                {
                    g_UsbSendNode = getNodeFromQueue(&g_UsbSendQueue);
                    if (g_UsbSendNode)
                    {
                        g_UsbSendBusy = 1;
                        USB_HostCdcDataSend(g_cdc.classHandle, (uint8_t *)&g_UsbSendNode->buffer[0],
                                            g_UsbSendNode->dataLength, USB_HostCdcDataOutCallback, &g_cdc);
                    }
                }
                if (!g_UartSendBusy)
                {
                    g_UartSendNode = getNodeFromQueue(&g_UartSendQueue);

                    if (g_UartSendNode)
                    {
                        g_txfer.buffer = g_UartSendNode->buffer;
                        g_txfer.size = g_UartSendNode->dataLength;
                        g_UartSendBusy = 1;
                        USB_SerialPortSend(&g_UartHandle, &g_txfer);
                    }
                }
                g_UartActive++;

                if (g_UartActive > USB_HOST_UART_RECV_TIMEOUT_THRSHOLD)
                {
                    g_UartActive = 0;

                    USB_BmEnterCritical(&usbOsaCurrentSr);
                    if ((g_CurrentUartRecvNode) && (g_CurrentUartRecvNode->dataLength))
                    {
                        insertNodeToQueue(&g_UsbSendQueue, g_CurrentUartRecvNode);
                        g_CurrentUartRecvNode = getNodeFromQueue(&g_EmptyQueue);
                    }
                    USB_BmExitCritical(usbOsaCurrentSr);
                }
            }
            break;
        case kRunSetControlInterface:
            cdcInstance->runWaitState = kRunWaitSetControlInterface;
            cdcInstance->runState = kRunIdle;
            if (USB_HostCdcSetControlInterface(cdcInstance->classHandle, cdcInstance->controlInterfaceHandle, 0,
                                               USB_HostCdcControlCallback, &g_cdc) != kStatus_USB_Success)
            {
                usb_echo("set control interface error\r\n");
            }
            break;
        case kRunSetControlInterfaceDone:
            cdcInstance->runWaitState = kRunWaitSetDataInterface;
            cdcInstance->runState = kRunIdle;
            if (USB_HostCdcSetDataInterface(cdcInstance->classHandle, cdcInstance->dataInterfaceHandle, 0,
                                            USB_HostCdcControlCallback, &g_cdc) != kStatus_USB_Success)
            {
                usb_echo("set data interface error\r\n");
            }
            cdcInstance->bulkInMaxPacketSize =
                USB_HostCdcGetPacketsize(cdcInstance->classHandle, USB_ENDPOINT_BULK, USB_IN);
            break;
        case kRunSetDataInterfaceDone:
            g_AttachFlag = 1;
            cdcInstance->runState = kRunGetStateDone;
            /*get the class-specific descriptor */
            /*usb_host_cdc_head_function_desc_struct_t *headDesc = NULL;
            usb_host_cdc_call_manage_desc_struct_t *callManage = NULL;
            usb_host_cdc_abstract_control_desc_struct_t *abstractControl = NULL;
            usb_host_cdc_union_interface_desc_struct_t *unionInterface =NULL;
            USB_HostCdcGetAcmDescriptor(cdcInstance->classHandle, &headDesc, &callManage, &abstractControl,
                                        &unionInterface);*/
            if (USB_HostCdcInterruptRecv(cdcInstance->classHandle, (uint8_t *)&cdcInstance->state,
                                         sizeof(cdcInstance->state), USB_HostCdcInterruptCallback,
                                         &g_cdc) != kStatus_USB_Success)
            {
                usb_echo("Error in USB_HostCdcInterruptRecv: %x\r\n", status);
            }
            break;
        case kRunGetStateDone:
            cdcInstance->runWaitState = kRunWaitSetCtrlState;
            cdcInstance->runState = kRunIdle;
#if USB_HOST_UART_SUPPORT_HW_FLOW
            USB_HostCdcSetAcmCtrlState(cdcInstance->classHandle, 1, 1, USB_HostCdcControlCallback, (void *)cdcInstance);
#else
            cdcInstance->runState = kRunSetCtrlStateDone;
#endif
            break;
        case kRunSetCtrlStateDone:
            cdcInstance->runWaitState = kRunWaitGetLineCode;
            cdcInstance->runState = kRunIdle;
            USB_HostCdcGetAcmLineCoding(cdcInstance->classHandle, &g_LineCode, USB_HostCdcControlCallback,
                                        (void *)cdcInstance);
            break;
        case kRunGetLineCodeDone:
            cdcInstance->runState = kRunIdle;
            break;
        default:
            break;
    }
}

usb_status_t USB_HostCdcEvent(usb_device_handle deviceHandle,
                              usb_host_configuration_handle configurationHandle,
                              uint32_t event_code)
{
    usb_status_t status;
    uint8_t id;
    usb_host_configuration_t *configuration;
    uint8_t interface_index;
    usb_host_interface_t *hostInterface;
    uint32_t info_value;

    status = kStatus_USB_Success;

    switch (event_code)
    {
        case kUSB_HostEventAttach:
            /* judge whether is configurationHandle supported */
            configuration = (usb_host_configuration_t *)configurationHandle;
            cdcDataInterfaceHandle = NULL;
            cdcDeviceHandle = NULL;
            cdcControlIntfHandle = NULL;

            USB_HostCdcInitBuffer();

            for (interface_index = 0; interface_index < configuration->interfaceCount; ++interface_index)
            {
                hostInterface = &configuration->interfaceList[interface_index];
                id = hostInterface->interfaceDesc->bInterfaceClass;

                if (id != USB_HOST_CDC_COMMUNICATIONS_CLASS_CODE)
                {
                    continue;
                }
                id = hostInterface->interfaceDesc->bInterfaceSubClass;
                if (id != USB_HOST_CDC_SUBCLASS_ACM_CODE)
                {
                    continue;
                }
                /*judge the subclass code */
                /*            id = hostInterface->interfaceDesc->bInterfaceProtocol;
                            if (id != USB_HOST_CDC_PROTOCOL_CODE)
                            {
                                continue;
                             }*/
                else
                {
                    cdcControlIntfHandle = hostInterface;
                    cdcDeviceHandle = deviceHandle;
                }
            }
            for (interface_index = 0; interface_index < configuration->interfaceCount; ++interface_index)
            {
                hostInterface = &configuration->interfaceList[interface_index];
                id = hostInterface->interfaceDesc->bInterfaceClass;

                if (id != USB_HOST_CDC_DATA_CLASS_CODE)
                {
                    continue;
                }
                id = hostInterface->interfaceDesc->bInterfaceSubClass;
                if (id != USB_HOST_CDC_DATA_SUBCLASS_CODE)
                {
                    continue;
                }
                id = hostInterface->interfaceDesc->bInterfaceProtocol;
                if (id != USB_HOST_CDC_DATA_PROTOCOL_CODE)
                {
                    continue;
                }
                else
                {
                    cdcDataInterfaceHandle = hostInterface;
                }
            }
            if ((NULL != cdcDataInterfaceHandle) && (NULL != cdcControlIntfHandle) && (NULL != cdcDeviceHandle))
            {
                status = kStatus_USB_Success;
            }
            else
            {
                status = kStatus_USB_NotSupported;
            }
            break;

        case kUSB_HostEventNotSupported:
            break;

        case kUSB_HostEventEnumerationDone:
            if (g_cdc.deviceState == kStatus_DEV_Idle)
            {
                if ((cdcDeviceHandle != NULL) && (cdcDataInterfaceHandle != NULL) && (cdcControlIntfHandle != NULL))
                {
                    g_cdc.deviceState = kStatus_DEV_Attached;
                    g_cdc.deviceHandle = cdcDeviceHandle;
                    g_cdc.dataInterfaceHandle = cdcDataInterfaceHandle;
                    g_cdc.controlInterfaceHandle = cdcControlIntfHandle;

                    USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDevicePID, &info_value);
                    usb_echo("device cdc attached:\r\npid=0x%x", info_value);
                    USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDeviceVID, &info_value);
                    usb_echo("vid=0x%x ", info_value);
                    USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDeviceAddress, &info_value);
                    usb_echo("address=%d\r\n", info_value);
                }
            }
            else
            {
                usb_echo("not idle cdc instance\r\n");
            }
            break;

        case kUSB_HostEventDetach:
            if (g_cdc.deviceState != kStatus_DEV_Idle)
            {
                g_cdc.deviceState = kStatus_DEV_Detached;
                g_AttachFlag = 0;
                USB_HostCdcInitBuffer();
            }
            break;

        default:
            break;
    }
    return status;
}
