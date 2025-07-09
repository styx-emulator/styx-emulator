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
#include "ieee11073_timer.h"
#include "ieee11073_types.h"
#include <stdio.h>
#include <math.h>
#include <string.h>
#include "fsl_debug_console.h"
#include "ieee11073_timer.h"
#include "ieee11073_agent.h"
#include "usb_device.h"
#include "usb_device_class.h"
#include "usb_device_descriptor.h"
#include "usb_shim_agent.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief Agent send data definition */
#define AGENT_SendData USB_ShimAgentSendData
/*! @brief the number of agent devices */
#define MAX_AGENT_NUM (1U)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*! @brief local function prototypes */
#if IEEE_MAX_TIMER_OBJECTS
static void AGENT_SendAssociationRequestTimeout(void *arg);
static void AGENT_SendConfigTimeout(void *arg);
#endif
static agent_struct_t *AGENT_GetDeviceByHandle(uint32_t handle);
static void AGENT_RecvAssociationResponse(uint32_t handle, aare_apdu_t *associaionResponse);
static void AGENT_RecvPresentationProtocolDataUnit(uint32_t handle, prst_apdu_t *pPrst);
#if AGENT_SUPPORT_FULL_FEATURE
static void AGENT_SendAssociationReleaseResponse(uint32_t handle, release_request_reason_t releaseReason);
static void AGENT_SendRoer(uint32_t handle, error_result_t *errorResult);
#endif
static void AGENT_RecvComplete(uint32_t handle, uint8_t *dataBuffer, uint32_t size);

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*! @brief the agent device instance */
agent_struct_t g_agentDevice[MAX_AGENT_NUM];

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief send association request.
 *
 * This function gets the association request data from application and sends
 * it to the host using PHDC transport channel, this request is to establish a
 * connection between the device and the host.
 *
 * @param handle        the agent handle.
 * @param assoc_ptr     the association request data.
 * @param size          the association request data size.
 */
void AGENT_SendAssociationRequest(uint32_t handle, uint8_t *associationData, uint32_t size)
{
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        if (AGENT_STATE_CON_UNASSOCIATED == pAgent->agentState)
        {
#if IEEE_MAX_TIMER_OBJECTS
            /* preparing association timer object */
            ieee11073_timer_struct_t *pAgentTimer = &pAgent->agentTimer[0U];
            pAgentTimer->timerObject.timerCount = (int32_t)(RC_ASSOC * TO_ASSOC); /* 30S */
            pAgentTimer->timerObject.timerCallback = AGENT_SendAssociationRequestTimeout;
            pAgentTimer->timerObject.timerArgument = (void *)pAgent;
            pAgentTimer->timerId = IEEE_AddTimerQueue(&pAgentTimer->timerObject);
#endif
            /* the first time for sending the association request to host */
            if (AGENT_SendData(handle, AGENT_SEND_DATA_QOS, (uint8_t *)associationData, size))
            {
#if _USB_DEBUG
                usb_echo("Send association request error\n\r");
#endif
            }
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot get agent device \n\r");
#endif
    }
}

#if IEEE_MAX_TIMER_OBJECTS
/*!
 * @brief association request timeout.
 *
 * This is the callback function which is called every time association request
 * timer expired.
 *
 * @param timerId       the identify of timer associated with the agent device.
 * @param arg           the timer callback param.
 */
static void AGENT_SendAssociationRequestTimeout(void *arg)
{
    agent_struct_t *pAgent = (agent_struct_t *)arg;
    /* pAgent->agentState = AGENT_STATE_CON_UNASSOCIATED */
    AGENT_SetAgentState(pAgent->agentHandle, AGENT_STATE_CON_UNASSOCIATED);
#if AGENT_SUPPORT_FULL_FEATURE
    AGENT_SendAssociationAbortRequest(pAgent->agentHandle, (abort_reason_t)ABORT_REASON_RESPONSE_TIMEOUT);
#endif
}
#endif
/*!
 * @brief send agent configuration.
 *
 * This function gets the agent configuration from application and sends it to
 * the host using PHDC transport channel.
 *
 * @param handle        the agent handle.
 * @param config_ptr    the agent configuration data.
 * @param size          the agent configuration data size.
 */
void AGENT_SendConfig(uint32_t handle, uint8_t *config, uint32_t size)
{
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        if (AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState)
        {
#if IEEE_MAX_TIMER_OBJECTS
            /* preparing association timer object */
            ieee11073_timer_struct_t *pAgentTimer = &pAgent->agentTimer[1U];
            pAgentTimer->timerObject.timerCount = TO_CONFIG; /* 10S */
            pAgentTimer->timerObject.timerCallback = AGENT_SendConfigTimeout;
            pAgentTimer->timerObject.timerArgument = (void *)pAgent;
            pAgentTimer->timerId = IEEE_AddTimerQueue(&pAgentTimer->timerObject);
#endif
            /* the first time for sending the association request to host */
            if (AGENT_SendData(handle, AGENT_SEND_DATA_QOS, (uint8_t *)config, size))
            {
#if _USB_DEBUG
                usb_echo("Send configuration error\n\r");
#endif
            }
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot get agent device \n\r");
#endif
    }
}

#if IEEE_MAX_TIMER_OBJECTS
/*!
 * @brief send configuration timeout.
 *
 * This is the callback function which is called every time sending configuration
 * timer expired.
 *
 * @param timerId       the identify of timer associated with the agent device.
 * @param arg           the timer callback param.
 */
static void AGENT_SendConfigTimeout(void *arg)
{
    agent_struct_t *pAgent = (agent_struct_t *)arg;
    /* pAgent->agentState = AGENT_STATE_CON_UNASSOCIATED */
    AGENT_SetAgentState(pAgent->agentHandle, AGENT_STATE_CON_UNASSOCIATED);
#if AGENT_SUPPORT_FULL_FEATURE
    AGENT_SendAssociationAbortRequest(pAgent->agentHandle, (abort_reason_t)ABORT_REASON_CONFIGURATION_TIMEOUT);
#endif
}
#endif

#if AGENT_SUPPORT_FULL_FEATURE
/*!
 * @brief send association abort request.
 *
 * This function implements association abort request, it builds abort data
 * and sends it out using PHDC transport channel.
 *
 * @param handle        the agent handle.
 * @param abort_reason  the abort reason.
 */
void AGENT_SendAssociationAbortRequest(uint32_t handle, abort_reason_t abortReason)
{
    apdu_t *pApdu;
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        uint16_t size;
        size = (uint16_t)(ABRT_DATA_LENGTH + APDU_HEADER_SIZE);
        pApdu = (apdu_t *)&pAgent->agentTxBuffer[0U];
        pApdu->choice = ABRT_CHOSEN;
        pApdu->length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE);
        pApdu->u.abrt.reason = USB_SHORT_FROM_BIG_ENDIAN(abortReason);
        if (AGENT_SendData(pAgent->agentHandle, AGENT_SEND_DATA_QOS, (uint8_t *)pApdu, (uint32_t)size))
        {
#if _USB_DEBUG
            usb_echo("Send abort request error\n\r");
#endif
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot find the agent device\n\r");
#endif
    }
}
#endif

#if AGENT_SUPPORT_FULL_FEATURE
/*!
 * @brief send association release request.
 *
 * This function implements association release request, it builds release data
 * and sends it out using PHDC transport channel.
 *
 * @param handle            the agent handle.
 * @param release_reason    the release reason.
 *
 * @retval AGENT_ERROR_SUCCESS          sending request is successful.
 * @retval AGENT_ERROR_INVALID_PARAM    the agent device is not found.
 */
void AGENT_SendAssociationRleaseRequest(uint32_t handle, release_request_reason_t releaseReason)
{
    apdu_t *pApdu;
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        uint16_t size;
        size = (uint16_t)(RLRQ_DATA_LENGTH + APDU_HEADER_SIZE);
        pApdu = (apdu_t *)&pAgent->agentTxBuffer[0U];
        pApdu->choice = RLRQ_CHOSEN;
        pApdu->length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE);
        pApdu->u.rlrq.reason = USB_SHORT_FROM_BIG_ENDIAN(releaseReason);
        if (AGENT_SendData(pAgent->agentHandle, AGENT_SEND_DATA_QOS, (uint8_t *)pApdu, (uint32_t)size))
        {
#if _USB_DEBUG
            usb_echo("Send release request error\n\r");
#endif
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot find agent device\n\r");
#endif
    }
}
#endif

#if AGENT_SUPPORT_FULL_FEATURE
/*!
 * @brief send association release response.
 *
 * This function implements association release response, it builds release
 * response data and sends it out using PHDC transport channel.
 *
 * @param pAgent            the agent device instance pointer.
 * @param release_reason    the release reason.
 *
 * @retval AGENT_ERROR_SUCCESS          sending response is successful.
 * @retval AGENT_ERROR_INVALID_PARAM    sending response is fail.
 */
static void AGENT_SendAssociationReleaseResponse(uint32_t handle, release_request_reason_t releaseReason)
{
    apdu_t *pApdu;
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        uint16_t size;
        size = (uint16_t)(RLRE_DATA_LENGTH + APDU_HEADER_SIZE);
        pApdu = (apdu_t *)&pAgent->agentTxBuffer[0U];
        pApdu->choice = RLRE_CHOSEN;
        pApdu->length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE);
        pApdu->u.rlre.reason = USB_SHORT_FROM_BIG_ENDIAN(releaseReason);
        if (AGENT_SendData(handle, AGENT_SEND_DATA_QOS, (uint8_t *)pApdu, (uint32_t)size))
        {
#if _USB_DEBUG
            usb_echo("Send release response error\n\r");
#endif
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot find the agent device\n\r");
#endif
    }
}
#endif

/*!
 * @brief get agent device by handle.
 *
 * This function searches the agent device instance corresponding with the
 * specified agent handle.
 *
 * @param handle            the agent handle.
 *
 * @retval pAgent           the agent device instance.
 * @retval NULL             the agent device is not found.
 */
static agent_struct_t *AGENT_GetDeviceByHandle(uint32_t handle)
{
    agent_struct_t *pAgent = NULL;
    for (uint8_t i = 0U; i < MAX_AGENT_NUM; i++)
    {
        if (handle == g_agentDevice[i].agentHandle)
        {
            pAgent = (agent_struct_t *)(&g_agentDevice[i]);
            break;
        }
    }
    return pAgent;
}

/*!
 * @brief set agent device state.
 *
 * This function sets the state of device corresponding with specified agent.
 *
 * @param handle            the agent handle.
 * @param state             the state to set.
 *
 * @retval AGENT_ERROR_SUCCESS          the agent device is found.
 * @retval AGENT_ERROR_INVALID_PARAM    the agent device is not found.
 */
void AGENT_SetAgentState(uint32_t handle, uint8_t state)
{
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        switch (state)
        {
            case AGENT_STATE_DISCONNECTED:
#if IEEE_MAX_TIMER_OBJECTS
                /* de-queue timer */
                for (uint8_t i = 0U; i < IEEE_MAX_TIMER_OBJECTS; i++)
                {
                    ieee11073_timer_struct_t *pAgentTimer = &pAgent->agentTimer[i];
                    IEEE_RemoveTimerQueue(pAgentTimer->timerId);
                }
#endif
                pAgent->agentState = state;
#if _USB_DEBUG
                usb_echo("\n\r11073Agent: ENTER DISCONNECTED state");
#endif
                break;
            case AGENT_STATE_CON_UNASSOCIATED:
                pAgent->agentState = state;
#if _USB_DEBUG
                usb_echo("\n\r11073Agent: ENTER UNASSOCIATED state");
#endif
                break;
            case AGENT_STATE_CON_ASSOCIATING:
                pAgent->agentState = state;
#if _USB_DEBUG
                usb_echo("\n\r11073Agent: ENTER ASSOCIATING state");
#endif
                break;
            case AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG:
                pAgent->agentState = state;
#if _USB_DEBUG
                usb_echo("\n\r11073Agent: ENTER CONFIGURING SENDING CONFIG state");
#endif
                break;
            case AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL:
                pAgent->agentState = state;
#if _USB_DEBUG
                usb_echo("\n\r11073Agent: ENTER CONFIGURING WAITING APPROVAL state");
#endif
                break;
            case AGENT_STATE_CON_ASSOC_OPERATING:
                pAgent->agentState = state;
#if _USB_DEBUG
                usb_echo("\n\r11073Agent: ENTER OPERATING state");
#endif
                break;
            case AGENT_STATE_CON_DISASSOCIATING:
                pAgent->agentState = state;
#if _USB_DEBUG
                usb_echo("\n\r11073Agent: ENTER DISASSOCIATING state");
#endif
                break;
            default:
#if _USB_DEBUG
                usb_echo("\n\r11073Agent: Error invalid state");
#endif
                break;
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("\n\r11073Agent: Error invalid param");
#endif
    }
}

/*!
 * @brief initialize the agent device.
 *
 * This function initializes the agent device and starts transporting.
 *
 * @param handle            the agent handle.
 */
void AGENT_Init(uint32_t handle)
{
    uint8_t isNonActiveAgent = 0U;
    uint8_t agentIndex = 0U;
    agent_struct_t *pAgent = NULL;
    for (; agentIndex < MAX_AGENT_NUM; agentIndex++)
    {
        if (0U == g_agentDevice[agentIndex].agentHandle)
        {
            isNonActiveAgent = 1U;
            break;
        }
    }
    if (0U == isNonActiveAgent)
    {
#if _USB_DEBUG
        usb_echo("ERROR: Users need to increase the max number of agent devices!\n\r");
#endif
    }
    else
    {
        /* Initialize Global Variable Structure */
        pAgent = (agent_struct_t *)(&g_agentDevice[agentIndex]);
        memset(pAgent, 0U, sizeof(agent_struct_t));
#if IEEE_MAX_TIMER_OBJECTS
        IEEE_TimerInit();
#endif
        /* set the default state of agent device is disconnected */
        AGENT_SetAgentState(pAgent->agentHandle, AGENT_STATE_DISCONNECTED);
        pAgent->agentHandle = handle;
    }
}

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
void AGENT_Callback(uint32_t handle, uint8_t request, uint8_t *data, uint32_t size)
{
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        switch (request)
        {
            case SHIM_AGENT_EVENT_RECV_MESSAGE_PREAMBLE:
            case SHIM_AGENT_EVENT_RECV_OPAQUE_DATA:
                break;
            case SHIM_AGENT_EVENT_RECV_COMPLETE:
            {
                AGENT_RecvComplete(handle, data, size);
            }
            break;
            case SHIM_AGENT_EVENT_SENT_COMPLETE:
            {
                if (AGENT_STATE_DISCONNECTED == pAgent->agentState)
                {
                    AGENT_SetAgentState(pAgent->agentHandle, AGENT_STATE_CON_UNASSOCIATED);
                    pAgent->isSendingRorsCmipGet = 0U;
                    AGENT_MedicalCallback(handle, AGENT_EVENT_CONNECTED, NULL);
                }
                else if (AGENT_STATE_CON_UNASSOCIATED == pAgent->agentState)
                {
#if IEEE_MAX_TIMER_OBJECTS
                    ieee11073_timer_struct_t *pAgentTimer = &pAgent->agentTimer[0U];
                    IEEE_RemoveTimerQueue(pAgentTimer->timerId);
#endif
                    AGENT_SetAgentState(pAgent->agentHandle, AGENT_STATE_CON_ASSOCIATING);
                }
                else if (AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState)
                {
#if IEEE_MAX_TIMER_OBJECTS
                    ieee11073_timer_struct_t *pAgentTimer;
                    pAgentTimer = &pAgent->agentTimer[1U];
                    IEEE_RemoveTimerQueue(pAgentTimer->timerId);
#endif
                    AGENT_SetAgentState(pAgent->agentHandle, AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL);
                }
                else if (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState)
                {
                    if (1U == pAgent->isSendingRorsCmipGet)
                    {
                        pAgent->isSendingRorsCmipGet = 0U;
                        AGENT_MedicalCallback(handle, AGENT_EVENT_RORS_CMIP_GET_SENT, NULL);
                    }
                }
                else
                {
                }
            }
            break;
            default:
                break;
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot the Agent device\n\r");
#endif
    }
}

/*!
 * @brief the agent receive complete.
 *
 * This function analyses the received APDU data and calls to corresponding
 * agent function.
 *
 * @param handle       the agent handle.
 * @param dataBuffer   pointer to data
 * @param size         data size
 */
static void AGENT_RecvComplete(uint32_t handle, uint8_t *dataBuffer, uint32_t size)
{
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        if (AGENT_STATE_DISCONNECTED != pAgent->agentState)
        {
            uint16_t apduChoice;
            apdu_t *pApdu = NULL;
            pApdu = (apdu_t *)dataBuffer;
            apduChoice = USB_SHORT_FROM_BIG_ENDIAN(pApdu->choice);
            switch (apduChoice)
            {
                case AARQ_CHOSEN:
                    if ((AGENT_STATE_CON_UNASSOCIATED == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOCIATING == pAgent->agentState))
                    {
                        /* agent-agent association - send aare request to reject association reqeuest*/
                        AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
#if AGENT_SUPPORT_FULL_FEATURE
/* cannot establish a connection between two USB devices, this case will never occurs */
#endif
                    }
                    else if ((AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState) ||
                             (AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL == pAgent->agentState) ||
                             (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState) ||
                             (AGENT_STATE_CON_DISASSOCIATING == pAgent->agentState))
                    {
                        /* Should not happen - send abort request*/
                        AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
#if AGENT_SUPPORT_FULL_FEATURE
                        AGENT_SendAssociationAbortRequest(handle, (abort_reason_t)ABORT_REASON_UNDEFINED);
#endif
                    }
                    else
                    {
                    }
                    break;
                case AARE_CHOSEN:
                    if ((AGENT_STATE_CON_UNASSOCIATED == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState) ||
                        (AGENT_STATE_CON_DISASSOCIATING == pAgent->agentState))
                    {
                        /* Should not happen - send abort request */
                        AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
#if AGENT_SUPPORT_FULL_FEATURE
                        /* send abort request */
                        AGENT_SendAssociationAbortRequest(handle, (abort_reason_t)ABORT_REASON_UNDEFINED);
#endif
                    }
                    else if ((AGENT_STATE_CON_ASSOCIATING == pAgent->agentState))
                    {
                        AGENT_RecvAssociationResponse(handle, &(pApdu->u.aare));
                    }
                    else
                    {
                    }
                    break;
                case RLRQ_CHOSEN:
                    if ((AGENT_STATE_CON_UNASSOCIATED == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOCIATING == pAgent->agentState))
                    {
                        /* Should not happen - send abort request to host */
                        AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
#if AGENT_SUPPORT_FULL_FEATURE
                        /* send abort request */
                        AGENT_SendAssociationAbortRequest(handle, (abort_reason_t)ABORT_REASON_UNDEFINED);
#endif
                    }
                    else if ((AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState) ||
                             (AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL == pAgent->agentState) ||
                             (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState) ||
                             (AGENT_STATE_CON_DISASSOCIATING == pAgent->agentState))
                    {
                        AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
#if AGENT_SUPPORT_FULL_FEATURE
                        /* send rlre(normal) */
                        AGENT_SendAssociationReleaseResponse(handle,
                                                             (release_request_reason_t)RELEASE_REQUEST_REASON_NORMAL);
#endif
                    }
                    else
                    {
                    }
                    break;
                case RLRE_CHOSEN:
                    if ((AGENT_STATE_CON_UNASSOCIATED == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOCIATING == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState))
                    {
                        /* Should not happen - send abort request to host */
                        AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
#if AGENT_SUPPORT_FULL_FEATURE
                        /* send abort request */
                        AGENT_SendAssociationAbortRequest(handle, (abort_reason_t)ABORT_REASON_UNDEFINED);
#endif
                    }
                    else if (AGENT_STATE_CON_DISASSOCIATING == pAgent->agentState)
                    {
                        AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
                    }
                    else
                    {
                    }
                    break;
                case ABRT_CHOSEN:
                    if ((AGENT_STATE_CON_UNASSOCIATED == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOCIATING == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL == pAgent->agentState) ||
                        (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState) ||
                        (AGENT_STATE_CON_DISASSOCIATING == pAgent->agentState))
                    {
                        AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
                    }
                    break;
                case PRST_CHOSEN:
                    AGENT_RecvPresentationProtocolDataUnit(handle, &(pApdu->u.prst));
                    break;
                default:
                    break;
            }
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot find the Agent device\n\r");
#endif
    }
}

/*!
 * @brief receive association response handle.
 *
 * This function handles the association request response sent by the host.
 *
 * @param handle       the agent handle.
 * @associaionResponse association response data
 */
static void AGENT_RecvAssociationResponse(uint32_t handle, aare_apdu_t *associaionResponse)
{
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        if (ACCEPTED == USB_SHORT_FROM_BIG_ENDIAN(associaionResponse->result))
        {
            /* The Agent is accepted by manager, change the state to operating,
            and wait roivCmipGet event from manager to change the procedure to
            operating */
            AGENT_SetAgentState(handle, AGENT_STATE_CON_ASSOC_OPERATING);
            AGENT_MedicalCallback(handle, AGENT_EVENT_ACCEPTED_AARQ, NULL);
        }
        else if (ACCEPTED_UNKNOWN_CONFIG == USB_SHORT_FROM_BIG_ENDIAN(associaionResponse->result))
        {
            /* The Agent is accepted by manager with unknown configuration, change agent state
            to configuring sending config, callback to application to send the device's configuration
            to the manager then change the procedure to configuring */
            AGENT_SetAgentState(handle, AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG);
            AGENT_MedicalCallback(handle, AGENT_EVENT_ACCEPTED_UNKNOWN_CONFIG_AARQ, NULL);
        }
        else
        {
            /* The Agent is rejected by manager, change to state to unassociated, change the procedure
            to unassociated, callback to application with Reject event */
            AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
            AGENT_MedicalCallback(handle, AGENT_EVENT_REJECTED_AARQ, NULL);
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot find the Agent device\n\r");
#endif
    }
}

/*!
 * @brief receive PRST handle.
 *
 * This function handles the request/data sent by the host when the device is in
 * operating state.
 *
 * @param handle       the agent handle.
 * @param pPrst        presentation data unit pointer.
 */
static void AGENT_RecvPresentationProtocolDataUnit(uint32_t handle, prst_apdu_t *pPrst)
{
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        data_apdu_t *dataApdu = (data_apdu_t *)&(pPrst->value[0U]);
        /* Store the invoke ID */
        pAgent->invokeId = dataApdu->invokeId;
        if ((AGENT_STATE_CON_UNASSOCIATED == pAgent->agentState) || (AGENT_STATE_CON_ASSOCIATING == pAgent->agentState))
        {
#if AGENT_SUPPORT_FULL_FEATURE
            /* should not happen, send abort request to the manager */
            AGENT_SendAssociationAbortRequest(handle, ABORT_REASON_UNDEFINED);
#endif
        }
        switch (USB_SHORT_FROM_BIG_ENDIAN(dataApdu->choice.choice))
        {
            case ROIV_CMIP_GET_CHOSEN:
                if ((AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState) ||
                    (AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL == pAgent->agentState) ||
                    (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState))
                {
                    /* The remote operation response | Get is sending */
                    pAgent->isSendingRorsCmipGet = 1U;
                    /* callback to application to send rors-cmip-ge (MDS attribute) */
                    AGENT_MedicalCallback(handle, AGENT_EVENT_RECV_ROIV_CMIP_GET, (uint8_t *)&pAgent->invokeId);
                }
                else if (AGENT_STATE_CON_DISASSOCIATING == pAgent->agentState)
                {
                    /* do nothing */
                }
                else
                {
                }
                break;
            case ROIV_CMIP_EVENT_REPORT_CHOSEN:
            case ROIV_CMIP_CONFIRMED_EVENT_REPORT_CHOSEN:
            case ROIV_CMIP_SET_CHOSEN:
            case ROIV_CMIP_CONFIRMED_SET_CHOSEN:
            case ROIV_CMIP_ACTION_CHOSEN:
            case ROIV_CMIP_CONFIRMED_ACTION_CHOSEN:
                if ((AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState) ||
                    (AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL == pAgent->agentState))
                {
#if AGENT_SUPPORT_FULL_FEATURE
                    /* not allowed, send roer with no-such-object-instance */
                    uint8_t tempBuffer[4U];
                    error_result_t *errorResult = (error_result_t *)&tempBuffer[0];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_OBJECT_INSTANCE);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    AGENT_SendRoer(handle, errorResult);
#endif
                }
                else if (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState)
                {
                    /* normal processing of message */
                }
                else if (AGENT_STATE_CON_DISASSOCIATING == pAgent->agentState)
                {
                    /* do nothing */
                }
                else
                {
                }
                break;
            case RORS_CMIP_CONFIRMED_EVENT_REPORT_CHOSEN:
                if ((AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState))
                {
#if AGENT_SUPPORT_FULL_FEATURE
                    /* should not happen, send abort request to the manager */
                    AGENT_SendAssociationAbortRequest(handle, ABORT_REASON_UNDEFINED);
#endif
                    AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
                }
                else if (AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL == pAgent->agentState)
                {
                    /* configuration accepted */
                    config_report_rsp_t *configReport =
                        (config_report_rsp_t *)(&dataApdu->choice.u.rorsCmipConfirmedEventReport.eventReplyInfo
                                                     .value[0]);
                    configReport->configReportId = USB_SHORT_FROM_BIG_ENDIAN(configReport->configReportId);
                    if ((EXTENDED_CONFIG_START == configReport->configReportId) &&
                        (ACCEPTED_CONFIG == configReport->configResult))
                    {
                        /* The device's configuration is accepted by manager, change the state to operating, callback to
                        application to start sending data */
                        AGENT_SetAgentState(handle, AGENT_STATE_CON_ASSOC_OPERATING);
                        AGENT_MedicalCallback(handle, AGENT_EVENT_ACCEPTED_CONFIG, NULL);
                    }
                    else
                    {
                        /* The device's configuration is not accepted by manager, change the state to sending
                        configuration,
                        callback to application to resent the config */
                        AGENT_SetAgentState(pAgent->agentHandle, AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG);
                        AGENT_MedicalCallback(handle, AGENT_EVENT_UNSUPPORTED_CONFIG, NULL);
                    }
                }
                else if (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState)
                {
                    /* the measurement data is sent complete, callback to application to send measurement data */
                    AGENT_MedicalCallback(handle, AGENT_EVENT_MEASUREMENT_SENT, NULL);
                }
                else if (AGENT_STATE_CON_DISASSOCIATING == pAgent->agentState)
                {
#if AGENT_SUPPORT_FULL_FEATURE
                    /* send abort */
                    AGENT_SendAssociationAbortRequest(handle, ABORT_REASON_UNDEFINED);
#endif
                }
                else
                {
                }
                break;
            case RORS_CMIP_GET_CHOSEN:
            case RORS_CMIP_CONFIRMED_SET_CHOSEN:
            case RORS_CMIP_CONFIRMED_ACTION_CHOSEN:
            case ROER_CHOSEN:
            case RORJ_CHOSEN:
                if ((AGENT_STATE_CON_ASSOC_CFG_SENDING_CONFIG == pAgent->agentState) ||
                    (AGENT_STATE_CON_ASSOC_CFG_WAITING_APPROVAL == pAgent->agentState))
                {
#if AGENT_SUPPORT_FULL_FEATURE
                    /* should not happen, send abort request to the manager */
                    AGENT_SendAssociationAbortRequest(handle, ABORT_REASON_UNDEFINED);
#endif
                    AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
                }
                else if (AGENT_STATE_CON_ASSOC_OPERATING == pAgent->agentState)
                {
                    /* normal processing of message, do nothing */
                }
                else if (AGENT_STATE_CON_DISASSOCIATING == pAgent->agentState)
                {
#if AGENT_SUPPORT_FULL_FEATURE
                    /* send abort */
                    AGENT_SendAssociationAbortRequest(handle, ABORT_REASON_UNDEFINED);
#endif
                    AGENT_SetAgentState(handle, AGENT_STATE_CON_UNASSOCIATED);
                }
                else
                {
                }
                break;
            default:
                break;
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot find the Agent device\n\r");
#endif
    }
}

#if AGENT_SUPPORT_FULL_FEATURE
/*!
 * @brief send error.
 * This function is called to send error command to the device.
 *
 * @param param             the phdc manager instance pointer.
 * @param errorResult       error result.
 */
static void AGENT_SendRoer(uint32_t handle, error_result_t *errorResult)
{
    agent_struct_t *pAgent = NULL;
    pAgent = AGENT_GetDeviceByHandle(handle);
    if (NULL != pAgent)
    {
        uint16_t size;
        apdu_t *pApdu;
        data_apdu_t *pPrst;

        /* Calculate the size of Roer data */
        size = (uint16_t)(APDU_HEADER_SIZE + PRST_HEADER_LENGTH + sizeof(errorResult->errorValue) +
                          sizeof(errorResult->parameter.length) +
                          USB_SHORT_FROM_BIG_ENDIAN(errorResult->parameter.length));

        pApdu = (apdu_t *)&pAgent->agentTxBuffer[0];
        pApdu->choice = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(PRST_CHOSEN);
        pApdu->length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE);
        pApdu->u.prst.length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE - sizeof(uint16_t));
        pPrst = (data_apdu_t *)&pApdu->u.prst.value[0U];
        pPrst->invokeId = pAgent->invokeId;
        pPrst->choice.choice = USB_SHORT_FROM_BIG_ENDIAN(ROER_CHOSEN);
        pPrst->choice.length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE - PRST_HEADER_LENGTH);
        pPrst->choice.u.roer.errorValue = errorResult->errorValue;
        pPrst->choice.u.roer.parameter.length = errorResult->parameter.length;
        if (USB_SHORT_FROM_BIG_ENDIAN(errorResult->parameter.length) > 0U)
        {
            memcpy(&pPrst->choice.u.roer.parameter.value[0U], &errorResult->parameter.value[0U],
                   USB_SHORT_FROM_BIG_ENDIAN(errorResult->parameter.length));
        }
        if (AGENT_SendData(handle, AGENT_SEND_DATA_QOS, (uint8_t *)pApdu, (uint32_t)size))
        {
#if _USB_DEBUG
            usb_echo("Send release response error\n\r");
#endif
        }
    }
    else
    {
#if _USB_DEBUG
        usb_echo("Cannot find the agent device\n\r");
#endif
    }
}
#endif
/* EOF */
