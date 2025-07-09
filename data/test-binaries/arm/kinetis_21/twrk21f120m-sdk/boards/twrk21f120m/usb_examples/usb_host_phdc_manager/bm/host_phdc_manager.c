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

#include "usb_host_config.h"
#include "usb_host.h"
#include "usb.h"
#include "ieee11073_types.h"
#include "ieee11073_nomenclature.h"
#include "host_phdc_manager.h"

#include "usb_host_phdc.h"
#include "fsl_debug_console.h"
#include <stdio.h>
#include <math.h>
#include <string.h>

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define USB_KHCI_TASK_STACKSIZE 3500U
/*! @brief the max number of supported system ID */
#define MAX_NUMBER_SUPPORTED_DEVICE 1U

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*! @brief the local function prototype */
static void PHDC_ManagerSetState(void *param, uint8_t state);
static void PHDC_ManagerRecvAssociationRequest(void *param, aarq_apdu_t *associationRequest);
static void PHDC_ManagerSendAssociationResponse(void *param, aare_apdu_t *associationResponse);
static void PHDC_ManagerSendAssociationAbortRequest(void *param, abort_reason_t abortReason);
static void PHDC_ManagerSendAssociationReleaseResponse(void *param, release_response_reason_t releaseReason);
static void PHDC_ManagerRecvPresentationProtocolDataUnit(void *param, prst_apdu_t *pPrst);
static void PHDC_ManagerRecvRoivCmipConfirmedEventReport(void *param, event_report_argument_simple_t *eventReport);
static void PHDC_ManagerRecvMdcNotiConfig(void *param, event_report_argument_simple_t *eventReport);
static void PHDC_ManagerRecvMdcNotiScanReportFixed(void *param, event_report_argument_simple_t *eventReport);
static void PHDC_ManagerRecvMdcNotiScanReportFixedMetricNU(config_object_t *configObject,
                                                           observation_scan_fixed_t *obsScanFixed);
static void PHDC_ManagerSendRorsCmipConfirmedEventReport(void *param, event_report_result_simple_t *eventResponse);
static void PHDC_ManagerPrintObjectInformation(type_t *objectType);
static void PHDC_ManagerSendRoivCmipGet(void *param, get_argument_simple_t *getArg, invoke_id_type_t invokeId);
static void PHDC_ManagerRecvRorsCmipGet(void *param, get_result_simple_t *getResult);
static void PHDC_ManagerSendRoer(void *param, error_result_t *errorResult);
static config_object_t *PHDC_ManagerGetConfigObject(void *param, handle_t objectHandle);
static ava_type_t *PHDC_ManagerGetAttribute(config_object_t *configObject, oid_type_t attributeId);
static void PHDC_ManagerPrintFloatValue(uint8_t *value);
static void PHDC_ManagerPrintSfloatValue(uint8_t *value);
static int32_t PHDC_ManagerConvertTwoComplement(uint8_t size, uint8_t *value);
static void PHDC_ManagerPrintAbsoluteTimeStamp(uint8_t *value);
static void PHDC_ManagerPrintNomenclature(oid_type_t type);
static void PHDC_ManagerPrintPartition(nom_partition_t partition);
static void PHDC_ManagerBulkInCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status);
static void PHDC_ManagerBulkOutCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status);
static void PHDC_ManagerRecvComplete(void *param);

/*******************************************************************************
 * Variables
 ******************************************************************************/

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_SendDataBuffer[APDU_MAX_BUFFER_SIZE];   /*!< use to send application protocol data unit */
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_RecvDataBuffer[APDU_MAX_BUFFER_SIZE];   /*!< use to receive application protocol data unit */

/*! @brief the temp buffer used to prepare the manager response data */
uint8_t s_tempBuffer[50U];

/*! @brief the host PHDC manager instance */
host_phdc_manager_instance_t g_phdcManagerInstance;
/*! @brief the list of supported system ID */
uint8_t s_listOfSupportedSystemId[MAX_NUMBER_SUPPORTED_DEVICE][8] = {
    {0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U, 0x00U}};
/*! @brief the list of supported device config */
uint16_t s_listOfSupportedDeviceConfig[MAX_NUMBER_SUPPORTED_DEVICE] = {0x0000U};

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief set state.
 *
 * This function is called to change the state of phdc manager
 *
 * @param param   the phdc manager instance pointer.
 * @param state   phdc manager state
 */
static void PHDC_ManagerSetState(void *param, uint8_t state)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    if (NULL != phdcManagerInstance)
    {
        switch (state)
        {
            case IEEE11073_MANAGER_DISCONNECTED:
                phdcManagerInstance->managerState = state;
                usb_echo("\n\r11073Manager: Enter Disconnected state");
                break;
            case IEEE11073_MANAGER_CONNECTED_UNASSOCIATED:
                phdcManagerInstance->managerState = state;
                usb_echo("\n\r11073Manager: Enter Connected Unassociated state");
                break;
            case IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING:
                phdcManagerInstance->managerState = state;
                usb_echo("\n\r11073Manager: Enter Associated Configuring Waiting state");
                break;
            case IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG:
                phdcManagerInstance->managerState = state;
                usb_echo("\n\r11073Manager: Enter Associated Configuring Checking state");
                break;
            case IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING:
                phdcManagerInstance->managerState = state;
                usb_echo("\n\r11073Manager: Enter Associated Operating state");
                break;
            case IEEE11073_MANAGER_DISASSOCIATING:
                phdcManagerInstance->managerState = state;
                usb_echo("\n\r11073Manager: Enter Disassociating state");
                break;
            default:
                usb_echo("\n\r11073Manager: Error Invalid state");
                break;
        }
    }
    else
    {
        usb_echo("\n\r11073Manager: Error Invalid request");
    }
}

/*!
 * @brief association request received.
 *
 * This function is called to process received association request data.
 *
 * @param param               The manager instance pointer.
 * @param associationRequest  Association request data
 */
static void PHDC_ManagerRecvAssociationRequest(void *param, aarq_apdu_t *associationRequest)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    aare_apdu_t *associationResponse = NULL;
    /* Initialize the association result variable is Reject-unknown */
    phdcManagerInstance->assocResult = REJECTED_UNKNOWN;
    uint32_t tempassocVersion;
    USB_ASSIGN_VALUE_ADDRESS_LONG_BY_BYTE(tempassocVersion, associationRequest->assocVersion);

    /* Checks the association version of association procedure */
    if (USB_LONG_FROM_BIG_ENDIAN(ASSOC_VERSION1) != tempassocVersion)
    {
        data_proto_t *dataProto = (data_proto_t *)&associationRequest->dataProtoList.value[0U];
        /* The manager does not understand the association version, it shall reject
           the association request with reject-unsupported-assoc-version */
        phdcManagerInstance->assocResult = REJECTED_UNSUPPORTED_ASSOC_VERSION;
        associationResponse = (aare_apdu_t *)&s_tempBuffer[0U];
        associationResponse->result = USB_SHORT_FROM_BIG_ENDIAN(phdcManagerInstance->assocResult);
        associationResponse->selectedDataProto.dataProtoId = dataProto->dataProtoId;
        associationResponse->selectedDataProto.dataProtoInfo.length = 0U;
    }
    else
    {
        data_proto_t *dataProto = (data_proto_t *)&associationRequest->dataProtoList.value[0U];
        if (USB_SHORT_FROM_BIG_ENDIAN(DATA_PROTO_ID_20601) != dataProto->dataProtoId)
        {
            /* The data-proto-id is not set to data-proto-id-20601, the manager shall send association
               response with reject-no-common-protocol */
            phdcManagerInstance->assocResult = REJECTED_NO_COMMON_PROTOCOL;
            associationResponse = (aare_apdu_t *)&s_tempBuffer[0U];
            associationResponse->result = USB_SHORT_FROM_BIG_ENDIAN(phdcManagerInstance->assocResult);
            associationResponse->selectedDataProto.dataProtoId = dataProto->dataProtoId;
            associationResponse->selectedDataProto.dataProtoInfo.length = 0U;
        }
        else
        {
            /* The data-proto-id is set to data-proto-id-20601, the data-proto-info shall be filled with
               PhdAssociationInformation */
            uint16_t offset = 0;
            phd_association_information_t *assocResponseInfo = NULL;
            phd_association_information_t *assocInfo =
                (phd_association_information_t *)&dataProto->dataProtoInfo.value[0U];
            uint8_t isSupportedDevice = 1U;
            /* System ID checking */
            for (uint8_t i = 0U; i < USB_SHORT_FROM_BIG_ENDIAN(assocInfo->systemId.length); i++)
            {
                if (s_listOfSupportedSystemId[0U][i] != *((uint8_t *)&assocInfo->systemId.value[0U] + i))
                {
                    isSupportedDevice = 0U;
                    break;
                }
            }
            if (0U == isSupportedDevice)
            {
                /* The system ID is not supported by manager,
                   it shall send association response with accepted-unknown-config */
                phdcManagerInstance->assocResult = ACCEPTED_UNKNOWN_CONFIG;
            }
            else
            {
                isSupportedDevice = 0U;
                for (uint8_t index = 0U; index < MAX_NUMBER_SUPPORTED_DEVICE; index++)
                {
                    if (s_listOfSupportedDeviceConfig[index] == assocInfo->devConfigId)
                    {
                        /* The device configuration is supported by manager */
                        isSupportedDevice = 1U;
                        break;
                    }
                }
                if (1U == isSupportedDevice)
                {
                    /* The manager recognizes the system ID and device configuration ID,
                       it shall send association response with accepted */
                    phdcManagerInstance->assocResult = ACCEPTED;
                }
                else
                {
                    /* The device configuration ID is not supported by manager,
                       it shall send association response with accepted-unknown-config */
                    phdcManagerInstance->assocResult = ACCEPTED_UNKNOWN_CONFIG;
                }
            }
            associationResponse = (aare_apdu_t *)&s_tempBuffer[0U];
            assocResponseInfo =
                (phd_association_information_t *)&associationResponse->selectedDataProto.dataProtoInfo.value[0];
            associationResponse->result = USB_SHORT_FROM_BIG_ENDIAN(phdcManagerInstance->assocResult);
            associationResponse->selectedDataProto.dataProtoId = dataProto->dataProtoId;
            associationResponse->selectedDataProto.dataProtoInfo.length = dataProto->dataProtoInfo.length;
            if (USB_SHORT_FROM_BIG_ENDIAN(dataProto->dataProtoInfo.length) > 0U)
            {
                uint8_t *temp8 = NULL;
                memcpy(&associationResponse->selectedDataProto.dataProtoInfo.value[0],
                       &dataProto->dataProtoInfo.value[0], USB_SHORT_FROM_BIG_ENDIAN(dataProto->dataProtoInfo.length));
                assocResponseInfo->systemType = USB_LONG_FROM_BIG_ENDIAN(0x80000000U); /* Manager system ID */
                /* Manager's response to config-id is always 0 */
                offset += sizeof(protocol_version_t) + sizeof(encoding_rules_t) + sizeof(nomenclature_version_t) +
                          sizeof(functional_units_t) + sizeof(system_type_t) + sizeof(uint16_t) +
                          USB_SHORT_FROM_BIG_ENDIAN(assocResponseInfo->systemId.length);
                temp8 = (uint8_t *)&associationResponse->selectedDataProto.dataProtoInfo.value[offset];
                USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(0U, temp8);
                /* Manager's response to data-req-mode-capab is always 0 */
                offset += sizeof(uint16_t);
                temp8 = (uint8_t *)&associationResponse->selectedDataProto.dataProtoInfo.value[offset];
                USB_LONG_TO_LITTLE_ENDIAN_ADDRESS(0U, temp8);
            }
        }
    }
    usb_echo("\n\r11073Manager: Received Association request.");
    /* Send back association response to the device */
    PHDC_ManagerSendAssociationResponse(param, associationResponse);
}

/*!
 * @brief send association response.
 * This function is called to send association response to the device.
 *
 * @param param                 the phdc manager instance pointer.
 * @param associationResponse   association result data
 */
static void PHDC_ManagerSendAssociationResponse(void *param, aare_apdu_t *associationResponse)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    apdu_t *pApdu;
    uint16_t size;
    if (NULL != associationResponse)
    {
        /* Calculate the size of association response data */
        size = (uint16_t)(APDU_HEADER_SIZE + sizeof(associationResponse->result) +
                          sizeof(associationResponse->selectedDataProto.dataProtoId) +
                          sizeof(associationResponse->selectedDataProto.dataProtoInfo.length) +
                          USB_SHORT_FROM_BIG_ENDIAN(associationResponse->selectedDataProto.dataProtoInfo.length));

        pApdu = (apdu_t *)&phdcManagerInstance->sendDataBuffer[0];
        USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->choice, USB_SHORT_FROM_BIG_ENDIAN(AARE_CHOSEN));
        USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->length, USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE));

        USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->u.aare.result, associationResponse->result);
        USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->u.aare.selectedDataProto.dataProtoId,
                                               associationResponse->selectedDataProto.dataProtoId);
        USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->u.aare.selectedDataProto.dataProtoInfo.length,
                                               associationResponse->selectedDataProto.dataProtoInfo.length);

        if (USB_SHORT_FROM_BIG_ENDIAN(associationResponse->selectedDataProto.dataProtoInfo.length) > 0U)
        {
            memcpy(&pApdu->u.aare.selectedDataProto.dataProtoInfo.value[0],
                   &associationResponse->selectedDataProto.dataProtoInfo.value[0],
                   USB_SHORT_FROM_BIG_ENDIAN(associationResponse->selectedDataProto.dataProtoInfo.length));
        }
        /* Send association response to the device */
        if (kStatus_USB_Success != USB_HostPhdcSend(phdcManagerInstance->classHandle, (uint8_t *)pApdu, (uint32_t)size,
                                                    PHDC_ManagerBulkOutCallback, phdcManagerInstance))
        {
            usb_echo("send aare error \n\r!");
        }
    }
    else
    {
        usb_echo("send aare error NULL response pointer\n\r!");
    }
}

/*!
 * @brief send association abort request.
 * This function is called to send association abort request to the device.
 *
 * @param param         the phdc manager instance pointer.
 * @param abortReason   association abort reason.
 */
static void PHDC_ManagerSendAssociationAbortRequest(void *param, abort_reason_t abortReason)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    apdu_t *pApdu;
    uint16_t size;
    /* Calculate the size of association request data */
    size = (uint16_t)(ASSOC_ABRT_HEADER_SIZE + APDU_HEADER_SIZE);
    pApdu = (apdu_t *)&phdcManagerInstance->sendDataBuffer[0];
    pApdu->choice = USB_SHORT_FROM_BIG_ENDIAN(ABRT_CHOSEN);
    pApdu->length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE);
    pApdu->u.abrt.reason = USB_SHORT_FROM_BIG_ENDIAN(abortReason);
    /* Send abort request to the device */
    if (kStatus_USB_Success != USB_HostPhdcSend(phdcManagerInstance->classHandle, (uint8_t *)pApdu, (uint32_t)size,
                                                PHDC_ManagerBulkOutCallback, phdcManagerInstance))
    {
        usb_echo("send abort error \n\r!");
    }
}

/*!
 * @brief send association release response.
 * This functions is called to send association release response to the device.
 *
 * @param param             the phdc manager instance pointer.
 * @param releaseReason     association release response reason.
 */
static void PHDC_ManagerSendAssociationReleaseResponse(void *param, release_response_reason_t releaseReason)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    apdu_t *pApdu;
    uint16_t size;
    size = (uint16_t)(ASSOC_RLRE_HEADER_SIZE + APDU_HEADER_SIZE);
    pApdu = (apdu_t *)&phdcManagerInstance->sendDataBuffer[0];
    pApdu->choice = USB_SHORT_FROM_BIG_ENDIAN(RLRE_CHOSEN);
    pApdu->length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE);
    pApdu->u.rlre.reason = USB_SHORT_FROM_BIG_ENDIAN(releaseReason);
    /* Send release response to the device */
    if (kStatus_USB_Success != USB_HostPhdcSend(phdcManagerInstance->classHandle, (uint8_t *)pApdu, (uint32_t)size,
                                                PHDC_ManagerBulkOutCallback, phdcManagerInstance))
    {
        usb_echo("send aare error \n\r!");
    }
}

/*!
 * @brief PHDC_ManagerRecvPresentationProtocolDataUnit.
 * This function processes the received presentation PDU data.
 *
 * @param param         the phdc manager instance pointer.
 * @param pPrst         the presentation PDU
 */
static void PHDC_ManagerRecvPresentationProtocolDataUnit(void *param, prst_apdu_t *pPrst)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    data_apdu_t *dataApdu = (data_apdu_t *)&(pPrst->value[0U]);
    /* Store the invoke ID */
    phdcManagerInstance->invokeId = dataApdu->invokeId;
    /* Get the prst choice */
    uint16_t prstChoice = dataApdu->choice.choice;
    if (IEEE11073_MANAGER_CONNECTED_UNASSOCIATED == phdcManagerInstance->managerState)
    {
        /* should not happen, send abort request to the device */
        PHDC_ManagerSendAssociationAbortRequest(param, ABORT_REASON_UNDEFINED);
    }
    else
    {
        switch (USB_SHORT_FROM_BIG_ENDIAN(prstChoice))
        {
            case ROIV_CMIP_EVENT_REPORT_CHOSEN:
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState)
                {
                    /* Not allowed, send Roer with no-such-object-instance, no state transition */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_OBJECT_INSTANCE);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                    phdcManagerInstance->managerState)
                {
                    /* The Agent only ever sends event report messages. This should never happen.
                    Roer with no-such-action is sent */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_ACTION);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, send rors or roer or rorj */
                }
                if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
                {
                    /* The manager will not provide any response */
                }
                break;
            case ROIV_CMIP_CONFIRMED_EVENT_REPORT_CHOSEN:
                /* Event report containing configuration from agent */
                PHDC_ManagerRecvRoivCmipConfirmedEventReport(
                    param, (event_report_argument_simple_t *)&(dataApdu->choice.u.roivCmipConfirmedEventReport));
                break;
            case ROIV_CMIP_GET_CHOSEN:
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState)
                {
                    /* Not allowed, send Roer with no-such-object-instance, no state transition */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_OBJECT_INSTANCE);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                    phdcManagerInstance->managerState)
                {
                    /* The Agent only ever sends event report messages. This should never happen.
                    Roer with no-such-action is sent */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_ACTION);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, send rors or roer or rorj */
                }
                if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
                {
                    /* The manager will not provide any response */
                }
                break;
            case ROIV_CMIP_SET_CHOSEN:
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState)
                {
                    /* Not allowed, send Roer with no-such-object-instance, no state transition */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_OBJECT_INSTANCE);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                    phdcManagerInstance->managerState)
                {
                    /* The Agent only ever sends event report messages. This should never happen.
                    Roer with no-such-action is sent */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_ACTION);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, send rors or roer or rorj */
                }
                if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
                {
                    /* The manager will not provide any response */
                }
                break;
            case ROIV_CMIP_CONFIRMED_SET_CHOSEN:
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState)
                {
                    /* Not allowed, send Roer with no-such-object-instance, no state transition */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_OBJECT_INSTANCE);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                    phdcManagerInstance->managerState)
                {
                    /* The Agent only ever sends event report messages. This should never happen.
                    Roer with no-such-action is sent */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_ACTION);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, send rors or roer or rorj */
                }
                if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
                {
                    /* The manager will not provide any response */
                }
                break;
            case ROIV_CMIP_ACTION_CHOSEN:
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState)
                {
                    /* Not allowed, send Roer with no-such-object-instance, no state transition */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_OBJECT_INSTANCE);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                    phdcManagerInstance->managerState)
                {
                    /* The Agent only ever sends event report messages. This should never happen.
                    Roer with no-such-action is sent */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_ACTION);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, send rors or roer or rorj */
                }
                if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
                {
                    /* The manager will not provide any response */
                }
                break;
            case ROIV_CMIP_CONFIRMED_ACTION_CHOSEN:
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState)
                {
                    /* Not allowed, send Roer with no-such-object-instance, no state transition */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_OBJECT_INSTANCE);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                    phdcManagerInstance->managerState)
                {
                    /* The Agent only ever sends event report messages. This should never happen.
                    Roer with no-such-action is sent */
                    error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
                    errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_ACTION);
                    errorResult->parameter.length = 0U; /* There is no parameter for error result */
                    /* Send rors or rore or rorj, no state transition */
                    PHDC_ManagerSendRoer(param, errorResult);
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, send rors or roer or rorj */
                }
                if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
                {
                    /* The manager will not provide any response */
                }
                break;
            case RORS_CMIP_CONFIRMED_EVENT_REPORT_CHOSEN:
                if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState) ||
                    (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                     phdcManagerInstance->managerState))
                {
                    /* The manager may have sent a roiv-cmip-get (handle = 0) */
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, this is the normal operating state */
                }
                if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
                {
                    /* Send abort request to device, change the state to unassociated */
                    PHDC_ManagerSendAssociationAbortRequest(param, ABORT_REASON_UNDEFINED);
                    PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
                }
                break;
            case RORS_CMIP_GET_CHOSEN:
                if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState) ||
                    (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                     phdcManagerInstance->managerState))
                {
                    /* The manager may have sent a roiv-cmip-get (handle = 0) */
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, this is the normal operating state */
                    PHDC_ManagerRecvRorsCmipGet(param, (get_result_simple_t *)&dataApdu->choice.u.rorsCmipGet);
                }
                break;
            case RORS_CMIP_CONFIRMED_SET_CHOSEN:
                if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState) ||
                    (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                     phdcManagerInstance->managerState))
                {
                    /* The manager may have sent a roiv-cmip-get (handle = 0) */
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, this is the normal operating state */
                }
                break;
            case RORS_CMIP_CONFIRMED_ACTION_CHOSEN:
                if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState) ||
                    (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                     phdcManagerInstance->managerState))
                {
                    /* The manager may have sent a roiv-cmip-get (handle = 0) */
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, this is the normal operating state */
                }
                break;
            case ROER_CHOSEN:
                if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState) ||
                    (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                     phdcManagerInstance->managerState))
                {
                    /* The manager may have sent a roiv-cmip-get (handle = 0) */
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, this is the normal operating state */
                }
                break;
            case RORJ_CHOSEN:
                if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState) ||
                    (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                     phdcManagerInstance->managerState))
                {
                    /* The manager may have sent a roiv-cmip-get (handle = 0) */
                }
                if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
                {
                    /* Normal processing of messages, this is the normal operating state */
                }
                break;
            default:
                break;
        }
    }
}

/*!
 * @brief PHDC_ManagerRecvRoivCmipConfirmedEventReport.
 * This function handles the ROIV_CMIP_CONFIRMED_EVENT_REPORT_CHOSEN choice.
 *
 * @param param         the phdc manager instance pointer.
 */
static void PHDC_ManagerRecvRoivCmipConfirmedEventReport(void *param, event_report_argument_simple_t *eventReport)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
    {
        /* The manager will not provide any response */
    }
    else
    {
        switch (USB_SHORT_FROM_BIG_ENDIAN(eventReport->eventType))
        {
            /* MDS object event */
            case MDC_NOTI_CONFIGURATION:
                /* Event report contains device configuration from the Agent */
                PHDC_ManagerRecvMdcNotiConfig(param, eventReport);
                break;
            case MDC_NOTI_SCAN_REPORT_VAR:
                break;
            case MDC_NOTI_SCAN_REPORT_FIXED:
                PHDC_ManagerRecvMdcNotiScanReportFixed(param, eventReport);
                break;
            case MDC_NOTI_SCAN_REPORT_MULTI_PERSON_VAR:
                break;
            case MDC_NOTI_SCAN_REPORT_MULTI_PERSON_FIXED:
                break;
            /* PM store object event */
            case MDC_NOTI_SEGMENT_DATA:
                break;
            /* Episodic configurable scanner object events */
            case MDC_NOTI_UNBUF_SCAN_REPORT_VAR:
                break;
            case MDC_NOTI_UNBUF_SCAN_REPORT_FIXED:
                break;
            case MDC_NOTI_UNBUF_SCAN_REPORT_GROUPED:
                break;
            case MDC_NOTI_UNBUF_SCAN_REPORT_MULTI_PERSON_VAR:
                break;
            case MDC_NOTI_UNBUF_SCAN_REPORT_MULTI_PERSON_FIXED:
                break;
            case MDC_NOTI_UNBUF_SCAN_REPORT_MULTI_PERSON_GROUPED:
                break;
            /* Periodic configurable scanner object events  */
            case MDC_NOTI_BUF_SCAN_REPORT_VAR:
                break;
            case MDC_NOTI_BUF_SCAN_REPORT_FIXED:
                break;
            case MDC_NOTI_BUF_SCAN_REPORT_GROUPED:
                break;
            case MDC_NOTI_BUF_SCAN_REPORT_MULTI_PERSON_VAR:
                break;
            case MDC_NOTI_BUF_SCAN_REPORT_MULTI_PERSON_FIXED:
                break;
            case MDC_NOTI_BUF_SCAN_REPORT_MULTI_PERSON_GROUPED:
                break;
            default:
                /* these event types will be enabled as required in future */
                break;
        }
    }
}

/*!
 * @brief PHDC_ManagerRecvMdcNotiConfig.
 * This function handles the MDC_NOTI_CONFIGURATION event types.
 *
 * @param param             the phdc manager instance pointer.
 * @param eventReport       the event report data.
 */
static void PHDC_ManagerRecvMdcNotiConfig(void *param, event_report_argument_simple_t *eventReport)
{
    /* manager instance pointer */
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    /* configuration report */
    config_report_t *configReport = (config_report_t *)&eventReport->eventInfo.value[0U];
    /* configuration object list */
    config_object_list_t *configObjectList = &(configReport->configObjList);
    /* initialize the configuration result */
    phdcManagerInstance->configResult = UNSUPPORTED_CONFIG;

    usb_echo("\n\r11073Manager: Received a configuration event report.");
    usb_echo("\n\r11073Manager: --------------------------------------------------");
    usb_echo("\n\r11073Manager: Configuration Report Id: %d.", USB_SHORT_FROM_BIG_ENDIAN(configReport->configReportId));
    usb_echo("\n\r11073Manager: Number of configuration Objects: %d.",
             USB_SHORT_FROM_BIG_ENDIAN(configObjectList->count));
    if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState)
    {
        event_report_result_simple_t *eventResponse = NULL;
        uint16_t configOffset = 0U;
        uint16_t configListSize = (uint16_t)(USB_SHORT_FROM_BIG_ENDIAN(configObjectList->length) +
                                             sizeof(configObjectList->count) + sizeof(configObjectList->length));
        /* Clear config object list */
        memset((void *)&phdcManagerInstance->configObjectList[0U], 0U, APDU_MAX_BUFFER_SIZE);
        /* Store the configuration object list to the manager instance pointer */
        memcpy((void *)&phdcManagerInstance->configObjectList[0U], (void *)configObjectList, configListSize);
        /* process configuration object list */
        for (uint8_t i = 0U; i < USB_SHORT_FROM_BIG_ENDIAN(configObjectList->count); i++)
        {
            /* get configuration object entry */
            config_object_t *configObject =
                (config_object_t *)(((uint8_t *)&configObjectList->value[0U]) + configOffset);
            attribute_list_t *attributeList = (attribute_list_t *)&configObject->attributes;
            uint16_t attributeOffset = 0U;
            usb_echo("\n\r11073Manager:  > Object Handle %d: Class = %d  Num Attributes = %d.",
                     USB_SHORT_FROM_BIG_ENDIAN(configObject->objectHandle),
                     USB_SHORT_FROM_BIG_ENDIAN(configObject->objectClass),
                     USB_SHORT_FROM_BIG_ENDIAN(attributeList->count));
            /* process attribute list */
            for (uint8_t j = 0U; j < USB_SHORT_FROM_BIG_ENDIAN(attributeList->count); j++)
            {
                /* get attribute entry */
                ava_type_t *attribute = (ava_type_t *)((uint8_t *)(&attributeList->value[0U]) + attributeOffset);
                usb_echo("\n\r11073Manager:  > > Attribute%d: Id = ", j);
                PHDC_ManagerPrintNomenclature(attribute->attributeId);
                /* Seek to the next attribute entry in the attribute list */
                attributeOffset += sizeof(attribute->attributeId) + sizeof(attribute->attributeValue.length) +
                                   USB_SHORT_FROM_BIG_ENDIAN(attribute->attributeValue.length);
            }
            /* Seek to the next configuration entry in the configuration object list */
            configOffset += sizeof(configObject->objectClass) + sizeof(configObject->objectHandle) +
                            sizeof(configObject->attributes.count) + sizeof(configObject->attributes.length) +
                            USB_SHORT_FROM_BIG_ENDIAN(configObject->attributes.length);
        }
        /* update the result of configuration processing */
        phdcManagerInstance->configResult = ACCEPTED_CONFIG;
        PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG);
        /* Prepare the configuration response data */
        eventResponse = (event_report_result_simple_t *)&s_tempBuffer[0U];
        config_report_rsp_t *configResponse;
        eventResponse->objectHandle = eventReport->objectHandle;
        USB_ASSIGN_VALUE_ADDRESS_LONG_BY_BYTE(eventResponse->currentTime, eventReport->eventTime);
        eventResponse->eventType = eventReport->eventType;
        eventResponse->eventReplyInfo.length = USB_SHORT_FROM_BIG_ENDIAN(sizeof(config_report_rsp_t));
        configResponse = (config_report_rsp_t *)(&eventResponse->eventReplyInfo.value[0]);
        configResponse->configReportId = configReport->configReportId;
        configResponse->configResult = USB_SHORT_FROM_BIG_ENDIAN(phdcManagerInstance->configResult);
        PHDC_ManagerSendRorsCmipConfirmedEventReport(param, eventResponse);
    }
    else if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG == phdcManagerInstance->managerState)
    {
        /* Received configuration report from agent when the manager does not expect */
        PHDC_ManagerSendAssociationAbortRequest(param, ABORT_REASON_UNDEFINED);
        PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG);
    }
    else if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState)
    {
        error_result_t *errorResult = (error_result_t *)&s_tempBuffer[0U];
        errorResult->errorValue = USB_SHORT_FROM_BIG_ENDIAN(NO_SUCH_OBJECT_INSTANCE);
        errorResult->parameter.length = 0U; /* There is no parameter for error result */
        /* Send rors or rore or rorj, no state transition */
        PHDC_ManagerSendRoer(param, errorResult);
    }
    else
    {
    }
}

/*!
 * @brief PHDC_ManagerRecvMdcNotiScanReportFixed.
 * This function handles the MDC_NOTI_SCAN_REPORT_FIXED event types.
 *
 * @param param             the phdc manager instance pointer.
 * @param apdu              application protocol data unit.
 * @param dataApdu          data APDU.
 */
static void PHDC_ManagerRecvMdcNotiScanReportFixed(void *param, event_report_argument_simple_t *eventReport)
{
    scan_report_info_fixed_t *scanReportInfoFixed = (scan_report_info_fixed_t *)&eventReport->eventInfo.value[0];
    observation_scan_fixed_list_t *obsScanFixedList =
        (observation_scan_fixed_list_t *)&scanReportInfoFixed->obsScanFixed;
    event_report_result_simple_t *eventResponse = NULL;
    uint16_t obsListOffset = 0U;
    usb_echo("\n\r11073Manager: Received a MDC Noti Scan Report Fixed event.");
    usb_echo("\n\r11073Manager: --------------------------------------------------");
    usb_echo("\n\r11073Manager: Scan Report Number: %d  Number Observations: %d",
             USB_SHORT_FROM_BIG_ENDIAN(scanReportInfoFixed->scanReportNo),
             USB_SHORT_FROM_BIG_ENDIAN(obsScanFixedList->count));

    for (uint8_t i = 0U; i < USB_SHORT_FROM_BIG_ENDIAN(obsScanFixedList->count); i++)
    {
        observation_scan_fixed_t *obsScanFixed =
            (observation_scan_fixed_t *)((uint8_t *)&(obsScanFixedList->value[0U]) + obsListOffset);
        config_object_t *configObject =
            PHDC_ManagerGetConfigObject(param, USB_SHORT_FROM_BIG_ENDIAN(obsScanFixed->objectHandle));

        if (NULL != configObject)
        {
            switch (USB_SHORT_FROM_BIG_ENDIAN(configObject->objectClass))
            {
                case MDC_MOC_VMO_METRIC_NUMERIC:
                    PHDC_ManagerRecvMdcNotiScanReportFixedMetricNU(configObject, obsScanFixed);
                    break;
                case MDC_MOC_VMO_METRIC_ENUMERATION:
                    break;
                case MDC_MOC_VMO_METRIC_REAL_TIME_SAMPLE_ARRAY:
                    break;
                default:
                    usb_echo(
                        "\n\r11073Manager: The object class is not supported to print out obsScanFixed report : %d",
                        configObject->objectClass);
                    break;
            }
        }
        else
        {
            usb_echo("\n\r11073Manager: Cannot find the object for obsScanFixed report : %d",
                     USB_SHORT_FROM_BIG_ENDIAN(obsScanFixed->objectHandle));
        }
        obsListOffset += sizeof(obsScanFixed->objectHandle) + sizeof(obsScanFixed->obsValData.length) +
                         USB_SHORT_FROM_BIG_ENDIAN(obsScanFixed->obsValData.length);
    }
    usb_echo("\n\r11073Manager: --------------------------------------------------");
    usb_echo("\n\r11073Manager: Send back MDC Noti Scan Fixed response.");
    /* prepare response data */
    eventResponse = (event_report_result_simple_t *)&s_tempBuffer[0U];
    eventResponse->objectHandle = eventReport->objectHandle;
    USB_ASSIGN_VALUE_ADDRESS_LONG_BY_BYTE(eventResponse->currentTime, eventReport->eventTime);
    eventResponse->eventType = eventReport->eventType;
    eventResponse->eventReplyInfo.length = 0U; /* There is no reply data */
    PHDC_ManagerSendRorsCmipConfirmedEventReport(param, eventResponse);
}

/*!
 * @brief PHDC_ManagerRecvMdcNotiScanReportFixedMetricNU.
 * This function process the observation data for the MDC_MOC_VMO_METRIC_NUMERIC class object.
 *
 * @param configObject         configuration object.
 * @param obsScanFixed         observation scan fixed report.
 */
static void PHDC_ManagerRecvMdcNotiScanReportFixedMetricNU(config_object_t *configObject,
                                                           observation_scan_fixed_t *obsScanFixed)
{
    ava_type_t *mdcAttributeValMap;
    attr_val_map_t *attributeValMap;
    uint16_t attributeOffset = 0U;
    /* Search the MDC_ATTRIBUTE_VALUE_MAP attribute in the object configuration to know
    the architecture of the received measurement data, if it is not found, the received data
    cannot be decoded */
    mdcAttributeValMap = PHDC_ManagerGetAttribute(configObject, MDC_ATTRIBUTE_VALUE_MAP);
    if (NULL != mdcAttributeValMap)
    {
        /* Initialize the observation offset */
        uint16_t observationOffset = 0;
        /* Get the Unit code for measurement data */
        ava_type_t *mdcAttributeUnitCode = PHDC_ManagerGetAttribute(configObject, MDC_ATTRIBUTE_UNIT_CODE);
        /* Get the MDC_ATTRIBUTE_ID_TYPE attribute */
        ava_type_t *mdcAttributeIdType = PHDC_ManagerGetAttribute(configObject, MDC_ATTRIBUTE_ID_TYPE);
        if (NULL != mdcAttributeIdType)
        {
            /* Get object type */
            type_t *objectType = (type_t *)&(mdcAttributeIdType->attributeValue.value[0U]);
            PHDC_ManagerPrintObjectInformation(objectType);
        }
        attributeValMap = (attr_val_map_t *)&(mdcAttributeValMap->attributeValue.value[0]);
        /* Decode the measurement data */
        for (uint8_t i = 0U; i < USB_SHORT_FROM_BIG_ENDIAN(attributeValMap->count); i++)
        {
            /* Get attribute value map entry */
            attr_val_map_entry_t *attributeValMapEntry =
                (attr_val_map_entry_t *)((uint8_t *)(&attributeValMap->value[0U]) + attributeOffset);
            octet_string_t *observationValData = (octet_string_t *)(&obsScanFixed->obsValData);
            /* Decode the observation value */
            switch (USB_SHORT_FROM_BIG_ENDIAN(attributeValMapEntry->attributeId))
            {
                case MDC_ATTRIBUTE_NUMERIC_VALUE_OBSERVATION:
                {
                    /* MDC Attribute Numeric Value Observation */
                    nu_obs_value_t *observationValue =
                        (nu_obs_value_t *)&(observationValData->value[observationOffset]);
                    usb_echo("\n\r11073Manager: Metric Id: ");
                    PHDC_ManagerPrintNomenclature(observationValue->metricId);
                    usb_echo(", unit code: ");
                    PHDC_ManagerPrintNomenclature(observationValue->unitCode);
                    usb_echo(", Observation Value: ");
                    PHDC_ManagerPrintFloatValue((uint8_t *)&observationValue->value);
                }
                break;
                case MDC_ATTRIBUTE_NUMERIC_VALUE_OBSERVATION_SIMPLE:
                    /* MDC Attribute Numeric Value Observation Simple */
                    usb_echo("\n\r11073Manager: Observation Value = ");
                    PHDC_ManagerPrintFloatValue(&(observationValData->value[observationOffset]));
                    /* The Unit code of observation value */
                    if (NULL != mdcAttributeUnitCode)
                    {
                        oid_type_t *temp = (oid_type_t *)&(mdcAttributeUnitCode->attributeValue.value[0U]);
                        usb_echo(" ");
                        PHDC_ManagerPrintNomenclature(*temp);
                    }
                    break;
                case MDC_ATTRIBUTE_NUMERIC_VALUE_OBSERVATION_BASIC:
                    /* MDC Attribute Numeric Value Observation Basic */
                    usb_echo("\n\r11073Manager: Observation Value = ");
                    PHDC_ManagerPrintSfloatValue(&(observationValData->value[observationOffset]));
                    /* The Unit code of observation value */
                    if (NULL != mdcAttributeUnitCode)
                    {
                        oid_type_t *temp = (oid_type_t *)&(mdcAttributeUnitCode->attributeValue.value[0U]);
                        usb_echo(" ");
                        PHDC_ManagerPrintNomenclature(*temp);
                    }
                    break;
                case MDC_ATTRIBUTE_NUMERIC_COMPOUND_VALUE_OBSERVATION:
                case MDC_ATTRIBUTE_NUMERIC_COMPOUND_VALUE_OBSERVATION_SIMPLE:
                case MDC_ATTRIBUTE_NUMERIC_COMPOUND_VALUE_OBSERVATION_BASIC:
                    /* These numeric compound value object will be enabled as required in future */
                    break;
                case MDC_ATTRIBUTE_NUMERIC_ACCURACY:
                    /* The numeric accuracy object will be enabled as required in future */
                    break;
                case MDC_ATTRIBUTE_TIME_STAMP_ABSOLUTE:
                    /* MDC Attribute Time Stamp Absolute */
                    usb_echo("\n\r11073Manager: Absolute Time Stamp = ");
                    PHDC_ManagerPrintAbsoluteTimeStamp(&(observationValData->value[observationOffset]));
                    break;
                default:
                    break;
            }
            observationOffset += USB_SHORT_FROM_BIG_ENDIAN(attributeValMapEntry->attributeLen);

            /* Seek to the next attribute value map entry in the MDC Attribute Value Map */
            attributeOffset += sizeof(attributeValMapEntry->attributeId) + sizeof(attributeValMapEntry->attributeLen);
        }
    }
    else
    {
        usb_echo("\n\r11073Manager: Missing MDC_ATTRIBUTE_VALUE_MAP attribute to print the fixed observation");
    }
}

/*!
 * @brief PHDC_ManagerSendRorsCmipConfirmedEventReport.
 * This function is called to send response for ROIV_CMIP_CONFIRMED_EVENT_REPORT_CHOSEN
 * choice.
 *
 * @param param             the phdc manager instance pointer.
 * @param eventResponse     event report result.
 */
static void PHDC_ManagerSendRorsCmipConfirmedEventReport(void *param, event_report_result_simple_t *eventResponse)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    apdu_t *pApdu;
    data_apdu_t *pPrst;
    uint16_t size;

    /* Calculate the size of rorsCmipConfirmedEventReport */
    size = (uint16_t)(APDU_HEADER_SIZE + ASSOC_PRST_HEADER_SIZE + sizeof(eventResponse->objectHandle) +
                      sizeof(eventResponse->currentTime) + sizeof(eventResponse->eventType) +
                      sizeof(eventResponse->eventReplyInfo.length) +
                      USB_SHORT_FROM_BIG_ENDIAN(eventResponse->eventReplyInfo.length));
    pApdu = (apdu_t *)&phdcManagerInstance->sendDataBuffer[0];
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->choice, USB_SHORT_FROM_BIG_ENDIAN(PRST_CHOSEN));
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->length, USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE));
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->u.prst.length,
                                                 USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE - sizeof(uint16_t)));

    pPrst = (data_apdu_t *)&(pApdu->u.prst.value[0U]);
    USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->invokeId, phdcManagerInstance->invokeId);
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(
        pPrst->choice.length, USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE - ASSOC_PRST_HEADER_SIZE));
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->choice.choice,
                                                 USB_SHORT_FROM_BIG_ENDIAN(RORS_CMIP_CONFIRMED_EVENT_REPORT_CHOSEN));
    USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->choice.u.rorsCmipConfirmedEventReport.objectHandle,
                                           eventResponse->objectHandle);
    USB_ASSIGN_VALUE_ADDRESS_LONG_BY_BYTE(pPrst->choice.u.rorsCmipConfirmedEventReport.currentTime,
                                          eventResponse->currentTime);

    USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->choice.u.rorsCmipConfirmedEventReport.eventType,
                                           eventResponse->eventType);
    USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->choice.u.rorsCmipConfirmedEventReport.eventReplyInfo.length,
                                           eventResponse->eventReplyInfo.length);

    if (USB_SHORT_FROM_BIG_ENDIAN(eventResponse->eventReplyInfo.length) > 0U)
    {
        memcpy(&(pPrst->choice.u.rorsCmipConfirmedEventReport.eventReplyInfo.value[0U]),
               &(eventResponse->eventReplyInfo.value[0U]),
               USB_SHORT_FROM_BIG_ENDIAN(eventResponse->eventReplyInfo.length));
    }
    /* Send rorsCmipConfirmedEventReport to the device */
    if (kStatus_USB_Success != USB_HostPhdcSend(phdcManagerInstance->classHandle, (uint8_t *)pApdu, (uint32_t)size,
                                                PHDC_ManagerBulkOutCallback, phdcManagerInstance))
    {
        usb_echo("send RorsCmipConfirmedEventReport error \n\r!");
    }
}

/*!
 * @brief PHDC_ManagerPrintObjectInformation.
 * This function is called to print out the object information
 * choice.
 *
 * @param objectType    The object to print
 */
static void PHDC_ManagerPrintObjectInformation(type_t *objectType)
{
    usb_echo("\n\r11073Manager: Object Type : ");
    PHDC_ManagerPrintNomenclature(objectType->code);
    usb_echo(", Partition: ");
    PHDC_ManagerPrintPartition(objectType->partition);
}

/*!
 * @brief PHDC_ManagerSendRoivCmipGet.
 * This function is called to send RoivCmipGet request to the device.
 *
 * @param param             the phdc manager instance pointer.
 * @param getArg            get argument.
 * @param invokeId          invoke Id number.
 */
static void PHDC_ManagerSendRoivCmipGet(void *param, get_argument_simple_t *getArg, invoke_id_type_t invokeId)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    uint16_t size;
    apdu_t *pApdu;
    data_apdu_t *pPrst;

    /* Calculate the size of RoivCmipGet request data */
    size = (uint16_t)(APDU_HEADER_SIZE + ASSOC_PRST_HEADER_SIZE + sizeof(getArg->objectHandle) +
                      sizeof(getArg->attributeIdList.count) + sizeof(getArg->attributeIdList.length) +
                      USB_SHORT_FROM_BIG_ENDIAN(getArg->attributeIdList.length));
    pApdu = (apdu_t *)&phdcManagerInstance->sendDataBuffer[0];
    /* Set value for APDU header */
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->choice, USB_SHORT_FROM_BIG_ENDIAN(PRST_CHOSEN));
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->length, USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE));

    /* Set value for PRST_APDU header */
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pApdu->u.prst.length,
                                                 USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE - sizeof(uint16_t)));

    pPrst = (data_apdu_t *)&(pApdu->u.prst.value[0U]);
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->invokeId, USB_SHORT_FROM_BIG_ENDIAN(invokeId));
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->choice.choice, USB_SHORT_FROM_BIG_ENDIAN(ROIV_CMIP_GET_CHOSEN));
    USB_ASSIGN_MACRO_VALUE_ADDRESS_SHORT_BY_BYTE(
        pPrst->choice.length, USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE - ASSOC_PRST_HEADER_SIZE));

    USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->choice.u.roivCmipGet.objectHandle, getArg->objectHandle);
    USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->choice.u.roivCmipGet.attributeIdList.count,
                                           getArg->attributeIdList.count);
    USB_ASSIGN_VALUE_ADDRESS_SHORT_BY_BYTE(pPrst->choice.u.roivCmipGet.attributeIdList.length,
                                           getArg->attributeIdList.length);
    if (USB_SHORT_FROM_BIG_ENDIAN(getArg->attributeIdList.length) > 0U)
    {
        memcpy((uint8_t *)&(pPrst->choice.u.roivCmipGet.attributeIdList.value[0U]),
               (uint8_t *)&(getArg->attributeIdList.value[0U]),
               USB_SHORT_FROM_BIG_ENDIAN(getArg->attributeIdList.length));
    }

    if (kStatus_USB_Success != USB_HostPhdcSend(phdcManagerInstance->classHandle, (uint8_t *)pApdu, (uint32_t)size,
                                                PHDC_ManagerBulkOutCallback, phdcManagerInstance))
    {
        usb_echo("send RoivCmipGet error");
    }
}

/*!
 * @brief PHDC_ManagerRecvRorsCmipGet.
 * This function handles the RORS_CMIP_GET_CHOSEN choice.
 *
 * @param param             the phdc manager instance pointer.
 * @param getResult         get result data.
 */
static void PHDC_ManagerRecvRorsCmipGet(void *param, get_result_simple_t *getResult)
{
    attribute_list_t *attributeList = (attribute_list_t *)&getResult->attributeList;
    uint16_t attributeOffset = 0U;
    usb_echo("\n\r11073Manager: Received a RORS_CMIP_GET_CHOSEN.");
    usb_echo("\n\r11073Manager: --------------------------------------------------");
    usb_echo("\n\r11073Manager: Number of attributes = %d", USB_SHORT_FROM_BIG_ENDIAN(attributeList->count));

    for (uint8_t i = 0U; i < USB_SHORT_FROM_BIG_ENDIAN(attributeList->count); i++)
    {
        ava_type_t *attribute = (ava_type_t *)((uint8_t *)(&attributeList->value[0U]) + attributeOffset);
        switch (USB_SHORT_FROM_BIG_ENDIAN(attribute->attributeId))
        {
            case MDC_ATTRIBUTE_SYSTEM_TYPE_SPECIFICATION_LIST:
            {
                type_ver_list_t *typeVerList = (type_ver_list_t *)&attribute->attributeValue.value[0U];
                for (uint8_t j = 0U; j < USB_SHORT_FROM_BIG_ENDIAN(typeVerList->count); j++)
                {
                    type_ver_t *typeVer = (type_ver_t *)&typeVerList->value[j];
                    switch (USB_SHORT_FROM_BIG_ENDIAN(typeVer->type))
                    {
                        case MDC_DEV_SPEC_PROFILE_PULSE_OXIMETER:
                            usb_echo("\n\r11073Manager: Type = Pulse Oximeter, Version = %d",
                                     USB_SHORT_FROM_BIG_ENDIAN(typeVer->version));
                            break;
                        case MDC_DEV_SPEC_PROFILE_BLOOD_PRESSURE:
                            usb_echo("\n\r11073Manager: Type = Blood Pressure, Version = %d",
                                     USB_SHORT_FROM_BIG_ENDIAN(typeVer->version));
                            break;
                        case MDC_DEV_SPEC_PROFILE_THERMOMETER:
                            usb_echo("\n\r11073Manager: Type = Thermometer, Version = %d",
                                     USB_SHORT_FROM_BIG_ENDIAN(typeVer->version));
                            break;
                        case MDC_DEV_SPEC_PROFILE_SCALE:
                            usb_echo("\n\r11073Manager: Type = Scale, Version = %d",
                                     USB_SHORT_FROM_BIG_ENDIAN(typeVer->version));
                            break;
                        case MDC_DEV_SPEC_PROFILE_GLUCOSE:
                            usb_echo("\n\r11073Manager: Type = Glucose Meter, Version = %d",
                                     USB_SHORT_FROM_BIG_ENDIAN(typeVer->version));
                            break;
                        case MDC_DEV_SPEC_PROFILE_HF_CARDIO:
                            usb_echo("\n\r11073Manager: Type = HF Cardio, Version = %d",
                                     USB_SHORT_FROM_BIG_ENDIAN(typeVer->version));
                            break;
                        case MDC_DEV_SPEC_PROFILE_HF_STRENGTH:
                            usb_echo("\n\r11073Manager: Type = HF Strength, Version = %d",
                                     USB_SHORT_FROM_BIG_ENDIAN(typeVer->version));
                            break;
                        case MDC_DEV_SPEC_PROFILE_AI_ACTIVITY_HUB:
                        case MDC_DEV_SPEC_PROFILE_AI_MED_MINDER:
                        default:
                            usb_echo("\n\r11073Manager: Type = (%s) Version = %d",
                                     USB_SHORT_FROM_BIG_ENDIAN(typeVer->type),
                                     USB_SHORT_FROM_BIG_ENDIAN(typeVer->version));
                            break;
                    }
                }
            }
            break;
            case MDC_ATTRIBUTE_ID_MODEL:
            {
                uint16_t stringOffset = 0U;
                usb_echo("\n\r11073Manager: Model: ");
                while (USB_SHORT_FROM_BIG_ENDIAN(attribute->attributeValue.length) > stringOffset)
                {
                    any_t *modelString = (any_t *)((uint8_t *)&attribute->attributeValue.value[0U] + stringOffset);
                    usb_echo("%s", modelString->value);
                    usb_echo(" ");
                    stringOffset += sizeof(modelString->length) + USB_SHORT_FROM_BIG_ENDIAN(modelString->length);
                }
            }
            break;
            default:
                break;
        }
        /* seek to the next attribute entry in the attribute list */
        attributeOffset += sizeof(attribute->attributeId) + sizeof(attribute->attributeValue.length) +
                           USB_SHORT_FROM_BIG_ENDIAN(attribute->attributeValue.length);
    }
}

/*!
 * @brief send error.
 * This function is called to send error command to the device.
 *
 * @param param             the phdc manager instance pointer.
 * @param errorResult       error result.
 */
static void PHDC_ManagerSendRoer(void *param, error_result_t *errorResult)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    uint16_t size;
    apdu_t *pApdu;
    data_apdu_t *pPrst;

    /* Calculate the size of Roer data */
    size = (uint16_t)(APDU_HEADER_SIZE + ASSOC_PRST_HEADER_SIZE + sizeof(errorResult->errorValue) +
                      sizeof(errorResult->parameter.length) + USB_SHORT_FROM_BIG_ENDIAN(errorResult->parameter.length));

    pApdu = (apdu_t *)&phdcManagerInstance->sendDataBuffer[0];
    pApdu->choice = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(PRST_CHOSEN);
    pApdu->length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE);
    pApdu->u.prst.length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE - sizeof(uint16_t));
    pPrst = (data_apdu_t *)&pApdu->u.prst.value[0U];
    pPrst->invokeId = phdcManagerInstance->invokeId;
    pPrst->choice.choice = USB_SHORT_FROM_BIG_ENDIAN(ROER_CHOSEN);
    pPrst->choice.length = (uint16_t)USB_SHORT_FROM_BIG_ENDIAN(size - APDU_HEADER_SIZE - ASSOC_PRST_HEADER_SIZE);
    pPrst->choice.u.roer.errorValue = errorResult->errorValue;
    pPrst->choice.u.roer.parameter.length = errorResult->parameter.length;
    if (USB_SHORT_FROM_BIG_ENDIAN(errorResult->parameter.length) > 0U)
    {
        memcpy(&pPrst->choice.u.roer.parameter.value[0U], &errorResult->parameter.value[0U],
               USB_SHORT_FROM_BIG_ENDIAN(errorResult->parameter.length));
    }
    if (kStatus_USB_Success != USB_HostPhdcSend(phdcManagerInstance->classHandle, (uint8_t *)pApdu, (uint32_t)size,
                                                PHDC_ManagerBulkOutCallback, phdcManagerInstance))
    {
        usb_echo("send roer error \n\r!");
    }
}

/*!
 * @brief PHDC_ManagerGetConfigObject.
 * This function returns the searched configuration object structure with all
 * the object entries.
 *
 * @param param            the phdc manager instance pointer.
 * @param objectHandle     object handle.
 *
 * @retval configuration object     if the object handle is found in the list.
 * @retval NULL                     if the object handle is not found in the list.
 */
static config_object_t *PHDC_ManagerGetConfigObject(void *param, handle_t objectHandle)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    config_object_list_t *configObjectList = (config_object_list_t *)&phdcManagerInstance->configObjectList[0U];
    config_object_t *configObjectEntry = NULL;
    if (0U != USB_SHORT_FROM_BIG_ENDIAN(configObjectList->count))
    {
        uint16_t configOffset = 0U;
        for (uint8_t i = 0U; i < USB_SHORT_FROM_BIG_ENDIAN(configObjectList->count); i++)
        {
            /* get the configuration object entry */
            configObjectEntry = (config_object_t *)(((uint8_t *)&configObjectList->value[0U]) + configOffset);
            if (objectHandle == USB_SHORT_FROM_BIG_ENDIAN(configObjectEntry->objectHandle))
            {
                /* The configuration object is found, return the configuration object */
                break;
            }
            /* Seek to the next configuration object entry in the list */
            configOffset += sizeof(configObjectEntry->objectClass) + sizeof(configObjectEntry->objectHandle) +
                            sizeof(configObjectEntry->attributes.count) + sizeof(configObjectEntry->attributes.length) +
                            USB_SHORT_FROM_BIG_ENDIAN(configObjectEntry->attributes.length);
            configObjectEntry = NULL;
        }
    }
    return configObjectEntry;
}

/*!
 * @brief PHDC_ManagerGetAttribute.
 * This function returns the searched attribute from the configuration object.
 *
 * @param configObject       the configuration object.
 * @param attributeId        attribute ID.
 *
 * @retval attribute object     if the attribute ID is found in the configuration object.
 * @retval NULL                 if the attribute ID is not found in the configuration object
 */
static ava_type_t *PHDC_ManagerGetAttribute(config_object_t *configObject, oid_type_t attributeId)
{
    /* initialize the attribute entry */
    ava_type_t *attributeEntry = NULL;
    if (NULL != configObject)
    {
        /* get the attribute list from configuration object */
        attribute_list_t *attributeList = (attribute_list_t *)&configObject->attributes;
        /* initialize the attribute offset */
        uint16_t attributeOffset = 0;
        /* process all the attributes */
        for (uint8_t i = 0U; i < USB_SHORT_FROM_BIG_ENDIAN(attributeList->count); i++)
        {
            /* Get the attribute entry */
            attributeEntry = (ava_type_t *)((uint8_t *)(&attributeList->value[0U]) + attributeOffset);

            if (attributeId == USB_SHORT_FROM_BIG_ENDIAN(attributeEntry->attributeId))
            {
                /* The attribute is found, return the attribute entry */
                break;
            }
            /* Seek to the next attribute entry in the list */
            attributeOffset += sizeof(attributeEntry->attributeId) + sizeof(attributeEntry->attributeValue.length) +
                               USB_SHORT_FROM_BIG_ENDIAN(attributeEntry->attributeValue.length);
            attributeEntry = NULL;
        }
    }
    return attributeEntry;
}

/*!
 * @brief PHDC_ManagerPrintFloatValue.
 * This function prints the floating point value.
 *
 * @param value         the value to print.
 */
static void PHDC_ManagerPrintFloatValue(uint8_t *value)
{
    /* The 32 bits contains an 8-bit signed exponent to base 10,
    followed by 24-bit signed integer (mantissa). Each is in 2'complement form.
    the return float value can be calculated with the formula:
        F = mantissa * 10^exponent
    */
    uint32_t rawValue;
    int32_t mantissa;
    int32_t exponent;
    float fValue;
    /* get Raw value from the pointer */
    memcpy(&rawValue, (uint8_t *)value, sizeof(rawValue));
    rawValue = USB_LONG_FROM_BIG_ENDIAN(rawValue);
    /* get 8-bit signed exponent */
    exponent = (int32_t)((rawValue & 0xFF000000U) >> 24U);
    /* get 24-bit signed integer (mantissa) */
    mantissa = (int32_t)(rawValue & 0x00FFFFFFU);
    exponent = PHDC_ManagerConvertTwoComplement(8U, (uint8_t *)&exponent);
    mantissa = PHDC_ManagerConvertTwoComplement(24U, (uint8_t *)&mantissa);
    fValue = (float)(mantissa * pow(10U, (double)exponent));
    usb_echo("%f", fValue);
}

/*!
 * @brief PHDC_ManagerPrintSfloatValue.
 * This function prints s-floating point value.
 *
 * @param value         the value to print.
 */
static void PHDC_ManagerPrintSfloatValue(uint8_t *value)
{
    /* The 16 bits contains an 4-bit signed exponent to base 10,
    followed by 12-bit signed integer (mantissa). Each is in 2'complement form.
    the return float value can be calculated with the formula:
        F = mantissa * 10^exponent
    */
    uint16_t rawValue;
    int32_t mantissa;
    int32_t exponent;
    float fValue;
    /* get Raw value from the pointer */
    memcpy(&rawValue, (uint8_t *)value, sizeof(rawValue));
    rawValue = USB_SHORT_FROM_BIG_ENDIAN(rawValue);
    /* get 4-bit signed exponent */
    exponent = (int32_t)((rawValue & 0xF000U) >> 12U);
    /* get 12-bit signed integer (mantissa) */
    mantissa = (int32_t)(rawValue & 0x0FFFU);
    exponent = PHDC_ManagerConvertTwoComplement(4U, (uint8_t *)&exponent);
    mantissa = PHDC_ManagerConvertTwoComplement(12U, (uint8_t *)&mantissa);
    fValue = (float)(mantissa * pow(10U, (double)exponent));
    usb_echo("%f", fValue);
}

/*!
 * @brief PHDC_ManagerConvertTwoComplement.
 * This function is called to convert 2's complement number to decimal
 * number.
 *
 * @param size         size of 2's complement number.
 * @param value        data pointer to convert
 */
static int32_t PHDC_ManagerConvertTwoComplement(uint8_t size, uint8_t *value)
{
    uint32_t significantMask;
    int32_t decimalValue;
    uint32_t rawValue;
    uint8_t isSupportConvert = 1U;
    memcpy(&rawValue, (uint8_t *)value, sizeof(rawValue));
    switch (size)
    {
        case 4U:
            significantMask = 0x0000000F;
            break;
        case 8U:
            significantMask = 0x000000FF;
            break;
        case 12U:
            significantMask = 0x00000FFF;
            break;
        case 24U:
            significantMask = 0x00FFFFFF;
            break;
        default:
            isSupportConvert = 0U;
            usb_echo("size of 2's complement number is not supported");
            break;
    }
    if (isSupportConvert)
    {
        rawValue = (uint32_t)(rawValue & significantMask);
        if (!(rawValue & (1U << (size - 1U))))
        {
            /* Positive number */
            decimalValue = (int32_t)(rawValue);
        }
        else
        {
            /* Negative number */
            rawValue = rawValue - 1U;
            rawValue = (uint32_t)((~rawValue) & significantMask);
            decimalValue = (int32_t)(0U - rawValue);
        }
    }
    else
    {
        decimalValue = 0U;
    }
    return decimalValue;
}

/*!
 * @brief PHDC_ManagerPrintAbsoluteTimeStamp.
 * This function prints absolute time stamp information.
 *
 * @param value         the value to print.
 */
static void PHDC_ManagerPrintAbsoluteTimeStamp(uint8_t *value)
{
    /* The absolute time data type is defined as follows:
    AbsoluteTime ::= SEQUENCE {
        century INT-U8,
        year INT-U8,
        month INT-U8,
        day INT-U8,
        hour INT-U8,
        minute INT-U8,
        second INT-U8,
        sec-fractions  INT-U8  -- 1/100 of second if available
    }
    */
    usb_echo("%02x%02x-%02x-%02x  %02x:%02x:%02x", value[0U], value[1U], value[2U], value[3U], value[4U], value[5U],
             value[6U]);
}

/*!
 * @brief PHDC_ManagerPrintNomenclature.
 * This function prints the nomenclature string corresponding with specified type
 * of OID.
 *
 * @param type          OID type.
 */
static void PHDC_ManagerPrintNomenclature(oid_type_t type)
{
    uint8_t isSupportedNomenclature = 0U;
    for (uint16_t i = 0U; i < g_nomAsciiCount; i++)
    {
        if ((g_nomenclatureAsciiTable[i].type == USB_SHORT_FROM_BIG_ENDIAN(type)) &&
            (NULL != g_nomenclatureAsciiTable[i].asciiString))
        {
            isSupportedNomenclature = 1U;
            usb_echo("%s", (uint8_t *)g_nomenclatureAsciiTable[i].asciiString);
        }
    }
    if (0U == isSupportedNomenclature)
    {
        usb_echo("%d", USB_SHORT_FROM_BIG_ENDIAN(type));
    }
}

/*!
 * @brief PHDC_ManagerPrintPartition.
 * This functions prints the partition string corresponding with specified type
 * of OID.
 *
 * @param partition     nomenclature partition.
 */
static void PHDC_ManagerPrintPartition(nom_partition_t partition)
{
    uint8_t isSupportedPartition = 0U;
    for (uint16_t i = 0U; i < g_partitionAsciiCount; i++)
    {
        if ((g_partitionAsciiTable[i].partition == USB_SHORT_FROM_BIG_ENDIAN(partition)) &&
            (NULL != g_partitionAsciiTable[i].asciiString))
        {
            isSupportedPartition = 1U;
            usb_echo("%s", (uint8_t *)g_partitionAsciiTable[i].asciiString);
        }
    }
    if (0U == isSupportedPartition)
    {
        usb_echo("%d", USB_SHORT_FROM_BIG_ENDIAN(partition));
    }
}

/*!
 * @brief PHDC_ManagerRecvComplete.
 * This function processes the received data.
 *
 * @param param         the phdc manager instance pointer.
 */
static void PHDC_ManagerRecvComplete(void *param)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    /* workaround */
    apdu_t *apdu = (apdu_t *)&phdcManagerInstance->recvDataBuffer[0];
    /* APDU processing */
    switch (USB_SHORT_FROM_BIG_ENDIAN(apdu->choice))
    {
        case AARQ_CHOSEN:
            if (IEEE11073_MANAGER_CONNECTED_UNASSOCIATED == phdcManagerInstance->managerState)
            {
                PHDC_ManagerRecvAssociationRequest(param, &apdu->u.aarq);
            }
            else if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING ==
                      phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                      phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState))
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
                /* Should not happen, send abort request to device with reason is normal */
                PHDC_ManagerSendAssociationAbortRequest(param, ABORT_REASON_UNDEFINED);
            }
            else
            {
            }
            break;
        case AARE_CHOSEN:
            if ((IEEE11073_MANAGER_CONNECTED_UNASSOCIATED == phdcManagerInstance->managerState) ||
                (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState) ||
                (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                 phdcManagerInstance->managerState) ||
                (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState) ||
                (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState))
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
                /* Should not happen, send abort request to device with reason is normal */
                PHDC_ManagerSendAssociationAbortRequest(param, ABORT_REASON_UNDEFINED);
            }
            break;
        case RLRQ_CHOSEN:
            if (IEEE11073_MANAGER_CONNECTED_UNASSOCIATED == phdcManagerInstance->managerState)
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
                /* Should not happen, send abort request to device with reason is normal */
                PHDC_ManagerSendAssociationAbortRequest(param, ABORT_REASON_UNDEFINED);
            }
            else if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING ==
                      phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                      phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState))
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
                /* The manager has received a request to release the association */
                PHDC_ManagerSendAssociationReleaseResponse(param, RELEASE_RESPONSE_REASON_NORMAL);
            }
            else if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_DISASSOCIATING);
                /* Should not happen, send abort request to device with reason is normal */
                PHDC_ManagerSendAssociationReleaseResponse(param, RELEASE_RESPONSE_REASON_NORMAL);
            }
            else
            {
            }
            break;
        case RLRE_CHOSEN:
            if (IEEE11073_MANAGER_CONNECTED_UNASSOCIATED == phdcManagerInstance->managerState)
            {
                /* should not happen */
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
            }
            else if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING ==
                      phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                      phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState))
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
                /* The manager has received a request to release the association */
                PHDC_ManagerSendAssociationAbortRequest(param, ABORT_REASON_UNDEFINED);
            }
            else if (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState)
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
            }
            else
            {
            }
            break;
        case ABRT_CHOSEN:
            if ((IEEE11073_MANAGER_CONNECTED_UNASSOCIATED == phdcManagerInstance->managerState) ||
                (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING == phdcManagerInstance->managerState) ||
                (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                 phdcManagerInstance->managerState) ||
                (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState) ||
                (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState))
            {
                /* should not happen */
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
            }
            break;
        case PRST_CHOSEN:
            if (IEEE11073_MANAGER_CONNECTED_UNASSOCIATED == phdcManagerInstance->managerState)
            {
                /* should not happen */
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
            }

            else if ((IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING ==
                      phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                      phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING == phdcManagerInstance->managerState) ||
                     (IEEE11073_MANAGER_DISASSOCIATING == phdcManagerInstance->managerState))
            {
                PHDC_ManagerRecvPresentationProtocolDataUnit(param, &apdu->u.prst);
            }
            else
            {
            }
            break;
        default:
            break;
    }
}

/*!
 * @brief host phdc manager control transfer callback.
 *
 * This function is used as callback function for control transfer .
 *
 * @param param      the host phdc manager instance pointer.
 * @param data       data buffer pointer.
 * @param dataLength data length.
 * @status           transfer result status.
 */
static void PHDC_ManagerControlCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    if (status != kStatus_USB_Success)
    {
        usb_echo("control transfer error\r\n");
    }
    else
    {
        if (phdcManagerInstance->runWaitState == kRunWaitSetInterface)
        {
            phdcManagerInstance->runState = kRunSetInterfaceDone;
        }
    }
}

/*!
 * @brief host phdc manager bulk in transfer callback.
 *
 * This function is used as callback function for bulk in transfer .
 *
 * @param param      the host phdc manager instance pointer.
 * @param data       data buffer pointer.
 * @param dataLength data length.
 * @status         transfer result status.
 */
static void PHDC_ManagerBulkInCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;

    if (phdcManagerInstance->runWaitState == kRunWaitDataReceived)
    {
        if (phdcManagerInstance->devState == kStatus_DEV_Attached)
        {
            if (status == kStatus_USB_Success)
            {
                phdcManagerInstance->runState = kRunDataReceived;
            }
            else
            {
                phdcManagerInstance->runState = kRunPrimeDataReceive;
            }
        }
    }
}

/*!
 * @brief host phdc manager bulk out transfer callback.
 *
 * This function is used as callback function for bulk out transfer .
 *
 * @param param      the host phdc manager instance pointer.
 * @param data       data buffer pointer.
 * @param dataLength data length.
 * @status         transfer result status.
 */
static void PHDC_ManagerBulkOutCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;
    if (kStatus_USB_Success == status)
    {
        if (IEEE11073_MANAGER_CONNECTED_UNASSOCIATED == phdcManagerInstance->managerState)
        {
            if (ACCEPTED == phdcManagerInstance->assocResult)
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING);
            }
            if (ACCEPTED_UNKNOWN_CONFIG == phdcManagerInstance->assocResult)
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING);
            }
        }
        else if (IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG ==
                 phdcManagerInstance->managerState)
        {
            if (ACCEPTED_CONFIG == phdcManagerInstance->configResult)
            {
                /* getArgument variable */
                get_argument_simple_t *getArg = (get_argument_simple_t *)&s_tempBuffer[0U];
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING);
                getArg->objectHandle = MDS_HANDLE;
                /* There is no attribute for get MDS attribute service request */
                getArg->attributeIdList.count = 0x0000U;
                getArg->attributeIdList.length = 0x0000U;
                PHDC_ManagerSendRoivCmipGet(param, getArg, 0x3456U /* start of DataApdu. MDER encoded. */);
            }
            else
            {
                PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING);
            }
        }
        else
        {
        }
    }
}

/*!
 * @brief host phdc manager function.
 *
 * This function implements the phdc manager action, it is used to create task.
 *
 * @param param   the host phdc manager instance pointer.
 */
void HOST_PhdcManagerTask(void *param)
{
    usb_status_t status = kStatus_USB_Success;
    host_phdc_manager_instance_t *phdcManagerInstance = (host_phdc_manager_instance_t *)param;

    /* device state changes */
    if (phdcManagerInstance->devState != phdcManagerInstance->prevState)
    {
        phdcManagerInstance->prevState = phdcManagerInstance->devState;
        switch (phdcManagerInstance->devState)
        {
            case kStatus_DEV_Idle:
                break;

            case kStatus_DEV_Attached:
                phdcManagerInstance->runState = kRunSetInterface;
                status =
                    USB_HostPhdcInit(phdcManagerInstance->deviceHandle, (void **)&phdcManagerInstance->classHandle);
                if (status != kStatus_USB_Success)
                {
                    usb_echo("Error in USB_HostPhdcInit: %x\r\n", status);
                }
                else
                {
                    usb_echo("phdc device attached\r\n");
                }

                break;
            case kStatus_DEV_Detached:
                phdcManagerInstance->devState = kStatus_DEV_Idle;
                phdcManagerInstance->runState = kRunIdle;
                USB_HostPhdcDeinit(phdcManagerInstance->deviceHandle, phdcManagerInstance->classHandle);
                PHDC_ManagerSetState(phdcManagerInstance, IEEE11073_MANAGER_DISCONNECTED);
                phdcManagerInstance->classHandle = NULL;
                usb_echo("\n\rphdc device detached\r\n");
                break;
            default:
                break;
        }
    }

    /* run state */
    switch (phdcManagerInstance->runState)
    {
        case kRunIdle:
            break;

        case kRunSetInterface:
            phdcManagerInstance->runWaitState = kRunWaitSetInterface;
            phdcManagerInstance->runState = kRunIdle;
            if (USB_HostPhdcSetInterface(phdcManagerInstance->classHandle, phdcManagerInstance->interfaceHandle, 0U,
                                         PHDC_ManagerControlCallback, phdcManagerInstance) != kStatus_USB_Success)
            {
                usb_echo("set interface error\r\n");
            }
            break;

        case kRunSetInterfaceDone:
            PHDC_ManagerSetState(param, IEEE11073_MANAGER_CONNECTED_UNASSOCIATED);
            /* Clear received buffer */
            memset((void *)&phdcManagerInstance->recvDataBuffer[0U], 0U, APDU_MAX_BUFFER_SIZE);
            phdcManagerInstance->runWaitState = kRunWaitDataReceived;
            phdcManagerInstance->runState = kRunIdle;
            status = USB_HostPhdcRecv(phdcManagerInstance->classHandle, 0xFEU, phdcManagerInstance->recvDataBuffer,
                                      APDU_MAX_BUFFER_SIZE, PHDC_ManagerBulkInCallback, phdcManagerInstance);
            if (status != kStatus_USB_Success)
            {
                usb_echo("Error in USB_HostPhdcRecv: %x\r\n", status);
            }
            break;
        case kRunDataReceived:
            PHDC_ManagerRecvComplete(param);
            phdcManagerInstance->runWaitState = kRunWaitDataReceived;
            phdcManagerInstance->runState = kRunIdle;
            status = USB_HostPhdcRecv(phdcManagerInstance->classHandle, 0xFEU, phdcManagerInstance->recvDataBuffer,
                                      APDU_MAX_BUFFER_SIZE, PHDC_ManagerBulkInCallback, phdcManagerInstance);
            if (status != kStatus_USB_Success)
            {
                usb_echo("Error in USB_HostPhdcRecv: %x\r\n", status);
            }
            break;

        case kRunPrimeDataReceive:
            phdcManagerInstance->runWaitState = kRunWaitDataReceived;
            phdcManagerInstance->runState = kRunIdle;
            status = USB_HostPhdcRecv(phdcManagerInstance->classHandle, 0xFEU, phdcManagerInstance->recvDataBuffer,
                                      APDU_MAX_BUFFER_SIZE, PHDC_ManagerBulkInCallback, phdcManagerInstance);
            if (status != kStatus_USB_Success)
            {
                usb_echo("Error in USB_HostPhdcRecv: %x\r\n", status);
            }
            break;
        default:
            break;
    }
}

/*!
 * @brief host phdc manager event function.
 *
 * This function should be called in the host callback function.
 *
 * @param deviceHandle           device handle.
 * @param configurationHandle    attached device's configuration descriptor information.
 * @param eventCode              callback event code, please reference to enumeration host_event_t.
 *
 * @retval kStatus_USB_Success              The host is initialized successfully.
 * @retval kStatus_USB_NotSupported         The configuration don't contain phdc device interface.
 */
usb_status_t HOST_PhdcManagerEvent(usb_device_handle deviceHandle,
                                   usb_host_configuration_handle configurationHandle,
                                   uint32_t eventCode)
{
    static usb_host_configuration_handle configHandle = NULL;
    usb_status_t status = kStatus_USB_Success;
    uint8_t id;
    usb_host_configuration_t *configuration;
    uint8_t interfaceIndex;
    usb_host_interface_t *interface;
    uint32_t infoValue;

    switch (eventCode)
    {
        case kUSB_HostEventAttach:
            status = kStatus_USB_NotSupported;
            /* judge whether is configurationHandle supported */
            configuration = (usb_host_configuration_t *)configurationHandle;
            for (interfaceIndex = 0U; interfaceIndex < configuration->interfaceCount; ++interfaceIndex)
            {
                interface = &configuration->interfaceList[interfaceIndex];
                id = interface->interfaceDesc->bInterfaceClass;
                if (id != USB_HOST_PHDC_CLASS_CODE)
                {
                    continue;
                }
                id = interface->interfaceDesc->bInterfaceSubClass;
                if (id != USB_HOST_PHDC_SUBCLASS_CODE)
                {
                    continue;
                }
                id = interface->interfaceDesc->bInterfaceProtocol;
                if (id != USB_HOST_PHDC_PROTOCOL)
                {
                    continue;
                }
                else
                {
                    g_phdcManagerInstance.recvDataBuffer = s_RecvDataBuffer;
                    g_phdcManagerInstance.sendDataBuffer = s_SendDataBuffer;
                    g_phdcManagerInstance.deviceHandle = deviceHandle;
                    g_phdcManagerInstance.interfaceHandle = interface;
                    configHandle = configurationHandle;
                    status = kStatus_USB_Success;
                }
            }
            break;

        case kUSB_HostEventNotSupported:
            break;

        case kUSB_HostEventEnumerationDone:
            if (configHandle == configurationHandle)
            {
                if ((g_phdcManagerInstance.deviceHandle != NULL) && (g_phdcManagerInstance.interfaceHandle != NULL))
                {
                    if (g_phdcManagerInstance.devState == kStatus_DEV_Idle)
                    {
                        g_phdcManagerInstance.devState = kStatus_DEV_Attached;
                        USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDevicePID, &infoValue);
                        usb_echo("phdc device attached:pid=0x%x", infoValue);
                        USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDeviceVID, &infoValue);
                        usb_echo("vid=0x%x ", infoValue);
                        USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDeviceAddress, &infoValue);
                        usb_echo("address=%d\r\n", infoValue);
                    }
                    else
                    {
                        usb_echo("not idle phdc device instance\r\n");
                    }
                }
            }
            break;

        case kUSB_HostEventDetach:
            if (configHandle == configurationHandle)
            {
                configHandle = NULL;
                if (g_phdcManagerInstance.devState != kStatus_DEV_Idle)
                {
                    g_phdcManagerInstance.devState = kStatus_DEV_Detached;
                }
            }
            break;
        default:
            break;
    }
    return status;
}
