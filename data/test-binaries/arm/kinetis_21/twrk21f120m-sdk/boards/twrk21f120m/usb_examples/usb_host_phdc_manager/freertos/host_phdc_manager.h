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

#ifndef _HOST_PHDC_MANAGER_H_
#define _HOST_PHDC_MANAGER_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief manager state: disconnected */
#define IEEE11073_MANAGER_DISCONNECTED (0x00U)
/*! @brief manager state: unassociated */
#define IEEE11073_MANAGER_CONNECTED_UNASSOCIATED (0x01U)
/*! @brief manager state: waiting configuration */
#define IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_WAITING (0x02U)
/*! @brief manager state: checking configuration */
#define IEEE11073_MANAGER_CONNECTED_ASSOCIATED_CONFIGURING_CHECKING_CONFIG (0x03U)
/*! @brief manager state: operating */
#define IEEE11073_MANAGER_CONNECTED_ASSOCIATED_OPERATING (0x04U)
/*! @brief manager state: disassociating */
#define IEEE11073_MANAGER_DISASSOCIATING (0x05U)

/*! @brief application protocol data unit header size */
#define APDU_HEADER_SIZE (0x04U)
/*! @brief association response header size */
#define ASSOC_RSP_HEADER_SIZE (0x02U)
/*! @brief association abort header size */
#define ASSOC_ABRT_HEADER_SIZE (0x02U)
/*! @brief association release response header size */
#define ASSOC_RLRE_HEADER_SIZE (0x02U)
/*! @brief association release request header size */
#define ASSOC_RLRQ_HEADER_SIZE (0x02U)
/*! @brief association presentation protocol data unit header size */
#define ASSOC_PRST_HEADER_SIZE (0x08U)
/*! @brief any defined header size */
#define ANY_HEADER_SIZE (0x02U)
/*! @brief event report result simple header size */
#define EVT_REPORT_RESULT_SIMPLE_HEADER_SIZE (0x0AU)

/*! @brief Medical device system handle */
#define MDS_HANDLE (0x00U)
/*! @brief Application protocol data unit max buffer size */
#define APDU_MAX_BUFFER_SIZE (0xFFU)
/*! @brief Scan response size */
#define SCAN_RES_SIZE (0x16U)

/*! @brief USB host phdc manager instance structure */
typedef struct _host_phdc_manager_instance
{
    usb_device_handle deviceHandle;            /*!< the phdc manager's device handle */
    usb_host_class_handle classHandle;         /*!< the phdc manager's class handle */
    usb_host_interface_handle interfaceHandle; /*!< the phdc manager's interface handle */
    uint8_t devState;                          /*!< device attach/detach status */
    uint8_t prevState;                         /*!< device attach/detach previous status */
    uint8_t runState;                          /*!< phdc manager application run status */
    uint8_t
        runWaitState; /*!< phdc manager application wait status, go to next run status when the wait status success */
    uint8_t managerState;                           /*!< the phdc manager's state */
    associate_result_t assocResult;                 /*!< association response result */
    config_result_t configResult;                   /*!< configuration response result */
    invoke_id_type_t invokeId;                      /*!< invoke ID number */
    uint8_t configObjectList[APDU_MAX_BUFFER_SIZE]; /*!< configuration object list */
    uint8_t *sendDataBuffer;                        /*!< use to send application protocol data unit */
    uint8_t *recvDataBuffer;                        /*!< use to receive application protocol data unit */
} host_phdc_manager_instance_t;

/*! @brief host app device attach/detach status */
typedef enum _host_phdc_manager_app_state
{
    kStatus_DEV_Idle = 0U, /*!< there is no device attach/detach */
    kStatus_DEV_Attached,  /*!< device is attached */
    kStatus_DEV_Detached,  /*!< device is detached */
} host_phdc_manager_app_state_t;

/*! @brief host app run status */
typedef enum _host_phdc_manager_run_state
{
    kRunIdle = 0U,        /*!< idle */
    kRunSetInterface,     /*!< execute set interface code */
    kRunWaitSetInterface, /*!< wait set interface done */
    kRunSetInterfaceDone, /*!< set interface is done, execute next step */
    kRunWaitDataReceived, /*!< wait interrupt in or bulk in data */
    kRunDataReceived,     /*!< interrupt in or bulk in data received */
    kRunPrimeDataReceive, /*!< prime interrupt in or bulk in receive */
} host_phdc_manager_run_state_t;

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*! @brief USB host phdc manager instance global variable */
extern host_phdc_manager_instance_t g_phdcManagerInstance;

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif
/*!
* @brief host phdc manager task function.
*
* This function implements the host phdc manager action, it is used to create task.
*
* @param param   the host phdc manager instance pointer.
*/
extern void HOST_PhdcManagerTask(void *param);

/*!
 * @brief host phdc manager callback function.
 *
 * This function should be called in the host callback function.
 *
 * @param deviceHandle           device handle.
 * @param configurationHandle    attached device's configuration descriptor information.
 * @param eventCode              callback event code, please reference to enumeration host_event_t.
 *
 * @retval kStatus_USB_Success              The host is initialized successfully.
 * @retval kStatus_USB_NotSupported         The configuration don't contain hid mouse interface.
 */
extern usb_status_t HOST_PhdcManagerEvent(usb_device_handle deviceHandle,
                                          usb_host_configuration_handle configurationHandle,
                                          uint32_t eventCode);

#if defined(__cplusplus)
}
#endif
#endif /* _HOST_PHDC_MANAGER_H_ */
