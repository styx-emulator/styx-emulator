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

#ifndef _HOST_MSD_FATFS_H_
#define _HOST_MSD_FATFS_H_

#include "usb_host.h"
#include "usb_host_msd.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief 0 - execute normal fatfs test code; 1 - execute throughput test code */
#define MSD_FATFS_THROUGHPUT_TEST_ENABLE (0U)

/*! @brief host app device attach/detach status */
typedef enum _usb_host_msd_app_state
{
    kStatus_DEV_Idle = 0, /*!< there is no device attach/detach */
    kStatus_DEV_Attached, /*!< device is attached */
    kStatus_DEV_Detached, /*!< device is detached */
} usb_host_msd_app_state_t;

/*! @brief host app run status */
typedef enum _usb_host_msd_run_state
{
    kRunIdle = 0,         /*!< idle */
    kRunSetInterface,     /*!< execute set interface code */
    kRunWaitSetInterface, /*!< wait set interface done */
    kRunMassStorageTest   /*!< execute mass storage test code */
} usb_host_msd_run_state_t;

/*! @brief USB host msd fatfs instance structure */
typedef struct _usb_host_msd_fatfs_instance
{
    usb_host_configuration_handle configHandle; /*!< configuration handle */
    usb_device_handle deviceHandle;             /*!< device handle */
    usb_host_class_handle classHandle;          /*!< class handle */
    usb_host_interface_handle interfaceHandle;  /*!< interface handle */
    uint8_t prevDeviceState;                    /*!< device attach/detach previous status */
    uint8_t deviceState;                        /*!< device attach/detach status */
    uint8_t runWaitState; /*!< application wait status, go to next run status when the wait status success */
    uint8_t runState;     /*!< application run status */
} usb_host_msd_fatfs_instance_t;

/*******************************************************************************
 * API
 ******************************************************************************/

/*!
 * @brief host msd callback function.
 *
 * This function should be called in the host callback function.
 *
 * @param deviceHandle           device handle.
 * @param configurationHandle attached device's configuration descriptor information.
 * @param eventCode           callback event code, please reference to enumeration host_event_t.
 *
 * @retval kStatus_USB_Success              The host is initialized successfully.
 * @retval kStatus_USB_NotSupported         The configuration don't contain msd interface.
 * @retval kStatus_USB_Error                There is no idle msd instance.
 */
extern usb_status_t USB_HostMsdEvent(usb_device_handle deviceHandle,
                                     usb_host_configuration_handle configurationHandle,
                                     uint32_t eventCode);

/*!
* @brief host msd fatfs task function.
*
* This function implements the host msd fatfs action, it is used to create task.
*
* @param arg   the host msd fatfs instance pointer.
*/
extern void USB_HostMsdTask(void *arg);

#endif /* _HOST_MSD_FATFS_H_ */
