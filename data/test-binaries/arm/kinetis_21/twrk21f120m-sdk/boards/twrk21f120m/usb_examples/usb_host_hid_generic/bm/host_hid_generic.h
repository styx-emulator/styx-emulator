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

#ifndef _HOST_HID_GENERIC_H_
#define _HOST_HID_GENERIC_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*! @brief buffer for receiving report descriptor and data */
#define HID_GENERIC_IN_BUFFER_SIZE (100U)
/*! @brief buffer for sending data */
#define HID_GENERIC_OUT_BUFFER_SIZE (8U)

/*! @brief host app device attach/detach status */
typedef enum _usb_host_hid_generic_app_state
{
    kStatus_DEV_Idle = 0, /*!< there is no device attach/detach */
    kStatus_DEV_Attached, /*!< device is attached */
    kStatus_DEV_Detached, /*!< device is detached */
} usb_host_hid_generic_app_state_t;

/*! @brief host app run status */
typedef enum _usb_host_hid_generic_run_state
{
    kRunIdle = 0,                /*!< idle */
    kRunSetInterface,            /*!< execute set interface code */
    kRunWaitSetInterface,        /*!< wait set interface done */
    kRunSetInterfaceDone,        /*!< set interface is done, execute next step */
    kRunWaitSetIdle,             /*!< wait set idle done */
    kRunSetIdleDone,             /*!< set idle is done, execute next step */
    kRunWaitGetReportDescriptor, /*!< wait get report descriptor done */
    kRunGetReportDescriptorDone, /*!< get report descriptor is done, execute next step */
    kRunWaitSetProtocol,         /*!< wait set protocol done */
    kRunSetProtocolDone,         /*!< set protocol is done, execute next step */
    kRunWaitDataReceived,        /*!< wait interrupt in data */
    kRunDataReceived,            /*!< interrupt in data received */
    kRunPrimeDataReceive,        /*!< prime interrupt in receive */
} usb_host_hid_generic_run_state_t;

/*! @brief USB host hid generic instance structure */
typedef struct _usb_host_hid_generic_instance
{
    usb_host_configuration_handle configHandle; /*!< the hid generic's configuration handle */
    usb_device_handle deviceHandle;             /*!< the hid generic's device handle */
    usb_host_class_handle classHandle;          /*!< the hid generic's class handle */
    usb_host_interface_handle interfaceHandle;  /*!< the hid generic's interface handle */
    uint8_t deviceState;                        /*!< device attach/detach status */
    uint8_t prevState;                          /*!< device attach/detach previous status */
    uint8_t runState;                           /*!< hid generic application run status */
    uint8_t
        runWaitState; /*!< hid generic application wait status, go to next run status when the wait status success */
    uint16_t inMaxPacketSize;  /*!< Interrupt in max packet size */
    uint16_t outMaxPacketSize; /*!< Interrupt out max packet size */
    uint8_t *genericInBuffer;
    uint8_t *genericOutBuffer;
    uint16_t sendIndex; /*!< data sending position */
} usb_host_hid_generic_instance_t;

/*******************************************************************************
 * API
 ******************************************************************************/

/*!
* @brief host hid generic task function.
*
* This function implements the host hid generic action, it is used to create task.
*
* @param param   the host hid generic instance pointer.
*/
extern void USB_HostHidGenericTask(void *param);

/*!
 * @brief host hid generic callback function.
 *
 * This function should be called in the host callback function.
 *
 * @param deviceHandle         device handle.
 * @param configurationHandle  attached device's configuration descriptor information.
 * @param eventCode            callback event code, please reference to enumeration host_event_t.
 *
 * @retval kStatus_USB_Success              The host is initialized successfully.
 * @retval kStatus_USB_NotSupported         The configuration don't contain hid generic interface.
 */
extern usb_status_t USB_HostHidGenericEvent(usb_device_handle deviceHandle,
                                            usb_host_configuration_handle configurationHandle,
                                            uint32_t eventCode);

#endif /* _HOST_HID_GENERIC_H_ */
