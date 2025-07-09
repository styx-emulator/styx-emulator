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

#ifndef _HOST_KEYBOARD_MOUSE_H_
#define _HOST_KEYBOARD_MOUSE_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief buffer for receiving report descriptor and data */
#define HID_BUFFER_SIZE (200U)

/*! @brief host app device attach/detach status */
typedef enum _usb_host_hid_app_state
{
    kStatus_DEV_Idle = 0, /*!< there is no device attach/detach */
    kStatus_DEV_Attached, /*!< device is attached */
    kStatus_DEV_Detached, /*!< device is detached */
} usb_host_hid_app_state_t;

/*! @brief host app run status */
typedef enum _usb_host_hid_run_state
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
} usb_host_hid_run_state_t;

/*******************************************************************************
 * API
 ******************************************************************************/

#endif /* _HOST_KEYBOARD_MOUSE_H_ */
