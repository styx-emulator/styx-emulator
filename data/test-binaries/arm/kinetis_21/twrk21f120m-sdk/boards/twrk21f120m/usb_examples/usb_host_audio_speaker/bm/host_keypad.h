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

#ifndef __HOST_KEYPAD_H__
#define __HOST_KEYPAD_H__

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define HID_BUFFER_SIZE 100
/*! @brief host app device attach/detach status */
typedef enum _host_keypad_app_state
{
    kStatus_DEV_Idle = 0, /*!< there is no device attach/detach */
    kStatus_DEV_Attached, /*!< device is attached */
    kStatus_DEV_Detached, /*!< device is detached */
} host_keypad_app_state_t;

/*! @brief host app run status */
typedef enum _host_keypad_run_state
{
    kRunIdle = 0,         /*!< idle */
    kRunSetInterface,     /*!< execute set interface code */
    kRunWaitSetInterface, /*!< wait set interface done */
    kRunSetInterfaceDone, /*!< set interface is done, execute next step */
    kRunWaitDataReceived, /*!< wait interrupt in data */
    kRunDataReceived,     /*!< interrupt in data received */
    kRunPrimeDataReceive, /*!< prime interrupt in receive */
} host_keypad_run_state_t;

/*! @brief USB host keypad instance structure */
typedef struct _host_keypad_instance
{
    usb_device_handle deviceHandle;            /*!< the keypad's device handle */
    usb_host_class_handle classHandle;         /*!< the keypad's class handle */
    usb_host_interface_handle interfaceHandle; /*!< the keypad's interface handle */
    uint8_t devState;                          /*!< device attach/detach status */
    uint8_t prevState;                         /*!< device attach/detach previous status */
    uint8_t runState;                          /*!< keypad application run status */
    uint8_t runWaitState;   /*!< keypad application wait status, go to next run status when the wait status success */
    uint16_t maxPacketSize; /*!< Interrupt in max packet size */
    uint8_t *keypadBuffer;  /*!< use to receive report descriptor and data */
} host_keypad_instance_t;

/*******************************************************************************
 * API
 ******************************************************************************/
extern void USB_KeypadTask(void *arg);

extern usb_status_t USB_HostKeypadEvent(usb_device_handle deviceHandle,
                                        usb_host_configuration_handle configurationHandle,
                                        uint32_t eventCode);

#endif /* __HOST_KEYPAD_H__ */
