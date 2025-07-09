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

#ifndef __USB_DEVICE_HID_H__
#define __USB_DEVICE_HID_H__

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief The class code of the HID class */
#define USB_DEVICE_CONFIG_HID_CLASS_CODE (0x03U)

/*! @brief Request code to get report of HID class. */
#define USB_DEVICE_HID_REQUEST_GET_REPORT (0x01U)
#define USB_DEVICE_HID_REQUEST_GET_REPORT_TYPE_INPUT (0x01U)
#define USB_DEVICE_HID_REQUEST_GET_REPORT_TYPE_OUPUT (0x02U)
#define USB_DEVICE_HID_REQUEST_GET_REPORT_TYPE_FEATURE (0x03U)
/*! @brief Request code to get idle of HID class. */
#define USB_DEVICE_HID_REQUEST_GET_IDLE (0x02U)
/*! @brief Request code to get protocol of HID class. */
#define USB_DEVICE_HID_REQUEST_GET_PROTOCOL (0x03U)
/*! @brief Request code to set report of HID class. */
#define USB_DEVICE_HID_REQUEST_SET_REPORT (0x09U)
/*! @brief Request code to set idle of HID class. */
#define USB_DEVICE_HID_REQUEST_SET_IDLE (0x0AU)
/*! @brief Request code to set protocol of HID class. */
#define USB_DEVICE_HID_REQUEST_SET_PROTOCOL (0x0BU)

#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U))
/*! @brief The sequence initiation time for the dcd module. */
#define USB_DEVICE_DCD_SEQ_INIT_TIME (1000U)
/*! @brief The time period to debounce on DP signal. */
#define USB_DEVICE_DCD_DBNC_MSEC (10U)
/*! @brief The time period comparator enabled. */
#define USB_DEVICE_DCD_VDPSRC_ON_MSEC (200U)
/*! @brief The amount of time that the module waits after primary detection before start to secondary detection. */
#define USB_DEVICE_DCD_TIME_WAIT_AFTER_PRI_DETECTION (40U)
/*! @brief The amount of time the module enable the Vdm_src. */
#define USB_DEVICE_DCD_TIME_DM_SRC_ON (10U)

/*! @brief USB DCD charging port type */
typedef enum _usb_device_dcd_port_type
{
    kUSB_DeviceDCDPortTypeNoPort = 0x0U,
    kUSB_DeviceDCDPortTypeSDP,
    kUSB_DeviceDCDPortTypeCDP,
    kUSB_DeviceDCDPortTypeDCP,
} usb_device_dcd_port_type_t;

/*! @brief USB DCD charging detect status */
typedef enum _usb_device_dcd_dev_status
{
    kUSB_DeviceDCDDevStatusVBUSDetect = 0x0U,
    kUSB_DeviceDCDDevStatusDataContactDetect,
    kUSB_DeviceDCDDevStatusChargingPortDetect,
    kUSB_DeviceDCDDevStatusTimeOut,
    kUSB_DeviceDCDDevStatusUnknownType,
    kUSB_DeviceDCDDevStatusDetectFinish,
    kUSB_DeviceDCDDevStatusComplete,
    kUSB_DeviceDCDDevStatusAttached,
    kUSB_DeviceDCDDevStatusDetached,
} usb_device_dcd_dev_status_t;
#endif
/*******************************************************************************
 * API
 ******************************************************************************/

#endif /* __USB_DEVICE_HID_H__ */
