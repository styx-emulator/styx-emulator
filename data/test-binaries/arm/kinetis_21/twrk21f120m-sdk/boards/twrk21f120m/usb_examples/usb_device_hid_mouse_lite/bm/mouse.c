/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 - 2017 NXP
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
#include "usb_device.h"

#include "usb_device_hid.h"

#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"

#include "mouse.h"

#include "fsl_device_registers.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"

#include <stdio.h>
#include <stdlib.h>
#if (defined(FSL_FEATURE_SOC_SYSMPU_COUNT) && (FSL_FEATURE_SOC_SYSMPU_COUNT > 0U))
#include "fsl_sysmpu.h"
#endif /* FSL_FEATURE_SOC_SYSMPU_COUNT */

#if defined(USB_DEVICE_CONFIG_EHCI) && (USB_DEVICE_CONFIG_EHCI > 0U)
#include "usb_phy.h"
#endif

#include "fsl_common.h"
#include "pin_mux.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
void BOARD_InitHardware(void);
void USB_DeviceClockInit(void);
void USB_DeviceIsrEnable(void);
#if USB_DEVICE_CONFIG_USE_TASK
void USB_DeviceTaskFn(void *deviceHandle);
#endif

static usb_status_t USB_DeviceHidMouseAction(void);
static usb_status_t USB_DeviceHidInterruptIn(usb_device_handle deviceHandle,
                                             usb_device_endpoint_callback_message_struct_t *event,
                                             void *arg);
static void USB_DeviceApplicationInit(void);

/*******************************************************************************
 * Variables
 ******************************************************************************/

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_MouseBuffer[USB_HID_MOUSE_REPORT_LENGTH];
usb_hid_mouse_struct_t g_UsbDeviceHidMouse;

extern uint8_t g_UsbDeviceCurrentConfigure;
extern uint8_t g_UsbDeviceInterface[USB_HID_MOUSE_INTERFACE_COUNT];

#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    ((defined(FSL_FEATURE_SOC_USBDCD_COUNT) && (FSL_FEATURE_SOC_USBDCD_COUNT > 0U)) ||        \
     (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)))
usb_device_dcd_charging_time_t g_UsbDeviceDcdTimingConfig;
#endif

/*******************************************************************************
 * Code
 ******************************************************************************/
#if (defined(USB_DEVICE_CONFIG_KHCI) && (USB_DEVICE_CONFIG_KHCI > 0U))
void USB0_IRQHandler(void)
{
    USB_DeviceKhciIsrFunction(g_UsbDeviceHidMouse.deviceHandle);
    /* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate overlapping
    exception return operation might vector to incorrect interrupt */
    __DSB();
}
#endif
void USB_DeviceClockInit(void)
{
#if defined(USB_DEVICE_CONFIG_KHCI) && (USB_DEVICE_CONFIG_KHCI > 0U)
    SystemCoreClockUpdate();
    CLOCK_EnableUsbfs0Clock(kCLOCK_UsbSrcPll0, CLOCK_GetFreq(kCLOCK_PllFllSelClk));
/*
 * If the SOC has USB KHCI dedicated RAM, the RAM memory needs to be clear after
 * the KHCI clock is enabled. When the demo uses USB EHCI IP, the USB KHCI dedicated
 * RAM can not be used and the memory can't be accessed.
 */
#if (defined(FSL_FEATURE_USB_KHCI_USB_RAM) && (FSL_FEATURE_USB_KHCI_USB_RAM > 0U))
#if (defined(FSL_FEATURE_USB_KHCI_USB_RAM_BASE_ADDRESS) && (FSL_FEATURE_USB_KHCI_USB_RAM_BASE_ADDRESS > 0U))
    for (int i = 0; i < FSL_FEATURE_USB_KHCI_USB_RAM; i++)
    {
        ((uint8_t *)FSL_FEATURE_USB_KHCI_USB_RAM_BASE_ADDRESS)[i] = 0x00U;
    }
#endif /* FSL_FEATURE_USB_KHCI_USB_RAM_BASE_ADDRESS */
#endif /* FSL_FEATURE_USB_KHCI_USB_RAM */
#endif
}
void USB_DeviceIsrEnable(void)
{
    uint8_t irqNumber;
#if defined(USB_DEVICE_CONFIG_KHCI) && (USB_DEVICE_CONFIG_KHCI > 0U)
    uint8_t usbDeviceKhciIrq[] = USB_IRQS;
    irqNumber = usbDeviceKhciIrq[CONTROLLER_ID - kUSB_ControllerKhci0];
#endif
/* Install isr, set priority, and enable IRQ. */
#if defined(__GIC_PRIO_BITS)
    GIC_SetPriority((IRQn_Type)irqNumber, USB_DEVICE_INTERRUPT_PRIORITY);
#else
    NVIC_SetPriority((IRQn_Type)irqNumber, USB_DEVICE_INTERRUPT_PRIORITY);
#endif
    EnableIRQ((IRQn_Type)irqNumber);
}
#if USB_DEVICE_CONFIG_USE_TASK
void USB_DeviceTaskFn(void *deviceHandle)
{
#if defined(USB_DEVICE_CONFIG_KHCI) && (USB_DEVICE_CONFIG_KHCI > 0U)
    USB_DeviceKhciTaskFunction(deviceHandle);
#endif
}
#endif

/* Update mouse pointer location. Draw a rectangular rotation*/
static usb_status_t USB_DeviceHidMouseAction(void)
{
    static int8_t x = 0U;
    static int8_t y = 0U;
    enum
    {
        RIGHT,
        DOWN,
        LEFT,
        UP
    };
    static uint8_t dir = RIGHT;

    switch (dir)
    {
        case RIGHT:
            /* Move right. Increase X value. */
            g_UsbDeviceHidMouse.buffer[1] = 2U;
            g_UsbDeviceHidMouse.buffer[2] = 0U;
            x++;
            if (x > 99U)
            {
                dir++;
            }
            break;
        case DOWN:
            /* Move down. Increase Y value. */
            g_UsbDeviceHidMouse.buffer[1] = 0U;
            g_UsbDeviceHidMouse.buffer[2] = 2U;
            y++;
            if (y > 99U)
            {
                dir++;
            }
            break;
        case LEFT:
            /* Move left. Discrease X value. */
            g_UsbDeviceHidMouse.buffer[1] = (uint8_t)(-2);
            g_UsbDeviceHidMouse.buffer[2] = 0U;
            x--;
            if (x < 2U)
            {
                dir++;
            }
            break;
        case UP:
            /* Move up. Discrease Y value. */
            g_UsbDeviceHidMouse.buffer[1] = 0U;
            g_UsbDeviceHidMouse.buffer[2] = (uint8_t)(-2);
            y--;
            if (y < 2U)
            {
                dir = RIGHT;
            }
            break;
        default:
            break;
    }
    /* Send mouse report to the host */
    return USB_DeviceSendRequest(g_UsbDeviceHidMouse.deviceHandle, USB_HID_MOUSE_ENDPOINT_IN,
                                 g_UsbDeviceHidMouse.buffer, USB_HID_MOUSE_REPORT_LENGTH);
}

/* HID mouse interrupt IN pipe callback */
static usb_status_t USB_DeviceHidInterruptIn(usb_device_handle deviceHandle,
                                             usb_device_endpoint_callback_message_struct_t *event,
                                             void *arg)
{
    /* Resport sent */
    if (g_UsbDeviceHidMouse.attach)
    {
        if ((NULL != event) && (event->length == USB_UNINITIALIZED_VAL_32))
        {
            return kStatus_USB_Error;
        }
        return USB_DeviceHidMouseAction();
    }

    return kStatus_USB_Error;
}

usb_status_t USB_DeviceCallback(usb_device_handle handle, uint32_t event, void *param)
{
    usb_status_t error = kStatus_USB_Success;
    uint8_t *temp8 = (uint8_t *)param;

    switch (event)
    {
        case kUSB_DeviceEventBusReset:
        {
            /* USB bus reset signal detected */
            /* Initialize the control IN and OUT pipes */
            USB_DeviceControlPipeInit(g_UsbDeviceHidMouse.deviceHandle);
            g_UsbDeviceHidMouse.attach = 0U;
#if (defined(USB_DEVICE_CONFIG_EHCI) && (USB_DEVICE_CONFIG_EHCI > 0U)) || \
    (defined(USB_DEVICE_CONFIG_LPCIP3511HS) && (USB_DEVICE_CONFIG_LPCIP3511HS > 0U))
            /* Get USB speed to configure the device, including max packet size and interval of the endpoints. */
            if (kStatus_USB_Success == USB_DeviceGetStatus(g_UsbDeviceHidMouse.deviceHandle, kUSB_DeviceStatusSpeed,
                                                           &g_UsbDeviceHidMouse.speed))
            {
                USB_DeviceSetSpeed(g_UsbDeviceHidMouse.speed);
            }
#endif
        }
        break;
#if (defined(USB_DEVICE_CONFIG_DETACH_ENABLE) && (USB_DEVICE_CONFIG_DETACH_ENABLE > 0U))
        case kUSB_DeviceEventAttach:
        {
#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    ((defined(FSL_FEATURE_SOC_USBDCD_COUNT) && (FSL_FEATURE_SOC_USBDCD_COUNT > 0U)) ||        \
     (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)))
            g_UsbDeviceHidMouse.vReginInterruptDetected = 1;
            g_UsbDeviceHidMouse.vbusValid = 1;
#else
            usb_echo("USB device attached.\r\n");
            USB_DeviceRun(g_UsbDeviceHidMouse.deviceHandle);
#endif
        }
        break;
        case kUSB_DeviceEventDetach:
        {
#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    ((defined(FSL_FEATURE_SOC_USBDCD_COUNT) && (FSL_FEATURE_SOC_USBDCD_COUNT > 0U)) ||        \
     (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)))
            g_UsbDeviceHidMouse.vReginInterruptDetected = 1;
            g_UsbDeviceHidMouse.vbusValid = 0;
            g_UsbDeviceHidMouse.attach = 0;
#else
            usb_echo("USB device detached.\r\n");
            g_UsbDeviceHidMouse.attach = 0;
            USB_DeviceStop(g_UsbDeviceHidMouse.deviceHandle);
#endif
        }
        break;
#endif
        case kUSB_DeviceEventSetConfiguration:
            if (USB_HID_MOUSE_CONFIGURE_INDEX == (*temp8))
            {
                /* If the confguration is valid, initliaze the HID mouse interrupt IN pipe */
                usb_device_endpoint_init_struct_t epInitStruct;
                usb_device_endpoint_callback_struct_t epCallback;

                epCallback.callbackFn = USB_DeviceHidInterruptIn;
                epCallback.callbackParam = handle;

                epInitStruct.zlt = 0U;
                epInitStruct.transferType = USB_ENDPOINT_INTERRUPT;
                epInitStruct.endpointAddress =
                    USB_HID_MOUSE_ENDPOINT_IN | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
                if (USB_SPEED_HIGH == g_UsbDeviceHidMouse.speed)
                {
                    epInitStruct.maxPacketSize = HS_HID_MOUSE_INTERRUPT_IN_PACKET_SIZE;
                }
                else
                {
                    epInitStruct.maxPacketSize = FS_HID_MOUSE_INTERRUPT_IN_PACKET_SIZE;
                }

                USB_DeviceInitEndpoint(g_UsbDeviceHidMouse.deviceHandle, &epInitStruct, &epCallback);

                g_UsbDeviceHidMouse.attach = 1U;
                error = USB_DeviceHidMouseAction(); /* run the cursor movement code */
            }
            break;
#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    ((defined(FSL_FEATURE_SOC_USBDCD_COUNT) && (FSL_FEATURE_SOC_USBDCD_COUNT > 0U)) ||        \
     (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)))
        case kUSB_DeviceEventDcdTimeOut:
            if (g_UsbDeviceHidMouse.dcdDevStatus == kUSB_DeviceDCDDevStatusVBUSDetect)
            {
                g_UsbDeviceHidMouse.dcdDevStatus = kUSB_DeviceDCDDevStatusTimeOut;
            }
            break;
        case kUSB_DeviceEventDcdUnknownType:
            if (g_UsbDeviceHidMouse.dcdDevStatus == kUSB_DeviceDCDDevStatusVBUSDetect)
            {
                g_UsbDeviceHidMouse.dcdDevStatus = kUSB_DeviceDCDDevStatusUnknownType;
            }
            break;
        case kUSB_DeviceEventSDPDetected:
            if (g_UsbDeviceHidMouse.dcdDevStatus == kUSB_DeviceDCDDevStatusVBUSDetect)
            {
                g_UsbDeviceHidMouse.dcdPortType = kUSB_DeviceDCDPortTypeSDP;
                g_UsbDeviceHidMouse.dcdDevStatus = kUSB_DeviceDCDDevStatusDetectFinish;
            }
            break;
        case kUSB_DeviceEventChargingPortDetected:
            if (g_UsbDeviceHidMouse.dcdDevStatus == kUSB_DeviceDCDDevStatusVBUSDetect)
            {
                g_UsbDeviceHidMouse.dcdDevStatus = kUSB_DeviceDCDDevStatusChargingPortDetect;
            }
            break;
        case kUSB_DeviceEventChargingHostDetected:
            if (g_UsbDeviceHidMouse.dcdDevStatus == kUSB_DeviceDCDDevStatusVBUSDetect)
            {
                g_UsbDeviceHidMouse.dcdDevStatus = kUSB_DeviceDCDDevStatusDetectFinish;
                g_UsbDeviceHidMouse.dcdPortType = kUSB_DeviceDCDPortTypeCDP;
            }
            break;
        case kUSB_DeviceEventDedicatedChargerDetected:
            if (g_UsbDeviceHidMouse.dcdDevStatus == kUSB_DeviceDCDDevStatusVBUSDetect)
            {
                g_UsbDeviceHidMouse.dcdDevStatus = kUSB_DeviceDCDDevStatusDetectFinish;
                g_UsbDeviceHidMouse.dcdPortType = kUSB_DeviceDCDPortTypeDCP;
            }
            break;
#endif
        default:
            break;
    }

    return error;
}

/* Get setup buffer */
usb_status_t USB_DeviceGetSetupBuffer(usb_device_handle handle, usb_setup_struct_t **setupBuffer)
{
    /* Keep the setup is 4-byte aligned */
    static uint32_t hid_mouse_setup[2];
    if (NULL == setupBuffer)
    {
        return kStatus_USB_InvalidParameter;
    }
    *setupBuffer = (usb_setup_struct_t *)&hid_mouse_setup;
    return kStatus_USB_Success;
}

/* Configure device remote wakeup */
usb_status_t USB_DeviceConfigureRemoteWakeup(usb_device_handle handle, uint8_t enable)
{
    return kStatus_USB_InvalidRequest;
}

/* Configure the endpoint status (idle or stall) */
usb_status_t USB_DeviceConfigureEndpointStatus(usb_device_handle handle, uint8_t ep, uint8_t status)
{
    if (status)
    {
        if ((USB_HID_MOUSE_ENDPOINT_IN == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
            (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            return USB_DeviceStallEndpoint(handle, ep);
        }
        else
        {
        }
    }
    else
    {
        if ((USB_HID_MOUSE_ENDPOINT_IN == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
            (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            return USB_DeviceUnstallEndpoint(handle, ep);
        }
        else
        {
        }
    }
    return kStatus_USB_InvalidRequest;
}

/* Get class-specific request buffer */
usb_status_t USB_DeviceGetClassReceiveBuffer(usb_device_handle handle,
                                             usb_setup_struct_t *setup,
                                             uint32_t *length,
                                             uint8_t **buffer)
{
    static uint8_t setupOut[8];
    if ((NULL == buffer) || ((*length) > sizeof(setupOut)))
    {
        return kStatus_USB_InvalidRequest;
    }
    *buffer = setupOut;
    return kStatus_USB_Success;
}

/* Handle class-specific request */
usb_status_t USB_DeviceProcessClassRequest(usb_device_handle handle,
                                           usb_setup_struct_t *setup,
                                           uint32_t *length,
                                           uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;

    if (setup->wIndex != USB_HID_MOUSE_INTERFACE_INDEX)
    {
        return error;
    }

    switch (setup->bRequest)
    {
        case USB_DEVICE_HID_REQUEST_GET_REPORT:
            break;
        case USB_DEVICE_HID_REQUEST_GET_IDLE:
            break;
        case USB_DEVICE_HID_REQUEST_GET_PROTOCOL:
            break;
        case USB_DEVICE_HID_REQUEST_SET_REPORT:
            break;
        case USB_DEVICE_HID_REQUEST_SET_IDLE:
            break;
        case USB_DEVICE_HID_REQUEST_SET_PROTOCOL:
            break;
        default:
            break;
    }

    return error;
}

static void USB_DeviceApplicationInit(void)
{
    USB_DeviceClockInit();
#if (defined(FSL_FEATURE_SOC_SYSMPU_COUNT) && (FSL_FEATURE_SOC_SYSMPU_COUNT > 0U))
    SYSMPU_Enable(SYSMPU, 0);
#endif /* FSL_FEATURE_SOC_SYSMPU_COUNT */

    /* Set HID mouse default state */
    g_UsbDeviceHidMouse.speed = USB_SPEED_FULL;
    g_UsbDeviceHidMouse.attach = 0U;
    g_UsbDeviceHidMouse.deviceHandle = NULL;
    g_UsbDeviceHidMouse.buffer = s_MouseBuffer;

#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    ((defined(FSL_FEATURE_SOC_USBDCD_COUNT) && (FSL_FEATURE_SOC_USBDCD_COUNT > 0U)) ||        \
     (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)))
    g_UsbDeviceHidMouse.dcdDevStatus = kUSB_DeviceDCDDevStatusDetached;

    g_UsbDeviceDcdTimingConfig.dcdSeqInitTime = USB_DEVICE_DCD_SEQ_INIT_TIME;
    g_UsbDeviceDcdTimingConfig.dcdDbncTime = USB_DEVICE_DCD_DBNC_MSEC;
    g_UsbDeviceDcdTimingConfig.dcdDpSrcOnTime = USB_DEVICE_DCD_VDPSRC_ON_MSEC;
    g_UsbDeviceDcdTimingConfig.dcdTimeWaitAfterPrD = USB_DEVICE_DCD_TIME_WAIT_AFTER_PRI_DETECTION;
    g_UsbDeviceDcdTimingConfig.dcdTimeDMSrcOn = USB_DEVICE_DCD_TIME_DM_SRC_ON;
#endif

    /* Initialize the usb stack and class drivers */
    if (kStatus_USB_Success != USB_DeviceInit(CONTROLLER_ID, USB_DeviceCallback, &g_UsbDeviceHidMouse.deviceHandle))
    {
        usb_echo("USB device mouse failed\r\n");
        return;
    }
    else
    {
#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    ((defined(FSL_FEATURE_SOC_USBDCD_COUNT) && (FSL_FEATURE_SOC_USBDCD_COUNT > 0U)) ||        \
     (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)))
        usb_echo("USB device DCD + HID mouse demo\r\n");
#else
        usb_echo("USB device HID mouse demo\r\n");
#endif
    }

    USB_DeviceIsrEnable();

#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    ((defined(FSL_FEATURE_SOC_USBDCD_COUNT) && (FSL_FEATURE_SOC_USBDCD_COUNT > 0U)) ||        \
     (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)))
#else
    /* Start USB device HID mouse */
    USB_DeviceRun(g_UsbDeviceHidMouse.deviceHandle);
#endif
}

/*!
 * @brief Application task function.
 *
 * This function runs the task for application.
 *
 * @return None.
 */
#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    ((defined(FSL_FEATURE_SOC_USBDCD_COUNT) && (FSL_FEATURE_SOC_USBDCD_COUNT > 0U)) ||        \
     (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)))
void USB_DeviceAppTask(void *parameter)
{
    usb_hid_mouse_struct_t *usbDeviceHidDcd = (usb_hid_mouse_struct_t *)parameter;

    if (usbDeviceHidDcd->vReginInterruptDetected)
    {
        usbDeviceHidDcd->vReginInterruptDetected = 0;
        if (usbDeviceHidDcd->vbusValid)
        {
            usb_echo("USB device attached.\r\n");
            USB_DeviceDcdInitModule(usbDeviceHidDcd->deviceHandle, &g_UsbDeviceDcdTimingConfig);
            usbDeviceHidDcd->dcdDevStatus = kUSB_DeviceDCDDevStatusVBUSDetect;
        }
        else
        {
            usb_echo("USB device detached.\r\n");
            USB_DeviceDcdDeinitModule(usbDeviceHidDcd->deviceHandle);
            USB_DeviceStop(usbDeviceHidDcd->deviceHandle);
            usbDeviceHidDcd->dcdPortType = kUSB_DeviceDCDPortTypeNoPort;
            usbDeviceHidDcd->dcdDevStatus = kUSB_DeviceDCDDevStatusDetached;
        }
    }

    if (usbDeviceHidDcd->dcdDevStatus == kUSB_DeviceDCDDevStatusChargingPortDetect) /* This is only for BC1.1 */
    {
        USB_DeviceRun(usbDeviceHidDcd->deviceHandle);
    }
    if (usbDeviceHidDcd->dcdDevStatus == kUSB_DeviceDCDDevStatusTimeOut)
    {
        usb_echo("Timeout error.\r\n");
        usbDeviceHidDcd->dcdDevStatus = kUSB_DeviceDCDDevStatusComplete;
    }
    if (usbDeviceHidDcd->dcdDevStatus == kUSB_DeviceDCDDevStatusUnknownType)
    {
        usb_echo("Unknown port type.\r\n");
        usbDeviceHidDcd->dcdDevStatus = kUSB_DeviceDCDDevStatusComplete;
    }
    if (usbDeviceHidDcd->dcdDevStatus == kUSB_DeviceDCDDevStatusDetectFinish)
    {
        if (usbDeviceHidDcd->dcdPortType == kUSB_DeviceDCDPortTypeSDP)
        {
            usb_echo("The device has been connected to a facility which is SDP(Standard Downstream Port).\r\n");
            USB_DeviceRun(usbDeviceHidDcd->deviceHandle); /* If the facility attached is SDP, start enumeration */
        }
        else if (usbDeviceHidDcd->dcdPortType == kUSB_DeviceDCDPortTypeCDP)
        {
            usb_echo("The device has been connected to a facility which is CDP(Charging Downstream Port).\r\n");
            USB_DeviceRun(usbDeviceHidDcd->deviceHandle); /* If the facility attached is CDP, start enumeration */
        }
        else if (usbDeviceHidDcd->dcdPortType == kUSB_DeviceDCDPortTypeDCP)
        {
            usb_echo("The device has been connected to a facility which is DCP(Dedicated Charging Port).\r\n");
        }
        usbDeviceHidDcd->dcdDevStatus = kUSB_DeviceDCDDevStatusComplete;
    }
}
#endif

#if defined(__CC_ARM) || defined(__GNUC__)
int main(void)
#else
void main(void)
#endif
{
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    USB_DeviceApplicationInit();

    while (1U)
    {
#if USB_DEVICE_CONFIG_USE_TASK
        USB_DeviceTaskFn(g_UsbDeviceHidMouse.deviceHandle);
#endif
#if (defined(USB_DEVICE_CHARGER_DETECT_ENABLE) && (USB_DEVICE_CHARGER_DETECT_ENABLE > 0U)) && \
    ((defined(FSL_FEATURE_SOC_USBDCD_COUNT) && (FSL_FEATURE_SOC_USBDCD_COUNT > 0U)) ||        \
     (defined(FSL_FEATURE_SOC_USBHSDCD_COUNT) && (FSL_FEATURE_SOC_USBHSDCD_COUNT > 0U)))
        USB_DeviceAppTask(&g_UsbDeviceHidMouse);
#endif
    }
}
