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
#include "usb_host_hid.h"
#include "host_keyboard_mouse.h"
#include "host_keyboard.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define KEYBOARD_USAGE_ID_NUMBER (57U)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*!
 * @brief print key to uart.
 *
 * @param key   key value.
 * @param shift 1 - shift is pressed; 0 - shift is not pressed.
 */
static void USB_HostKeyboardPrintKey(uint8_t key, uint8_t shift);

/*!
 * @brief process hid data and print keyboard action.
 *
 * @param buffer   hid data buffer.
 */
static void USB_HostKeyboardProcessBuffer(usb_host_keyboard_instance_t *keyboardInstance);

/*!
 * @brief host keyboard interrupt in transfer callback.
 *
 * This function is used as callback function when call USB_HostHidRecv .
 *
 * @param param    the host keyboard instance pointer.
 * @param data     data buffer pointer.
 * @param dataLength data length.
 * @status         transfer result status.
 */
static void USB_HostHidInCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status);

/*******************************************************************************
 * Variables
 ******************************************************************************/

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_KeyboardBuffer[HID_BUFFER_SIZE]; /*!< use to receive report descriptor and data */
usb_host_keyboard_instance_t g_HostHidKeyboard;

/* keyboard key values */
static const uint8_t g_HostKeyboardTable[KEYBOARD_USAGE_ID_NUMBER][2] = {
    {0, 0},       /* 0 */
    {0, 0},       /* 1 */
    {0, 0},       /* 2 */
    {0, 0},       /* 3 */
    {'a', 'A'},   /* 4 */
    {'b', 'B'},   /* 5 */
    {'c', 'C'},   /* 6 */
    {'d', 'D'},   /* 7 */
    {'e', 'E'},   /* 8 */
    {'f', 'F'},   /* 9 */
    {'g', 'G'},   /* 10 */
    {'h', 'H'},   /* 11 */
    {'i', 'I'},   /* 12 */
    {'j', 'J'},   /* 13 */
    {'k', 'K'},   /* 14 */
    {'l', 'L'},   /* 15 */
    {'m', 'M'},   /* 16 */
    {'n', 'N'},   /* 17 */
    {'o', 'O'},   /* 18 */
    {'p', 'P'},   /* 19 */
    {'q', 'Q'},   /* 20 */
    {'r', 'R'},   /* 21 */
    {'s', 'S'},   /* 22 */
    {'t', 'T'},   /* 23 */
    {'u', 'U'},   /* 24 */
    {'v', 'V'},   /* 25 */
    {'w', 'W'},   /* 26 */
    {'x', 'X'},   /* 27 */
    {'y', 'Y'},   /* 28 */
    {'z', 'Z'},   /* 29 */
    {'1', '!'},   /* 30 */
    {'2', '@'},   /* 31 */
    {'3', '#'},   /* 32 */
    {'4', '$'},   /* 33 */
    {'5', '%'},   /* 34 */
    {'6', '^'},   /* 35 */
    {'7', '&'},   /* 36 */
    {'8', '*'},   /* 37 */
    {'9', '('},   /* 38 */
    {'0', ')'},   /* 39 */
    {'\n', '\n'}, /* 40 */
    {0x1B, 0x1B}, /* 41 ESC */
    {'\b', '\b'}, /* 42 BACKSPACE */
    {'\t', '\t'}, /* 43 TAB */
    {' ', ' '},   /* 44 */
    {'-', '_'},   /* 45 */
    {'=', '+'},   /* 46 */
    {'[', '{'},   /* 47 */
    {']', '}'},   /* 48 */
    {'\\', '|'},  /* 49 */
    {0, 0},       /* 50 */
    {';', ':'},   /* 51 */
    {'\'', '\"'}, /* 52 */
    {'`', '~'},   /* 53 */
    {',', '<'},   /* 54 */
    {'.', '>'},   /* 55 */
    {'/', '?'},   /* 56 */
};

/*******************************************************************************
 * Code
 ******************************************************************************/
/*Host hid example doesn't support HID report descriptor analysis, this example assume that the received data are sent
 * by specific order. */
static void USB_HostKeyboardPrintKey(uint8_t key, uint8_t shift)
{
    if (key == 0x4B)
    {
        usb_echo("page_up"); /* for supporting usb device hid keyboard example */
    }
    else if (key == 0x4E)
    {
        usb_echo("page_down"); /* for supporting usb device hid keyboard example */
    }
    else if (key <= 56)
    {
        usb_echo("%c", g_HostKeyboardTable[key][shift]);
    }
    else
    {
        ; /* this simple keyboard example don't support the key */
    }
}

static void USB_HostKeyboardProcessBuffer(usb_host_keyboard_instance_t *keyboardInstance)
{
    uint8_t currentIndex, longIndex;
    uint8_t key;

    /* if all packet data is same the packet is invalid */
    key = keyboardInstance->keyboardBuffer[0];
    for (currentIndex = 1; currentIndex < 8; ++currentIndex)
    {
        if (key != keyboardInstance->keyboardBuffer[currentIndex])
        {
            break;
        }
    }
    if (currentIndex >= 8) /* all packet data is same */
    {
        for (currentIndex = 0; currentIndex < 6; ++currentIndex)
        {
            keyboardInstance->lastPressData[currentIndex] = 0;
        }
        keyboardInstance->shiftPressed = 0;
        return;
    }

    /* shift control key */
    key = keyboardInstance->keyboardBuffer[0];
    if (key & 0x22)
    {
        keyboardInstance->shiftPressed = 1;
    }
    else
    {
        keyboardInstance->shiftPressed = 0;
    }

    /* process every key */
    longIndex = 0;
    for (currentIndex = 2; currentIndex < 8; ++currentIndex)
    {
        key = keyboardInstance->keyboardBuffer[currentIndex]; /* key value */
        if (!key)                                             /* key is invalid */
        {
            break;
        }
        if (longIndex < 6) /* note: long pressed key is continuous */
        {
            for (; longIndex < 6; ++longIndex)
            {
                if (key == keyboardInstance->lastPressData[longIndex]) /* the key is long pressed */
                {
                    break;
                }
            }
            if (longIndex >= 6) /* the key is new */
            {
                USB_HostKeyboardPrintKey(key, keyboardInstance->shiftPressed);
            }
        }
        else /* the key is new */
        {
            USB_HostKeyboardPrintKey(key, keyboardInstance->shiftPressed);
        }
    }

    /* save the data for comparing with next data */
    for (currentIndex = 0; currentIndex < 6; ++currentIndex)
    {
        keyboardInstance->lastPressData[currentIndex] = keyboardInstance->keyboardBuffer[currentIndex + 2];
    }
}

static void USB_HostHidInCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    usb_host_keyboard_instance_t *keyboardInstance = (usb_host_keyboard_instance_t *)param;

    if (keyboardInstance->runWaitState == kRunWaitDataReceived)
    {
        if (keyboardInstance->deviceState == kStatus_DEV_Attached)
        {
            if (status == kStatus_USB_Success)
            {
                keyboardInstance->runState = kRunDataReceived; /* go to process data */
            }
            else
            {
                keyboardInstance->runState = kRunPrimeDataReceive; /* go to prime next receiving */
            }
        }
    }
}

static void USB_HostHidControlCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    usb_host_keyboard_instance_t *keyboardInstance = (usb_host_keyboard_instance_t *)param;

    if (keyboardInstance->runWaitState == kRunWaitSetInterface) /* set interface done */
    {
        keyboardInstance->runState = kRunSetInterfaceDone;
    }
    else if (keyboardInstance->runWaitState == kRunWaitSetIdle) /* hid set idle done */
    {
        keyboardInstance->runState = kRunSetIdleDone;
    }
    else if (keyboardInstance->runWaitState == kRunWaitGetReportDescriptor) /* hid get report descriptor done */
    {
        keyboardInstance->runState = kRunGetReportDescriptorDone;
    }
    else if (keyboardInstance->runWaitState == kRunWaitSetProtocol) /* hid set protocol done */
    {
        keyboardInstance->runState = kRunSetProtocolDone;
    }
    else
    {
    }
}

void USB_HostHidKeyboardTask(void *param)
{
    usb_host_keyboard_instance_t *keyboardInstance = (usb_host_keyboard_instance_t *)param;
    usb_host_hid_descriptor_t *hidDescriptor;
    uint32_t keyboardReportLength = 0;
    uint8_t *descriptor;
    uint32_t endPosition;
    uint8_t index;

    /* device state changes, process once for each state */
    if (keyboardInstance->deviceState != keyboardInstance->prevState)
    {
        keyboardInstance->prevState = keyboardInstance->deviceState;
        switch (keyboardInstance->deviceState)
        {
            case kStatus_DEV_Idle:
                break;

            case kStatus_DEV_Attached: /* deivce is attached and numeration is done */
                keyboardInstance->runState = kRunSetInterface;
                /* hid class initialization */
                if (USB_HostHidInit(keyboardInstance->deviceHandle, &keyboardInstance->classHandle) !=
                    kStatus_USB_Success)
                {
                    usb_echo("host hid class initialize fail\r\n");
                }
                else
                {
                    usb_echo("keyboard attached\r\n");
                }
                for (index = 0; index < 6; ++index)
                {
                    keyboardInstance->lastPressData[index] = 0x00;
                    keyboardInstance->keyboardBuffer[index] = 0x00;
                }
                keyboardInstance->keyboardBuffer[6] = keyboardInstance->keyboardBuffer[7] = 0x00;
                break;

            case kStatus_DEV_Detached: /* device is detached */
                keyboardInstance->runState = kRunIdle;
                keyboardInstance->deviceState = kStatus_DEV_Idle;
                USB_HostHidDeinit(keyboardInstance->deviceHandle,
                                  keyboardInstance->classHandle); /* hid class de-initialization */
                keyboardInstance->classHandle = NULL;
                for (index = 0; index < 6; ++index)
                {
                    keyboardInstance->lastPressData[index] = 0x00;
                    keyboardInstance->keyboardBuffer[index] = 0x00;
                }
                keyboardInstance->keyboardBuffer[6] = keyboardInstance->keyboardBuffer[7] = 0x00;
                usb_echo("keyboard detached\r\n");
                break;

            default:
                break;
        }
    }

    switch (keyboardInstance->runState)
    {
        case kRunIdle:
            break;

        case kRunSetInterface: /* 1. set hid interface */
            keyboardInstance->runWaitState = kRunWaitSetInterface;
            keyboardInstance->runState = kRunIdle;
            if (USB_HostHidSetInterface(keyboardInstance->classHandle, keyboardInstance->interfaceHandle, 0,
                                        USB_HostHidControlCallback, keyboardInstance) != kStatus_USB_Success)
            {
                usb_echo("set interface error\r\n");
            }
            break;

        case kRunSetInterfaceDone: /* 2. hid set idle */
            keyboardInstance->maxPacketSize =
                USB_HostHidGetPacketsize(keyboardInstance->classHandle, USB_ENDPOINT_INTERRUPT, USB_IN);

            /* first: set idle */
            keyboardInstance->runWaitState = kRunWaitSetIdle;
            keyboardInstance->runState = kRunIdle;
            if (USB_HostHidSetIdle(keyboardInstance->classHandle, 0, 0, USB_HostHidControlCallback, keyboardInstance) !=
                kStatus_USB_Success)
            {
                usb_echo("error in USB_HostHidSetIdle\r\n");
            }
            break;

        case kRunSetIdleDone: /* 3. hid get report descriptor */
            /* get report descriptor */
            hidDescriptor = NULL;
            descriptor = (uint8_t *)((usb_host_interface_t *)keyboardInstance->interfaceHandle)->interfaceExtension;
            endPosition = (uint32_t)descriptor +
                          ((usb_host_interface_t *)keyboardInstance->interfaceHandle)->interfaceExtensionLength;

            while ((uint32_t)descriptor < endPosition)
            {
                if (*(descriptor + 1) == USB_DESCRIPTOR_TYPE_HID) /* descriptor type */
                {
                    hidDescriptor = (usb_host_hid_descriptor_t *)descriptor;
                    break;
                }
                else
                {
                    descriptor = (uint8_t *)((uint32_t)descriptor + (*descriptor)); /* next descriptor */
                }
            }

            if (hidDescriptor != NULL)
            {
                usb_host_hid_class_descriptor_t *hidClassDescriptor;
                hidClassDescriptor = (usb_host_hid_class_descriptor_t *)&(hidDescriptor->bHidDescriptorType);
                for (index = 0; index < hidDescriptor->bNumDescriptors; ++index)
                {
                    hidClassDescriptor += index;
                    if (hidClassDescriptor->bHidDescriptorType == USB_DESCRIPTOR_TYPE_HID_REPORT)
                    {
                        keyboardReportLength =
                            (uint16_t)USB_SHORT_FROM_LITTLE_ENDIAN_ADDRESS(hidClassDescriptor->wDescriptorLength);
                        break;
                    }
                }
            }
            if (keyboardReportLength > HID_BUFFER_SIZE)
            {
                usb_echo("hid buffer is too small\r\n");
                keyboardInstance->runState = kRunIdle;
                return;
            }

            if (keyboardReportLength > 0) /* when report descriptor length is zero, go to next step */
            {
                keyboardInstance->runWaitState = kRunWaitGetReportDescriptor;
                keyboardInstance->runState = kRunIdle;
                /* second: get report descriptor */
                USB_HostHidGetReportDescriptor(keyboardInstance->classHandle, keyboardInstance->keyboardBuffer,
                                               keyboardReportLength, USB_HostHidControlCallback, keyboardInstance);
                break;
            }

        case kRunGetReportDescriptorDone: /* 4. hid set protocol */
            keyboardInstance->runWaitState = kRunWaitSetProtocol;
            keyboardInstance->runState = kRunIdle;
            /* third: set protocol */
            if (USB_HostHidSetProtocol(keyboardInstance->classHandle, USB_HOST_HID_REQUEST_PROTOCOL_REPORT,
                                       USB_HostHidControlCallback, keyboardInstance) != kStatus_USB_Success)
            {
                usb_echo("error in USB_HostHidSetProtocol\r\n");
            }
            break;

        case kRunSetProtocolDone: /* 5. start to receive data */
            keyboardInstance->runWaitState = kRunWaitDataReceived;
            keyboardInstance->runState = kRunIdle;
            if (USB_HostHidRecv(keyboardInstance->classHandle, keyboardInstance->keyboardBuffer,
                                keyboardInstance->maxPacketSize, USB_HostHidInCallback,
                                keyboardInstance) != kStatus_USB_Success)
            {
                usb_echo("error in USB_HostHidRecv\r\n");
            }
            break;

        case kRunDataReceived: /* process received data and receive next data */
            USB_HostKeyboardProcessBuffer(keyboardInstance);

            keyboardInstance->runWaitState = kRunWaitDataReceived;
            keyboardInstance->runState = kRunIdle;
            if (USB_HostHidRecv(keyboardInstance->classHandle, keyboardInstance->keyboardBuffer,
                                keyboardInstance->maxPacketSize, USB_HostHidInCallback,
                                keyboardInstance) != kStatus_USB_Success)
            {
                usb_echo("Error in USB_HostHidRecv\r\n");
            }
            break;

        case kRunPrimeDataReceive: /* receive data */
            keyboardInstance->runWaitState = kRunWaitDataReceived;
            keyboardInstance->runState = kRunIdle;
            if (USB_HostHidRecv(keyboardInstance->classHandle, keyboardInstance->keyboardBuffer,
                                keyboardInstance->maxPacketSize, USB_HostHidInCallback,
                                keyboardInstance) != kStatus_USB_Success)
            {
                usb_echo("error in USB_HostHidRecv\r\n");
            }
            break;

        default:
            break;
    }
}

usb_status_t USB_HostHidKeyboardEvent(usb_device_handle deviceHandle,
                                      usb_host_configuration_handle configurationHandle,
                                      uint32_t eventCode)
{
    usb_host_configuration_t *configuration;
    usb_host_interface_t *interface;
    uint32_t infoValue;
    usb_status_t status = kStatus_USB_Success;
    uint8_t interfaceIndex;
    uint8_t id;

    switch (eventCode)
    {
        case kUSB_HostEventAttach:
            /* judge whether is configurationHandle supported */
            configuration = (usb_host_configuration_t *)configurationHandle;
            for (interfaceIndex = 0; interfaceIndex < configuration->interfaceCount; ++interfaceIndex)
            {
                interface = &configuration->interfaceList[interfaceIndex];
                id = interface->interfaceDesc->bInterfaceClass;
                if (id != USB_HOST_HID_CLASS_CODE)
                {
                    continue;
                }
                id = interface->interfaceDesc->bInterfaceSubClass;
                if ((id != USB_HOST_HID_SUBCLASS_CODE_NONE) && (id != USB_HOST_HID_SUBCLASS_CODE_BOOT))
                {
                    continue;
                }
                id = interface->interfaceDesc->bInterfaceProtocol;
                if (id != USB_HOST_HID_PROTOCOL_KEYBOARD)
                {
                    continue;
                }
                else
                {
                    if (g_HostHidKeyboard.deviceState == kStatus_DEV_Idle)
                    {
                        /* the interface is supported by the application */
                        g_HostHidKeyboard.keyboardBuffer = s_KeyboardBuffer;
                        g_HostHidKeyboard.deviceHandle = deviceHandle;
                        g_HostHidKeyboard.interfaceHandle = interface;
                        g_HostHidKeyboard.configHandle = configurationHandle;
                        return kStatus_USB_Success;
                    }
                    else
                    {
                        continue;
                    }
                }
            }
            status = kStatus_USB_NotSupported;
            break;

        case kUSB_HostEventNotSupported:
            break;

        case kUSB_HostEventEnumerationDone:
            if (g_HostHidKeyboard.configHandle == configurationHandle)
            {
                if ((g_HostHidKeyboard.deviceHandle != NULL) && (g_HostHidKeyboard.interfaceHandle != NULL))
                {
                    /* the device enumeration is done */
                    if (g_HostHidKeyboard.deviceState == kStatus_DEV_Idle)
                    {
                        g_HostHidKeyboard.deviceState = kStatus_DEV_Attached;

                        USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDevicePID, &infoValue);
                        usb_echo("hid keyboard attached:pid=0x%x", infoValue);
                        USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDeviceVID, &infoValue);
                        usb_echo("vid=0x%x ", infoValue);
                        USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDeviceAddress, &infoValue);
                        usb_echo("address=%d\r\n", infoValue);
                    }
                    else
                    {
                        usb_echo("not idle host keyboard instance\r\n");
                        status = kStatus_USB_Error;
                    }
                }
            }
            break;

        case kUSB_HostEventDetach:
            if (g_HostHidKeyboard.configHandle == configurationHandle)
            {
                /* the device is detached */
                g_HostHidKeyboard.configHandle = NULL;
                if (g_HostHidKeyboard.deviceState != kStatus_DEV_Idle)
                {
                    g_HostHidKeyboard.deviceState = kStatus_DEV_Detached;
                }
            }
            break;

        default:
            break;
    }
    return status;
}
