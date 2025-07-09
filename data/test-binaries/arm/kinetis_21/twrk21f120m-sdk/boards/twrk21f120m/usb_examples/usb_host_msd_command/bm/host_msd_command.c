/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
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
#include "usb_host_msd.h"
#include "host_msd_command.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

#if MSD_THROUGHPUT_TEST_ENABLE
#include "fsl_device_registers.h"
#define THROUGHPUT_BUFFER_SIZE (64 * 1024) /* throughput test buffer */
#define MCU_CORE_CLOCK (120000000)         /* mcu core clock, user need to configure it. */
#endif                                     /* MSD_THROUGHPUT_TEST_ENABLE */

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*!
 * @brief host msd ufi command callback.
 *
 * This function is used as callback function for ufi command.
 *
 * @param param      the host msd command instance pointer.
 * @param data       data buffer pointer.
 * @param dataLength data length.
 * @status           transfer result status.
 */
static void USB_HostMsdUfiCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status);

/*!
 * @brief host msd control transfer callback.
 *
 * This function is used as callback function for control transfer .
 *
 * @param param      the host msd command instance pointer.
 * @param data       data buffer pointer.
 * @param dataLength data length.
 * @status           transfer result status.
 */
static void USB_HostMsdControlCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status);

/*!
 * @brief host msd command test done.
 *
 * @param msdCommandInstance   the host command instance pointer.
 */
static void msd_command_test_done(usb_host_msd_command_instance_t *msdCommandInstance);

/*!
 * @brief host msd command test.
 *
 * This function implements msd command test.
 *
 * @param msdCommandInstance   the host command instance pointer.
 */
static void USB_HostMsdCommandTest(usb_host_msd_command_instance_t *msdCommandInstance);

/*******************************************************************************
 * Variables
 ******************************************************************************/
extern usb_host_handle g_HostHandle;                        /* global host handle */
usb_host_msd_command_instance_t g_MsdCommandInstance = {0}; /* global msd command instance */
/* command on-going state. It should set to 1 when start command, it is set to 0 in the callback */
volatile uint8_t ufiIng;
/* command callback status */
volatile usb_status_t ufiStatus;

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t s_TestUfiBuffer[512]; /*!< test buffer */

#if MSD_THROUGHPUT_TEST_ENABLE
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint32_t testThroughputBuffer[THROUGHPUT_BUFFER_SIZE / 4]; /* the buffer for throughput test */
uint32_t testSizeArray[] = {50 * 1024, 50 * 1024}; /* test time and test size (uint: K) */
#endif                                             /* MSD_THROUGHPUT_TEST_ENABLE */

/*******************************************************************************
 * Code
 ******************************************************************************/

static void USB_HostMsdUfiCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    ufiIng = 0;
    ufiStatus = status;
}

static void USB_HostMsdControlCallback(void *param, uint8_t *data, uint32_t dataLength, usb_status_t status)
{
    usb_host_msd_command_instance_t *msdCommandInstance = (usb_host_msd_command_instance_t *)param;

    if (msdCommandInstance->runWaitState == kRunWaitSetInterface) /* set interface finish */
    {
        msdCommandInstance->runWaitState = kRunIdle;
        msdCommandInstance->runState = kRunMassStorageTest;
    }
}

static void msd_command_test_done(usb_host_msd_command_instance_t *msdCommandInstance)
{
    usb_echo("........................test done....................\r\n");
}

static inline void USB_HostControllerTaskFunction(usb_host_handle hostHandle)
{
#if ((defined USB_HOST_CONFIG_KHCI) && (USB_HOST_CONFIG_KHCI))
    USB_HostKhciTaskFunction(hostHandle);
#endif /* USB_HOST_CONFIG_KHCI */
#if ((defined USB_HOST_CONFIG_EHCI) && (USB_HOST_CONFIG_EHCI))
    USB_HostEhciTaskFunction(hostHandle);
#endif /* USB_HOST_CONFIG_EHCI */
#if ((defined USB_HOST_CONFIG_OHCI) && (USB_HOST_CONFIG_OHCI > 0U))
    USB_HostOhciTaskFunction(g_HostHandle);
#endif /* USB_HOST_CONFIG_OHCI */
#if ((defined USB_HOST_CONFIG_IP3516HS) && (USB_HOST_CONFIG_IP3516HS > 0U))
    USB_HostIp3516HsTaskFunction(g_HostHandle);
#endif /* USB_HOST_CONFIG_IP3516HS */
}

static void USB_HostMsdCommandTest(usb_host_msd_command_instance_t *msdCommandInstance)
{
    usb_status_t status;
    uint32_t blockSize = 512;
    uint32_t address;

    usb_echo("........................test start....................\r\n");

    usb_echo("get max logical units....");
    ufiIng = 1;
    status = USB_HostMsdGetMaxLun(msdCommandInstance->classHandle, msdCommandInstance->testUfiBuffer,
                                  USB_HostMsdUfiCallback, msdCommandInstance);
    if (status != kStatus_USB_Success)
    {
        usb_echo("error\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }
    while (ufiIng) /* wait the command */
    {
        USB_HostControllerTaskFunction(g_HostHandle);
    }
    if (ufiStatus == kStatus_USB_Success) /* print the command result */
    {
        usb_echo("success, logical units: %d\r\n", msdCommandInstance->testUfiBuffer[0]);
    }
    else
    {
        usb_echo("fail\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }

    if (msdCommandInstance->deviceState != kStatus_DEV_Attached)
    {
        msd_command_test_done(msdCommandInstance);
        return;
    }
    usb_echo("test unit ready....");
    ufiIng = 1;
    status = USB_HostMsdTestUnitReady(msdCommandInstance->classHandle, 0, USB_HostMsdUfiCallback, msdCommandInstance);
    if (status != kStatus_USB_Success)
    {
        usb_echo("error\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }
    while (ufiIng) /* wait the command */
    {
        USB_HostControllerTaskFunction(g_HostHandle);
    }
    if ((ufiStatus == kStatus_USB_Success) || (ufiStatus == kStatus_USB_MSDStatusFail)) /* print the command result */
    {
        usb_echo("success, unit status: %s\r\n", ufiStatus == kStatus_USB_MSDStatusFail ? "not ready" : "ready");
    }
    else
    {
        usb_echo("fail\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }

    if (msdCommandInstance->deviceState != kStatus_DEV_Attached)
    {
        msd_command_test_done(msdCommandInstance);
        return;
    }
    usb_echo("request sense....");
    ufiIng = 1;
    status = USB_HostMsdRequestSense(msdCommandInstance->classHandle, 0, msdCommandInstance->testUfiBuffer,
                                     sizeof(usb_host_ufi_sense_data_t), USB_HostMsdUfiCallback, msdCommandInstance);
    if (status != kStatus_USB_Success)
    {
        usb_echo("error\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }
    while (ufiIng) /* wait the command */
    {
        USB_HostControllerTaskFunction(g_HostHandle);
    }
    if (ufiStatus == kStatus_USB_Success) /* print the command result */
    {
        usb_echo("success\r\n");
    }
    else
    {
        usb_echo("fail\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }

    if (msdCommandInstance->deviceState != kStatus_DEV_Attached)
    {
        msd_command_test_done(msdCommandInstance);
        return;
    }
    usb_echo("inquiry...");
    ufiIng = 1;
    status = USB_HostMsdInquiry(msdCommandInstance->classHandle, 0, msdCommandInstance->testUfiBuffer,
                                sizeof(usb_host_ufi_inquiry_data_t), USB_HostMsdUfiCallback, msdCommandInstance);
    if (status != kStatus_USB_Success)
    {
        usb_echo("error\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }
    while (ufiIng) /* wait the command */
    {
        USB_HostControllerTaskFunction(g_HostHandle);
    }
    if (ufiStatus == kStatus_USB_Success) /* print the command result */
    {
        usb_echo("success\r\n");
    }
    else
    {
        usb_echo("fail\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }

    if (msdCommandInstance->deviceState != kStatus_DEV_Attached)
    {
        msd_command_test_done(msdCommandInstance);
        return;
    }
    usb_echo("read capacity...");
    ufiIng = 1;
    status = USB_HostMsdReadCapacity(msdCommandInstance->classHandle, 0, msdCommandInstance->testUfiBuffer,
                                     sizeof(usb_host_ufi_read_capacity_t), USB_HostMsdUfiCallback, msdCommandInstance);
    if (status != kStatus_USB_Success)
    {
        usb_echo("error\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }
    while (ufiIng) /* wait the command */
    {
        USB_HostControllerTaskFunction(g_HostHandle);
    }
    if (ufiStatus == kStatus_USB_Success) /* print the command result */
    {
        address = (uint32_t) & (msdCommandInstance->testUfiBuffer[0]);
        address = (uint32_t)((usb_host_ufi_read_capacity_t *)(address))->blockLengthInBytes;
        blockSize = USB_LONG_FROM_BIG_ENDIAN_ADDRESS(((uint8_t *)address));
        address = (uint32_t) & (msdCommandInstance->testUfiBuffer[0]);
        address = (uint32_t)((usb_host_ufi_read_capacity_t *)(address))->lastLogicalBlockAddress;
        usb_echo("success, last logical block:%d block length:%d\r\n",
                 USB_LONG_FROM_BIG_ENDIAN_ADDRESS(((uint8_t *)address)), blockSize);
    }
    else
    {
        usb_echo("fail\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }

    if (msdCommandInstance->deviceState != kStatus_DEV_Attached)
    {
        msd_command_test_done(msdCommandInstance);
        return;
    }
    if (blockSize == 0)
    {
        blockSize = 512;
    }
    usb_echo("read(10)...");
    ufiIng = 1;
    status = USB_HostMsdRead10(msdCommandInstance->classHandle, 0, 0, msdCommandInstance->testUfiBuffer, blockSize, 1,
                               USB_HostMsdUfiCallback, msdCommandInstance);
    if (status != kStatus_USB_Success)
    {
        usb_echo("error\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }
    while (ufiIng) /* wait the command */
    {
        USB_HostControllerTaskFunction(g_HostHandle);
    }
    if (ufiStatus == kStatus_USB_Success) /* print the command result */
    {
        usb_echo("success\r\n");
    }
    else
    {
        usb_echo("fail\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }

    if (msdCommandInstance->deviceState != kStatus_DEV_Attached)
    {
        msd_command_test_done(msdCommandInstance);
        return;
    }
    usb_echo("write(10)...");
    ufiIng = 1;
    status = USB_HostMsdWrite10(msdCommandInstance->classHandle, 0, 0, msdCommandInstance->testUfiBuffer, blockSize, 1,
                                USB_HostMsdUfiCallback, msdCommandInstance);
    if (status != kStatus_USB_Success)
    {
        usb_echo("error\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }
    while (ufiIng) /* wait the command */
    {
        USB_HostControllerTaskFunction(g_HostHandle);
    }
    if (ufiStatus == kStatus_USB_Success) /* print the command result */
    {
        usb_echo("success\r\n");
    }
    else
    {
        usb_echo("fail\r\n");
        msd_command_test_done(msdCommandInstance);
        return;
    }

#if MSD_THROUGHPUT_TEST_ENABLE
    uint64_t totalTime;
    uint32_t testSize;
    uint32_t blockAddress;
    uint8_t testIndex;

    /* time delay (~100ms) */
    for (testSize = 0; testSize < 400000; ++testSize)
    {
        __ASM("nop");
    }

    CoreDebug->DEMCR |= (1 << CoreDebug_DEMCR_TRCENA_Pos);

    for (testSize = 0; testSize < (THROUGHPUT_BUFFER_SIZE / 4); ++testSize)
    {
        testThroughputBuffer[testSize] = testSize;
    }

    usb_echo("throughput test:\r\n");
    for (testIndex = 0; testIndex < (sizeof(testSizeArray) / 4); ++testIndex)
    {
        totalTime = 0;
        blockAddress = 0;
        testSize = testSizeArray[testIndex] * 1024;
        while (testSize)
        {
            if (msdCommandInstance->deviceState != kStatus_DEV_Attached)
            {
                msd_command_test_done(msdCommandInstance);
                return;
            }
            ufiIng = 1;
            DWT->CYCCNT = 0;
            DWT->CTRL |= (1 << DWT_CTRL_CYCCNTENA_Pos);
            status =
                USB_HostMsdWrite10(msdCommandInstance->classHandle, 0, blockAddress,
                                   (uint8_t *)&testThroughputBuffer[0], THROUGHPUT_BUFFER_SIZE,
                                   (THROUGHPUT_BUFFER_SIZE / blockSize), USB_HostMsdUfiCallback, msdCommandInstance);
            if (status != kStatus_USB_Success)
            {
                usb_echo("    error\r\n");
                msd_command_test_done(msdCommandInstance);
                return;
            }
            while (ufiIng) /* wait the command */
            {
                USB_HostControllerTaskFunction(g_HostHandle);
            }
            totalTime += DWT->CYCCNT;
            DWT->CTRL &= ~(1U << DWT_CTRL_CYCCNTENA_Pos);
            if (ufiStatus != kStatus_USB_Success)
            {
                usb_echo("fail\r\n");
                msd_command_test_done(msdCommandInstance);
                return;
            }
            testSize -= THROUGHPUT_BUFFER_SIZE;
            blockAddress += (THROUGHPUT_BUFFER_SIZE / blockSize);
        }
        testSize = testSizeArray[testIndex];
        usb_echo("    write %dKB data the speed is %d KB/s\r\n", testSize,
                 (uint32_t)((uint64_t)testSize * (uint64_t)MCU_CORE_CLOCK / (uint64_t)totalTime));

        totalTime = 0;
        blockAddress = 0;
        testSize = testSizeArray[testIndex] * 1024;
        while (testSize)
        {
            if (msdCommandInstance->deviceState != kStatus_DEV_Attached)
            {
                msd_command_test_done(msdCommandInstance);
                return;
            }
            ufiIng = 1;
            DWT->CYCCNT = 0;
            DWT->CTRL |= (1 << DWT_CTRL_CYCCNTENA_Pos);
            status =
                USB_HostMsdRead10(msdCommandInstance->classHandle, 0, blockAddress, (uint8_t *)&testThroughputBuffer[0],
                                  THROUGHPUT_BUFFER_SIZE, (THROUGHPUT_BUFFER_SIZE / blockSize), USB_HostMsdUfiCallback,
                                  msdCommandInstance);
            if (status != kStatus_USB_Success)
            {
                usb_echo("    error\r\n");
                msd_command_test_done(msdCommandInstance);
                return;
            }
            while (ufiIng) /* wait the command */
            {
                USB_HostControllerTaskFunction(g_HostHandle);
            }
            totalTime += DWT->CYCCNT;
            DWT->CTRL &= ~(1U << DWT_CTRL_CYCCNTENA_Pos);
            if (ufiStatus != kStatus_USB_Success)
            {
                usb_echo("fail\r\n");
                msd_command_test_done(msdCommandInstance);
                return;
            }
            testSize -= THROUGHPUT_BUFFER_SIZE;
            blockAddress += (THROUGHPUT_BUFFER_SIZE / blockSize);
        }
        testSize = testSizeArray[testIndex];
        usb_echo("    read %dKB data the speed is %d KB/s\r\n", testSize,
                 (uint32_t)((uint64_t)testSize * (uint64_t)MCU_CORE_CLOCK / (uint64_t)totalTime));
    }
#endif /* MSD_THROUGHPUT_TEST_ENABLE */

    msd_command_test_done(msdCommandInstance); /* all test are done */
}

void USB_HostMsdTask(void *arg)
{
    usb_status_t status;
    usb_host_msd_command_instance_t *msdCommandInstance = (usb_host_msd_command_instance_t *)arg;

    if (msdCommandInstance->deviceState != msdCommandInstance->prevDeviceState)
    {
        msdCommandInstance->prevDeviceState = msdCommandInstance->deviceState;
        switch (msdCommandInstance->deviceState)
        {
            case kStatus_DEV_Idle:
                break;

            case kStatus_DEV_Attached: /* deivce is attached and numeration is done */
                status = USB_HostMsdInit(msdCommandInstance->deviceHandle,
                                         &msdCommandInstance->classHandle); /* msd class initialization */
                if (status != kStatus_USB_Success)
                {
                    usb_echo("usb host msd init fail\r\n");
                    return;
                }
                msdCommandInstance->runState = kRunSetInterface;
                break;

            case kStatus_DEV_Detached: /* device is detached */
                msdCommandInstance->deviceState = kStatus_DEV_Idle;
                msdCommandInstance->runState = kRunIdle;
                USB_HostMsdDeinit(msdCommandInstance->deviceHandle,
                                  msdCommandInstance->classHandle); /* msd class de-initialization */
                msdCommandInstance->classHandle = NULL;

                usb_echo("mass storage device detached\r\n");
                break;

            default:
                break;
        }
    }

    /* run state */
    switch (msdCommandInstance->runState)
    {
        case kRunIdle:
            break;

        case kRunSetInterface: /* set msd interface */
            msdCommandInstance->runState = kRunIdle;
            msdCommandInstance->runWaitState = kRunWaitSetInterface;
            status = USB_HostMsdSetInterface(msdCommandInstance->classHandle, msdCommandInstance->interfaceHandle, 0,
                                             USB_HostMsdControlCallback, msdCommandInstance);
            if (status != kStatus_USB_Success)
            {
                usb_echo("set interface fail\r\n");
            }
            break;

        case kRunMassStorageTest:                       /* set interface succeed */
            USB_HostMsdCommandTest(msdCommandInstance); /* test msd device */
            msdCommandInstance->runState = kRunIdle;
            break;

        default:
            break;
    }
}

usb_status_t USB_HostMsdEvent(usb_device_handle deviceHandle,
                              usb_host_configuration_handle configurationHandle,
                              uint32_t eventCode)
{
    usb_status_t status = kStatus_USB_Success;
    uint8_t id;
    usb_host_configuration_t *configuration;
    uint8_t interfaceIndex;
    usb_host_interface_t *interface;
    uint32_t infoValue;

    switch (eventCode)
    {
        case kUSB_HostEventAttach:
            /* judge whether is configurationHandle supported */
            configuration = (usb_host_configuration_t *)configurationHandle;
            for (interfaceIndex = 0; interfaceIndex < configuration->interfaceCount; ++interfaceIndex)
            {
                interface = &configuration->interfaceList[interfaceIndex];
                id = interface->interfaceDesc->bInterfaceClass;
                if (id != USB_HOST_MSD_CLASS_CODE)
                {
                    continue;
                }
                id = interface->interfaceDesc->bInterfaceSubClass;
                if ((id != USB_HOST_MSD_SUBCLASS_CODE_UFI) && (id != USB_HOST_MSD_SUBCLASS_CODE_SCSI))
                {
                    continue;
                }
                id = interface->interfaceDesc->bInterfaceProtocol;
                if (id != USB_HOST_MSD_PROTOCOL_BULK)
                {
                    continue;
                }
                else
                {
                    if (g_MsdCommandInstance.deviceState == kStatus_DEV_Idle)
                    {
                        /* the interface is supported by the application */
                        g_MsdCommandInstance.testUfiBuffer = s_TestUfiBuffer;
                        g_MsdCommandInstance.deviceHandle = deviceHandle;
                        g_MsdCommandInstance.interfaceHandle = interface;
                        g_MsdCommandInstance.configHandle = configurationHandle;
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
            if (g_MsdCommandInstance.configHandle == configurationHandle)
            {
                if ((g_MsdCommandInstance.deviceHandle != NULL) && (g_MsdCommandInstance.interfaceHandle != NULL))
                {
                    /* the device enumeration is done */
                    if (g_MsdCommandInstance.deviceState == kStatus_DEV_Idle)
                    {
                        g_MsdCommandInstance.deviceState = kStatus_DEV_Attached;

                        USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDevicePID, &infoValue);
                        usb_echo("mass storage device attached:pid=0x%x", infoValue);
                        USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDeviceVID, &infoValue);
                        usb_echo("vid=0x%x ", infoValue);
                        USB_HostHelperGetPeripheralInformation(deviceHandle, kUSB_HostGetDeviceAddress, &infoValue);
                        usb_echo("address=%d\r\n", infoValue);
                    }
                    else
                    {
                        usb_echo("not idle msd instance\r\n");
                        status = kStatus_USB_Error;
                    }
                }
            }
            break;

        case kUSB_HostEventDetach:
            if (g_MsdCommandInstance.configHandle == configurationHandle)
            {
                /* the device is detached */
                g_MsdCommandInstance.configHandle = NULL;
                if (g_MsdCommandInstance.deviceState != kStatus_DEV_Idle)
                {
                    g_MsdCommandInstance.deviceState = kStatus_DEV_Detached;
                }
            }
            break;

        default:
            break;
    }
    return status;
}
