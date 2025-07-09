/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
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

#include <stdio.h>
#include "fsl_sd.h"
#include "fsl_debug_console.h"
#include "FreeRTOS.h"
#include "semphr.h"
#include "task.h"
#include "board.h"
#include "fsl_sysmpu.h"
#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/


/*! @brief Data block count accessed in card */
#define DATA_BLOCK_COUNT (5U)
/*! @brief Start data block number accessed in card */
#define DATA_BLOCK_START (2U)
/*! @brief Data buffer size. */
#define DATA_BUFFER_SIZE (FSL_SDMMC_DEFAULT_BLOCK_SIZE * DATA_BLOCK_COUNT)

/*! @brief Task stack size. */
#define ACCESSCARD_TASK_STACK_SIZE (DATA_BUFFER_SIZE + 1000U)
/*! @brief Task stack priority. */
#define ACCESSCARD_TASK_PRIORITY (configMAX_PRIORITIES - 2U)

/*! @brief Task stack size. */
#define CARDDETECT_TASK_STACK_SIZE (DATA_BUFFER_SIZE + 1000U)
/*! @brief Task stack priority. */
#define CARDDETECT_TASK_PRIORITY (configMAX_PRIORITIES - 1U)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*!
 * @brief SD card access task.
 *
 * @param pvParameters Task parameter.
 */
static void AccessCardTask(void *pvParameters);

/*!
 * @brief SD card detect task.
 *
 * @param pvParameters Task parameter.
 */
static void CardDetectTask(void *pvParameters);

/*!
* @brief call back function for SD card detect.
*
* @param isInserted  true,  indicate the card is insert.
*                    false, indicate the card is remove.
* @param userData
*/
static void SDCARD_DetectCallBack(bool isInserted, void *userData);

/*!
* @brief card read/write function.
*
* @param card card descriptor
* @param isReadOnly read only flag
*/
static status_t SDCARD_ReadWrite(sd_card_t *card, bool isReadOnly);

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*! @brief Card descriptor. */
sd_card_t g_sd;

/* @brief decription about the read/write buffer
* The size of the read/write buffer should be a multiple of 512, since SDHC/SDXC card uses 512-byte fixed
* block length and this driver example is enabled with a SDHC/SDXC card.If you are using a SDSC card, you
* can define the block length by yourself if the card supports partial access.
* The address of the read/write buffer should align to the specific DMA data buffer address align value if
* DMA transfer is used, otherwise the buffer address is not important.
* At the same time buffer address/size should be aligned to the cache line size if cache is supported.
*/
/*! @brief Data written to the card */
SDK_ALIGN(uint8_t g_dataWrite[SDK_SIZEALIGN(DATA_BUFFER_SIZE, SDMMC_DATA_BUFFER_ALIGN_CACHE)],
          MAX(SDMMC_DATA_BUFFER_ALIGN_CACHE, SDMMCHOST_DMA_BUFFER_ADDR_ALIGN));
/*! @brief Data read from the card */
SDK_ALIGN(uint8_t g_dataRead[SDK_SIZEALIGN(DATA_BUFFER_SIZE, SDMMC_DATA_BUFFER_ALIGN_CACHE)],
          MAX(SDMMC_DATA_BUFFER_ALIGN_CACHE, SDMMCHOST_DMA_BUFFER_ADDR_ALIGN));

/*! @brief SDMMC host detect card configuration */
static const sdmmchost_detect_card_t s_sdCardDetect = {
#ifndef BOARD_SD_DETECT_TYPE
    .cdType = kSDMMCHOST_DetectCardByGpioCD,
#else
    .cdType = BOARD_SD_DETECT_TYPE,
#endif
    .cdTimeOut_ms = (~0U),
    .cardInserted = SDCARD_DetectCallBack,
    .cardRemoved = SDCARD_DetectCallBack,
};
/*! @brief SD card detect flag  */
static bool s_cardInserted = false;

/*! @brief Card semaphore  */
static SemaphoreHandle_t s_CardAccessSemaphore = NULL;
static SemaphoreHandle_t s_CardDetectSemaphore = NULL;

/*******************************************************************************
 * Code
 ******************************************************************************/
static void SDCARD_DetectCallBack(bool isInserted, void *userData)
{
    s_cardInserted = isInserted;
    xSemaphoreGiveFromISR(s_CardDetectSemaphore, NULL);
}

static void CardDetectTask(void *pvParameters)
{
    while (true)
    {
        if (!s_cardInserted)
        {
            PRINTF("\r\nPlease insert a card into board.\r\n");
            /* power off card */
            SD_PowerOffCard(g_sd.host.base, g_sd.usrParam.pwr);
        }

        /* take card detect semaphore */
        xSemaphoreTake(s_CardDetectSemaphore, portMAX_DELAY);
        if (s_cardInserted)
        {
            PRINTF("\r\nCard inserted.\r\n");
            /* power on the card */
            SD_PowerOnCard(g_sd.host.base, g_sd.usrParam.pwr);
            /* Init card. */
            if (SD_CardInit(&g_sd))
            {
                PRINTF("\r\nSD card init failed.\r\n");
                return;
            }
            xSemaphoreGive(s_CardAccessSemaphore);
        }
        else
        {
            PRINTF("\r\nCard removed.\r\n");
        }
    }
}

static void AccessCardTask(void *pvParameters)
{
    sd_card_t *card = &g_sd;
    bool isReadOnly;
    char ch = '0';

    /* take card access semaphore */
    xSemaphoreTake(s_CardAccessSemaphore, portMAX_DELAY);

    while (ch != 'q')
    {
        if (SD_IsCardPresent(card) == false)
        {
            /* take card access semaphore */
            xSemaphoreTake(s_CardAccessSemaphore, portMAX_DELAY);
        }

        PRINTF("\r\nRead/Write/Erase the card continuously until encounter error......\r\n");
        /* Check if card is readonly. */
        isReadOnly = SD_CheckReadOnly(card);

        SDCARD_ReadWrite(card, isReadOnly);

        PRINTF(
            "\r\nInput 'q' to quit card access task.\
            \r\nInput other char to read/write/erase data blocks again.\r\n");
        ch = GETCHAR();
        PUTCHAR(ch);
    }

    PRINTF("\r\nThe card access task will not access card again.\r\n");

    SD_Deinit(card);

    vTaskSuspend(NULL);
}

/*! @brief Main function */
int main(void)
{
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    SYSMPU_Enable(SYSMPU, false);

    s_CardAccessSemaphore = xSemaphoreCreateBinary();
    s_CardDetectSemaphore = xSemaphoreCreateBinary();

    g_sd.host.base = SD_HOST_BASEADDR;
    g_sd.host.sourceClock_Hz = SD_HOST_CLK_FREQ;
    g_sd.usrParam.cd = &s_sdCardDetect;

#if defined(__CORTEX_M)
    NVIC_SetPriority(SD_HOST_IRQ, 5U);
#else
    GIC_SetPriority(SD_HOST_IRQ, 25U);
#endif

    PRINTF("\r\nSDCARD freertos example.\r\n");

    /* SD host init function */
    if (SD_HostInit(&g_sd) != kStatus_Success)
    {
        PRINTF("\r\nSD host init fail\r\n");
        return -1;
    }

    if (pdPASS !=
        xTaskCreate(AccessCardTask, "AccessCardTask", ACCESSCARD_TASK_STACK_SIZE, NULL, ACCESSCARD_TASK_PRIORITY, NULL))
    {
        return -1;
    }

    if (pdPASS !=
        xTaskCreate(CardDetectTask, "CardDetectTask", CARDDETECT_TASK_STACK_SIZE, NULL, CARDDETECT_TASK_PRIORITY, NULL))
    {
        return -1;
    }

    /* Start the tasks and timer running. */
    vTaskStartScheduler();

    /* Scheduler should never reach this point. */
    while (true)
    {
    }
}

static status_t SDCARD_ReadWrite(sd_card_t *card, bool isReadOnly)
{
    if (isReadOnly)
    {
        PRINTF("\r\nRead one data block......\r\n");
        if (kStatus_Success != SD_ReadBlocks(card, g_dataRead, DATA_BLOCK_START, 1U))
        {
            PRINTF("Read one data block failed.\r\n");
            return kStatus_Fail;
        }

        PRINTF("Read multiple data blocks......\r\n");
        if (kStatus_Success != SD_ReadBlocks(card, g_dataRead, DATA_BLOCK_START, DATA_BLOCK_COUNT))
        {
            PRINTF("Read multiple data blocks failed.\r\n");
            return kStatus_Fail;
        }
    }
    else
    {
        memset(g_dataWrite, 0x67U, sizeof(g_dataWrite));

        PRINTF("\r\nWrite/read one data block......\r\n");
        if (kStatus_Success != SD_WriteBlocks(card, g_dataWrite, DATA_BLOCK_START, 1U))
        {
            PRINTF("Write one data block failed.\r\n");
            return kStatus_Fail;
        }

        memset(g_dataRead, 0U, sizeof(g_dataRead));
        if (kStatus_Success != SD_ReadBlocks(card, g_dataRead, DATA_BLOCK_START, 1U))
        {
            PRINTF("Read one data block failed.\r\n");
            return kStatus_Fail;
        }

        PRINTF("Compare the read/write content......\r\n");
        if (memcmp(g_dataRead, g_dataWrite, FSL_SDMMC_DEFAULT_BLOCK_SIZE))
        {
            PRINTF("The read/write content isn't consistent.\r\n");
            return kStatus_Fail;
        }
        PRINTF("The read/write content is consistent.\r\n");

        PRINTF("Write/read multiple data blocks......\r\n");
        if (kStatus_Success != SD_WriteBlocks(card, g_dataWrite, DATA_BLOCK_START, DATA_BLOCK_COUNT))
        {
            PRINTF("Write multiple data blocks failed.\r\n");
            return kStatus_Fail;
        }

        memset(g_dataRead, 0U, sizeof(g_dataRead));

        if (kStatus_Success != SD_ReadBlocks(card, g_dataRead, DATA_BLOCK_START, DATA_BLOCK_COUNT))
        {
            PRINTF("Read multiple data blocks failed.\r\n");
            return kStatus_Fail;
        }

        PRINTF("Compare the read/write content......\r\n");
        if (memcmp(g_dataRead, g_dataWrite, FSL_SDMMC_DEFAULT_BLOCK_SIZE))
        {
            PRINTF("The read/write content isn't consistent.\r\n");
            return kStatus_Fail;
        }
        PRINTF("The read/write content is consistent.\r\n");

        PRINTF("Erase multiple data blocks......\r\n");
        if (kStatus_Success != SD_EraseBlocks(card, DATA_BLOCK_START, DATA_BLOCK_COUNT))
        {
            PRINTF("Erase multiple data blocks failed.\r\n");
            return kStatus_Fail;
        }
    }

    return kStatus_Success;
}
