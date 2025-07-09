/*
 * The Clear BSD License
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
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

#include "fsl_sdmmc_host.h"
#include "fsl_sdmmc_event.h"
#include "board.h"
#include "fsl_port.h"
#include "fsl_gpio.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/*!
 * @brief SDMMCHOST detect card by GPIO.
 */
static void SDMMCHOST_DetectCardByGpio(const sdmmchost_detect_card_t *cd);

/*!
 * @brief SDMMCHOST detect card insert status by host controller.
 * @param base host base address.
 */
static void SDMMCHOST_DetectCardInsertByHost(SDMMCHOST_TYPE *base);

/*!
 * @brief host controller error recovery.
 * @param host base address.
 */
static void SDMMCHOST_ErrorRecovery(SDMMCHOST_TYPE *base);

/*!
 * @brief SDMMCHOST transfer function.
 * @param base host base address.
 * @param content transfer configurations.
 */
static status_t SDMMCHOST_TransferFunction(SDMMCHOST_TYPE *base, SDMMCHOST_TRANSFER *content);

/*!
 * @brief card detect deinit function.
 */
static void SDMMCHOST_CardDetectDeinit(void);

/*!
 * @brief card detect deinit function.
 * @param host base address.
 * @param host detect card configuration.
 */
static status_t SDMMCHOST_CardDetectInit(SDMMCHOST_TYPE *base, const sdmmchost_detect_card_t *cd);

/*******************************************************************************
 * Variables
 ******************************************************************************/
static uint32_t s_sdhcAdmaTable[SDHC_ADMA_TABLE_WORDS];
/*! @brief Card detect flag. */
static volatile bool s_sdInsertedFlag = false;
extern volatile uint32_t s_timeMilliseconds;
/*******************************************************************************
 * Code
 ******************************************************************************/
static void SDMMCHOST_DetectCardByGpio(const sdmmchost_detect_card_t *cd)
{
    if (GPIO_ReadPinInput(BOARD_SDHC_CD_GPIO_BASE, BOARD_SDHC_CD_GPIO_PIN) == SDMMCHOST_CARD_INSERT_CD_LEVEL)
    {
        s_sdInsertedFlag = true;
        if (cd && (cd->cardInserted))
        {
            cd->cardInserted(true, cd->userData);
        }
    }
    else
    {
        s_sdInsertedFlag = false;
        if (cd && (cd->cardRemoved))
        {
            cd->cardRemoved(false, cd->userData);
        }
    }
}

static void SDMMCHOST_DetectCardInsertByHost(SDMMCHOST_TYPE *base)
{
    if (SDMMCHOST_CARD_DETECT_INSERT_STATUS(base))
    {
        s_sdInsertedFlag = true;
    }
}

static status_t SDMMCHOST_TransferFunction(SDMMCHOST_TYPE *base, SDMMCHOST_TRANSFER *content)
{
    status_t error = kStatus_Success;

    if (kStatus_Success != SDHC_TransferBlocking(base, s_sdhcAdmaTable, SDHC_ADMA_TABLE_WORDS, content))
    {
        error = kStatus_Fail;
        /* host error recovery */
        SDMMCHOST_ErrorRecovery(base);
    }

    return error;
}

static void SDMMCHOST_ErrorRecovery(SDMMCHOST_TYPE *base)
{
    uint32_t status = false;
    /* get host present status */
    status = SDHC_GetPresentStatusFlags(base);
    /* check command inhibit status flag */
    if ((status & kSDHC_CommandInhibitFlag) != 0U)
    {
        /* reset command line */
        SDHC_Reset(base, kSDHC_ResetCommand, 100U);
    }
    /* check data inhibit status flag */
    if ((status & kSDHC_DataInhibitFlag) != 0U)
    {
        /* reset data line */
        SDHC_Reset(base, kSDHC_ResetData, 100U);
    }
}

static status_t SDMMCHOST_CardDetectInit(SDMMCHOST_TYPE *base, const sdmmchost_detect_card_t *cd)
{
    sdmmchost_detect_card_type_t cdType = kSDMMCHOST_DetectCardByGpioCD;

    if (cd != NULL)
    {
        cdType = cd->cdType;
    }

    if (cdType == kSDMMCHOST_DetectCardByGpioCD)
    {
        SDMMCHOST_DetectCardByGpio(cd);
    }
    else if (cdType == kSDMMCHOST_DetectCardByHostDATA3)
    {
        /* enable card detect through DATA3 */
        SDMMCHOST_CARD_DETECT_DATA3_ENABLE(base, true);
        /* enable card detect status */
        SDMMCHOST_CARD_DETECT_INSERT_ENABLE(base);
    }
    else
    {
        /* SDHC do not support detect card through CD */
        return kStatus_Fail;
    }

    return kStatus_Success;
}

static void SDMMCHOST_CardDetectDeinit(void)
{
    s_sdInsertedFlag = false;
}

void SDMMCHOST_Delay(uint32_t milliseconds)
{
    SDMMCEVENT_Delay(milliseconds);
}

status_t SDMMCHOST_WaitCardDetectStatus(SDMMCHOST_TYPE *base, const sdmmchost_detect_card_t *cd, bool waitCardStatus)
{
    sdmmchost_detect_card_type_t cdType = kSDMMCHOST_DetectCardByGpioCD;

    if (cd != NULL)
    {
        cdType = cd->cdType;
    }

    if (waitCardStatus != s_sdInsertedFlag)
    {
        /* Wait card inserted. */
        do
        {
            if (cdType != kSDMMCHOST_DetectCardByGpioCD)
            {
                SDMMCHOST_DetectCardInsertByHost(base);
            }
            else
            {
                SDMMCHOST_DetectCardByGpio(cd);
            }
        } while (waitCardStatus != s_sdInsertedFlag);
    }

    return kStatus_Success;
}

bool SDMMCHOST_IsCardPresent(void)
{
    return s_sdInsertedFlag;
}

void SDMMCHOST_PowerOffCard(SDMMCHOST_TYPE *base, const sdmmchost_pwr_card_t *pwr)
{
    if (pwr != NULL)
    {
        pwr->powerOff();
        SDMMCHOST_Delay(pwr->powerOffDelay_ms);
    }
}

void SDMMCHOST_PowerOnCard(SDMMCHOST_TYPE *base, const sdmmchost_pwr_card_t *pwr)
{
    /* use user define the power on function  */
    if (pwr != NULL)
    {
        pwr->powerOn();
        SDMMCHOST_Delay(pwr->powerOnDelay_ms);
    }
    else
    {
        /* Delay several milliseconds to make card stable. */
        SDMMCHOST_Delay(1000U);
    }
}

status_t SDMMCHOST_Init(SDMMCHOST_CONFIG *host, void *userData)
{
    sdhc_host_t *sdhcHost = (sdhc_host_t *)host;

    /* init event timer */
    SDMMCEVENT_InitTimer();

    /* Initializes SDHC. */
    sdhcHost->config.cardDetectDat3 = false;
    sdhcHost->config.endianMode = SDHC_ENDIAN_MODE;
    sdhcHost->config.dmaMode = SDHC_DMA_MODE;
    sdhcHost->config.readWatermarkLevel = SDHC_READ_WATERMARK_LEVEL;
    sdhcHost->config.writeWatermarkLevel = SDHC_WRITE_WATERMARK_LEVEL;
    SDHC_Init(sdhcHost->base, &(sdhcHost->config));

    /* Define transfer function. */
    sdhcHost->transfer = SDMMCHOST_TransferFunction;
    /* card detect init */
    SDMMCHOST_CardDetectInit(sdhcHost->base, userData);

    return kStatus_Success;
}

void SDMMCHOST_Reset(SDMMCHOST_TYPE *base)
{
    /* reserved for future */
}

void SDMMCHOST_Deinit(void *host)
{
    sdhc_host_t *sdhcHost = (sdhc_host_t *)host;
    SDHC_Deinit(sdhcHost->base);
    SDMMCHOST_CardDetectDeinit();
}
