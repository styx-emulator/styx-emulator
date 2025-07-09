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

#ifndef _FSL_SDIO_H_
#define _FSL_SDIO_H_

#include "fsl_sdmmc_common.h"

/*!
 * @addtogroup SDIOCARD
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*! @brief card user parameter, user can define the parameter according the board, card capability */
typedef struct _sdiocard_usr_param
{
    const sdmmchost_detect_card_t *cd; /*!< card detect type */
    const sdmmchost_pwr_card_t *pwr;   /*!< power control configuration */
} sdiocard_usr_param_t;

/*!
 * @brief SDIO card state
 *
 * Define the card structure including the necessary fields to identify and describe the card.
 */
typedef struct _sdio_card
{
    SDMMCHOST_CONFIG host;         /*!< Host information */
    sdiocard_usr_param_t usrParam; /*!< user parameter */
    bool isHostReady;              /*!< use this flag to indicate if need host re-init or not*/
    bool memPresentFlag;           /*!< indicate if memory present */
    uint32_t busClock_Hz;          /*!< SD bus clock frequency united in Hz */
    uint32_t relativeAddress;      /*!< Relative address of the card */
    uint8_t sdVersion;             /*!< SD version */
    uint8_t sdioVersion;           /*!< SDIO version */
    uint8_t cccrVersioin;          /*!< CCCR version */
    uint8_t ioTotalNumber;         /*!< total number of IO function */
    uint32_t cccrflags;            /*!< Flags in _sd_card_flag */
    uint32_t io0blockSize;         /*!< record the io0 block size*/
    uint32_t ocr;                  /*!< Raw OCR content, only 24bit avalible for SDIO card */
    uint32_t commonCISPointer;     /*!< point to common CIS */

    sdio_fbr_t ioFBR[7U]; /*!< FBR table */

    sdio_common_cis_t commonCIS; /*!< CIS table */
    sdio_func_cis_t funcCIS[7U]; /*!< function CIS table*/

} sdio_card_t;

/*************************************************************************************************
 * API
 ************************************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif
/*!
 * @name SDIOCARD Function
 * @{
 */

/*!
 * @brief SDIO card init function
 *
 * @param card Card descriptor.
 * @retval kStatus_SDMMC_GoIdleFailed
 * @retval kStatus_SDMMC_HandShakeOperationConditionFailed
 * @retval kStatus_SDMMC_SDIO_InvalidCard
 * @retval kStatus_SDMMC_SDIO_InvalidVoltage
 * @retval kStatus_SDMMC_SendRelativeAddressFailed
 * @retval kStatus_SDMMC_SelectCardFailed
 * @retval kStatus_SDMMC_SDIO_SwitchHighSpeedFail
 * @retval kStatus_SDMMC_SDIO_ReadCISFail
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_Init(sdio_card_t *card);

/*!
 * @brief SDIO card deinit, include card and host deinit.
 *
 * @param card Card descriptor.
 */
void SDIO_Deinit(sdio_card_t *card);

/*!
 * @brief Initializes the card.
 *
 * This function initializes the card only, make sure the host is ready when call this function,
 * otherwise it will return kStatus_SDMMC_HostNotReady.
 *
 * @param card Card descriptor.
 * @retval kStatus_SDMMC_HostNotReady host is not ready.
 * @retval kStatus_SDMMC_GoIdleFailed Go idle failed.
 * @retval kStatus_SDMMC_NotSupportYet Card not support.
 * @retval kStatus_SDMMC_SendOperationConditionFailed Send operation condition failed.
 * @retval kStatus_SDMMC_AllSendCidFailed Send CID failed.
 * @retval kStatus_SDMMC_SendRelativeAddressFailed Send relative address failed.
 * @retval kStatus_SDMMC_SendCsdFailed Send CSD failed.
 * @retval kStatus_SDMMC_SelectCardFailed Send SELECT_CARD command failed.
 * @retval kStatus_SDMMC_SendScrFailed Send SCR failed.
 * @retval kStatus_SDMMC_SetBusWidthFailed Set bus width failed.
 * @retval kStatus_SDMMC_SwitchHighSpeedFailed Switch high speed failed.
 * @retval kStatus_SDMMC_SetCardBlockSizeFailed Set card block size failed.
 * @retval kStatus_Success Operate successfully.
 */
status_t SDIO_CardInit(sdio_card_t *card);

/*!
 * @brief Deinitializes the card.
 *
 * This function deinitializes the specific card.
 *
 * @param card Card descriptor.
 */
void SDIO_CardDeinit(sdio_card_t *card);

/*!
 * @brief initialize the host.
 *
 * This function deinitializes the specific host.
 *
 * @param card Card descriptor.
 */
status_t SDIO_HostInit(sdio_card_t *card);

/*!
 * @brief Deinitializes the host.
 *
 * This function deinitializes the host.
 *
 * @param card Card descriptor.
 */
void SDIO_HostDeinit(sdio_card_t *card);

/*!
 * @brief reset the host.
 *
 * This function reset the specific host.
 *
 * @param host host descriptor.
 */
void SDIO_HostReset(SDMMCHOST_CONFIG *host);

/*!
 * @brief power on card.
 *
 * The power on operation depend on host or the user define power on function.
 * @param base host base address.
 * @param pwr user define power control configuration
 */
void SDIO_PowerOnCard(SDMMCHOST_TYPE *base, const sdmmchost_pwr_card_t *pwr);

/*!
 * @brief power on card.
 *
 * The power off operation depend on host or the user define power on function.
 * @param base host base address.
 * @param pwr user define power control configuration
 */
void SDIO_PowerOffCard(SDMMCHOST_TYPE *base, const sdmmchost_pwr_card_t *pwr);

/*!
 * @brief set SDIO card to inactive state
 *
 * @param card Card descriptor.
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_CardInActive(sdio_card_t *card);

/*!
 * @brief IO direct write transfer function
 *
 * @param card Card descriptor.
 * @param function IO numner
 * @param register address
 * @param the data pinter to write
 * @param raw flag, indicate read after write or write only
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_IO_Write_Direct(sdio_card_t *card, sdio_func_num_t func, uint32_t regAddr, uint8_t *data, bool raw);

/*!
 * @brief IO direct read transfer function
 *
 * @param card Card descriptor.
 * @param function IO number
 * @param register address
 * @param data pointer to read
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_IO_Read_Direct(sdio_card_t *card, sdio_func_num_t func, uint32_t regAddr, uint8_t *data);

/*!
 * @brief IO extended write transfer function
 *
 * @param card Card descriptor.
 * @param function IO number
 * @param register address
 * @param data buffer to write
 * @param data count
 * @param write flags
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_SDMMC_SDIO_InvalidArgument
 * @retval kStatus_Success
 */
status_t SDIO_IO_Write_Extended(
    sdio_card_t *card, sdio_func_num_t func, uint32_t regAddr, uint8_t *buffer, uint32_t count, uint32_t flags);
/*!
 * @brief IO extended read transfer function
 *
 * @param card Card descriptor.
 * @param function IO number
 * @param register address
 * @param data buffer to read
 * @param data count
 * @param write flags
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_SDMMC_SDIO_InvalidArgument
 * @retval kStatus_Success
 */
status_t SDIO_IO_Read_Extended(
    sdio_card_t *card, sdio_func_num_t func, uint32_t regAddr, uint8_t *buffer, uint32_t count, uint32_t flags);
/*!
 * @brief get SDIO card capability
 *
 * @param card Card descriptor.
 * @param function IO number
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_GetCardCapability(sdio_card_t *card, sdio_func_num_t func);

/*!
 * @brief set SDIO card block size
 *
 * @param card Card descriptor.
 * @param function io number
 * @param block size
 * @retval kStatus_SDMMC_SetCardBlockSizeFailed
 * @retval kStatus_SDMMC_SDIO_InvalidArgument
 * @retval kStatus_Success
 */
status_t SDIO_SetBlockSize(sdio_card_t *card, sdio_func_num_t func, uint32_t blockSize);

/*!
 * @brief set SDIO card reset
 *
 * @param card Card descriptor.
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_CardReset(sdio_card_t *card);

/*!
 * @brief set SDIO card data bus width
 *
 * @param card Card descriptor.
 * @param data bus width
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_SetDataBusWidth(sdio_card_t *card, sdio_bus_width_t busWidth);

/*!
 * @brief switch the card to high speed
 *
 * @param card Card descriptor.
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_SDMMC_SDIO_SwitchHighSpeedFail
 * @retval kStatus_Success
 */
status_t SDIO_SwitchToHighSpeed(sdio_card_t *card);

/*!
 * @brief read SDIO card CIS for each function
 *
 * @param card Card descriptor.
 * @param function io number
 * @param tuple code list
 * @param tuple code number
 * @retval kStatus_SDMMC_SDIO_ReadCISFail
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_ReadCIS(sdio_card_t *card, sdio_func_num_t func, const uint32_t *tupleList, uint32_t tupleNum);

/*!
 * @brief enable IO interrupt
 *
 * @param card Card descriptor.
 * @param function IO number
 * @param enable/disable flag
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_EnableIOInterrupt(sdio_card_t *card, sdio_func_num_t func, bool enable);

/*!
 * @brief enable IO and wait IO ready
 *
 * @param card Card descriptor.
 * @param function IO number
 * @param enable/disable flag
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_EnableIO(sdio_card_t *card, sdio_func_num_t func, bool enable);

/*!
 * @brief select IO
 *
 * @param card Card descriptor.
 * @param function IO number
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_SelectIO(sdio_card_t *card, sdio_func_num_t func);

/*!
 * @brief Abort IO transfer
 *
 * @param card Card descriptor.
 * @param function IO number
 * @retval kStatus_SDMMC_TransferFailed
 * @retval kStatus_Success
 */
status_t SDIO_AbortIO(sdio_card_t *card, sdio_func_num_t func);

/*!
 * @brief sdio wait card detect function.
 *
 * Detect card through GPIO, CD, DATA3.
 *
 * @param card card descriptor.
 * @param card detect configuration
 * @param waitCardStatus wait card detect status
 */
status_t SDIO_WaitCardDetectStatus(SDMMCHOST_TYPE *hostBase, const sdmmchost_detect_card_t *cd, bool waitCardStatus);

/*!
 * @brief sdio card present check function.
 *
 * @param card card descriptor.
 */
bool SDIO_IsCardPresent(sdio_card_t *card);

/* @} */

#if defined(__cplusplus)
}
#endif
/*! @} */
#endif /* _FSL_SDIO_H_*/
