/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
 * All rights reserved.
 *
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
 * DISCLAIMED. IN NO EVENT SL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _FSL_SDSPI_DISK_H_
#define _FSL_SDSPI_DISK_H_

#include <stdint.h>
#include "diskio.h"
#include "fsl_common.h"
#include "board.h"

/*!
 * @addtogroup SD Disk over SPI
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* DSPI clock source */
#if (BOARD_SDSPI_SPI_BASE == SPI0_BASE)
#define DSPI_MASTER_CLK_SRC (DSPI0_CLK_SRC)
#elif(BOARD_SDSPI_SPI_BASE == SPI1_BASE)
#define DSPI_MASTER_CLK_SRC (DSPI0_CLK_SRC)
#elif(BOARD_SDSPI_SPI_BASE == SPI2_BASE)
#define DSPI_MASTER_CLK_SRC (DSPI2_CLK_SRC)
#elif(BOARD_SDSPI_SPI_BASE == SPI3_BASE)
#define DSPI_MASTER_CLK_SRC (DSPI3_CLK_SRC)
#elif(BOARD_SDSPI_SPI_BASE == SPI4_BASE)
#define DSPI_MASTER_CLK_SRC (DSPI4_CLK_SRC)
#else
#error Should define the DSPI_MASTER_CLK_SRC!
#endif

/* Which PCS used to select the slave */
#if (BOARD_SDSPI_SPI_PCS_NUMBER == 0U)
#define DSPI_MASTER_PCS_CONFIG kDSPI_Pcs0
#define DSPI_MASTER_PCS_TRANSFER kDSPI_MasterPcs0
#elif(BOARD_SDSPI_SPI_PCS_NUMBER == 1U)
#define DSPI_MASTER_PCS_CONFIG kDSPI_Pcs1
#define DSPI_MASTER_PCS_TRANSFER kDSPI_MasterPcs1
#elif(BOARD_SDSPI_SPI_PCS_NUMBER == 2U)
#define DSPI_MASTER_PCS_CONFIG kDSPI_Pcs2
#define DSPI_MASTER_PCS_TRANSFER kDSPI_MasterPcs2
#elif(BOARD_SDSPI_SPI_PCS_NUMBER == 3U)
#define DSPI_MASTER_PCS_CONFIG kDSPI_Pcs3
#define DSPI_MASTER_PCS_TRANSFER kDSPI_MasterPcs3
#elif(BOARD_SDSPI_SPI_PCS_NUMBER == 4U)
#define DSPI_MASTER_PCS_CONFIG kDSPI_Pcs4
#define DSPI_MASTER_PCS_TRANSFER kDSPI_MasterPcs4
#elif(BOARD_SDSPI_SPI_PCS_NUMBER == 5U)
#define DSPI_MASTER_PCS_CONFIG kDSPI_Pcs5
#define DSPI_MASTER_PCS_TRANSFER kDSPI_MasterPcs5
#endif

#define DSPI_MASTER_CTAR (kDSPI_Ctar0) /* The CTAR to describle the transfer attribute */
#define DSPI_BUS_BAUDRATE (500000U)    /* Transfer baudrate - 500k */
/*************************************************************************************************
 * API - SD disk interface
 ************************************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @name SD over SPI Disk Function
 * @{
 */

/*!
 * @brief Initializes SD disk over SPI.
 *
 * @param physicalDrive Physical drive number.
 * @retval STA_NOINIT Failed.
 * @retval RES_OK Success.
 */
DSTATUS sdspi_disk_initialize(uint8_t physicalDrive);

/*!
 * Gets SD over SPI disk status
 *
 * @param physicalDrive Physical drive number.
 * @retval STA_NOINIT Failed.
 * @retval RES_OK Success.
 */
DSTATUS sdspi_disk_status(uint8_t physicalDrive);

/*!
 * @brief Reads SD disk over SPI.
 *
 * @param physicalDrive Physical drive number.
 * @param buffer The data buffer pointer to store read content.
 * @param sector The start sector number to be read.
 * @param count The sector count to be read.
 * @retval RES_PARERR Failed.
 * @retval RES_OK Success.
 */
DRESULT sdspi_disk_read(uint8_t physicalDrive, uint8_t *buffer, uint32_t sector, uint8_t count);

/*!
 * @brief Writes to SD disk over SPI.
 *
 * @param physicalDrive Physical drive number.
 * @param buffer The data buffer pointer to store write content.
 * @param sector The start sector number to be written.
 * @param count The sector count to be written.
 * @retval RES_PARERR Failed.
 * @retval RES_OK Success.
 */
DRESULT sdspi_disk_write(uint8_t physicalDrive, const uint8_t *buffer, uint32_t sector, uint8_t count);

/*!
 * @brief SD over SPI disk IO operation.
 *
 * @param physicalDrive Physical drive number.
 * @param command The command to be set.
 * @param buffer The buffer to store command result.
 * @retval RES_PARERR Failed.
 * @retval RES_OK Success.
 */
DRESULT sdspi_disk_ioctl(uint8_t physicalDrive, uint8_t command, void *buffer);

/*************************************************************************************************
 * API - SPI interface
 ************************************************************************************************/
/*!
 * @brief Initializes the SPI.
 */
void spi_init(void);

/*!
 * @brief Sets the SPI bus frequency.
 *
 * @param frequency The frequency to set.
 * @retval kStatus_Success Success.
 * @retval kStatus_Fail Failed.
 */
status_t spi_set_frequency(uint32_t frequency);

/*!
 * @brief Transfers data over SPI bus in full-duplex way.
 *
 * @param in The buffer to save the data to be sent.
 * @param out The buffer to save the data to be read.
 * @param size The transfer data size.
 * @return The status of the function DSPI_MasterTransferPolling().
 */
status_t spi_exchange(uint8_t *in, uint8_t *out, uint32_t size);

/*!
 * @brief Initializes the timer to generator 1ms interrupt used to get current time in milliseconds.
 */
void timer_init(void);

/*!
 * @brief Gets current time in milliseconds.
 *
 * @return Current time in milliseconds.
 */
uint32_t timer_get_current_milliseconds(void);

/*!
 * @brief Initializes the host descriptor.
 */
void sdspi_host_init(void);

/* @} */
#if defined(__cplusplus)
}
#endif

#endif /* _FSL_SDSPI_DISK_H_ */
