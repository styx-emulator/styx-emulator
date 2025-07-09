/*
 * The Clear BSD License
 * Copyright (c) 2013 - 2015, Freescale Semiconductor, Inc.
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

#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "fsl_dspi.h"
#include "board.h"

#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define EXAMPLE_DSPI_SLAVE_BASEADDR SPI0
#define TRANSFER_SIZE 64U /*! Transfer dataSize */

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/* DSPI user callback */
void DSPI_SlaveUserCallback(SPI_Type *base, dspi_slave_handle_t *handle, status_t status, void *userData);

/*******************************************************************************
 * Variables
 ******************************************************************************/
uint8_t slaveRxData[TRANSFER_SIZE] = {0U};

dspi_slave_handle_t g_s_handle;
volatile bool isTransferCompleted = false;

/*******************************************************************************
 * Code
 ******************************************************************************/

void DSPI_SlaveUserCallback(SPI_Type *base, dspi_slave_handle_t *handle, status_t status, void *userData)
{
    if (status == kStatus_Success)
    {
        PRINTF("This is DSPI slave transfer completed callback. \r\n");
        PRINTF("It's a successful transfer. \r\n\r\n");
    }

    if (status == kStatus_DSPI_Error)
    {
        PRINTF("This is DSPI slave transfer completed callback. \r\n");
        PRINTF("Error occured in this transfer. \r\n\r\n");
    }

    isTransferCompleted = true;
}

/*!
 * @brief Main function
 */
int main(void)
{
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    PRINTF("DSPI board to board polling example.\r\n");

    uint32_t i;
    dspi_slave_config_t slaveConfig;
    dspi_transfer_t slaveXfer;

    /* Slave config */
    slaveConfig.whichCtar = kDSPI_Ctar0;
    slaveConfig.ctarConfig.bitsPerFrame = 8U;
    slaveConfig.ctarConfig.cpol = kDSPI_ClockPolarityActiveHigh;
    slaveConfig.ctarConfig.cpha = kDSPI_ClockPhaseFirstEdge;
    slaveConfig.enableContinuousSCK = false;
    slaveConfig.enableRxFifoOverWrite = false;
    slaveConfig.enableModifiedTimingFormat = false;
    slaveConfig.samplePoint = kDSPI_SckToSin0Clock;

    DSPI_SlaveInit(EXAMPLE_DSPI_SLAVE_BASEADDR, &slaveConfig);

    DSPI_SlaveTransferCreateHandle(EXAMPLE_DSPI_SLAVE_BASEADDR, &g_s_handle, DSPI_SlaveUserCallback, NULL);

    while (1)
    {
        PRINTF("\r\n Slave example is running...\r\n");

        /* Reset the receive buffer */
        for (i = 0U; i < TRANSFER_SIZE; i++)
        {
            slaveRxData[i] = 0U;
        }

        /* Set slave transfer ready to receive data */
        isTransferCompleted = false;
        slaveXfer.txData = NULL;
        slaveXfer.rxData = slaveRxData;
        slaveXfer.dataSize = TRANSFER_SIZE;
        slaveXfer.configFlags = kDSPI_SlaveCtar0;

        /* Slave start receive */
        DSPI_SlaveTransferNonBlocking(EXAMPLE_DSPI_SLAVE_BASEADDR, &g_s_handle, &slaveXfer);

        while (!isTransferCompleted)
        {
        }

        /* Set slave transfer ready to send back data */
        isTransferCompleted = false;
        slaveXfer.txData = slaveRxData;
        slaveXfer.rxData = NULL;
        slaveXfer.dataSize = TRANSFER_SIZE;
        slaveXfer.configFlags = kDSPI_SlaveCtar0;

        /* Slave start send */
        DSPI_SlaveTransferNonBlocking(EXAMPLE_DSPI_SLAVE_BASEADDR, &g_s_handle, &slaveXfer);

        while (!isTransferCompleted)
        {
        }

        /* Print out receive buffer */
        PRINTF("\r\n Slave received:");
        for (i = 0U; i < TRANSFER_SIZE; i++)
        {
            /* Print 16 numbers in a line */
            if ((i & 0x0FU) == 0U)
            {
                PRINTF("\r\n    ");
            }
            PRINTF(" %02X", slaveRxData[i]);
        }
        PRINTF("\r\n");
    }
}
