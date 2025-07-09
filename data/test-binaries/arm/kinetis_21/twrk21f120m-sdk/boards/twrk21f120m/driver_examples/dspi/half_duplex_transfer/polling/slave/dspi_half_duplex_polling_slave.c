/*
 * The Clear BSD License
 * Copyright 2017 NXP
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

#include "fsl_debug_console.h"
#include "fsl_dspi.h"
#include "board.h"

#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define EXAMPLE_DSPI_SLAVE_BASEADDR SPI0
/* The slave will receive 64 bytes from master, and then send them back.
 * slave will do this operation in one transimission, so the transfer data size is 128,
 * and slave will store the received data from the address of dataBuff[64] in the
 * first half transimission. In the second half transimission, slave will send them
 * back to the master board.
 */
#define BUFFER_SIZE (192)
#define RX_BUFFER_INDEX (64)
#define TRANSFER_DATA_SIZE (128)
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/
static uint8_t dataBuff[BUFFER_SIZE] = {0};

dspi_slave_handle_t handle;
static volatile bool slaveFinished = false;
/*******************************************************************************
 * Code
 ******************************************************************************/
static void slaveCallback(SPI_Type *base, dspi_slave_handle_t *slaveHandle, status_t status, void *userData)
{
    slaveFinished = true;
}

int main(void)
{
    uint32_t i = 0;
    dspi_transfer_t xfer = {0};
    dspi_slave_config_t slaveConfig;

    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    PRINTF("\n\rThis is slave example for DSPI half-duplex polling transfer.");
    PRINTF("\n\rSlave is working....\r\n");

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
    DSPI_SlaveTransferCreateHandle(EXAMPLE_DSPI_SLAVE_BASEADDR, &handle, slaveCallback, NULL);

    /* Receive data from master board for polling half-duplex transfer.*/
    xfer.txData = dataBuff;
    xfer.rxData = &dataBuff[RX_BUFFER_INDEX];
    xfer.dataSize = TRANSFER_DATA_SIZE;
    DSPI_SlaveTransferNonBlocking(EXAMPLE_DSPI_SLAVE_BASEADDR, &handle, &xfer);

    /* Wait for the recieve complete. */
    while (slaveFinished != true)
    {
    }

    PRINTF("\r\nThe received data of half-duplex polling transfer are:");
    for (i = 0; i < BUFFER_SIZE / 3; i++)
    {
        /* Print 16 data in a line. */
        if ((i & 0x0F) == 0)
        {
            PRINTF("\r\n");
        }
        PRINTF("  0x%02X", dataBuff[i + RX_BUFFER_INDEX]);
    }

    PRINTF("\r\n\r\nSlave transfer completed.");

    DSPI_Deinit(EXAMPLE_DSPI_SLAVE_BASEADDR);

    while (1)
    {
    }
}
