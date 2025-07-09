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

/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "timers.h"

/* Freescale includes. */
#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "fsl_dspi.h"
#include "fsl_dspi_freertos.h"
#include "board.h"

#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
* Definitions
******************************************************************************/
#define EXAMPLE_DSPI_MASTER_BASE (SPI0_BASE)

#define EXAMPLE_DSPI_SLAVE_BASE (SPI1_BASE)

#define EXAMPLE_DSPI_MASTER_IRQN (SPI0_IRQn)
#define EXAMPLE_DSPI_SLAVE_IRQN (SPI1_IRQn)

#define DSPI_MASTER_CLK_SRC (DSPI0_CLK_SRC)
#define DSPI_MASTER_CLK_FREQ CLOCK_GetFreq((DSPI0_CLK_SRC))

#define SINGLE_BOARD 0
#define BOARD_TO_BOARD 1

#define EXAMPLE_CONNECT_DSPI SINGLE_BOARD
#if (EXAMPLE_CONNECT_DSPI == BOARD_TO_BOARD)
#define isMASTER 0
#define isSLAVE 1
#define SPI_MASTER_SLAVE isMASTER
#endif
#define EXAMPLE_DSPI_MASTER_BASEADDR ((SPI_Type *)EXAMPLE_DSPI_MASTER_BASE)
#define EXAMPLE_DSPI_SLAVE_BASEADDR ((SPI_Type *)EXAMPLE_DSPI_SLAVE_BASE)

#define TRANSFER_SIZE (256)         /*! Transfer size */
#define TRANSFER_BAUDRATE (500000U) /*! Transfer baudrate - 500k */

/*******************************************************************************
* Variables
******************************************************************************/
uint8_t masterReceiveBuffer[TRANSFER_SIZE] = {0};
uint8_t masterSendBuffer[TRANSFER_SIZE] = {0};
uint8_t slaveReceiveBuffer[TRANSFER_SIZE] = {0};
uint8_t slaveSendBuffer[TRANSFER_SIZE] = {0};

dspi_slave_handle_t g_s_handle;
SemaphoreHandle_t dspi_sem;
/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* Task priorities. */
#define slave_task_PRIORITY (configMAX_PRIORITIES - 2)
#define master_task_PRIORITY (configMAX_PRIORITIES - 1)
/* Interrupt priorities. */
#define DSPI_NVIC_PRIO 2

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static void slave_task(void *pvParameters);
#if ((SPI_MASTER_SLAVE == isMaster) || (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD))
static void master_task(void *pvParameters);
#endif

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Application entry point.
 */
int main(void)
{
    /* Init board hardware. */
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    /* Set interrupt priorities */
    NVIC_SetPriority(EXAMPLE_DSPI_SLAVE_IRQN, 2);
    NVIC_SetPriority(EXAMPLE_DSPI_MASTER_IRQN, 3);

    PRINTF("FreeRTOS DSPI example start.\r\n");
#if (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD)
    PRINTF("This example use one dspi instance as master and another as slave on one board.\r\n");
#elif(EXAMPLE_CONNECT_DSPI == BOARD_TO_BOARD)
    PRINTF("This example use two boards to connect with one as master and anohter as slave.\r\n");
#endif
    PRINTF("Master and slave are both use interrupt way.\r\n");
    PRINTF("Please make sure you make the correct line connection. Basically, the connection is: \r\n");
    PRINTF("DSPI_master -- DSPI_slave   \r\n");
    PRINTF("   CLK      --    CLK  \r\n");
    PRINTF("   PCS0     --    PCS0 \r\n");
    PRINTF("   SOUT     --    SIN  \r\n");
    PRINTF("   SIN      --    SOUT \r\n");
#if (EXAMPLE_CONNECT_DSPI == BOARD_TO_BOARD)
    PRINTF("   GND      --    GND \r\n");
#endif

    if (xTaskCreate(slave_task, "Slave_task", configMINIMAL_STACK_SIZE + 64, NULL, slave_task_PRIORITY, NULL) != pdPASS)
    {
        PRINTF("Failed to create slave task");
        while (1)
            ;
    }

    vTaskStartScheduler();
    for (;;)
        ;
}

/*!
 * @brief Data structure and callback function for slave SPI communication.
 */

typedef struct _callback_message_t
{
    status_t async_status;
    SemaphoreHandle_t sem;
} callback_message_t;

void DSPI_SlaveUserCallback(SPI_Type *base, dspi_slave_handle_t *handle, status_t status, void *userData)
{
    callback_message_t *cb_msg = (callback_message_t *)userData;
    BaseType_t reschedule;

    cb_msg->async_status = status;
    xSemaphoreGiveFromISR(cb_msg->sem, &reschedule);
    portYIELD_FROM_ISR(reschedule);
}

/*!
 * @brief Task responsible for slave SPI communication.
 */
static void slave_task(void *pvParameters)
{
#if ((SPI_MASTER_SLAVE == isSLAVE) || (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD))
    dspi_slave_config_t slaveConfig;
    dspi_transfer_t slaveXfer;
#endif
    uint32_t errorCount;
    uint32_t i;
    callback_message_t cb_msg;

    cb_msg.sem = xSemaphoreCreateBinary();
    dspi_sem = cb_msg.sem;
    if (cb_msg.sem == NULL)
    {
        PRINTF("DSPI slave: Error creating semaphore\r\n");
        vTaskSuspend(NULL);
    }
    /*Set up the transfer data*/
    for (i = 0; i < TRANSFER_SIZE; i++)
    {
        masterSendBuffer[i] = i % 256;
        masterReceiveBuffer[i] = 0;

        slaveSendBuffer[i] = ~masterSendBuffer[i];
        slaveReceiveBuffer[i] = 0;
    }
#if ((SPI_MASTER_SLAVE == isSLAVE) || (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD))
    /*Slave config*/
    slaveConfig.whichCtar = kDSPI_Ctar0;
    slaveConfig.ctarConfig.bitsPerFrame = 8;
    slaveConfig.ctarConfig.cpol = kDSPI_ClockPolarityActiveHigh;
    slaveConfig.ctarConfig.cpha = kDSPI_ClockPhaseFirstEdge;
    slaveConfig.enableContinuousSCK = false;
    slaveConfig.enableRxFifoOverWrite = false;
    slaveConfig.enableModifiedTimingFormat = false;
    slaveConfig.samplePoint = kDSPI_SckToSin0Clock;

    DSPI_SlaveInit(EXAMPLE_DSPI_SLAVE_BASEADDR, &slaveConfig);

    /*Set up slave first */
    DSPI_SlaveTransferCreateHandle(EXAMPLE_DSPI_SLAVE_BASEADDR, &g_s_handle, DSPI_SlaveUserCallback, &cb_msg);

    /*Set slave transfer ready to receive/send data*/
    slaveXfer.txData = slaveSendBuffer;
    slaveXfer.rxData = slaveReceiveBuffer;
    slaveXfer.dataSize = TRANSFER_SIZE;
    slaveXfer.configFlags = kDSPI_SlaveCtar0;

    DSPI_SlaveTransferNonBlocking(EXAMPLE_DSPI_SLAVE_BASEADDR, &g_s_handle, &slaveXfer);
#endif /* ((SPI_MASTER_SLAVE == isSLAVE) ||  (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD)) */

#if ((SPI_MASTER_SLAVE == isMASTER) || (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD))
    if (xTaskCreate(master_task, "Master_task", configMINIMAL_STACK_SIZE + 64, NULL, master_task_PRIORITY, NULL) !=
        pdPASS)
    {
        PRINTF("Failed to create master task");
        vTaskSuspend(NULL);
    }
#endif /* ((SPI_MASTER_SLAVE == isMASTER) ||  (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD)) */

    /* Wait for transfer to finish */
    xSemaphoreTake(cb_msg.sem, portMAX_DELAY);
#if ((SPI_MASTER_SLAVE == isSLAVE) || (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD))
    if (cb_msg.async_status == kStatus_Success)
    {
        PRINTF("DSPI slave transfer completed successfully. \r\n\r\n");
    }
    else
    {
        PRINTF("DSPI slave transfer completed with error. \r\n\r\n");
    }
#endif
    errorCount = 0;
    for (i = 0; i < TRANSFER_SIZE; i++)
    {
#if (EXAMPLE_CONNECT_DSPI == BOARD_TO_BOARD)
#if (SPI_MASTER_SLAVE == isMASTER)
        if (slaveSendBuffer[i] != masterReceiveBuffer[i])
        {
            errorCount++;
        }
#elif(SPI_MASTER_SLAVE == isSLAVE)
        if (masterSendBuffer[i] != slaveReceiveBuffer[i])
        {
            errorCount++;
        }
#endif
#elif(EXAMPLE_CONNECT_DSPI == SINGLE_BOARD)
        if (masterSendBuffer[i] != slaveReceiveBuffer[i])
        {
            errorCount++;
        }

        if (slaveSendBuffer[i] != masterReceiveBuffer[i])
        {
            errorCount++;
        }
#endif
    }
    if (errorCount == 0)
    {
        PRINTF("DSPI transfer all data matched! \r\n");
    }
    else
    {
        PRINTF("Error occured in DSPI transfer ! \r\n");
    }

    vTaskSuspend(NULL);
}

/*!
 * @brief Task responsible for master SPI communication.
 */
#if ((SPI_MASTER_SLAVE == isMaster) || (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD))
static void master_task(void *pvParameters)
{
    dspi_transfer_t masterXfer;
    dspi_rtos_handle_t master_rtos_handle;
    dspi_master_config_t masterConfig;
    uint32_t sourceClock;
    status_t status;

    /*Master config*/
    masterConfig.whichCtar = kDSPI_Ctar0;
    masterConfig.ctarConfig.baudRate = TRANSFER_BAUDRATE;
    masterConfig.ctarConfig.bitsPerFrame = 8;
    masterConfig.ctarConfig.cpol = kDSPI_ClockPolarityActiveHigh;
    masterConfig.ctarConfig.cpha = kDSPI_ClockPhaseFirstEdge;
    masterConfig.ctarConfig.direction = kDSPI_MsbFirst;
    masterConfig.ctarConfig.pcsToSckDelayInNanoSec = 2000;
    masterConfig.ctarConfig.lastSckToPcsDelayInNanoSec = 2000;
    masterConfig.ctarConfig.betweenTransferDelayInNanoSec = 1000;

    masterConfig.whichPcs = kDSPI_Pcs0;
    masterConfig.pcsActiveHighOrLow = kDSPI_PcsActiveLow;

    masterConfig.enableContinuousSCK = false;
    masterConfig.enableRxFifoOverWrite = false;
    masterConfig.enableModifiedTimingFormat = false;
    masterConfig.samplePoint = kDSPI_SckToSin0Clock;

    sourceClock = DSPI_MASTER_CLK_FREQ;
    status = DSPI_RTOS_Init(&master_rtos_handle, EXAMPLE_DSPI_MASTER_BASEADDR, &masterConfig, sourceClock);

    if (status != kStatus_Success)
    {
        PRINTF("DSPI master: error during initialization. \r\n");
        vTaskSuspend(NULL);
    }
    /*Start master transfer*/
    masterXfer.txData = masterSendBuffer;
    masterXfer.rxData = masterReceiveBuffer;
    masterXfer.dataSize = TRANSFER_SIZE;
    masterXfer.configFlags = kDSPI_MasterCtar0 | kDSPI_MasterPcs0 | kDSPI_MasterPcsContinuous;

    status = DSPI_RTOS_Transfer(&master_rtos_handle, &masterXfer);

    if (status == kStatus_Success)
    {
#if (EXAMPLE_CONNECT_DSPI == BOARD_TO_BOARD)
        xSemaphoreGive(dspi_sem);
#endif
        PRINTF("DSPI master transfer completed successfully. \r\n\r\n");
    }
    else
    {
        PRINTF("DSPI master transfer completed with error. \r\n\r\n");
    }

    vTaskSuspend(NULL);
}
#endif //((SPI_MASTER_SLAVE == isMaster) || (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD))
