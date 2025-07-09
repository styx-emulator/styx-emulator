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

/*  Standard C Included Files */
#include <string.h>

/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "timers.h"
#include "semphr.h"

/*  SDK Included Files */
#include "board.h"
#include "fsl_debug_console.h"
#include "fsl_i2c.h"
#include "fsl_i2c_freertos.h"

#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define EXAMPLE_I2C_MASTER_BASE (I2C0_BASE)
#define EXAMPLE_I2C_MASTER_IRQN (I2C0_IRQn)
#define EXAMPLE_I2C_MASTER_CLK_SRC (I2C0_CLK_SRC)
#define EXAMPLE_I2C_MASTER_CLK_FREQ CLOCK_GetFreq((I2C0_CLK_SRC))

#define EXAMPLE_I2C_SLAVE_BASE (I2C1_BASE)
#define EXAMPLE_I2C_SLAVE_IRQN (I2C1_IRQn)
#define EXAMPLE_I2C_SLAVE_CLK_SRC (I2C1_CLK_SRC)
#define EXAMPLE_I2C_SLAVE_CLK_FREQ CLOCK_GetFreq((I2C1_CLK_SRC))

#define SINGLE_BOARD 0
#define BOARD_TO_BOARD 1

#define EXAMPLE_CONNECT_I2C SINGLE_BOARD
#if (EXAMPLE_CONNECT_I2C == BOARD_TO_BOARD)
#define isMASTER 0
#define isSLAVE 1
#define I2C_MASTER_SLAVE isMASTER
#endif

#define EXAMPLE_I2C_MASTER ((I2C_Type *)EXAMPLE_I2C_MASTER_BASE)
#define EXAMPLE_I2C_SLAVE ((I2C_Type *)EXAMPLE_I2C_SLAVE_BASE)

#define I2C_MASTER_SLAVE_ADDR_7BIT (0x7EU)
#define I2C_BAUDRATE (100000) /* 100K */
#define I2C_DATA_LENGTH (32)  /* MAX is 256 */

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

uint8_t g_slave_buff[I2C_DATA_LENGTH];
uint8_t g_master_buff[I2C_DATA_LENGTH];

i2c_master_handle_t *g_m_handle;
i2c_slave_handle_t g_s_handle;
SemaphoreHandle_t i2c_sem;

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* Task priorities. */
#define slave_task_PRIORITY (configMAX_PRIORITIES - 1)
#define master_task_PRIORITY (configMAX_PRIORITIES - 2)
/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static void slave_task(void *pvParameters);
#if ((I2C_MASTER_SLAVE == isMaster) || (EXAMPLE_CONNECT_I2C == SINGLE_BOARD))
static void master_task(void *pvParameters);
#endif

/*******************************************************************************
 * Code
 ******************************************************************************/

int main(void)
{
    /* Init board hardware. */
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();

    /* Set interrupt priorities */
    NVIC_SetPriority(EXAMPLE_I2C_SLAVE_IRQN, 2);
    NVIC_SetPriority(EXAMPLE_I2C_MASTER_IRQN, 3);

    PRINTF("\r\n==FreeRTOS I2C example start.==\r\n");
#if (EXAMPLE_CONNECT_I2C == SINGLE_BOARD)
    PRINTF("This example use one i2c instance as master and another as slave on one board.\r\n");
#elif(EXAMPLE_CONNECT_I2C == BOARD_TO_BOARD)
    PRINTF("This example use two boards to connect with one as master and another as slave.\r\n");
#endif

    if (xTaskCreate(slave_task, "Slave_task", configMINIMAL_STACK_SIZE + 60, NULL, slave_task_PRIORITY, NULL) != pdPASS)
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
 * @brief Data structure and callback function for slave I2C communication.
 */

typedef struct _callback_message_t
{
    status_t async_status;
    SemaphoreHandle_t sem;
} callback_message_t;

#if (I2C_MASTER_SLAVE == isSLAVE)
static void i2c_slave_callback(I2C_Type *base, i2c_slave_transfer_t *xfer, void *userData)
{
    callback_message_t *cb_msg = (callback_message_t *)userData;
    BaseType_t reschedule;

    switch (xfer->event)
    {
        /*  Transmit request */
        case kI2C_SlaveTransmitEvent:
            /*  Update information for transmit process */
            xfer->data = g_slave_buff;
            xfer->dataSize = I2C_DATA_LENGTH;
            break;

        /*  Receive request */
        case kI2C_SlaveReceiveEvent:
            /*  Update information for received process */
            xfer->data = g_slave_buff;
            xfer->dataSize = I2C_DATA_LENGTH;
            break;

        /*  Transfer done */
        case kI2C_SlaveCompletionEvent:
            cb_msg->async_status = xfer->completionStatus;
            xSemaphoreGiveFromISR(cb_msg->sem, &reschedule);
            portYIELD_FROM_ISR(reschedule);
            break;

        default:
            break;
    }
}
#endif

/*!
 * @brief Task responsible for slave I2C communication.
 */

static void slave_task(void *pvParameters)
{
#if ((I2C_MASTER_SLAVE == isSLAVE) || (EXAMPLE_CONNECT_I2C == SINGLE_BOARD))
    i2c_slave_config_t slaveConfig;
#endif

    callback_message_t cb_msg = {0};

    cb_msg.sem = xSemaphoreCreateBinary();
    if (cb_msg.sem == NULL)
    {
        PRINTF("I2C slave: Error creating semaphore\r\n");
        vTaskSuspend(NULL);
    }
    i2c_sem = cb_msg.sem;

#if ((I2C_MASTER_SLAVE == isSLAVE) || (EXAMPLE_CONNECT_I2C == SINGLE_BOARD))
    /* Set up I2C slave */
    /*
     * slaveConfig.addressingMode = kI2C_Address7bit;
     * slaveConfig.enableGeneralCall = false;
     * slaveConfig.enableWakeUp = false;
     * slaveConfig.enableBaudRateCtl = false;
     * slaveConfig.enableSlave = true;
     */
    I2C_SlaveGetDefaultConfig(&slaveConfig);
    slaveConfig.slaveAddress = I2C_MASTER_SLAVE_ADDR_7BIT;
#if defined(FSL_FEATURE_SOC_I2C_COUNT) && FSL_FEATURE_SOC_I2C_COUNT
    slaveConfig.addressingMode = kI2C_Address7bit;
    slaveConfig.upperAddress = 0; /*  not used for this example */
    I2C_SlaveInit(EXAMPLE_I2C_SLAVE, &slaveConfig, EXAMPLE_I2C_SLAVE_CLK_FREQ);
#endif
#if defined(FSL_FEATURE_SOC_II2C_COUNT) && FSL_FEATURE_SOC_II2C_COUNT
    I2C_SlaveInit(EXAMPLE_I2C_SLAVE, &slaveConfig);
#endif
    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        g_slave_buff[i] = 0;
    }

    memset(&g_s_handle, 0, sizeof(g_s_handle));

    I2C_SlaveTransferCreateHandle(EXAMPLE_I2C_SLAVE, &g_s_handle, i2c_slave_callback, &cb_msg);
    I2C_SlaveTransferNonBlocking(EXAMPLE_I2C_SLAVE, &g_s_handle, kI2C_SlaveCompletionEvent);
#endif /* ((I2C_MASTER_SLAVE == isSLAVE) ||  (EXAMPLE_CONNECT_I2C == SINGLE_BOARD)) */

#if ((I2C_MASTER_SLAVE == isMASTER) || (EXAMPLE_CONNECT_I2C == SINGLE_BOARD))
    if (xTaskCreate(master_task, "Master_task", configMINIMAL_STACK_SIZE + 124, NULL, master_task_PRIORITY, NULL) !=
        pdPASS)
    {
        PRINTF("Failed to create master task");
        vTaskSuspend(NULL);
    }
#endif /* ((I2C_MASTER_SLAVE == isMASTER) ||  (EXAMPLE_CONNECT_I2C == SINGLE_BOARD)) */

    /* Wait for transfer to finish */
    xSemaphoreTake(cb_msg.sem, portMAX_DELAY);

#if ((I2C_MASTER_SLAVE == isSLAVE) || (EXAMPLE_CONNECT_DSPI == SINGLE_BOARD))
    if (cb_msg.async_status == kStatus_Success)
    {
        PRINTF("I2C slave transfer completed successfully. \r\n\r\n");
    }
    else
    {
        PRINTF("I2C slave transfer completed with error. \r\n\r\n");
    }

#if (EXAMPLE_CONNECT_I2C == SINGLE_BOARD)
    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        if (g_slave_buff[i] != g_master_buff[i])
        {
            PRINTF("\r\nError occured in this transfer ! \r\n");
            break;
        }
    }
#endif

    PRINTF("Slave received data :");
    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        if (i % 8 == 0)
        {
            PRINTF("\r\n");
        }
        PRINTF("0x%2x  ", g_slave_buff[i]);
    }
    PRINTF("\r\n\r\n");

#if (EXAMPLE_CONNECT_I2C == SINGLE_BOARD)
    /* Set up slave ready to send data to master. */
    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        g_slave_buff[i] = ~g_slave_buff[i];
    }

    PRINTF("This time , slave will send data: :");
    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        if (i % 8 == 0)
        {
            PRINTF("\r\n");
        }
        PRINTF("0x%2x  ", g_slave_buff[i]);
    }
    PRINTF("\r\n\r\n");
#endif
#endif

    /* Wait for transfer to finish */
    xSemaphoreTake(cb_msg.sem, portMAX_DELAY);
#if (EXAMPLE_CONNECT_I2C == BOARD_TO_BOARD)
    PRINTF("\r\nEnd of FreeRTOS I2C example.\r\n");
#endif

    vTaskSuspend(NULL);
}

#if ((I2C_MASTER_SLAVE == isMaster) || (EXAMPLE_CONNECT_I2C == SINGLE_BOARD))
static void master_task(void *pvParameters)
{
    i2c_rtos_handle_t master_rtos_handle;
    i2c_master_config_t masterConfig;
    i2c_master_transfer_t masterXfer;
    uint32_t sourceClock;
    status_t status;

    /* Set up i2c master to send data to slave */
    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        g_master_buff[i] = i;
    }

    PRINTF("Master will send data :");
    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        if (i % 8 == 0)
        {
            PRINTF("\r\n");
        }
        PRINTF("0x%2x  ", g_master_buff[i]);
    }
    PRINTF("\r\n\r\n");

    /*
     * masterConfig.baudRate_Bps = 100000U;
     * masterConfig.enableStopHold = false;
     * masterConfig.glitchFilterWidth = 0U;
     * masterConfig.enableMaster = true;
     */
    I2C_MasterGetDefaultConfig(&masterConfig);
    masterConfig.baudRate_Bps = I2C_BAUDRATE;
    sourceClock = EXAMPLE_I2C_MASTER_CLK_FREQ;

    status = I2C_RTOS_Init(&master_rtos_handle, EXAMPLE_I2C_MASTER, &masterConfig, sourceClock);
    if (status != kStatus_Success)
    {
        PRINTF("I2C master: error during init, %d", status);
    }

    g_m_handle = &master_rtos_handle.drv_handle;

    memset(&masterXfer, 0, sizeof(masterXfer));
    masterXfer.slaveAddress = I2C_MASTER_SLAVE_ADDR_7BIT;
    masterXfer.direction = kI2C_Write;
    masterXfer.subaddress = 0;
    masterXfer.subaddressSize = 0;
    masterXfer.data = g_master_buff;
    masterXfer.dataSize = I2C_DATA_LENGTH;
    masterXfer.flags = kI2C_TransferDefaultFlag;

    status = I2C_RTOS_Transfer(&master_rtos_handle, &masterXfer);
    if (status != kStatus_Success)
    {
        PRINTF("I2C master: error during write transaction, %d", status);
    }

    /* Set up master to receive data from slave. */

    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        g_master_buff[i] = 0;
    }

    masterXfer.slaveAddress = I2C_MASTER_SLAVE_ADDR_7BIT;
    masterXfer.direction = kI2C_Read;
    masterXfer.subaddress = 0;
    masterXfer.subaddressSize = 0;
    masterXfer.data = g_master_buff;
    masterXfer.dataSize = I2C_DATA_LENGTH;
    masterXfer.flags = kI2C_TransferDefaultFlag;

    status = I2C_RTOS_Transfer(&master_rtos_handle, &masterXfer);
    if (status != kStatus_Success)
    {
        PRINTF("I2C master: error during read transaction, %d", status);
    }
#if (EXAMPLE_CONNECT_DSPI == BOARD_TO_BOARD)
    else
    {
        xSemaphoreGive(i2c_sem);
    }
#endif

#if (EXAMPLE_CONNECT_I2C == SINGLE_BOARD)
    /* Transfer completed. Check the data. */
    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        if (g_slave_buff[i] != g_master_buff[i])
        {
            PRINTF("\r\nError occured in the transfer ! \r\n");
            break;
        }
    }
#endif

    PRINTF("Master received data :");
    for (uint32_t i = 0; i < I2C_DATA_LENGTH; i++)
    {
        if (i % 8 == 0)
        {
            PRINTF("\r\n");
        }
        PRINTF("0x%2x  ", g_master_buff[i]);
    }
    PRINTF("\r\n\r\n");

    PRINTF("\r\nEnd of FreeRTOS I2C example.\r\n");

    vTaskSuspend(NULL);
}
#endif //((I2C_MASTER_SLAVE == isMaster) || (EXAMPLE_CONNECT_I2C == SINGLE_BOARD))
