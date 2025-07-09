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

/*System includes.*/
#include <stdio.h>

/* Kernel includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "timers.h"

/* Freescale includes. */
#include "fsl_device_registers.h"
#include "fsl_debug_console.h"
#include "board.h"

#include "fsl_common.h"
#include "pin_mux.h"
#include "clock_config.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define MAX_LOG_LENGTH 20
/*******************************************************************************
* Globals
******************************************************************************/
/* Logger queue handle */
static QueueHandle_t log_queue = NULL;
/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/* Application API */
static void write_task_1(void *pvParameters);
static void write_task_2(void *pvParameters);

/* Logger API */
void log_add(char *log);
void log_init(uint32_t queue_length, uint32_t max_log_lenght);
static void log_task(void *pvParameters);
/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief Main function
 */
int main(void)
{
    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_InitDebugConsole();
    /* Initialize logger for 10 logs with maximum lenght of one log 20 B */
    log_init(10, MAX_LOG_LENGTH);
    if (xTaskCreate(write_task_1, "WRITE_TASK_1", configMINIMAL_STACK_SIZE + 166, NULL, tskIDLE_PRIORITY + 2, NULL) !=
        pdPASS)
    {
        PRINTF("Task creation failed!.\r\n");
        while (1)
            ;
    }
    if (xTaskCreate(write_task_2, "WRITE_TASK_2", configMINIMAL_STACK_SIZE + 166, NULL, tskIDLE_PRIORITY + 2, NULL) !=
        pdPASS)
    {
        PRINTF("Task creation failed!.\r\n");
        while (1)
            ;
    }
    vTaskStartScheduler();
    for (;;)
        ;
}

/*******************************************************************************
 * Application functions
 ******************************************************************************/
/*!
 * @brief write_task_1 function
 */
static void write_task_1(void *pvParameters)
{
    char log[MAX_LOG_LENGTH + 1];
    uint32_t i = 0;
    for (i = 0; i < 5; i++)
    {
        sprintf(log, "Task1 Message %d", (int)i);
        log_add(log);
        taskYIELD();
    }
    vTaskSuspend(NULL);
}

/*!
 * @brief write_task_2 function
 */
static void write_task_2(void *pvParameters)
{
    char log[MAX_LOG_LENGTH + 1];
    uint32_t i = 0;
    for (i = 0; i < 5; i++)
    {
        sprintf(log, "Task2 Message %d", (int)i);
        log_add(log);
        taskYIELD();
    }
    vTaskSuspend(NULL);
}

/*******************************************************************************
 * Logger functions
 ******************************************************************************/
/*!
 * @brief log_add function
 */
void log_add(char *log)
{
    xQueueSend(log_queue, log, 0);
}

/*!
 * @brief log_init function
 */
void log_init(uint32_t queue_length, uint32_t max_log_lenght)
{
    log_queue = xQueueCreate(queue_length, max_log_lenght);
    if (xTaskCreate(log_task, "log_task", configMINIMAL_STACK_SIZE + 166, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS)
    {
        PRINTF("Task creation failed!.\r\n");
        while (1)
            ;
    }
}

/*!
 * @brief log_print_task function
 */
static void log_task(void *pvParameters)
{
    uint32_t counter = 0;
    char log[MAX_LOG_LENGTH + 1];
    while (1)
    {
        xQueueReceive(log_queue, log, portMAX_DELAY);
        PRINTF("Log %d: %s\r\n", counter, log);
        counter++;
    }
}
