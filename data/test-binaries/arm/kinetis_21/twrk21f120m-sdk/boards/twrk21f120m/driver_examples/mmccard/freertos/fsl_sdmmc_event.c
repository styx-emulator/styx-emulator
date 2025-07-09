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

#include <stdint.h>
#include <stdbool.h>
#include "FreeRTOS.h"
#include "semphr.h"
#include "event_groups.h"
#include "fsl_sdmmc_event.h"

/*******************************************************************************
 * Definitons
 ******************************************************************************/
/*! @brief Convert the milliseconds to ticks in FreeRTOS. */
#define MSEC_TO_TICK(msec) \
    (((uint32_t)(msec) + 500uL / (uint32_t)configTICK_RATE_HZ) * (uint32_t)configTICK_RATE_HZ / 1000uL)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/*!
 * @brief Get event instance.
 * @param eventType The event type
 * @return The event instance's pointer.
 */
static SemaphoreHandle_t *SDMMCEVENT_GetInstance(sdmmc_event_t eventType);

/*******************************************************************************
 * Variables
 ******************************************************************************/
/*! @brief Transfer complete event. */
static SemaphoreHandle_t g_eventTransferComplete;
/*! @brief Card detect event. */
static SemaphoreHandle_t g_eventCardDetect;

/*******************************************************************************
 * Code
 ******************************************************************************/
static SemaphoreHandle_t *SDMMCEVENT_GetInstance(sdmmc_event_t eventType)
{
    SemaphoreHandle_t *event;

    switch (eventType)
    {
        case kSDMMCEVENT_TransferComplete:
            event = &g_eventTransferComplete;
            break;
        case kSDMMCEVENT_CardDetect:
            event = &g_eventCardDetect;
            break;
        default:
            event = NULL;
            break;
    }

    return event;
}

bool SDMMCEVENT_Create(sdmmc_event_t eventType)
{
    SemaphoreHandle_t *event = SDMMCEVENT_GetInstance(eventType);

    if (event)
    {
        *event = xSemaphoreCreateBinary();
        if (*event == NULL)
        {
            return false;
        }

        return true;
    }
    else
    {
        return false;
    }
}

bool SDMMCEVENT_Wait(sdmmc_event_t eventType, uint32_t timeoutMilliseconds)
{
    uint32_t timeoutTicks;
    SemaphoreHandle_t *event = SDMMCEVENT_GetInstance(eventType);

    if (timeoutMilliseconds && event)
    {
        if (timeoutMilliseconds == ~0U)
        {
            timeoutTicks = portMAX_DELAY;
        }
        else
        {
            timeoutTicks = MSEC_TO_TICK(timeoutMilliseconds);
        }
        if (xSemaphoreTake(*event, timeoutTicks) == pdFALSE)
        {
            return false; /* timeout */
        }
        else
        {
            return true; /* event taken */
        }
    }
    else
    {
        return false;
    }
}

bool SDMMCEVENT_Notify(sdmmc_event_t eventType)
{
    SemaphoreHandle_t *event = SDMMCEVENT_GetInstance(eventType);
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    BaseType_t xResult = pdFAIL;

    if (event)
    {
        xResult = xSemaphoreGiveFromISR(*event, &xHigherPriorityTaskWoken);
        if (xResult != pdFAIL)
        {
            portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}

void SDMMCEVENT_Delete(sdmmc_event_t eventType)
{
    SemaphoreHandle_t *event = SDMMCEVENT_GetInstance(eventType);

    if (event)
    {
        vSemaphoreDelete(*event);
    }
}

void SDMMCEVENT_Delay(uint32_t milliseconds)
{
    vTaskDelay(MSEC_TO_TICK(milliseconds));
}
