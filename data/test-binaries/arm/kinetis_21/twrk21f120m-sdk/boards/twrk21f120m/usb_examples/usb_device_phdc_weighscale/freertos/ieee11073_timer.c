/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
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

#include "usb_device_config.h"
#include "usb.h"
#include "timers.h"
#include "board.h"
#include "ieee11073_timer.h"
#if ((defined IEEE_MAX_TIMER_OBJECTS) && (IEEE_MAX_TIMER_OBJECTS > 0))
#include "stdio.h"
#include "string.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define IEEE11073_TIMER_PERIOD (1000 / portTICK_PERIOD_MS)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

static void IEEE_TimerISR(TimerHandle_t xTimer);

/*******************************************************************************
 * Variables
 ******************************************************************************/

static TimerHandle_t s_ieee11073TimerHandle = NULL;
static uint8_t s_ieee11073TimerLevel;
/*! @brief array of timer objects */
ieee11073_timer_object_t s_ieee11073TimerObjectArray[IEEE_MAX_TIMER_OBJECTS];

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * @brief timer initialization.
 *
 * This function initializes the timer object queue and system clock counter.
 *
 * @param controller_ID     the identify of timer controller.
 *
 * @retval success of error.
 */
void IEEE_TimerInit(void)
{
    /* Create the phdTimer timer. */
    s_ieee11073TimerHandle = xTimerCreate("phdTimer", IEEE11073_TIMER_PERIOD, pdTRUE, 0, IEEE_TimerISR);
    s_ieee11073TimerLevel = 0U;
    /* Clear timer queue */
    (void)memset(s_ieee11073TimerObjectArray, 0U, sizeof(s_ieee11073TimerObjectArray));
}

/*!
 * @brief add timer queue.
 *
 * This function is called to add timer object to timer queue.
 *
 * @param timerObject       Timer object.
 *
 * @retval timerIndex       The timer queue is not full.
 * @retval -1               The input timer object is NULL.
                            The timer queue is full.
 */
uint8_t IEEE_AddTimerQueue(ieee11073_timer_object_t *timerObject)
{
    if (NULL != timerObject)
    {
        /* Timer Index return value */
        uint8_t timerIndex = 0U;
        /* Queue full checking */
        uint8_t isQueueFull = 1U;
        /* Add timerObject to queue */
        for (timerIndex = 0U; timerIndex < IEEE_MAX_TIMER_OBJECTS; timerIndex++)
        {
            if (s_ieee11073TimerObjectArray[timerIndex].timerCallback == NULL)
            {
                isQueueFull = 0U;
                (void)memcpy(&s_ieee11073TimerObjectArray[timerIndex], timerObject, sizeof(ieee11073_timer_object_t));
                break;
            }
        }
        if (isQueueFull)
        {
            /* Timer queue is full */
            return (uint8_t)-1;
        }
        else
        {
            if (0U == s_ieee11073TimerLevel)
            {
                /* Start timer */
                xTimerStartFromISR(s_ieee11073TimerHandle, 0);
            }
            s_ieee11073TimerLevel++;
            return timerIndex;
        }
    }
    /* Invalid parameter */
    return (uint8_t)-1;
}

/*!
 * @brief remove timer queue.
 *
 * This function is called to remove timer object from timer queue.
 *
 * @param timerIndex      index of timer object in queue.
 */
void IEEE_RemoveTimerQueue(uint8_t timerIndex)
{
    if (timerIndex < IEEE_MAX_TIMER_OBJECTS)
    {
        if (NULL != s_ieee11073TimerObjectArray[timerIndex].timerCallback)
        {
            /* Clear the time object in queue corresponding with timerIndex */
            (void)memset(&s_ieee11073TimerObjectArray[timerIndex], 0U, sizeof(ieee11073_timer_object_t));
            s_ieee11073TimerObjectArray[timerIndex].timerCallback = NULL;
            if (s_ieee11073TimerLevel)
            {
                s_ieee11073TimerLevel--;
            }
            if (0U == s_ieee11073TimerLevel)
            {
                /* Stop timer */
                xTimerStopFromISR(s_ieee11073TimerHandle, 0);
            }
        }
    }
}

/*!
 * @brief timer interrupt service function.
 *
 * This function services programmable interrupt timer when a timer object
 * expired, then removes the timer object from timer queue and calls to the
 * callback function (if registered).
 */
static void IEEE_TimerISR(TimerHandle_t xTimer)
{
    uint8_t index;
    for (index = 0U; index < IEEE_MAX_TIMER_OBJECTS; index++)
    {
        if (NULL != s_ieee11073TimerObjectArray[index].timerCallback)
        {
            ieee11073_timer_object_t *timerObject = &s_ieee11073TimerObjectArray[index];
            timerObject->timerCount--;
            if (timerObject->timerCount <= 0U)
            {
                /* Call Pending Timer CallBacks */
                timerObject->timerCallback(timerObject->timerArgument);
                /* remove timer object from timer queue */
                IEEE_RemoveTimerQueue(index);
            }
        }
    }
}
#endif
