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

#ifndef _IEEE11073_TIMER_H_
#define _IEEE11073_TIMER_H_

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief max timer object support */
#ifndef IEEE_MAX_TIMER_OBJECTS
#define IEEE_MAX_TIMER_OBJECTS 0U
#endif
#if IEEE_MAX_TIMER_OBJECTS

/*! @brief timer callback function prototype */
typedef void (*ieee11073_timer_callback)(void *timerArgument);

/*! @brief timer object structure */
typedef struct _ieee11073_timer_object
{
    int32_t timerCount;                     /*!< Time out value in seconds */
    ieee11073_timer_callback timerCallback; /*!< Callback function */
    void *timerArgument;                    /*!< Callback function argument */
} ieee11073_timer_object_t;

/*******************************************************************************
 * API
 ******************************************************************************/

/*! @brief global function prototypes */
#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief timer initialization.
 *
 * This function initializes the timer object queue and system clock counter.
 *
 * @param controller_ID     the identify of timer controller.
 *
 * @retval success of error.
 */
extern void IEEE_TimerInit(void);

/*!
 * @brief add timer queue.
 *
 * This function is called to add timer object to timer queue.
 *
 * @param pTimerObject      timer object.
 *
 * @retval success of error.
 */
extern uint8_t IEEE_AddTimerQueue(ieee11073_timer_object_t *timerObject);

/*!
 * @brief remove timer queue.
 *
 * This function is called to remove timer object from timer queue.
 *
 * @param pTimerObject      index of timer object in queue.
 *
 * @retval success of error.
 */
extern void IEEE_RemoveTimerQueue(uint8_t timerIndex);
#if defined(__cplusplus)
}
#endif
#endif
#endif
/* _IEEE11073_TIMER_H_ */
