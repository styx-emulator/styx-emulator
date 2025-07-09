/*
 * The Clear BSD License
 * Copyright (c) 2015-2016, Freescale Semiconductor, Inc.
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

#ifndef _FSL_SMARTCARD_RTOS_H_
#define _FSL_SMARTCARD_RTOS_H_

#include "fsl_smartcard.h"
#if (defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && (FSL_FEATURE_SOC_EMVSIM_COUNT))
#include "fsl_smartcard_emvsim.h"
#else
#include "fsl_smartcard_uart.h"
#endif

#include "fsl_smartcard_phy.h"

#include <FreeRTOS.h>
#include <event_groups.h>
#include <semphr.h>

/*!
 * @addtogroup smartcard_freertos_driver
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief Smart card RTOS transfer complete flag */
#define RTOS_SMARTCARD_COMPLETE 0x1u

/*! @brief Smart card RTOS transfer time-out flag */
#define RTOS_SMARTCARD_TIMEOUT 0x2u

/*! @brief Common Smart card driver API defines */
#if (defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && (FSL_FEATURE_SOC_EMVSIM_COUNT))
#define SMARTCARD_Control(base, context, control, param) \
    SMARTCARD_EMVSIM_Control(base, context, control, param) /*!< Common Smart card API macro */
#define SMARTCARD_Transfer(base, context, xfer) \
    SMARTCARD_EMVSIM_TransferNonBlocking(base, context, xfer) /*!< Common Smart card API macro */
#define SMARTCARD_AbortTransfer(base, context) \
    SMARTCARD_EMVSIM_AbortTransfer(base, context) /*!< Common Smart card API macro */
#define SMARTCARD_Init(base, context, sourceClockHz) \
    SMARTCARD_EMVSIM_Init(base, context, sourceClockHz)      /*!< Common Smart card API macro */
#define SMARTCARD_Deinit(base) SMARTCARD_EMVSIM_Deinit(base) /*!< Common Smart card API macro */
#define SMARTCARD_GetTransferRemainingBytes(base, context) \
    SMARTCARD_EMVSIM_GetTransferRemainingBytes(base, context) /*!< Common Smart card API macro */
#define SMARTCARD_GetDefaultConfig(cardParams) \
    SMARTCARD_EMVSIM_GetDefaultConfig(cardParams) /*!< Common Smart card API macro */
#else                                             /* Smart card module is UART */
#define SMARTCARD_Control(base, context, control, param) \
    SMARTCARD_UART_Control(base, context, control, 0) /*!< Common Smart card API macro */
#define SMARTCARD_Transfer(base, context, xfer) \
    SMARTCARD_UART_TransferNonBlocking(base, context, xfer) /*!< Common Smart card API macro */
#define SMARTCARD_AbortTransfer(base, context) \
    SMARTCARD_UART_AbortTransfer(base, context) /*!< Common Smart card API macro */
#define SMARTCARD_Init(base, context, sourceClockHz) \
    SMARTCARD_UART_Init(base, context, sourceClockHz)      /*!< Common Smart card API macro */
#define SMARTCARD_Deinit(base) SMARTCARD_UART_Deinit(base) /*!< Common Smart card API macro */
#define SMARTCARD_GetTransferRemainingBytes(base, context) \
    SMARTCARD_UART_GetTransferRemainingBytes(base, context) /*!< Common Smart card API macro */
#define SMARTCARD_GetDefaultConfig(cardParams) \
    SMARTCARD_UART_GetDefaultConfig(cardParams) /*!< Common Smart card API macro */
#endif /* (defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && (FSL_FEATURE_SOC_EMVSIM_COUNT)) */

/*! @brief Runtime RTOS Smart card driver context.*/
typedef struct rtos_smartcard_context
{
    SemaphoreHandle_t x_sem;       /*!< RTOS unique access assurance object */
    SemaphoreHandle_t x_event;     /*!< RTOS synchronization object */
    smartcard_context_t x_context; /*!< transactional layer state */
} rtos_smartcard_context_t;

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief Initializes a Smart card (EMVSIM/UART) peripheral for Smart card/ISO-7816 operation.
 * Also initialize Smart card PHY interface.
 *
 * This function ungates the Smart card clock, initializes the module to EMV default settings,
 * configures the IRQ state structure, and enables the module-level interrupt to the core.
 * Initializes RTOS synchronization objects and context.
 *
 * @param base The Smart card peripheral base address.
 * @param ctx The Smart card RTOS structure.
 * @param sourceClockHz Smart card clock generation module source clock.
 *
 * @return A zero in success or error code.
 */
int SMARTCARD_RTOS_Init(void *base, rtos_smartcard_context_t *ctx, uint32_t sourceClockHz);

/*!
 * @brief
 *
 * This function disables the Smart card (EMVSIM/UART) interrupts, disables the transmitter and receiver, and
 * flushes the FIFOs (for modules that support FIFOs) and gates Smart card clock in SIM. It also deactivates  Smart card
 * PHY
 * interface, stops Smart card clocks, and frees all synchronization objects allocated in the RTOS Smart card context.
 *
 * @param ctx The Smart card RTOS state.
 *
 * @return A zero in success or error code.
 */
int SMARTCARD_RTOS_Deinit(rtos_smartcard_context_t *ctx);

/*!
 * @brief Transfers data using interrupts.
 *
 * A blocking (also known as synchronous) function means that the function returns
 * after the transfer is done. User can cancel this transfer by calling the function AbortTransfer.
 *
 * @param ctx A pointer to the RTOS Smart card driver context.
 * @param xfer Smart card transfer structure.
 *
 * @return A zero in success or error code.
 */
int SMARTCARD_RTOS_Transfer(rtos_smartcard_context_t *ctx, smartcard_xfer_t *xfer);

/*!
 * @brief Terminates an asynchronous EMVSIM transfer early.
 *
 * During an async EMVSIM transfer, the user can terminate the transfer early
 * if the transfer is still in progress.
 *
 * @param ctx A pointer to the RTOS Smart card driver context.

 * @return A zero in success or error code.
 */
int SMARTCARD_RTOS_AbortTransfer(rtos_smartcard_context_t *ctx);

/*!
 * @brief Waits until the transfer is finished.
 *
 * Task waits on a transfer finish event. Don't initialize the transfer. Instead, wait for a transfer callback.
 * This function can be used while waiting on an initial TS character.
 *
 * @param ctx A pointer to the RTOS Smart card driver context.
 *
 * @return A zero in success or error code.
 */
int SMARTCARD_RTOS_WaitForXevent(rtos_smartcard_context_t *ctx);
/*!
 * @brief Controls the Smart card module per different user requests.
 *
 * @param ctx The Smart card RTOS context pointer.
 * @param control Control type.
 * @param param Integer value to control the command.
 *
 * @return A zero in success or error code.
 */
int SMARTCARD_RTOS_Control(rtos_smartcard_context_t *ctx, smartcard_control_t control, uint32_t param);

/*!
 * @brief Controls the Smart card module as per different user request.
 *
 * @param ctx The Smart card RTOS context pointer.
 * @param control Control type
 * @param param Integer value  to control the command.
 *
 * @return A zero in success or error code.
 */
int SMARTCARD_RTOS_PHY_Control(rtos_smartcard_context_t *ctx, smartcard_interface_control_t control, uint32_t param);

/*!
 * @brief Activates the Smart card interface.
 *
 * @param ctx The Smart card RTOS driver context structure.
 * @param resetType type of reset to be performed, possible values
 *                       = kSmartcardColdReset, kSmartcardWarmReset
 *
 * @return A zero in success or error code.
 */
int SMARTCARD_RTOS_PHY_Activate(rtos_smartcard_context_t *ctx, smartcard_reset_type_t resetType);

/*!
 * @brief Deactivates the Smart card interface.
 *
 * @param ctx The Smart card RTOS driver context structure.
 *
 * @return A zero in success or error code.
 */
int SMARTCARD_RTOS_PHY_Deactivate(rtos_smartcard_context_t *ctx);

/*@}*/

#if defined(__cplusplus)
}
#endif

/*! @}*/
#endif /* _FSL_SMARTCARD_RTOS_H_*/
