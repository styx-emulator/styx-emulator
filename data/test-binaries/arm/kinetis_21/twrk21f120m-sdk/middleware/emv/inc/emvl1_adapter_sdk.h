/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
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
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _EMVL1_ADAPTER_SDK_H_
#define _EMVL1_ADAPTER_SDK_H_

#if defined(FSL_RTOS_FREE_RTOS)
#include "fsl_smartcard_freertos.h"
#elif defined(FSL_RTOS_UCOSII)
#include "fsl_smartcard_ucosii.h"
#elif defined(FSL_RTOS_UCOSIII)
#include "fsl_smartcard_ucosiii.h"
#else /* Bare Metal */
#include "fsl_smartcard.h"
#if (defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && (FSL_FEATURE_SOC_EMVSIM_COUNT))
#include "fsl_smartcard_emvsim.h"
#else
#include "fsl_smartcard_uart.h"
#endif
#include "fsl_smartcard_phy.h"
#endif /* FSL_RTOS_FREE_RTOS */

/*******************************************************************************
 * Variables
 ******************************************************************************/
/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*!
 * @addtogroup emvl1 EMV L1 Stack (EMVL1)
 * @{
 */

/*! @file */

/* Defined SDK specific APIs */
//${macro:start}
#if defined(FSL_RTOS_FREE_RTOS) || defined(FSL_RTOS_UCOSII) || defined(FSL_RTOS_UCOSIII)
#define SMARTCARD_CONTROL(context, control, param) \
    SMARTCARD_RTOS_Control(context, control, 0)                                  /*!< Common Smart card API macro */
#define SMARTCARD_TRANSFER(context, xfer) SMARTCARD_RTOS_Transfer(context, xfer) /*!< Common Smart card API macro */
#define SMARTCARD_GET_TRANSFER_REMAINING_BYTES(context) \
    SMARTCARD_RTOS_GetTransferRemainingBytes(context) /*!< Common Smart card API macro */
#define SMARTCARD_CONFIG_BAUDRATE(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_ConfigureBaudrate, 0) /*!< Common Smart card API macro */
#define SMARTCARD_SETUP_ATR(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_SetupATRMode, 0) /*!< Common Smart card API macro */
#define SMARTCARD_SETUP_T0(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_SetupT0Mode, 0) /*!< Common Smart card API macro */
#define SMARTCARD_SETUP_T1(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_SetupT1Mode, 0) /*!< Common Smart card API macro */
#define SMARTCARD_RESET_WWT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_ResetWWT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_RESET_CWT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_ResetCWT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_RESET_BWT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_ResetBWT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_WWT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_EnableWWT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_CWT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_EnableCWT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_BWT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_EnableBWT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_WWT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_DisableWWT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_CWT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_DisableCWT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_BWT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_DisableBWT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_ADT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_EnableADT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_ADT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_DisableADT, 0) /*!< Common Smart card API macro */
#define SMARTCARD_SET_WTX(context, mWTX)                                \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_ResetWaitTimeMultiplier, \
                           (uint32_t)mWTX) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_INIT_DETECT(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_EnableInitDetect, 0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_ANACK(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_EnableAnack, 0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_ANACK(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_DisableAnack, 0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_RECEIVER(context) \
    SMARTCARD_RTOS_Control(context, kSMARTCARD_EnableReceiverMode, 0) /*!< Common Smart card API macro */

#define SMARTCARD_PHY_ACTIVATE(context, resetType) \
    SMARTCARD_RTOS_PHY_Activate(context, resetType)                              /*!< Common Smart card API macro */
#define SMARTCARD_PHY_DEACTIVATE(context) SMARTCARD_RTOS_PHY_Deactivate(context) /*!< Common Smart card API macro */
#define SMARTCARD_PHY_CONTROL(context, control, param) \
    SMARTCARD_RTOS_PHY_Control(context, control, param) /*!< Common Smart card API macro */
/* defined(FSL_RTOS_FREE_RTOS) */
#else
#if (defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && (FSL_FEATURE_SOC_EMVSIM_COUNT))
#define SMARTCARD_CONTROL(context, control, param)                                     \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, control, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_TRANSFER(context, xfer)                                                 \
    SMARTCARD_EMVSIM_TransferNonBlocking(((smartcard_context_t *)context)->base, context, \
                                         xfer) /*!< Common Smart card API macro */
#define SMARTCARD_INIT(base, context, sourceClockHz) \
    SMARTCARD_EMVSIM_Init(base, context, sourceClockHz)      /*!< Common Smart card API macro */
#define SMARTCARD_DEINIT(base) SMARTCARD_EMVSIM_Deinit(base) /*!< Common Smart card API macro */
#define SMARTCARD_GET_TRANSFER_REMAINING_BYTES(context)                                \
    SMARTCARD_EMVSIM_GetTransferRemainingBytes(((smartcard_context_t *)context)->base, \
                                               context) /*!< Common Smart card API macro */
#define SMARTCARD_ABORT_TRANSFER(context)                                          \
    SMARTCARD_EMVSIM_AbortTransfer(((smartcard_context_t *)context)->base,         \
                                   context) /*!< Common Smart card API macro \ \ \ \
                                               */
#define SMARTCARD_CONFIG_BAUDRATE(context)                                                                  \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ConfigureBaudrate, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_SETUP_ATR(context)                                                                   \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_SetupATRMode, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_SETUP_T0(context)                                                                   \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_SetupT0Mode, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_SETUP_T1(context)                                                                   \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_SetupT1Mode, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_RESET_WWT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ResetWWT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_RESET_CWT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ResetCWT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_RESET_BWT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ResetBWT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_WWT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableWWT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_CWT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableCWT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_BWT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableBWT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_WWT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableWWT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_CWT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableCWT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_BWT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableBWT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_ADT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableADT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_ADT(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableADT, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_SET_WTX(context, mWTX)                                                                          \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ResetWaitTimeMultiplier, \
                             (uint32_t)mWTX) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_INIT_DETECT(context)                                                              \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableInitDetect, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_ANACK(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableAnack, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_ANACK(context)                                                               \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableAnack, \
                             0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_RECEIVER(context)                                                                   \
    SMARTCARD_EMVSIM_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableReceiverMode, \
                             0) /*!< Common Smart card API macro */

#else /* SMARTCARD module is UART */
#define SMARTCARD_CONTROL(context, control, param)                                   \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, control, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_TRANSFER(context, xfer)                                               \
    SMARTCARD_UART_TransferNonBlocking(((smartcard_context_t *)context)->base, context, \
                                       xfer) /*!< Common Smart card API macro */
#define SMARTCARD_INIT(base, context, sourceClockHz) \
    SMARTCARD_UART_Init(base, context, sourceClockHz)      /*!< Common Smart card API macro */
#define SMARTCARD_DEINIT(base) SMARTCARD_UART_Deinit(base) /*!< Common Smart card API macro */
#define SMARTCARD_GET_TRANSFER_REMAINING_BYTES(context)                              \
    SMARTCARD_UART_GetTransferRemainingBytes(((smartcard_context_t *)context)->base, \
                                             context) /*!< Common Smart card API macro */
#define SMARTCARD_ABORT_TRANSFER(context) \
    SMARTCARD_UART_AbortTransfer(((smartcard_context_t *)context)->base, context) /*!< Common Smart card API macro */
#define SMARTCARD_CONFIG_BAUDRATE(context)                                                                \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ConfigureBaudrate, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_SETUP_ATR(context)                                                                 \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_SetupATRMode, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_SETUP_T0(context)                                                                 \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_SetupT0Mode, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_SETUP_T1(context)                                                                 \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_SetupT1Mode, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_RESET_WWT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ResetWWT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_RESET_CWT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ResetCWT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_RESET_BWT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ResetBWT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_WWT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableWWT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_CWT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableCWT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_BWT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableBWT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_WWT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableWWT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_CWT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableCWT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_BWT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableBWT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_ADT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableADT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_ADT(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableADT, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_SET_WTX(context, mWTX)                                                                        \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_ResetWaitTimeMultiplier, \
                           (uint32_t)mWTX) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_INIT_DETECT(context)                                                            \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableInitDetect, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_ANACK(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableAnack, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_DISABLE_ANACK(context)                                                             \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_DisableAnack, \
                           0) /*!< Common Smart card API macro */
#define SMARTCARD_ENABLE_RECEIVER(context)                                                                 \
    SMARTCARD_UART_Control(((smartcard_context_t *)context)->base, context, kSMARTCARD_EnableReceiverMode, \
                           0) /*!< Common Smart card API macro */
#endif                        /* (defined(FSL_FEATURE_SOC_EMVSIM_COUNT) && (FSL_FEATURE_SOC_EMVSIM_COUNT)) */

#define SMARTCARD_PHY_ACTIVATE(context, resetType)                          \
    SMARTCARD_PHY_Activate(((smartcard_context_t *)context)->base, context, \
                           resetType) /*!< Common Smart card API macro */
#define SMARTCARD_PHY_DEACTIVATE(context) \
    SMARTCARD_PHY_Deactivate(((smartcard_context_t *)context)->base, context) /*!< Common Smart card API macro */
#define SMARTCARD_PHY_CONTROL(context, control, param)                              \
    SMARTCARD_PHY_Control(((smartcard_context_t *)context)->base, context, control, \
                          param) /*!< Common Smart card API macro */
#define SMARTCARD_PHY_INIT(base, config, sourceClockHz) \
    SMARTCARD_PHY_Init(base, config, sourceClockHz)                           /*!< Common Smart card API macro */
#define SMARTCARD_PHY_DEINIT(base, config) SMARTCARD_PHY_Deinit(base, config) /*!< Common Smart card API macro */
#define SMARTCARD_PHY_GET_DEFAULT_CONFIG(config) \
    SMARTCARD_PHY_GetDefaultConfig(config) /*!< Common Smart card API macro */

#endif /* USE_RTOS */

//${macro:end}
/*******************************************************************************
* API
******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*! @}*/
#if defined(__cplusplus)
}
#endif
/*! @}*/
#endif /* _EMVL1_ADAPTER_SDK_H_ */
