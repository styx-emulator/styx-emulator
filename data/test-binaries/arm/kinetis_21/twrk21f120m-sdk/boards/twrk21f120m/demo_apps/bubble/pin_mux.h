/*
 * The Clear BSD License
 * Copyright (c) 2016, Freescale Semiconductor, Inc.
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
 * o Neither the name of Freescale Semiconductor, Inc. nor the names of its
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

#ifndef _PIN_MUX_H_
#define _PIN_MUX_H_

/***********************************************************************************************************************
 * Definitions
 **********************************************************************************************************************/

/*! @brief Direction type  */
typedef enum _pin_mux_direction
{
    kPIN_MUX_DirectionInput = 0U,        /* Input direction */
    kPIN_MUX_DirectionOutput = 1U,       /* Output direction */
    kPIN_MUX_DirectionInputOrOutput = 2U /* Input or output direction */
} pin_mux_direction_t;

/*!
 * @addtogroup pin_mux
 * @{
 */

/***********************************************************************************************************************
 * API
 **********************************************************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif


/*! @name PORTD8 (coord A10), J14[A43]/U2[3]/UART5_RX
  @{ */
#define BOARD_DEBUG_UART_RX_PERIPHERAL UART5                /*!<@brief Device name: UART5 */
#define BOARD_DEBUG_UART_RX_SIGNAL RX                       /*!<@brief UART5 signal: RX */
#define BOARD_DEBUG_UART_RX_PORT PORTD                      /*!<@brief PORT device name: PORTD */
#define BOARD_DEBUG_UART_RX_PIN 8U                          /*!<@brief PORTD pin index: 8 */
#define BOARD_DEBUG_UART_RX_PIN_NAME UART5_RX               /*!<@brief Pin name */
#define BOARD_DEBUG_UART_RX_LABEL "J14[A43]/U2[3]/UART5_RX" /*!<@brief Label */
#define BOARD_DEBUG_UART_RX_NAME "DEBUG_UART_RX"            /*!<@brief Identifier name */
                                                            /* @} */

/*! @name PORTD9 (coord A9), J14[A44]/UART5_TX
  @{ */
#define BOARD_DEBUG_UART_TX_PERIPHERAL UART5          /*!<@brief Device name: UART5 */
#define BOARD_DEBUG_UART_TX_SIGNAL TX                 /*!<@brief UART5 signal: TX */
#define BOARD_DEBUG_UART_TX_PORT PORTD                /*!<@brief PORT device name: PORTD */
#define BOARD_DEBUG_UART_TX_PIN 9U                    /*!<@brief PORTD pin index: 9 */
#define BOARD_DEBUG_UART_TX_PIN_NAME UART5_TX         /*!<@brief Pin name */
#define BOARD_DEBUG_UART_TX_LABEL "J14[A44]/UART5_TX" /*!<@brief Label */
#define BOARD_DEBUG_UART_TX_NAME "DEBUG_UART_TX"      /*!<@brief Identifier name */
                                                      /* @} */

/*! @name PORTD4 (coord A3), J14[B47]/J14[A78]/J15[1]/LED_J_PTD4
  @{ */
#define BOARD_LED_GREEN_PERIPHERAL FTM0                             /*!<@brief Device name: FTM0 */
#define BOARD_LED_GREEN_SIGNAL CH                                   /*!<@brief FTM0 signal: CH */
#define BOARD_LED_GREEN_PORT PORTD                                  /*!<@brief PORT device name: PORTD */
#define BOARD_LED_GREEN_PIN 4U                                      /*!<@brief PORTD pin index: 4 */
#define BOARD_LED_GREEN_CHANNEL 4                                   /*!<@brief FTM0 channel: 4 */
#define BOARD_LED_GREEN_PIN_NAME FTM0_CH4                           /*!<@brief Pin name */
#define BOARD_LED_GREEN_LABEL "J14[B47]/J14[A78]/J15[1]/LED_J_PTD4" /*!<@brief Label */
#define BOARD_LED_GREEN_NAME "LED_GREEN"                            /*!<@brief Identifier name */
                                                                    /* @} */

/*! @name PORTD5 (coord A2), J14[A79]/J15[3]/LED_J_PTD5
  @{ */
#define BOARD_LED_YELLOW_PERIPHERAL FTM0                    /*!<@brief Device name: FTM0 */
#define BOARD_LED_YELLOW_SIGNAL CH                          /*!<@brief FTM0 signal: CH */
#define BOARD_LED_YELLOW_PORT PORTD                         /*!<@brief PORT device name: PORTD */
#define BOARD_LED_YELLOW_PIN 5U                             /*!<@brief PORTD pin index: 5 */
#define BOARD_LED_YELLOW_CHANNEL 5                          /*!<@brief FTM0 channel: 5 */
#define BOARD_LED_YELLOW_PIN_NAME FTM0_CH5                  /*!<@brief Pin name */
#define BOARD_LED_YELLOW_LABEL "J14[A79]/J15[3]/LED_J_PTD5" /*!<@brief Label */
#define BOARD_LED_YELLOW_NAME "LED_YELLOW"                  /*!<@brief Identifier name */
                                                            /* @} */

/*!
 * @brief Configures pin routing and optionally pin electrical features.
 *
 */
void BOARD_InitPins(void);

/*! @name PORTC11 (coord C5), J3[4]/J14[A8]/J14[A60]/J14[B51]/J14[B71]/U7[6]/I2C1_SDA
  @{ */
/*!
 * @brief Device name: I2C1 */
#define BOARD_I2C_CONFIGUREPINS_ACCL_SDA_PERIPHERAL I2C1
/*!
 * @brief I2C1 signal: SDA */
#define BOARD_I2C_CONFIGUREPINS_ACCL_SDA_SIGNAL SDA
/*!
 * @brief PORT device name: PORTC */
#define BOARD_I2C_CONFIGUREPINS_ACCL_SDA_PORT PORTC
/*!
 * @brief PORTC pin index: 11 */
#define BOARD_I2C_CONFIGUREPINS_ACCL_SDA_PIN 11U
/*!
 * @brief Pin name */
#define BOARD_I2C_CONFIGUREPINS_ACCL_SDA_PIN_NAME I2C1_SDA
/*!
 * @brief Label */
#define BOARD_I2C_CONFIGUREPINS_ACCL_SDA_LABEL "J3[4]/J14[A8]/J14[A60]/J14[B51]/J14[B71]/U7[6]/I2C1_SDA"
/*!
 * @brief Identifier name */
#define BOARD_I2C_CONFIGUREPINS_ACCL_SDA_NAME "ACCL_SDA"
/* @} */

/*!
 *
 */
void BOARD_I2C_ConfigurePins(void);

#if defined(__cplusplus)
}
#endif

/*!
 * @}
 */
#endif /* _PIN_MUX_H_ */

/***********************************************************************************************************************
 * EOF
 **********************************************************************************************************************/
