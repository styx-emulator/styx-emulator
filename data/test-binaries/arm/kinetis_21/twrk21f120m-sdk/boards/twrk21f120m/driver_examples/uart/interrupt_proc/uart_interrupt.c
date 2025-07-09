/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * Copyright 2016-2017 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted (subject to the limitations in the disclaimer
 * below) provided that the following conditions are met:
 *
 * o Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * o Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY
 * THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT
 * NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "board.h"
#include "fsl_uart.h"

#include "clock_config.h"
#include "pin_mux.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define DEMO_UART UART5
#define DEMO_UART_CLKSRC kCLOCK_BusClk
#define DEMO_UART_CLK_FREQ CLOCK_GetFreq(kCLOCK_BusClk)
#define DEMO_UART_IRQn UART5_RX_TX_IRQn
#define DEMO_UART_IRQHandler UART5_RX_TX_IRQHandler

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

volatile uint8_t msgBuffer[20];
volatile int msgBufferIdx = 0;
volatile int processing = 0;

/*******************************************************************************
 * Code
 ******************************************************************************/

void win() {
  // yay, we got here!
}

void DEMO_UART_IRQHandler(void) {
  uint8_t data;

  /* If new data arrived. */
  if ((kUART_RxDataRegFullFlag | kUART_RxOverrunFlag) &
      UART_GetStatusFlags(DEMO_UART)) {
    data = UART_ReadByte(DEMO_UART);

    if (!processing) {
      if (msgBufferIdx < sizeof(msgBuffer)) {
        msgBuffer[msgBufferIdx] = data;
        msgBufferIdx += 1;
        if (data == '\n') {
          processing = 1;
        }
      } else if (data == '\n') {
        // reset the message buffer since we don't have the whole message
        msgBufferIdx = 0;
      }
    }
  }
  /* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate
    overlapping exception return operation might vector to incorrect interrupt
  */
#if defined __CORTEX_M && (__CORTEX_M == 4U)
  __DSB();
#endif
}

/*!
 * @brief Main function
 */
int main(void) {
  uart_config_t config;

  BOARD_InitPins();
  BOARD_BootClockRUN();

  /*
   * config.baudRate_Bps = 115200U;
   * config.parityMode = kUART_ParityDisabled;
   * config.stopBitCount = kUART_OneStopBit;
   * config.txFifoWatermark = 0;
   * config.rxFifoWatermark = 1;
   * config.enableTx = false;
   * config.enableRx = false;
   */
  UART_GetDefaultConfig(&config);
  config.baudRate_Bps = BOARD_DEBUG_UART_BAUDRATE;
  config.enableTx = true;
  config.enableRx = true;

  UART_Init(DEMO_UART, &config, DEMO_UART_CLK_FREQ);

  uint8_t ch;
  if (ch >= 'A' && ch <= 'F') {
    UART_WriteBlocking(DEMO_UART, &ch, 1);
  }
  EnableIRQ(DEMO_UART_IRQn);

  while (1) {
    if (processing) {
      if (msgBufferIdx == 3) {
        if (msgBuffer[0] == 'O') {
          if (msgBuffer[1] == 'K') {
            if (msgBuffer[2] == '\n') {
              win();
            }
          }
        }
      }
      msgBufferIdx = 0;
      processing = 0;
    }
  }
}
