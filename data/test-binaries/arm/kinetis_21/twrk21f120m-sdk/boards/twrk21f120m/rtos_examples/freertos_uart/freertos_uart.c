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

/* FreeRTOS kernel includes. */
#include "FreeRTOS.h"
#include "queue.h"
#include "task.h"
#include "timers.h"

/* Freescale includes. */
#include "board.h"
#include "fsl_debug_console.h"
#include "fsl_device_registers.h"

#include "fsl_uart.h"
#include "fsl_uart_freertos.h"

#include "clock_config.h"
#include "fsl_common.h"
#include "pin_mux.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* UART instance and clock */
#define DEMO_UART UART5
#define DEMO_UART_CLKSRC kCLOCK_BusClk
#define DEMO_UART_CLK_FREQ CLOCK_GetFreq(kCLOCK_BusClk)
#define DEMO_UART_RX_TX_IRQn UART5_RX_TX_IRQn
/* Task priorities. */
#define uart_task_PRIORITY (configMAX_PRIORITIES - 1)
/*******************************************************************************
 * Prototypes
 ******************************************************************************/
static void uart_task(void *pvParameters);

/*******************************************************************************
 * Variables
 ******************************************************************************/
const char *to_send = "FreeRTOS UART driver example!\r\n";
const char *send_ring_overrun = "\r\nRing buffer overrun!\r\n";
const char *send_hardware_overrun = "\r\nHardware buffer overrun!\r\n";
uint8_t background_buffer[32];
uint8_t recv_buffer[4];

uart_rtos_handle_t handle;
struct _uart_handle t_handle;

uart_rtos_config_t uart_config = {
    .baudrate = 115200,
    .parity = kUART_ParityDisabled,
    .stopbits = kUART_OneStopBit,
    .buffer = background_buffer,
    .buffer_size = sizeof(background_buffer),
};

/*******************************************************************************
 * Code
 ******************************************************************************/
/*!
 * @brief Application entry point.
 */
int main(void) {
  /* Init board hardware. */
  BOARD_InitPins();
  BOARD_BootClockRUN();
  NVIC_SetPriority(DEMO_UART_RX_TX_IRQn, 5);
  if (xTaskCreate(uart_task, "Uart_task", configMINIMAL_STACK_SIZE + 10, NULL,
                  uart_task_PRIORITY, NULL) != pdPASS) {
    PRINTF("Task creation failed!.\r\n");
    while (1)
      ;
  }
  vTaskStartScheduler();
  for (;;)
    ;
}

/*!
 * @brief Task responsible for loopback.
 */
static void uart_task(void *pvParameters) {
  int error;
  size_t n;

  uart_config.srcclk = DEMO_UART_CLK_FREQ;
  uart_config.base = DEMO_UART;

  if (0 > UART_RTOS_Init(&handle, &t_handle, &uart_config)) {
    vTaskSuspend(NULL);
  }

  /* Send introduction message. */
  if (0 > UART_RTOS_Send(&handle, (uint8_t *)to_send, strlen(to_send))) {
    vTaskSuspend(NULL);
  }

  /* Receive user input and send it back to terminal. */
  do {
    error = UART_RTOS_Receive(&handle, recv_buffer, sizeof(recv_buffer), &n);
    if (error == kStatus_UART_RxHardwareOverrun) {
      /* Notify about hardware buffer overrun */
      if (kStatus_Success != UART_RTOS_Send(&handle,
                                            (uint8_t *)send_hardware_overrun,
                                            strlen(send_hardware_overrun))) {
        vTaskSuspend(NULL);
      }
    }
    if (error == kStatus_UART_RxRingBufferOverrun) {
      /* Notify about ring buffer overrun */
      if (kStatus_Success != UART_RTOS_Send(&handle,
                                            (uint8_t *)send_ring_overrun,
                                            strlen(send_ring_overrun))) {
        vTaskSuspend(NULL);
      }
    }
    if (n > 0) {
      /* send back the received data */
      UART_RTOS_Send(&handle, (uint8_t *)recv_buffer, n);
    }
  } while (kStatus_Success == error);

  UART_RTOS_Deinit(&handle);
  vTaskSuspend(NULL);
}
