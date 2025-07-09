#include "main.h"

#define USART UART4

volatile uint8_t data_received = 0; // global flag for interrupt handling

/**
 * uart_demo
 *
 * This code sets up UART on the STM32F405 to
 * run a program taking commands through UART
 * and transmitting responses.
 *
 * Note that UART initialization in this file
 * is not completely set up compared to in the
 * real processor because some functionality
 * is abstracted over in emulation.
 */

/**
 * Halts the processor.
 */
void halt() {
  asm inline("bkpt;nop;nop");
}

/**
 * Initializes USART port, but does not turn
 * it on.
 *
 * @param USARTx
 *    the USART port to initialize
 */
void usart_init(USART_TypeDef *USARTx) {
  LL_USART_InitTypeDef u;

  LL_USART_StructInit(&u);

  ErrorStatus status = LL_USART_Init(USARTx, &u);

  if (status == ERROR) {
    halt();
  }
}

/**
 * Transmits a byte through a USART port given that it is enabled.
 *
 * @param b
 *      the byte to be transmitted
 */
void send_byte(uint8_t b) {
  while (!LL_USART_IsActiveFlag_TXE(USART)) {}

  LL_USART_TransmitData8(USART, b);
}

int main(void) {
  __enable_irq();
  NVIC_EnableIRQ(UART4_IRQn);
  NVIC_SetPriority(UART4_IRQn, 2);
  usart_init(USART);
  LL_USART_Enable(USART);
  LL_USART_EnableIT_RXNE(USART);

  uint8_t byte;

  do {
    while (data_received == 0) {} // wait for interrupt to set the flag

    byte = LL_USART_ReceiveData8(USART); // read received byte

    send_byte('G');
    send_byte('o');
    send_byte('t');
    send_byte(':');
    send_byte(byte);
    send_byte('\n');

    data_received = 0; // clear the flag
  } while (1);

  return 0;
}

// Interrupt Handler for UART 4
void UART4_IRQHandler(void) {
  // check for which interrupt was tripped
  if ((UART4->SR >> 5) & 0x00000001 == 1) { // RXNE interrupt, cleared by read to SR and then read to DR
    data_received = 1; // tell main to go ahead and proceed
  }
}
