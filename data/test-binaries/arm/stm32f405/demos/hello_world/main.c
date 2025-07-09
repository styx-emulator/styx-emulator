#include "main.h"

#define USART UART4

void halt() {
  asm inline("bkpt;nop;nop");
}

void usart_init() {
  LL_USART_InitTypeDef u;

  LL_USART_StructInit(&u);

  ErrorStatus status = LL_USART_Init(USART, &u);

  if (status == ERROR) {
    halt();
  }
}

void send_byte(uint8_t b) {
  while (!LL_USART_IsActiveFlag_TXE(USART)) {}

  LL_USART_TransmitData8(USART, b);
}

int main(void) {
  usart_init();

  send_byte('H');
  send_byte('e');
  send_byte('l');
  send_byte('l');
  send_byte('o');
  send_byte(' ');
  send_byte('W');
  send_byte('o');
  send_byte('r');
  send_byte('l');
  send_byte('d');
  send_byte('!');
  while (1) {}
  return 0;
}
