#define USE_STDPERIPH_DRIVER
#include "stm32f10x_spi.h"

int fast_rand(void) {
    int g_seed = (214013*g_seed+2531011);
    return (g_seed>>16)&0x7FFF;
}

void spi_init() {
    SPI_InitTypeDef spi_init;
    spi_init.SPI_Direction = SPI_Direction_2Lines_FullDuplex;
    spi_init.SPI_Mode = SPI_Mode_Master;
    spi_init.SPI_DataSize = SPI_DataSize_8b;
    spi_init.SPI_CPOL = SPI_CPOL_Low;
    spi_init.SPI_CPHA = SPI_CPHA_1Edge;
    spi_init.SPI_NSS = SPI_NSS_Soft;
    spi_init.SPI_BaudRatePrescaler = SPI_BaudRatePrescaler_2;
    spi_init.SPI_FirstBit = SPI_FirstBit_MSB;

    SPI_Init(SPI1, &spi_init);
}

#define SelectSlave SPI_NSSInternalSoftwareConfig(SPI1, SPI_NSSInternalSoft_Set)
#define DeselectSlave SPI_NSSInternalSoftwareConfig(SPI1, SPI_NSSInternalSoft_Reset)

#define WREN SelectSlave;SPI_I2S_SendData(SPI1, 0b00000110);DeselectSlave
#define WRDI SPI_I2S_SendData(SPI1, 0b00000100)

#define WRITE SPI_I2S_SendData(SPI1, 0b00000010)
#define READ SPI_I2S_SendData(SPI1, 0b00000011)

#define WAIT_TXE while (SPI_I2S_GetFlagStatus(SPI1, SPI_I2S_FLAG_TXE) == RESET) {}
#define WAIT_RXNE while (SPI_I2S_GetFlagStatus(SPI1, SPI_I2S_FLAG_RXNE) == RESET) {}

#define WIP(status) (status & 1)

// addresses are 16 bits wide, so sending an address requires 2 separate SPI write transactions
#define WRITE_ADDR(a) WAIT_TXE; SPI_I2S_SendData(SPI1, (a >> 8) & 0xFF); WAIT_TXE; SPI_I2S_SendData(SPI1, a & 0xFF)

void eeprom_write_mem(uint16_t address, uint16_t* data, int len) {
    WREN;

    SelectSlave;
    WRITE;
    WRITE_ADDR(address);
    int i = 0;
    while (i < len) {
        WAIT_TXE;
        SPI_I2S_SendData(SPI1, (uint16_t)(data[i]));
        i++;
    }
    DeselectSlave;
}
void eeprom_read_mem(uint16_t address, uint16_t* buffer, int len) {
    SelectSlave;
    READ;
    WRITE_ADDR(address);

    int i = 0;
    while (i < len) {
        WAIT_RXNE;
        buffer[i] = SPI_I2S_ReceiveData(SPI1);
        i++;
    }
    DeselectSlave;
}

void sleep(int count) {
    int i = 0;
    while (i < count) { i++; }
}

#define SIZE 4

uint16_t write_data[SIZE];
uint16_t buffer[SIZE];

int main() {
    sleep(100000);

    spi_init();

    uint16_t pointer = 0;

    while (1) {
        for (int i = 0; i < SIZE; i++) {
            write_data[i] = fast_rand() & 0xFFFF;
        }

        eeprom_write_mem(pointer, write_data, SIZE);

        eeprom_read_mem(pointer, buffer, SIZE);

        pointer += SIZE;
    }
}
