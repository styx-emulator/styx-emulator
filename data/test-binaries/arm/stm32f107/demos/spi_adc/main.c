#define USE_STDPERIPH_DRIVER
#include "stm32f10x_spi.h"

#define SelectSlave SPI_NSSInternalSoftwareConfig(SPI2, SPI_NSSInternalSoft_Set)
#define DeselectSlave SPI_NSSInternalSoftwareConfig(SPI2, SPI_NSSInternalSoft_Reset)
#define WAIT_RXNE while (SPI_I2S_GetFlagStatus(SPI2, SPI_I2S_FLAG_RXNE) == RESET) {}

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

    SPI_Init(SPI2, &spi_init);
    DeselectSlave;
}

void read_adc(uint16_t* store) {
    SelectSlave;

    int result = 0;

    WAIT_RXNE;
    result = SPI_I2S_ReceiveData(SPI2) << 8;

    WAIT_RXNE;
    result |= SPI_I2S_ReceiveData(SPI2);

    DeselectSlave;

    *store = result;
}

void sleep(int count) {
    int i = 0;
    while (i < count) { i++; }
}

int main() {
    sleep(100000);

    spi_init();

    uint16_t signal_val = 0;

    read_adc(&signal_val);

    while (1) {}
}
