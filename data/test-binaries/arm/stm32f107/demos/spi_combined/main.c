#define USE_STDPERIPH_DRIVER
#include "stm32f10x_spi.h"

#define WAIT_RXNE_ADC while (SPI_I2S_GetFlagStatus(SPI2, SPI_I2S_FLAG_RXNE) == RESET) {}
#define WAIT_TXE_DAC while (SPI_I2S_GetFlagStatus(SPI3, SPI_I2S_FLAG_TXE) == RESET) {}

#define WAIT_TXE_EEPROM while (SPI_I2S_GetFlagStatus(SPI1, SPI_I2S_FLAG_TXE) == RESET) {}

#define SelectEEPROM SPI_NSSInternalSoftwareConfig(SPI1, SPI_NSSInternalSoft_Set)
#define SelectADC SPI_NSSInternalSoftwareConfig(SPI2, SPI_NSSInternalSoft_Set)
#define SelectDAC SPI_NSSInternalSoftwareConfig(SPI3, SPI_NSSInternalSoft_Set)

#define DeselectEEPROM SPI_NSSInternalSoftwareConfig(SPI1, SPI_NSSInternalSoft_Reset)
#define DeselectADC SPI_NSSInternalSoftwareConfig(SPI2, SPI_NSSInternalSoft_Reset)
#define DeselectDAC SPI_NSSInternalSoftwareConfig(SPI3, SPI_NSSInternalSoft_Reset)

#define WREN SelectEEPROM;SPI_I2S_SendData(SPI1, 0b00000110);DeselectEEPROM
#define WRITE SPI_I2S_SendData(SPI1, 0b00000010)
// addresses are 16 bits wide, so sending an address requires 2 separate SPI write transactions
#define WRITE_HALFWORD(d) WAIT_TXE_EEPROM; SPI_I2S_SendData(SPI1, (d >> 8) & 0xFF); WAIT_TXE_EEPROM; SPI_I2S_SendData(SPI1, d & 0xFF)

void spi_init() {
    static const uint16_t CR1_INIT = 0x3244;
    SPI1->CR1 = CR1_INIT;
    SPI2->CR1 = CR1_INIT;
    SPI3->CR1 = CR1_INIT;
}

// fake sleep, used to wait a little bit
void sleep(int count) {
    int i = 0;
    while (i < count) { i++; }
}

int fill_count = 0;
static uint16_t data_queue[3] = {0,0,0};

uint16_t compute_avg() {
    return (data_queue[0] + data_queue[1]*2 + data_queue[2])/4;
}

void insert_element(uint16_t val) {
    if (fill_count == 3) {
        data_queue[0] = data_queue[1];
        data_queue[1] = data_queue[2];
        data_queue[2] = val;
    }
    else {
        data_queue[fill_count] = val;
        fill_count++;
    }
}

void read_adc(uint16_t* store) {
    // reading the ADC value requires two single byte reads
    SelectADC;

    int result = 0;

    WAIT_RXNE_ADC;
    result = (SPI_I2S_ReceiveData(SPI2) & 0xFF) << 8;

    WAIT_RXNE_ADC;
    result |= (SPI_I2S_ReceiveData(SPI2) & 0xFF);

    *store = result;

    DeselectADC;
}

void write_dac(uint16_t signal_val) {
    // writing to the DAC requires 2 single byte writes
    SelectDAC;

    WAIT_TXE_DAC;
    SPI_I2S_SendData(SPI3, signal_val >> 8);

    WAIT_TXE_DAC;
    SPI_I2S_SendData(SPI3, signal_val & 0xFF);

    WAIT_TXE_DAC;
    DeselectDAC;
}

void write_eeprom(uint16_t data, uint16_t* address) {
    // writing to the EEPROM requires writing the address first then the data, each as 2 single byte writes
    WREN;
    SelectEEPROM;

    WRITE;
    WRITE_HALFWORD(*address);

    WAIT_TXE_EEPROM;
    WRITE_HALFWORD(data);

    DeselectEEPROM;

    *address += 2;
}

int main() {
    spi_init();

    uint16_t signal_val = 0;

    uint16_t address = 0;

    while (1) {
        read_adc(&signal_val);
        write_dac(signal_val);
        write_eeprom(signal_val, &address);
    }
}
