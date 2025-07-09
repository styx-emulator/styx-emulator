#define USE_STDPERIPH_DRIVER
#include "stm32f10x_i2c.h"

void i2c_init() {
    I2C_InitTypeDef i2c_init;
    i2c_init.I2C_ClockSpeed = 100000;
    i2c_init.I2C_Mode = I2C_Mode_I2C;
    i2c_init.I2C_DutyCycle = I2C_DutyCycle_16_9;
    i2c_init.I2C_OwnAddress1 = 0x1;
    i2c_init.I2C_Ack = I2C_Ack_Enable;
    i2c_init.I2C_AcknowledgedAddress = I2C_AcknowledgedAddress_7bit;
    I2C_Init(I2C1, &i2c_init);

    // enable interrupts
    I2C_ITConfig(I2C1, I2C_IT_BUF | I2C_IT_EVT, ENABLE);
    NVIC_EnableIRQ(I2C1_EV_IRQn);
}

#define RTC_ADDR 0x68 << 1

enum State {
    IDLE,
    ADDRESS,
    REGISTER,
    START_READ,
    READ,
    WRITE,
} state;

uint8_t tx_buf[64];
uint8_t rx_buf[64];
int end = 0;
int size = 0;
uint8_t target_reg = 0;

void begin_i2c_read(int len, uint8_t reg) {
    if (len <= 0)
        return;

    size = len;
    target_reg = reg;
    state = ADDRESS;

    // generate start condition
    I2C_GenerateSTART(I2C1, ENABLE);
}


void sleep(int x) {
    int i = 0;
    while (i < x) {
        i++;
    }
}

void I2C1_EV_IRQHandler(void) {
    switch (state) {
        case ADDRESS:
            if (I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT)) {
                I2C_Send7bitAddress(I2C1, RTC_ADDR, I2C_Direction_Transmitter);
                state = REGISTER;
            }
            break;
        case REGISTER:
            if (I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED)) {
                I2C_SendData(I2C1, target_reg);
                state = WRITE;
            }
            break;
        case WRITE:
            if (I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED)) {
                // generate repeat start condition
                I2C_GenerateSTART(I2C1, ENABLE);
            }
            if (I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT)) {
                I2C_Send7bitAddress(I2C1, RTC_ADDR, I2C_Direction_Receiver);
                state = START_READ;
            }
        case START_READ:
            if (I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_RECEIVER_MODE_SELECTED)) {
                end = 0;
                state = READ;
            }
            break;
        case READ:
            if (I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_RECEIVED)) {
                if (end >= size - 1) {
                    I2C_GenerateSTOP(I2C1, ENABLE);
                    state = IDLE;
                }
                tx_buf[end] = I2C_ReceiveData(I2C1);
                end++;
            }
            break;
        default:
            // ignore
            break;
    }
}

int main() {
    sleep(100000);
    i2c_init();

    begin_i2c_read(3, 0);

    while (1) {}
}
