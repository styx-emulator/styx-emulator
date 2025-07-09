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
}

#define RTC_ADDR 0x68 << 1
#define TC74_ADDR 0x4D << 1

void write_rtc(uint8_t* msg, int len, uint8_t register_address) {
    if (len <= 0)
        return;

    // generate start condition
    I2C_GenerateSTART(I2C1, ENABLE);

    // wait for start to be released
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT)) {}

    // send address of slave to communicate with
    I2C_Send7bitAddress(I2C1, RTC_ADDR, I2C_Direction_Transmitter);

    // wait for ack from slave
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED)) {}

    // set write pointer
    I2C_SendData(I2C1, register_address);
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED)) {}

    // send data
    int sent = 0;
    while (sent < len) {
        I2C_SendData(I2C1, msg[sent]);
        sent++;
        while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED)) {}
    }

    I2C_GenerateSTOP(I2C1, ENABLE);
}

void read_rtc(uint8_t* buffer, int len, uint8_t register_address) {
    if (len <= 0)
        return;

    // generate start condition
    I2C_GenerateSTART(I2C1, ENABLE);

    // wait for start to be released
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT)) {}

    // set read pointer
    I2C_Send7bitAddress(I2C1, RTC_ADDR, I2C_Direction_Transmitter);
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED)) {}
    I2C_SendData(I2C1, register_address);
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED)) {}

    // generate repeat start condition
    I2C_GenerateSTART(I2C1, ENABLE);

    // wait for start to be released
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT)) {}

    // send address of slave to communicate with
    I2C_Send7bitAddress(I2C1, RTC_ADDR, I2C_Direction_Receiver);

    // wait for ack from slave
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_RECEIVER_MODE_SELECTED)) {}

    // receive data
    int recv = 0;
    while (recv < len) {
        // wait for message to be available
        while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_RECEIVED)) {}

        buffer[recv] = I2C_ReceiveData(I2C1);
        recv++;
    }

    I2C_GenerateSTOP(I2C1, ENABLE);
}

void read_temp(uint8_t* buffer, int len, uint8_t command) {
    if (len <= 0)
        return;

    // generate start condition
    I2C_GenerateSTART(I2C1, ENABLE);

    // wait for start to be released
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT)) {}

    // write command
    I2C_Send7bitAddress(I2C1, TC74_ADDR, I2C_Direction_Transmitter);
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED)) {}
    I2C_SendData(I2C1, command);
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED)) {}

    // generate repeat start condition
    I2C_GenerateSTART(I2C1, ENABLE);

    // wait for start to be released
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT)) {}

    // send address of slave to communicate with
    I2C_Send7bitAddress(I2C1, TC74_ADDR, I2C_Direction_Receiver);

    // receive data
    int recv = 0;
    while (recv < len) {
        // wait for message to be available
        while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_RECEIVED)) {}

        buffer[recv] = I2C_ReceiveData(I2C1);
        recv++;
    }

    I2C_GenerateSTOP(I2C1, ENABLE);
}

void write_temp(uint8_t* msg, int len, uint8_t command) {
    if (len <= 0)
        return;

    // generate start condition
    I2C_GenerateSTART(I2C1, ENABLE);

    // wait for start to be released
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_MODE_SELECT)) {}

    // send address of slave to communicate with
    I2C_Send7bitAddress(I2C1, TC74_ADDR, I2C_Direction_Transmitter);

    // wait for ack from slave
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_TRANSMITTER_MODE_SELECTED)) {}

    // send command
    I2C_SendData(I2C1, command);
    while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED)) {}

    // send data
    int sent = 0;
    while (sent < len) {
        I2C_SendData(I2C1, msg[sent]);
        sent++;
        while (!I2C_CheckEvent(I2C1, I2C_EVENT_MASTER_BYTE_TRANSMITTED)) {}
    }

    I2C_GenerateSTOP(I2C1, ENABLE);
}

void sleep(int x) {
    int i = 0;
    while (i < x) {
        i++;
    }
}

int main() {
    sleep(100000);
    i2c_init();

    // seconds, minutes, hours
    uint8_t cur_time[4] = {0,0,0,0};

    read_rtc(cur_time, 3, 0x0);

    sleep(100000);

    uint8_t msg = 0b11000000;
    uint8_t temp[2] = {0,0};
    write_temp(&msg, 1, 0x1);
    sleep(10000);
    read_temp(temp, 1, 0x0);

    while (1) {}
}
