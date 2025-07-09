/*
 * The Clear BSD License
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
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
 * o Neither the name of the copyright holder nor the names of its
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

#include "board.h"
#include "fsl_dmamux.h"
#include "fsl_sai_edma.h"
#include "fsl_debug_console.h"
#include "arm_math.h"

#include "fsl_sgtl5000.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "fsl_gpio.h"
#include "fsl_port.h"
#include "fsl_sysmpu.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define DEMO_SAI I2S0
#define DEMO_I2C I2C1
#define DEMO_SAI_CLKSRC kCLOCK_CoreSysClk
#define DEMO_SAI_CLK_FREQ CLOCK_GetFreq(kCLOCK_CoreSysClk)
#define DEMO_I2C_CLKSRC kCLOCK_BusClk
#define DEMO_I2C_CLK_FREQ CLOCK_GetFreq(kCLOCK_BusClk)
#define DEMO_SDCARD (1)
#define EXAMPLE_DMA DMA0
#define EXAMPLE_DMAMUX DMAMUX
#define EXAMPLE_TX_CHANNEL (0U)
#define EXAMPLE_RX_CHANNEL (1U)
#define EXAMPLE_SAI_TX_SOURCE kDmaRequestMux0I2S0Tx
#define EXAMPLE_SAI_RX_SOURCE kDmaRequestMux0I2S0Rx
#define SAI_UserTxIRQHandler I2S0_Tx_IRQHandler
#define SAI_UserRxIRQHandler I2S0_Rx_IRQHandler
#define DEMO_SAI_TX_IRQ I2S0_Tx_IRQn
#define DEMO_SAI_RX_IRQ I2S0_Rx_IRQn

#define I2C_RELEASE_SDA_PORT PORTC
#define I2C_RELEASE_SCL_PORT PORTC
#define I2C_RELEASE_SDA_GPIO GPIOC
#define I2C_RELEASE_SDA_PIN 11U
#define I2C_RELEASE_SCL_GPIO GPIOC
#define I2C_RELEASE_SCL_PIN 10U
#define I2C_RELEASE_BUS_COUNT 100U
#define OVER_SAMPLE_RATE (384U)
#define SAMPLE_RATE (kSAI_SampleRate16KHz)
#define BUFFER_SIZE (512)
#define BUFFER_NUM (4)
/*******************************************************************************
 * Prototypes
 ******************************************************************************/
void BOARD_I2C_ReleaseBus(void);
static void txCallback(I2S_Type *base, sai_edma_handle_t *handle, status_t status, void *userData);
static void rxCallback(I2S_Type *base, sai_edma_handle_t *handle, status_t status, void *userData);
#if defined DEMO_SDCARD
/*!
* @brief wait card insert function.
*/
static status_t sdcardWaitCardInsert(void);
#endif
/*******************************************************************************
 * Variables
 ******************************************************************************/
sai_edma_handle_t txHandle = {0};
edma_handle_t dmaTxHandle = {0};
sai_edma_handle_t rxHandle = {0};
edma_handle_t dmaRxHandle = {0};
static sai_transfer_format_t format = {0};
static uint8_t audioBuff[BUFFER_SIZE * BUFFER_NUM];
static float32_t ffData[2 * BUFFER_SIZE];
static float32_t ffResult[BUFFER_SIZE];
#if defined(DEMO_CODEC_WM8960)
wm8960_handle_t codecHandle = {0};
#elif defined(DEMO_CODEC_DA7212)
da7212_handle_t codecHandle = {0};
#else
sgtl_handle_t codecHandle = {0};
#endif

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
lpi2c_master_handle_t i2cHandle = {0};
#else
i2c_master_handle_t i2cHandle = {{0, 0, kI2C_Write, 0, 0, NULL, 0}, 0, 0, NULL, NULL};
#endif
volatile bool istxFinished = false;
volatile bool isrxFinished = false;
volatile uint32_t beginCount = 0;
volatile uint32_t sendCount = 0;
volatile uint32_t receiveCount = 0;
volatile bool sdcard = false;

#if defined DEMO_SDCARD
#include "fsl_sd.h"
#include "ff.h"
#include "diskio.h"
/* static values for fatfs */
AT_NONCACHEABLE_SECTION(static FATFS g_fileSystem); /* File system object */
AT_NONCACHEABLE_SECTION(static FIL g_fileObject);   /* File object */
AT_NONCACHEABLE_SECTION(static BYTE work[_MAX_SS]);
volatile uint32_t fullBlock = 0;
volatile uint32_t emptyBlock = BUFFER_NUM;
/*! @brief SDMMC host detect card configuration */
static const sdmmchost_detect_card_t s_sdCardDetect = {
#ifndef BOARD_SD_DETECT_TYPE
    .cdType = kSDMMCHOST_DetectCardByGpioCD,
#else
    .cdType = BOARD_SD_DETECT_TYPE,
#endif
    .cdTimeOut_ms = (~0U),
};
extern sd_card_t g_sd; /* sd card descriptor */
#endif

/*******************************************************************************
 * Code
 ******************************************************************************/

static void i2c_release_bus_delay(void)
{
    uint32_t i = 0;
    for (i = 0; i < I2C_RELEASE_BUS_COUNT; i++)
    {
        __NOP();
    }
}

void BOARD_I2C_ReleaseBus(void)
{
    uint8_t i = 0;
    gpio_pin_config_t pin_config;
    port_pin_config_t i2c_pin_config = {0};

    /* Config pin mux as gpio */
    i2c_pin_config.pullSelect = kPORT_PullUp;
    i2c_pin_config.mux = kPORT_MuxAsGpio;

    pin_config.pinDirection = kGPIO_DigitalOutput;
    pin_config.outputLogic = 1U;
    CLOCK_EnableClock(kCLOCK_PortC);
    PORT_SetPinConfig(I2C_RELEASE_SCL_PORT, I2C_RELEASE_SCL_PIN, &i2c_pin_config);
    PORT_SetPinConfig(I2C_RELEASE_SCL_PORT, I2C_RELEASE_SDA_PIN, &i2c_pin_config);

    GPIO_PinInit(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, &pin_config);
    GPIO_PinInit(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, &pin_config);

    /* Drive SDA low first to simulate a start */
    GPIO_PinWrite(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, 0U);
    i2c_release_bus_delay();

    /* Send 9 pulses on SCL and keep SDA high */
    for (i = 0; i < 9; i++)
    {
        GPIO_PinWrite(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, 0U);
        i2c_release_bus_delay();

        GPIO_PinWrite(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, 1U);
        i2c_release_bus_delay();

        GPIO_PinWrite(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, 1U);
        i2c_release_bus_delay();
        i2c_release_bus_delay();
    }

    /* Send stop */
    GPIO_PinWrite(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, 0U);
    i2c_release_bus_delay();

    GPIO_PinWrite(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, 0U);
    i2c_release_bus_delay();

    GPIO_PinWrite(I2C_RELEASE_SCL_GPIO, I2C_RELEASE_SCL_PIN, 1U);
    i2c_release_bus_delay();

    GPIO_PinWrite(I2C_RELEASE_SDA_GPIO, I2C_RELEASE_SDA_PIN, 1U);
    i2c_release_bus_delay();
}
#if defined DEMO_SDCARD
static void wav_header(uint8_t *header, uint32_t sampleRate, uint32_t bitsPerFrame, uint32_t fileSize)
{
    uint32_t totalDataLen = fileSize - 8U;
    uint32_t audioDataLen = fileSize - 44U;
    uint32_t byteRate = sampleRate * (bitsPerFrame / 8U) * 2U;
    header[0] = 'R';
    header[1] = 'I';
    header[2] = 'F';
    header[3] = 'F';
    header[4] = (totalDataLen & 0xff); /* file-size (equals file-size - 8) */
    header[5] = ((totalDataLen >> 8U) & 0xff);
    header[6] = ((totalDataLen >> 16U) & 0xff);
    header[7] = ((totalDataLen >> 24U) & 0xff);
    header[8] = 'W'; /* Mark it as type "WAVE" */
    header[9] = 'A';
    header[10] = 'V';
    header[11] = 'E';
    header[12] = 'f'; /* Mark the format section 'fmt ' chunk */
    header[13] = 'm';
    header[14] = 't';
    header[15] = ' ';
    header[16] = 16; /* 4 bytes: size of 'fmt ' chunk, Length of format data.  Always 16 */
    header[17] = 0;
    header[18] = 0;
    header[19] = 0;
    header[20] = 1; /* format = 1 ,Wave type PCM */
    header[21] = 0;
    header[22] = 2; /* channels */
    header[23] = 0;
    header[24] = (sampleRate & 0xff);
    header[25] = ((sampleRate >> 8U) & 0xff);
    header[26] = ((sampleRate >> 16U) & 0xff);
    header[27] = ((sampleRate >> 24U) & 0xff);
    header[28] = (byteRate & 0xff);
    header[29] = ((byteRate >> 8U) & 0xff);
    header[30] = ((byteRate >> 16U) & 0xff);
    header[31] = ((byteRate >> 24U) & 0xff);
    header[32] = (2 * bitsPerFrame / 8); /* block align */
    header[33] = 0;
    header[34] = 16; /* bits per sample */
    header[35] = 0;
    header[36] = 'd'; /*"data" marker */
    header[37] = 'a';
    header[38] = 't';
    header[39] = 'a';
    header[40] = (audioDataLen & 0xff); /* data-size (equals file-size - 44).*/
    header[41] = ((audioDataLen >> 8) & 0xff);
    header[42] = ((audioDataLen >> 16) & 0xff);
    header[43] = ((audioDataLen >> 24) & 0xff);
}
#endif /* DEMO_SDCARD */

float32_t do_fft(sai_transfer_format_t *dataFormat, uint8_t *buffer, float32_t *fftData, float32_t *fftResult)
{
    /* Counter variable for navigating buffers */
    uint32_t counter;

    /* Return value for wav frequency in hertz */
    float32_t wavFreqHz;

    /* CMSIS status & FFT instance */
    arm_status status;                /* ARM status variable */
    arm_cfft_radix2_instance_f32 fft; /* ARM FFT instance */

    /* Frequency analysis variables */
    float32_t maxValue;     /* max value for greatest FFT bin amplitude */
    uint32_t testIndex = 0; /* value for storing the bin location with maxValue */
    uint32_t complexBuffSize = BUFFER_SIZE * 2;
    uint32_t fftSize = BUFFER_SIZE;                  /* FFT bin size */
    uint32_t ifftFlag = 0;                           /* Flag for the selection of CFFT/CIFFT */
    uint32_t doBitReverse = 1;                       /* Flag for selection of normal order or bit reversed order */
    uint32_t sampleRate = dataFormat->sampleRate_Hz; /* Get sample rate from current format */
    float32_t hzPerBin = 2 * ((float32_t)sampleRate / (float32_t)fftSize); /* Calculate hz per FFT bin */

    uint8_t *temp8; /* Point to data for 8 bit samples */
    uint8_t temp8Data;

    uint16_t *temp16; /* Point to data for 16 bit samples */
    int16_t temp16Data;

    uint32_t *temp32; /* Point to data for 32 bit samples */
    int32_t temp32Data;

    /* Set status as success */
    status = ARM_MATH_SUCCESS;

    /* Wav data variables */
    switch (dataFormat->bitWidth)
    {
        case 8:
            temp8 = (uint8_t *)buffer;
            temp8Data = 0;

            /* Copy wav data to fft input array */
            for (counter = 0; counter < complexBuffSize; counter++)
            {
                if (counter % 2 == 0)
                {
                    temp8Data = (uint8_t)*temp8;
                    fftData[counter] = (float32_t)temp8Data;
                    temp8++;
                }
                else
                {
                    fftData[counter] = 0.0;
                }
            }

            /* Set instance for Real FFT */
            status = arm_cfft_radix2_init_f32(&fft, fftSize, ifftFlag, doBitReverse);

            /* Perform Real FFT on fftData */
            arm_cfft_radix2_f32(&fft, fftData);

            /* Populate FFT bins */
            arm_cmplx_mag_f32(fftData, fftResult, fftSize);

            /* Zero out non-audible, low-frequency noise from FFT Results. */
            fftResult[0] = 0.0;

            /* Find max bin and location of max (first half of bins as this is the only valid section) */
            arm_max_f32(fftResult, fftSize, &maxValue, &testIndex);

            break;

        case 16:
            temp16 = (uint16_t *)buffer;
            temp16Data = 0;

            /* Copy wav data to fft input array */
            for (counter = 0; counter < complexBuffSize; counter++)
            {
                if (counter % 2 == 0)
                {
                    temp16Data = (int16_t)*temp16;
                    fftData[counter] = (float32_t)temp16Data;
                    temp16++;
                }
                else
                {
                    fftData[counter] = 0.0;
                }
            }

            /* Set instance for Real FFT */
            status = arm_cfft_radix2_init_f32(&fft, fftSize, ifftFlag, doBitReverse);

            /* Perform Real FFT on fftData */
            arm_cfft_radix2_f32(&fft, fftData);

            /* Populate FFT bins */
            arm_cmplx_mag_f32(fftData, fftResult, fftSize);

            /* Zero out non-audible, low-frequency noise from FFT Results. */
            fftResult[0] = 0.0;

            /* Find max bin and location of max (first half of bins as this is the only valid section) */
            arm_max_f32(fftResult, fftSize, &maxValue, &testIndex);

            break;

        case 32:
            temp32 = (uint32_t *)buffer;
            temp32Data = 0;

            /* Copy wav data to fft input array */
            for (counter = 0; counter < complexBuffSize; counter++)
            {
                if (counter % 2 == 0)
                {
                    temp32Data = (int32_t)*temp32;
                    fftData[counter] = (float32_t)temp32Data;
                    temp32++;
                }
                else
                {
                    fftData[counter] = 0.0;
                }
            }

            /* Set instance for Real FFT */
            status = arm_cfft_radix2_init_f32(&fft, fftSize, ifftFlag, doBitReverse);

            /* Perform Real FFT on fftData */
            arm_cfft_radix2_f32(&fft, fftData);

            /* Populate FFT bins */
            arm_cmplx_mag_f32(fftData, fftResult, fftSize);

            /* Zero out non-audible, low-frequency noise from FFT Results. */
            fftResult[0] = 0.0;

            /* Find max bin and location of max (first half of bins as this is the only valid section) */
            arm_max_f32(fftResult, fftSize, &maxValue, &testIndex);

            break;

        default:
            __asm("NOP");
            break;
    }

    if (status != ARM_MATH_SUCCESS)
    {
        wavFreqHz = 0; /* If an error has occured set frequency of wav data to 0Hz */
        PRINTF("\r\nFFT compuation error.\r\n");
    }
    else
    {
        /* Set wavFreqHz to bin location of max amplitude multiplied by the hz per bin */
        wavFreqHz = testIndex * hzPerBin;
    }

    return wavFreqHz;
}

static void txCallback(I2S_Type *base, sai_edma_handle_t *handle, status_t status, void *userData)
{
    sai_transfer_t xfer = {0};

    sendCount++;
#if defined DEMO_SDCARD
    if (sdcard)
    {
        emptyBlock++;
    }
#endif
    if (sendCount == beginCount)
    {
        istxFinished = true;
        SAI_TransferTerminateSendEDMA(base, handle);
        sendCount = 0;
    }
    else
    {
        if (!sdcard)
        {
            xfer.data = audioBuff + ((sendCount - 1U) % BUFFER_NUM) * BUFFER_SIZE;
            xfer.dataSize = BUFFER_SIZE;
            SAI_TransferSendEDMA(base, handle, &xfer);
        }
    }
}

static void rxCallback(I2S_Type *base, sai_edma_handle_t *handle, status_t status, void *userData)
{
    sai_transfer_t xfer = {0};

    receiveCount++;

#if defined DEMO_SDCARD
    if (sdcard)
    {
        fullBlock++;
    }

#endif

    if (receiveCount == beginCount)
    {
        isrxFinished = true;
        SAI_TransferTerminateReceiveEDMA(base, handle);
        receiveCount = 0;
    }
    else
    {
        if (!sdcard)
        {
            xfer.data = audioBuff + ((receiveCount - 1U) % BUFFER_NUM) * BUFFER_SIZE;
            xfer.dataSize = BUFFER_SIZE;
            SAI_TransferReceiveEDMA(base, handle, &xfer);
        }
    }
}

#if defined DEMO_SDCARD
static status_t sdcardWaitCardInsert(void)
{
    /* Save host information. */
    g_sd.host.base = SD_HOST_BASEADDR;
    g_sd.host.sourceClock_Hz = SD_HOST_CLK_FREQ;
    /* card detect type */
    g_sd.usrParam.cd = &s_sdCardDetect;
    /* SD host init function */
    if (SD_HostInit(&g_sd) != kStatus_Success)
    {
        PRINTF("\r\nSD host init fail\r\n");
        return kStatus_Fail;
    }
    /* power off card */
    SD_PowerOffCard(g_sd.host.base, g_sd.usrParam.pwr);
    /* wait card insert */
    if (SD_WaitCardDetectStatus(SD_HOST_BASEADDR, &s_sdCardDetect, true) == kStatus_Success)
    {
        PRINTF("\r\nCard inserted.\r\n");
        /* power on the card */
        SD_PowerOnCard(g_sd.host.base, g_sd.usrParam.pwr);
    }
    else
    {
        PRINTF("\r\nCard detect fail.\r\n");
        return kStatus_Fail;
    }

    return kStatus_Success;
}
#endif

void RecordPlayback(uint32_t time_s)
{
    sai_transfer_t xfer = {0};
    uint32_t i = 0;

    /* First clear the buffer */
    memset(audioBuff, 0, BUFFER_SIZE * BUFFER_NUM);
    istxFinished = false;
    isrxFinished = false;
    sdcard = false;
    sendCount = 0;
    receiveCount = 0;

    /* Compute the begin count */
    beginCount = time_s * SAMPLE_RATE * 4u / BUFFER_SIZE;

    xfer.dataSize = BUFFER_SIZE;
    /* Start record first */
    for (i = 0; i < BUFFER_NUM; i++)
    {
        xfer.data = audioBuff + i * BUFFER_SIZE;
        SAI_TransferReceiveEDMA(DEMO_SAI, &rxHandle, &xfer);
    }

    /* Start send */
    for (i = 0; i < BUFFER_NUM; i++)
    {
        xfer.data = audioBuff + i * BUFFER_SIZE;
        SAI_TransferSendEDMA(DEMO_SAI, &txHandle, &xfer);
    }

    /* Wait for record and playback finished */
    while ((istxFinished != true) || (isrxFinished != true))
    {
    }
}

void PlaybackSine(uint32_t SineWaveFreqHz, uint32_t time_s)
{
    uint32_t count = SAMPLE_RATE / SineWaveFreqHz;
    uint32_t i = 0;
    uint32_t val = 0;
    sai_transfer_t xfer = {0};
    float32_t freq = 0;

    /* Clear the status */
    istxFinished = false;
    sdcard = false;
    sendCount = 0;

    /* Gnerate the sine wave data */
    for (i = 0; i < count; i++)
    {
        val = arm_sin_q15(0x8000 * i / count);
        audioBuff[4 * i] = val & 0xFFU;
        audioBuff[4 * i + 1U] = (val >> 8U) & 0xFFU;
        audioBuff[4 * i + 2U] = val & 0xFFU;
        audioBuff[4 * i + 3U] = (val >> 8U) & 0xFFU;
    }

    /* Repeat the cycle */
    for (i = 1; i < (BUFFER_SIZE * BUFFER_NUM) / (4 * count); i++)
    {
        memcpy(audioBuff + (i * 4 * count), audioBuff, (4 * count));
    }

    /* Send times according to the time need to playback */
    beginCount = SAMPLE_RATE * time_s * 4 / BUFFER_SIZE;

    /* Compute the frequency of the data using FFT */
    freq = do_fft(&format, audioBuff, ffData, ffResult);

    PRINTF("\r\n Data frequency is %f\r\n", freq);

    /* Do the playback */
    xfer.data = audioBuff;
    xfer.dataSize = BUFFER_SIZE;
    for (i = 0; i < SAI_XFER_QUEUE_SIZE; i++)
    {
        xfer.data = audioBuff + i * BUFFER_SIZE;
        SAI_TransferSendEDMA(DEMO_SAI, &txHandle, &xfer);
    }

    /* Wait for the send finished */
    while (istxFinished != true)
    {
    }
}

#if defined DEMO_SDCARD
void RecordSDCard(uint32_t time_s)
{
    uint32_t i = 0;
    uint32_t bytesWritten = 0;
    uint32_t bytesRead = 0;
    uint32_t txindex = 0;
    uint32_t rxindex = 0;
    uint32_t sdReadCount = 0;
    uint8_t header[44] = {0};
    uint32_t fileSize = time_s * SAMPLE_RATE * 2U * 2U + 44U;
    FRESULT error;
    sai_transfer_t xfer = {0};

    /* Clear the status */
    isrxFinished = false;
    receiveCount = 0;
    istxFinished = false;
    sendCount = 0;
    sdcard = true;

    PRINTF("\r\nBegin to record......\r\n");
    PRINTF("\r\nFile path is record/music1.wav\r\n");
    error = f_open(&g_fileObject, _T("/record/music1.wav"), (FA_WRITE | FA_READ | FA_CREATE_ALWAYS));
    if (error)
    {
        if (error == FR_EXIST)
        {
            PRINTF("File exists.\r\n");
        }
        else
        {
            PRINTF("Open file failed.\r\n");
            return;
        }
    }

    /* Write the data into the sdcard */
    wav_header(header, SAMPLE_RATE, 16, fileSize);

    /* Write the wav header */
    error = f_write(&g_fileObject, (void *)header, 44U, (UINT *)&bytesWritten);
    if ((error) || (bytesWritten != 44))
    {
        PRINTF("Write file failed. \r\n");
    }

    /* Start to record */
    beginCount = time_s * SAMPLE_RATE * 2U * 2U / BUFFER_SIZE;

    /* Start record first */
    memset(audioBuff, 0, BUFFER_SIZE * BUFFER_NUM);
    xfer.dataSize = BUFFER_SIZE;
    for (i = 0; i < BUFFER_NUM; i++)
    {
        xfer.data = audioBuff + i * BUFFER_SIZE;
        SAI_TransferReceiveEDMA(DEMO_SAI, &rxHandle, &xfer);
    }

    emptyBlock = 0;
    while ((isrxFinished != true) || (fullBlock != 0))
    {
        if (fullBlock > 0)
        {
            f_write(&g_fileObject, audioBuff + txindex * BUFFER_SIZE, BUFFER_SIZE, (UINT *)&bytesWritten);
            txindex = (txindex + 1U) % BUFFER_NUM;
            fullBlock--;
            emptyBlock++;
        }

        if ((emptyBlock > 0) && (isrxFinished == false))
        {
            xfer.data = audioBuff + rxindex * BUFFER_SIZE;
            rxindex = (rxindex + 1U) % BUFFER_NUM;
            SAI_TransferReceiveEDMA(DEMO_SAI, &rxHandle, &xfer);
            emptyBlock--;
        }
    }
    f_close(&g_fileObject);
    PRINTF("\r\nRecord is finished!\r\n");

    /* Playback the record file */
    PRINTF("\r\nPlayback the recorded file...");
    txindex = 0;
    rxindex = 0;
    emptyBlock = 0;
    fullBlock = 0;
    memset(audioBuff, 0, BUFFER_SIZE * BUFFER_NUM);
    f_open(&g_fileObject, _T("/record/music1.wav"), (FA_READ));
    if (f_lseek(&g_fileObject, 44U))
    {
        PRINTF("Set file pointer position failed. \r\n");
    }

    for (i = 0; i < BUFFER_NUM; i++)
    {
        f_read(&g_fileObject, (void *)(audioBuff + i * BUFFER_SIZE), BUFFER_SIZE, (UINT *)&bytesRead);
        sdReadCount++;
        fullBlock++;
    }

    /* Wait for playback finished */
    while (istxFinished != true)
    {
        if ((emptyBlock > 0) && (sdReadCount < beginCount))
        {
            f_read(&g_fileObject, (void *)(audioBuff + rxindex * BUFFER_SIZE), BUFFER_SIZE, (UINT *)&bytesRead);
            rxindex = (rxindex + 1U) % BUFFER_NUM;
            emptyBlock--;
            fullBlock++;
            sdReadCount++;
        }

        if (fullBlock > 0)
        {
            xfer.data = audioBuff + txindex * BUFFER_SIZE;
            txindex = (txindex + 1U) % BUFFER_NUM;
            SAI_TransferSendEDMA(DEMO_SAI, &txHandle, &xfer);
            fullBlock--;
        }
    }
    f_close(&g_fileObject);
    PRINTF("\r\nPlayback is finished!\r\n");
}
#endif /* DEMO_SDCARD */

/*!
 * @brief Main function
 */
int main(void)
{
    sai_config_t config;
    uint32_t mclkSourceClockHz = 0U;
    edma_config_t dmaConfig = {0};
#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    lpi2c_master_config_t i2cConfig = {0};
#else
    i2c_master_config_t i2cConfig = {0};
#endif
    uint32_t i2cSourceClock;
    char input = '1';

    BOARD_InitPins();
    BOARD_BootClockRUN();
    BOARD_I2C_ReleaseBus();
    BOARD_I2C_ConfigurePins();
    BOARD_InitDebugConsole();
    SYSMPU_Enable(SYSMPU, false);

    PRINTF("SAI Demo started!\n\r");

    /* Create EDMA handle */
    /*
     * dmaConfig.enableRoundRobinArbitration = false;
     * dmaConfig.enableHaltOnError = true;
     * dmaConfig.enableContinuousLinkMode = false;
     * dmaConfig.enableDebugMode = false;
     */
    EDMA_GetDefaultConfig(&dmaConfig);
    EDMA_Init(EXAMPLE_DMA, &dmaConfig);
    EDMA_CreateHandle(&dmaTxHandle, EXAMPLE_DMA, EXAMPLE_TX_CHANNEL);
    EDMA_CreateHandle(&dmaRxHandle, EXAMPLE_DMA, EXAMPLE_RX_CHANNEL);

    DMAMUX_Init(EXAMPLE_DMAMUX);
    DMAMUX_SetSource(EXAMPLE_DMAMUX, EXAMPLE_TX_CHANNEL, (uint8_t)EXAMPLE_SAI_TX_SOURCE);
    DMAMUX_EnableChannel(EXAMPLE_DMAMUX, EXAMPLE_TX_CHANNEL);
    DMAMUX_SetSource(EXAMPLE_DMAMUX, EXAMPLE_RX_CHANNEL, (uint8_t)EXAMPLE_SAI_RX_SOURCE);
    DMAMUX_EnableChannel(EXAMPLE_DMAMUX, EXAMPLE_RX_CHANNEL);

    /* Init SAI module */
    /*
     * config.masterSlave = kSAI_Master;
     * config.mclkSource = kSAI_MclkSourceSysclk;
     * config.protocol = kSAI_BusLeftJustified;
     * config.syncMode = kSAI_ModeAsync;
     * config.mclkOutputEnable = true;
     */
    SAI_TxGetDefaultConfig(&config);
    SAI_TxInit(DEMO_SAI, &config);

    /* Initialize SAI Rx */
    SAI_RxGetDefaultConfig(&config);
    SAI_RxInit(DEMO_SAI, &config);

    /* Configure the audio format */
    format.bitWidth = kSAI_WordWidth16bits;
    format.channel = 0U;
    format.sampleRate_Hz = SAMPLE_RATE;
#if (defined FSL_FEATURE_SAI_HAS_MCLKDIV_REGISTER && FSL_FEATURE_SAI_HAS_MCLKDIV_REGISTER) || \
    (defined FSL_FEATURE_PCC_HAS_SAI_DIVIDER && FSL_FEATURE_PCC_HAS_SAI_DIVIDER)
    format.masterClockHz = OVER_SAMPLE_RATE * format.sampleRate_Hz;
#else
    format.masterClockHz = DEMO_SAI_CLK_FREQ;
#endif
    format.protocol = config.protocol;
    format.stereo = kSAI_Stereo;
#if defined(FSL_FEATURE_SAI_FIFO_COUNT) && (FSL_FEATURE_SAI_FIFO_COUNT > 1)
    format.watermark = FSL_FEATURE_SAI_FIFO_COUNT / 2U;
#endif

    /* Configure Sgtl5000 I2C */
    codecHandle.base = DEMO_I2C;
    codecHandle.i2cHandle = &i2cHandle;
    i2cSourceClock = DEMO_I2C_CLK_FREQ;

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    /*
     * i2cConfig.debugEnable = false;
     * i2cConfig.ignoreAck = false;
     * i2cConfig.pinConfig = kLPI2C_2PinOpenDrain;
     * i2cConfig.baudRate_Hz = 100000U;
     * i2cConfig.busIdleTimeout_ns = 0;
     * i2cConfig.pinLowTimeout_ns = 0;
     * i2cConfig.sdaGlitchFilterWidth_ns = 0;
     * i2cConfig.sclGlitchFilterWidth_ns = 0;
     */
    LPI2C_MasterGetDefaultConfig(&i2cConfig);
    LPI2C_MasterInit(DEMO_I2C, &i2cConfig, i2cSourceClock);
    LPI2C_MasterTransferCreateHandle(DEMO_I2C, &i2cHandle, NULL, NULL);
#else
    /*
     * i2cConfig.baudRate_Bps = 100000U;
     * i2cConfig.enableStopHold = false;
     * i2cConfig.glitchFilterWidth = 0U;
     * i2cConfig.enableMaster = true;
     */
    I2C_MasterGetDefaultConfig(&i2cConfig);
    I2C_MasterInit(DEMO_I2C, &i2cConfig, i2cSourceClock);
    I2C_MasterTransferCreateHandle(DEMO_I2C, &i2cHandle, NULL, NULL);
#endif

#if defined(DEMO_CODEC_WM8960)
    WM8960_Init(&codecHandle, NULL);
    WM8960_ConfigDataFormat(&codecHandle, format.masterClockHz, format.sampleRate_Hz, format.bitWidth);
#elif defined(DEMO_CODEC_DA7212)
    DA7212_Init(&codecHandle, NULL);
    DA7212_ConfigAudioFormat(&codecHandle, format.sampleRate_Hz, format.masterClockHz, format.bitWidth);
    DA7212_ChangeOutput(&codecHandle, kDA7212_Output_HP);
#else
    /* Use default settings for sgtl5000 */
    SGTL_Init(&codecHandle, NULL);
    /* Configure codec format */
    SGTL_ConfigDataFormat(&codecHandle, format.masterClockHz, format.sampleRate_Hz, format.bitWidth);
#endif

    SAI_TransferTxCreateHandleEDMA(DEMO_SAI, &txHandle, txCallback, NULL, &dmaTxHandle);
    SAI_TransferRxCreateHandleEDMA(DEMO_SAI, &rxHandle, rxCallback, NULL, &dmaRxHandle);

    mclkSourceClockHz = DEMO_SAI_CLK_FREQ;
    SAI_TransferTxSetFormatEDMA(DEMO_SAI, &txHandle, &format, mclkSourceClockHz, format.masterClockHz);
    SAI_TransferRxSetFormatEDMA(DEMO_SAI, &rxHandle, &format, mclkSourceClockHz, format.masterClockHz);

    /* Enable interrupt to handle FIFO error */
    SAI_TxEnableInterrupts(DEMO_SAI, kSAI_FIFOErrorInterruptEnable);
    SAI_RxEnableInterrupts(DEMO_SAI, kSAI_FIFOErrorInterruptEnable);
    EnableIRQ(DEMO_SAI_TX_IRQ);
    EnableIRQ(DEMO_SAI_RX_IRQ);

#if defined DEMO_SDCARD
    /* If there is SDCard, Initialize SDcard and Fatfs */
    FRESULT error;

    const TCHAR driverNumberBuffer[3U] = {SDDISK + '0', ':', '/'};

    PRINTF("\r\nPlease insert a card into board.\r\n");

    if (sdcardWaitCardInsert() != kStatus_Success)
    {
        return -1;
    }

    if (f_mount(&g_fileSystem, driverNumberBuffer, 0U))
    {
        PRINTF("Mount volume failed.\r\n");
        return -1;
    }

#if (_FS_RPATH >= 2U)
    error = f_chdrive((char const *)&driverNumberBuffer[0U]);
    if (error)
    {
        PRINTF("Change drive failed.\r\n");
        return -1;
    }
#endif

#if _USE_MKFS
    PRINTF("\r\nMake file system......The time may be long if the card capacity is big.\r\n");
    if (f_mkfs(driverNumberBuffer, FM_ANY, 0U, work, sizeof work))
    {
        PRINTF("Make file system failed.\r\n");
        return -1;
    }
#endif /* _USE_MKFS */

    PRINTF("\r\nCreate directory......\r\n");
    error = f_mkdir(_T("/record"));
    if (error)
    {
        if (error == FR_EXIST)
        {
            PRINTF("Directory exists.\r\n");
        }
        else
        {
            PRINTF("Make directory failed.\r\n");
            return -1;
        }
    }

#endif /* DEMO_SDCARD */
    PRINTF("\n\rPlease choose the option :\n\r");
    while (1)
    {
        PRINTF("\r1. Record and playback at same time\r\n");
        PRINTF("\r2. Playback sine wave\r\n");
#if defined DEMO_SDCARD
        PRINTF("\r3. Record to SDcard, after record plyaback it\r\n");
#endif /* DEMO_SDCARD */
#if defined DIG_MIC
        PRINTF("\r4. Record using digital mic and playback at the same time\r\n");
#endif
        PRINTF("\r5. Quit\r\n");

        input = GETCHAR();
        PUTCHAR(input);
        PRINTF("\r\n");

        if (input == '5')
        {
            break;
        }

        switch (input)
        {
            case '1':
#if defined DIG_MIC
                /* Set the audio input source to AUX */
                DA7212_ChangeInput(&codecHandle, kDA7212_Input_AUX);
#endif
                RecordPlayback(30);
                break;
            case '2':
                PlaybackSine(250, 5);
                break;
#if defined DEMO_SDCARD
            case '3':
                RecordSDCard(5);
                break;
#endif
#if defined DIG_MIC
            case '4':
                /* Set the audio input source to DMIC */
                DA7212_ChangeInput(&codecHandle, kDA7212_Input_MIC1_An);
                RecordPlayback(30);
                break;
#endif
            default:
                PRINTF("\rInvallid Input Parameter, please re-enter\r\n");
                break;
        }
    }

#if defined(DEMO_CODEC_WM8960)
    WM8960_Deinit(&codecHandle);
#elif defined(DEMO_CODEC_DA7212)
#else
    SGTL_Deinit(&codecHandle);
#endif

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && (FSL_FEATURE_SOC_LPI2C_COUNT)
    LPI2C_MasterDeinit(DEMO_I2C);
#else
    I2C_MasterDeinit(DEMO_I2C);
#endif
    PRINTF("\n\r SAI demo finished!\n\r ");
    while (1)
    {
    }
}

void SAI_UserTxIRQHandler(void)
{
    /* Clear the FEF flag */
    SAI_TxClearStatusFlags(DEMO_SAI, kSAI_FIFOErrorFlag);
    SAI_TxSoftwareReset(DEMO_SAI, kSAI_ResetTypeFIFO);
/* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate overlapping
  exception return operation might vector to incorrect interrupt */
#if defined __CORTEX_M && (__CORTEX_M == 4U)
    __DSB();
#endif
}

void SAI_UserRxIRQHandler(void)
{
    SAI_RxClearStatusFlags(DEMO_SAI, kSAI_FIFOErrorFlag);
    SAI_RxSoftwareReset(DEMO_SAI, kSAI_ResetTypeFIFO);
/* Add for ARM errata 838869, affects Cortex-M4, Cortex-M4F Store immediate overlapping
  exception return operation might vector to incorrect interrupt */
#if defined __CORTEX_M && (__CORTEX_M == 4U)
    __DSB();
#endif
}
