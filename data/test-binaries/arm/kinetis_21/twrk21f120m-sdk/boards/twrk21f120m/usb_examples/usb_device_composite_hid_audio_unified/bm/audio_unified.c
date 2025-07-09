/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 NXP
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

#include "usb_device_config.h"
#include "usb.h"
#include "usb_device.h"

#include "usb_device_class.h"
#include "usb_device_audio.h"

#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"

#include "composite.h"

#include "fsl_device_registers.h"
#include "clock_config.h"
#include "board.h"
#include <stdio.h>
#include <stdlib.h>
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define AUDIO_SAMPLING_RATE_TO_10_14 (AUDIO_SAMPLING_RATE_KHZ << 14)
#define AUDIO_SAMPLING_RATE_TO_16_16 (AUDIO_SAMPLING_RATE_KHZ << 20)
#define AUDIO_UPDATE_FEEDBACK_DATA(m, n) \
    {                                    \
        m[0] = (n & 0xFFU);              \
        m[1] = ((n >> 8U) & 0xFFU);      \
        m[2] = ((n >> 16U) & 0xFFU);     \
    }

#define USB_AUDIO_ENTER_CRITICAL() \
    \
USB_OSA_SR_ALLOC();                \
    \
USB_OSA_ENTER_CRITICAL()

#define USB_AUDIO_EXIT_CRITICAL() USB_OSA_EXIT_CRITICAL()
/*******************************************************************************
 * Prototypes
 ******************************************************************************/
usb_status_t USB_DeviceAudioCallback(class_handle_t handle, uint32_t event, void *param);
usb_status_t USB_DeviceCallback(usb_device_handle handle, uint32_t event, void *param);

extern void BOARD_USB_AUDIO_KEYBOARD_Init(void);
extern void BOARD_USB_Audio_TxRxInit(uint32_t samplingRate);
extern void BOARD_I2C_LPI2C_Init(void);
extern void BOARD_Codec_Init(void);
extern void BOARD_SetCodecMuteUnmute(bool);
#if AUDIO_DMA_EDMA_MODE
extern void BOARD_DMA_EDMA_Config(void);
extern void BOARD_Create_Audio_DMA_EDMA_Handle(void);
extern void BOARD_DMA_EDMA_Set_AudioFormat(void);
extern void BOARD_DMA_EDMA_Enable_Audio_Interrupts(void);
extern void BOARD_DMA_EDMA_Start(void);
#endif
#if AUDIO_INTERRUPT_IRQ_MODE
extern void BOARD_Interrupt_Set_AudioFormat(void);
extern void BOARD_Enable_Audio_Interrupts(void);
#endif
/*******************************************************************************
 * Variables
 ******************************************************************************/
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t audioPlayDataBuff[AUDIO_SPEAKER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_OUT_ENDP_PACKET_SIZE];
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t audioPlayPacket[(FS_ISO_OUT_ENDP_PACKET_SIZE + AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE)];

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t audioRecDataBuff[AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE];
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t audioRecPacket[(FS_ISO_IN_ENDP_PACKET_SIZE + AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE)];

USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t audioFeedBackBuffer[3] = {TSAMFREQ2BYTES(AUDIO_SAMPLING_RATE_TO_10_14)};

usb_device_composite_struct_t *g_deviceAudioComposite;
volatile bool g_CodecMuteUnmute = false;
extern usb_device_composite_struct_t g_composite;

/*******************************************************************************
* Code
******************************************************************************/

/* Initialize the structure information for sai. */
void Init_Board_Sai_Codec(void)
{
    usb_echo("Init Audio SAI and CODEC\r\n");

    BOARD_USB_AUDIO_KEYBOARD_Init();

    BOARD_USB_Audio_TxRxInit(AUDIO_SAMPLING_RATE);
    BOARD_I2C_LPI2C_Init();
    BOARD_Codec_Init();

#if AUDIO_INTERRUPT_IRQ_MODE
    BOARD_Interrupt_Set_AudioFormat();
    BOARD_Enable_Audio_Interrupts();
#endif
#if AUDIO_DMA_EDMA_MODE
    BOARD_DMA_EDMA_Config();
    BOARD_Create_Audio_DMA_EDMA_Handle();
    BOARD_DMA_EDMA_Set_AudioFormat();
    BOARD_DMA_EDMA_Enable_Audio_Interrupts();
    BOARD_DMA_EDMA_Start();
#endif
}

/*!
 * @brief Audio class specific request function.
 *
 * This function handles the Audio class specific requests.
 *
 * @param handle           The USB device handle.
 * @param event            The USB device event type.
 * @param param            The parameter of the device specific request.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceAudioRequest(class_handle_t handle, uint32_t event, void *param)
{
    usb_device_control_request_struct_t *request = (usb_device_control_request_struct_t *)param;
    usb_status_t error = kStatus_USB_Success;
    uint16_t volume;

    switch (event)
    {
        case USB_DEVICE_AUDIO_GET_CUR_MUTE_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.curMute;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.curMute);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_VOLUME_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.curVolume;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.curVolume);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_BASS_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.curBass;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.curBass);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_MID_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.curMid;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.curMid);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_TREBLE_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.curTreble;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.curTreble);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_AUTOMATIC_GAIN_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.curAutomaticGain;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.curAutomaticGain);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_DELAY_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.curDelay;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.curDelay);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_SAMPLING_FREQ_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.curSamplingFrequency;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.curSamplingFrequency);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_VOLUME_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.minVolume;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.minVolume);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_BASS_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.minBass;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.minBass);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_MID_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.minMid;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.minMid);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_TREBLE_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.minTreble;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.minTreble);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_DELAY_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.minDelay;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.minDelay);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_SAMPLING_FREQ_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.minSamplingFrequency;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.minSamplingFrequency);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_VOLUME_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.maxVolume;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.maxVolume);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_BASS_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.maxBass;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.maxBass);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_MID_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.maxMid;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.maxMid);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_TREBLE_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.maxTreble;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.maxTreble);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_DELAY_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.maxDelay;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.maxDelay);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_SAMPLING_FREQ_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.maxSamplingFrequency;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.maxSamplingFrequency);
            break;
        case USB_DEVICE_AUDIO_GET_RES_VOLUME_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.resVolume;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.resVolume);
            break;
        case USB_DEVICE_AUDIO_GET_RES_BASS_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.resBass;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.resBass);
            break;
        case USB_DEVICE_AUDIO_GET_RES_MID_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.resMid;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.resMid);
            break;
        case USB_DEVICE_AUDIO_GET_RES_TREBLE_CONTROL:
            request->buffer = &g_deviceAudioComposite->audioUnified.resTreble;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.resTreble);
            break;
        case USB_DEVICE_AUDIO_GET_RES_DELAY_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.resDelay;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.resDelay);
            break;
        case USB_DEVICE_AUDIO_GET_RES_SAMPLING_FREQ_CONTROL:
            request->buffer = g_deviceAudioComposite->audioUnified.resSamplingFrequency;
            request->length = sizeof(g_deviceAudioComposite->audioUnified.resSamplingFrequency);
            break;

        case USB_DEVICE_AUDIO_SET_CUR_VOLUME_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.curVolume;
            }
            else
            {
                volume = (uint16_t)((uint16_t)g_deviceAudioComposite->audioUnified.curVolume[1] << 8U);
                volume |= (uint8_t)(g_deviceAudioComposite->audioUnified.curVolume[0]);
                g_deviceAudioComposite->audioUnified.codecTask |= VOLUME_CHANGE_TASK;
            }
            break;
        case USB_DEVICE_AUDIO_SET_CUR_MUTE_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.curMute;
            }
            else
            {
                if (g_deviceAudioComposite->audioUnified.curMute)
                {
                    g_deviceAudioComposite->audioUnified.codecTask |= MUTE_CODEC_TASK;
                }
                else
                {
                    g_deviceAudioComposite->audioUnified.codecTask |= UNMUTE_CODEC_TASK;
                }
            }
            break;
        case USB_DEVICE_AUDIO_SET_CUR_BASS_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.curBass;
            }
            break;
        case USB_DEVICE_AUDIO_SET_CUR_MID_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.curMid;
            }
            break;
        case USB_DEVICE_AUDIO_SET_CUR_TREBLE_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.curTreble;
            }
            break;
        case USB_DEVICE_AUDIO_SET_CUR_AUTOMATIC_GAIN_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.curAutomaticGain;
            }
            break;
        case USB_DEVICE_AUDIO_SET_CUR_DELAY_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.curDelay;
            }
            break;
        case USB_DEVICE_AUDIO_SET_CUR_SAMPLING_FREQ_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.curSamplingFrequency;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MIN_VOLUME_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.minVolume;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MIN_BASS_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.minBass;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MIN_MID_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.minMid;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MIN_TREBLE_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.minTreble;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MIN_DELAY_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.minDelay;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MIN_SAMPLING_FREQ_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.minSamplingFrequency;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MAX_VOLUME_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.maxVolume;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MAX_BASS_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.maxBass;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MAX_MID_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.maxMid;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MAX_TREBLE_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.maxTreble;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MAX_DELAY_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.maxDelay;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MAX_SAMPLING_FREQ_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.maxSamplingFrequency;
            }
            break;
        case USB_DEVICE_AUDIO_SET_RES_VOLUME_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.resVolume;
            }
            break;
        case USB_DEVICE_AUDIO_SET_RES_BASS_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.resBass;
            }
            break;
        case USB_DEVICE_AUDIO_SET_RES_MID_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.resMid;
            }
            break;
        case USB_DEVICE_AUDIO_SET_RES_TREBLE_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = &g_deviceAudioComposite->audioUnified.resTreble;
            }
            break;
        case USB_DEVICE_AUDIO_SET_RES_DELAY_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.resDelay;
            }
            break;
        case USB_DEVICE_AUDIO_SET_RES_SAMPLING_FREQ_CONTROL:
            if (request->isSetup == 1U)
            {
                request->buffer = g_deviceAudioComposite->audioUnified.resSamplingFrequency;
            }
            break;
        default:
            error = kStatus_USB_InvalidRequest;
            break;
    }
    return error;
}

/* The AudioSpeakerBufferSpaceUsed() function gets the reserved speaker ringbuffer size */
uint32_t AudioSpeakerBufferSpaceUsed(void)
{
    if (g_deviceAudioComposite->audioUnified.tdReadNumberPlay > g_deviceAudioComposite->audioUnified.tdWriteNumberPlay)
    {
        g_deviceAudioComposite->audioUnified.speakerReservedSpace =
            g_deviceAudioComposite->audioUnified.tdReadNumberPlay -
            g_deviceAudioComposite->audioUnified.tdWriteNumberPlay;
    }
    else
    {
        g_deviceAudioComposite->audioUnified.speakerReservedSpace =
            g_deviceAudioComposite->audioUnified.tdReadNumberPlay +
            AUDIO_SPEAKER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_OUT_ENDP_PACKET_SIZE -
            g_deviceAudioComposite->audioUnified.tdWriteNumberPlay;
    }
    return g_deviceAudioComposite->audioUnified.speakerReservedSpace;
}

/* The USB_AudioFeedbackDataUpdate() function calculates the feedback data */
void USB_AudioFeedbackDataUpdate()
{
    static uint32_t feedbackValue = 0x0, originFeedbackValue = 0x0;
    uint32_t usedSpace = 0;

    if (g_deviceAudioComposite->audioUnified.speakerIntervalCount != AUDIO_CALCULATE_Ff_INTERVAL)
    {
        g_deviceAudioComposite->audioUnified.speakerIntervalCount++;
        return;
    }
    g_deviceAudioComposite->audioUnified.speakerIntervalCount = 1;

    g_deviceAudioComposite->audioUnified.timesFeedbackCalculate++;
    if (g_deviceAudioComposite->audioUnified.timesFeedbackCalculate == 2)
    {
        originFeedbackValue = ((g_deviceAudioComposite->audioUnified.audioSendCount -
                                g_deviceAudioComposite->audioUnified.lastAudioSendCount)
                               << 4) /
                              (AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE);
        feedbackValue = originFeedbackValue;
        AUDIO_UPDATE_FEEDBACK_DATA(audioFeedBackBuffer, originFeedbackValue);
    }
    else if (g_deviceAudioComposite->audioUnified.timesFeedbackCalculate > 2)
    {
        usedSpace = AudioSpeakerBufferSpaceUsed();
        if (usedSpace >=
            AUDIO_BUFFER_UPPER_LIMIT(AUDIO_SPEAKER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_OUT_ENDP_PACKET_SIZE))
        {
            feedbackValue -= (AUDIO_SAMPLING_RATE_KHZ / AUDIO_SAMPLING_RATE_16KHZ) * (AUDIO_ADJUST_MIN_STEP);
        }
        else if (usedSpace <
                 AUDIO_BUFFER_LOWER_LIMIT(AUDIO_SPEAKER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_OUT_ENDP_PACKET_SIZE))
        {
            feedbackValue += (AUDIO_SAMPLING_RATE_KHZ / AUDIO_SAMPLING_RATE_16KHZ) * (AUDIO_ADJUST_MIN_STEP);
        }
        else
        {
        }
        AUDIO_UPDATE_FEEDBACK_DATA(audioFeedBackBuffer, feedbackValue);
    }
    else
    {
    }
    g_deviceAudioComposite->audioUnified.lastAudioSendCount = g_deviceAudioComposite->audioUnified.audioSendCount;
}

/* The USB_AudioRecorderBufferSpaceAvailable() function gets the reserved recorder ringbuffer size */
uint32_t USB_AudioRecorderBufferSpaceAvailable(void)
{
    if (g_deviceAudioComposite->audioUnified.tdReadNumberRec > g_deviceAudioComposite->audioUnified.tdWriteNumberRec)
    {
        g_deviceAudioComposite->audioUnified.recorderReservedSpace =
            g_deviceAudioComposite->audioUnified.tdReadNumberRec -
            g_deviceAudioComposite->audioUnified.tdWriteNumberRec;
    }
    else
    {
        g_deviceAudioComposite->audioUnified.recorderReservedSpace =
            g_deviceAudioComposite->audioUnified.tdReadNumberRec +
            AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE -
            g_deviceAudioComposite->audioUnified.tdWriteNumberRec;
    }
    return g_deviceAudioComposite->audioUnified.recorderReservedSpace;
}

/* The USB_RecorderDataMatch() function increase/decrease the adjusted packet interval according to the reserved
 * ringbuffer size */
uint32_t USB_RecorderDataMatch(uint32_t reservedspace)
{
    uint32_t epPacketSize = 0;
    if (reservedspace >= AUDIO_BUFFER_UPPER_LIMIT(AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE))
    {
        epPacketSize = FS_ISO_IN_ENDP_PACKET_SIZE + AUDIO_FORMAT_SIZE * AUDIO_FORMAT_CHANNELS;
    }
    else if ((reservedspace >=
              AUDIO_BUFFER_LOWER_LIMIT(AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE)) &&
             (reservedspace <
              AUDIO_BUFFER_UPPER_LIMIT(AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE)))
    {
        epPacketSize = FS_ISO_IN_ENDP_PACKET_SIZE;
    }
    else if (reservedspace <
             AUDIO_BUFFER_LOWER_LIMIT(AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE))
    {
        epPacketSize = FS_ISO_IN_ENDP_PACKET_SIZE - AUDIO_FORMAT_SIZE * AUDIO_FORMAT_CHANNELS;
    }
    else
    {
    }
    return epPacketSize;
}

/* The USB_AudioRecorderGetBuffer() function gets audioRecPacket from the audioRecDataBuff in every callback*/
void USB_AudioRecorderGetBuffer(uint8_t *buffer, uint32_t size)
{
    while (size)
    {
        *buffer = audioRecDataBuff[g_deviceAudioComposite->audioUnified.tdWriteNumberRec];
        g_deviceAudioComposite->audioUnified.tdWriteNumberRec++;
        buffer++;
        size--;

        if (g_deviceAudioComposite->audioUnified.tdWriteNumberRec >=
            AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE)
        {
            g_deviceAudioComposite->audioUnified.tdWriteNumberRec = 0;
        }
    }
}

/* The USB_AudioSpeakerPutBuffer() function fills the audioRecDataBuff with audioPlayPacket in every callback*/
void USB_AudioSpeakerPutBuffer(uint8_t *buffer, uint32_t size)
{
    while (size)
    {
        audioPlayDataBuff[g_deviceAudioComposite->audioUnified.tdReadNumberPlay] = *buffer;
        g_deviceAudioComposite->audioUnified.tdReadNumberPlay++;
        buffer++;
        size--;

        if (g_deviceAudioComposite->audioUnified.tdReadNumberPlay >=
            AUDIO_SPEAKER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_OUT_ENDP_PACKET_SIZE)
        {
            g_deviceAudioComposite->audioUnified.tdReadNumberPlay = 0;
        }
    }
}

/*!
 * @brief device Audio callback function.
 *
 * This function handle the Audio class specified event.
 * @param handle          The USB class  handle.
 * @param event           The USB device event type.
 * @param param           The parameter of the class specific event.
 * @return kStatus_USB_Success or error.
 */
usb_status_t USB_DeviceAudioCompositeCallback(class_handle_t handle, uint32_t event, void *param)
{
    usb_status_t error = kStatus_USB_Error;
    usb_device_endpoint_callback_message_struct_t *ep_cb_param;
    ep_cb_param = (usb_device_endpoint_callback_message_struct_t *)param;
    uint32_t epPacketSize = FS_ISO_IN_ENDP_PACKET_SIZE;

    switch (event)
    {
        case kUSB_DeviceAudioEventStreamSendResponse:
            if ((g_deviceAudioComposite->audioUnified.attach) && (ep_cb_param->length != (USB_UNINITIALIZED_VAL_32)))
            {
                if (ep_cb_param->length == ((USB_SPEED_HIGH == g_composite.speed) ? HS_ISO_FEEDBACK_ENDP_PACKET_SIZE :
                                                                                    FS_ISO_FEEDBACK_ENDP_PACKET_SIZE))
                {
                    error = USB_DeviceAudioSend(
                        g_deviceAudioComposite->audioUnified.audioSpeakerHandle, USB_AUDIO_SPEAKER_FEEDBACK_ENDPOINT,
                        audioFeedBackBuffer, (USB_SPEED_HIGH == g_composite.speed) ? HS_ISO_FEEDBACK_ENDP_PACKET_SIZE :
                                                                                     FS_ISO_FEEDBACK_ENDP_PACKET_SIZE);
                }
                else
                {
                    if (g_deviceAudioComposite->audioUnified.startRec == 0)
                    {
                        g_deviceAudioComposite->audioUnified.startRec = 1;
                    }
                    if ((g_deviceAudioComposite->audioUnified.tdReadNumberRec >=
                         AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE / 2) &&
                        (g_deviceAudioComposite->audioUnified.startRecHalfFull == 0))
                    {
                        g_deviceAudioComposite->audioUnified.startRecHalfFull = 1;
                    }
                    if (g_deviceAudioComposite->audioUnified.startRecHalfFull)
                    {
                        USB_AUDIO_ENTER_CRITICAL();
                        epPacketSize = USB_RecorderDataMatch(USB_AudioRecorderBufferSpaceAvailable());
                        USB_AUDIO_EXIT_CRITICAL();

                        USB_AudioRecorderGetBuffer(audioRecPacket, epPacketSize);

                        error =
                            USB_DeviceAudioSend(g_deviceAudioComposite->audioUnified.audioRecorderHandle,
                                                USB_AUDIO_RECORDER_STREAM_ENDPOINT, &audioRecPacket[0], epPacketSize);

                        g_deviceAudioComposite->audioUnified.usbSendTimes++;
                    }
                    else
                    {
                        error = USB_DeviceAudioSend(g_deviceAudioComposite->audioUnified.audioRecorderHandle,
                                                    USB_AUDIO_RECORDER_STREAM_ENDPOINT, &audioRecDataBuff[0],
                                                    FS_ISO_IN_ENDP_PACKET_SIZE);
                    }
                }
            }
            break;
        case kUSB_DeviceAudioEventStreamRecvResponse:
            if ((g_deviceAudioComposite->audioUnified.attach) && (ep_cb_param->length != (USB_UNINITIALIZED_VAL_32)))
            {
                if (g_deviceAudioComposite->audioUnified.startPlay == 0)
                {
                    g_deviceAudioComposite->audioUnified.startPlay = 1;
                }
                if ((g_deviceAudioComposite->audioUnified.tdReadNumberPlay >=
                     AUDIO_SPEAKER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_OUT_ENDP_PACKET_SIZE / 2) &&
                    (g_deviceAudioComposite->audioUnified.startPlayHalfFull == 0))
                {
                    g_deviceAudioComposite->audioUnified.startPlayHalfFull = 1;
                }
                USB_AudioSpeakerPutBuffer(audioPlayPacket, ep_cb_param->length);
                g_deviceAudioComposite->audioUnified.usbRecvCount += ep_cb_param->length;
                g_deviceAudioComposite->audioUnified.usbRecvTimes++;
                USB_AUDIO_ENTER_CRITICAL();
                USB_AudioFeedbackDataUpdate();
                USB_AUDIO_EXIT_CRITICAL();
                error = USB_DeviceAudioRecv(handle, USB_AUDIO_SPEAKER_STREAM_ENDPOINT, &audioPlayPacket[0],
                                            (FS_ISO_OUT_ENDP_PACKET_SIZE + AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE));
            }
            break;

        default:
            if (param && (event > 0xFF))
            {
                error = USB_DeviceAudioRequest(handle, event, param);
            }
            break;
    }

    return error;
}

/* The USB_DeviceAudioRecorderStatusReset() function resets the audio recorder status to the initialized status */
void USB_DeviceAudioRecorderStatusReset(void)
{
    g_deviceAudioComposite->audioUnified.startRec = 0;
    g_deviceAudioComposite->audioUnified.startRecHalfFull = 0;
    g_deviceAudioComposite->audioUnified.audioRecvCount = 0;
    g_deviceAudioComposite->audioUnified.usbSendTimes = 0;
    g_deviceAudioComposite->audioUnified.tdReadNumberRec = 0;
    g_deviceAudioComposite->audioUnified.tdWriteNumberRec = 0;
    g_deviceAudioComposite->audioUnified.recorderReservedSpace = 0;
}

/* The USB_DeviceAudioSpeakerStatusReset() function resets the audio speaker status to the initialized status */
void USB_DeviceAudioSpeakerStatusReset(void)
{
    g_deviceAudioComposite->audioUnified.startPlay = 0;
    g_deviceAudioComposite->audioUnified.startPlayHalfFull = 0;
    g_deviceAudioComposite->audioUnified.tdReadNumberPlay = 0;
    g_deviceAudioComposite->audioUnified.tdWriteNumberPlay = 0;
    g_deviceAudioComposite->audioUnified.audioSendCount = 0;
    g_deviceAudioComposite->audioUnified.usbRecvCount = 0;
    g_deviceAudioComposite->audioUnified.lastAudioSendCount = 0;
    g_deviceAudioComposite->audioUnified.audioSendTimes = 0;
    g_deviceAudioComposite->audioUnified.usbRecvTimes = 0;
    g_deviceAudioComposite->audioUnified.speakerIntervalCount = 0;
    g_deviceAudioComposite->audioUnified.speakerReservedSpace = 0;
    g_deviceAudioComposite->audioUnified.timesFeedbackCalculate = 0;
    g_deviceAudioComposite->audioUnified.speakerDetachOrNoInput = 0;
}

/*!
 * @brief Audio set configuration function.
 *
 * This function sets configuration for msc class.
 *
 * @param handle The Audio class handle.
 * @param configure The Audio class configure index.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceAudioCompositeSetConfigure(class_handle_t handle, uint8_t configure)
{
    if (USB_COMPOSITE_CONFIGURE_INDEX == configure)
    {
        g_deviceAudioComposite->audioUnified.attach = 1U;
    }
    return kStatus_USB_Success;
}

usb_status_t USB_DeviceAudioRecorderSetInterface(class_handle_t handle, uint8_t interface, uint8_t alternateSetting)
{
    if (alternateSetting == 1U)
    {
        USB_DeviceAudioRecorderStatusReset();
        USB_DeviceAudioSend(g_deviceAudioComposite->audioUnified.audioRecorderHandle,
                            USB_AUDIO_RECORDER_STREAM_ENDPOINT, &audioRecDataBuff[0], FS_ISO_IN_ENDP_PACKET_SIZE);
    }
    return kStatus_USB_Error;
}

usb_status_t USB_DeviceAudioSpeakerSetInterface(class_handle_t handle, uint8_t interface, uint8_t alternateSetting)
{
    if (alternateSetting == 1U)
    {
        USB_DeviceAudioSpeakerStatusReset();
        USB_DeviceAudioRecv(g_deviceAudioComposite->audioUnified.audioSpeakerHandle, USB_AUDIO_SPEAKER_STREAM_ENDPOINT,
                            &audioPlayDataBuff[0], FS_ISO_OUT_ENDP_PACKET_SIZE);

        USB_DeviceAudioSend(g_deviceAudioComposite->audioUnified.audioSpeakerHandle,
                            USB_AUDIO_SPEAKER_FEEDBACK_ENDPOINT, audioFeedBackBuffer,
                            (USB_SPEED_HIGH == g_composite.speed) ? HS_ISO_FEEDBACK_ENDP_PACKET_SIZE :
                                                                    FS_ISO_FEEDBACK_ENDP_PACKET_SIZE);
    }
    return kStatus_USB_Error;
}
/*!
 * @brief Audio init function.
 *
 * This function initializes the device with the composite device class information.
 *
 * @param device_composite          The pointer to the composite device structure.
 * @return kStatus_USB_Success .
 */
usb_status_t USB_DeviceAudioCompositeInit(usb_device_composite_struct_t *device_composite)
{
    g_deviceAudioComposite = device_composite;
    g_deviceAudioComposite->audioUnified.copyProtect = 0x01U;
    g_deviceAudioComposite->audioUnified.curMute = 0x00U;
    g_deviceAudioComposite->audioUnified.curVolume[0] = 0x00U;
    g_deviceAudioComposite->audioUnified.curVolume[1] = 0x80U;
    g_deviceAudioComposite->audioUnified.minVolume[0] = 0x00U;
    g_deviceAudioComposite->audioUnified.minVolume[1] = 0x80U;
    g_deviceAudioComposite->audioUnified.maxVolume[0] = 0xFFU;
    g_deviceAudioComposite->audioUnified.maxVolume[1] = 0X7FU;
    g_deviceAudioComposite->audioUnified.resVolume[0] = 0x01U;
    g_deviceAudioComposite->audioUnified.resVolume[1] = 0x00U;
    g_deviceAudioComposite->audioUnified.curBass = 0x00U;
    g_deviceAudioComposite->audioUnified.curBass = 0x00U;
    g_deviceAudioComposite->audioUnified.minBass = 0x80U;
    g_deviceAudioComposite->audioUnified.maxBass = 0x7FU;
    g_deviceAudioComposite->audioUnified.resBass = 0x01U;
    g_deviceAudioComposite->audioUnified.curMid = 0x00U;
    g_deviceAudioComposite->audioUnified.minMid = 0x80U;
    g_deviceAudioComposite->audioUnified.maxMid = 0x7FU;
    g_deviceAudioComposite->audioUnified.resMid = 0x01U;
    g_deviceAudioComposite->audioUnified.curTreble = 0x01U;
    g_deviceAudioComposite->audioUnified.minTreble = 0x80U;
    g_deviceAudioComposite->audioUnified.maxTreble = 0x7FU;
    g_deviceAudioComposite->audioUnified.resTreble = 0x01U;
    g_deviceAudioComposite->audioUnified.curAutomaticGain = 0x01U;
    g_deviceAudioComposite->audioUnified.curDelay[0] = 0x00U;
    g_deviceAudioComposite->audioUnified.curDelay[1] = 0x40U;
    g_deviceAudioComposite->audioUnified.minDelay[0] = 0x00U;
    g_deviceAudioComposite->audioUnified.minDelay[1] = 0x00U;
    g_deviceAudioComposite->audioUnified.maxDelay[0] = 0xFFU;
    g_deviceAudioComposite->audioUnified.maxDelay[1] = 0xFFU;
    g_deviceAudioComposite->audioUnified.resDelay[0] = 0x00U;
    g_deviceAudioComposite->audioUnified.resDelay[1] = 0x01U;
    g_deviceAudioComposite->audioUnified.curLoudness = 0x01U;
    g_deviceAudioComposite->audioUnified.curSamplingFrequency[0] = 0x00U;
    g_deviceAudioComposite->audioUnified.curSamplingFrequency[1] = 0x00U;
    g_deviceAudioComposite->audioUnified.curSamplingFrequency[2] = 0x01U;
    g_deviceAudioComposite->audioUnified.minSamplingFrequency[0] = 0x00U;
    g_deviceAudioComposite->audioUnified.minSamplingFrequency[1] = 0x00U;
    g_deviceAudioComposite->audioUnified.minSamplingFrequency[2] = 0x01U;
    g_deviceAudioComposite->audioUnified.maxSamplingFrequency[0] = 0x00U;
    g_deviceAudioComposite->audioUnified.maxSamplingFrequency[1] = 0x00U;
    g_deviceAudioComposite->audioUnified.maxSamplingFrequency[2] = 0x01U;
    g_deviceAudioComposite->audioUnified.resSamplingFrequency[0] = 0x00U;
    g_deviceAudioComposite->audioUnified.resSamplingFrequency[1] = 0x00U;
    g_deviceAudioComposite->audioUnified.resSamplingFrequency[2] = 0x01U;
    g_deviceAudioComposite->audioUnified.tdReadNumberPlay = 0;
    g_deviceAudioComposite->audioUnified.tdWriteNumberPlay = 0;
    g_deviceAudioComposite->audioUnified.tdReadNumberRec = 0;
    g_deviceAudioComposite->audioUnified.tdWriteNumberRec = 0;
    g_deviceAudioComposite->audioUnified.audioSendCount = 0;
    g_deviceAudioComposite->audioUnified.lastAudioSendCount = 0;
    g_deviceAudioComposite->audioUnified.usbRecvCount = 0;
    g_deviceAudioComposite->audioUnified.audioSendTimes = 0;
    g_deviceAudioComposite->audioUnified.usbRecvTimes = 0;
    g_deviceAudioComposite->audioUnified.audioRecvCount = 0;
    g_deviceAudioComposite->audioUnified.usbSendTimes = 0;
    g_deviceAudioComposite->audioUnified.startPlay = 0;
    g_deviceAudioComposite->audioUnified.startPlayHalfFull = 0;
    g_deviceAudioComposite->audioUnified.startRec = 0;
    g_deviceAudioComposite->audioUnified.startRecHalfFull = 0;
    g_deviceAudioComposite->audioUnified.speakerIntervalCount = 0;
    g_deviceAudioComposite->audioUnified.speakerReservedSpace = 0;
    g_deviceAudioComposite->audioUnified.recorderReservedSpace = 0;
    g_deviceAudioComposite->audioUnified.timesFeedbackCalculate = 0;
    g_deviceAudioComposite->audioUnified.speakerDetachOrNoInput = 0;
    return kStatus_USB_Success;
}

void USB_AudioCodecTask(void)
{
    if (g_deviceAudioComposite->audioUnified.codecTask & MUTE_CODEC_TASK)
    {
        usb_echo("Set Cur Mute : %x\r\n", g_deviceAudioComposite->audioUnified.curMute);
        BOARD_SetCodecMuteUnmute(true);
        g_deviceAudioComposite->audioUnified.codecTask &= ~MUTE_CODEC_TASK;
        g_CodecMuteUnmute = true;
    }
    if (g_deviceAudioComposite->audioUnified.codecTask & UNMUTE_CODEC_TASK)
    {
        usb_echo("Set Cur Mute : %x\r\n", g_deviceAudioComposite->audioUnified.curMute);
        BOARD_SetCodecMuteUnmute(false);
        g_deviceAudioComposite->audioUnified.codecTask &= ~UNMUTE_CODEC_TASK;
        g_CodecMuteUnmute = true;
    }
    if (g_deviceAudioComposite->audioUnified.codecTask & VOLUME_CHANGE_TASK)
    {
        usb_echo("Set Cur Volume : %x\r\n", (uint16_t)(g_deviceAudioComposite->audioUnified.curVolume[1] << 8U) |
                                                g_deviceAudioComposite->audioUnified.curVolume[0]);
        g_deviceAudioComposite->audioUnified.codecTask &= ~VOLUME_CHANGE_TASK;
    }
}

void USB_AudioSpeakerResetTask(void)
{
    if (g_deviceAudioComposite->audioUnified.speakerDetachOrNoInput)
    {
        USB_DeviceAudioSpeakerStatusReset();
    }
}
