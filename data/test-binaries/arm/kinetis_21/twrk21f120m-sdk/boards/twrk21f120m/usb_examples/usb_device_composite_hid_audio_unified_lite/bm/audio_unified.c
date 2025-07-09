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

#include "usb_device_audio.h"
#include "usb_device_ch9.h"
#include "usb_device_descriptor.h"

#include "audio_unified.h"

#include "fsl_device_registers.h"
#include "clock_config.h"
#include "board.h"
#include "fsl_debug_console.h"

#include <stdio.h>
#include <stdlib.h>

#include "composite.h"

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
volatile bool g_CodecMuteUnmute = false;

uint8_t g_InterfaceIsSet = 0;

static usb_device_composite_struct_t *g_deviceComposite;

usb_status_t USB_DeviceAudioProcessTerminalRequest(uint32_t audioCommand, uint32_t *length, uint8_t **buffer);

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
/* The AudioSpeakerBufferSpaceUsed() function gets the reserved speaker ringbuffer size */
uint32_t AudioSpeakerBufferSpaceUsed(void)
{
    if (g_deviceComposite->audioUnified.tdReadNumberPlay > g_deviceComposite->audioUnified.tdWriteNumberPlay)
    {
        g_deviceComposite->audioUnified.speakerReservedSpace =
            g_deviceComposite->audioUnified.tdReadNumberPlay - g_deviceComposite->audioUnified.tdWriteNumberPlay;
    }
    else
    {
        g_deviceComposite->audioUnified.speakerReservedSpace =
            g_deviceComposite->audioUnified.tdReadNumberPlay +
            AUDIO_SPEAKER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_OUT_ENDP_PACKET_SIZE -
            g_deviceComposite->audioUnified.tdWriteNumberPlay;
    }
    return g_deviceComposite->audioUnified.speakerReservedSpace;
}

/* The USB_AudioFeedbackDataUpdate() function calculates the feedback data */
void USB_AudioFeedbackDataUpdate()
{
    static uint32_t feedbackValue = 0x0, originFeedbackValue = 0x0;
    uint32_t usedSpace = 0;

    if (g_deviceComposite->audioUnified.speakerIntervalCount != AUDIO_CALCULATE_Ff_INTERVAL)
    {
        g_deviceComposite->audioUnified.speakerIntervalCount++;
        return;
    }
    g_deviceComposite->audioUnified.speakerIntervalCount = 1;

    g_deviceComposite->audioUnified.timesFeedbackCalculate++;
    if (g_deviceComposite->audioUnified.timesFeedbackCalculate == 2)
    {
        originFeedbackValue =
            ((g_deviceComposite->audioUnified.audioSendCount - g_deviceComposite->audioUnified.lastAudioSendCount)
             << 4) /
            (AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE);
        feedbackValue = originFeedbackValue;
        AUDIO_UPDATE_FEEDBACK_DATA(audioFeedBackBuffer, originFeedbackValue);
    }
    else if (g_deviceComposite->audioUnified.timesFeedbackCalculate > 2)
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
    g_deviceComposite->audioUnified.lastAudioSendCount = g_deviceComposite->audioUnified.audioSendCount;
}

/* The USB_AudioRecorderBufferSpaceAvailable() function gets the reserved recorder ringbuffer size */
uint32_t USB_AudioRecorderBufferSpaceAvailable(void)
{
    if (g_deviceComposite->audioUnified.tdReadNumberRec > g_deviceComposite->audioUnified.tdWriteNumberRec)
    {
        g_deviceComposite->audioUnified.recorderReservedSpace =
            g_deviceComposite->audioUnified.tdReadNumberRec - g_deviceComposite->audioUnified.tdWriteNumberRec;
    }
    else
    {
        g_deviceComposite->audioUnified.recorderReservedSpace =
            g_deviceComposite->audioUnified.tdReadNumberRec +
            AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE -
            g_deviceComposite->audioUnified.tdWriteNumberRec;
    }
    return g_deviceComposite->audioUnified.recorderReservedSpace;
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
        *buffer = audioRecDataBuff[g_deviceComposite->audioUnified.tdWriteNumberRec];
        g_deviceComposite->audioUnified.tdWriteNumberRec++;
        buffer++;
        size--;

        if (g_deviceComposite->audioUnified.tdWriteNumberRec >=
            AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE)
        {
            g_deviceComposite->audioUnified.tdWriteNumberRec = 0;
        }
    }
}

/* The USB_AudioSpeakerPutBuffer() function fills the audioRecDataBuff with audioPlayPacket in every callback*/
void USB_AudioSpeakerPutBuffer(uint8_t *buffer, uint32_t size)
{
    while (size)
    {
        audioPlayDataBuff[g_deviceComposite->audioUnified.tdReadNumberPlay] = *buffer;
        g_deviceComposite->audioUnified.tdReadNumberPlay++;
        buffer++;
        size--;

        if (g_deviceComposite->audioUnified.tdReadNumberPlay >=
            AUDIO_SPEAKER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_OUT_ENDP_PACKET_SIZE)
        {
            g_deviceComposite->audioUnified.tdReadNumberPlay = 0;
        }
    }
}
/*!
 * @brief Audio wav data prepare function.
 *
 * This function prepare audio wav data before send.
 */
/* USB device audio ISO OUT endpoint callback */
usb_status_t USB_DeviceAudioIsoIN(usb_device_handle deviceHandle,
                                  usb_device_endpoint_callback_message_struct_t *event,
                                  void *arg)
{
    usb_status_t error = kStatus_USB_Error;
    usb_device_endpoint_callback_message_struct_t *ep_cb_param;
    ep_cb_param = (usb_device_endpoint_callback_message_struct_t *)event;
    uint32_t epPacketSize = FS_ISO_IN_ENDP_PACKET_SIZE;
    if ((g_deviceComposite->audioUnified.attach) &&
        (ep_cb_param->length == ((USB_SPEED_HIGH == g_deviceComposite->audioUnified.speed) ?
                                     HS_ISO_FEEDBACK_ENDP_PACKET_SIZE :
                                     FS_ISO_FEEDBACK_ENDP_PACKET_SIZE)))
    {
        error = USB_DeviceSendRequest(deviceHandle, USB_AUDIO_SPEAKER_FEEDBACK_ENDPOINT, audioFeedBackBuffer,
                                      (USB_SPEED_HIGH == g_deviceComposite->audioUnified.speed) ?
                                          HS_ISO_FEEDBACK_ENDP_PACKET_SIZE :
                                          FS_ISO_FEEDBACK_ENDP_PACKET_SIZE);
    }
    else
    {
        if (g_deviceComposite->audioUnified.startRec == 0)
        {
            g_deviceComposite->audioUnified.startRec = 1;
        }
        if ((g_deviceComposite->audioUnified.tdReadNumberRec >=
             AUDIO_RECORDER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_IN_ENDP_PACKET_SIZE / 2) &&
            (g_deviceComposite->audioUnified.startRecHalfFull == 0))
        {
            g_deviceComposite->audioUnified.startRecHalfFull = 1;
        }
        if (g_deviceComposite->audioUnified.startRecHalfFull)
        {
            USB_AUDIO_ENTER_CRITICAL();
            epPacketSize = USB_RecorderDataMatch(USB_AudioRecorderBufferSpaceAvailable());
            USB_AUDIO_EXIT_CRITICAL();

            USB_AudioRecorderGetBuffer(audioRecPacket, epPacketSize);

            error = USB_DeviceSendRequest(deviceHandle, USB_AUDIO_RECORDER_STREAM_ENDPOINT, &audioRecPacket[0],
                                          epPacketSize);

            g_deviceComposite->audioUnified.usbSendTimes++;
        }
        else
        {
            error = USB_DeviceSendRequest(deviceHandle, USB_AUDIO_RECORDER_STREAM_ENDPOINT, &audioRecDataBuff[0],
                                          FS_ISO_IN_ENDP_PACKET_SIZE);
        }
    }

    return error;
}

/*!
 * @brief Audio wav data prepare function.
 *
 * This function prepare audio wav data before send.
 */
/* USB device audio ISO OUT endpoint callback */
usb_status_t USB_DeviceAudioIsoOUT(usb_device_handle deviceHandle,
                                   usb_device_endpoint_callback_message_struct_t *event,
                                   void *arg)
{
    usb_status_t error = kStatus_USB_Error;
    usb_device_endpoint_callback_message_struct_t *ep_cb_param;
    ep_cb_param = (usb_device_endpoint_callback_message_struct_t *)event;
    if ((g_deviceComposite->audioUnified.attach) && (ep_cb_param->length != (USB_UNINITIALIZED_VAL_32)))
    {
        if (g_deviceComposite->audioUnified.startPlay == 0)
        {
            g_deviceComposite->audioUnified.startPlay = 1;
        }
        if ((g_deviceComposite->audioUnified.tdReadNumberPlay >=
             AUDIO_SPEAKER_DATA_WHOLE_BUFFER_LENGTH * FS_ISO_OUT_ENDP_PACKET_SIZE / 2) &&
            (g_deviceComposite->audioUnified.startPlayHalfFull == 0))
        {
            g_deviceComposite->audioUnified.startPlayHalfFull = 1;
        }
        USB_AudioSpeakerPutBuffer(audioPlayPacket, ep_cb_param->length);
        g_deviceComposite->audioUnified.usbRecvCount += ep_cb_param->length;
        g_deviceComposite->audioUnified.usbRecvTimes++;
        USB_AUDIO_ENTER_CRITICAL();
        USB_AudioFeedbackDataUpdate();
        USB_AUDIO_EXIT_CRITICAL();
        error = USB_DeviceRecvRequest(deviceHandle, USB_AUDIO_SPEAKER_STREAM_ENDPOINT, &audioPlayPacket[0],
                                      (FS_ISO_OUT_ENDP_PACKET_SIZE + AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE));
    }
    return error;
}
usb_status_t USB_DeviceAudioGetControlTerminal(usb_device_handle handle,
                                               usb_setup_struct_t *setup,
                                               uint32_t *length,
                                               uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint32_t audioCommand = 0U;

    switch (setup->bRequest)
    {
        /* Copy Protect Control only supports the CUR attribute!*/
        case USB_DEVICE_AUDIO_GET_CUR_VOLUME_REQUEST:

            break;
        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);
    return error;
}

usb_status_t USB_DeviceAudioGetCurAudioFeatureUnit(usb_device_handle handle,
                                                   usb_setup_struct_t *setup,
                                                   uint32_t *length,
                                                   uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;
    /* Select SET request Control Feature Unit Module */
    switch (controlSelector)
    {
        case USB_DEVICE_AUDIO_MUTE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_MUTE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_VOLUME_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_VOLUME_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_BASS_CONTROL;
            break;
        case USB_DEVICE_AUDIO_MID_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_MID_CONTROL;
            break;
        case USB_DEVICE_AUDIO_TREBLE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_TREBLE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_GRAPHIC_EQUALIZER_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_GRAPHIC_EQUALIZER_CONTROL;
            break;
        case USB_DEVICE_AUDIO_AUTOMATIC_GAIN_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_AUTOMATIC_GAIN_CONTROL;
            break;
        case USB_DEVICE_AUDIO_DELAY_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_DELAY_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_BOOST_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_BASS_BOOST_CONTROL;
            break;
        case USB_DEVICE_AUDIO_LOUDNESS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_CUR_LOUDNESS_CONTROL;
            break;
        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);

    return error;
}

usb_status_t USB_DeviceAudioGetMinAudioFeatureUnit(usb_device_handle handle,
                                                   usb_setup_struct_t *setup,
                                                   uint32_t *length,
                                                   uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;

    /* Select SET request Control Feature Unit Module */
    switch (controlSelector)
    {
        case USB_DEVICE_AUDIO_VOLUME_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MIN_VOLUME_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MIN_BASS_CONTROL;
            break;
        case USB_DEVICE_AUDIO_MID_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MIN_MID_CONTROL;
            break;
        case USB_DEVICE_AUDIO_TREBLE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MIN_TREBLE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_GRAPHIC_EQUALIZER_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MIN_GRAPHIC_EQUALIZER_CONTROL;
            break;
        case USB_DEVICE_AUDIO_DELAY_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MIN_DELAY_CONTROL;
            break;
        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);
    return error;
}

usb_status_t USB_DeviceAudioGetMaxAudioFeatureUnit(usb_device_handle handle,
                                                   usb_setup_struct_t *setup,
                                                   uint32_t *length,
                                                   uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;

    /* Select SET request Control Feature Unit Module */
    switch (controlSelector)
    {
        case USB_DEVICE_AUDIO_VOLUME_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MAX_VOLUME_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MAX_BASS_CONTROL;
            break;
        case USB_DEVICE_AUDIO_MID_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MAX_MID_CONTROL;
            break;
        case USB_DEVICE_AUDIO_TREBLE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MAX_TREBLE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_GRAPHIC_EQUALIZER_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MAX_GRAPHIC_EQUALIZER_CONTROL;
            break;
        case USB_DEVICE_AUDIO_DELAY_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_MAX_DELAY_CONTROL;
            break;
        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);
    return error;
}

usb_status_t USB_DeviceAudioGetResAudioFeatureUnit(usb_device_handle handle,
                                                   usb_setup_struct_t *setup,
                                                   uint32_t *length,
                                                   uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;
    /* Select SET request Control Feature Unit Module */
    switch (controlSelector)
    {
        case USB_DEVICE_AUDIO_VOLUME_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_RES_VOLUME_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_RES_BASS_CONTROL;
            break;
        case USB_DEVICE_AUDIO_MID_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_RES_MID_CONTROL;
            break;
        case USB_DEVICE_AUDIO_TREBLE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_RES_TREBLE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_GRAPHIC_EQUALIZER_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_RES_GRAPHIC_EQUALIZER_CONTROL;
            break;
        case USB_DEVICE_AUDIO_DELAY_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_GET_RES_DELAY_CONTROL;
            break;
        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);

    return error;
}

usb_status_t USB_DeviceAudioSetCurAudioFeatureUnit(usb_device_handle handle,
                                                   usb_setup_struct_t *setup,
                                                   uint32_t *length,
                                                   uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;

    switch (controlSelector)
    {
        case USB_DEVICE_AUDIO_MUTE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_MUTE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_VOLUME_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_VOLUME_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_BASS_CONTROL;
            break;
        case USB_DEVICE_AUDIO_MID_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_MID_CONTROL;
            break;
        case USB_DEVICE_AUDIO_TREBLE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_TREBLE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_GRAPHIC_EQUALIZER_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_GRAPHIC_EQUALIZER_CONTROL;
            break;
        case USB_DEVICE_AUDIO_AUTOMATIC_GAIN_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_AUTOMATIC_GAIN_CONTROL;
            break;
        case USB_DEVICE_AUDIO_DELAY_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_DELAY_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_BOOST_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_BASS_BOOST_CONTROL;
            break;
        case USB_DEVICE_AUDIO_LOUDNESS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_CUR_LOUDNESS_CONTROL;
            break;
        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);
    return error;
}

usb_status_t USB_DeviceAudioSetMinAudioFeatureUnit(usb_device_handle handle,
                                                   usb_setup_struct_t *setup,
                                                   uint32_t *length,
                                                   uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;
    switch (controlSelector)
    {
        case USB_DEVICE_AUDIO_VOLUME_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MIN_VOLUME_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MIN_BASS_CONTROL;
            break;
        case USB_DEVICE_AUDIO_MID_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MIN_MID_CONTROL;
            break;
        case USB_DEVICE_AUDIO_TREBLE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MIN_TREBLE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_GRAPHIC_EQUALIZER_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MIN_GRAPHIC_EQUALIZER_CONTROL;
            break;
        case USB_DEVICE_AUDIO_DELAY_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MIN_DELAY_CONTROL;
            break;
        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);

    return error;
}

usb_status_t USB_DeviceAudioSetMaxAudioFeatureUnit(usb_device_handle handle,
                                                   usb_setup_struct_t *setup,
                                                   uint32_t *length,
                                                   uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;
    switch (controlSelector)
    {
        case USB_DEVICE_AUDIO_VOLUME_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MAX_VOLUME_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MAX_BASS_CONTROL;
            break;
        case USB_DEVICE_AUDIO_MID_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MAX_MID_CONTROL;
            break;
        case USB_DEVICE_AUDIO_TREBLE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MAX_TREBLE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_GRAPHIC_EQUALIZER_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MAX_GRAPHIC_EQUALIZER_CONTROL;
            break;
        case USB_DEVICE_AUDIO_DELAY_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_MAX_DELAY_CONTROL;
            break;
        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);

    return error;
}

usb_status_t USB_DeviceAudioSetResAudioFeatureUnit(usb_device_handle handle,
                                                   usb_setup_struct_t *setup,
                                                   uint32_t *length,
                                                   uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;
    switch (controlSelector)
    {
        case USB_DEVICE_AUDIO_VOLUME_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_RES_VOLUME_CONTROL;
            break;
        case USB_DEVICE_AUDIO_BASS_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_RES_BASS_CONTROL;
            break;
        case USB_DEVICE_AUDIO_MID_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_RES_MID_CONTROL;
            break;
        case USB_DEVICE_AUDIO_TREBLE_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_RES_TREBLE_CONTROL;
            break;
        case USB_DEVICE_AUDIO_GRAPHIC_EQUALIZER_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_RES_GRAPHIC_EQUALIZER_CONTROL;
            break;
        case USB_DEVICE_AUDIO_DELAY_CONTROL_SELECTOR:
            audioCommand = USB_DEVICE_AUDIO_SET_RES_DELAY_CONTROL;
            break;
        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);
    return error;
}

usb_status_t USB_DeviceAudioGetFeatureUnit(usb_device_handle handle,
                                           usb_setup_struct_t *setup,
                                           uint32_t *length,
                                           uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;

    /* Select SET request Control Feature Unit Module */
    switch (setup->bRequest)
    {
        case USB_DEVICE_AUDIO_GET_CUR_VOLUME_REQUEST:
            error = USB_DeviceAudioGetCurAudioFeatureUnit(handle, setup, length, buffer);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_VOLUME_REQUEST:
            error = USB_DeviceAudioGetMinAudioFeatureUnit(handle, setup, length, buffer);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_VOLUME_REQUEST:
            error = USB_DeviceAudioGetMaxAudioFeatureUnit(handle, setup, length, buffer);
            break;
        case USB_DEVICE_AUDIO_GET_RES_VOLUME_REQUEST:
            error = USB_DeviceAudioGetResAudioFeatureUnit(handle, setup, length, buffer);
            break;
        default:
            break;
    }
    return error;
}

usb_status_t USB_DeviceAudioSetFeatureUnit(usb_device_handle handle,
                                           usb_setup_struct_t *setup,
                                           uint32_t *length,
                                           uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    /* Select SET request Control Feature Unit Module */
    switch (setup->bRequest)
    {
        case USB_DEVICE_AUDIO_SET_CUR_VOLUME_REQUEST:
            error = USB_DeviceAudioSetCurAudioFeatureUnit(handle, setup, length, buffer);
            break;
        case USB_DEVICE_AUDIO_SET_MIN_VOLUME_REQUEST:
            error = USB_DeviceAudioSetMinAudioFeatureUnit(handle, setup, length, buffer);
            break;
        case USB_DEVICE_AUDIO_SET_MAX_VOLUME_REQUEST:
            error = USB_DeviceAudioSetMaxAudioFeatureUnit(handle, setup, length, buffer);
            break;
        case USB_DEVICE_AUDIO_SET_RES_VOLUME_REQUEST:
            error = USB_DeviceAudioSetResAudioFeatureUnit(handle, setup, length, buffer);
            break;
        default:
            break;
    }
    return error;
}

usb_status_t USB_DeviceAudioSetControlTerminal(usb_device_handle handle,
                                               usb_setup_struct_t *setup,
                                               uint32_t *length,
                                               uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;

    return error;
}

usb_status_t USB_DeviceAudioSetRequestInterface(usb_device_handle handle,
                                                usb_setup_struct_t *setup,
                                                uint32_t *length,
                                                uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t entity_id = (uint8_t)(setup->wIndex >> 0x08);

    if ((entity_id == USB_AUDIO_RECORDER_CONTROL_OUTPUT_TERMINAL_ID) ||
        (entity_id == USB_AUDIO_SPEAKER_CONTROL_OUTPUT_TERMINAL_ID))
    {
        error = USB_DeviceAudioSetControlTerminal(handle, setup, length, buffer);
    }
    else if ((entity_id == USB_AUDIO_RECORDER_CONTROL_FEATURE_UNIT_ID) ||
             (entity_id == USB_AUDIO_SPEAKER_CONTROL_FEATURE_UNIT_ID))
    {
        error = USB_DeviceAudioSetFeatureUnit(handle, setup, length, buffer);
    }
    else
    {
    }

    return error;
}

usb_status_t USB_DeviceAudioGetRequestInterface(usb_device_handle handle,
                                                usb_setup_struct_t *setup,
                                                uint32_t *length,
                                                uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t entity_id = (uint8_t)(setup->wIndex >> 0x08);
    if ((entity_id == USB_AUDIO_RECORDER_CONTROL_INPUT_TERMINAL_ID) ||
        (entity_id == USB_AUDIO_SPEAKER_CONTROL_INPUT_TERMINAL_ID))
    {
        error = USB_DeviceAudioGetControlTerminal(handle, setup, length, buffer);
    }
    else if (entity_id == USB_AUDIO_RECORDER_CONTROL_FEATURE_UNIT_ID)
    {
        error = USB_DeviceAudioGetFeatureUnit(handle, setup, length, buffer);
    }
    else if (entity_id == USB_AUDIO_SPEAKER_CONTROL_FEATURE_UNIT_ID)
    {
        error = USB_DeviceAudioGetFeatureUnit(handle, setup, length, buffer);
    }
    else
    {
    }
    return error;
}

usb_status_t USB_DeviceAudioSetRequestEndpoint(usb_device_handle handle,
                                               usb_setup_struct_t *setup,
                                               uint32_t *length,
                                               uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;

    /* Select SET request Control Feature Unit Module */
    switch (setup->bRequest)
    {
        case USB_DEVICE_AUDIO_SET_CUR_VOLUME_REQUEST:
            switch (controlSelector)
            {
                case USB_DEVICE_AUDIO_SAMPLING_FREQ_CONTROL_SELECTOR:
                    audioCommand = USB_DEVICE_AUDIO_SET_CUR_SAMPLING_FREQ_CONTROL;
                    break;
                case USB_DEVICE_AUDIO_PITCH_CONTROL_SELECTOR:
                    audioCommand = USB_DEVICE_AUDIO_SET_CUR_PITCH_CONTROL;
                    break;
                default:
                    break;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MIN_VOLUME_REQUEST:
            switch (controlSelector)
            {
                case USB_DEVICE_AUDIO_SAMPLING_FREQ_CONTROL_SELECTOR:
                    audioCommand = USB_DEVICE_AUDIO_SET_MIN_SAMPLING_FREQ_CONTROL;
                    break;
                default:
                    break;
            }
            break;
        case USB_DEVICE_AUDIO_SET_MAX_VOLUME_REQUEST:
            switch (controlSelector)
            {
                case USB_DEVICE_AUDIO_SAMPLING_FREQ_CONTROL_SELECTOR:
                    audioCommand = USB_DEVICE_AUDIO_SET_MAX_SAMPLING_FREQ_CONTROL;
                    break;
                default:
                    break;
            }
            break;
        case USB_DEVICE_AUDIO_SET_RES_VOLUME_REQUEST:
            switch (controlSelector)
            {
                case USB_DEVICE_AUDIO_SAMPLING_FREQ_CONTROL_SELECTOR:
                    audioCommand = USB_DEVICE_AUDIO_SET_RES_SAMPLING_FREQ_CONTROL;
                    break;
                default:
                    break;
            }
            break;

        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);
    return error;
}

usb_status_t USB_DeviceAudioGetRequestEndpoint(usb_device_handle handle,
                                               usb_setup_struct_t *setup,
                                               uint32_t *length,
                                               uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;
    uint8_t controlSelector = (setup->wValue >> 0x08) & 0xFFU;
    uint32_t audioCommand = 0U;
    /* Select SET request Control Feature Unit Module */
    switch (setup->bRequest)
    {
        case USB_DEVICE_AUDIO_GET_CUR_VOLUME_REQUEST:
            switch (controlSelector)
            {
                case USB_DEVICE_AUDIO_SAMPLING_FREQ_CONTROL_SELECTOR:

                    audioCommand = USB_DEVICE_AUDIO_GET_CUR_SAMPLING_FREQ_CONTROL;
                    break;
                default:
                    break;
            }
            break;
        case USB_DEVICE_AUDIO_GET_MIN_VOLUME_REQUEST:
            switch (controlSelector)
            {
                case USB_DEVICE_AUDIO_SAMPLING_FREQ_CONTROL_SELECTOR:

                    audioCommand = USB_DEVICE_AUDIO_GET_MIN_SAMPLING_FREQ_CONTROL;
                    break;
                default:
                    break;
            }
            break;
        case USB_DEVICE_AUDIO_GET_MAX_VOLUME_REQUEST:
            switch (controlSelector)
            {
                case USB_DEVICE_AUDIO_SAMPLING_FREQ_CONTROL_SELECTOR:

                    audioCommand = USB_DEVICE_AUDIO_GET_MAX_SAMPLING_FREQ_CONTROL;
                    break;
                default:
                    break;
            }
            break;
        case USB_DEVICE_AUDIO_GET_RES_VOLUME_REQUEST:
            switch (controlSelector)
            {
                case USB_DEVICE_AUDIO_SAMPLING_FREQ_CONTROL_SELECTOR:
                    audioCommand = USB_DEVICE_AUDIO_GET_RES_SAMPLING_FREQ_CONTROL;

                    break;
                default:
                    break;
            }
            break;

        default:
            break;
    }
    error = USB_DeviceAudioProcessTerminalRequest(audioCommand, length, buffer);
    return error;
}

usb_status_t USB_DeviceAudioUnifiedClassRequestIntfRecipient(usb_device_handle handle,
                                                usb_setup_struct_t *setup,
                                                uint32_t *length,
                                                uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;

    switch (setup->bmRequestType)
    {
        case USB_DEVICE_AUDIO_SET_REQUEST_INTERFACE:
            error = USB_DeviceAudioSetRequestInterface(handle, setup, length, buffer);
            break;
        case USB_DEVICE_AUDIO_GET_REQUEST_INTERFACE:
            error = USB_DeviceAudioGetRequestInterface(handle, setup, length, buffer);
            break;
        default:
            break;
    }

    return error;
}

usb_status_t USB_DeviceAudioUnifiedClassRequestEndpRecipient(usb_device_handle handle,
                                                usb_setup_struct_t *setup,
                                                uint32_t *length,
                                                uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_InvalidRequest;

    switch (setup->bmRequestType)
    {
        case USB_DEVICE_AUDIO_SET_REQUEST_ENDPOINT:
            error = USB_DeviceAudioSetRequestEndpoint(handle, setup, length, buffer);
            break;
        case USB_DEVICE_AUDIO_GET_REQUEST_ENDPOINT:
            error = USB_DeviceAudioGetRequestEndpoint(handle, setup, length, buffer);
            break;
        default:
            break;
    }

    return error;
}

usb_status_t USB_DeviceAudioProcessTerminalRequest(uint32_t audioCommand, uint32_t *length, uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_Success;
    uint16_t volume = 0;
    uint8_t *volBuffAddr;

    switch (audioCommand)
    {
        case USB_DEVICE_AUDIO_GET_CUR_MUTE_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.curMute;
            *length = sizeof(g_deviceComposite->audioUnified.curMute);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_VOLUME_CONTROL:
            *buffer = g_deviceComposite->audioUnified.curVolume;
            *length = sizeof(g_deviceComposite->audioUnified.curVolume);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_BASS_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.curBass;
            *length = sizeof(g_deviceComposite->audioUnified.curBass);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_MID_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.curMid;
            *length = sizeof(g_deviceComposite->audioUnified.curMid);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_TREBLE_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.curTreble;
            *length = sizeof(g_deviceComposite->audioUnified.curTreble);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_AUTOMATIC_GAIN_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.curAutomaticGain;
            *length = sizeof(g_deviceComposite->audioUnified.curAutomaticGain);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_DELAY_CONTROL:
            *buffer = g_deviceComposite->audioUnified.curDelay;
            *length = sizeof(g_deviceComposite->audioUnified.curDelay);
            break;
        case USB_DEVICE_AUDIO_GET_CUR_SAMPLING_FREQ_CONTROL:
            *buffer = g_deviceComposite->audioUnified.curSamplingFrequency;
            *length = sizeof(g_deviceComposite->audioUnified.curSamplingFrequency);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_VOLUME_CONTROL:
            *buffer = g_deviceComposite->audioUnified.minVolume;
            *length = sizeof(g_deviceComposite->audioUnified.minVolume);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_BASS_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.minBass;
            *length = sizeof(g_deviceComposite->audioUnified.minBass);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_MID_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.minMid;
            *length = sizeof(g_deviceComposite->audioUnified.minMid);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_TREBLE_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.minTreble;
            *length = sizeof(g_deviceComposite->audioUnified.minTreble);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_DELAY_CONTROL:
            *buffer = g_deviceComposite->audioUnified.minDelay;
            *length = sizeof(g_deviceComposite->audioUnified.minDelay);
            break;
        case USB_DEVICE_AUDIO_GET_MIN_SAMPLING_FREQ_CONTROL:
            *buffer = g_deviceComposite->audioUnified.minSamplingFrequency;
            *length = sizeof(g_deviceComposite->audioUnified.minSamplingFrequency);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_VOLUME_CONTROL:
            *buffer = g_deviceComposite->audioUnified.maxVolume;
            *length = sizeof(g_deviceComposite->audioUnified.maxVolume);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_BASS_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.maxBass;
            *length = sizeof(g_deviceComposite->audioUnified.maxBass);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_MID_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.maxMid;
            *length = sizeof(g_deviceComposite->audioUnified.maxMid);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_TREBLE_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.maxTreble;
            *length = sizeof(g_deviceComposite->audioUnified.maxTreble);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_DELAY_CONTROL:
            *buffer = g_deviceComposite->audioUnified.maxDelay;
            *length = sizeof(g_deviceComposite->audioUnified.maxDelay);
            break;
        case USB_DEVICE_AUDIO_GET_MAX_SAMPLING_FREQ_CONTROL:
            *buffer = g_deviceComposite->audioUnified.maxSamplingFrequency;
            *length = sizeof(g_deviceComposite->audioUnified.maxSamplingFrequency);
            break;
        case USB_DEVICE_AUDIO_GET_RES_VOLUME_CONTROL:
            *buffer = g_deviceComposite->audioUnified.resVolume;
            *length = sizeof(g_deviceComposite->audioUnified.resVolume);
            break;
        case USB_DEVICE_AUDIO_GET_RES_BASS_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.resBass;
            *length = sizeof(g_deviceComposite->audioUnified.resBass);
            break;
        case USB_DEVICE_AUDIO_GET_RES_MID_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.resMid;
            *length = sizeof(g_deviceComposite->audioUnified.resMid);
            break;
        case USB_DEVICE_AUDIO_GET_RES_TREBLE_CONTROL:
            *buffer = &g_deviceComposite->audioUnified.resTreble;
            *length = sizeof(g_deviceComposite->audioUnified.resTreble);
            break;
        case USB_DEVICE_AUDIO_GET_RES_DELAY_CONTROL:
            *buffer = g_deviceComposite->audioUnified.resDelay;
            *length = sizeof(g_deviceComposite->audioUnified.resDelay);
            break;
        case USB_DEVICE_AUDIO_GET_RES_SAMPLING_FREQ_CONTROL:
            *buffer = g_deviceComposite->audioUnified.resSamplingFrequency;
            *length = sizeof(g_deviceComposite->audioUnified.resSamplingFrequency);
            break;

        case USB_DEVICE_AUDIO_SET_CUR_VOLUME_CONTROL:
            volBuffAddr = *buffer;
            g_deviceComposite->audioUnified.curVolume[0] = *volBuffAddr;
            g_deviceComposite->audioUnified.curVolume[1] = *(volBuffAddr + 1);
            volume = (uint16_t)((uint16_t)g_deviceComposite->audioUnified.curVolume[1] << 8U);
            volume |= (uint8_t)(g_deviceComposite->audioUnified.curVolume[0]);
            g_deviceComposite->audioUnified.codecTask |= VOLUME_CHANGE_TASK;
            break;
        case USB_DEVICE_AUDIO_SET_CUR_MUTE_CONTROL:
            g_deviceComposite->audioUnified.curMute = **(buffer);
            if (g_deviceComposite->audioUnified.curMute)
            {
                g_deviceComposite->audioUnified.codecTask |= MUTE_CODEC_TASK;
            }
            else
            {
                g_deviceComposite->audioUnified.codecTask |= UNMUTE_CODEC_TASK;
            }
            break;
        case USB_DEVICE_AUDIO_SET_CUR_BASS_CONTROL:
            g_deviceComposite->audioUnified.curBass = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_CUR_MID_CONTROL:
            g_deviceComposite->audioUnified.curMid = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_CUR_TREBLE_CONTROL:
            g_deviceComposite->audioUnified.curTreble = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_CUR_AUTOMATIC_GAIN_CONTROL:
            g_deviceComposite->audioUnified.curAutomaticGain = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_CUR_DELAY_CONTROL:
            g_deviceComposite->audioUnified.curDelay[0] = **(buffer);
            g_deviceComposite->audioUnified.curDelay[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_CUR_SAMPLING_FREQ_CONTROL:
            g_deviceComposite->audioUnified.curSamplingFrequency[0] = **(buffer);
            g_deviceComposite->audioUnified.curSamplingFrequency[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_MIN_VOLUME_CONTROL:
            g_deviceComposite->audioUnified.minVolume[0] = **(buffer);
            g_deviceComposite->audioUnified.minVolume[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_MIN_BASS_CONTROL:
            g_deviceComposite->audioUnified.minBass = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_MIN_MID_CONTROL:
            g_deviceComposite->audioUnified.minMid = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_MIN_TREBLE_CONTROL:
            g_deviceComposite->audioUnified.minTreble = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_MIN_DELAY_CONTROL:
            g_deviceComposite->audioUnified.minDelay[0] = **(buffer);
            g_deviceComposite->audioUnified.minDelay[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_MIN_SAMPLING_FREQ_CONTROL:
            g_deviceComposite->audioUnified.minSamplingFrequency[0] = **(buffer);
            g_deviceComposite->audioUnified.minSamplingFrequency[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_MAX_VOLUME_CONTROL:
            g_deviceComposite->audioUnified.maxVolume[0] = **(buffer);
            g_deviceComposite->audioUnified.maxVolume[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_MAX_BASS_CONTROL:
            g_deviceComposite->audioUnified.maxBass = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_MAX_MID_CONTROL:
            g_deviceComposite->audioUnified.maxMid = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_MAX_TREBLE_CONTROL:
            g_deviceComposite->audioUnified.maxTreble = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_MAX_DELAY_CONTROL:
            g_deviceComposite->audioUnified.maxDelay[0] = **(buffer);
            g_deviceComposite->audioUnified.maxDelay[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_MAX_SAMPLING_FREQ_CONTROL:
            g_deviceComposite->audioUnified.maxSamplingFrequency[0] = **(buffer);
            g_deviceComposite->audioUnified.maxSamplingFrequency[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_RES_VOLUME_CONTROL:
            g_deviceComposite->audioUnified.resVolume[0] = **(buffer);
            g_deviceComposite->audioUnified.resVolume[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_RES_BASS_CONTROL:
            g_deviceComposite->audioUnified.resBass = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_RES_MID_CONTROL:
            g_deviceComposite->audioUnified.resMid = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_RES_TREBLE_CONTROL:
            g_deviceComposite->audioUnified.resTreble = **(buffer);
            break;
        case USB_DEVICE_AUDIO_SET_RES_DELAY_CONTROL:
            g_deviceComposite->audioUnified.resDelay[0] = **(buffer);
            g_deviceComposite->audioUnified.resDelay[1] = **(buffer + 1);
            break;
        case USB_DEVICE_AUDIO_SET_RES_SAMPLING_FREQ_CONTROL:
            g_deviceComposite->audioUnified.resSamplingFrequency[0] = **(buffer);
            g_deviceComposite->audioUnified.resSamplingFrequency[1] = **(buffer + 1);
            break;
        default:
            error = kStatus_USB_InvalidRequest;
            break;
    }
    return error;
}

usb_status_t USB_DeviceAudioUnifiedConfigureEndpointStatus(usb_device_handle handle, uint8_t ep, uint8_t status)
{
    usb_status_t error = kStatus_USB_Error;
    if (status)
    {
        if ((USB_AUDIO_RECORDER_STREAM_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
            (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            return USB_DeviceStallEndpoint(handle, ep);
        }
        else if ((USB_AUDIO_CONTROL_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
                 (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            return USB_DeviceStallEndpoint(handle, ep);
        }
        else if ((USB_AUDIO_SPEAKER_STREAM_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
                 (!(ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK)))
        {
            return USB_DeviceStallEndpoint(handle, ep);
        }
        else if ((USB_AUDIO_SPEAKER_FEEDBACK_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
                 (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            return USB_DeviceStallEndpoint(handle, ep);
        }
        else
        {
        }
    }
    else
    {
        if ((USB_AUDIO_RECORDER_STREAM_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
            (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            return USB_DeviceUnstallEndpoint(handle, ep);
        }
        else if ((USB_AUDIO_CONTROL_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
                 (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            return USB_DeviceUnstallEndpoint(handle, ep);
        }
        else if ((USB_AUDIO_SPEAKER_STREAM_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
                 (!(ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK)))
        {
            return USB_DeviceUnstallEndpoint(handle, ep);
        }
        else if ((USB_AUDIO_SPEAKER_FEEDBACK_ENDPOINT == (ep & USB_ENDPOINT_NUMBER_MASK)) &&
                 (ep & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK))
        {
            return USB_DeviceUnstallEndpoint(handle, ep);
        }
        else
        {
        }
    }
    return error;
}

/* The USB_DeviceAudioRecorderStatusReset() function resets the audio recorder status to the initialized status */
void USB_DeviceAudioRecorderStatusReset(void)
{
    g_deviceComposite->audioUnified.startRec = 0;
    g_deviceComposite->audioUnified.startRecHalfFull = 0;
    g_deviceComposite->audioUnified.audioRecvCount = 0;
    g_deviceComposite->audioUnified.usbSendTimes = 0;
    g_deviceComposite->audioUnified.tdReadNumberRec = 0;
    g_deviceComposite->audioUnified.tdWriteNumberRec = 0;
    g_deviceComposite->audioUnified.recorderReservedSpace = 0;
}

/* The USB_DeviceAudioSpeakerStatusReset() function resets the audio speaker status to the initialized status */
void USB_DeviceAudioSpeakerStatusReset(void)
{
    g_deviceComposite->audioUnified.startPlay = 0;
    g_deviceComposite->audioUnified.startPlayHalfFull = 0;
    g_deviceComposite->audioUnified.tdReadNumberPlay = 0;
    g_deviceComposite->audioUnified.tdWriteNumberPlay = 0;
    g_deviceComposite->audioUnified.audioSendCount = 0;
    g_deviceComposite->audioUnified.usbRecvCount = 0;
    g_deviceComposite->audioUnified.lastAudioSendCount = 0;
    g_deviceComposite->audioUnified.audioSendTimes = 0;
    g_deviceComposite->audioUnified.usbRecvTimes = 0;
    g_deviceComposite->audioUnified.speakerIntervalCount = 0;
    g_deviceComposite->audioUnified.speakerReservedSpace = 0;
    g_deviceComposite->audioUnified.timesFeedbackCalculate = 0;
    g_deviceComposite->audioUnified.speakerDetachOrNoInput = 0;
}

/*!
 * @brief Audio Generator device set configuration function.
 *
 * This function sets configuration for Audio class.
 *
 * @param handle The Audio class handle.
 * @param configure The Audio class configure index.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceAudioUnifiedSetConfigure(usb_device_handle handle, uint8_t configure)
{
    usb_status_t error = kStatus_USB_Success;
    if (USB_COMPOSITE_CONFIGURE_INDEX == configure)
    {
        g_deviceComposite->audioUnified.attach = 1U;
    }
    return error;
}

usb_status_t USB_DeviceAudioRecorderSetInterface(usb_device_handle handle, uint8_t interface, uint8_t alternateSetting)
{
    usb_device_endpoint_init_struct_t epInitStruct;
    usb_device_endpoint_callback_struct_t epCallback;
    usb_status_t error = kStatus_USB_Error;

    epCallback.callbackFn = USB_DeviceAudioIsoIN;
    epCallback.callbackParam = handle;

    epInitStruct.zlt = 0U;
    epInitStruct.transferType = USB_ENDPOINT_ISOCHRONOUS;
    epInitStruct.endpointAddress =
        USB_AUDIO_RECORDER_STREAM_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
    if (USB_SPEED_HIGH == g_deviceComposite->speed)
    {
        epInitStruct.maxPacketSize = HS_ISO_IN_ENDP_PACKET_SIZE;
    }
    else
    {
        epInitStruct.maxPacketSize = FS_ISO_IN_ENDP_PACKET_SIZE;
    }

    USB_DeviceInitEndpoint(handle, &epInitStruct, &epCallback);
    error = USB_DeviceSendRequest(handle, USB_AUDIO_RECORDER_STREAM_ENDPOINT, &audioRecDataBuff[0],
                                  (USB_SPEED_HIGH == g_deviceComposite->audioUnified.speed) ?
                                      (HS_ISO_IN_ENDP_PACKET_SIZE + AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE) :
                                      (FS_ISO_IN_ENDP_PACKET_SIZE + AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE));
    return error;
}

usb_status_t USB_DeviceAudioSpeakerSetInterface(usb_device_handle handle, uint8_t interface, uint8_t alternateSetting)
{
    usb_device_endpoint_init_struct_t epInitStruct;
    usb_device_endpoint_callback_struct_t epCallback;
    usb_status_t error = kStatus_USB_Error;

    epCallback.callbackFn = USB_DeviceAudioIsoIN;
    epCallback.callbackParam = handle;

    epInitStruct.zlt = 0U;
    epInitStruct.transferType = USB_ENDPOINT_ISOCHRONOUS;
    epInitStruct.endpointAddress =
        USB_AUDIO_SPEAKER_FEEDBACK_ENDPOINT | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
    if (USB_SPEED_HIGH == g_deviceComposite->speed)
    {
        epInitStruct.maxPacketSize = HS_ISO_FEEDBACK_ENDP_PACKET_SIZE;
    }
    else
    {
        epInitStruct.maxPacketSize = FS_ISO_FEEDBACK_ENDP_PACKET_SIZE;
    }
    USB_DeviceInitEndpoint(handle, &epInitStruct, &epCallback);
    error = USB_DeviceSendRequest(handle, USB_AUDIO_SPEAKER_FEEDBACK_ENDPOINT, audioFeedBackBuffer,
                                  (USB_SPEED_HIGH == g_deviceComposite->audioUnified.speed) ?
                                      HS_ISO_FEEDBACK_ENDP_PACKET_SIZE :
                                      FS_ISO_FEEDBACK_ENDP_PACKET_SIZE);

    epCallback.callbackFn = USB_DeviceAudioIsoOUT;
    epCallback.callbackParam = handle;

    epInitStruct.zlt = 0U;
    epInitStruct.transferType = USB_ENDPOINT_ISOCHRONOUS;
    epInitStruct.endpointAddress =
        USB_AUDIO_SPEAKER_STREAM_ENDPOINT | (USB_OUT << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT);
    if (USB_SPEED_HIGH == g_deviceComposite->speed)
    {
        epInitStruct.maxPacketSize = (HS_ISO_OUT_ENDP_PACKET_SIZE + AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE);
    }
    else
    {
        epInitStruct.maxPacketSize = (FS_ISO_OUT_ENDP_PACKET_SIZE + AUDIO_FORMAT_CHANNELS * AUDIO_FORMAT_SIZE);
    }
    USB_DeviceInitEndpoint(handle, &epInitStruct, &epCallback);
    error =
        USB_DeviceRecvRequest(handle, USB_AUDIO_SPEAKER_STREAM_ENDPOINT, &audioPlayDataBuff[0],
                              (USB_SPEED_HIGH == g_deviceComposite->audioUnified.speed) ? HS_ISO_OUT_ENDP_PACKET_SIZE :
                                                                                          FS_ISO_OUT_ENDP_PACKET_SIZE);

    return error;
}

/*!
 * @brief Audio Generator device initialization function.
 *
 * This function initializes the device with the composite device class information.
 *
 * @param deviceComposite The pointer to the composite device structure.
 *
 * @return A USB error code or kStatus_USB_Success.
 */
usb_status_t USB_DeviceAudioUnifiedInit(usb_device_composite_struct_t *deviceComposite)
{
    g_deviceComposite = deviceComposite;
    g_deviceComposite->audioUnified.copyProtect = 0x01U;
    g_deviceComposite->audioUnified.curMute = 0x00U;
    g_deviceComposite->audioUnified.curVolume[0] = 0x00U;
    g_deviceComposite->audioUnified.curVolume[1] = 0x80U;
    g_deviceComposite->audioUnified.minVolume[0] = 0x00U;
    g_deviceComposite->audioUnified.minVolume[1] = 0x80U;
    g_deviceComposite->audioUnified.maxVolume[0] = 0xFFU;
    g_deviceComposite->audioUnified.maxVolume[1] = 0X7FU;
    g_deviceComposite->audioUnified.resVolume[0] = 0x01U;
    g_deviceComposite->audioUnified.resVolume[1] = 0x00U;
    g_deviceComposite->audioUnified.curBass = 0x00U;
    g_deviceComposite->audioUnified.curBass = 0x00U;
    g_deviceComposite->audioUnified.minBass = 0x80U;
    g_deviceComposite->audioUnified.maxBass = 0x7FU;
    g_deviceComposite->audioUnified.resBass = 0x01U;
    g_deviceComposite->audioUnified.curMid = 0x00U;
    g_deviceComposite->audioUnified.minMid = 0x80U;
    g_deviceComposite->audioUnified.maxMid = 0x7FU;
    g_deviceComposite->audioUnified.resMid = 0x01U;
    g_deviceComposite->audioUnified.curTreble = 0x01U;
    g_deviceComposite->audioUnified.minTreble = 0x80U;
    g_deviceComposite->audioUnified.maxTreble = 0x7FU;
    g_deviceComposite->audioUnified.resTreble = 0x01U;
    g_deviceComposite->audioUnified.curAutomaticGain = 0x01U;
    g_deviceComposite->audioUnified.curDelay[0] = 0x00U;
    g_deviceComposite->audioUnified.curDelay[1] = 0x40U;
    g_deviceComposite->audioUnified.minDelay[0] = 0x00U;
    g_deviceComposite->audioUnified.minDelay[1] = 0x00U;
    g_deviceComposite->audioUnified.maxDelay[0] = 0xFFU;
    g_deviceComposite->audioUnified.maxDelay[1] = 0xFFU;
    g_deviceComposite->audioUnified.resDelay[0] = 0x00U;
    g_deviceComposite->audioUnified.resDelay[1] = 0x01U;
    g_deviceComposite->audioUnified.curLoudness = 0x01U;
    g_deviceComposite->audioUnified.curSamplingFrequency[0] = 0x00U;
    g_deviceComposite->audioUnified.curSamplingFrequency[1] = 0x00U;
    g_deviceComposite->audioUnified.curSamplingFrequency[2] = 0x01U;
    g_deviceComposite->audioUnified.minSamplingFrequency[0] = 0x00U;
    g_deviceComposite->audioUnified.minSamplingFrequency[1] = 0x00U;
    g_deviceComposite->audioUnified.minSamplingFrequency[2] = 0x01U;
    g_deviceComposite->audioUnified.maxSamplingFrequency[0] = 0x00U;
    g_deviceComposite->audioUnified.maxSamplingFrequency[1] = 0x00U;
    g_deviceComposite->audioUnified.maxSamplingFrequency[2] = 0x01U;
    g_deviceComposite->audioUnified.resSamplingFrequency[0] = 0x00U;
    g_deviceComposite->audioUnified.resSamplingFrequency[1] = 0x00U;
    g_deviceComposite->audioUnified.resSamplingFrequency[2] = 0x01U;
    g_deviceComposite->audioUnified.speed = USB_SPEED_FULL;
    g_deviceComposite->audioUnified.tdReadNumberPlay = 0;
    g_deviceComposite->audioUnified.tdWriteNumberPlay = 0;
    g_deviceComposite->audioUnified.tdReadNumberRec = 0;
    g_deviceComposite->audioUnified.tdWriteNumberRec = 0;
    g_deviceComposite->audioUnified.audioSendCount = 0;
    g_deviceComposite->audioUnified.lastAudioSendCount = 0;
    g_deviceComposite->audioUnified.usbRecvCount = 0;
    g_deviceComposite->audioUnified.audioSendTimes = 0;
    g_deviceComposite->audioUnified.usbRecvTimes = 0;
    g_deviceComposite->audioUnified.audioRecvCount = 0;
    g_deviceComposite->audioUnified.usbSendTimes = 0;
    g_deviceComposite->audioUnified.startPlay = 0;
    g_deviceComposite->audioUnified.startPlayHalfFull = 0;
    g_deviceComposite->audioUnified.startRec = 0;
    g_deviceComposite->audioUnified.startRecHalfFull = 0;
    g_deviceComposite->audioUnified.speakerIntervalCount = 0;
    g_deviceComposite->audioUnified.speakerReservedSpace = 0;
    g_deviceComposite->audioUnified.recorderReservedSpace = 0;
    g_deviceComposite->audioUnified.timesFeedbackCalculate = 0;
    g_deviceComposite->audioUnified.speakerDetachOrNoInput = 0;
    for (uint8_t i = 0; i < USB_AUDIO_COMPOSITE_INTERFACE_COUNT; i++)
    {
        g_deviceComposite->audioUnified.currentInterfaceAlternateSetting[i] = 0;
    }
    return kStatus_USB_Success;
}

void USB_AudioCodecTask(void)
{
    if (g_deviceComposite->audioUnified.codecTask & MUTE_CODEC_TASK)
    {
        usb_echo("Set Cur Mute : %x\r\n", g_deviceComposite->audioUnified.curMute);
        BOARD_SetCodecMuteUnmute(true);
        g_deviceComposite->audioUnified.codecTask &= ~MUTE_CODEC_TASK;
        g_CodecMuteUnmute = true;
    }
    if (g_deviceComposite->audioUnified.codecTask & UNMUTE_CODEC_TASK)
    {
        usb_echo("Set Cur Mute : %x\r\n", g_deviceComposite->audioUnified.curMute);
        BOARD_SetCodecMuteUnmute(false);
        g_deviceComposite->audioUnified.codecTask &= ~UNMUTE_CODEC_TASK;
        g_CodecMuteUnmute = true;
    }
    if (g_deviceComposite->audioUnified.codecTask & VOLUME_CHANGE_TASK)
    {
        usb_echo("Set Cur Volume : %x\r\n", (uint16_t)(g_deviceComposite->audioUnified.curVolume[1] << 8U) |
                                                g_deviceComposite->audioUnified.curVolume[0]);
        g_deviceComposite->audioUnified.codecTask &= ~VOLUME_CHANGE_TASK;
    }
}

void USB_AudioSpeakerResetTask(void)
{
    if (g_deviceComposite->audioUnified.speakerDetachOrNoInput)
    {
        USB_DeviceAudioSpeakerStatusReset();
    }
}
