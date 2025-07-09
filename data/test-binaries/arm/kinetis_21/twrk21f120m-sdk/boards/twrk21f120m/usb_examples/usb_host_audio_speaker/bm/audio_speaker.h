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

#ifndef __AUDIO_SPEAKER_H__
#define __AUDIO_SPEAKER_H__

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define MOUSE_MAX_COUNT 2
#define HOST_VOLUME_STEP 1
#define HOST_MIN_VOLUME 0
#define HOST_MAX_VOLUME 10

#define EP_TYPE_MASK (0x03)

/*! @brief host audio speaker app device attach/detach status */
typedef enum _host_audio_app_state
{
    kStatus_DEV_Idle = 0, /*!< there is no device attach/detach */
    kStatus_DEV_Attached, /*!< device is attached */
    kStatus_DEV_Detached, /*!< device is detached */
} host_audio_app_state_t;

/*! @brief host app run status */
typedef enum __host_audio_app_runState
{
    kRunIdle = 0,                    /*!< idle */
    kRunSetControlInterface,         /*!< execute set control interface code */
    kRunSetControlInterfaceDone,     /*!<  set control interface done */
    kRunWaitSetControlInterface,     /*!< wait control interface done */
    kRunWaitSetStreamInterface,      /*!< wait steam interface done */
    kRunSetInterfaceDone,            /*!< set interface done */
    kRunWaitGetStreamDescriptor,     /*!< wait get stream descriotor */
    kRunGetStreamDescriptorDone,     /*!< get stream descriotor done */
    kRunWaitAudioGetMinVolume,       /*!< wait get minimum volume command done */
    kRunAudioGetMaxVolume,           /*!< execute get maximum volume command done */
    kRunWaitAudioGetMaxVolume,       /*!< wait get maximum volume command done */
    kRunAudioGetResVolume,           /*!< execute get res volume command done */
    kRunWaitAudioGetResVolume,       /*!< wait get res volume command done */
    kRunAudioConfigChannel,          /*!< execute config audio channel */
    kRunWaitAudioConfigChannel,      /*!< wait config audio channel */
    kRunAudioConfigChannel1Vol,      /*!< execute config audio channel 1*/
    kRunWaitAudioConfigChannel1Vol,  /*!< wait config audio channel 1*/
    kRunAudioConfigChannel2Vol,      /*!< execute config audio channel 2*/
    kRunWaitAudioConfigChannel2Vol,  /*!< wait config audio channel 2*/
    kRunWaitAudioSetCurSamplingFreq, /*!< wait config audio set sampling freq*/
    kRunAudioSetCurSamplingFreq,     /*!< execute audio set current sampling freq*/
    kRunAudioConfigMute,             /*!< execute audio config mute*/
    kRunWaitAudioConfigMute,         /*!< wait audio config mute*/
    kRunAudioDone,                   /*!< audio done */
} host_audio_app_runState_t;

/*! @brief USB host audio instance structure */
typedef struct _audio_speraker_instance
{
    usb_device_handle deviceHandle;              /*!< the audio speaker device handle */
    usb_host_class_handle classHandle;           /*!< the audio speaker class handle */
    usb_host_interface_handle controlIntfHandle; /*!< the audio speaker control interface handle */
    usb_host_interface_handle streamIntfHandle;  /*!< the audio speaker stream interface handle */
    uint8_t devState;                            /*!< device attach/detach status */
    uint8_t prevState;                           /*!< device attach/detach previous status */
    uint8_t runState;                            /*!< audio speaker application run status */
    uint8_t runWaitState;                        /*!< audio speaker application run status */
    uint16_t maxPacketSize;                      /*!< iso max packet size */
    uint8_t dataReceived;                        /*!< data recived  */
    uint8_t deviceIsUsed;                        /*!< device is used or not */
    uint8_t bufCount;                            /*!< audio buffer count*/
} audio_speraker_instance_t;

#endif /* __AUDIO_SPEAKER_H__ */
