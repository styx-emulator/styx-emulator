/********************************************************************************

Copyright(c) 2008 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:

    This is the header file for USB Audio
    Class Driver (Device Mode).

*********************************************************************************/

#ifndef _ADI_USB_AUDIO_CLASS_H_
#define _ADI_USB_AUDIO_CLASS_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers\usb\class\peripheral\audio\adi_usb_audio.h>

/******* ENABLE THE DESCRETE FREQUENCY CODE *******/
#define DISCRETE_FREQ                           0
/**************************************************/

/* Add the alternate interface to the defined interface */
#define ALT_INTERFACE           0

#define PLAYBACK_INFO           0
#define RECORD_INFO             0
#define STOP_INFO               0

/*
 *  Macros
 */
#define LOBYTE(a) ((u8)a)
#define HIBYTE(a) ((u8)(a >> 8))

#define LOWORD(a) ((u16)a)
#define HIWORD(a) ((u16)(a >> 16))

/* USB Audio Specification in BCD */
#define USB_AUDIO_SPEC_1_0      0x0100
#define USB_AUDIO_SPEC_2_0      0x0200

/* Number of Audio control interface in a collection, only 1*/
#define AUDIO_NUM_CONTROL_INTERFACES        1

/* Number of Audio streaming interfaces in this collection*/
#define AUDIO_NUM_STREAMING_INTERFACES      2

/* Number of MIDI interfaces in this collection */
#define AUDIO_NUM_MIDI_INTERFACES           0

/* Total number of interfaces in the Audio Collection */
#define AUDIO_NUM_TOTAL_INTERFACES ((AUDIO_NUM_CONTROL_INTERFACES)   + \
                                    (AUDIO_NUM_STREAMING_INTERFACES) + \
                                    (AUDIO_NUM_MIDI_INTERFACES) )

/* Default class specific audio control descriptor length is 8 bytes */
#define AUDIO_CLASS_SPECIFIC_AC_DESC_LEN (  8 +                              \
                                            AUDIO_NUM_STREAMING_INTERFACES + \
                                            AUDIO_NUM_MIDI_INTERFACES)

#define NUM_CHANNELS_RECORDING                  2

#define INTERFACE_FOR_AUDIOCONTROL              0
#define ALTSETTING_FOR_AUDIOCONTROL             0

#define USB_AUDIO_CONTROL_INTERFACE_COLLECTION  2

/* Control requestion direction */
#define USB_CONTROL_REQUEST_IN                  0
#define USB_CONTROL_REQUEST_OUT                 1

/* Defines for Playback */
#define AUDIO_TERMID_USBOUT                     0x01
#define AUDIO_UNITID_PLAYBACK_VOLUME_OUT        0x02
#define AUDIO_TERMID_LINEOUT                    0x03

/* Defines for Record */
#define AUDIO_TERMID_MICIN                      0x04
#define AUDIO_TERMID_LINEIN                     0x05
#define AUDIO_TERMID_USBIN                      0x06
#define AUDIO_UNITID_MIC_VOLUME_RECORD          0x07
#define AUDIO_UNITID_SELECTOR_RECORD            0x08
#define AUDIO_UNITID_SELECTOR_RECORD_1          0x09
#define AUDIO_UNITID_MIXER                      0x0A
#define AUDIO_UNITID_MIC_VOLUME_RECORD_1        0x0B
#define AUDIO_UNITID_LINEIN_VOLUME_RECORD       0x0C
#define AUDIO_UNITID_LINEIN_VOLUME_RECORD_1     0x0D

#define NUM_AUDIO_INTERFACES                    4

#define MAX_CLASS_SPECIFIC_OBJS                 20

/* Number of extra bytes tacked on to the standard EP descriptor */
/* USB Audio Class specificatio 1.0 */
#define AUDIO_EP_EXTRA_BYTES                    2

#define MAX_ENDPOINTS_OBJS                      3

#define MAX_ENDPOINT_SPECIFIC_OBJS              7

typedef struct ObjectInfo
{
  int ID;
  void *pObj;
}OBJECT_INFO;

typedef struct {
    s16 Min;
    s16 Max;
    s16 Res;
    s16 Cur;
} ADI_USB_AUDIO_LEVELS_DEF;


typedef struct AudioControlClassSpecificInfo
{
  CS_SPECIFIC_AC_DESCRIPTOR     csACD;
  INPUT_TERMINAL_DESCRIPTOR     out_input_TD;
  OUTPUT_TERMINAL_DESCRIPTOR    out_output_TD;
  INPUT_TERMINAL_DESCRIPTOR     in_input_TD[7];
  OUTPUT_TERMINAL_DESCRIPTOR    in_output_TD;
  FEATURE_UNIT_DESCRIPTOR       featureUD;
  FEATURE_UNIT_DESCRIPTOR       in_featureUD[7];
  SELECTOR_UNIT_DESCRIPTOR      in_selectorUD;
  CS_SPECIFIC_AS_INTERFACE_DESCRIPTOR formatTypeD;
  TYPE_1_FORMAT_TYPE_DESCRIPTOR type1FormatD;
  CS_SPECIFIC_AS_INTERFACE_DESCRIPTOR in_formatTypeD;
  TYPE_1_FORMAT_TYPE_DESCRIPTOR in_type1FormatD;
  CS_SPECIFIC_AS_ISOCHRONOUS_EP_DESCRIPTOR audioEpD;
  AC_EP_DESCRIPTOR_EXT          audioEpDExt[5];
  CS_SPECIFIC_AS_ISOCHRONOUS_EP_DESCRIPTOR in_audioEpD;
  AC_EP_DESCRIPTOR_EXT          in_audioEpDExt;
  MIXER_UNIT_DESCRIPTOR         in_mixerUD;
  PROCESS_UNIT_DESCRIPTOR       processUnitD;
}AUDIO_CONTROL_SPECIFIC_INFO,*PAUDIO_CONTROL_SPECIFIC_INFO;

typedef struct AudioStreamingDeviceData {
ADI_DEV_DEVICE_HANDLE   DeviceHandle;
ADI_DMA_MANAGER_HANDLE  DMAHandle;
ADI_DCB_CALLBACK_FN     DMCallback;
ADI_DCB_HANDLE          DCBHandle;
ADI_DEV_DIRECTION       Direction;
bool                    Open;
bool                    Started;
void                    *CriticalData;
ADI_DEV_DEVICE_HANDLE   PeripheralDevHandle;
ADI_DEV_DEVICE_HANDLE   CodecDevHandle;
int                     DeviceID;
bool                    deviceReady;
OBJECT_INFO             ConfigObject;
OBJECT_INFO             InterfaceObjects[10];
OBJECT_INFO             AltInterfaceObjects[5];
INTERFACE_DESCRIPTOR    AudioInterfaceObjects[10];
OBJECT_INFO             EndPointObjects[MAX_ENDPOINTS_OBJS];
AUDIO_CONTROL_SPECIFIC_INFO  acSpecifcInfo;
INTERFACE_SPECIFIC_OBJECT   IFaceClassSpecificObj[MAX_CLASS_SPECIFIC_OBJS];
CLASS_SPECIFIC_OBJECT       CfgClassSpecificObj[MAX_CLASS_SPECIFIC_OBJS];
ENDPOINT_SPECIFIC_OBJECT    EndpointSpecificObj[MAX_ENDPOINT_SPECIFIC_OBJS];
OBJECT_INFO                 ASEndpointObj[MAX_ENDPOINT_SPECIFIC_OBJS];
u8                      audio_IN_EP;
u8                      audio_OUT_EP;
u8                      audio_FB_EP;
u16                     playbackChannels;
USB_SETUP_PACKET        AudioSetupPkt;
u8                      playbackStarted;
u8                      pbkNotifyApp;
u8                      recordStarted;
USB_EP_INFO             *pOUTEPInfo;
USB_EP_INFO             *pINEPInfo;
bool                    deviceConfigured;
u32                     playbackMaxPacketSize;
u32                     recordMaxPacketSize;
ADI_DEV_BUFFER          *pFreeRxList;
ADI_DEV_BUFFER          *pFreeTxList;
u32                     currentRxPointer;
ADI_DEV_1D_BUFFER       *pTopRxBuffer;
ADI_DEV_1D_BUFFER       *pCurrentRxBuffer;
ADI_DEV_1D_BUFFER       *pRxBufferQueue;
ADI_DEV_1D_BUFFER       *pRxBufferQueueTop;
ADI_DEV_MODE            DataFlowMethod;
ADI_DEV_1D_BUFFER       AudioRxBuffer;
bool                    pbkBufferHalfFull;
bool                    codecStarted;
bool                    bufferReady;
u32                     controlDataDirection;
u8                      recordSelect;
bool                    lineInMicMixer;
bool                    micInAdcMixer;
bool                    enableMicRecordCtl;
bool                    enableLineInRecordCtl;
u32                     processUnitEnable;
u32                     playbackSampleFreq;
bool                    playback16BitResolution;
u8                      pbkSampleRate;
bool                    micDefaultRecord;
bool                 enableFeedback   ;
u32                     feedbackInterval;
ADI_USB_AUDIO_LEVELS_DEF PlaybackLevels;
ADI_USB_AUDIO_LEVELS_DEF RecordLevels;

}AUDIO_STREAMING_DEV_DATA;

enum{ NONE, SAMPLE_RATE_48K, SAMPLE_RATE_96K, SAMPLE_RATE_96K_48K };

#define MIC_IN_SELECT                       1
#define LINE_IN_SELECT                      2

#define AUDIO_CONTROL                       0
#define AUDIO_STREAM_OUT                    1
#define AUDIO_STREAM_IN                     2
#define AUDIO_CONTROL_HEADER                3

#define AUDIO_ALT_STREAM_OUT                0
#define AUDIO_ALT_STREAM_IN                 1

#define AUDIO_STREAM_EP_PLAYBACK            0
#define AUDIO_STREAM_EP_FEEDBACK            1
#define AUDIO_STREAM_EP_RECORD              2

/* Audio Control */
#define INTERFACE_NUM_FOR_AUDIO_CONTROL     0
#define ALT_INTERFACE_NUM_FOR_AUDIO_CONTROL 0

/* Audio Streaming Interfaces */
#define INTERFACE_NUM_FOR_AUDIO_STREAMING          1
#define INTERFACE_NUM_FOR_AUDIO_STREAMING_RECORD   2

/* Audio Streaming Alternate Interfaces */
#define ALT_INTERFACE_NUM_FOR_AUDIO_STREAMING_IDLE      0
#define ALT_INTERFACE_NUM_FOR_AUDIO_STREAMING           1

#define USB_AUDIO_DESCRIPTOR_INTERFACE      0x24
#define USB_AUDIO_DESCRIPTOR_ENDPOINT       0x25

#define USB_AUDIO_TERMINALTYPE_SPEAKER      0x0301
#define USB_AUDIO_TERMINALTYPE_LINE         0x0603

#define  ENDPOINT_INTERVAL                  4

#define SAMPLINGRATE                        48000
#define CONTAINER_SIZE                      16
#define PLAYBACK_DELAY                      1
#define BIT_DEPTH                           16

#define USB_AUDIO_EP_ATTRIB_ISOCH           0x01

#define USB_AUDIO_EP_ATTRIB_ASYNC           0x04
#define USB_AUDIO_EP_ATTRIB_ADAPTIVE        0x08
#define USB_AUDIO_EP_ATTRIB_SYNC            0xC0

#define USB_AUDIO_FORMAT_TAG_PCM            0x0001
#define USB_AUDIO_SAMPLING_FREQ_DISCREET    0x01

#define FEEDBACK_PBK_EP                     1
#define MAX_PACKET_SIZE_FEEDBACK            3

#define FEEDBACK_FREQUENCY_NORMAL           0x0c0000
#define FEEDBACK_FREQUENCY_PLEASE_HURRY     0x0D0000
#define FEEDBACK_FREQUENCY_PLEASE_SLOWDOWN  0x0b8000

/* Audio Feature Unit sizes */
#define TWO_CHANNEL_PBK_FU_SIZE             10
#define SIX_CHANNEL_PBK_FU_SIZE             14

#define MAX_PACKET_SIZE_RECORDING                        (((SAMPLINGRATE) * NUM_CHANNELS_RECORDING * (CONTAINER_SIZE / 8)) / 1000)

#define AUDIO_CONTROL_INTERFACE_DESCRIPTOR_LEN              10 //This could increase...
#define AUDIO_CONTROL_OUT_INPUT_TERMINAL_DESCRIPTOR_LEN     12
#define AUDIO_CONTROL_OUT_OUTPUT_TERMINAL_DESCRIPTOR_LEN    9
#define AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN           0
#define AUDIO_CONTROL_IN_INPUT_TERMINAL_DESCRIPTOR_LEN      12
#define AUDIO_CONTROL_IN_OUTPUT_TERMINAL_DESCRIPTOR_LEN     9
#define AUDIO_STREAMING_ENDPOINT_DESCRIPTOR_LEN             9
#define AUDIO_STREAMING_ENDPOINT_GENERAL_DESCRIPTOR_LEN     7

#define AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN_RECORD_1  9
#define AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN_RECORD_3  9
#define AUDIO_CONTROL_MIXER_UNIT_DESCRIPTOR_LEN_RECORD      14

#define LINE_IN_MIC_MIXER_LEN \
        (AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN_RECORD_1 +\
         AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN_RECORD_3 +\
         AUDIO_CONTROL_MIXER_UNIT_DESCRIPTOR_LEN_RECORD)

#define AUDIO_SELECTOR_UNIT_DESCRIPTOR_LEN                  8

#define AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN_RECORD    10
#define AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN_RECORD_2  10
#define AUDIO_CONTROL_LINE_IN_INPUT_TERMINAL_DESCRIPTOR_LEN 12

#define AUDIO_PBK_STREAMING_TYPE_I_FMT_DESCRIPTOR_LEN       14
#define AUDIO_REC_STREAMING_TYPE_I_FMT_DESCRIPTOR_LEN       14


#define TOTAL_AUDIO_CONTROL_DESCRIPTOR_LEN \
    (AUDIO_CONTROL_INTERFACE_DESCRIPTOR_LEN +\
    AUDIO_CONTROL_OUT_INPUT_TERMINAL_DESCRIPTOR_LEN +\
    AUDIO_CONTROL_OUT_OUTPUT_TERMINAL_DESCRIPTOR_LEN +\
    AUDIO_CONTROL_IN_INPUT_TERMINAL_DESCRIPTOR_LEN +\
    AUDIO_CONTROL_IN_OUTPUT_TERMINAL_DESCRIPTOR_LEN +\
    AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN +\
    AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN_RECORD +\
    AUDIO_CONTROL_FEATURE_UNIT_DESCRIPTOR_LEN_RECORD_2 +\
    AUDIO_CONTROL_LINE_IN_INPUT_TERMINAL_DESCRIPTOR_LEN +\
    AUDIO_SELECTOR_UNIT_DESCRIPTOR_LEN)

#define TOTAL_CONFIG_DESCRIPTOR_LEN \
        (CONFIGURATION_DESCRIPTOR_LEN + \
        INTERFACE_DESCRIPTOR_LEN + \
        TOTAL_AUDIO_CONTROL_DESCRIPTOR_LEN +\
        INTERFACE_DESCRIPTOR_LEN + \
        INTERFACE_DESCRIPTOR_LEN + \
        AUDIO_STREAMING_GENERAL_DESCRIPTOR_LEN +\
        AUDIO_PBK_STREAMING_TYPE_I_FMT_DESCRIPTOR_LEN + \
        AUDIO_STREAMING_ENDPOINT_GENERAL_DESCRIPTOR_LEN +\
        AUDIO_STREAMING_ENDPOINT_DESCRIPTOR_LEN + \
        INTERFACE_DESCRIPTOR_LEN +\
        INTERFACE_DESCRIPTOR_LEN + \
        AUDIO_STREAMING_GENERAL_DESCRIPTOR_LEN +\
        AUDIO_STREAMING_TYPE_I_FMT_DESCRIPTOR_LEN + \
        AUDIO_STREAMING_ENDPOINT_DESCRIPTOR_LEN +\
        AUDIO_STREAMING_ENDPOINT_GENERAL_DESCRIPTOR_LEN)

/**************************************************************************************/

#define INTERFACE_FOR_AUDIOCONTROL          0
#define ALTSETTING_FOR_AUDIOCONTROL         0

#define FEATURE_UNIT_MUTE_CONTROL           0x1
#define FEATURE_UNIT_VOLUME_CONTROL         0x2
#define FEATURE_UNIT_BASS_CONTROL           0x4
#define FEATURE_UNIT_TREBLE_CONTROL         0x8
#define FEATURE_UNIT_EQ_CONTROL             0x10
#define FEATURE_UNIT_AGC_CONTROL            0x20
#define FEATURE_UNIT_DELAY_CONTROL          0x40
#define FEATURE_UNIT_BASS_BOOST_CONTROL     0x80

/* Default playback volume definitions */
#define PBKVOLUME_MIN 0
#define PBKVOLUME_MAX 0x7fff
#define PBKVOLUME_RES 0x0180    /* 1.5 dB  */

/* Default record volume definitions */
#define RECVOLUME_MIN 0
#define RECVOLUME_MAX 0x7fff
#define RECVOLUME_RES 0x0180    /* 1.5 dB  */

#define VOLUME_MID    0x3fff

//Audio Class Requests (bRequest)
#define SET_CUR 0x01
#define GET_CUR 0x81
#define SET_MIN 0x02
#define GET_MIN 0x82
#define SET_MAX 0x03
#define GET_MAX 0x83
#define SET_RES 0x04
#define GET_RES 0x84
#define SET_MEM 0x05
#define GET_MEM 0x85
#define GET_STAT 0xFF

/* IO Control commands handled by the Audio Class driver */
#define ADI_USB_AUDIO_CMD_IS_DEVICE_CONFIGURED          (ADI_USB_AUDIO_ENUMERATION_START + 0x00000000)
#define ADI_USB_AUDIO_CMD_SET_RX_BUFFER                 (ADI_USB_AUDIO_ENUMERATION_START + 0x00000001)
#define ADI_USB_AUDIO_CMD_SET_TX_BUFFER                 (ADI_USB_AUDIO_ENUMERATION_START + 0x00000002)
#define ADI_USB_AUDIO_CMD_SET_VID                       (ADI_USB_AUDIO_ENUMERATION_START + 0x00000003)
#define ADI_USB_AUDIO_CMD_SET_PID                       (ADI_USB_AUDIO_ENUMERATION_START + 0x00000004)
#define ADI_USB_AUDIO_CMD_SET_PRODUCT_STRING            (ADI_USB_AUDIO_ENUMERATION_START + 0x00000005)
#define ADI_USB_AUDIO_CMD_SET_MANUFACTURER_STRING       (ADI_USB_AUDIO_ENUMERATION_START + 0x00000006)
#define ADI_USB_AUDIO_CMD_SET_PLAYBACK_CHANNELS         (ADI_USB_AUDIO_ENUMERATION_START + 0x00000007)
#define ADI_USB_AUDIO_CMD_DISABLE_MIXER                 (ADI_USB_AUDIO_ENUMERATION_START + 0x00000008)
#define ADI_USB_AUDIO_CMD_MIC_IN_ADC_MIXER              (ADI_USB_AUDIO_ENUMERATION_START + 0x00000009)
#define ADI_USB_AUDIO_CMD_ENABLE_MIC_RECORD_CTL         (ADI_USB_AUDIO_ENUMERATION_START + 0x0000000A)
#define ADI_USB_AUDIO_CMD_ENABLE_LINEIN_RECORD_CTL      (ADI_USB_AUDIO_ENUMERATION_START + 0x0000000B)
#define ADI_USB_AUDIO_CMD_RETURN_CTL_DATA_1             (ADI_USB_AUDIO_ENUMERATION_START + 0x0000000C)
#define ADI_USB_AUDIO_CMD_RETURN_CTL_DATA_2             (ADI_USB_AUDIO_ENUMERATION_START + 0x0000000D)
#define ADI_USB_AUDIO_CMD_GET_PBK_SAMPLE_FREQ           (ADI_USB_AUDIO_ENUMERATION_START + 0x0000000E)
#define ADI_USB_AUDIO_CMD_SET_32BIT_PBK_RESOLUTION      (ADI_USB_AUDIO_ENUMERATION_START + 0x0000000F)
#define ADI_USB_AUDIO_CMD_SET_16BIT_PBK_RESOLUTION      (ADI_USB_AUDIO_ENUMERATION_START + 0x00000010)
#define ADI_USB_AUDIO_CMD_SET_PBK_SAMPLE_RATE_48K_ONLY  (ADI_USB_AUDIO_ENUMERATION_START + 0x00000011)
#define ADI_USB_AUDIO_CMD_SET_PBK_SAMPLE_RATE_96K_ONLY  (ADI_USB_AUDIO_ENUMERATION_START + 0x00000012)
#define ADI_USB_AUDIO_CMD_SET_PBK_SAMPLE_RATE_96K_48K   (ADI_USB_AUDIO_ENUMERATION_START + 0x00000013)
#define ADI_USB_AUDIO_CMD_SET_MIC_RECORD_SELECT         (ADI_USB_AUDIO_ENUMERATION_START + 0x00000014)
#define ADI_USB_AUDIO_CMD_SET_LINEIN_RECORD_SELECT      (ADI_USB_AUDIO_ENUMERATION_START + 0x00000015)
#define ADI_USB_AUDIO_CMD_ENABLE_FEEDBACK               (ADI_USB_AUDIO_ENUMERATION_START + 0x00000016)
#define ADI_USB_AUDIO_CMD_DISABLE_FEEDBACK              (ADI_USB_AUDIO_ENUMERATION_START + 0x00000017)

/* USB Audio Class Events */
#define ADI_USB_AUDIO_EVENT_PLAYBACK_STARTED            (ADI_USB_AUDIO_ENUMERATION_START + 0x00000020)
#define ADI_USB_AUDIO_EVENT_PLAYBACK_STOPPED            (ADI_USB_AUDIO_ENUMERATION_START + 0x00000021)
#define ADI_USB_AUDIO_EVENT_RECORD_STARTED              (ADI_USB_AUDIO_ENUMERATION_START + 0x00000022)
#define ADI_USB_AUDIO_EVENT_RECORD_STOPPED              (ADI_USB_AUDIO_ENUMERATION_START + 0x00000023)

#define ADI_USB_AUDIO_EVENT_SET_MASTER_VOLUME           (ADI_USB_AUDIO_ENUMERATION_START + 0x00000024)
#define ADI_USB_AUDIO_EVENT_SET_MASTER_MUTE             (ADI_USB_AUDIO_ENUMERATION_START + 0x00000025)
#define ADI_USB_AUDIO_EVENT_SET_LINEIN_VOLUME           (ADI_USB_AUDIO_ENUMERATION_START + 0x00000026)
#define ADI_USB_AUDIO_EVENT_SET_LINEIN_MUTE             (ADI_USB_AUDIO_ENUMERATION_START + 0x00000027)
#define ADI_USB_AUDIO_EVENT_SET_MIC_VOLUME              (ADI_USB_AUDIO_ENUMERATION_START + 0x00000028)
#define ADI_USB_AUDIO_EVENT_SET_MIC_MUTE                (ADI_USB_AUDIO_ENUMERATION_START + 0x00000029)
#define ADI_USB_AUDIO_EVENT_SET_LINEIN_SELECT           (ADI_USB_AUDIO_ENUMERATION_START + 0x0000002A)
#define ADI_USB_AUDIO_EVENT_SET_MIC_SELECT              (ADI_USB_AUDIO_ENUMERATION_START + 0x0000002B)
#define ADI_USB_AUDIO_EVENT_SET_RECORD_MASTER_GAIN      (ADI_USB_AUDIO_ENUMERATION_START + 0x0000002C)

#define ADI_USB_AUDIO_EVENT_GET_MASTER_VOLUME           (ADI_USB_AUDIO_ENUMERATION_START + 0x00000040)
#define ADI_USB_AUDIO_EVENT_GET_MASTER_MUTE             (ADI_USB_AUDIO_ENUMERATION_START + 0x00000041)
#define ADI_USB_AUDIO_EVENT_GET_LINEIN_VOLUME           (ADI_USB_AUDIO_ENUMERATION_START + 0x00000042)
#define ADI_USB_AUDIO_EVENT_GET_LINEIN_MUTE             (ADI_USB_AUDIO_ENUMERATION_START + 0x00000043)
#define ADI_USB_AUDIO_EVENT_GET_MIC_VOLUME              (ADI_USB_AUDIO_ENUMERATION_START + 0x00000044)
#define ADI_USB_AUDIO_EVENT_GET_MIC_MUTE                (ADI_USB_AUDIO_ENUMERATION_START + 0x00000045)
#define ADI_USB_AUDIO_EVENT_GET_LINEIN_SELECT           (ADI_USB_AUDIO_ENUMERATION_START + 0x00000046)
#define ADI_USB_AUDIO_EVENT_GET_MIC_SELECT              (ADI_USB_AUDIO_ENUMERATION_START + 0x00000047)
#define ADI_USB_AUDIO_EVENT_GET_RECORD_MASTER_GAIN      (ADI_USB_AUDIO_ENUMERATION_START + 0x00000048)

#define ADI_USB_AUDIO_CMD_SET_PLAYBACK_VOL_LEVELS       (ADI_USB_AUDIO_ENUMERATION_START + 0x00000049)
#define ADI_USB_AUDIO_CMD_SET_RECORD_VOL_LEVELS         (ADI_USB_AUDIO_ENUMERATION_START + 0x0000004A)
#define ADI_USB_AUDIO_CMD_SET_CUR_PLAYBACK_VOL_LEVEL    (ADI_USB_AUDIO_ENUMERATION_START + 0x0000004B)
#define ADI_USB_AUDIO_CMD_GET_CUR_PLAYBACK_VOL_LEVEL    (ADI_USB_AUDIO_ENUMERATION_START + 0x0000004C)
#define ADI_USB_AUDIO_CMD_SET_CUR_RECORD_VOL_LEVEL      (ADI_USB_AUDIO_ENUMERATION_START + 0x0000004D)
#define ADI_USB_AUDIO_CMD_GET_CUR_RECORD_VOL_LEVEL      (ADI_USB_AUDIO_ENUMERATION_START + 0x0000004E)



#if DISCRETE_FREQ
#define ADI_USB_AUDIO_EVENT_SET_CODEC_SAMPLE_RATE       (ADI_USB_AUDIO_ENUMERATION_START + 0x00000050)
#endif

#define EP_ZERO 0

/* Entry point to Audio Class driver (Devive Mode) */
extern ADI_DEV_PDD_ENTRY_POINT ADI_USB_Device_AudioClass_Entrypoint;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_AUDIO_CLASS_H_ */
