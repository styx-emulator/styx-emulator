/***********************************************************************
 * Copyright(c) 2008 Analog Devices, Inc. All Rights Reserved.
 *
 * This software is proprietary and confidential.  By using this software
 * you agree to the terms of the associated Analog Devices License Agreement.
 *
 ************************************************************************
 *
 * Description:
 * Common data structures pertaining to audio class drivers.
 *
 ***********************************************************************/
#ifndef _ADI_USB_AUDIO_H_
#define _ADI_USB_AUDIO_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers\usb\usb_core\adi_usb_common.h>
#include <drivers\usb\usb_core\adi_usb_terminaltypes.h>
#include <drivers\usb\usb_core\adi_usb_types.h>

/* Audio Interface SubClass Codes */
#define USB_AUDIO_SUBCLASS_UNDEFINED         0x00
#define USB_AUDIO_SUBCLASS_AUDIO_CONTROL     0x01
#define USB_AUDIO_SUBCLASS_AUDIO_STREAMING   0x02
#define USB_AUDIO_SUBCLASS_AUDIO_MIDI        0x03

/* Interface protocols */
#define USB_AUDIO_PROTOCOL_NONE              0x00

/* Audio Class specific Descriptor types */
#define USB_AUDIO_CS_UNDEFINED               0x20
#define USB_AUDIO_CS_DEVICE                  0x21
#define USB_AUDIO_CS_CONFIGURATION           0x22
#define USB_AUDIO_CS_STRING                  0x23
#define USB_AUDIO_CS_INTERFACE               0x24
#define USB_AUDIO_CS_ENDPOINT                0x25

/* Audio control interface - subtype definitions */
#define USB_AC_DESCRIPTOR_UNDEFINED                0x00
#define USB_AC_DESCRIPTOR_SUBTYPE_HEADER           0x01
#define USB_AC_DESCRIPTOR_SUBTYPE_INPUT_TERMINAL   0x02
#define USB_AC_DESCRIPTOR_SUBTYPE_OUTPUT_TERMINAL  0x03
#define USB_AC_DESCRIPTOR_SUBTYPE_MIXER_UNIT       0x04
#define USB_AC_DESCRIPTOR_SUBTYPE_SELECTOR_UNIT    0x05
#define USB_AC_DESCRIPTOR_SUBTYPE_FEATURE_UNIT     0x06
#define USB_AC_DESCRIPTOR_SUBTYPE_PROCESSING_UNIT  0x07
#define USB_AC_DESCRIPTOR_SUBTYPE_EXTENSION_UNIT   0x08

/* Process Unit - Process Types */
#define USB_AC_PROCESS_UNIT_PROCESS_UNDEFINED      0x00
#define USB_AC_PROCESS_UNIT_UPDOWNMIX_PROCESS      0x01
#define USB_AC_PROCESS_UNIT_DOLBY_PROLOGIC_PROCESS 0x02
#define USB_AC_PROCESS_UNIT_3D_STEREO_EXTENDER_PROCESS  0x03
#define USB_AC_PROCESS_UNIT_REVERBERATION_PROCESS  0x04
#define USB_AC_PROCESS_UNIT_CHORUS_PROCESS         0x05
#define USB_AC_PROCESS_UNIT_DYN_RANGE_COMP_PROCESS 0x06

/* Format Type Code */
#define USB_AUDIO_FORMAT_TYPE_I                    0x1;

/* Terminal Control selectors */
#define USB_AC_TERMINAL_CONTROL_UNDEFINED          0x00
#define USB_AC_TERMINAL_COPY_PROTECT_CONTROL       0x01

/* Feature unit control selectors */
#define USB_AC_FEATURE_UNIT_CONTROL_UNDEFINED      0x00
#define USB_AC_FEATURE_UNIT_MUTE_CONTROL           0x01
#define USB_AC_FEATURE_UNIT_VOLUME_CONTROL         0x02
#define USB_AC_FEATURE_UNIT_BASS_CONTROL           0x03
#define USB_AC_FEATURE_UNIT_MID_CONTROL            0x04
#define USB_AC_FEATURE_UNIT_TREBLE_CONTROL         0x05
#define USB_AC_FEATURE_UNIT_GRAPHIC_EQUALIZER_CONTROL      0x06
#define USB_AC_FEATURE_UNIT_AUTOMATIC_GAIN_CONTROL         0x07
#define USB_AC_FEATURE_UNIT_DELAY_CONTROL          0x08
#define USB_AC_FEATURE_UNIT_BASS_BOOST_CONTROL     0x09
#define USB_AC_FEATURE_UNIT_LOUDNESS_CONTROL       0x0A

/* Audio Up Down Mix Processing unit control selectors */
#define USB_AC_UD_UNIT_CONTROL_UNDEFINED           0x00
#define USB_AC_UD_ENABLE_CONTROL                   0x01
#define USB_AC_UD_MODE_SELECT_CONTROL              0x02

/* Audio Dolby prologic processing unit control selectors */
#define USB_AC_DP_CONTROL_UNDEFINED                0x00
#define USB_AC_DP_ENABLE_CONTROL                   0x01
#define USB_AC_DP_MODE_SELECT_CONTROL              0x02

/* Audio 3D Stereo Extender processing unit control selectors */
#define USB_AC_3D_CONTROL_UNDEFINED                0x00
#define USB_AC_3D_ENABLE_CONTROL                   0x01
#define USB_AC_3D_SPACIOUSNESS_CONTROL             0x02

/* Audio Reverberation Processing unit control selectors */
#define USB_AC_RV_CONTROL_UNDEFINED                0x00
#define USB_AC_RV_ENABLE_CONTROL                   0x01
#define USB_AC_RV_LEVEL_CONTROL                    0x02
#define USB_AC_RV_TIME_CONTROL                     0x03
#define USB_AC_RV_FEEDBACK_CONTROL                 0x04

/* Audio Chorus processing unit control selectors */
#define USB_AC_CH_CONTROL_UNDEFINED                0x00
#define USB_AC_CH_ENABLE_CONTROL                   0x01
#define USB_AC_CH_LEVEL_CONTROL                    0x02
#define USB_AC_CH_RATE_CONTROL                     0x03
#define USB_AC_CH_DEPTH_CONTROL                    0x04

/* Audio class specific Endpoint descriptor subtypes */
#define USB_AUDIO_DESCRIPTOR_UNDEFINED            0x00
#define USB_AUDIO_EP_GENERAL                      0x01

/* Audio streaming interface - subtype definitions */
#define USB_AS_DESCRIPTOR_UNDEFINED                0x00
#define USB_AS_DESCRIPTOR_SUBTYPE_GENERAL          0x01
#define USB_AS_DESCRIPTOR_SUBTYPE_FORMAT_TYPE      0x02
#define USB_AS_DESCRIPTOR_SUBTYPE_FORMAT_SPECIFIC  0x03

/* USB Audio descriptor lengths */
#define USB_AUDIO_INPUT_TERMINAL_DESCRIPTOR_LEN    12
#define USB_AUDIO_OUTPUT_TERMINAL_DESCRIPTOR_LEN   9
#define AUDIO_STREAMING_GENERAL_DESCRIPTOR_LEN     7
#define AUDIO_STREAMING_TYPE_I_FMT_DESCRIPTOR_LEN  11

/***********************************************************************
 *
 *                 Standard Requests
 *
 ***********************************************************************/

#define  USB_AUDIO_REQUEST_CODE_UNDEFINED      0x00
#define  USB_AUDIO_REQUEST_CODE_SET_CUR        0x01
#define  USB_AUDIO_REQUEST_CODE_SET_MIN        0x02
#define  USB_AUDIO_REQUEST_CODE_SET_MAX        0x03
#define  USB_AUDIO_REQUEST_CODE_SET_RES        0x04
#define  USB_AUDIO_REQUEST_CODE_SET_MEM        0x05

#define  USB_AUDIO_REQUEST_CODE_GET_CUR        0x81
#define  USB_AUDIO_REQUEST_CODE_GET_MIN        0x82
#define  USB_AUDIO_REQUEST_CODE_GET_MAX        0x83
#define  USB_AUDIO_REQUEST_CODE_GET_RES        0x84
#define  USB_AUDIO_REQUEST_CODE_GET_MEM        0x85
#define  USB_AUDIO_REQUEST_CODE_GET_STAT       0xFF

/********************************************************
 *
 * Standard Audio Control interface descriptor is same as
 * standard interface descriptor
 *
 **/
typedef struct InterfaceDescriptor  AUDIO_CONTROL_INTERFACE_DESCRIPTOR;

/********************************************************
 *
 * Class Specific Audio Control interface descriptor.
 * Size 8 + n bytes where n is the number of Interfaces.
 *
 **/
#define MAX_CS_AC_NUM_INTERFACES 2

typedef struct CSSpecificAudioControlDescriptor
{
#if 0
  u8  bLength;            /* Size of this descriptor in bytes 8 + n */
  u8  bDescriptorType;    /* CS_INTERFACE descriptor type */
  u8  bDescriptorSubtype; /* HEADER descriptor subtype */
  u16 wbcdADC;            /* Audioclass Specification release no# bcd */
  u16 wTotalLength;       /* Total Number of bytes for AC (CSAC+UNIT+TER) */
  u8  bInCollection;      /* No# of AS and MIDI in this Interface collectio*/
  u8  baInterfaceNr[MAX_CS_AC_NUM_INTERFACES]; /* Number of interfaces */
#else
  u8  bLength;            /* Size of this descriptor in bytes 8 + n */
  u8  bDescriptorType;    /* CS_INTERFACE descriptor type */
  u8  bDescriptorSubtype; /* HEADER descriptor subtype */
  u8  bcdADC_lo;            /* Audioclass Specification release no# bcd */
  u8  bcdADC_hi;            /* Audioclass Specification release no# bcd */
  u8  TotalLength_lo;       /* Total Number of bytes for AC (CSAC+UNIT+TER) */
  u8  TotalLength_hi;       /* Total Number of bytes for AC (CSAC+UNIT+TER) */
  u8  bInCollection;      /* No# of AS and MIDI in this Interface collectio*/
  u8  baInterfaceNr[MAX_CS_AC_NUM_INTERFACES];      /* Number of interfaces */
#endif
}CS_SPECIFIC_AC_DESCRIPTOR,*PCS_SPECIFIC_AC_DESCRIPTOR;

typedef struct CSSpecificFormatTypeDescriptor
{
  u8  bLength;            /* Size of this descriptor in bytes */
  u8  bDescriptorType;    /* CS_INTERFACE descriptor type */
  u8  bDescriptorSubtype; /* GENERAL descriptor subtype */
  u8  bTermLink;          /* What EP/Terminal connection */
  u8  bDelay;               /* Data path delay */
  u16 wFormatTag;       /* Audio Format to use*/
}FORMAT_TYPE_DESCRIPTOR,*PFORMAT_TYPE_DESCRIPTOR;

/********************************************************
 *
 * Audio Control Interrupt Endpoint descriptor
 *
 **/
typedef struct ACInterruptEPDescriptor
{
 u8   bLength;            /* Size of this descriptor */
 u8   bDescriptorType;    /* constant ENDPOINT descriptor type  */
 u8   bEndpointAddress;   /* The address of the endpoint */
 u8   bmAttributes;       /* Bitmap */
 u16  wMaxPacketSize;     /* Maximim packet size for this endpoint */
 u8   bInterval;          /* ~10ms */
 u8   bRefresh;           /* reset to 0 */
 u8   bSynchAddress;      /* reset to 0 */
}AC_INTERRUPT_EP_DESCRIPTOR,*PAC_INTERRUPT_EP_DESCRIPTOR;

typedef struct ACEPDescriptorExt
{
 u8   bRefresh;           /* reset to 0 */
 u8   bSynchAddress;      /* reset to 0 */
}AC_EP_DESCRIPTOR_EXT,*PAC_EP_DESCRIPTOR_EXT;

/***********************************************************************
 *
 *                Unit and Terminal Descriptors
 *
 ***********************************************************************/

/********************************************************
 *
 * Input Terminal Descriptor, 12 bytes.
 *
 **/
typedef struct InputTerminalDescriptor
{
 u8   bLength;            /* Size of this descriptor 0xC */
 u8   bDescriptorType;    /* constant CS_INTERFACE   */
 u8   bDescriptorSubtype; /* constant INPUT_TERMINAL */
 u8   bTerminalID;        /* constant uniquely identifying the Terminal */
 u16  wTerminalType;      /* constant characterizing the terminal */
 u8   bAssocTerminal;     /* ID of the associated output terminal */
 u8   bNrChannels;        /* Number of logical output channel */
 u16  wChannelConfig;     /* Bitmap - describes spatial location */
 u8   iChannelNames;      /* Index  - Index of a string descriptor */
 u8   iTerminal;          /* Index  - Index of a string descriptor */
}INPUT_TERMINAL_DESCRIPTOR,*PINPUT_TERMINAL_DESCRIPTOR;

/********************************************************
 *
 * Output Terminal Descriptor, 9 bytes.
 *
 **/
typedef struct OutputTerminalDescriptor
{
 u8   bLength;            /* Size of this descriptor */
 u8   bDescriptorType;    /* constant CS_INTERFACE   */
 u8   bDescriptorSubtype; /* constant OUTPUT_TERMINAL */
 u8   bTerminalID;        /* constant uniquely identifying the Terminal */
 u16  wTerminalType;      /* constant characterizing the terminal */
 u8   bAssocTerminal;     /* ID of the associated output terminal */
 u8   bSourceID;          /* constant  - ID of unit or terminal associated */
 u8   iTerminal;          /* Index  - Index of a string descriptor */
}OUTPUT_TERMINAL_DESCRIPTOR,*POUTPUT_TERMINAL_DESCRIPTOR;


/********************************************************
 *
 * Mixer Unit Descriptor.
 *
 **/
#ifndef MAX_MIXER_UNIT_NUM_INPUT_PINS
/* This is so that we define the line-in and mic exposed to the MIXER */
#if defined(__ADSP_MOAB__)
#define MAX_MIXER_UNIT_NUM_INPUT_PINS           3
#else
#define MAX_MIXER_UNIT_NUM_INPUT_PINS           2
#endif
#endif /* MAX_MIXER_UNIT_NUM_INPUT_PINS */

#ifndef MAX_MIXER_UNIT_NUM_CONTROL_BITS
#define MAX_MIXER_UNIT_NUM_CONTROL_BITS         8
#endif

typedef struct MixerUnitDescriptor
{
 u8   bLength;            /* Size of this descriptor */
 u8   bDescriptorType;    /* constant CS_INTERFACE   */
 u8   bDescriptorSubtype; /* constant MIXER_UNIT     */
 u8   bUnitID;            /* constant - uniquely identifies this unit */
 u8   bNrInPins;          /* Number of input pins to this Unit */
 u8   baSourceID[MAX_MIXER_UNIT_NUM_INPUT_PINS];
 u8   bNrChannels;        /* Number of logical output channels */
 u8   bChannelConfig_lo;  /* Bitmap - Describes spatial loc of logical chan */
 u8   bChannelConfig_hi;
 u8   iChannelNames;      /* Index string descriptor describing the name */
 u8   bmControls;         /* control bits */
 u8   iMixer;             /* Index to the string descriptor */
}MIXER_UNIT_DESCRIPTOR,*PMIXER_UNIT_DESCRIPTOR;

typedef struct SelectorUnitDescriptor
{
 u8   bLength;            /* Size of this descriptor */
 u8   bDescriptorType;    /* constant CS_INTERFACE   */
 u8   bDescriptorSubtype; /* constant SELECTOR_UNIT     */
 u8   bUnitID;            /* constant - uniquely identifies this unit */
 u8   bNrInPins;          /* Number of input pins to this Unit */
 u8   baSourceID[2];
 u8   iSelector;
}SELECTOR_UNIT_DESCRIPTOR,*PSELECTOR_UNIT_DESCRIPTOR;

/********************************************************
 *
 * Feature Unit Descriptor.
 * Size of this descriptor : 6 + (ch+1)*n bytes
 *
 **/

#ifndef USB_AUDIO_CHANNEL_CONFIG_BITMAP
inline int USB_AUDIO_CHANNEL_CONFIG_BITMAP(NrChannels) {
    int val=0,i;
    for(i=0;i<NrChannels;i++)
        val |= (1 << i);
    return val;
}
#endif /* USB_AUDIO_CHANNEL_CONFIG_BITMAP*/

#define  FEATURE_UNIT_NUM_BYTES_PER_CONTROL 2
#define  FEATUTE_UNIT_BMA_CONTROLS_ELEMENT_COUNT ((USB_AUDIO_NUM_PLAYBACK_CHANNELS + 1 ) * FEATURE_UNIT_NUM_BYTES_PER_CONTROL)

typedef struct FeatureUnitDescriptor
{
 u8   bLength;            /* Size of this descriptor */
 u8   bDescriptorType;    /* constant CS_INTERFACE   */
 u8   bDescriptorSubtype; /* constant FEATURE_UNIT   */
 u8   bUnitID;            /* contant identifying this unit */
 u8   bSourceID;          /* Associated ID of the Unit or terminal */
 u8   bControlSize;       /* Size in bytes of an element of bmaControls[] */
 u8   bmaControls[8];     /* Size in bytes of an element of bmaControls[] */
 u8   iFeature;           /* Index of a string descriptor */
}FEATURE_UNIT_DESCRIPTOR,*PFEATURE_UNIT_DESCRIPTOR;

/********************************************************
 *
 * Process Unit Descriptor.
 *
 **/
#ifndef MAX_PROCESS_UNIT_INPUT_PINS
#define MAX_PROCESS_UNIT_INPUT_PINS 1
#endif /* MAX_PROCESS_UNIT_INPUT_PINS */

#ifndef MAX_PROCESS_UNIT_NUM_BM_CONTROLS
#define MAX_PROCESS_UNIT_NUM_BM_CONTROLS 1
#endif /* MAX_PROCESS_UNIT_NUM_BM_CONTROLS */

typedef struct ProcessUnitDescriptor
{
 u8   bLength;            /* Size of this descriptor */
 u8   bDescriptorType;    /* constant CS_INTERFACE   */
 u8   bDescriptorSubtype; /* constant PROCESS_UNIT   */
 u8   bUnitID;            /* constant identifying this unit */
 u16  wProcessType;       /* constant identifying the type of process unit */
 u8   bNrPins;            /* Number of input pins */
 u8   bSourceID[MAX_PROCESS_UNIT_INPUT_PINS]; /* Input pin <--> UNIT/TER ID */
 u8   bNrChannels;        /* Number of logical output channels */
 u16  wChannelConfig;     /* Bitmap - spatial location */
 u8   iChannelNames;      /* Index of string descriptor */
 u8   bControlSize;       /* Size in bytes of the bmControls */
 u8   bmControls[MAX_PROCESS_UNIT_NUM_BM_CONTROLS];/* Number of BM controls*/
 u8   iProcessing;        /* Index of the string descriptor */
 u8   ProcessSpecific[1]; /* process specific descriptor */
}PROCESS_UNIT_DESCRIPTOR,*PPROCESS_UNIT_DESCRIPTOR;

/********************************************************
 *
 * Up/Down-Mix processing Unit descriptor
 *
 **/
#ifndef MAX_UP_DOWN_PROCESS_UNIT_NUM_MODES
#define MAX_UP_DOWN_PROCESS_UNIT_NUM_MODES 1
#endif /* MAX_UP_DOWN_PROCESS_UNIT_NUM_MODES */
typedef struct UpDownMixProcessUnitDescriptor
{
 u8   bLength;            /* Size of this descriptor */
 u8   bDescriptorType;    /* constant CS_INTERFACE   */
 u8   bDescriptorSubtype; /* constant PROCESS_UNIT   */
 u8   bUnitID;            /* constant identifying this unit */
 u16  wProcessType;       /* constant identifying the type of process unit */
 u8   bNrPins;            /* Number of input pins */
 u8   bSourceID;          /* Associated ID of the unit or terminal */
 u8   bNrChannels;        /* Number of logical  output channels */
 u16  wChannelConfig;     /* Bitmap describes the spatial location */
 u8   iChannelNames;      /* Index of a string descriptor */
 u8   bControlSize;       /* Size of the control descriptor */
 u8   bmControls[MAX_PROCESS_UNIT_NUM_BM_CONTROLS]; /* number of bm controls*/
 u8   iProcessing;        /* index of a string descriptor */
 u8   bNrModes;           /* Number of modes */
 u16  waModes[MAX_UP_DOWN_PROCESS_UNIT_NUM_MODES];/* No# channels in mode x */
}UP_DOWN_MIX_PROCESS_UNIT_DESCRIPTOR,*PUP_DOWN_MIX_PROCESS_UNIT_DESCRIPTOR;


/***********************************************************************
 *
 *                 Audio Streaming - descriptors
 *
 ***********************************************************************/

/********************************************************
 *
 * Standard Audio Streaming interface descriptor is same as
 * standard interface descriptor
 *
 **/
typedef struct InterfaceDescriptor  AUDIO_STREAMING_INTERFACE_DESCRIPTOR;

/********************************************************
 *
 * Class Specific Audio Streaming Interface Descriptor
 *
 **/
typedef struct CSAudioStreamingInterfaceDescriptor
{
#if 0
  u8   bLength;            /* Size of this descriptor */
  u8   bDescriptorType;    /* constant CS_INTERFACE   */
  u8   bDescriptorSubtype; /* constant AS_GENERAL   */
  u8   bTerminalLink;      /* Terminal ID to which the endpoint */
  u8   bDelay;             /* Delay introduced by the data path */
  u16  wFormatTag;         /* Audio Data format */
#else
  u8   bLength;            /* Size of this descriptor */
  u8   bDescriptorType;    /* constant CS_INTERFACE   */
  u8   bDescriptorSubtype; /* constant AS_GENERAL   */
  u8   bTerminalLink;      /* Terminal ID to which the endpoint */
  u8   bDelay;             /* Delay introduced by the data path */
  u8   bFormatTag_lo;      /* Audio Data format */
  u8   bFormatTag_hi;      /* Audio Data format */
#endif
}CS_SPECIFIC_AS_INTERFACE_DESCRIPTOR,*PCS_SPECIFIC_AS_INTERFACE_DESCRIPTOR;


/********************************************************
 *
 * Standard Audio Streaming Isochronous Audio Data EP Descriptor
 *
 **/
typedef struct ASIsochronousEPDescriptor
{
  u8   bLength;            /* Size of this descriptor */
  u8   bDescriptorType;    /* constant ENDPOINT   */
  u8   bEndpointAddress;   /* The address the endpoint */
  u8   bmAttributes;       /* bitmap for attributes */
  u16  wMaxPacketSize;     /* Maximum packet size for this endpoint */
  u8   bInterval;          /* Poll period in ms */
  u8   bRefresh;           /* reset to 0 */
  u8   bSynchAddress;      /* Address of the endpoint for sync info */
}AS_ISOCHRONOUS_EP_DESCRIPTOR, *PAS_ISOCHRONOUS_EP_DESCRIPTOR;

/* Endpoint Object */
typedef struct CSEndpointObject
{
  AS_ISOCHRONOUS_EP_DESCRIPTOR *pEndpointDesc;    /* Endpoint Descriptor */
  ENDPOINT_SPECIFIC_OBJECT     *pEndpointSpecificObj; /* EP-Specific Config Obj*/
  struct CSEndpointObject      *pNext;            /* Next Endpoint object */
  /* pNextActiveEp is used by the peripheral driver to get the currently active endpoint list */
  struct EndpointObject        *pNextActiveEpObj;        /* Points to the next peer endpoint object */
  int                          ID;                /* Endpoint ID */
  USB_EP_INFO                  EPInfo;
}CS_ENDPOINT_OBJECT,*PCS_ENDPOINT_OBJECT;

/********************************************************
 *
 * Class Specific Audio Streaming Isochronous Audio Data
 * EP Descriptor
 *
 **/
typedef struct CSASIsochronousEPDescriptor
{
  u8   bLength;            /* Size of this descriptor */
  u8   bDescriptorType;    /* constant CS_ENDPOINT   */
  u8   bDescriptorSubtype; /* EP_GENERAL */
  u8   bmAttributes;       /* bitmap for attributes */
  u8   bLockDelayUnits;    /* Indicates which units used for wLockDelay */
  u8   bLockDelay[2];       /* Time to lock the endpoint */
}CS_SPECIFIC_AS_ISOCHRONOUS_EP_DESCRIPTOR, *PCS_SPECIFIC_AS_ISOCHRONOUS_EP_DESCRIPTOR;

/********************************************************
 *
 * Standard Audio Isochronous Sync Endpoint Descriptor
 *
 **/
typedef struct ASIsochronousSyncEPDescriptor
{
  u8   bLength;            /* Size of this descriptor */
  u8   bDescriptorType;    /* constant ENDPOINT   */
  u8   bEndpointAddress;   /* The address the endpoint */
  u8   bmAttributes;       /* bitmap for attributes */
  u16  wMaxPacketSize;     /* Maximum packet size for this endpoint */
  u8   bInterval;          /* Poll period in ms */
  u8   bRefresh;           /* reset to 0 */
  u8   bSynchAddress;      /* Address of the endpoint for sync info */
}AS_ISOCHRONOUS_SYNC_EP_DESCRIPTOR,*PAS_ISOCHRONOUS_SYNC_EP_DESCRIPTOR;


typedef struct AudioRequestPacket
{
  u8  bmRequestType;    /* Request type */
  u8  bRequest;         /* See enum AudioRequests */
  u16 wValue;           /* CS selector varies with wIndex value */
  u16 wIndex;           /* Interface or Endpoint ID */
  u16 wLength;          /* length of the parameter block */
  void  *Data;          /* Actual Data */
}AUDIO_REQUEST_PACKET,*PAUDIO_REQUEST_PACKET;

typedef struct Type1FormatTypeDescriptor
{
  u8   bLength;             /* Size of this descriptor */
  u8   bDescriptorType;     /* Descriptor Type */
  u8   bDEscriptorSubType;  /* Descriptor Sub Type */
  u8   bFormatType;         /* Format Type */
  u8   bNrChannels;         /* Number of Physical Channels */
  u8   bSubFrameSize;       /* Number of bytes in subframe */
  u8   bBitResolution;      /* Number of bits usede */
  u8   bSamFreqType;        /* How sampling freq can be programmed */
  u8   tSampFreq[9];        /* Sample Freqs in 1Hz */
}TYPE_1_FORMAT_TYPE_DESCRIPTOR,*PTYPE_1_FORMAT_TYPE_DESCRIPTOR;

/*******************************************************************************************************/

/* USB setup packet (USB spec: 9.3) */
typedef struct _USB_SETUP_PACKET
{
    u8 bmRequestType;
    u8 bRequest;
    u16 wValue;
    u16 wIndex;
    u16 wLength;
} USB_SETUP_PACKET, *PUSB_SETUP_PACKET;

#define USB_CONTROL_REQUEST_TYPE_DIRECTION_MASK 0x80
#define USB_CONTROL_REQUEST_TYPE_DIRECTION_BITSHIFT 7
#define USB_CONTROL_REQUEST_TYPE_TYPE_MASK 0x60
#define USB_CONTROL_REQUEST_TYPE_TYPE_BITSHIFT 5
#define USB_CONTROL_REQUEST_TYPE_RECIPIENT_MASK 0x1f
#define USB_CONTROL_REQUEST_TYPE_RECIPIENT_BITSHIFT 0

#define USB_CONTROL_REQUEST_GET_DIRECTION(a) ((a & USB_CONTROL_REQUEST_TYPE_DIRECTION_MASK) >> USB_CONTROL_REQUEST_TYPE_DIRECTION_BITSHIFT)
#define USB_CONTROL_REQUEST_GET_TYPE(a) ((a & USB_CONTROL_REQUEST_TYPE_TYPE_MASK) >> USB_CONTROL_REQUEST_TYPE_TYPE_BITSHIFT)
#define USB_CONTROL_REQUEST_GET_RECIPIENT(a) (a & USB_CONTROL_REQUEST_TYPE_RECIPIENT_MASK)


#define USB_CONTROL_REQUEST_TYPE_OUT 0
#define USB_CONTROL_REQUEST_TYPE_IN 1
#define USB_CONTROL_REQUEST_TYPE_STANDARD 0x00
#define USB_CONTROL_REQUEST_TYPE_CLASS 0x01
#define USB_CONTROL_REQUEST_TYPE_VENDOR 0x02
#define USB_CONTROL_REQUEST_TYPE_DEVICE 0x00
#define USB_CONTROL_REQUEST_TYPE_INTERFACE 0x01
#define USB_CONTROL_REQUEST_TYPE_ENDPOINT 0x02
#define USB_CONTROL_REQUEST_TYPE_OTHER 0x03

#define USB_GET_DESCRIPTOR 6
#define USB_SET_DESCRIPTOR 7

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_AUDIO_H_ */
