/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_terminaltypes.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
             Defines standard terminal types.  Refer: "Universal Serial Bus Device
             Class Definition for Terminal Types".

*********************************************************************************/

#ifndef _ADI_USB_TERMINALTYPES_H_
#define _ADI_USB_TERMINALTYPES_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* USB Terminal types */
#define USB_AUDIO_TERMINAL_TYPE_UNDEFINED          0x0100
#define USB_AUDIO_TERMINAL_TYPE_STREAMING          0x0101
#define USB_AUDIO_TERMINAL_TYPE_VENDORSPECIFIC     0x01FF

/* USB Input terminal types */
#define USB_AUDIO_INPUT_TERMINALTYPE_UNDEFINED              0x0200
#define USB_AUDIO_INPUT_TERMINALTYPE_MICROPHONE             0x0201
#define USB_AUDIO_INPUT_TERMINALTYPE_DESKTOP_MICROPHONE     0x0202
#define USB_AUDIO_INPUT_TERMINALTYPE_PERSONAL_MICROPHONE    0x0203
#define USB_AUDIO_INPUT_TERMINALTYPE_OMINI_MICROPHONE       0x0204
#define USB_AUDIO_INPUT_TERMINALTYPE_MICROPHONE_ARRAY       0x0204

/* USB Output terminal types */
#define USB_AUDIO_OUTPUT_TERMINALTYPE_UNDEFINED              0x0300
#define USB_AUDIO_OUTPUT_TERMINALTYPE_SPEAKER                0x0301
#define USB_AUDIO_OUTPUT_TERMINALTYPE_HEADPHONES             0x0302
#define USB_AUDIO_OUTPUT_TERMINALTYPE_HMDA                   0x0303
#define USB_AUDIO_OUTPUT_TERMINALTYPE_DESKTOP_SPEAKER        0x0304
#define USB_AUDIO_OUTPUT_TERMINALTYPE_ROOM_SPEAKER           0x0305
#define USB_AUDIO_OUTPUT_TERMINALTYPE_COMM_SPEAKER           0x0306
#define USB_AUDIO_OUTPUT_TERMINALTYPE_LOW_FREQ_SPEAKER       0x0307

/* Bi-directional terminal types */
#define USB_AUDIO_BIDIR_TERMINALTYPE_UNDEFINED               0x0400
#define USB_AUDIO_BIDIR_TERMINALTYPE_HANDSET                 0x0401
#define USB_AUDIO_BIDIR_TERMINALTYPE_HM_HANDSET              0x0402
#define USB_AUDIO_BIDIR_TERMINALTYPE_SPEAKER_PHONE           0x0403
#define USB_AUDIO_BIDIR_TERMINALTYPE_ES_SPEAKER_PHONE        0x0404
#define USB_AUDIO_BIDIR_TERMINALTYPE_EC_SPEAKER_PHONE        0x0405

/* Telephony terminal types */
#define USB_TELEPHONY_TERMINALTYPE_UNDEFIEND                 0x0500
#define USB_TELEPHONY_TERMINALTYPE_PHONE_LINE                0x0501
#define USB_TELEPHONY_TERMINALTYPE_TELEPHONE                 0x0502
#define USB_TELEPHONY_TERMINALTYPE_DOWNLINE_PHONE            0x0503

/* External Terminal devices */
#define USB_EXTERNAL_TERMINALTYPE_UNDEFIEND                  0x0600
#define USB_EXTERNAL_TERMINALTYPE_ANALOG_CONNECTOR           0x0601
#define USB_EXTERNAL_TERMINALTYPE_DIGITAL_AUDIO              0x0602
#define USB_EXTERNAL_TERMINALTYPE_LINE_CONNECTOR             0x0603
#define USB_EXTERNAL_TERMINALTYPE_LEGACY_AUDIO_CONNECTOR     0x0604
#define USB_EXTERNAL_TERMINALTYPE_S_PDIF_INTERFACE           0x0605
#define USB_EXTERNAL_TERMINALTYPE_1394_DA_STREAM             0x0606
#define USB_EXTERNAL_TERMINALTYPE_1394_DV_STREAM             0x0607

/* Embedded function terminal types */
#define USB_EMBEDDED_TERMINALTYPE_UNDEFIEND                  0x0700
#define USB_EMBEDDED_TERMINALTYPE_LCNS                       0x0701
#define USB_EMBEDDED_TERMINALTYPE_EQU_NOISE                  0x0702
#define USB_EMBEDDED_TERMINALTYPE_CD_PLAYER                  0x0703
#define USB_EMBEDDED_TERMINALTYPE_DAT                        0x0704
#define USB_EMBEDDED_TERMINALTYPE_DCC                        0x0705
#define USB_EMBEDDED_TERMINALTYPE_MINI_DISK                  0x0706
#define USB_EMBEDDED_TERMINALTYPE_ANALOG_TAPE                0x0707
#define USB_EMBEDDED_TERMINALTYPE_PHONOGRAPH                 0x0708
#define USB_EMBEDDED_TERMINALTYPE_VCR_AUDIO                  0x0709
#define USB_EMBEDDED_TERMINALTYPE_VIDEO_DISC_AUDIO           0x070A
#define USB_EMBEDDED_TERMINALTYPE_DVD_AUDIO                  0x070B
#define USB_EMBEDDED_TERMINALTYPE_TV_TUNER_AUDIO             0x070C
#define USB_EMBEDDED_TERMINALTYPE_SATELLITE_RECEIVER_AUDIO   0x070D
#define USB_EMBEDDED_TERMINALTYPE_CABLE_TUNER_AUDIO          0x070E
#define USB_EMBEDDED_TERMINALTYPE_DSS_AUDIO                  0x070F
#define USB_EMBEDDED_TERMINALTYPE_RADIO_RECEIVER             0x0710
#define USB_EMBEDDED_TERMINALTYPE_RADIO_TRANSMITTER          0x0711
#define USB_EMBEDDED_TERMINALTYPE_MULTITRACK_RECORDER        0x0712
#define USB_EMBEDDED_TERMINALTYPE_SYNTHESIZER                0x0713

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_TERMINALTYPES_H_ */
