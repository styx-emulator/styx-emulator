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

#ifndef __USB_DEVICE_VIDEO_H__
#define __USB_DEVICE_VIDEO_H__

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* USB Video device class codes */

/*! @brief Video device class code */
#define USB_DEVICE_VIDEO_CC_VIDEO (0x0EU)

/*! @brief Video device subclass code */
#define USB_DEVICE_VIDEO_SC_UNDEFINED (0x00U)
#define USB_DEVICE_VIDEO_SC_VIDEOCONTROL (0x01U)
#define USB_DEVICE_VIDEO_SC_VIDEOSTREAMING (0x02U)
#define USB_DEVICE_VIDEO_SC_VIDEO_INTERFACE_COLLECTION (0x03U)

/*! @brief Video device protocol code */
#define USB_DEVICE_VIDEO_PC_PROTOCOL_UNDEFINED (0x00U)
#define USB_DEVICE_VIDEO_PC_PROTOCOL_15 (0x01U)

/*! @brief Video device class-specific descriptor type */
#define USB_DESCRIPTOR_TYPE_VIDEO_CS_UNDEFINED (0x20U)
#define USB_DESCRIPTOR_TYPE_VIDEO_CS_DEVICE (0x21U)
#define USB_DESCRIPTOR_TYPE_VIDEO_CS_CONFIGURATION (0x22U)
#define USB_DESCRIPTOR_TYPE_VIDEO_CS_STRING (0x23U)
#define USB_DESCRIPTOR_TYPE_VIDEO_CS_INTERFACE (0x24U)
#define USB_DESCRIPTOR_TYPE_VIDEO_CS_ENDPOINT (0x25U)

/*! @brief Video device class-specific VC interface descriptor subtype */
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_DESCRIPTOR_UNDEFINED (0x00U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_HEADER (0x01U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_INPUT_TERMINAL (0x02U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_OUTPUT_TERMINAL (0x03U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_SELECTOR_UNIT (0x04U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_PROCESSING_UNIT (0x05U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_EXTENSION_UNIT (0x06U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_ENCODING_UNIT (0x07U)

/*! @brief Video device class-specific VS interface descriptor subtype */
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_UNDEFINED (0x00U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_INPUT_HEADER (0x01U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_OUTPUT_HEADER (0x02U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_STILL_IMAGE_FRAME (0x03U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_UNCOMPRESSED (0x04U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FRAME_UNCOMPRESSED (0x05U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_MJPEG (0x06U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FRAME_MJPEG (0x07U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_MPEG2TS (0x0AU)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_DV (0x0CU)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_COLORFORMAT (0x0DU)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_FRAME_BASED (0x10U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FRAME_FRAME_BASED (0x11U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_STREAM_BASED (0x12U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_H264 (0x13U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FRAME_H264 (0x14U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_H264_SIMULCAST (0x15U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_VP8 (0x16U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FRAME_VP8 (0x17U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_VP8_SIMULCAST (0x18U)

/*! @brief Video device class-specific VC endpoint descriptor subtype */
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_EP_UNDEFINED (0x00U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_EP_GENERAL (0x01U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_EP_ENDPOINT (0x02U)
#define USB_DESCRIPTOR_SUBTYPE_VIDEO_EP_INTERRUPT (0x03U)

/*! @brief Video device class-specific request code */
#define USB_DEVICE_VIDEO_REQUEST_CODE_UNDEFINED (0x00U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_SET_CUR (0x01U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_SET_CUR_ALL (0x11U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_CUR (0x81U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_MIN (0x82U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_MAX (0x83U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_RES (0x84U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_LEN (0x85U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_INFO (0x86U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_DEF (0x87U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_CUR_ALL (0x91U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_MIN_ALL (0x92U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_MAX_ALL (0x93U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_RES_ALL (0x94U)
#define USB_DEVICE_VIDEO_REQUEST_CODE_GET_DEF_ALL (0x97U)

/*! @brief Video device class-specific VideoControl interface control selector */
#define USB_DEVICE_VIDEO_VC_CONTROL_UNDEFINED (0x00U)
#define USB_DEVICE_VIDEO_VC_VIDEO_POWER_MODE_CONTROL (0x01U)
#define USB_DEVICE_VIDEO_VC_REQUEST_ERROR_CODE_CONTROL (0x02U)

/*! @brief Video device class-specific Terminal control selector */
#define USB_DEVICE_VIDEO_TE_CONTROL_UNDEFINED (0x00U)

/*! @brief Video device class-specific Selector Unit control selector */
#define USB_DEVICE_VIDEO_SU_CONTROL_UNDEFINED (0x00U)
#define USB_DEVICE_VIDEO_SU_INPUT_SELECT_CONTROL (0x01U)

/*! @brief Video device class-specific Camera Terminal control selector */
#define USB_DEVICE_VIDEO_CT_CONTROL_UNDEFINED (0x00U)
#define USB_DEVICE_VIDEO_CT_SCANNING_MODE_CONTROL (0x01U)
#define USB_DEVICE_VIDEO_CT_AE_MODE_CONTROL (0x02U)
#define USB_DEVICE_VIDEO_CT_AE_PRIORITY_CONTROL (0x03U)
#define USB_DEVICE_VIDEO_CT_EXPOSURE_TIME_ABSOLUTE_CONTROL (0x04U)
#define USB_DEVICE_VIDEO_CT_EXPOSURE_TIME_RELATIVE_CONTROL (0x05U)
#define USB_DEVICE_VIDEO_CT_FOCUS_ABSOLUTE_CONTROL (0x06U)
#define USB_DEVICE_VIDEO_CT_FOCUS_RELATIVE_CONTROL (0x07U)
#define USB_DEVICE_VIDEO_CT_FOCUS_AUTO_CONTROL (0x08U)
#define USB_DEVICE_VIDEO_CT_IRIS_ABSOLUTE_CONTROL (0x09U)
#define USB_DEVICE_VIDEO_CT_IRIS_RELATIVE_CONTROL (0x0AU)
#define USB_DEVICE_VIDEO_CT_ZOOM_ABSOLUTE_CONTROL (0x0BU)
#define USB_DEVICE_VIDEO_CT_ZOOM_RELATIVE_CONTROL (0x0CU)
#define USB_DEVICE_VIDEO_CT_PANTILT_ABSOLUTE_CONTROL (0x0DU)
#define USB_DEVICE_VIDEO_CT_PANTILT_RELATIVE_CONTROL (0x0EU)
#define USB_DEVICE_VIDEO_CT_ROLL_ABSOLUTE_CONTROL (0x0FU)
#define USB_DEVICE_VIDEO_CT_ROLL_RELATIVE_CONTROL (0x10U)
#define USB_DEVICE_VIDEO_CT_PRIVACY_CONTROL (0x11U)
#define USB_DEVICE_VIDEO_CT_FOCUS_SIMPLE_CONTROL (0x12U)
#define USB_DEVICE_VIDEO_CT_WINDOW_CONTROL (0x13U)
#define USB_DEVICE_VIDEO_CT_REGION_OF_INTEREST_CONTROL (0x14U)

/*! @brief Video device class-specific Processing Unit control selector */
#define USB_DEVICE_VIDEO_PU_CONTROL_UNDEFINED (0x00U)
#define USB_DEVICE_VIDEO_PU_BACKLIGHT_COMPENSATION_CONTROL (0x01U)
#define USB_DEVICE_VIDEO_PU_BRIGHTNESS_CONTROL (0x02U)
#define USB_DEVICE_VIDEO_PU_CONTRAST_CONTROL (0x03U)
#define USB_DEVICE_VIDEO_PU_GAIN_CONTROL (0x04U)
#define USB_DEVICE_VIDEO_PU_POWER_LINE_FREQUENCY_CONTROL (0x05U)
#define USB_DEVICE_VIDEO_PU_HUE_CONTROL (0x06U)
#define USB_DEVICE_VIDEO_PU_SATURATION_CONTROL (0x07U)
#define USB_DEVICE_VIDEO_PU_SHARPNESS_CONTROL (0x08U)
#define USB_DEVICE_VIDEO_PU_GAMMA_CONTROL (0x09U)
#define USB_DEVICE_VIDEO_PU_WHITE_BALANCE_TEMPERATURE_CONTROL (0x0AU)
#define USB_DEVICE_VIDEO_PU_WHITE_BALANCE_TEMPERATURE_AUTO_CONTROL (0x0BU)
#define USB_DEVICE_VIDEO_PU_WHITE_BALANCE_COMPONENT_CONTROL (0x0CU)
#define USB_DEVICE_VIDEO_PU_WHITE_BALANCE_COMPONENT_AUTO_CONTROL (0x0DU)
#define USB_DEVICE_VIDEO_PU_DIGITAL_MULTIPLIER_CONTROL (0x0EU)
#define USB_DEVICE_VIDEO_PU_DIGITAL_MULTIPLIER_LIMIT_CONTROL (0x0FU)
#define USB_DEVICE_VIDEO_PU_HUE_AUTO_CONTROL (0x10U)
#define USB_DEVICE_VIDEO_PU_ANALOG_VIDEO_STANDARD_CONTROL (0x11U)
#define USB_DEVICE_VIDEO_PU_ANALOG_LOCK_STATUS_CONTROL (0x12U)
#define USB_DEVICE_VIDEO_PU_CONTRAST_AUTO_CONTROL (0x13U)

/*! @brief Video device class-specific Encoding Unit control selector */
#define USB_DEVICE_VIDEO_EU_CONTROL_UNDEFINED (0x00U)
#define USB_DEVICE_VIDEO_EU_SELECT_LAYER_CONTROL (0x01U)
#define USB_DEVICE_VIDEO_EU_PROFILE_TOOLSET_CONTROL (0x02U)
#define USB_DEVICE_VIDEO_EU_VIDEO_RESOLUTION_CONTROL (0x03U)
#define USB_DEVICE_VIDEO_EU_MIN_FRAME_INTERVAL_CONTROL (0x04U)
#define USB_DEVICE_VIDEO_EU_SLICE_MODE_CONTROL (0x05U)
#define USB_DEVICE_VIDEO_EU_RATE_CONTROL_MODE_CONTROL (0x06U)
#define USB_DEVICE_VIDEO_EU_AVERAGE_BITRATE_CONTROL (0x07U)
#define USB_DEVICE_VIDEO_EU_CPB_SIZE_CONTROL (0x08U)
#define USB_DEVICE_VIDEO_EU_PEAK_BIT_RATE_CONTROL (0x09U)
#define USB_DEVICE_VIDEO_EU_QUANTIZATION_PARAMS_CONTROL (0x0AU)
#define USB_DEVICE_VIDEO_EU_SYNC_REF_FRAME_CONTROL (0x0BU)
#define USB_DEVICE_VIDEO_EU_LTR_BUFFER_ CONTROL(0x0CU)
#define USB_DEVICE_VIDEO_EU_LTR_PICTURE_CONTROL (0x0DU)
#define USB_DEVICE_VIDEO_EU_LTR_VALIDATION_CONTROL (0x0EU)
#define USB_DEVICE_VIDEO_EU_LEVEL_IDC_LIMIT_CONTROL (0x0FU)
#define USB_DEVICE_VIDEO_EU_SEI_PAYLOADTYPE_CONTROL (0x10U)
#define USB_DEVICE_VIDEO_EU_QP_RANGE_CONTROL (0x11U)
#define USB_DEVICE_VIDEO_EU_PRIORITY_CONTROL (0x12U)
#define USB_DEVICE_VIDEO_EU_START_OR_STOP_LAYER_CONTROL (0x13U)
#define USB_DEVICE_VIDEO_EU_ERROR_RESILIENCY_CONTROL (0x14U)

/*! @brief Video device class-specific Extension Unit control selector */
#define USB_DEVICE_VIDEO_XU_CONTROL_UNDEFINED (0x00U)

/*! @brief Video device class-specific VideoStreaming Interface control selector */
#define USB_DEVICE_VIDEO_VS_CONTROL_UNDEFINED (0x00U)
#define USB_DEVICE_VIDEO_VS_PROBE_CONTROL (0x01U)
#define USB_DEVICE_VIDEO_VS_COMMIT_CONTROL (0x02U)
#define USB_DEVICE_VIDEO_VS_STILL_PROBE_CONTROL (0x03U)
#define USB_DEVICE_VIDEO_VS_STILL_COMMIT_CONTROL (0x04U)
#define USB_DEVICE_VIDEO_VS_STILL_IMAGE_TRIGGER_CONTROL (0x05U)
#define USB_DEVICE_VIDEO_VS_STREAM_ERROR_CODE_CONTROL (0x06U)
#define USB_DEVICE_VIDEO_VS_GENERATE_KEY_FRAME_CONTROL (0x07U)
#define USB_DEVICE_VIDEO_VS_UPDATE_FRAME_SEGMENT_CONTROL (0x08U)
#define USB_DEVICE_VIDEO_VS_SYNCH_DELAY_CONTROL (0x09U)

/* video device terminal types */

/*! @brief Video device USB terminal type */
#define USB_DEVICE_VIDEO_TT_VENDOR_SPECIFIC (0x0100U)
#define USB_DEVICE_VIDEO_TT_STREAMING (0x0101U)

/*! @brief Video device input terminal type */
#define USB_DEVICE_VIDEO_ITT_VENDOR_SPECIFIC (0x0200U)
#define USB_DEVICE_VIDEO_ITT_CAMERA (0x0201U)
#define USB_DEVICE_VIDEO_ITT_MEDIA_TRANSPORT_INPUT (0x0202U)

/*! @brief Video device output terminal type */
#define USB_DEVICE_VIDEO_OTT_VENDOR_SPECIFIC (0x0300U)
#define USB_DEVICE_VIDEO_OTT_DISPLAY (0x0301U)
#define USB_DEVICE_VIDEO_OTT_MEDIA_TRANSPORT_OUTPUT (0x0302U)

/*! @brief Video device external terminal type */
#define USB_DEVICE_VIDEO_ET_VENDOR_SPECIFIC (0x0400U)
#define USB_DEVICE_VIDEO_ET_COMPOSITE_CONNECTOR (0x0401U)
#define USB_DEVICE_VIDEO_ET_SVIDEO_CONNECTOR (0x0402U)
#define USB_DEVICE_VIDEO_ET_COMPONENT_CONNECTOR (0x0403U)

/* request code */
/*! @brief Video device class setup request set type */
#define USB_DEVICE_VIDEO_SET_REQUEST_INTERFACE (0x21U)
#define USB_DEVICE_VIDEO_SET_REQUEST_ENDPOINT (0x22U)

/*! @brief Video device class setup request get type */
#define USB_DEVICE_VIDEO_GET_REQUEST_INTERFACE (0xA1U)
#define USB_DEVICE_VIDEO_GET_REQUEST_ENDPOINT (0xA2U)

/*! @brief Video device still image trigger control */
#define USB_DEVICE_VIDEO_STILL_IMAGE_TRIGGER_NORMAL_OPERATION (0x00U)
#define USB_DEVICE_VIDEO_STILL_IMAGE_TRIGGER_TRANSMIT_STILL_IMAGE (0x01U)
#define USB_DEVICE_VIDEO_STILL_IMAGE_TRIGGER_TRANSMIT_STILL_IMAGE_VS_DEDICATED_BULK_PIPE (0x02U)
#define USB_DEVICE_VIDEO_STILL_IMAGE_TRIGGER_ABORT_STILL_IMAGE_TRANSMISSION (0x03U)

/*! @brief The payload header structure for MJPEG payload format. */
STRUCT_PACKED
struct _usb_device_video_mjpeg_payload_header_struct
{
    uint8_t bHeaderLength; /*!< The payload header length. */
    union
    {
        uint8_t bmheaderInfo; /*!< The payload header bitmap field. */
        struct
        {
            uint8_t frameIdentifier : 1U; /*!< Frame Identifier. This bit toggles at each frame start boundary and stays
                                             constant for the rest of the frame.*/
            uint8_t endOfFrame : 1U; /*!< End of Frame. This bit indicates the end of a video frame and is set in the
                                        last video sample that belongs to a frame.*/
            uint8_t
                presentationTimeStamp : 1U; /*!< Presentation Time Stamp. This bit, when set, indicates the presence of
                                               a PTS field.*/
            uint8_t sourceClockReference : 1U; /*!< Source Clock Reference. This bit, when set, indicates the presence
                                                  of a SCR field.*/
            uint8_t reserved : 1U;             /*!< Reserved. Set to 0. */
            uint8_t stillImage : 1U;  /*!< Still Image. This bit, when set, identifies a video sample that belongs to a
                                         still image.*/
            uint8_t errorBit : 1U;    /*!< Error Bit. This bit, when set, indicates an error in the device streaming.*/
            uint8_t endOfHeader : 1U; /*!< End of Header. This bit, when set, indicates the end of the BFH fields.*/
        } headerInfoBits;
        struct
        {
            uint8_t FID : 1U; /*!< Frame Identifier. This bit toggles at each frame start boundary and stays constant
                                 for the rest of the frame.*/
            uint8_t EOI : 1U; /*!< End of Frame. This bit indicates the end of a video frame and is set in the last
                                 video sample that belongs to a frame.*/
            uint8_t PTS : 1U; /*!< Presentation Time Stamp. This bit, when set, indicates the presence of a PTS field.*/
            uint8_t SCR : 1U; /*!< Source Clock Reference. This bit, when set, indicates the presence of a SCR field.*/
            uint8_t RES : 1U; /*!< Reserved. Set to 0. */
            uint8_t STI : 1U; /*!< Still Image. This bit, when set, identifies a video sample that belongs to a still
                                 image.*/
            uint8_t ERR : 1U; /*!< Error Bit. This bit, when set, indicates an error in the device streaming.*/
            uint8_t EOH : 1U; /*!< End of Header. This bit, when set, indicates the end of the BFH fields.*/
        } headerInfoBitmap;
    } headerInfoUnion;
    uint32_t dwPresentationTime;      /*!< Presentation time stamp (PTS) field.*/
    uint8_t bSourceClockReference[6]; /*!< Source clock reference (SCR) field.*/
} STRUCT_UNPACKED;
typedef struct _usb_device_video_mjpeg_payload_header_struct usb_device_video_mjpeg_payload_header_struct_t;

/*! @brief The Video probe and commit controls structure.*/
STRUCT_PACKED
struct _usb_device_video_probe_and_commit_controls_struct
{
    union
    {
        uint8_t bmHint; /*!< Bit-field control indicating to the function what fields shall be kept fixed. */
        struct
        {
            uint8_t dwFrameInterval : 1U; /*!< dwFrameInterval field.*/
            uint8_t wKeyFrameRate : 1U;   /*!< wKeyFrameRate field.*/
            uint8_t wPFrameRate : 1U;     /*!< wPFrameRate field.*/
            uint8_t wCompQuality : 1U;    /*!< wCompQuality field.*/
            uint8_t wCompWindowSize : 1U; /*!< wCompWindowSize field.*/
            uint8_t reserved : 3U;        /*!< Reserved field.*/
        } hintBitmap;
    } hintUnion;
    union
    {
        uint8_t bmHint; /*!< Bit-field control indicating to the function what fields shall be kept fixed. */
        struct
        {
            uint8_t reserved : 8U; /*!< Reserved field.*/
        } hintBitmap;
    } hintUnion1;
    uint8_t bFormatIndex;     /*!< Video format index from a format descriptor.*/
    uint8_t bFrameIndex;      /*!< Video frame index from a frame descriptor.*/
    uint32_t dwFrameInterval; /*!< Frame interval in 100ns units.*/
    uint16_t wKeyFrameRate;   /*!< Key frame rate in key-frame per video-frame units.*/
    uint16_t wPFrameRate;     /*!< PFrame rate in PFrame/key frame units.*/
    uint16_t wCompQuality;    /*!< Compression quality control in abstract units 0U (lowest) to 10000U (highest).*/
    uint16_t wCompWindowSize; /*!< Window size for average bit rate control.*/
    uint16_t wDelay; /*!< Internal video streaming interface latency in ms from video data capture to presentation on
                        the USB.*/
    uint32_t dwMaxVideoFrameSize;      /*!< Maximum video frame or codec-specific segment size in bytes.*/
    uint32_t dwMaxPayloadTransferSize; /*!< Specifies the maximum number of bytes that the device can transmit or
                                          receive in a single payload transfer.*/
    uint32_t dwClockFrequency; /*!< The device clock frequency in Hz for the specified format. This specifies the
                                  units used for the time information fields in the Video Payload Headers in the data
                                  stream.*/
    uint8_t bmFramingInfo;     /*!< Bit-field control supporting the following values: D0 Frame ID, D1 EOF.*/
    uint8_t bPreferedVersion;  /*!< The preferred payload format version supported by the host or device for the
                                  specified bFormatIndex value.*/
    uint8_t bMinVersion; /*!< The minimum payload format version supported by the device for the specified bFormatIndex
                            value.*/
    uint8_t bMaxVersion; /*!< The maximum payload format version supported by the device for the specified bFormatIndex
                            value.*/
#if defined(USB_DEVICE_VIDEO_CLASS_VERSION_1_5) && USB_DEVICE_VIDEO_CLASS_VERSION_1_5
    uint8_t bUsage; /*!< This bitmap enables features reported by the bmUsages field of the Video Frame Descriptor.*/
    uint8_t
        bBitDepthLuma;  /*!< Represents bit_depth_luma_minus8 + 8U, which must be the same as bit_depth_chroma_minus8 +
                           8.*/
    uint8_t bmSettings; /*!< A bitmap of flags that is used to discover and control specific features of a temporally
                           encoded video stream.*/
    uint8_t bMaxNumberOfRefFramesPlus1; /*!< Host indicates the maximum number of frames stored for use as references.*/
    uint16_t bmRateControlModes;        /*!< This field contains 4U sub-fields, each of which is a 4U bit number.*/
    uint64_t bmLayoutPerStream;         /*!< This field contains 4U sub-fields, each of which is a 2U byte number.*/
#endif
} STRUCT_UNPACKED;
typedef struct _usb_device_video_probe_and_commit_controls_struct usb_device_video_probe_and_commit_controls_struct_t;

/*! @brief The Video still probe and still commit controls structure.*/
STRUCT_PACKED
struct _usb_device_video_still_probe_and_commit_controls_struct
{
    uint8_t bFormatIndex;              /*!< Video format index from a format descriptor.*/
    uint8_t bFrameIndex;               /*!< Video frame index from a frame descriptor.*/
    uint8_t bCompressionIndex;         /*!< Compression index from a frame descriptor.*/
    uint32_t dwMaxVideoFrameSize;      /*!< Maximum still image size in bytes.*/
    uint32_t dwMaxPayloadTransferSize; /*!< Specifies the maximum number of bytes that the device can transmit or
                                          receive in a single payload transfer.*/
} STRUCT_UNPACKED;
typedef struct _usb_device_video_still_probe_and_commit_controls_struct
    usb_device_video_still_probe_and_commit_controls_struct_t;

/*******************************************************************************
 * API
 ******************************************************************************/
#endif /* __USB_DEVICE_VIDEO_H__ */
