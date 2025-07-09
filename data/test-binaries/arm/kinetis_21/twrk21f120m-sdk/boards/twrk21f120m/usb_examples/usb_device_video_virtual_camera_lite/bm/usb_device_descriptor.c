/*
 * The Clear BSD License
 * Copyright (c) 2015 - 2016, Freescale Semiconductor, Inc.
 * Copyright 2016 , 2018 NXP
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

#include "usb_device_video.h"

#include "usb_device_descriptor.h"
#include "virtual_camera.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

extern usb_status_t USB_DeviceCallback(usb_device_handle deviceHandle, uint32_t event, void *param);

/*******************************************************************************
 * Variables
 ******************************************************************************/

uint8_t g_UsbDeviceCurrentConfigure = 0U;
uint8_t g_UsbDeviceInterface[USB_VIDEO_VIRTUAL_CAMERA_INTERFACE_COUNT];

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceDescriptor[] = {
    USB_DESCRIPTOR_LENGTH_DEVICE, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_DEVICE,   /* DEVICE Descriptor Type */
    USB_SHORT_GET_LOW(USB_DEVICE_SPECIFIC_BCD_VERSION),
    USB_SHORT_GET_HIGH(USB_DEVICE_SPECIFIC_BCD_VERSION), /* USB Specification Release Number in
                                                            Binary-Coded Decimal (i.e., 2.10 is 210H). */
    USB_DEVICE_CLASS,                                    /* Class code (assigned by the USB-IF). */
    USB_DEVICE_SUBCLASS,                                 /* Subclass code (assigned by the USB-IF). */
    USB_DEVICE_PROTOCOL,                                 /* Protocol code (assigned by the USB-IF). */
    USB_CONTROL_MAX_PACKET_SIZE,                         /* Maximum packet size for endpoint zero
                                                            (only 8, 16, 32, or 64 are valid) */
    0xC9U, 0x1FU,                                        /* Vendor ID (assigned by the USB-IF) */
    0x99U, 0x00U,                                        /* Product ID (assigned by the manufacturer) */
    USB_SHORT_GET_LOW(USB_DEVICE_DEMO_BCD_VERSION),
    USB_SHORT_GET_HIGH(USB_DEVICE_DEMO_BCD_VERSION), /* Device release number in binary-coded decimal */
    0x01U,                                           /* Index of string descriptor describing manufacturer */
    0x02U,                                           /* Index of string descriptor describing product */
    0x00U,                                           /* Index of string descriptor describing the
                                                        device's serial number */
    USB_DEVICE_CONFIGURATION_COUNT,                  /* Number of possible configurations */
};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceConfigurationDescriptor[] = {
    USB_DESCRIPTOR_LENGTH_CONFIGURE, /* Size of this descriptor in bytes */
    USB_DESCRIPTOR_TYPE_CONFIGURE,   /* CONFIGURATION Descriptor Type */
    USB_SHORT_GET_LOW(USB_DESCRIPTOR_LENGTH_CONFIGURE + USB_DESCRIPTOR_LENGTH_INTERFACE_ASSOCIATION +
                      USB_DESCRIPTOR_LENGTH_INTERFACE + USB_VIDEO_VIRTUAL_CAMERA_VC_INTERFACE_HEADER_LENGTH +
                      USB_VIDEO_VIRTUAL_CAMERA_VC_INPUT_TERMINAL_LENGTH +
                      USB_VIDEO_VIRTUAL_CAMERA_VC_OUTPUT_TERMINAL_LENGTH +
                      USB_VIDEO_VIRTUAL_CAMERA_VC_PROCESSING_UNIT_LENGTH + USB_DESCRIPTOR_LENGTH_ENDPOINT +
                      USB_DESCRIPTOR_LENGTH_INTERFACE + USB_VIDEO_VIRTUAL_CAMERA_VS_INTERFACE_HEADER_LENGTH +
                      USB_VIDEO_MJPEG_FORMAT_DESCRIPTOR_LENGTH + USB_VIDEO_MJPEG_FRAME_DESCRIPTOR_LENGTH +
                      USB_VIDEO_MJPEG_FRAME_STILL_DESCRIPTOR_LENGTH + USB_DESCRIPTOR_LENGTH_INTERFACE +
                      USB_DESCRIPTOR_LENGTH_ENDPOINT),
    USB_SHORT_GET_HIGH(USB_DESCRIPTOR_LENGTH_CONFIGURE + USB_DESCRIPTOR_LENGTH_INTERFACE_ASSOCIATION +
                       USB_DESCRIPTOR_LENGTH_INTERFACE + USB_VIDEO_VIRTUAL_CAMERA_VC_INTERFACE_HEADER_LENGTH +
                       USB_VIDEO_VIRTUAL_CAMERA_VC_INPUT_TERMINAL_LENGTH +
                       USB_VIDEO_VIRTUAL_CAMERA_VC_OUTPUT_TERMINAL_LENGTH +
                       USB_VIDEO_VIRTUAL_CAMERA_VC_PROCESSING_UNIT_LENGTH + USB_DESCRIPTOR_LENGTH_ENDPOINT +
                       USB_DESCRIPTOR_LENGTH_INTERFACE + USB_VIDEO_VIRTUAL_CAMERA_VS_INTERFACE_HEADER_LENGTH +
                       USB_VIDEO_MJPEG_FORMAT_DESCRIPTOR_LENGTH + USB_VIDEO_MJPEG_FRAME_DESCRIPTOR_LENGTH +
                       USB_VIDEO_MJPEG_FRAME_STILL_DESCRIPTOR_LENGTH + USB_DESCRIPTOR_LENGTH_INTERFACE +
                       USB_DESCRIPTOR_LENGTH_ENDPOINT), /* Total length of data returned for this configuration. */
    USB_VIDEO_VIRTUAL_CAMERA_INTERFACE_COUNT,           /* Number of interfaces supported by this configuration */
    USB_VIDEO_VIRTUAL_CAMERA_CONFIGURE_INDEX,           /* Value to use as an argument to the
                                                 SetConfiguration() request to select this configuration */
    0x00U,                                              /* Index of string descriptor describing this configuration */
    (USB_DESCRIPTOR_CONFIGURE_ATTRIBUTE_D7_MASK) |
        (USB_DEVICE_CONFIG_SELF_POWER << USB_DESCRIPTOR_CONFIGURE_ATTRIBUTE_SELF_POWERED_SHIFT) |
        (USB_DEVICE_CONFIG_REMOTE_WAKEUP << USB_DESCRIPTOR_CONFIGURE_ATTRIBUTE_REMOTE_WAKEUP_SHIFT),
    /* Configuration characteristics
        D7: Reserved (set to one)
        D6: Self-powered
        D5: Remote Wakeup
        D4...0: Reserved (reset to zero)
     */
    USB_DEVICE_MAX_POWER, /* Maximum power consumption of the USB
                           * device from the bus in this specific
                           * configuration when the device is fully
                           * operational. Expressed in 2 mA units
                           *  (i.e., 50 = 100 mA).
                           */
    /* Interface Association Descriptor */
    USB_DESCRIPTOR_LENGTH_INTERFACE_ASSOCIATION,      /* size of the IAD */
    USB_DESCRIPTOR_TYPE_INTERFACE_ASSOCIATION,        /* INTERFACE ASSOCIATION Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_CONTROL_INTERFACE_INDEX, /* Interface number of the first VideoControl
                                                         interface that is associated with this function. */
    USB_VIDEO_VIRTUAL_CAMERA_INTERFACE_COUNT,         /* Number of contiguous VideoStreaming interfaces that are
                                                         associated with this function.
                                                         The count includes the first VideoControl interface and all
                                                         its associated VideoStreaming interfaces.
                                                      */
    USB_DEVICE_VIDEO_CC_VIDEO,                        /* CC_VIDEO, Video Interface Class code */
    USB_DEVICE_VIDEO_SC_VIDEO_INTERFACE_COLLECTION,   /* SC_VIDEO_INTERFACE_COLLECTION. Video Interface
                                                         Subclass code */
    USB_DEVICE_VIDEO_PC_PROTOCOL_UNDEFINED,           /* Not used, Must be set to PC_PROTOCOL_UNDEFINED */
    0x03U,                                            /* Index of a string descriptor */

    /* Standard VC Interface Descriptor */
    USB_DESCRIPTOR_LENGTH_INTERFACE,                  /* Size of this descriptor */
    USB_DESCRIPTOR_TYPE_INTERFACE,                    /* INTERFACE Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_CONTROL_INTERFACE_INDEX, /* Index of control interface */
    0x00U,                                            /* Index of the interface setting */
    USB_VIDEO_VIRTUAL_CAMERA_CONTROL_ENDPOINT_COUNT,  /* One endpoint of control pipe */
    USB_DEVICE_VIDEO_CC_VIDEO,                        /* CC_VIDEO */
    USB_DEVICE_VIDEO_SC_VIDEOCONTROL,                 /* SC_VIDEOCONTROL */
    USB_DEVICE_VIDEO_VIRTUAL_CAMERA_PROTOCOL,         /* Protocol */
    0x00U,                                            /* Index of this string descriptor */

    /* Class-Specific VC Interface header Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_VC_INTERFACE_HEADER_LENGTH, /* Size of this descriptor, 12+n */
    USB_DESCRIPTOR_TYPE_VIDEO_CS_INTERFACE,              /* CS_INTERFACE, descriptor type */
    USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_HEADER,              /* VC_HEADER, descriptor subtype */
    USB_SHORT_GET_LOW(USB_DEVICE_VIDEO_SPECIFIC_BCD_VERSION), USB_SHORT_GET_HIGH(USB_DEVICE_VIDEO_SPECIFIC_BCD_VERSION),
    /* bcdUVC */
    USB_SHORT_GET_LOW(USB_VIDEO_VIRTUAL_CAMERA_VC_INTERFACE_TOTAL_LENGTH),
    USB_SHORT_GET_HIGH(USB_VIDEO_VIRTUAL_CAMERA_VC_INTERFACE_TOTAL_LENGTH),
    /* Total number of bytes returned for the class-specific VideoControl interface descriptor.
       Includes the combined length of this descriptor header and all Unit and Terminal descriptors. */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_CLOCK_FREQUENCY),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_CLOCK_FREQUENCY),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_CLOCK_FREQUENCY),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_CLOCK_FREQUENCY),
    /* Use of this field has been deprecated. */
    USB_VIDEO_VIRTUAL_CAMERA_STREAM_INTERFACE_COUNT, /* The number of VideoStreaming interfaces in the Video
                                                        Interface Collection to which this VideoControl
                                                        interface belongs: n */
    USB_VIDEO_VIRTUAL_CAMERA_STREAM_INTERFACE_INDEX, /* Interface number of the first VideoStreaming
                                                        interface in the Collection */

    /* Input Terminal Descriptor (Camera) */
    USB_VIDEO_VIRTUAL_CAMERA_VC_INPUT_TERMINAL_LENGTH, /* Size of this descriptor, 15+n */
    USB_DESCRIPTOR_TYPE_VIDEO_CS_INTERFACE,            /* CS_INTERFACE, descriptor type */
    USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_INPUT_TERMINAL,    /* VC_INPUT_TERMINAL, descriptor subtype */
    USB_VIDEO_VIRTUAL_CAMERA_VC_INPUT_TERMINAL_ID,     /* A non-zero constant that uniquely identifies the
                                                          Terminal within the video function. This value is used
                                                          in all requests to address this Terminal. */
    USB_SHORT_GET_LOW(USB_VIDEO_VIRTUAL_CAMERA_VC_INPUT_TERMINAL_TYPE),
    USB_SHORT_GET_HIGH(USB_VIDEO_VIRTUAL_CAMERA_VC_INPUT_TERMINAL_TYPE),
    /* ITT_CAMERA, Constant that characterizes the type of Terminal */
    0x00U,               /* ID of the Output Terminal to which this Input Terminal is associated */
    0x00U,               /* Index of a string descriptor */
    0x00U, 0x00U,        /* The value of Lmin, unsupported */
    0x00U, 0x00U,        /* The value of Lmax, unsupported */
    0x00U, 0x00U,        /* The value of Locular, unsupported */
    0x03U,               /* Size in bytes of the bmControls field: n */
    0x00U, 0x00U, 0x00U, /* Not control supported */

    /* Output Terminal Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_VC_OUTPUT_TERMINAL_LENGTH, /* Size of this descriptor, 9+n */
    USB_DESCRIPTOR_TYPE_VIDEO_CS_INTERFACE,             /* CS_INTERFACE, descriptor type */
    USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_OUTPUT_TERMINAL,    /* VC_OUTPUT_TERMINAL, descriptor subtype */
    USB_VIDEO_VIRTUAL_CAMERA_VC_OUTPUT_TERMINAL_ID,     /* A non-zero constant that uniquely identifies the
                                                           Terminal within the video function. This value is
                                                           used in all requests to address this Terminal. */
    USB_SHORT_GET_LOW(USB_DEVICE_VIDEO_TT_STREAMING), USB_SHORT_GET_HIGH(USB_DEVICE_VIDEO_TT_STREAMING),
    /* TT_STREAMING, Constant that characterizes the type of Terminal */
    0x00U, /* ID of the Input Terminal to which this Output Terminal is associated */
    USB_VIDEO_VIRTUAL_CAMERA_VC_INPUT_TERMINAL_ID, /* ID of the Unit or Terminal to which this Terminal is
                                                      connected */
    0x00U,                                         /* Index of a string descriptor */

    /* Processing Unit Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_VC_PROCESSING_UNIT_LENGTH, /* Size of this descriptor, 10+n */
    USB_DESCRIPTOR_TYPE_VIDEO_CS_INTERFACE,             /* CS_INTERFACE, descriptor type */
    USB_DESCRIPTOR_SUBTYPE_VIDEO_VC_PROCESSING_UNIT,    /* VC_PROCESSING_UNIT, descriptor subtype */
    USB_VIDEO_VIRTUAL_CAMERA_VC_PROCESSING_UNIT_ID,     /* A non-zero constant that uniquely identifies the
                                                           Terminal within the video function. This value is
                                                           used in all requests to address this Terminal. */
    USB_VIDEO_VIRTUAL_CAMERA_VC_INPUT_TERMINAL_ID,      /* ID of the Unit or Terminal to which this Terminal is
                                                           connected */
    0x00U, 0x00U, /* This field indicates the maximum digital magnification, multiplied by 100U */
#if defined(USB_DEVICE_VIDEO_CLASS_VERSION_1_5) && (USB_DEVICE_VIDEO_CLASS_VERSION_1_5 > 0U)
    0x03U,               /* Size of the bmControls field, in bytes: n */
    0x00U, 0x00U, 0x00U, /* Not control supported */
#else
    0x02U,        /* Size of the bmControls field, in bytes: n */
    0x00U, 0x00U, /* Not control supported */
#endif     /* USB_DEVICE_VIDEO_CLASS_VERSION_1_5 */
    0x00U, /* Index of a string descriptor */
#if defined(USB_DEVICE_VIDEO_CLASS_VERSION_1_1) && (USB_DEVICE_VIDEO_CLASS_VERSION_1_1 > 0U) \
|| defined(USB_DEVICE_VIDEO_CLASS_VERSION_1_5) && (USB_DEVICE_VIDEO_CLASS_VERSION_1_5 > 0U)
    0x00U, /* A bitmap of all analog video standards supported by the Processing Unit */
#endif     /* USB_DEVICE_VIDEO_CLASS_VERSION_1_1 || USB_DEVICE_VIDEO_CLASS_VERSION_1_5 */
    /* Standard VC Interrupt Endpoint Descriptor */
    USB_DESCRIPTOR_LENGTH_ENDPOINT, /* Size of this descriptor, in bytes: 7U */
    USB_DESCRIPTOR_TYPE_ENDPOINT,   /* ENDPOINT descriptor type */
    USB_VIDEO_VIRTUAL_CAMERA_CONTROL_ENDPOINT |
        (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT), /* Endpoint address */
    USB_ENDPOINT_INTERRUPT,                                          /* Transfer type */
    USB_SHORT_GET_LOW(FS_INTERRUPT_IN_PACKET_SIZE),
    USB_SHORT_GET_HIGH(FS_INTERRUPT_IN_PACKET_SIZE),
    /* Max Packet Size */
    FS_INTERRUPT_IN_INTERVAL, /* Interval */

    /* Standard VS Interface Descriptor */
    USB_DESCRIPTOR_LENGTH_INTERFACE,                 /* Size of this descriptor */
    USB_DESCRIPTOR_TYPE_INTERFACE,                   /* INTERFACE Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_STREAM_INTERFACE_INDEX, /* Index of stream interface */
    0x00U,                                           /* Index of the interface setting */
    0U,                                              /* No endpoint of stream pipe */
    USB_DEVICE_VIDEO_CC_VIDEO,                       /* CC_VIDEO */
    USB_DEVICE_VIDEO_SC_VIDEOSTREAMING,              /* SC_VIDEOSTREAMING */
    USB_DEVICE_VIDEO_VIRTUAL_CAMERA_PROTOCOL,        /* Protocol */
    0x00U,                                           /* Index of this string descriptor */

    /* VS Specific Input Header Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_VS_INTERFACE_HEADER_LENGTH, /* Size of this descriptor, in bytes: 13+(p*n) */
    USB_DESCRIPTOR_TYPE_VIDEO_CS_INTERFACE,              /* CS_INTERFACE descriptor type */
    USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_INPUT_HEADER,        /* VS_INPUT_HEADER descriptor subtype */
    USB_VIDEO_VIRTUAL_CAMERA_FORMAT_COUNT,               /* One format (p = 1U)*/
    USB_SHORT_GET_LOW(USB_VIDEO_VIRTUAL_CAMERA_VS_INTERFACE_TOTAL_LENGTH),
    USB_SHORT_GET_HIGH(USB_VIDEO_VIRTUAL_CAMERA_VS_INTERFACE_TOTAL_LENGTH),
    /* Total number of bytes returned for the class-specific VideoStreaming interface descriptors including
       this header descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_STREAM_ENDPOINT_IN | (USB_IN << 0x07U),
    /* The address of the isochronous or bulk endpoint used for video data */
    0x00U,                                                /* Dynamic Format Change unsupported */
    USB_VIDEO_VIRTUAL_CAMERA_VC_OUTPUT_TERMINAL_ID,       /* The terminal ID of the Output Terminal to which the
                                                             video endpoint of this interface is connected */
    USB_VIDEO_VIRTUAL_CAMERA_STREAM_STILL_CAPTURE_METHOD, /* Method 2U, still image capture supported */
    USB_VIDEO_VIRTUAL_CAMERA_STREAM_STILL_CAPTURE_TRIGGER_SUPPOTED,
    /* Unsupported hardware trigger */
    0x00U, /* Specifies how the host software shall respond to a hardware trigger interrupt event from this
             interface */
    0x01U, /* Size of each bmaControl(x) field */
    0x00U, /* Not used */

    /* Motion-JPEG Video Format Descriptor */
    USB_VIDEO_MJPEG_FORMAT_DESCRIPTOR_LENGTH,     /* Size of this Descriptor, in bytes: 11U */
    USB_DESCRIPTOR_TYPE_VIDEO_CS_INTERFACE,       /* CS_INTERFACE descriptor type */
    USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FORMAT_MJPEG, /* VS_FORMAT_MJPEG descriptor subtype */
    USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FORMAT_INDEX,  /* Index of this Format Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_COUNT,   /* Number of Frame Descriptors following that correspond to
                                                     this format */
    0x01U,                                        /* Specifies characteristics of this format */
    0x01U,                                        /* Optimum Frame Index */
    0x00U,                                        /* The X dimension of the picture aspect ratio */
    0x00U,                                        /* The Y dimension of the picture aspect ratio */
    0x00U,                                        /* Specifies interlace information */
    0x00U,                                        /* Not uesd */

    /* Motion-JPEG Video Frame Descriptor */
    USB_VIDEO_MJPEG_FRAME_DESCRIPTOR_LENGTH,     /* Size of this Descriptor */
    USB_DESCRIPTOR_TYPE_VIDEO_CS_INTERFACE,      /* CS_INTERFACE descriptor type */
    USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_FRAME_MJPEG, /* VS_FRAME_MJPEG descriptor subtype */
    USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INDEX,  /* First frame */
    0x00U,                                       /* D0, Only for still capture method 1U
                                                   D1, Fixed frame-rate */
    USB_SHORT_GET_LOW(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_WIDTH),
    USB_SHORT_GET_HIGH(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_WIDTH),
    /* Width */
    USB_SHORT_GET_LOW(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_HEIGHT),
    USB_SHORT_GET_HIGH(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_HEIGHT),
    /* Height */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MIN_BIT_RATE),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MIN_BIT_RATE),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MIN_BIT_RATE),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MIN_BIT_RATE),
    /* Min bit Rate */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MAX_BIT_RATE),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MAX_BIT_RATE),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MAX_BIT_RATE),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MAX_BIT_RATE),
    /* Max bit Rate */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MAX_FRAME_SIZE),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MAX_FRAME_SIZE),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MAX_FRAME_SIZE),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_MAX_FRAME_SIZE),
    /* Max Frame buffer size */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_DEFAULT_INTERVAL),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_DEFAULT_INTERVAL),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_DEFAULT_INTERVAL),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_DEFAULT_INTERVAL),
    /* Default Frame interval */
    USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_TYPE, /* frame interval type */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_30FPS),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_30FPS),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_30FPS),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_30FPS),
    /* 30fps */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_25FPS),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_25FPS),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_25FPS),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_25FPS),
    /* 25fps */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_20FPS),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_20FPS),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_20FPS),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_20FPS),
    /* 20fps */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_15FPS),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_15FPS),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_15FPS),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_15FPS),
    /* 15fps */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_10FPS),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_10FPS),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_10FPS),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_10FPS),
    /* 10fps */
    USB_LONG_GET_BYTE0(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_5FPS),
    USB_LONG_GET_BYTE1(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_5FPS),
    USB_LONG_GET_BYTE2(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_5FPS),
    USB_LONG_GET_BYTE3(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_INTERVAL_5FPS),
    /* 5fps */

    /* Still Image Frame Descriptor */
    USB_VIDEO_MJPEG_FRAME_STILL_DESCRIPTOR_LENGTH,     /* Size of this descriptor */
    USB_DESCRIPTOR_TYPE_VIDEO_CS_INTERFACE,            /* CS_INTERFACE descriptor type */
    USB_DESCRIPTOR_SUBTYPE_VIDEO_VS_STILL_IMAGE_FRAME, /* VS_STILL_IMAGE_FRAME descriptor subtype */
    0x00U,                                             /* If method 3U of still image capture is used,
                                                         this contains the address of the bulk endpoint
                                                         used for still image capture */
    0x01U,                                             /* Number of Image Size patterns of this format: n */
    USB_SHORT_GET_LOW(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_WIDTH),
    USB_SHORT_GET_HIGH(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_WIDTH),
    /* Width */
    USB_SHORT_GET_LOW(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_HEIGHT),
    USB_SHORT_GET_HIGH(USB_VIDEO_VIRTUAL_CAMERA_MJPEG_FRAME_HEIGHT),
    /* Height */
    0x00U, /* Compression of the still image in pattern */

    /* Standard VS Interface Descriptor */
    USB_DESCRIPTOR_LENGTH_INTERFACE,                 /* Size of this descriptor */
    USB_DESCRIPTOR_TYPE_INTERFACE,                   /* INTERFACE Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_STREAM_INTERFACE_INDEX, /* Index of stream interface */
    0x01U,                                           /* Index of the interface setting */
    USB_VIDEO_VIRTUAL_CAMERA_STREAM_ENDPOINT_COUNT,  /* One endpoint of stream pipe */
    USB_DEVICE_VIDEO_CC_VIDEO,                       /* CC_VIDEO */
    USB_DEVICE_VIDEO_SC_VIDEOSTREAMING,              /* SC_VIDEOSTREAMING */
    USB_DEVICE_VIDEO_VIRTUAL_CAMERA_PROTOCOL,        /* Protocol */
    0x00U,                                           /* Index of this string descriptor */

    /*Endpoint descriptor */
    USB_DESCRIPTOR_LENGTH_ENDPOINT, /* Size of this descriptor */
    USB_DESCRIPTOR_TYPE_ENDPOINT,   /* ENDPOINT Descriptor */
    USB_VIDEO_VIRTUAL_CAMERA_STREAM_ENDPOINT_IN | (USB_IN << USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_SHIFT),
    USB_ENDPOINT_ISOCHRONOUS | USB_DESCRIPTOR_ENDPOINT_ATTRIBUTE_SYNC_TYPE_ASYNC,
    USB_SHORT_GET_LOW(FS_STREAM_IN_PACKET_SIZE), USB_SHORT_GET_HIGH(FS_STREAM_IN_PACKET_SIZE),
    /* Max Packet Size */
    FS_STREAM_IN_INTERVAL, /* Interval */
};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString0[] = {
    2U + 2U, USB_DESCRIPTOR_TYPE_STRING, 0x09U, 0x04U,
};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString1[] = {
    2U + 2U * 18U, USB_DESCRIPTOR_TYPE_STRING,
    'N',           0x00U,
    'X',           0x00U,
    'P',           0x00U,
    ' ',           0x00U,
    'S',           0x00U,
    'E',           0x00U,
    'M',           0x00U,
    'I',           0x00U,
    'C',           0x00U,
    'O',           0x00U,
    'N',           0x00U,
    'D',           0x00U,
    'U',           0x00U,
    'C',           0x00U,
    'T',           0x00U,
    'O',           0x00U,
    'R',           0x00U,
    'S',           0x00U,
};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString2[] = {
    2U + 2U * 10U, USB_DESCRIPTOR_TYPE_STRING,
    'V',           0x00U,
    'I',           0x00U,
    'D',           0x00U,
    'E',           0x00U,
    'O',           0x00U,
    ' ',           0x00U,
    'D',           0x00U,
    'E',           0x00U,
    'M',           0x00U,
    'O',           0x00U,
};

USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE)
uint8_t g_UsbDeviceString3[] = {
    2U + 2U * 21U, USB_DESCRIPTOR_TYPE_STRING,
    'V',           0x00U,
    'i',           0x00U,
    'r',           0x00U,
    't',           0x00U,
    'u',           0x00U,
    'a',           0x00U,
    'l',           0x00U,
    ' ',           0x00U,
    'C',           0x00U,
    'a',           0x00U,
    'm',           0x00U,
    'e',           0x00U,
    'r',           0x00U,
    'a',           0x00U,
    ' ',           0x00U,
    'D',           0x00U,
    'e',           0x00U,
    'v',           0x00U,
    'i',           0x00U,
    'c',           0x00U,
    'e',           0x00U,
};

uint32_t g_UsbDeviceStringDescriptorLength[USB_DEVICE_STRING_COUNT] = {
    sizeof(g_UsbDeviceString0), sizeof(g_UsbDeviceString1), sizeof(g_UsbDeviceString2), sizeof(g_UsbDeviceString3),
};

uint8_t *g_UsbDeviceStringDescriptorArray[USB_DEVICE_STRING_COUNT] = {
    g_UsbDeviceString0, g_UsbDeviceString1, g_UsbDeviceString2, g_UsbDeviceString3,
};

usb_language_t g_UsbDeviceLanguage[USB_DEVICE_LANGUAGE_COUNT] = {{
    g_UsbDeviceStringDescriptorArray, g_UsbDeviceStringDescriptorLength, (uint16_t)0x0409U,
}};

usb_language_list_t g_UsbDeviceLanguageList = {
    g_UsbDeviceString0, sizeof(g_UsbDeviceString0), g_UsbDeviceLanguage, USB_DEVICE_LANGUAGE_COUNT,
};

/*******************************************************************************
 * Code
 ******************************************************************************/

/* Get descriptor request */
usb_status_t USB_DeviceGetDescriptor(usb_device_handle handle,
                                     usb_setup_struct_t *setup,
                                     uint32_t *length,
                                     uint8_t **buffer)
{
    usb_status_t error = kStatus_USB_Success;
    uint8_t descriptorType = (uint8_t)((setup->wValue & 0xFF00U) >> 8U);
    uint8_t descriptorIndex = (uint8_t)((setup->wValue & 0x00FFU));
    if (USB_REQUEST_STANDARD_GET_DESCRIPTOR != setup->bRequest)
    {
        return kStatus_USB_InvalidRequest;
    }
    switch (descriptorType)
    {
        case USB_DESCRIPTOR_TYPE_STRING:
        {
            /* Get string descriptor */
            if (0U == descriptorIndex)
            {
                *buffer = (uint8_t *)g_UsbDeviceLanguageList.languageString;
                *length = g_UsbDeviceLanguageList.stringLength;
            }
            else
            {
                uint8_t languageId = 0U;
                uint8_t languageIndex = USB_DEVICE_STRING_COUNT;

                for (; languageId < USB_DEVICE_LANGUAGE_COUNT; languageId++)
                {
                    if (setup->wIndex == g_UsbDeviceLanguageList.languageList[languageId].languageId)
                    {
                        if (descriptorIndex < USB_DEVICE_STRING_COUNT)
                        {
                            languageIndex = descriptorIndex;
                        }
                        break;
                    }
                }

                if (USB_DEVICE_STRING_COUNT == languageIndex)
                {
                    return kStatus_USB_InvalidRequest;
                }
                *buffer = (uint8_t *)g_UsbDeviceLanguageList.languageList[languageId].string[languageIndex];
                *length = g_UsbDeviceLanguageList.languageList[languageId].length[languageIndex];
            }
        }
        break;
        case USB_DESCRIPTOR_TYPE_DEVICE:
        {
            /* Get device descriptor */
            *buffer = g_UsbDeviceDescriptor;
            *length = USB_DESCRIPTOR_LENGTH_DEVICE;
        }
        break;
        case USB_DESCRIPTOR_TYPE_CONFIGURE:
        {
            /* Get configuration descriptor */
            *buffer = g_UsbDeviceConfigurationDescriptor;
            *length = USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL;
        }
        break;
        default:
            error = kStatus_USB_InvalidRequest;
            break;
    } /* End Switch */
    return error;
}

/* Set current confgiuration request */
usb_status_t USB_DeviceSetConfigure(usb_device_handle handle, uint8_t configure)
{
    if (!configure)
    {
        return kStatus_USB_Error;
    }
    g_UsbDeviceCurrentConfigure = configure;
    return USB_DeviceCallback(handle, kUSB_DeviceEventSetConfiguration, &configure);
}

/* Get current confgiuration request */
usb_status_t USB_DeviceGetConfigure(usb_device_handle handle, uint8_t *configure)
{
    *configure = g_UsbDeviceCurrentConfigure;
    return kStatus_USB_Success;
}

/* Set current alternate settting of the interface request */
usb_status_t USB_DeviceSetInterface(usb_device_handle handle, uint8_t interface, uint8_t alternateSetting)
{
    g_UsbDeviceInterface[interface] = alternateSetting;
    return USB_DeviceCallback(handle, kUSB_DeviceEventSetInterface, &interface);
}

/* Get current alternate settting of the interface request */
usb_status_t USB_DeviceGetInterface(usb_device_handle handle, uint8_t interface, uint8_t *alternateSetting)
{
    *alternateSetting = g_UsbDeviceInterface[interface];
    return kStatus_USB_Success;
}

/* Due to the difference of HS and FS descriptors, the device descriptors and configurations need to be updated to match
 * current speed.
 * As the default, the device descriptors and configurations are configured by using FS parameters for both EHCI and
 * KHCI.
 * When the EHCI is enabled, the application needs to call this fucntion to update device by using current speed.
 * The updated information includes endpoint max packet size, endpoint interval, etc. */
usb_status_t USB_DeviceSetSpeed(uint8_t speed)
{
    usb_descriptor_union_t *descriptorHead;
    usb_descriptor_union_t *descriptorTail;

    descriptorHead = (usb_descriptor_union_t *)&g_UsbDeviceConfigurationDescriptor[0];
    descriptorTail =
        (usb_descriptor_union_t *)(&g_UsbDeviceConfigurationDescriptor[USB_DESCRIPTOR_LENGTH_CONFIGURATION_ALL - 1U]);

    while (descriptorHead < descriptorTail)
    {
        if (descriptorHead->common.bDescriptorType == USB_DESCRIPTOR_TYPE_ENDPOINT)
        {
            if (USB_SPEED_HIGH == speed)
            {
                if ((USB_VIDEO_VIRTUAL_CAMERA_STREAM_ENDPOINT_IN ==
                    (descriptorHead->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)) &&
                    ((descriptorHead->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                     USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_IN))
                {
                    descriptorHead->endpoint.bInterval = HS_STREAM_IN_INTERVAL;
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(HS_STREAM_IN_PACKET_SIZE,
                                                       descriptorHead->endpoint.wMaxPacketSize);
                }
                else
                {
                    descriptorHead->endpoint.bInterval = HS_INTERRUPT_IN_INTERVAL;
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(HS_INTERRUPT_IN_PACKET_SIZE,
                                                       descriptorHead->endpoint.wMaxPacketSize);
                }
            }
            else
            {
                if ((USB_VIDEO_VIRTUAL_CAMERA_STREAM_ENDPOINT_IN ==
                    (descriptorHead->endpoint.bEndpointAddress & USB_ENDPOINT_NUMBER_MASK)) &&
                    ((descriptorHead->endpoint.bEndpointAddress & USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_MASK) ==
                     USB_DESCRIPTOR_ENDPOINT_ADDRESS_DIRECTION_IN))
                {
                    descriptorHead->endpoint.bInterval = FS_STREAM_IN_INTERVAL;
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(FS_STREAM_IN_PACKET_SIZE,
                                                       descriptorHead->endpoint.wMaxPacketSize);
                }
                else
                {
                    descriptorHead->endpoint.bInterval = FS_INTERRUPT_IN_INTERVAL;
                    USB_SHORT_TO_LITTLE_ENDIAN_ADDRESS(FS_INTERRUPT_IN_PACKET_SIZE,
                                                       descriptorHead->endpoint.wMaxPacketSize);
                }
            }
        }
        descriptorHead = (usb_descriptor_union_t *)((uint8_t *)descriptorHead + descriptorHead->common.bLength);
    }

    return kStatus_USB_Success;
}
