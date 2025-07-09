/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_dma.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the DMA Manager.

*********************************************************************************/

#ifndef __ADI_DMA_H__
#define __ADI_DMA_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#if !defined(_LANGUAGE_ASM)

/*********************************************************************

Macros for the memory usage of the DMA Manager

*********************************************************************/

#define ADI_DMA_BASE_MEMORY (12)     // base memory needed for the DMA manager (bytes)
#define ADI_DMA_CHANNEL_MEMORY (112) // additional memory needed for each DMA channel (bytes)

/*********************************************************************

Typedef for a DMA channel handle

*********************************************************************/

typedef void *ADI_DMA_MANAGER_HANDLE; // DMA manager handle
typedef void *ADI_DMA_CHANNEL_HANDLE; // DMA channel handle
typedef void *ADI_DMA_STREAM_HANDLE;  // DMA memory stream handle

/*********************************************************************

Data structure and bitfield enumerations for DMA configuration control register

*********************************************************************/

typedef enum ADI_DMA_FLOW
{
    ADI_DMA_FLOW_STOP = 0,
    ADI_DMA_FLOW_AUTOBUFFER = 1,
    ADI_DMA_FLOW_ARRAY = 4,
    ADI_DMA_FLOW_SMALL = 6,
    ADI_DMA_FLOW_LARGE = 7
} ADI_DMA_FLOW;

typedef enum ADI_DMA_NDSIZE
{
    ADI_DMA_NDSIZE_STOP = 0,
    ADI_DMA_NDSIZE_ARRAY = 7,
    ADI_DMA_NDSIZE_SMALL = 8,
    ADI_DMA_NDSIZE_LARGE = 9
} ADI_DMA_NDSIZE;

typedef enum ADI_DMA_DI_EN
{
    ADI_DMA_DI_EN_DISABLE,
    ADI_DMA_DI_EN_ENABLE
} ADI_DMA_DI_EN;

typedef enum ADI_DMA_DI_SEL
{
    ADI_DMA_DI_SEL_OUTER_LOOP,
    ADI_DMA_DI_SEL_INNER_LOOP
} ADI_DMA_DI_SEL;

typedef enum ADI_DMA_RESTART
{
    ADI_DMA_RESTART_RETAIN,
    ADI_DMA_RESTART_DISCARD
} ADI_DMA_RESTART;

typedef enum ADI_DMA_DMA2D
{
    ADI_DMA_DMA2D_LINEAR,
    ADI_DMA_DMA2D_2D
} ADI_DMA_DMA2D;

typedef enum ADI_DMA_WDSIZE
{
    ADI_DMA_WDSIZE_8BIT,
    ADI_DMA_WDSIZE_16BIT,
    ADI_DMA_WDSIZE_32BIT
} ADI_DMA_WDSIZE;

typedef enum ADI_DMA_WNR
{
    ADI_DMA_WNR_READ,
    ADI_DMA_WNR_WRITE
} ADI_DMA_WNR;

typedef enum ADI_DMA_EN
{
    ADI_DMA_EN_DISABLE,
    ADI_DMA_EN_ENABLE
} ADI_DMA_EN;

#if defined(__ECC__)
#pragma pack(2)
#elif defined(__ghs__)
#elif defined(__GNUC__)
#endif

typedef struct ADI_DMA_CONFIG_REG
{
    volatile u16 b_DMA_EN : 1;   // 0     Enabled
    volatile u16 b_WNR : 1;      // 1     Direction
    volatile u16 b_WDSIZE : 2;   // 2:3   Transfer word size
    volatile u16 b_DMA2D : 1;    // 4     DMA mode
    volatile u16 b_RESTART : 1;  // 5     Retain FIFO
    volatile u16 b_DI_SEL : 1;   // 6     Data interrupt timing select
    volatile u16 b_DI_EN : 1;    // 7     Data interrupt enabled
    volatile u16 b_NDSIZE : 4;   // 8:11  Flex descriptor size
    volatile u16 b_FLOW : 3;     // 12:14 Flow
    volatile u16 b_RESERVED : 1; // 15    Reserved
} ADI_DMA_CONFIG_REG;

#if defined(__ECC__)
#pragma pack()
#elif defined(__ghs__)
#elif defined(__GNUC__)
#endif

/*********************************************************************

Descriptor definitions

*********************************************************************/

#if defined(__ECC__)
#pragma pack(2)
#elif defined(__ghs__)
#elif defined(__GNUC__)
#endif

typedef struct ADI_DMA_DESCRIPTOR_SMALL
{                              // DMA descriptor small model
    u16 pNext;                 // next descriptor in the chain
    u16 StartAddressLow;       // lower 16 bits of the start address of the data
    u16 StartAddressHigh;      // upper 16 bits of the start address of the data
    ADI_DMA_CONFIG_REG Config; // configuration control register
    u16 XCount;                // X (column) count
    s16 XModify;               // X (column) stride
    u16 YCount;                // Y (row) count
    s16 YModify;               // Y (row) stride
    u16 CallbackFlag;          // callback flag
} ADI_DMA_DESCRIPTOR_SMALL;

typedef struct ADI_DMA_DESCRIPTOR_LARGE
{                                           // DMA descriptor large model
    struct ADI_DMA_DESCRIPTOR_LARGE *pNext; // next descriptor in the chain
    void *StartAddress;                     // start address of the data
    ADI_DMA_CONFIG_REG Config;              // configuration control register
    u16 XCount;                             // X (column) count
    s16 XModify;                            // X (column) stride
    u16 YCount;                             // Y (row) count
    s16 YModify;                            // Y (row) stride
    u16 CallbackFlag;                       // callback flag
} ADI_DMA_DESCRIPTOR_LARGE;

typedef struct ADI_DMA_DESCRIPTOR_ARRAY
{                              // DMA descriptor array model
    void *StartAddress;        // start address of the data
    ADI_DMA_CONFIG_REG Config; // configuration control register
    u16 XCount;                // X (column) count
    s16 XModify;               // X (column) stride
    u16 YCount;                // Y (row) count
    s16 YModify;               // Y (row) stride
    u16 CallbackFlag;          // callback flag
} ADI_DMA_DESCRIPTOR_ARRAY;

#if defined(__ECC__)
#pragma pack()
#elif defined(__ghs__)
#elif defined(__GNUC__)
#endif

typedef union ADI_DMA_DESCRIPTOR_UNION
{                                   // union of all descriptor types
    ADI_DMA_DESCRIPTOR_SMALL Small; // small model descriptor
    ADI_DMA_DESCRIPTOR_LARGE Large; // large model descriptor
    ADI_DMA_DESCRIPTOR_ARRAY Array; // array of descriptors
} ADI_DMA_DESCRIPTOR_UNION;

typedef ADI_DMA_DESCRIPTOR_UNION *ADI_DMA_DESCRIPTOR_HANDLE; // descriptor handle

/*********************************************************************

2D Memory copy data structures

*********************************************************************/

typedef struct ADI_DMA_2D_TRANSFER
{                       // structure to describe a 2D transfer
    void *StartAddress; // start address
    u16 XCount;         // X (column) count
    s16 XModify;        // X (column) stride
    u16 YCount;         // Y (row) count
    s16 YModify;        // Y (row) stride
} ADI_DMA_2D_TRANSFER;

/*********************************************************************

DMA data transfer modes

*********************************************************************/

typedef enum
{                                  // Data transfer mode
    ADI_DMA_MODE_UNDEFINED,        // undefined
    ADI_DMA_MODE_SINGLE,           // single straight buffer
    ADI_DMA_MODE_CIRCULAR,         // single circular buffer
    ADI_DMA_MODE_DESCRIPTOR_ARRAY, // descriptor based - array
    ADI_DMA_MODE_DESCRIPTOR_SMALL, // descriptor based - small
    ADI_DMA_MODE_DESCRIPTOR_LARGE  // descriptor based - large
} ADI_DMA_MODE;

/*********************************************************************

Macros for PMAP creation and dissection

*********************************************************************/
// macro to create PMAP ID
#define ADI_DMA_CREATE_PMAP(PMAP_FIELD, CONTROLLER_ID) \
    (((CONTROLLER_ID) << 0) |                          \
     ((PMAP_FIELD) << 16))

#define ADI_DMA_GET_PMAP_FIELD(PMAP) ((PMAP) >> 16)     // gets the pmap field value
#define ADI_DMA_GET_CONTROLLER_ID(PMAP) ((PMAP) & 0xff) // gets the controller ID

/*********************************************************************

DMA channel IDs and mapping values (processor specific)

*********************************************************************/

/********************
    Edinburgh
********************/

#if defined(__ADSP_EDINBURGH__) // settings for BF533, 532, 531

typedef enum
{                         // DMA Channel ID
    ADI_DMA_DMA0,         // DMA 0 - default channel for PPI.
    ADI_DMA_DMA1,         // DMA 1 - default channel for SPORT0 receive.
    ADI_DMA_DMA2,         // DMA 2 - default channel for SPORT0 transmit.
    ADI_DMA_DMA3,         // DMA 3 - default channel for SPORT1 receive.
    ADI_DMA_DMA4,         // DMA 4 - default channel for SPORT1 transmit
    ADI_DMA_DMA5,         // DMA 5 - default channel for SPI.
    ADI_DMA_DMA6,         // DMA 6 - default channel for UART receive.
    ADI_DMA_DMA7,         // DMA 7 - default channel for UART transmit.
    ADI_DMA_MDMA_D0,      // Memory DMA Stream 0 Destination.
    ADI_DMA_MDMA_S0,      // Memory DMA Stream 0 Source.
    ADI_DMA_MDMA_D1,      // Memory DMA Stream 1 Destination.
    ADI_DMA_MDMA_S1,      // Memory DMA Stream 1 Source.
    ADI_DMA_CHANNEL_COUNT // number of DMA channels
} ADI_DMA_CHANNEL_ID;

typedef enum
{                   // Stream IDs for memory DMA
    ADI_DMA_MDMA_0, // memory DMA stream 0
    ADI_DMA_MDMA_1, // memory DMA stream 1

    ADI_DMA_MEMORY_STREAM_COUNT // number of memory DMA streams
} ADI_DMA_STREAM_ID;

typedef enum
{                                                         // Values to use when setting/sensing mapping
    ADI_DMA_PMAP_PPI = ADI_DMA_CREATE_PMAP(0x0, 0),       // PPI
    ADI_DMA_PMAP_SPORT0_RX = ADI_DMA_CREATE_PMAP(0x1, 0), // SPORT0 RX
    ADI_DMA_PMAP_SPORT0_TX = ADI_DMA_CREATE_PMAP(0x2, 0), // SPORT0 TX
    ADI_DMA_PMAP_SPORT1_RX = ADI_DMA_CREATE_PMAP(0x3, 0), // SPORT1 RX
    ADI_DMA_PMAP_SPORT1_TX = ADI_DMA_CREATE_PMAP(0x4, 0), // SPORT1 TX
    ADI_DMA_PMAP_SPI = ADI_DMA_CREATE_PMAP(0x5, 0),       // SPI
    ADI_DMA_PMAP_UART_RX = ADI_DMA_CREATE_PMAP(0x6, 0),   // UART RX
    ADI_DMA_PMAP_UART_TX = ADI_DMA_CREATE_PMAP(0x7, 0),   // UART TX
    ADI_DMA_PMAP_UNDEFINED = ADI_DMA_CREATE_PMAP(0xf, 0)  // undefined (available for use)
} ADI_DMA_PMAP;

#endif

/********************
    Braemar
********************/

#if defined(__ADSP_BRAEMAR__) // settings for BF534, 536, 537

typedef enum
{                         // DMA Channel ID
    ADI_DMA_DMA0,         // DMA 0   - default channel for PPI.
    ADI_DMA_DMA1,         // DMA 1   - default channel for Ethernet MAC receive.
    ADI_DMA_DMA2,         // DMA 2   - default channel for Ethernet MAC transmit.
    ADI_DMA_DMA3,         // DMA 3   - default channel for SPORT0 receive.
    ADI_DMA_DMA4,         // DMA 4   - default channel for SPORT0 transmit.
    ADI_DMA_DMA5,         // DMA 5   - default channel for SPORT1 receive.
    ADI_DMA_DMA6,         // DMA 6   - default channel for SPORT1 transmit
    ADI_DMA_DMA7,         // DMA 7   - default channel for SPI.
    ADI_DMA_DMA8,         // DMA 8   - default channel for UART0 receive.
    ADI_DMA_DMA9,         // DMA 9   - default channel for UART0 transmit.
    ADI_DMA_DMA10,        // DMA 10  - default channel for UART1 receive.
    ADI_DMA_DMA11,        // DMA 11  - default channel for UART1 transmit.
    ADI_DMA_MDMA_D0,      // Memory DMA Stream 0 Destination.
    ADI_DMA_MDMA_S0,      // Memory DMA Stream 0 Source.
    ADI_DMA_MDMA_D1,      // Memory DMA Stream 1 Destination.
    ADI_DMA_MDMA_S1,      // Memory DMA Stream 1 Source.
    ADI_DMA_CHANNEL_COUNT // number of DMA channels
} ADI_DMA_CHANNEL_ID;

typedef enum
{                   // Stream IDs for memory DMA
    ADI_DMA_MDMA_0, // memory DMA stream 0
    ADI_DMA_MDMA_1, // memory DMA stream 1

    ADI_DMA_MEMORY_STREAM_COUNT // number of memory DMA streams
} ADI_DMA_STREAM_ID;

typedef enum
{                                                           // Values to use when setting/sensing mapping
    ADI_DMA_PMAP_PPI = ADI_DMA_CREATE_PMAP(0x0, 0),         // PPI
    ADI_DMA_PMAP_ETHERNET_RX = ADI_DMA_CREATE_PMAP(0x1, 0), // Ethernet MAC RX
    ADI_DMA_PMAP_ETHERNET_TX = ADI_DMA_CREATE_PMAP(0x2, 0), // Ethernet MAC TX
    ADI_DMA_PMAP_SPORT0_RX = ADI_DMA_CREATE_PMAP(0x3, 0),   // SPORT0 RX
    ADI_DMA_PMAP_SPORT0_TX = ADI_DMA_CREATE_PMAP(0x4, 0),   // SPORT0 TX
    ADI_DMA_PMAP_SPORT1_RX = ADI_DMA_CREATE_PMAP(0x5, 0),   // SPORT1 RX
    ADI_DMA_PMAP_SPORT1_TX = ADI_DMA_CREATE_PMAP(0x6, 0),   // SPORT1 TX
    ADI_DMA_PMAP_SPI = ADI_DMA_CREATE_PMAP(0x7, 0),         // SPI
    ADI_DMA_PMAP_UART0_RX = ADI_DMA_CREATE_PMAP(0x8, 0),    // UART0 RX
    ADI_DMA_PMAP_UART0_TX = ADI_DMA_CREATE_PMAP(0x9, 0),    // UART0 TX
    ADI_DMA_PMAP_UART1_RX = ADI_DMA_CREATE_PMAP(0xa, 0),    // UART1 RX
    ADI_DMA_PMAP_UART1_TX = ADI_DMA_CREATE_PMAP(0xb, 0),    // UART1 TX
    ADI_DMA_PMAP_UNDEFINED = ADI_DMA_CREATE_PMAP(0xf, 0)    // undefined (available for use)
} ADI_DMA_PMAP;

#endif

/********************
    Teton-Lite
********************/

#if defined(__ADSP_TETON__) // settings for BF561

typedef enum
{                     // DMA Channel ID
    ADI_DMA_DMA1_0,   // DMA1 Channel 0 - default channel for PPI1
    ADI_DMA_DMA1_1,   // DMA1 Channel 1 - default channel for PPI2
    ADI_DMA_DMA1_2,   // DMA1 Channel 2
    ADI_DMA_DMA1_3,   // DMA1 Channel 3
    ADI_DMA_DMA1_4,   // DMA1 Channel 4
    ADI_DMA_DMA1_5,   // DMA1 Channel 5
    ADI_DMA_DMA1_6,   // DMA1 Channel 6
    ADI_DMA_DMA1_7,   // DMA1 Channel 7
    ADI_DMA_DMA1_8,   // DMA1 Channel 8
    ADI_DMA_DMA1_9,   // DMA1 Channel 9
    ADI_DMA_DMA1_10,  // DMA1 Channel 10
    ADI_DMA_DMA1_11,  // DMA1 Channel 11
    ADI_DMA_MDMA1_D0, // DMA1 Memory DMA Stream 0 Destination.
    ADI_DMA_MDMA1_S0, // DMA1 Memory DMA Stream 0 Source.
    ADI_DMA_MDMA1_D1, // DMA1 Memory DMA Stream 1 Destination.
    ADI_DMA_MDMA1_S1, // DMA1 Memory DMA Stream 1 Source.

    ADI_DMA_DMA2_0,   // DMA2 Channel 0 - default channel for SPORT0 RX
    ADI_DMA_DMA2_1,   // DMA2 Channel 1 - default channel for SPORT0 TX
    ADI_DMA_DMA2_2,   // DMA2 Channel 2 - default channel for SPORT1 RX
    ADI_DMA_DMA2_3,   // DMA2 Channel 3 - default channel for SPORT1 TX
    ADI_DMA_DMA2_4,   // DMA2 Channel 4 - default channel for SPI
    ADI_DMA_DMA2_5,   // DMA2 Channel 5 - default channel for UART RX
    ADI_DMA_DMA2_6,   // DMA2 Channel 6 - default channel for UART TX
    ADI_DMA_DMA2_7,   // DMA2 Channel 7
    ADI_DMA_DMA2_8,   // DMA2 Channel 8
    ADI_DMA_DMA2_9,   // DMA2 Channel 9
    ADI_DMA_DMA2_10,  // DMA2 Channel 10
    ADI_DMA_DMA2_11,  // DMA2 Channel 11
    ADI_DMA_MDMA2_D0, // DMA2 Memory DMA Stream 0 Destination.
    ADI_DMA_MDMA2_S0, // DMA2 Memory DMA Stream 0 Source.
    ADI_DMA_MDMA2_D1, // DMA2 Memory DMA Stream 1 Destination.
    ADI_DMA_MDMA2_S1, // DMA2 Memory DMA Stream 1 Source.

    ADI_DMA_IMDMA_D0, // IMDMA Stream 0 Destination.
    ADI_DMA_IMDMA_S0, // IMDMA Stream 0 Source.
    ADI_DMA_IMDMA_D1, // IMDMA Stream 1 Destination.
    ADI_DMA_IMDMA_S1, // IMDMA Stream 1 Source.

    ADI_DMA_CHANNEL_COUNT // number of DMA channels
} ADI_DMA_CHANNEL_ID;

typedef enum
{                    // Stream IDs for memory DMA
    ADI_DMA_MDMA1_0, // memory DMA, controller 1, stream 0
    ADI_DMA_MDMA1_1, // memory DMA, controller 1, stream 1
    ADI_DMA_MDMA2_0, // memory DMA, controller 2, stream 0
    ADI_DMA_MDMA2_1, // memory DMA, controller 2, stream 1
    ADI_DMA_IMDMA_0, // internal memory DMA, stream 0
    ADI_DMA_IMDMA_1, // internal memory DMA, stream 1

    ADI_DMA_MEMORY_STREAM_COUNT // number of memory DMA streams
} ADI_DMA_STREAM_ID;

typedef enum
{                                                         // Values to use when setting/sensing mapping
    ADI_DMA_PMAP_PPI1 = ADI_DMA_CREATE_PMAP(0x0, 0),      // PPI 1
    ADI_DMA_PMAP_PPI2 = ADI_DMA_CREATE_PMAP(0x1, 0),      // PPI 2
    ADI_DMA_PMAP_SPORT0_RX = ADI_DMA_CREATE_PMAP(0x0, 1), // SPORT0 RX
    ADI_DMA_PMAP_SPORT0_TX = ADI_DMA_CREATE_PMAP(0x1, 1), // SPORT0 TX
    ADI_DMA_PMAP_SPORT1_RX = ADI_DMA_CREATE_PMAP(0x2, 1), // SPORT1 RX
    ADI_DMA_PMAP_SPORT1_TX = ADI_DMA_CREATE_PMAP(0x3, 1), // SPORT1 TX
    ADI_DMA_PMAP_SPI = ADI_DMA_CREATE_PMAP(0x4, 1),       // SPI
    ADI_DMA_PMAP_UART_RX = ADI_DMA_CREATE_PMAP(0x5, 1),   // UART RX
    ADI_DMA_PMAP_UART_TX = ADI_DMA_CREATE_PMAP(0x6, 1),   // UART TX
    ADI_DMA_PMAP_UNDEFINED = ADI_DMA_CREATE_PMAP(0xf, 0)  // undefined (available for use)
} ADI_DMA_PMAP;

#endif

/********************
    Stirling
********************/

#if defined(__ADSP_STIRLING__) // settings for BF538, BF539

typedef enum
{                     // DMA Channel ID
    ADI_DMA_DMA0,     // DMA0 Channel 0   - default channel for PPI
    ADI_DMA_DMA1,     // DMA0 Channel 1   - default channel for SPORT0 RX
    ADI_DMA_DMA2,     // DMA0 Channel 2   - default channel for SPORT0 TX
    ADI_DMA_DMA3,     // DMA0 Channel 3   - default channel for SPORT1 RX
    ADI_DMA_DMA4,     // DMA0 Channel 4   - default channel for SPORT1 TX
    ADI_DMA_DMA5,     // DMA0 Channel 5   - default channel for SPI0
    ADI_DMA_DMA6,     // DMA0 Channel 6   - default channel for UART0 RX
    ADI_DMA_DMA7,     // DMA0 Channel 7   - default channel for UART0 TX
    ADI_DMA_MDMA0_D0, // DMA0 Memory DMA Controller 0 Stream 0 Destination.
    ADI_DMA_MDMA0_S0, // DMA0 Memory DMA Controller 0 Stream 0 Source.
    ADI_DMA_MDMA0_D1, // DMA0 Memory DMA Controller 0 Stream 1 Destination.
    ADI_DMA_MDMA0_S1, // DMA0 Memory DMA Controller 0 Stream 1 Source.

    ADI_DMA_DMA8,     // DMA1 Channel 8   - default channel for SPORT2 RX
    ADI_DMA_DMA9,     // DMA1 Channel 9   - default channel for SPORT2 TX
    ADI_DMA_DMA10,    // DMA1 Channel 10  - default channel for SPORT3 RX
    ADI_DMA_DMA11,    // DMA1 Channel 11  - default channel for SPORT3 TX
    ADI_DMA_DMA12,    // DMA1 Channel 12
    ADI_DMA_DMA13,    // DMA1 Channel 13
    ADI_DMA_DMA14,    // DMA1 Channel 14  - default channel for SPI1
    ADI_DMA_DMA15,    // DMA1 Channel 15  - default channel for SPI2
    ADI_DMA_DMA16,    // DMA1 Channel 16  - default channel for UART1 RX
    ADI_DMA_DMA17,    // DMA1 Channel 17  - default channel for UART1 TX
    ADI_DMA_DMA18,    // DMA1 Channel 18  - default channel for UART2 RX
    ADI_DMA_DMA19,    // DMA1 Channel 19  - default channel for UART2 TX
    ADI_DMA_MDMA1_D0, // DMA1 Memory DMA Controller 1 Stream 0 Destination.
    ADI_DMA_MDMA1_S0, // DMA1 Memory DMA Controller 1 Stream 0 Source.
    ADI_DMA_MDMA1_D1, // DMA1 Memory DMA Controller 1 Stream 1 Destination.
    ADI_DMA_MDMA1_S1, // DMA1 Memory DMA Controller 1 Stream 1 Source.

    ADI_DMA_CHANNEL_COUNT // number of DMA channels
} ADI_DMA_CHANNEL_ID;

typedef enum
{                    // Stream IDs for memory DMA
    ADI_DMA_MDMA0_0, // memory DMA, controller 0, stream 0
    ADI_DMA_MDMA0_1, // memory DMA, controller 0, stream 1
    ADI_DMA_MDMA1_0, // memory DMA, controller 1, stream 0
    ADI_DMA_MDMA1_1, // memory DMA, controller 1, stream 1

    ADI_DMA_MEMORY_STREAM_COUNT // number of memory DMA streams
} ADI_DMA_STREAM_ID;

typedef enum
{                                                         // Values to use when setting/sensing mapping
    ADI_DMA_PMAP_PPI = ADI_DMA_CREATE_PMAP(0x0, 0),       // PPI
    ADI_DMA_PMAP_SPORT0_RX = ADI_DMA_CREATE_PMAP(0x1, 0), // SPORT0 RX
    ADI_DMA_PMAP_SPORT0_TX = ADI_DMA_CREATE_PMAP(0x2, 0), // SPORT0 TX
    ADI_DMA_PMAP_SPORT1_RX = ADI_DMA_CREATE_PMAP(0x3, 0), // SPORT1 RX
    ADI_DMA_PMAP_SPORT1_TX = ADI_DMA_CREATE_PMAP(0x4, 0), // SPORT1 TX
    ADI_DMA_PMAP_SPI0 = ADI_DMA_CREATE_PMAP(0x5, 0),      // SPI0
    ADI_DMA_PMAP_UART0_RX = ADI_DMA_CREATE_PMAP(0x6, 0),  // UART0 RX
    ADI_DMA_PMAP_UART0_TX = ADI_DMA_CREATE_PMAP(0x7, 0),  // UART0 TX
    ADI_DMA_PMAP_SPORT2_RX = ADI_DMA_CREATE_PMAP(0x0, 1), // SPORT2 RX
    ADI_DMA_PMAP_SPORT2_TX = ADI_DMA_CREATE_PMAP(0x1, 1), // SPORT2 TX
    ADI_DMA_PMAP_SPORT3_RX = ADI_DMA_CREATE_PMAP(0x2, 1), // SPORT3 RX
    ADI_DMA_PMAP_SPORT3_TX = ADI_DMA_CREATE_PMAP(0x3, 1), // SPORT3 TX
    ADI_DMA_PMAP_SPI1 = ADI_DMA_CREATE_PMAP(0x6, 1),      // SPI1
    ADI_DMA_PMAP_SPI2 = ADI_DMA_CREATE_PMAP(0x7, 1),      // SPI2
    ADI_DMA_PMAP_UART1_RX = ADI_DMA_CREATE_PMAP(0x8, 1),  // UART1 RX
    ADI_DMA_PMAP_UART1_TX = ADI_DMA_CREATE_PMAP(0x9, 1),  // UART1 TX
    ADI_DMA_PMAP_UART2_RX = ADI_DMA_CREATE_PMAP(0xa, 1),  // UART2 RX
    ADI_DMA_PMAP_UART2_TX = ADI_DMA_CREATE_PMAP(0xb, 1),  // UART2 TX
    ADI_DMA_PMAP_UNDEFINED = ADI_DMA_CREATE_PMAP(0xf, 0)  // undefined (available for use)
} ADI_DMA_PMAP;

#endif

/********************
    Moab
********************/

#if defined(__ADSP_MOAB__) // settings for BF54x

typedef enum
{                     // DMA Channel ID
    ADI_DMA_DMA0,     // DMA0 Channel 0   - default channel for SPORT0 RX
    ADI_DMA_DMA1,     // DMA0 Channel 1   - default channel for SPORT0 TX
    ADI_DMA_DMA2,     // DMA0 Channel 2   - default channel for SPORT1 RX
    ADI_DMA_DMA3,     // DMA0 Channel 3   - default channel for SPORT1 TX
    ADI_DMA_DMA4,     // DMA0 Channel 4   - default channel for SPI0
    ADI_DMA_DMA5,     // DMA0 Channel 5   - default channel for SPI1
    ADI_DMA_DMA6,     // DMA0 Channel 6   - default channel for UART0 RX
    ADI_DMA_DMA7,     // DMA0 Channel 7   - default channel for UART0 TX
    ADI_DMA_DMA8,     // DMA0 Channel 8   - default channel for UART1 RX
    ADI_DMA_DMA9,     // DMA0 Channel 9   - default channel for UART1 TX
    ADI_DMA_DMA10,    // DMA0 Channel 10  - default channel for ATAPI RX
    ADI_DMA_DMA11,    // DMA0 Channel 11  - default channel for ATAPI TX
    ADI_DMA_MDMA0_D0, // DMA0 Memory DMA Controller 0 Stream 0 Destination.
    ADI_DMA_MDMA0_S0, // DMA0 Memory DMA Controller 0 Stream 0 Source.
    ADI_DMA_MDMA0_D1, // DMA0 Memory DMA Controller 0 Stream 1 Destination.
    ADI_DMA_MDMA0_S1, // DMA0 Memory DMA Controller 0 Stream 1 Source.
    ADI_DMA_DMA12,    // DMA1 Channel 12  - default channel for EPPI0
    ADI_DMA_DMA13,    // DMA1 Channel 13  - default channel for EPPI1
    ADI_DMA_DMA14,    // DMA1 Channel 14  - default channel for EPPI2/Host DMA
    ADI_DMA_DMA15,    // DMA1 Channel 15  - default channel for PIXC image (read from memory)
    ADI_DMA_DMA16,    // DMA1 Channel 16  - default channel for PIXC overlay (read from memory)
    ADI_DMA_DMA17,    // DMA1 Channel 17  - default channel for PIXC output (write to memory)
    ADI_DMA_DMA18,    // DMA1 Channel 18  - default channel for SPORT2 RX
    ADI_DMA_DMA19,    // DMA1 Channel 19  - default channel for SPORT2 TX
    ADI_DMA_DMA20,    // DMA1 Channel 20  - default channel for SPORT3 RX
    ADI_DMA_DMA21,    // DMA1 Channel 21  - default channel for SPORT3 TX
    ADI_DMA_DMA22,    // DMA1 Channel 22  - default channel for SDH/NFC
    ADI_DMA_DMA23,    // DMA1 Channel 23  - default channel for SPI2
    ADI_DMA_MDMA1_D0, // DMA1 Memory DMA Controller 1 Stream 0 Destination.
    ADI_DMA_MDMA1_S0, // DMA1 Memory DMA Controller 1 Stream 0 Source.
    ADI_DMA_MDMA1_D1, // DMA1 Memory DMA Controller 1 Stream 1 Destination.
    ADI_DMA_MDMA1_S1, // DMA1 Memory DMA Controller 1 Stream 1 Source.

    ADI_DMA_CHANNEL_COUNT // number of DMA channels
} ADI_DMA_CHANNEL_ID;

typedef enum
{                    // Stream IDs for memory DMA
    ADI_DMA_MDMA0_0, // memory DMA, controller 0, stream 0
    ADI_DMA_MDMA0_1, // memory DMA, controller 0, stream 1
    ADI_DMA_MDMA1_0, // memory DMA, controller 1, stream 0
    ADI_DMA_MDMA1_1, // memory DMA, controller 1, stream 1

    ADI_DMA_MEMORY_STREAM_COUNT // number of memory DMA streams
} ADI_DMA_STREAM_ID;

typedef enum
{                                                            // Values to use when setting/sensing mapping
    ADI_DMA_PMAP_SPORT0_RX = ADI_DMA_CREATE_PMAP(0x0, 0),    // SPORT0 RX
    ADI_DMA_PMAP_SPORT0_TX = ADI_DMA_CREATE_PMAP(0x1, 0),    // SPORT0 TX
    ADI_DMA_PMAP_SPORT1_RX = ADI_DMA_CREATE_PMAP(0x2, 0),    // SPORT1 RX
    ADI_DMA_PMAP_SPORT1_TX = ADI_DMA_CREATE_PMAP(0x3, 0),    // SPORT1 TX
    ADI_DMA_PMAP_SPI0 = ADI_DMA_CREATE_PMAP(0x4, 0),         // SPI0
    ADI_DMA_PMAP_SPI1 = ADI_DMA_CREATE_PMAP(0x5, 0),         // SPI1
    ADI_DMA_PMAP_UART0_RX = ADI_DMA_CREATE_PMAP(0x6, 0),     // UART0 RX
    ADI_DMA_PMAP_UART0_TX = ADI_DMA_CREATE_PMAP(0x7, 0),     // UART0 TX
    ADI_DMA_PMAP_UART1_RX = ADI_DMA_CREATE_PMAP(0x8, 0),     // UART1 RX
    ADI_DMA_PMAP_UART1_TX = ADI_DMA_CREATE_PMAP(0x9, 0),     // UART1 TX
    ADI_DMA_PMAP_ATAPI_RX = ADI_DMA_CREATE_PMAP(0xa, 0),     // ATAPI RX
    ADI_DMA_PMAP_ATAPI_TX = ADI_DMA_CREATE_PMAP(0xb, 0),     // ATAPI TX
    ADI_DMA_PMAP_EPPI0 = ADI_DMA_CREATE_PMAP(0x0, 1),        // EPPI0
    ADI_DMA_PMAP_EPPI1 = ADI_DMA_CREATE_PMAP(0x1, 1),        // EPPI1
    ADI_DMA_PMAP_EPPI2_HOST = ADI_DMA_CREATE_PMAP(0x2, 1),   // EPPI2/Host DMA
    ADI_DMA_PMAP_PIXC_IMAGE = ADI_DMA_CREATE_PMAP(0x3, 1),   // PIXC image
    ADI_DMA_PMAP_PIXC_OVERLAY = ADI_DMA_CREATE_PMAP(0x4, 1), // PIXC overlay
    ADI_DMA_PMAP_PIXC_OUTPUT = ADI_DMA_CREATE_PMAP(0x5, 1),  // PIXC output
    ADI_DMA_PMAP_SPORT2_RX = ADI_DMA_CREATE_PMAP(0x6, 1),    // SPORT2 RX
    ADI_DMA_PMAP_SPORT2_TX = ADI_DMA_CREATE_PMAP(0x7, 1),    // SPORT2 TX
    ADI_DMA_PMAP_SPORT3_RX = ADI_DMA_CREATE_PMAP(0x8, 1),    // SPORT3 RX
    ADI_DMA_PMAP_SPORT3_TX = ADI_DMA_CREATE_PMAP(0x9, 1),    // SPORT3 TX
    ADI_DMA_PMAP_SDH_NFC = ADI_DMA_CREATE_PMAP(0xa, 1),      // SDH/NFX
    ADI_DMA_PMAP_SPI2 = ADI_DMA_CREATE_PMAP(0xb, 1),         // SPI2
    ADI_DMA_PMAP_UART2_RX = ADI_DMA_CREATE_PMAP(0xc, 1),     // UART2 RX
    ADI_DMA_PMAP_UART2_TX = ADI_DMA_CREATE_PMAP(0xd, 1),     // UART2 TX
    ADI_DMA_PMAP_UART3_RX = ADI_DMA_CREATE_PMAP(0xe, 1),     // UART3 RX
    ADI_DMA_PMAP_UART3_TX = ADI_DMA_CREATE_PMAP(0xf, 1),     // UART3 TX
    ADI_DMA_PMAP_UNDEFINED = ADI_DMA_CREATE_PMAP(0xf, 0)     // undefined (available for use)
} ADI_DMA_PMAP;

#endif

/********************
    Kookaburra/Mockingbird
********************/

#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) // settings for BF522, BF523, BF524, 525, BF526, 527

typedef enum
{                         // DMA Channel ID
    ADI_DMA_DMA0,         // DMA 0   - default channel for PPI.
    ADI_DMA_DMA1,         // DMA 1   - default channel for Ethernet MAC receive.
    ADI_DMA_DMA2,         // DMA 2   - default channel for Ethernet MAC transmit.
    ADI_DMA_DMA3,         // DMA 3   - default channel for SPORT0 receive.
    ADI_DMA_DMA4,         // DMA 4   - default channel for SPORT0 transmit.
    ADI_DMA_DMA5,         // DMA 5   - default channel for SPORT1 receive.
    ADI_DMA_DMA6,         // DMA 6   - default channel for SPORT1 transmit
    ADI_DMA_DMA7,         // DMA 7   - default channel for SPI.
    ADI_DMA_DMA8,         // DMA 8   - default channel for UART0 receive.
    ADI_DMA_DMA9,         // DMA 9   - default channel for UART0 transmit.
    ADI_DMA_DMA10,        // DMA 10  - default channel for UART1 receive.
    ADI_DMA_DMA11,        // DMA 11  - default channel for UART1 transmit.
    ADI_DMA_MDMA_D0,      // Memory DMA Stream 0 Destination.
    ADI_DMA_MDMA_S0,      // Memory DMA Stream 0 Source.
    ADI_DMA_MDMA_D1,      // Memory DMA Stream 1 Destination.
    ADI_DMA_MDMA_S1,      // Memory DMA Stream 1 Source.
    ADI_DMA_CHANNEL_COUNT // number of DMA channels
} ADI_DMA_CHANNEL_ID;

typedef enum
{                   // Stream IDs for memory DMA
    ADI_DMA_MDMA_0, // memory DMA stream 0
    ADI_DMA_MDMA_1, // memory DMA stream 1

    ADI_DMA_MEMORY_STREAM_COUNT // number of memory DMA streams
} ADI_DMA_STREAM_ID;

typedef enum
{                                                         // Values to use when setting/sensing mapping
    ADI_DMA_PMAP_PPI = ADI_DMA_CREATE_PMAP(0x0, 0),       // PPI
    ADI_DMA_PMAP_MAC_RX = ADI_DMA_CREATE_PMAP(0x1, 0),    // Ethernet MAC RX
    ADI_DMA_PMAP_MAC_TX = ADI_DMA_CREATE_PMAP(0x2, 0),    // Ethernet MAC TX
    ADI_DMA_PMAP_SPORT0_RX = ADI_DMA_CREATE_PMAP(0x3, 0), // SPORT0 RX
    ADI_DMA_PMAP_SPORT0_TX = ADI_DMA_CREATE_PMAP(0x4, 0), // SPORT0 TX
    ADI_DMA_PMAP_SPORT1_RX = ADI_DMA_CREATE_PMAP(0x5, 0), // SPORT1 RX
    ADI_DMA_PMAP_SPORT1_TX = ADI_DMA_CREATE_PMAP(0x6, 0), // SPORT1 TX
    ADI_DMA_PMAP_SPI = ADI_DMA_CREATE_PMAP(0x7, 0),       // SPI
    ADI_DMA_PMAP_UART0_RX = ADI_DMA_CREATE_PMAP(0x8, 0),  // UART0 RX
    ADI_DMA_PMAP_UART0_TX = ADI_DMA_CREATE_PMAP(0x9, 0),  // UART0 TX
    ADI_DMA_PMAP_UART1_RX = ADI_DMA_CREATE_PMAP(0xa, 0),  // UART1 RX
    ADI_DMA_PMAP_UART1_TX = ADI_DMA_CREATE_PMAP(0xb, 0),  // UART1 TX
    ADI_DMA_PMAP_UNDEFINED = ADI_DMA_CREATE_PMAP(0xf, 0)  // undefined (available for use)
} ADI_DMA_PMAP;

#endif // Kookaburra/Mockingbird

/********************
    Brodie
********************/

#if defined(__ADSP_BRODIE__) // settings for BF512, BF514, BF516

typedef enum
{                         // DMA Channel ID
    ADI_DMA_DMA0,         // DMA 0   - default channel for PPI.
    ADI_DMA_DMA1,         // DMA 1   - default channel for Ethernet MAC receive.
    ADI_DMA_DMA2,         // DMA 2   - default channel for Ethernet MAC transmit.
    ADI_DMA_DMA3,         // DMA 3   - default channel for SPORT0 receive.
    ADI_DMA_DMA4,         // DMA 4   - default channel for SPORT0 transmit/RSI
    ADI_DMA_DMA5,         // DMA 5   - default channel for SPORT1 recieve/ SPI1 Transmit/Receive.
    ADI_DMA_DMA6,         // DMA 6   - default channel for SPORT1 transmit
    ADI_DMA_DMA7,         // DMA 7   - default channel for SPI0 Transmit/Receive.
    ADI_DMA_DMA8,         // DMA 8   - default channel for UART0 receive.
    ADI_DMA_DMA9,         // DMA 9   - default channel for UART0 transmit.
    ADI_DMA_DMA10,        // DMA 10  - default channel for UART1 receive.
    ADI_DMA_DMA11,        // DMA 11  - default channel for UART1 transmit.
    ADI_DMA_MDMA_D0,      // Memory DMA Stream 0 Destination.
    ADI_DMA_MDMA_S0,      // Memory DMA Stream 0 Source.
    ADI_DMA_MDMA_D1,      // Memory DMA Stream 1 Destination
    ADI_DMA_MDMA_S1,      // Memory DMA Stream 1 Source.
    ADI_DMA_CHANNEL_COUNT // number of DMA channels
} ADI_DMA_CHANNEL_ID;

typedef enum
{                   // Stream IDs for memory DMA
    ADI_DMA_MDMA_0, // memory DMA stream 0
    ADI_DMA_MDMA_1, // memory DMA stream 1

    ADI_DMA_MEMORY_STREAM_COUNT // number of memory DMA streams
} ADI_DMA_STREAM_ID;

typedef enum
{                                                                  // Values to use when setting/sensing mapping
    ADI_DMA_PMAP_PPI = ADI_DMA_CREATE_PMAP(0x0, 0),                // PPI
    ADI_DMA_PMAP_MAC_RX = ADI_DMA_CREATE_PMAP(0x1, 0),             // Ethernet MAC RX
    ADI_DMA_PMAP_MAC_TX = ADI_DMA_CREATE_PMAP(0x2, 0),             // Ethernet MAC TX
    ADI_DMA_PMAP_SPORT0_RX = ADI_DMA_CREATE_PMAP(0x3, 0),          // SPORT0 RX
    ADI_DMA_PMAP_SPORT0_TX_AND_RSI = ADI_DMA_CREATE_PMAP(0x4, 0),  // SPORT0 TX and RSI
    ADI_DMA_PMAP_SPORT1_RX_AND_SPI1 = ADI_DMA_CREATE_PMAP(0x5, 0), // SPORT1 RX and SPI1
    ADI_DMA_PMAP_SPORT1_TX = ADI_DMA_CREATE_PMAP(0x6, 0),          // SPORT1 TX
    ADI_DMA_PMAP_SPI0 = ADI_DMA_CREATE_PMAP(0x7, 0),               // SPI0
    ADI_DMA_PMAP_UART0_RX = ADI_DMA_CREATE_PMAP(0x8, 0),           // UART0 RX
    ADI_DMA_PMAP_UART0_TX = ADI_DMA_CREATE_PMAP(0x9, 0),           // UART0 TX
    ADI_DMA_PMAP_UART1_RX = ADI_DMA_CREATE_PMAP(0xa, 0),           // UART1 RX
    ADI_DMA_PMAP_UART1_TX = ADI_DMA_CREATE_PMAP(0xb, 0),           // UART1 TX
    ADI_DMA_PMAP_UNDEFINED = ADI_DMA_CREATE_PMAP(0xf, 0)           // undefined (available for use)
} ADI_DMA_PMAP;

#endif // Brodie

/********************
    Moy (ADSP-BF50x)
********************/

#if defined(__ADSP_MOY__) /* Settings for BF504, BF504F, BF506F */

typedef enum /* DMA Channel IDs */
{
    ADI_DMA_DMA0,    /* DMA 0   - default channel for PPI Transmit/Receive */
    ADI_DMA_DMA1,    /* DMA 1   - default channel for RSI Transmit/Receive */
    ADI_DMA_DMA2,    /* DMA 2   - default channel for SPORT0 Receive */
    ADI_DMA_DMA3,    /* DMA 3   - default channel for SPORT0 Transmit */
    ADI_DMA_DMA4,    /* DMA 4   - default channel for SPORT  Recieve */
    ADI_DMA_DMA5,    /* DMA 5   - default channel for SPORT1 Transmit */
    ADI_DMA_DMA6,    /* DMA 6   - default channel for SPI0 Transmit/Receive */
    ADI_DMA_DMA7,    /* DMA 7   - default channel for SPI1 Transmit/Receive */
    ADI_DMA_DMA8,    /* DMA 8   - default channel for UART0 Receive */
    ADI_DMA_DMA9,    /* DMA 9   - default channel for UART0 Transmit */
    ADI_DMA_DMA10,   /* DMA 10  - default channel for UART1 Receive */
    ADI_DMA_DMA11,   /* DMA 11  - default channel for UART1 Transmit */
    ADI_DMA_MDMA_D0, /* Memory DMA Stream 0 Destination */
    ADI_DMA_MDMA_S0, /* Memory DMA Stream 0 Source */
    ADI_DMA_MDMA_D1, /* Memory DMA Stream 1 Destination */
    ADI_DMA_MDMA_S1, /* Memory DMA Stream 1 Source */

    ADI_DMA_CHANNEL_COUNT /* Number of DMA channels */

} ADI_DMA_CHANNEL_ID;

typedef enum
{                 /* Stream IDs for Memory DMA */
  ADI_DMA_MDMA_0, /* Memory DMA stream 0 */
  ADI_DMA_MDMA_1, /* Memory DMA stream 1 */

  ADI_DMA_MEMORY_STREAM_COUNT /* Number of Memory DMA streams */

} ADI_DMA_STREAM_ID;

typedef enum /* Values to use when setting/sensing mapping */
{
    ADI_DMA_PMAP_PPI = ADI_DMA_CREATE_PMAP(0x0, 0),       /* PPI */
    ADI_DMA_PMAP_RSI = ADI_DMA_CREATE_PMAP(0x1, 0),       /* RSI */
    ADI_DMA_PMAP_SPORT0_RX = ADI_DMA_CREATE_PMAP(0x2, 0), /* SPORT0 RX */
    ADI_DMA_PMAP_SPORT0_TX = ADI_DMA_CREATE_PMAP(0x3, 0), /* SPORT0 TX */
    ADI_DMA_PMAP_SPORT1_RX = ADI_DMA_CREATE_PMAP(0x4, 0), /* SPORT1 RX */
    ADI_DMA_PMAP_SPORT1_TX = ADI_DMA_CREATE_PMAP(0x5, 0), /* SPORT1 TX */
    ADI_DMA_PMAP_SPI0 = ADI_DMA_CREATE_PMAP(0x6, 0),      /* SPI0 */
    ADI_DMA_PMAP_SPI1 = ADI_DMA_CREATE_PMAP(0x7, 0),      /* SPI1 */
    ADI_DMA_PMAP_UART0_RX = ADI_DMA_CREATE_PMAP(0x8, 0),  /* UART0 RX */
    ADI_DMA_PMAP_UART0_TX = ADI_DMA_CREATE_PMAP(0x9, 0),  /* UART0 TX */
    ADI_DMA_PMAP_UART1_RX = ADI_DMA_CREATE_PMAP(0xa, 0),  /* UART1 RX */
    ADI_DMA_PMAP_UART1_TX = ADI_DMA_CREATE_PMAP(0xb, 0),  /* UART1 TX */

    ADI_DMA_PMAP_UNDEFINED = ADI_DMA_CREATE_PMAP(0xf, 0) /* undefined (available for use) */

} ADI_DMA_PMAP;

#endif /* Moy */

/********************
    Delta (ADSP-BF59x)
********************/

#if defined(__ADSP_DELTA__) /* Settings for BF59x */

typedef enum /* DMA Channel IDs */
{
    ADI_DMA_DMA0,    /* DMA 0   - default channel for PPI Transmit/Receive */
    ADI_DMA_DMA1,    /* DMA 1   - default channel for SPORT0 Receive */
    ADI_DMA_DMA2,    /* DMA 2   - default channel for SPORT0 Transmit */
    ADI_DMA_DMA3,    /* DMA 3   - default channel for SPORT1  Recieve */
    ADI_DMA_DMA4,    /* DMA 4   - default channel for SPORT1 Transmit */
    ADI_DMA_DMA5,    /* DMA 5   - default channel for SPI0 Transmit/Receive */
    ADI_DMA_DMA6,    /* DMA 6   - default channel for SPI1 Transmit/Receive */
    ADI_DMA_DMA7,    /* DMA 7   - default channel for UART0 Receive */
    ADI_DMA_DMA8,    /* DMA 8   - default channel for UART0 Transmit */
    ADI_DMA_MDMA_D0, /* Memory DMA Stream 0 Destination */
    ADI_DMA_MDMA_S0, /* Memory DMA Stream 0 Source */
    ADI_DMA_MDMA_D1, /* Memory DMA Stream 1 Destination */
    ADI_DMA_MDMA_S1, /* Memory DMA Stream 1 Source */

    ADI_DMA_CHANNEL_COUNT /* Number of DMA channels */

} ADI_DMA_CHANNEL_ID;

typedef enum
{                 /* Stream IDs for Memory DMA */
  ADI_DMA_MDMA_0, /* Memory DMA stream 0 */
  ADI_DMA_MDMA_1, /* Memory DMA stream 1 */

  ADI_DMA_MEMORY_STREAM_COUNT /* Number of Memory DMA streams */

} ADI_DMA_STREAM_ID;

typedef enum /* Values to use when setting/sensing mapping */
{
    ADI_DMA_PMAP_PPI = ADI_DMA_CREATE_PMAP(0x0, 0),       /* PPI */
    ADI_DMA_PMAP_SPORT0_RX = ADI_DMA_CREATE_PMAP(0x1, 0), /* SPORT0 RX */
    ADI_DMA_PMAP_SPORT0_TX = ADI_DMA_CREATE_PMAP(0x2, 0), /* SPORT0 TX */
    ADI_DMA_PMAP_SPORT1_RX = ADI_DMA_CREATE_PMAP(0x3, 0), /* SPORT1 RX */
    ADI_DMA_PMAP_SPORT1_TX = ADI_DMA_CREATE_PMAP(0x4, 0), /* SPORT1 TX */
    ADI_DMA_PMAP_SPI0 = ADI_DMA_CREATE_PMAP(0x5, 0),      /* SPI0 */
    ADI_DMA_PMAP_SPI1 = ADI_DMA_CREATE_PMAP(0x6, 0),      /* SPI1 */
    ADI_DMA_PMAP_UART0_RX = ADI_DMA_CREATE_PMAP(0x7, 0),  /* UART0 RX */
    ADI_DMA_PMAP_UART0_TX = ADI_DMA_CREATE_PMAP(0x8, 0),  /* UART0 TX */

    ADI_DMA_PMAP_UNDEFINED = ADI_DMA_CREATE_PMAP(0xf, 0) /* undefined (available for use) */

} ADI_DMA_PMAP;

#endif /* Delta */

/*********************************************************************

DMA control commands

*********************************************************************/

typedef enum ADI_DMA_CMD
{                                                  // DMA command IDs
    ADI_DMA_CMD_START = ADI_DMA_ENUMERATION_START, // starting point

    ADI_DMA_CMD_END,                 // end of table                             (Value = NULL)
    ADI_DMA_CMD_PAIR,                // single command pair being passed         (Value = ADI_DMA_CMD_VALUE_PAIR *)
    ADI_DMA_CMD_TABLE,               // table of command pairs being passed      (Value = ADI_DMA_CMD_VALUE_PAIR *)
    ADI_DMA_CMD_SET_LOOPBACK,        // enable/disable loopback                  (Value = TRUE/FALSE)
    ADI_DMA_CMD_SET_STREAMING,       // enable/disable streaming                 (Value = TRUE/FALSE)
    ADI_DMA_CMD_SET_DATAFLOW,        // enable/disable dataflow                  (Value = TRUE/FALSE)
    ADI_DMA_CMD_FLUSH,               // flush channel of all buffers             (Value = NULL)
    ADI_DMA_CMD_GET_TRANSFER_STATUS, // gets the transfer status                 (Value = TRUE - in progress/FALSE - not in progress)
    ADI_DMA_CMD_SET_TC,              // sets a traffic control parameter         (Value = ADI_DMA_TC_SET *)
    ADI_DMA_CMD_GET_TC,              // gets a traffic control parameter         (Value = ADI_DMA_TC_GET *)
    ADI_DMA_CMD_GET_CURRENT_ADDRESS  // gets DMA current address register value  (Value = u32 *)
} ADI_DMA_CMD;

typedef struct ADI_DMA_CMD_VALUE_PAIR
{                          // DMA command value pair
    ADI_DMA_CMD CommandID; // command ID
    void *Value;           // parameter
} ADI_DMA_CMD_VALUE_PAIR;

typedef enum ADI_DMA_TC_PARAMETER
{                   // DMA traffic control parameter
    ADI_DMA_TC_DCB, // DMA core bus
    ADI_DMA_TC_DEB, // DMA access bus
    ADI_DMA_TC_DAB, // DMA external bus
    ADI_DMA_TC_MDMA // MDMA round robin
} ADI_DMA_TC_PARAMETER;

typedef struct ADI_DMA_TC_SET
{                                     // structure for setting a DMA traffic control parameter
    ADI_DMA_TC_PARAMETER ParameterID; // parameter to set or sense
    u16 ControllerID;                 // DMA controller ID (first controller starts at 0)
    u16 Value;                        // value to set parameter to
} ADI_DMA_TC_SET;

typedef struct ADI_DMA_TC_GET
{                                     // structure for getting a DMA traffic control parameter
    ADI_DMA_TC_PARAMETER ParameterID; // parameter to set or sense
    u16 ControllerID;                 // DMA controller ID (first controller starts at 0)
    u16 *pValue;                      // location where parameter value will be stored
} ADI_DMA_TC_GET;

/*********************************************************************

DMA events

*********************************************************************/

typedef enum
{                                                    // DMA events
    ADI_DMA_EVENT_START = ADI_DMA_ENUMERATION_START, // 0x30000 - starting point

    ADI_DMA_EVENT_DESCRIPTOR_PROCESSED, // 0x30001 - descriptor processed                     (pArg = pointer to descriptor)
    ADI_DMA_EVENT_INNER_LOOP_PROCESSED, // 0x30002 - inner loop of circular buffer processed  (pArg = circular buffer start address)
    ADI_DMA_EVENT_OUTER_LOOP_PROCESSED, // 0x30003 - outer loop of circular buffer processed  (pArg = circular buffer start address)
    ADI_DMA_EVENT_ERROR_INTERRUPT       // 0x30004 - DMA error interrupt asserted             (pArg = NULL)
} ADI_DMA_EVENT;

/*********************************************************************

DMA API return codes

*********************************************************************/

typedef enum
{                               // DMA return codes
    ADI_DMA_RESULT_SUCCESS = 0, // generic success
    ADI_DMA_RESULT_FAILED = 1,  // generic failure

    ADI_DMA_RESULT_START = ADI_DMA_ENUMERATION_START, // 0x30000 - starting point

    ADI_DMA_RESULT_NOT_SUPPORTED,                  // 0x30001 - not supported
    ADI_DMA_RESULT_IN_USE,                         // 0x30002 - resource is already in use
    ADI_DMA_RESULT_ALREADY_RUNNING,                // 0x30003 - DMA is already running
    ADI_DMA_RESULT_NOT_MAPPED,                     // 0x30004 - peripheral is not mapped to a channel
    ADI_DMA_RESULT_BAD_HANDLE,                     // 0x30005 - bad channel handle
    ADI_DMA_RESULT_BAD_DESCRIPTOR,                 // 0x30006 - bad descriptor
    ADI_DMA_RESULT_BAD_MODE,                       // 0x30007 - bad channel mode
    ADI_DMA_RESULT_BAD_CHANNEL_ID,                 // 0x30008 - no such channel ID
    ADI_DMA_RESULT_BAD_MEMORY_STREAM_ID,           // 0x30009 - no such memory stream ID
    ADI_DMA_RESULT_BAD_PERIPHERAL,                 // 0x3000a - bad peripheral value
    ADI_DMA_RESULT_NO_BUFFER,                      // 0x3000b - channel has no buffer
    ADI_DMA_RESULT_ALL_IN_USE,                     // 0x3000c - no free channel memory structures are available
    ADI_DMA_RESULT_BAD_COMMAND,                    // 0x3000d - invalid command item
    ADI_DMA_RESULT_BAD_DATA_SIZE,                  // 0x3000e - memory DMA source and destination conflict
    ADI_DMA_RESULT_BAD_DATA_WIDTH,                 // 0x3000f - data element width is not valid
    ADI_DMA_RESULT_NO_MEMORY,                      // 0x30010 - cannot allocate memory to channel object
    ADI_DMA_RESULT_CANT_HOOK_INTERRUPT,            // 0x30011 - can't hook an interrupt
    ADI_DMA_RESULT_CANT_UNHOOK_INTERRUPT,          // 0x30012 - can't unhook an interrupt
    ADI_DMA_RESULT_INVALID_SEQUENCE,               // 0x30013 - invalid programming sequence
    ADI_DMA_RESULT_BAD_CONFIG_REG,                 // 0x30014 - bad configuration register value
    ADI_DMA_RESULT_ALIGNMENT_ERROR,                // 0x30015 - parameters will cause an alignment error
    ADI_DMA_RESULT_BAD_XCOUNT,                     // 0x30016 - an invalid XCount value was supplied
    ADI_DMA_RESULT_NON_TERMINATED_CHAIN,           // 0x30017 - the descriptor chain is not NULL terminated
    ADI_DMA_RESULT_NO_CALLBACK_FUNCTION_SUPPLIED,  // 0x30018 - no callback function was provided to the open function
    ADI_DMA_RESULT_BAD_CONTROLLER_ID,              // 0x30019 - bad controller ID specified
    ADI_DMA_RESULT_BAD_TC_PARAMETER,               // 0x3001a - bad traffic control parameter
    ADI_DMA_RESULT_BAD_DIRECTION,                  // 0x3001b - bad WNR direction
    ADI_DMA_RESULT_INCOMPATIBLE_WDSIZE,            // 0x3001c - source and destination have different WDSIZE values
    ADI_DMA_RESULT_INCOMPATIBLE_TRANSFER_SIZE,     // 0x3001d - source and destination have different transfer sizes
    ADI_DMA_RESULT_NULL_DESCRIPTOR,                // 0x3001e - a NULL descriptor was passed to the function
    ADI_DMA_RESULT_CALLBACKS_DISALLOWED_ON_SOURCE, // 0x3001f - callbacks are not allowed on source memory DMA descriptors
    ADI_DMA_RESULT_INCOMPATIBLE_CALLBACK,          // 0x30020 - destination descriptor callback incompatible with source descriptors
    ADI_DMA_RESULT_BAD_CHANNEL_MEMORY_SIZE,        // 0x30021 - the ADI_DMA_CHANNEL_MEMORY macro is invalid (internal error)
    ADI_DMA_RESULT_INCOMPATIBLE_IVG_LEVEL          // 0x30022 - this function cannot be called from the current IVG level
} ADI_DMA_RESULT;

/*********************************************************************

API function prototypes

*********************************************************************/

#ifdef __cplusplus
extern "C"
{
#endif

    //******************
    // Primary functions
    //******************

    ADI_DMA_RESULT adi_dma_Init(                // Initializes the DMA Manager
        void *pMemory,                          // pointer to memory
        const size_t MemorySize,                // size of memory (in bytes)
        u32 *pMaxChannels,                      // number of channels that can be supported
        ADI_DMA_MANAGER_HANDLE *pManagerHandle, // address where DMA manager will store the manager handle
        void *pCriticalRegionArg                // parameter for critical region function
    );

    ADI_DMA_RESULT adi_dma_Terminate(        // Terminates the DMA manager
        ADI_DMA_MANAGER_HANDLE ManagerHandle // DMA manager handle
    );

    ADI_DMA_RESULT adi_dma_Open(                // Opens a DMA channel
        ADI_DMA_MANAGER_HANDLE ManagerHandle,   // DMA manager handle
        ADI_DMA_CHANNEL_ID ChannelID,           // Channel ID
        void *ClientHandle,                     // client handle argument passed in callbacks
        ADI_DMA_CHANNEL_HANDLE *pChannelHandle, // location where DMA channel handle will be stored
        ADI_DMA_MODE Mode,                      // DMA operating mode
        ADI_DCB_HANDLE DCBHandle,               // deferred callback service handle
        ADI_DCB_CALLBACK_FN ClientCallback      // client callback function
    );

    ADI_DMA_RESULT adi_dma_Close(             // Closes a DMA channel
        ADI_DMA_CHANNEL_HANDLE ChannelHandle, // channel handle
        u32 WaitFlag                          // wait for transfers to complete flag (TRUE/FALSE)
    );

    ADI_DMA_RESULT adi_dma_Control(           // Controls/configures a DMA channel
        ADI_DMA_CHANNEL_HANDLE ChannelHandle, // channel handle
        ADI_DMA_CMD Command,                  // command ID
        void *Value                           // command specific value
    );

    ADI_DMA_RESULT adi_dma_Queue(                  // Queues a descriptor(s) to a channel
        ADI_DMA_CHANNEL_HANDLE ChannelHandle,      // channel handle
        ADI_DMA_DESCRIPTOR_HANDLE DescriptorHandle // descriptor handle
    );

    ADI_DMA_RESULT adi_dma_Buffer(            // Provides a one-shot or circular buffer to a channel
        ADI_DMA_CHANNEL_HANDLE ChannelHandle, // channel handle
        void *StartAddress,                   // start address of data
        ADI_DMA_CONFIG_REG Config,            // configuration control register
        u16 XCount,                           // X (column) count
        s16 XModify,                          // X (column) stride
        u16 YCount,                           // Y (row) count
        s16 YModify                           // Y (row) stride
    );

    //******************
    // Helper functions
    //******************

    ADI_DMA_RESULT adi_dma_GetMapping( // Gets the channel ID to which a DMA compatible device is mapped
        ADI_DMA_PMAP pmap,             // peripheral map value
        ADI_DMA_CHANNEL_ID *pChannelID // location where the channel ID of the peripheral will be stored
    );

    ADI_DMA_RESULT adi_dma_SetMapping( // Sets the mapping of a DMA compatible device to a DMA channel
        ADI_DMA_PMAP pmap,             // peripheral map value
        ADI_DMA_CHANNEL_ID ChannelID   // channel ID to which the peripheral will be mapped
    );

    ADI_DMA_RESULT adi_dma_GetPeripheralInterruptID( // Gets the peripheral interrupt ID for a given DMA channel ID
        ADI_DMA_CHANNEL_ID ChannelID,                // DMA channel ID
        ADI_INT_PERIPHERAL_ID *pPeripheralID         // location where the peripheral ID will be stored
    );

    /* Sets the bits in the configuration word for a chain of descriptors */
    ADI_DMA_RESULT adi_dma_SetConfigWord(
        ADI_DMA_CHANNEL_HANDLE ChannelHandle,      // channel handle
        ADI_DMA_DESCRIPTOR_HANDLE DescriptorHandle // descriptor chain
    );

    //******************
    // Memory DMA functions
    //******************

    ADI_DMA_RESULT adi_dma_MemoryOpen(        // Opens a memory DMA stream
        ADI_DMA_MANAGER_HANDLE ManagerHandle, // DMA manager handle
        ADI_DMA_STREAM_ID StreamID,           // memory stream ID
        void *ClientHandle,                   // client handle argument passed in callbacks
        ADI_DMA_STREAM_HANDLE *pStreamHandle, // location where DMA stream handle will be stored
        void *DCBHandle                       // deferred callback service handle
    );

    ADI_DMA_RESULT adi_dma_MemoryClose(     // Closes a memory DMA stream
        ADI_DMA_STREAM_HANDLE StreamHandle, // stream handle
        u32 WaitFlag                        // wait for transfers to complete flag (TRUE/FALSE)
    );

    ADI_DMA_RESULT adi_dma_MemoryCopy(      // copies memory in a 1D fashion
        ADI_DMA_STREAM_HANDLE StreamHandle, // stream handle
        void *pDest,                        // memory destination address
        void *pSrc,                         // memory source address
        u16 ElementWidth,                   // element width (in bytes)
        u16 ElementCount,                   // element count
        ADI_DCB_CALLBACK_FN ClientCallback  // client callback function (Synchronous when NULL)
    );

    ADI_DMA_RESULT adi_dma_MemoryCopy2D(    // copies memory in a 2D fashion
        ADI_DMA_STREAM_HANDLE StreamHandle, // stream handle
        ADI_DMA_2D_TRANSFER *pDest,         // destination channel configuration
        ADI_DMA_2D_TRANSFER *pSrc,          // source channel configuration
        u32 ElementWidth,                   // element width (in bytes)
        ADI_DCB_CALLBACK_FN ClientCallback  // client callback function (Synchronous when NULL)
    );

    //******************
    // Memory DMA functions for use when queueing
    //******************

    ADI_DMA_RESULT adi_dma_MemoryQueueOpen(   // Opens a memory DMA stream for queueing
        ADI_DMA_MANAGER_HANDLE ManagerHandle, // DMA manager handle
        ADI_DMA_STREAM_ID StreamID,           // memory stream ID
        void *ClientHandle,                   // client handle argument passed in callbacks
        ADI_DMA_STREAM_HANDLE *pStreamHandle, // location where DMA stream handle will be stored
        void *DCBHandle,                      // deferred callback service handle
        ADI_DCB_CALLBACK_FN ClientCallback    // client callback function
    );

    ADI_DMA_RESULT adi_dma_MemoryQueueClose( // Closes a memory DMA stream that was opened for queueing
        ADI_DMA_STREAM_HANDLE StreamHandle,  // stream handle
        u32 WaitFlag                         // wait for transfers to complete flag (TRUE/FALSE)
    );

    ADI_DMA_RESULT adi_dma_MemoryQueueControl( // Controls/configures a memory DMA stream
        ADI_DMA_STREAM_HANDLE StreamHandle,    // stream handle
        ADI_DMA_CMD Command,                   // command ID
        void *Value                            // command specific value
    );

    ADI_DMA_RESULT adi_dma_MemoryQueue(                  // Queues memory DMA descriptor(s) to a stream
        ADI_DMA_STREAM_HANDLE StreamHandle,              // stream handle
        ADI_DMA_DESCRIPTOR_LARGE *pSourceDescriptor,     // source descriptor handle
        ADI_DMA_DESCRIPTOR_LARGE *pDestinationDescriptor // destination descriptor handle
    );

#ifdef __cplusplus
}
#endif

/********************************************************************************/

#endif //! defined(_LANGUAGE_ASM)

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_DMA_H__ */
