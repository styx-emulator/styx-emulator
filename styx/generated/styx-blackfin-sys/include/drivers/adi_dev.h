/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_dev.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the Device Manager.

*********************************************************************/

/* This has been moved here from below as a temporary solution to TAR #32242 */
#include <services/services.h>

#ifndef __ADI_DEV_H__
#define __ADI_DEV_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Insure the system services have been included

*********************************************************************/

// This has been moved above as a temporary solution to TAR #32242
// #include <services/services.h>

/*********************************************************************

Insure the device driver model supports the given processor family

*********************************************************************/

#if defined(__ADSP_EDINBURGH__)   \
 || defined(__ADSP_BRAEMAR__)     \
 || defined(__ADSP_TETON__)       \
 || defined(__ADSP_STIRLING__)    \
 || defined(__ADSP_MOAB__)        \
 || defined(__ADSP_KOOKABURRA__)  \
 || defined(__ADSP_MOCKINGBIRD__) \
 || defined(__ADSP_BRODIE__)      \
 || defined(__ADSP_MOY__)         \
 || defined(__ADSP_DELTA__)

#else
#error "*** The Device Driver Model does not yet support this processor ***"
#endif

#if !defined(_LANGUAGE_ASM)


/*********************************************************************

Device Driver Enumeration Start Values

Each device driver can extend the existing command IDs, event IDs and
return codes.  In order to avoid conflicts, these enumerations must be
unique so that no two device drivers share the same enumeration values.

The macros below define the enumeration start values for each device
driver.  Within each device driver's .h file, the enumeration values for
new command IDs, event IDs and return codes should begin with the
appropriate value from the list below.  Each driver can add up to 65535
new types before any conflicts occur.  Also note that each driver should
prefix all macros, functions, non-static and non-automatic variables with
the prefixes shown below.

(NOTE: all drivers should use the return code of ADI_DEV_RESULT_SUCCESS,
which has the value 0, for all successful function calls.)

For example, the PPI driver uses the prefix "ADI_PPI" and "adi_ppi" and
begins it's enumeration values starting with ADI_PPI_ENUMERATION_START.

When new drivers are added to the distribution, begin the enumeration
for the new driver with the value indicated below, then replace that value
on the line below with it's current value + 0x10000.

Next driver enumeration starts at -> 0x40340000

*********************************************************************/

// adc
#define ADI_AD1871_ENUMERATION_START        (0x40010000)    // AD1871 driver enumeration start
#define ADI_AD7266_ENUMERATION_START        (0x40020000)    // AD7266 driver enumeration start
#define ADI_AD7276_ENUMERATION_START        (0x40028000)    // AD7276 driver enumeration start
#define ADI_AD7356_ENUMERATION_START        (0x40260000)    // AD7356 driver enumeration start
#define ADI_AD7476A_ENUMERATION_START       (0x40030000)    // AD7476A driver enumeration start
#define ADI_AD7477A_ENUMERATION_START       (0x401a0000)    // AD7477A driver enumeration start
#define ADI_AD7478A_ENUMERATION_START       (0x401b0000)    // AD7478A driver enumeration start
#define ADI_AD7476_ENUMERATION_START        (0x401c0000)    // AD7476 driver enumeration start
#define ADI_AD7477_ENUMERATION_START        (0x401d0000)    // AD7477 driver enumeration start
#define ADI_AD7478_ENUMERATION_START        (0x401e0000)    // AD7478 driver enumeration start
#define ADI_AD7674_ENUMERATION_START        (0x40040000)    // AD7674 driver enumeration start
#define ADI_BF506ADC1_ENUMERATION_START     (0x40330000)    // ADSP-BF506F ADC Enumeration start

// codec
#define ADI_AD1836_ENUMERATION_START        (0x40050000)    // AD1836 driver enumeration start
#define ADI_AD1938_ENUMERATION_START        (0x40060000)    // AD1938 driver enumeration start
#define ADI_ADAV801_ENUMERATION_START       (0x40070000)    // ADAV801 driver enumeration start
#define ADI_BF52xC1_ENUMERATION_START       (0x402B0000)    // BF52xC1 driver enumeration start
#define ADI_AC97_ENUMERATION_START          (0x402C0000)    // AC'97 driver enumeration start
#define ADI_AD1980_ENUMERATION_START        (0x402D0000)    // AD1980 driver enumeration start
#define ADI_SSM2602_ENUMERATION_START       (0x40300000)    // SSM2602 driver enumeration start
#define ADI_SSM2603_ENUMERATION_START       (0x40310000)    // SSM2603 driver enumeration start

// dac
#define ADI_AD1854_ENUMERATION_START        (0x40080000)    // AD1854 driver enumeration start
#define ADI_AD5453_ENUMERATION_START        (0x40270000)    // AD5453 driver enumeration start

// decoder
#define ADI_ADV7183_ENUMERATION_START       (0x40090000)    // ADV7183 driver enumeration start

// encoder
#define ADI_ADV717x_ENUMERATION_START       (0x400a0000)    // ADV717x driver enumeration start

// lcd
#define ADI_NL6448BC3354_ENUMERATION_START  (0x400b0000)    // NEC NL6448BC3354 LCD driver enumeration start
#define ADI_LQ10D368_ENUMERATION_START      (0x40140000)    // Sharp LQ10D368 LCD driver enumeration start
#define ADI_TMS350MHQ03_ENUMERATION_START   (0x401f0000)    // TMS350MHQ03 LCD driver enumeration start (DMTC)
#define ADI_LQ043T1DG01_ENUMERATION_START   (0x40250000)    // Sharp LQ043T1DG01 LCD driver enumeration start (BF548 Ez-Kit)
#define ADI_T350MCQB01_ENUMERATION_START    (0x402A0000)    // Varitronix T350MCQB-01 LCD driver enumeration start (BF527 Ez-Kit)
#define ADI_LQ035Q1DH02_ENUMERATION_START   (0x402F0000)    // Sharp LQ035Q1DH02 LCD driver enumeration start (LCD Extender)

// ppi
#define ADI_PPI_ENUMERATION_START           (0x400c0000)    // PPI driver enumeration start

// Pixel compositor
#define ADI_PIXC_ENUMERATION_START          (0x40160000)    // Pixel compositor driver enumeration start
// EPPI
#define ADI_EPPI_ENUMERATION_START          (0x40170000)    // EPPI driver enumeration start

// Keypad
#define ADI_KEYPAD_ENUMERATION_START        (0x40190000)    // Keypad driver enumeration start
#define ADI_ADP5520_ENUMERATION_START       (0x40320000)    // ADP5520 keypad/backlight/etc (BF527 EZ-Kit 2.1 on)

// Touch screen
#define ADI_AD7877_ENUMERATION_START        (0x40180000)    // AD7877 driver enumeration start
#define ADI_AD7879_ENUMERATION_START        (0x401A0000)    // AD7877 driver enumeration start

/* Capacitance converter */
#define ADI_AD7147_ENUMERATION_START        (0x401B0000)    /* AD7147 driver enumeration start*/

// Combination TouchScreen and Keypad Controller
#define ADI_MAX1233_ENUMERATION_START       (0x40290000)    // Maxim MAX1233 driver enum start

// sensor
#define ADI_MT9V022_ENUMERATION_START       (0x400d0000)    // Micron MT9V022 sensor driver enumeration start
#define ADI_MT9V111_ENUMERATION_START       (0x40150000)    // Micron MT9V111 sensor driver enumeration start
#define ADI_OV7x48_ENUMERATION_START        (0x400e0000)    // Omnivision OV7x48 sensor driver enumeration start

// spi
#define ADI_SPI_ENUMERATION_START           (0x400f0000)    // SPI driver enumeration start

// sport
#define ADI_SPORT_ENUMERATION_START         (0x40100000)    // SPORT driver enumeration start

// twi
#define ADI_TWI_ENUMERATION_START           (0x40110000)    // TWI driver enumeration start

// uart
#define ADI_UART_ENUMERATION_START          (0x40120000)    // UART driver enumeration start

// rotary
#define ADI_ROTARY_ENUMERATION_START        (0x40200000)    // Rotary driver enumeration start

// USB
#define ADI_USB_ENUMERATION_START           (0x40210000)    // common USB enumeration start
#define ADI_USB_NET2272_ENUMERATION_START   (0x40220000)    // NET2272 USB controller driver enumeration start
#define ADI_USB_BF54X_ENUMERATION_START     (0x40230000)    // BF54x USB controller driver enumeration start
#define ADI_USB_BF52X_ENUMERATION_START     (0x40240000)    // BF52x USB controller driver enumeration start
#define ADI_USB_MSD_ENUMERATION_START       (0x40250000)    // Mass Storage Device (peripheral mode) enumeration start
#define ADI_USB_MSD_HOST_ENUMERATION_START  (0x40260000)    // Mass Storage Device (host mode) enumeration start
#define ADI_USB_AUDIO_ENUMERATION_START     (0x40270000)    // Audio Device enumeration start

/* NAND Flash Controller (NFC) */
#define ADI_NFC_ENUMERATION_START           (0x402E0000)    /* NFC driver enumeration start */

/* These enumeration starts are no longer used going forward.  They were used when all drivers
   shared the same enumeration starts.  They are retained for compatibility with any drivers not
   using the new method.  They should not be used in any new driver development.  */
#define ADI_DEV_CMD_PDD_START               (0x40130000)    /* old command ID enumerations                          */
#define ADI_DEV_RESULT_PDD_START            (0x40130000)    /* old return code enumerations                         */
#define ADI_DEV_EVENT_PDD_START             (0x40130000)    /* old event ID enumerations                            */


/*********************************************************************

Macros for the memory usage of the Device Manager

*********************************************************************/

#define ADI_DEV_BASE_MEMORY     (12)    /* base memory needed for the device manager (bytes)    */
#define ADI_DEV_DEVICE_MEMORY   (104)   /* additional memory needed for each device (bytes)     */

/*********************************************************************

Macros for TWI/SPI Device Access Service for off chip devices

*********************************************************************/

#define     ADI_DEV_REGEND      0xFFFF  /* Device Access delimiter (indicates end of device register access) */

/*********************************************************************

Datatypes for handles into the device manager and device drivers

*********************************************************************/

typedef void *ADI_DEV_MANAGER_HANDLE;       /* Handle to a device manager                               */
typedef void *ADI_DEV_DEVICE_HANDLE;        /* Handle to a device driver                                */
typedef void *ADI_DEV_PDD_HANDLE;           /* Handle to a physical device (used by device manager only)*/



/*********************************************************************

Dataflow enumerations

*********************************************************************/

typedef enum {                          /* Dataflow methods                 */
    ADI_DEV_MODE_UNDEFINED,             /* undefined                        */
    ADI_DEV_MODE_CIRCULAR,              /* circular buffer                  */
    ADI_DEV_MODE_CHAINED,               /* chained                          */
    ADI_DEV_MODE_CHAINED_LOOPBACK,      /* chained with loopback            */
    ADI_DEV_MODE_SEQ_CHAINED,           /* sequential chained               */
    ADI_DEV_MODE_SEQ_CHAINED_LOOPBACK   /* sequential chained with loopback */
} ADI_DEV_MODE;


typedef enum {                          /* Data direction                   */
    ADI_DEV_DIRECTION_UNDEFINED,        /* undefined                        */
    ADI_DEV_DIRECTION_INBOUND,          /* inbound (read)                   */
    ADI_DEV_DIRECTION_OUTBOUND,         /* outbound (write)                 */
    ADI_DEV_DIRECTION_BIDIRECTIONAL     /* both (read and write)            */
} ADI_DEV_DIRECTION;

/*********************************************************************

Enumerations for command IDs (extensible by physical drivers)

*********************************************************************/


enum {                                          /* Command IDs                                                                                                      */
    ADI_DEV_CMD_START=ADI_DEV_ENUMERATION_START,/* 0x40000000 - starting point                                                                                      */

    ADI_DEV_CMD_UNDEFINED,                      /* 0x0001 - undefined                                                                                               */

    ADI_DEV_CMD_END,                            /* 0x0002 - end of table                                                (Value = NULL)                              */
    ADI_DEV_CMD_PAIR,                           /* 0x0003 - single command pair being passed                            (Value = ADI_DEV_CMD_VALUE_PAIR *)          */
    ADI_DEV_CMD_TABLE,                          /* 0x0004 - table of command pairs being passed                         (Value = ADI_DEV_CMD_VALUE_PAIR *)          */

    ADI_DEV_CMD_SET_DATAFLOW,                   /* 0x0005 - enable/disable dataflow                                     (Value = TRUE/FALSE)                        */

    ADI_DEV_CMD_SET_DATAFLOW_METHOD,            /* 0x0006 - set the dataflow method                                     (Value = TRUE/FALSE)                        */
    ADI_DEV_CMD_NOT_USED_1,                     /* 0x0007 - no longer used (was GET_DATAFLOW_METHOD)                                                                */

    ADI_DEV_CMD_SET_SYNCHRONOUS,                /* 0x0008 - set the device to synchronous I/O                           (Value = TRUE/FALSE)                        */
    ADI_DEV_CMD_NOT_USED_2,                     /* 0x0009 - no longer used (was GET_SYNCHRONOUS)                                                                    */

    ADI_DEV_CMD_SET_STREAMING,                  /* 0x000a - sets streaming mode                                         (Value = TRUE/FALSE)                        */

    ADI_DEV_CMD_GET_MAX_INBOUND_SIZE,           /* 0x000b - get the size of the biggest inbound packet                  (Value = u32 *)                             */
    ADI_DEV_CMD_GET_MAX_OUTBOUND_SIZE,          /* 0x000c - get the size of the biggest outbound packet                 (Value = u32 *)                             */

    ADI_DEV_CMD_GET_PERIPHERAL_DMA_SUPPORT,     /* 0x000d - does the device support processor DMA                       (Value = u32 *)                             */
    ADI_DEV_CMD_GET_INBOUND_DMA_PMAP_ID,        /* 0x000e - gets the peripheral's DMA PMAP value for inbound data       (Value = ADI_DMA_PMAP *)                    */
    ADI_DEV_CMD_GET_OUTBOUND_DMA_PMAP_ID,       /* 0x000f - gets the peripheral's DMA PMAP value for outbound data      (Value = ADI_DMA_PMAP *)                    */
    ADI_DEV_CMD_SET_INBOUND_DMA_CHANNEL_ID,     /* 0x0010 - sets the DMA channel ID for inbound DMA                     (Value = ADI_DMA_CHANNEL_ID)                */
    ADI_DEV_CMD_GET_INBOUND_DMA_CHANNEL_ID,     /* 0x0011 - gets the DMA channel ID for inbound DMA                     (Value = ADI_DMA_CHANNEL_ID *)              */
    ADI_DEV_CMD_SET_OUTBOUND_DMA_CHANNEL_ID,    /* 0x0012 - sets the DMA channel ID for outbound DMA                    (Value = ADI_DMA_CHANNEL_ID)                */
    ADI_DEV_CMD_GET_OUTBOUND_DMA_CHANNEL_ID,    /* 0x0013 - gets the DMA channel ID for outbound DMA                    (Value = ADI_DMA_CHANNEL_ID *)              */
    ADI_DEV_CMD_GET_2D_SUPPORT,                 /* 0x0014 - queries whether the device supports 2D transfers            (Value = u32 *)                             */

    ADI_DEV_CMD_SET_ERROR_REPORTING,            /* 0x0015 - enables/disables error reporting                            (Value = TRUE/FALSE)                        */

    ADI_DEV_CMD_FREQUENCY_CHANGE_PROLOG,        /* 0x0016 - notification of an impending core/system frequency change   (Value = ADI_DEV_FREQUENCIES *CurrentFreqs) */
    ADI_DEV_CMD_FREQUENCY_CHANGE_EPILOG,        /* 0x0017 - notification of new core/system frequency settings          (Value = ADI_DEV_FREQUENCIES *NewFreqs)     */

                                                /* TWI/SPI Device access service commands                                                                           */
    ADI_DEV_CMD_REGISTER_READ,                  /* 0x0018 - reads a single device register                              (Value = ADI_DEV_ACCESS_REGISTER *)         */
    ADI_DEV_CMD_REGISTER_FIELD_READ,            /* 0x0019 - reads a specific device register field                      (Value = ADI_DEV_ACCESS_REGISTER_FIELD *)   */
    ADI_DEV_CMD_REGISTER_TABLE_READ,            /* 0x001a - reads a table of selective device registers                 (Value = ADI_DEV_ACCESS_REGISTER *)         */
    ADI_DEV_CMD_REGISTER_FIELD_TABLE_READ,      /* 0x001b - reads a table of selective device register(s) field(s)      (Value = ADI_DEV_ACCESS_REGISTER_FIELD *)   */
    ADI_DEV_CMD_REGISTER_BLOCK_READ,            /* 0x001c - reads a block of consecutive device registers               (Value = ADI_DEV_ACCESS_REGISTER_BLOCK *)   */
    ADI_DEV_CMD_REGISTER_WRITE,                 /* 0x001d - writes to a single device register                          (Value = ADI_DEV_ACCESS_REGISTER *)         */
    ADI_DEV_CMD_REGISTER_FIELD_WRITE,           /* 0x001e - writes to a specific device register field                  (Value = ADI_DEV_ACCESS_REGISTER_FIELD *)   */
    ADI_DEV_CMD_REGISTER_TABLE_WRITE,           /* 0x001f - writes to a table of selective device registers             (Value = ADI_DEV_ACCESS_REGISTER *)         */
    ADI_DEV_CMD_REGISTER_FIELD_TABLE_WRITE,     /* 0x0020 - writes to a table of selective device register(s) field(s)  (Value = ADI_DEV_ACCESS_REGISTER_FIELD *)   */
    ADI_DEV_CMD_REGISTER_BLOCK_WRITE,           /* 0x0021 - writes to a block of consecutive device registers           (Value = ADI_DEV_ACCESS_REGISTER_BLOCK *)   */

    ADI_DEV_CMD_UPDATE_1D_DATA_POINTER,         /* 0x0022 - updates the data pointer in a single 1D buffer              (Value = ADI_DEV_1D_BUFFER *)               */
    ADI_DEV_CMD_UPDATE_2D_DATA_POINTER,         /* 0x0023 - updates the data pointer in a single 2D buffer              (Value = ADI_DEV_2D_BUFFER *)               */
    ADI_DEV_CMD_UPDATE_SEQ_1D_DATA_POINTER,     /* 0x0024 - updates the data pointer in a single sequential 1D buffer   (Value = ADI_DEV_SEQ_1D_BUFFER *)           */

    ADI_DEV_CMD_GET_INBOUND_DMA_CURRENT_ADDRESS,    /* 0x0025 - gets current address register value of Inbound DMA      (Value = u32 *)                             */
    ADI_DEV_CMD_GET_OUTBOUND_DMA_CURRENT_ADDRESS,   /* 0x0026 - gets current address register value of Outbound DMA     (Value = u32 *)                             */

    ADI_DEV_CMD_GET_INBOUND_DMA_INFO,           /* 0x0027 - gets channel information for Inbound DMAs                   (Value = ADI_DEV_DMA_INFO *)                */
    ADI_DEV_CMD_GET_OUTBOUND_DMA_INFO,          /* 0x0028 - gets channel information for Outbound DMAs                  (Value = ADI_DEV_DMA_INFO *)                */
    ADI_DEV_CMD_OPEN_PERIPHERAL_DMA,            /* 0x0029 - Peripheral requesting Device manager to open a DMA channel  (Value = ADI_DEV_DMA_INFO *)                */
    ADI_DEV_CMD_CLOSE_PERIPHERAL_DMA,           /* 0x002a - Peripheral requesting Device manager to close a DMA channel (Value = ADI_DEV_DMA_INFO *)                */

    ADI_DEV_CMD_SET_INBOUND_DMA_CHAIN_CHANNEL_ID,   /* 0x002b - sets the DMA channel IDs for inbound DMA chain          (Value = ADI_DEV_DMA_ACCESS *)              */
    ADI_DEV_CMD_GET_INBOUND_DMA_CHAIN_CHANNEL_ID,   /* 0x002c - gets the DMA channel IDs for inbound DMA chain          (Value = ADI_DEV_DMA_ACCESS *)              */
    ADI_DEV_CMD_SET_OUTBOUND_DMA_CHAIN_CHANNEL_ID,  /* 0x002d - sets the DMA channel IDs for outbound DMA chain         (Value = ADI_DEV_DMA_ACCESS *)              */
    ADI_DEV_CMD_GET_OUTBOUND_DMA_CHAIN_CHANNEL_ID,  /* 0x002e - gets the DMA channel IDs for outbound DMA chain         (Value = ADI_DEV_DMA_ACCESS *)              */

    ADI_DEV_CMD_GET_INBOUND_DMA_CHAIN_CURRENT_ADDRESS,  /* 0x002f -gets current address register value of Inbound DMA chain     (Value = ADI_DEV_DMA_ACCESS *)      */
    ADI_DEV_CMD_GET_OUTBOUND_DMA_CHAIN_CURRENT_ADDRESS, /* 0x0030 -gets current address register value of Outbound DMA chain    (Value = ADI_DEV_DMA_ACCESS *)      */

    ADI_DEV_CMD_CHANGE_CLIENT_CALLBACK_FUNCTION,    /* 0x0031 - changes the client callback function for the device    (Value = ADI_DCB_CALLBACK_FN)      */
    ADI_DEV_CMD_CHANGE_CLIENT_HANDLE                /* 0x0032 - changes the client handle for the device    (Value = void* )      */
};


typedef struct ADI_DEV_CMD_VALUE_PAIR {     /* DEV command value pair   */
    u32     CommandID;                      /* command ID               */
    void    *Value;                         /* parameter                */
} ADI_DEV_CMD_VALUE_PAIR;



/*********************************************************************

Enumerations for callback events (extensible by physical drivers)

*********************************************************************/

enum {                                              /* Events                                                   */
    ADI_DEV_EVENT_START=ADI_DEV_ENUMERATION_START,  /* 0x40000000 - starting point                              */

    ADI_DEV_EVENT_BUFFER_PROCESSED,                 /* 0x0001 - buffer completed processing                     */
    ADI_DEV_EVENT_SUB_BUFFER_PROCESSED,             /* 0x0002 - a circular sub-buffer has been processed        */
    ADI_DEV_EVENT_DMA_ERROR_INTERRUPT               /* 0x0003 - DMA controller generated an error interrupt     */


};

/*********************************************************************

Enumerations for return codes (extensible by physical drivers)

*********************************************************************/

enum {                                                  /* Return codes                                                                 */
    ADI_DEV_RESULT_SUCCESS=0,                           /* generic success                                                              */
    ADI_DEV_RESULT_FAILED=1,                            /* generic failure                                                              */

    ADI_DEV_RESULT_START=ADI_DEV_ENUMERATION_START,     /* 0x40000000 - starting point                                                  */

    ADI_DEV_RESULT_NOT_SUPPORTED,                       /* 0x0001 - not supported                                                       */
    ADI_DEV_RESULT_DEVICE_IN_USE,                       /* 0x0002 - device already in use                                               */
    ADI_DEV_RESULT_NO_MEMORY,                           /* 0x0003 - insufficient memory for operation                                   */
    ADI_DEV_RESULT_NOT_USED_1,                          /* 0x0004 - no longer used (was ADI_DEV_RESULT_TOO_MANY_DEVICES)                */
    ADI_DEV_RESULT_BAD_DEVICE_NUMBER,                   /* 0x0005 - bad device number                                                   */
    ADI_DEV_RESULT_DIRECTION_NOT_SUPPORTED,             /* 0x0006 - data direction not supported                                        */
    ADI_DEV_RESULT_BAD_DEVICE_HANDLE,                   /* 0x0007 - bad device handle                                                   */
    ADI_DEV_RESULT_BAD_MANAGER_HANDLE,                  /* 0x0008 - bad device manager handle                                           */
    ADI_DEV_RESULT_BAD_PDD_HANDLE,                      /* 0x0009 - bad physical driver handle                                          */
    ADI_DEV_RESULT_INVALID_SEQUENCE,                    /* 0x000a - invalid sequence of commands                                        */
    ADI_DEV_RESULT_ATTEMPTED_READ_ON_OUTBOUND_DEVICE,   /* 0x000b - attempted read on outbound device                                   */
    ADI_DEV_RESULT_ATTEMPTED_WRITE_ON_INBOUND_DEVICE,   /* 0x000c - attempted write on inbound device                                   */
    ADI_DEV_RESULT_DATAFLOW_UNDEFINED,                  /* 0x000d - dataflow method is undefined                                        */
    ADI_DEV_RESULT_DATAFLOW_INCOMPATIBLE,               /* 0x000e - operation is incompatible with the dataflow method                  */
    ADI_DEV_RESULT_BUFFER_TYPE_INCOMPATIBLE,            /* 0x000f - device does not support the given buffer type                       */
    ADI_DEV_RESULT_NOT_USED_2,                          /* 0x0010 - no longer used (was ADI_DEV_RESULT_CALLBACK_ERROR)                  */
    ADI_DEV_RESULT_CANT_HOOK_INTERRUPT,                 /* 0x0011 - can't hook an interrupt                                             */
    ADI_DEV_RESULT_CANT_UNHOOK_INTERRUPT,               /* 0x0012 - can't unhood an interrupt                                           */
    ADI_DEV_RESULT_NON_TERMINATED_LIST,                 /* 0x0013 - non-NULL terminated buffer list                                     */
    ADI_DEV_RESULT_NO_CALLBACK_FUNCTION_SUPPLIED,       /* 0x0014 - no callback function was provided to the open function              */
    ADI_DEV_RESULT_REQUIRES_UNIDIRECTIONAL_DEVICE,      /* 0x0015 - requires uni-directional device                                     */
    ADI_DEV_RESULT_REQUIRES_BIDIRECTIONAL_DEVICE,       /* 0x0016 - requires bidirectional device                                       */

                                                        /* Return codes for TWI/SPI Device access service                               */
    ADI_DEV_RESULT_TWI_LOCKED,                          /* 0x0017 - TWI locked in other operation                                       */
    ADI_DEV_RESULT_REQUIRES_TWI_CONFIG_TABLE,           /* 0x0018 - requires configuration table for the TWI driver                     */
    ADI_DEV_RESULT_CMD_NOT_SUPPORTED,                   /* 0x0019 - Command not supported                                               */
    ADI_DEV_RESULT_INVALID_REG_ADDRESS,                 /* 0x001a - Accessing invalid Device Register address                           */
    ADI_DEV_RESULT_INVALID_REG_FIELD,                   /* 0x001b - Accessing invalid Device Register field location                    */
    ADI_DEV_RESULT_INVALID_REG_FIELD_DATA,              /* 0x001c - Providing invalid Device Register field value                       */
    ADI_DEV_RESULT_ATTEMPT_TO_WRITE_READONLY_REG,       /* 0x001d - Attempt to write a readonly register                                */
    ADI_DEV_RESULT_ATTEMPT_TO_ACCESS_RESERVE_AREA,      /* 0x001e - Attempt to access a reserved location                               */
    ADI_DEV_RESULT_ACCESS_TYPE_NOT_SUPPORTED,           /* 0x001f - Access type provided by the driver is not supported                 */

    ADI_DEV_RESULT_DATAFLOW_NOT_ENABLED,                /* 0x0020 - In sync mode, buffers provided before dataflow enabled              */
    ADI_DEV_RESULT_BAD_DIRECTION_FIELD,                 /* 0x0021 - In sequential I/O mode, buffers provided with an invalid direction value */
    ADI_DEV_RESULT_BAD_IVG,                             /* 0x0022 - Bad IVG number detected                                             */

    ADI_DEV_RESULT_SWITCH_BUFFER_PAIR_INVALID,          /* 0x0023 - Invalid buffer pair provided with Switch/Update switch buffer type  */
    ADI_DEV_RESULT_DMA_CHANNEL_UNAVAILABLE,             /* 0x0024 - No DMA channel is available to process the given command/buffer     */
    ADI_DEV_RESULT_ATTEMPTED_BUFFER_TABLE_NESTING       /* 0x0025 - buffer table nesting is not allowed                                 */
};




/*********************************************************************

Enumerations for defining the details of the library being used.

*********************************************************************/

typedef enum ADI_DEV_LIBRARY_PROC {                 /* Processor */
    ADI_DEV_LIBRARY_PROC_UNKNOWN=0,
    ADI_DEV_LIBRARY_PROC_BF512,
    ADI_DEV_LIBRARY_PROC_BF526,
    ADI_DEV_LIBRARY_PROC_BF527,
    ADI_DEV_LIBRARY_PROC_BF533,
    ADI_DEV_LIBRARY_PROC_BF537,
    ADI_DEV_LIBRARY_PROC_BF538,
    ADI_DEV_LIBRARY_PROC_BF548,
    ADI_DEV_LIBRARY_PROC_BF561,
    ADI_DEV_LIBRARY_PROC_BF506F,
    ADI_DEV_LIBRARY_PROC_BF592
} ADI_DEV_LIBRARY_PROC;

typedef enum ADI_DEV_LIBRARY_CONFIG {               /* Debug vs Release library */
    ADI_DEV_LIBRARY_CONFIG_UNKNOWN=0,
    ADI_DEV_LIBRARY_CONFIG_DEBUG,
    ADI_DEV_LIBRARY_CONFIG_RELEASE
} ADI_DEV_LIBRARY_CONFIG;

typedef enum ADI_DEV_LIBRARY_WRKRNDS {              /* Chip workarounds for anomalies ("y" in the library name) */
    ADI_DEV_LIBRARY_WRKRNDS_UNKNOWN=0,
    ADI_DEV_LIBRARY_WRKRNDS_ENABLED,
    ADI_DEV_LIBRARY_WRKRNDS_DISABLED
} ADI_DEV_LIBRARY_WRKRNDS;

#define ADI_DEV_LIBRARY_CHIP_REV_NONE   0x7F        /* This is for unknown chip revisions */
#define ADI_DEV_LIBRARY_CHIP_REV_AUTO   0x7E        /* This is for "auto" projects which automatically detect chip rev */

typedef struct ADI_DEV_LIBRARY_DETAILS {
    enum ADI_DEV_LIBRARY_PROC       Processor;
    enum ADI_DEV_LIBRARY_CONFIG     Config;
    enum ADI_DEV_LIBRARY_WRKRNDS    Workarounds;
    u8                              ChipRev;        /* This is a number representing the chip version of the processor */
} ADI_DEV_LIBRARY_DETAILS;



/*********************************************************************

Callback options for devices opened using circular buffer mode

*********************************************************************/

typedef enum {                          /* Circular buffer callback type    */
    ADI_DEV_CIRC_NO_CALLBACK,           /* no callback                      */
    ADI_DEV_CIRC_SUB_BUFFER,            /* callback on sub-buffer complete  */
    ADI_DEV_CIRC_FULL_BUFFER            /* callback on full buffer complete */
} ADI_DEV_CIRCULAR_CALLBACK;

/*********************************************************************

Enumerations and structures for buffers

*********************************************************************/

#define ADI_DEV_RESERVED_SIZE   (sizeof(ADI_DMA_DESCRIPTOR_UNION))  /* size in bytes of reserved field in DEV_BUFFER    */

typedef enum {                          /* Buffer types                                                                 */
    ADI_DEV_BUFFER_UNDEFINED,           /* undefined                                                                    */
    ADI_DEV_1D,                         /* 1 dimensional buffer                                                         */
    ADI_DEV_2D,                         /* 2 dimensional buffer                                                         */
    ADI_DEV_CIRC,                       /* circular buffer                                                              */
    ADI_DEV_SEQ_1D,                     /* sequential 1 dimensional buffer                                              */
    ADI_DEV_SWITCH,                     /* Switch buffer                                                                */
    ADI_DEV_UPDATE_SWITCH,              /* Buffer to chain with the existing Switch buffer                              */
    ADI_DEV_BUFFER_SKIP,                /* skip this buffer & corresponding DMA channel (to support multi-DMA devices)  */
    ADI_DEV_BUFFER_TABLE,               /* Table of buffers                                                             */
    ADI_DEV_BUFFER_END                  /* end of buffer array                                                          */
} ADI_DEV_BUFFER_TYPE;

typedef struct adi_dev_1d_buffer {                                  /* 1D ("normal") buffer                             */
    char                        Reserved[ADI_DEV_RESERVED_SIZE];    /* reserved for physical device driver use          */
    void                        *Data;                              /* pointer to data                                  */
    u32                         ElementCount;                       /* data element count                               */
    u32                         ElementWidth;                       /* data element width (in bytes)                    */
    void                        *CallbackParameter;                 /* callback flag/pArg value                         */
    volatile u32                ProcessedFlag;                      /* processed flag                                   */
    u32                         ProcessedElementCount;              /* # of bytes read in/out                           */
    struct adi_dev_1d_buffer    *pNext;                             /* next buffer                                      */
    void                        *pAdditionalInfo;                   /* device specific pointer to additional info       */
} ADI_DEV_1D_BUFFER;

typedef struct adi_dev_2d_buffer {                                  /* 2D buffer                                        */
    char                        Reserved[ADI_DEV_RESERVED_SIZE];    /* reserved for physical device driver use          */
    void                        *Data;                              /* pointer to data                                  */
    u32                         ElementWidth;                       /* data element width (in bytes)                    */
    u32                         XCount;                             /* XCOUNT value for 2D                              */
    s32                         XModify;                            /* XMODIFY value for 2D                             */
    u32                         YCount;                             /* YCOUNT value for 2D                              */
    s32                         YModify;                            /* YMODIFY value for 2D                             */
    void                        *CallbackParameter;                 /* callback flag/pArg value                         */
    volatile u32                ProcessedFlag;                      /* processed flag                                   */
    u32                         ProcessedElementCount;              /* elements read in/out                             */
    struct adi_dev_2d_buffer    *pNext;                             /* next buffer                                      */
    void                        *pAdditionalInfo;                   /* device specific pointer to additional info       */
} ADI_DEV_2D_BUFFER;

typedef struct adi_dev_circular_buffer {                            /* Circular buffer                                  */
    char                        Reserved[ADI_DEV_RESERVED_SIZE];    /* reserved for physical driver use                 */
    void                        *Data;                              /* pointer to data                                  */
    u32                         SubBufferCount;                     /* number of subbuffers                             */
    u32                         SubBufferElementCount;              /* number of data elements in 1 subbuffer           */
    u32                         ElementWidth;                       /* data element width (in bytes)                    */
    ADI_DEV_CIRCULAR_CALLBACK   CallbackType;                       /* circular buffer callback switch                  */
    void                        *pAdditionalInfo;                   /* device specific pointer to additional info       */
} ADI_DEV_CIRCULAR_BUFFER;

typedef struct adi_dev_seq_1d_buffer {                              /* Sequential 1D buffer                             */
    ADI_DEV_1D_BUFFER           Buffer;                             /* buffer                                           */
    ADI_DEV_DIRECTION           Direction;                          /* direction                                        */
} ADI_DEV_SEQ_1D_BUFFER;

typedef struct ADI_DEV_BUFFER_PAIR  {                               /* Buffer pair                                      */
    ADI_DEV_BUFFER_TYPE         BufferType;                         /* buffer type                                      */
    union ADI_DEV_BUFFER        *pBuffer;                           /* pointer to a buffer of above type                */
}ADI_DEV_BUFFER_PAIR;

typedef union ADI_DEV_BUFFER {                                      /* union of buffer types                            */
    ADI_DEV_1D_BUFFER           OneD;                               /* 1D buffer                                        */
    ADI_DEV_2D_BUFFER           TwoD;                               /* 2D buffer                                        */
    ADI_DEV_CIRCULAR_BUFFER     Circular;                           /* circular buffer                                  */
    ADI_DEV_SEQ_1D_BUFFER       Seq1D;                              /* 1D sequential buffer                             */
    ADI_DEV_BUFFER_PAIR         BufferPair;                         /* Buffer pair                                      */
} ADI_DEV_BUFFER;

/*********************************************************************

Data structure to hold peripheral DMA channel information

*********************************************************************/
typedef struct ADI_DEV_DMA_INFO {                   /* structure to hold peripheral DMA channel information             */
    ADI_DMA_PMAP                MappingID;          /* DMA peripheral mapping ID                                        */
    ADI_DMA_CHANNEL_HANDLE      ChannelHandle;      /* handle to this DMA channel                                       */
    u8                          SwitchModeFlag;     /* Switch mode status flag (TRUE when in switch mode)               */
    ADI_DMA_DESCRIPTOR_UNION    *pSwitchHead;       /* Head of Switch buffer chain                                      */
    ADI_DMA_DESCRIPTOR_UNION    *pSwitchTail;       /* Tail of Switch buffer chain                                      */
    struct ADI_DEV_DMA_INFO     *pNext;             /* pointer to structure holding next DMA channel info               */
} ADI_DEV_DMA_INFO;

/*********************************************************************

Data structure to access peripheral's Inbound/Outbound DMA chain data

    Values: DmaChannelCount - Holds number of Inbound/Outbound DMA channels
                              to access in the selected peripheral's
                              Inbound/Outbound DMA chain

            pData           - Pointer to the first location in an array
                              that holds (or) to hold DMA related data.
                              The array data type should same as the
                              DMA related data to be accessed.
                              For example, to get channel id's of selected
                              DMA channels in a peripheral, the array
                              should be of type ADI_DMA_CHANNEL_ID, with
                              address of the array passed as type void.

*********************************************************************/

typedef struct ADI_DEV_DMA_ACCESS
{
    u8      DmaChannelCount;        /* # DMA channels to access in the selected device                  */
    void    *pData;                 /* start location of an array that holds/to hold DMA related data   */
}ADI_DEV_DMA_ACCESS;

/*********************************************************************

Data structures for frequency changes

*********************************************************************/

typedef struct ADI_DEV_FREQUENCIES {    /* structure containing clock frequencies (in Hz)   */
    u32     CoreClock;                  /* core clock (cclk)                                */
    u32     SystemClock;                /* system clock (sclk)                              */
    u32     VCO;                        /* voltage controlled oscillator (vco)              */
} ADI_DEV_FREQUENCIES;

/*********************************************************************

Data structures for reads/writes of single, selective,
blocks of offchip device registers and register field(s)

*********************************************************************/

/* Single and Selective Register Access                                     */
/* Data structure to access a single register                               */
/* Array structure to access a table of selective device registers          */
typedef struct ADI_DEV_ACCESS_REGISTER
{
    u16     Address;            /* Device register address                  */
    u16     Data;               /* Data read/written from/to the register   */
} ADI_DEV_ACCESS_REGISTER;

/* Block Register Access                                                    */
/* Data structure to access a block of consecutive registers                */
typedef struct ADI_DEV_ACCESS_REGISTER_BLOCK
{
    u32     Count;              /* number of registers to be accessed       */
    u16     Address;            /* starting address of register block       */
    u16     *pData;             /* pointer to a 'Count' sized array of register data read/written from/to the device */
} ADI_DEV_ACCESS_REGISTER_BLOCK;

/* Register Field Access                                                    */
/* Basic element to access single register field                            */
/*Array structure to access a table of selective device register(s) field(s)*/
typedef struct ADI_DEV_ACCESS_REGISTER_FIELD
{
  u16 Address;      /* Register address to access                           */
  u16 Field;        /* Register field in the above address to be accessed (list provided in corresponding offchip driver header file) */
  u16 Data;         /* Register field data read/written from/to the device  */
} ADI_DEV_ACCESS_REGISTER_FIELD;

/*********************************************************************

Physical driver entry point

*********************************************************************/

typedef struct {                                    /* Entry point to the physical driver                   */
    u32 (*adi_pdd_Open)(                            /* Open a device                                        */
        ADI_DEV_MANAGER_HANDLE  ManagerHandle,      /* device manager handle                                */
        u32                     DevNumber,          /* device number                                        */
        ADI_DEV_DEVICE_HANDLE   DeviceHandle,       /* DM handle                                            */
        ADI_DEV_PDD_HANDLE      *pPDDHandle,        /* pointer to PDD handle location                       */
        ADI_DEV_DIRECTION       Direction,          /* data direction                                       */
        void                    *pCriticalRegionArg,/* critical region parameter                            */
        ADI_DMA_MANAGER_HANDLE  DMAHandle,          /* handle to the DMA manager                            */
        ADI_DCB_HANDLE          DCBHandle,          /* callback handle                                      */
        ADI_DCB_CALLBACK_FN     DMCallback          /* device manager callback function                     */
    );
    u32 (*adi_pdd_Close)(                           /* Closes a device                                      */
        ADI_DEV_PDD_HANDLE      PDDHandle           /* PDD handle                                           */
    );
    u32 (*adi_pdd_Read)(                            /* Reads data or queues an inbound buffer to a device   */
        ADI_DEV_PDD_HANDLE      PDDHandle,          /* PDD handle                                           */
        ADI_DEV_BUFFER_TYPE     BufferType,         /* buffer type                                          */
        ADI_DEV_BUFFER          *pBuffer            /* pointer to buffer                                    */
    );
    u32 (*adi_pdd_Write)(                           /* Writes data or queues an outbound buffer to a device */
        ADI_DEV_PDD_HANDLE      PDDHandle,          /* PDD handle                                           */
        ADI_DEV_BUFFER_TYPE     BufferType,         /* buffer type                                          */
        ADI_DEV_BUFFER          *pBuffer            /* pointer to buffer                                    */
    );
    u32 (*adi_pdd_Control)(                         /* Sets or senses a device specific parameter           */
        ADI_DEV_PDD_HANDLE      PDDHandle,          /* PDD handle                                           */
        u32                     CommandID,          /* command ID                                           */
        void                    *Value              /* command specific value                               */
    );
    u32 (*adi_pdd_SequentialIO)(                    /* Sequentially reads/writes data to a device           */
        ADI_DEV_PDD_HANDLE      PDDHandle,          /* PDD handle                                           */
        ADI_DEV_BUFFER_TYPE     BufferType,         /* buffer type                                          */
        ADI_DEV_BUFFER          *pBuffer            /* pointer to buffer                                    */
    );
} ADI_DEV_PDD_ENTRY_POINT;


/*********************************************************************

Device Manager API Function declarations

*********************************************************************/


#ifdef __cplusplus
extern "C" {
#endif

u32 adi_dev_Init(                                   /* Initializes the device Manager                           */
    void                    *pMemory,               /* pointer to memory                                        */
    const size_t            MemorySize,             /* size of memory (in bytes)                                */
    u32                     *pMaxDevices,           /* number of devices that can be supported                  */
    ADI_DEV_MANAGER_HANDLE  *pManagerHandle,        /*address where device manager will store the manager handle*/
    void                    *pEnterCriticalArg      /* parameter for enter critical region                      */
);


u32 adi_dev_Terminate(                              /* Terminates the device Manager                            */
    ADI_DEV_MANAGER_HANDLE  ManagerHandle           /* device manager handle                                    */
);


u32 adi_dev_Open(                                   /* Open a device                                            */
    ADI_DEV_MANAGER_HANDLE  ManagerHandle,          /* device manager handle                                    */
    ADI_DEV_PDD_ENTRY_POINT *pEntryPoint,           /* PDD entry point                                          */
    u32                     DevNumber,              /* device number                                            */
    void                    *ClientHandle,          /* client handle                                            */
    ADI_DEV_DEVICE_HANDLE   *pDeviceHandle,         /*pointer to location where the device handle will be stored*/
    ADI_DEV_DIRECTION       Direction,              /* data direction                                           */
    ADI_DMA_MANAGER_HANDLE  DMAHandle,              /* handle to the DMA manager                                */
    ADI_DCB_HANDLE          DCBHandle,              /* handle to the callback manager                           */
    ADI_DCB_CALLBACK_FN     ClientCallback          /* client callback function                                 */
);


u32 adi_dev_Close(                                  /* Closes a device                                          */
    ADI_DEV_DEVICE_HANDLE   DeviceHandle            /* Device handle                                            */
);


u32 adi_dev_Read(                                   /* Reads data or queues an inbound buffer to a device       */
    ADI_DEV_DEVICE_HANDLE   DeviceHandle,           /* Device handle                                            */
    ADI_DEV_BUFFER_TYPE     BufferType,             /* buffer type                                              */
    ADI_DEV_BUFFER          *pBuffer                /* pointer to buffer                                        */
);


u32 adi_dev_Write(                                  /* Writes data or queues an outbound buffer to a device     */
    ADI_DEV_DEVICE_HANDLE   DeviceHandle,           /* Device handle                                            */
    ADI_DEV_BUFFER_TYPE     BufferType,             /* buffer type                                              */
    ADI_DEV_BUFFER          *pBuffer                /* pointer to buffer                                        */
);


u32 adi_dev_Control(                                /* Sets or senses a device specific parameter               */
    ADI_DEV_DEVICE_HANDLE   DeviceHandle,           /* Device handle                                            */
    u32                     CommandID,              /* command ID                                               */
    void                    *Value                  /* command specific value                                   */
);


u32 adi_dev_SequentialIO(                           /* Sequentially read/writes data to a device                */
    ADI_DEV_DEVICE_HANDLE   DeviceHandle,           /* Device handle                                            */
    ADI_DEV_BUFFER_TYPE     BufferType,             /* buffer type                                              */
    ADI_DEV_BUFFER          *pBuffer                /* pointer to buffer                                        */
);


u32 adi_dev_GetLibraryDetails(                      /* Get the processor, chip rev, debug/release, and other    */
    ADI_DEV_LIBRARY_DETAILS *pLibraryDetails        /* details for this particular library.                     */
);

#ifdef __cplusplus
}
#endif


/********************************************************************************/

#endif /* !defined(_LANGUAGE_ASM) */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __ADI_DEV_H__  */
