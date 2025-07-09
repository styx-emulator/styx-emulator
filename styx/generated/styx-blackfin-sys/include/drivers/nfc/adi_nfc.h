/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_nfc.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the primary include file for ADI NAND Flash Controller (NFC) Driver

Note:

    NFC = NAND Flash Controller
    NFD = NAND Flash Device (memory)

    NFD memory contains N number of 'Blocks'
    Each NFD 'Block' contains M number of 'Pages'
    Each NFD 'Page' can be splitted in to Page Data area and Page Spare area
        - Page Data Area holds actual user data
        - Page Spare area is used for error correction and
          other memory management tasks.

    NFC driver treats Page Data area as small packets (called NFD Data packet)
        One NFD Data packet = 256 bytes
        Each NFD Data packet is provided with 8 bytes of Spare Area

    In Sector Access Mode, 1 sector = 512 bytes(for x8), 256 words (for x16)

***********************************************************************/

#ifndef __ADI_NFC_H__
#define __ADI_NFC_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Entry point to the NAND Flash Controller PID

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADI_NFC_EntryPoint;

/*********************************************************************

Macros used by NFC driver

** NOTE: Values assigned to below Macros MUST NOT be changed **

*********************************************************************/

/* NFC DMA Frame memory (Descriptor + ECC) to handle one NFD Data Packet */
#define ADI_NFC_DMA_DATA_FRAME_BASE_MEMORY      (sizeof(ADI_DMA_DESCRIPTOR_LARGE) + 4)
/* NFD Data Packet size in bytes */
#define ADI_NFD_DATA_PKT_SIZE_IN_BYTES          256
/* NFD Sector size in bytes */
#define ADI_NFD_SECTOR_SIZE_IN_BYTES            512

/*********************************************************************

NFD specific commands

*********************************************************************/

#define ADI_NFD_CMD_RESET                       0x00FF  /* Command to reset command interface and status register   */
#define ADI_NFD_CMD_PAGE_READ                   0x0000  /* Command to initiate page read                            */
#define ADI_NFD_CMD_PAGE_READ_CONFIRM           0x0030  /* Command to confirm page read                             */
#define ADI_NFD_CMD_PAGE_RANDOM_READ            0x0005  /* Command to initiate random read within a page            */
#define ADI_NFD_CMD_PAGE_RANDOM_READ_CONFIRM    0x00E0  /* Command to confirm random read within a page             */
#define ADI_NFD_CMD_PAGE_PROGRAM                0x0080  /* Command to initiate page program                         */
#define ADI_NFD_CMD_PAGE_PROGRAM_CONFIRM        0x0010  /* Command to confirm page program                          */
#define ADI_NFD_CMD_PAGE_PROGRAM_RANDOM         0x0085  /* Command to initiate random page program                  */
#define ADI_NFD_CMD_BLOCK_ERASE                 0x0060  /* Command to initiate block erase                          */
#define ADI_NFD_CMD_BLOCK_ERASE_CONFIRM         0x00D0  /* Command to confirm block erase                           */
#define ADI_NFD_CMD_READ_ELECTRONIC_SIGN        0x0090  /* Command to read Electronic Signature                     */
#define ADI_NFD_CMD_READ_STATUS                 0x0070  /* Command to read Status register                          */

/*********************************************************************

Data structure to pass NFD Block/Page/Column address to Access

*********************************************************************/

typedef struct ADI_NFD_ADDRESS
{
    u16     BlockAddress;   /* NAND Memory Block address to access          */
    u16     PageAddress;    /* NAND Memory Page address to access           */
    u16     ColumnAddress;  /* NAND Memory Column address to start with     */
} ADI_NFD_ADDRESS;

/*********************************************************************

Data structure to issue a direct NFD access request.
Direct access means accessing NFD memory without using DMA

Direct access can be used to access any part of NFD Memory,
where as DMA based NFC access can be used only to access
NFD Data Memory area in a page

*********************************************************************/
typedef struct ADI_NFD_DIRECT_ACCESS
{
    u16     BlockAddress;   /* NAND Memory Block address to access                                                              */
    u16     PageAddress;    /* NAND Memory Page address to access                                                               */
    u16     ColumnAddress;  /* NAND Memory Column address to start with                                                         */
    void    *pData;         /* pointer to array holding/to hold NFD data (u8 type array for x8 NFD, u16 type array for x16 NFD) */
    u32     AccessCount;    /* #bytes or #words to read from/write to NFD (in bytes for x8 type NFD, in words for x16 type NFD) */
} ADI_NFD_DIRECT_ACCESS;

/*********************************************************************

Enumerations and Defines for NFD information

*********************************************************************/
/* NAND Flash Device Type */
typedef enum ADI_NFC_NFD_TYPE
{
    ADI_NFD_UNDEFINED,          /* NAND Flash Device type is not defined yet            */
    ADI_NFD_SMALL_PAGE_x8,      /* Small Page NAND Flash Device with 8-bit Data Bus     */
    ADI_NFD_SMALL_PAGE_x16,     /* Small Page NAND Flash Device with 16-bit Data Bus    */
    ADI_NFD_LARGE_PAGE_x8,      /* Large Page NAND Flash Device with 8-bit Data Bus     */
    ADI_NFD_LARGE_PAGE_x16      /* Large Page NAND Flash Device with 16-bit Data Bus    */
}ADI_NFC_NFD_TYPE;

/*********************************************************************

Enumerations for NFC ECC Storage Mode

*********************************************************************/
/* NFC ECC Mode */
typedef enum ADI_NFC_ECC_MODE
{
    ADI_NFC_ECC_MODE_NON_SEQUENTIAL = 0,    /* ECC stored non-sequentially in NFD Spare area    */
    ADI_NFC_ECC_MODE_SEQUENTIAL,            /* ECC stored sequentially in NFD Spare area        */
    ADI_NFC_ECC_MODE_DISABLE                /* Disable Error correction/Discard HW generated ECC*/
} ADI_NFC_ECC_MODE;

/*********************************************************************

Data structure to hold NAND Flash Device information

*********************************************************************/

/* Structure to hold NAND Flash Device parameters */
typedef struct ADI_NFD_INFO_TABLE
{
    u8                  tWPmin;             /* tWP Minimum (Write Enable Low to Write Enable High) value
                                               mentioned in NAND Flash device spec (in nano seconds)                        */
    u8                  tCSmin;             /* tCS Minimum (Chip Enable Low to Write Enable High) value
                                               mentioned in NAND Flash device spec (in nano seconds)                        */
    u8                  tRPmin;             /* tRP Minimum (Read Enable Low to Read Enable High/Read Enable Pulse Width) value
                                               mentioned in NAND Flash device spec (in nano seconds)                        */
    u8                  tREAmax;            /* tREA Maximum (Read Enable Low to Output Valid/Read Enable Access time) value
                                               mentioned in NAND Flash device spec (in nano seconds)                        */
    u8                  tCEAmax;            /* tCEA Maximum (Read Enable Low to Output Valid/Read Enable Access time) value
                                               mentioned in NAND Flash device spec (in nano seconds)                        */
    u16                 PageSize;           /* Page size (in bytes for x8, in words for x16)                                */
    u16                 DataAreaPerPage;    /* Data Area size per Page (in bytes for x8, in words for x16)                  */
    u16                 PagesPerBlock;      /* Number of pages per block                                                    */
    u16                 TotalBlocks;        /* Total blocks in this device(including invalid blocks)                        */
    ADI_NFC_NFD_TYPE    NFDType;            /* NAND Flash Device Type                                                       */
}ADI_NFD_INFO_TABLE;

/* NFD information table Example

static const ADI_NFD_INFO_TABLE  NFD_Info[] =
{
    // Information table for ST Microelectronics NAND02GW3B2C NAND Flash Device on ADSP-BF548 Ez-Kit Lite
    {
        15,                     // tWP Minimum value from NAND02GW3B2C spec (15 ns for 3V device)
        20,                     // tCS Minimum value from NAND02GW3B2C spec (20 ns for 3V device)
        15,                     // tRP Minimum value from NAND02GW3B2C spec (15 ns for 3V device)
        20,                     // tREA Maximum value from NAND02GW3B2C spec (20 ns for 3V device)
        25,                     // tCEA Maximum value from NAND02GW3B2C spec (25 ns for 3V device)
        2112,                   // Page Size (in bytes)
        2048,                   // Data Area size per page (in bytes)
        64,                     // Pages per Block
        2048,                   // Total Blocks in this device (including invalid blocks)
        ADI_NFD_LARGE_PAGE_x8,  // NFD type
    },

    // Information table for ST Microelectronics NAND04GW3B2BN6E NAND Flash Device on ADSP-BF527 Ez-Kit Lite
    {
        15,                     // tWP Minimum value from NAND04GW3B2BN6E spec (15 ns for 3V device)
        25,                     // tCS Minimum value from NAND04GW3B2BN6E spec (25 ns for 3V device)
        15,                     // tRP Minimum value from NAND04GW3B2BN6E spec (15 ns for 3V device)
        25,                     // tREA Maximum value from NAND04GW3B2BN6E spec (25 ns for 3V device)
        30,                     // tCEA Maximum value from NAND04GW3B2BN6E spec (30 ns for 3V device)
        2112,                   // Page Size (in bytes)
        2048,                   // Data Area size per page (in bytes)
        64,                     // Pages per Block
        4096,                   // Total Blocks in this device (including invalid blocks)
        ADI_NFD_LARGE_PAGE_x8,  // NFD type
    },

    // Information table for ST Microelectronics NAND02GR3B2CZAB NAND Flash Device on ADSP-BF526 Ez-Kit Lite
    {
        25,                     // tWP Minimum value from NAND02GR3B2CZAB spec  (25 ns for 1.8V device)
        35,                     // tCS Minimum value from NAND02GR3B2CZAB spec  (35 ns for 1.8V device)
        25,                     // tRP Minimum value from NAND02GR3B2CZAB spec  (25 ns for 1.8V device)
        30,                     // tREA Maximum value from NAND02GR3B2CZAB spec (30 ns for 1.8V device)
        45,                     // tCEA Maximum value from NAND02GR3B2CZAB spec (45 ns for 1.8V device)
        2112,                   // Page Size (in bytes)
        2048,                   // Data Area size per page (in bytes)
        64,                     // Pages per Block
        2048,                   // Total Blocks in this device (including invalid blocks)
        ADI_NFD_LARGE_PAGE_x8,  // NFD type
    },

};
*/

/*********************************************************************

Data Structure to set NFC DMA Frame buffer. It is not mandatory to
provide a DMA frame buffer, but doing so will improve NFC driver performance

Formula to calculate Number of DMA Frames
for a particular NFD = (NFD Data Size per page / NFD Data Packet size)
                     = (NFD Data Size per page / 256)

For example,
Number of DMA Frames required for NAND02GW3B2C NFD  = (2048 / 256) = 8.

DMA Frame memory size required for NAND02GW3B2C NFD = (ADI_NFC_DMA_DATA_FRAME_BASE_MEMORY * 8)

*********************************************************************/

/* Data structure to set NFC DMA Frame buffer */
typedef struct ADI_NFC_DMA_FRAME_BUFFER
{
    void    *pDMAFrameMemory;   /* Pointer to NFC DMA Data Frame memory allocated by the application    */
    u8      NumDMAFrames;       /* Number of NFC DMA Data Frames(must be = NFD Data Size per page / 256)*/
}ADI_NFC_DMA_FRAME_BUFFER;

/*********************************************************************

NFC Driver specific commands

*********************************************************************/

enum {                                                  /* NFC Command id's  */

    ADI_NFC_CMD_START = ADI_NFC_ENUMERATION_START,      /* 0x402E0000 - NFC driver enumuration start */


    ADI_NFC_CMD_PASS_NFD_INFO,                          /* 0x402E0001 - Pass NAND Flash Device specific information
                                                                        Value   = address of NFD Information table (ADI_NFD_INFO_TABLE type structure)
                                                                        Default = NULL. This Command is MANDATORY and MUST be issued soon after opening the driver
                                                        */

    ADI_NFC_CMD_SET_256BYTES_ALIGN_BUFFER,              /* 0x402E0002 - Pass address of 256 bytes buffer that can be used by the DMA to access NFD Spare Area and
                                                                        to align NFD Data Area to NFD Data Packet sized boundary (256 bytes)
                                                                        Value   = u8* (start address of a 256 bytes array)
                                                                        Default = NULL
                                                                        Note: This Command is MANDATORY for DMA based NFC access and
                                                                              MUST be issued before submitting a read / write buffer
                                                        */

    ADI_NFC_CMD_SET_DMA_FRAME_BUFFER,                   /* 0x402E0003 - Pass address of DMA Frame buffer that can be used to build descriptor chains to
                                                                        access a NFD page. It is not mandatory to provide DMA Frame buffer, but doing so
                                                                        will improve the NFC performance.
                                                                        Value   = ADI_NFC_DMA_FRAME_BUFFER * (address of a DMA Frame buffer structure)
                                                                        Default = NULL (Driver will use 1D buffer reserved area to build DMA descriptor)
                                                        */

    ADI_NFC_CMD_SET_ECC_MODE,                           /* 0x402E0004 - Set ECC storage mode
                                                                        Value   = ADI_NFC_ECC_MODE
                                                                        Default = ADI_NFC_ECC_MODE_DISABLE
                                                        */

    ADI_NFC_CMD_SET_ECC_START_LOC,                      /* 0x402E0005 - Set Nth byte/word of Data packet spare area that holds/to hold 1st byte/word of ECC
                                                                        Rest of the ECC bytes/words will be stored in N+1 and N+2 locations of NFD spare area
                                                                        Value   = u16
                                                                        Default = 0 (ECC read from/written to NFD spare area starting from byte/word 0)
                                                        */

    ADI_NFC_CMD_SEND_NFD_ACCESS_REQUEST,                /* 0x402E0006 - Send a NFD access request using Block/Page/Column address
                                                                        NFC Driver uses DMA to service this request
                                                                        Value   = address of ADI_NFD_ADDRESS type structure
                                                                        Default = NULL
                                                        */

    ADI_NFC_CMD_SEND_SECTOR_ACCESS_REQUEST,             /* 0x402E0007 - Send a NFD access request using physical sector number
                                                                        NFC Driver uses DMA to service this request
                                                                        Value   = u32 (start sector number to access)
                                                        */

    ADI_NFC_CMD_ERASE_NFD_BLOCK,                        /* 0x402E0008 - Command to Erase a NFD Block
                                                                        Value   = u16 (Block number to erase)
                                                        */

    ADI_NFC_CMD_READ_NFD_DIRECT,                        /* 0x402E0009 - Reads #bytes/#words from NFD starting from the given Block/Page/Column address
                                                                        NFC Driver reads NFD directly using NFC registers. DMA will not used to service this request
                                                                        Value   = address of ADI_NFD_DIRECT_ACCESS type structure
                                                        */

    ADI_NFC_CMD_WRITE_NFD_DIRECT,                       /* 0x402E000A - Writes #bytes/#words to NFD starting from the given Block/Page/Column address
                                                                        NFC Driver reads NFD directly using NFC registers. DMA will not used to service this request
                                                                        Value   = address of ADI_NFD_DIRECT_ACCESS type structure
                                                        */

    ADI_NFC_CMD_TERMINATE_NFD_ACCESS,                   /* 0x402E000B - Terminate all NFC/NFD related access requests in progress
                                                                        Value   = NULL
                                                        */

    ADI_NFC_CMD_GET_NFD_STATUS,                         /* 0x402E000C - Get NFD status register value
                                                                        Value   = u8* (location to store status register value read from NFD)
                                                        */

    ADI_NFC_CMD_GET_NFD_ELECTRONIC_SIGNATURE,           /* 0x402E000D - Get NFD Electronic signature
                                                                        Value   = u32* (location to store Electronic signature read from NFD)
                                                        */

    ADI_NFC_CMD_GET_NFD_INFO,                           /* 0x402E000E - Get address of a structure holding NAND Flash Device specific information
                                                                        Value   = ADI_NFD_INFO_TABLE * (location to store address of NFD Information table)
                                                        */
    ADI_NFC_CMD_GET_ELEMENT_SIZE                        /* 0x402E000D - Get NFD Data ELEMENT Size
                                                                        Value   = u32* (location to store size of data element)
                                                        */

};

/*********************************************************************

Enumerations for NFC Driver return codes

*********************************************************************/

enum {                                                  /* NFC Driver return codes                                                                  */
    ADI_NFC_RESULT_START = ADI_NFC_ENUMERATION_START,   /* 0x402E0000 - NFC driver enumuration start                                                */
    ADI_NFC_RESULT_CMD_NOT_SUPPORTED,                   /* 0x402E0001 - Command not supported by this driver                                        */
    ADI_NFC_RESULT_NFD_UNDEFINED,                       /* 0x402E0002 - NAND Flash Device type is undefined                                         */
    ADI_NFC_RESULT_NFD_NOT_SUPPORTED,                   /* 0x402E0003 - Driver does not support this NAND Flash Device type                         */
    ADI_NFC_RESULT_NFD_ACCESS_IN_PROGRESS,              /* 0x402E0004 - Results when client issues as NFD access request
                                                                        before the previous request gets serviced                                   */
    ADI_NFC_RESULT_NFD_ADDRESS_OUT_OF_BOUNDARY,         /* 0x402E0005 - Block/Page/Column address or Sector number issued by
                                                                        the client exceeds NAND Flash Device Memory size                            */
    ADI_NFC_RESULT_NFD_DATA_ERROR,                      /* 0x402E0006 - Detected an uncorrectable error with data read from NFD                     */
    ADI_NFC_RESULT_NO_ALIGNMENT_BUFFER                  /* 0x402E0007 - Results when client tries to perform a DMA based NFC access without
                                                                        providing a 256-bytes buffer for Spare Area Access & NFD Packet Alignment   */
};

/*********************************************************************

Enumerations for NFC Driver Events

*********************************************************************/

enum {                                                      /* NFC Driver Events                            */
    ADI_NFC_EVENT_START = ADI_NFC_ENUMERATION_START         /* 0x402E0000 - NFC driver enumuration start    */
};

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /* __ADI_NFC_H__ */

/*****/
