/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_nand.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the include file for the ADI NAND Flash controller PID

***********************************************************************/

#ifndef __ADI_NAND_H__
#define __ADI_NAND_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers/nfc/adi_nfc.h>

/*********************************************************************

Entry point to the USB PID

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADI_NAND_Entrypoint;

/*********************************************************************

NAND Driver specific control commands

*********************************************************************/

enum {
    ADI_NAND_CMD_START = ADI_PID_CUSTOM_CMD_START,       /* (0x000AA000) */
    ADI_NAND_CMD_SET_NFC_HANDLE,
    ADI_NAND_CMD_SET_RESERVED_SIZE,
    ADI_NAND_CMD_SET_NFD_INFO,
    ADI_NAND_CMD_SET_RAMDISK_START_LOCATION,
    ADI_NAND_CMD_SET_MBR,
    ADI_NAND_CMD_PREPARE_NFD_FOR_FTL,
    ADI_NAND_CMD_SET_SECTOR_SIZE
};

/* The following is omitted when included in the driver source module */
#if !defined(__ADI_NAND_HOST_C__)

/* The following is omitted when included in the driver source module */

/*********************************************************************

The following is the default configuration for the USB driver.
To use, define the _ADI_NAND_DEFAULT_DEF_ macro in the enclosing file

*********************************************************************/
/* Information table for ST Microelectronics NAND04GW3B2BN6E NAND Flash Device on ADSP-BF527 Ez-Kit Lite */
#if defined(__ADSP_KOOKABURRA__)
#if 0
extern const ADI_NFD_INFO_TABLE  ADI_EZKIT_NFD_Info =
{
    15,                     /* tWP Minimum value from NAND04GW3B2BN6E spec  (15 ns for 3V device)   */
    25,                     /* tCS Minimum value from NAND04GW3B2BN6E spec  (25 ns for 3V device)   */
    15,                     /* tRP Minimum value from NAND04GW3B2BN6E spec  (15 ns for 3V device)   */
    25,                     /* tREA Maximum value from NAND04GW3B2BN6E spec (25 ns for 3V device)   */
    30,                     /* tCEA Maximum value from NAND04GW3B2BN6E spec (30 ns for 3V device)   */
    2112,                   /* Page Size (in bytes)                                                 */
    2048,                   /* Data Area size per page (in bytes)                                   */
    64,                     /* Pages per Block                                                      */
    4096,                   /* Total Blocks in this device (including invalid blocks)               */
    ADI_NFD_LARGE_PAGE_x8,  /* NFD type                                                             */
};
#else
extern const ADI_NFD_INFO_TABLE  ADI_EZKIT_NFD_Info =
{
    20,                     /* tWP Minimum value from NAND04GW3B2BN6E spec  (15 ns for 3V device)   */
    25,                     /* tCS Minimum value from NAND04GW3B2BN6E spec  (25 ns for 3V device)   */
    15,                     /* tRP Minimum value from NAND04GW3B2BN6E spec  (15 ns for 3V device)   */
    25,                     /* tREA Maximum value from NAND04GW3B2BN6E spec (25 ns for 3V device)   */
    30,                     /* tCEA Maximum value from NAND04GW3B2BN6E spec (30 ns for 3V device)   */
    2112,                   /* Page Size (in bytes)                                                 */
    2048,                   /* Data Area size per page (in bytes)                                   */
    64,                     /* Pages per Block                                                      */
    4096,                   /* Total Blocks in this device (including invalid blocks)               */
    ADI_NFD_LARGE_PAGE_x8,  /* NFD type                                                             */
};
#endif

#endif  /* __ADSP_KOOKABURRA__ */

#if defined(__ADSP_MOCKINGBIRD__)

extern const ADI_NFD_INFO_TABLE  ADI_EZKIT_NFD_Info =
{
    25,                     /* tWP Minimum value from NAND02GR3B2CZAB spec  (25 ns for 1.8V device)   */
    35,                     /* tCS Minimum value from NAND02GR3B2CZAB spec  (35 ns for 1.8V device)   */
    25,                     /* tRP Minimum value from NAND02GR3B2CZAB spec  (25 ns for 1.8V device)   */
    30,                     /* tREA Maximum value from NAND02GR3B2CZAB spec (30 ns for 1.8V device)   */
    45,                     /* tCEA Maximum value from NAND02GR3B2CZAB spec (45 ns for 1.8V device)   */
    2112,                   /* Page Size (in bytes)                                                   */
    2048,                   /* Data Area size per page (in bytes)                                     */
    64,                     /* Pages per Block                                                        */
    2048,                   /* Total Blocks in this device (including invalid blocks)                 */
    ADI_NFD_LARGE_PAGE_x8,  /* NFD type                                                               */
};

#endif  /* __ADSP_MOCKINGBIRD__*/

/* Information table for ST Microelectronics NAND02GW3B2C NAND Flash Device on ADSP-BF548 Ez-Kit Lite */
#if defined(__ADSP_MOAB__)

extern const ADI_NFD_INFO_TABLE  ADI_EZKIT_NFD_Info =
{
    15,                     /* tWP Minimum value from NAND02GW3B2C spec  (15 ns for 3V device)  */
    20,                     /* tCS Minimum value from NAND02GW3B2C spec  (20 ns for 3V device)  */
    15,                     /* tRP Minimum value from NAND02GW3B2C spec  (15 ns for 3V device)  */
    20,                     /* tREA Maximum value from NAND02GW3B2C spec (20 ns for 3V device)  */
    25,                     /* tCEA Maximum value from NAND02GW3B2C spec (25 ns for 3V device)  */
    2112,                   /* Page Size (in bytes)                                             */
    2048,                   /* Data Area size per page (in bytes)                               */
    64,                     /* Pages per Block                                                  */
    2048,                   /* Total Blocks in this device (including invalid blocks)           */
    ADI_NFD_LARGE_PAGE_x8,  /* NFD type                                                         */
};

#endif  /* __ADSP_MOAB__ */

#if defined(_ADI_NAND_DEFAULT_DEF_)

static ADI_DEV_CMD_VALUE_PAIR ADI_NAND_ConfigurationTable [] = {
    { ADI_NAND_CMD_SET_NFD_INFO,                  (void *)&ADI_EZKIT_NFD_Info },  /* NFD Information table    */
    { ADI_DEV_CMD_END,                       NULL     },
};

static ADI_FSS_DEVICE_DEF ADI_NAND_Def = {
    0,                                          /* Not Applicable                           */
    &ADI_NAND_Entrypoint,                    /* Entry Points for Driver                  */
    ADI_NAND_ConfigurationTable,             /* Command Table to configure USB Driver    */
    NULL,                                       /* Critical region data                     */
    ADI_DEV_DIRECTION_BIDIRECTIONAL,            /* Direction (RW media)                     */
    NULL                                        /* Device Handle                            */
};

#endif /* _ADI_NAND_DEFAULT_DEF_ */

#endif /* __ADI_NAND_HOST_C__ */


#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif      /* __ADI_NAND_H__   */
