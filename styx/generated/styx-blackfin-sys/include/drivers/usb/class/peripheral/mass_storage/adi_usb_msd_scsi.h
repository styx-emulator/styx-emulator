/*********************************************************************************

Copyright(c) 2007 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_msd_scsi.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:

    This is the SCSI protocol header file for USB Mass Storage
    Class Driver.

*********************************************************************************/

#ifndef _ADI_USB_MSD_SCSI_H_
#define _ADI_USB_MSD_SCSI_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* SCSI-2 MEDIUM TYPES */
#define SCSI_MEDIUM_UNKNOWN             0xFF

/* MANDATORY SCSI-2 COMMANDS */
#define SCSI_TEST_UNIT_READY            0x00
#define SCSI_REQUEST_SENSE              0x03
#define SCSI_INQUIRY                    0x12
#define SCSI_SEND_DIAGNOSTIC            0x1D

/* DEVICE SPECIFIC SCSI-2COMMANDS */
#define SCSI_MODE_SELECT6               0x15
#define SCSI_MODE_SENSE6                0x1A
#define SCSI_START_STOP                 0x1B
#define SCSI_MEDIUM_REMOVAL             0X1E
#define SCSI_READ_CAPACITY              0x25
#define SCSI_READ10                     0x28
#define SCSI_WRITE10                    0x2A
#define SCSI_VERIFY                     0x2F
#define SCSI_MODE_SELECT10              0x55
#define SCSI_MODE_SENSE10               0x5A

/* SCSI MMC Commands */
#define SCSI_READ_FORMAT_CAPACITIES     0x23

/* Mode Pages */
#define MODE_PAGE_FLEXIBLE_DISK         0x05
#define MODE_PAGE_CDROM                 0x0D
#define MODE_PAGE_CDROM_AUDIO           0x0E
#define MODE_PAGE_CDROM_CAPS            0x2A

/* SCSI-2 SENSE KEYS */
#define SENSE_NONE                      0x00
#define SENSE_RECOVERED_ERROR           0x01
#define SENSE_NOT_READY                 0x02
#define SENSE_MEDIUM_ERROR              0x03
#define SENSE_HARDWARE_ERROR            0x04
#define SENSE_ILLEGAL_REQUEST           0x05
#define SENSE_UNIT_ATTENTION            0x06
#define SENSE_DATA_PROTECT              0x07
#define SENSE_BLANK_CHECK               0x08
#define SENSE_ABORTED_COMMAND           0x0B

/* SCSI-2 ASC (of interest) */
#define ASC_NONE                        0x00
#define ASC_INVALID_COMMAND             0x20
#define ASC_WRITE_ERROR                 0x0C
#define ASC_INVALID_FIELD_IN_CDB        0x24
#define ASC_PARAMETER_VALUE_INVALID     0X26
#define ASC_WRITE_PROTECTED             0x27
#define ASC_MEDIA_CHANGED               0x28
#define ASC_RESET                       0x29
#define ASC_COMMANDS_CLEARED            0x2F
#define ASC_MEDIUM_NOT_PRESENT          0x3A
#define ASC_SCSI_PARITY_ERROR           0x47

#define SCSI_COMMAND_BLOCK_SIZE_6       6
#define SCSI_COMMAND_BLOCK_SIZE_10      10

/* Inquiry defines */

#define SCSI_DEVICE_DIRECT_ACCESS       0x00    /* Direct Access Device */
#define REMOVABLE_DEVICE                0x80    /* Removable */
#define SPC_2                           0x04    /* SPC-2 compliance */
#define SPC_3                           0x05    /* SPC-3 compliance */
#define RESPONCE_FORMAT                 0x02    /* Responce data format */
#define RESPONCE_SIZE                   0x20    /* Responce has 20+4 bytes */

/* SCSI function prototypes */
u32 SCSI_Init(void);

/* External SCSI functions */

extern u32  SCSI_Init(void);
extern bool SCSI_IsValidCommandBlock (u8 * pCommandBlock, u8 len);
extern bool SCSI_ProcessCDB (u8 * pCommandBlock, u8 len, u32 datalen, void *pBuffer, u32 *pActualBytesToReturn);
extern void SCSI_ProcessData (void *pBuffer, u32 len);

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_MSD_SCSI_H_ */
