/*********************************************************************************

Copyright(c) 2007 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_msd_class_host.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:

    This is the header file for USB Mass Storage
    Class Driver (Host Mode).

*********************************************************************************/

#ifndef _ADI_USB_MSD_CLASS_HOST_H_
#define _ADI_USB_MSD_CLASS_HOST_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers/usb/controller/otg/adi/hdrc/adi_usb_hdrc.h>

#define MSD_ASSERT(x) do {                                                  \
            if(x) {                                                         \
            printf("Assertion Failed at line %d in %s\n",                   \
                __LINE__,__FILE__); fflush(NULL); asm("emuexcpt;"); }       \
            }while(0)

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
#define SCSI_FORMAT_CAPACITIES_CURMAX_DESC_SIZE 8


#define SCSI_COMMAND_BLOCK_SIZE_6       6
#define SCSI_COMMAND_BLOCK_SIZE_10      10

#define RESPONCE_SIZE                   0x24

/* SCSI Command TAGS */
#define TAG_REQ_SENSE                   0x41444903
#define TAG_READ10                      0x41444928
#define TAG_WRITE10                     0x4144492A
#define TAG_INQUIRY                     0x41444912
#define TAG_TEST_UNIT_READY             0x41444900
#define TAG_READ_FORMAT_CAPACITIES      0x41444923
#define TAG_READ_CAPACITY               0x41444925
#define TAG_MODE_SENSE6                 0x4144491A

#define ADI_USB_MSD_CMD_IS_DEVICE_ENUMERATED        (ADI_USB_MSD_ENUMERATION_START + 0x00000050)
#define ADI_USB_MSD_CMD_SCSI_READ10                 (ADI_USB_MSD_ENUMERATION_START + 0x00000051)
#define ADI_USB_MSD_CMD_SCSI_WRITE10                (ADI_USB_MSD_ENUMERATION_START + 0x00000052)
#define ADI_USB_MSD_CMD_INQUIRY                     (ADI_USB_MSD_ENUMERATION_START + 0x00000053)
#define ADI_USB_MSD_CMD_TEST_UNIT_READY             (ADI_USB_MSD_ENUMERATION_START + 0x00000054)
#define ADI_USB_MSD_CMD_READ_FORMAT_CAPACITIES      (ADI_USB_MSD_ENUMERATION_START + 0x00000055)
#define ADI_USB_MSD_CMD_READ_CAPACITY               (ADI_USB_MSD_ENUMERATION_START + 0x00000056)
#define ADI_USB_MSD_CMD_MODE_SENSE6                 (ADI_USB_MSD_ENUMERATION_START + 0x00000057)
#define ADI_USB_MSD_DISABLE_LDEB2_URGENT            (ADI_USB_MSD_ENUMERATION_START + 0x00000059)
#define ADI_USB_MSD_CMD_REQ_SENSE                   (ADI_USB_MSD_ENUMERATION_START + 0x0000005A)
#define ADI_USB_MSD_CMD_GET_FORMAT_CAPACITIES_DATA  (ADI_USB_MSD_ENUMERATION_START + 0x0000005B)
#define ADI_USB_MSD_CMD_GET_CAPACITY_TEN_DATA       (ADI_USB_MSD_ENUMERATION_START + 0x0000005C)

#define ADI_USB_MSD_EVENT_INQUIRY_COMPLETE                  (ADI_USB_MSD_ENUMERATION_START + 0x00000070)
#define ADI_USB_MSD_EVENT_READ_FORMAT_CAPACITY_COMPLETE     (ADI_USB_MSD_ENUMERATION_START + 0x00000071)
#define ADI_USB_MSD_EVENT_READ_CAPACITY_COMPLETE            (ADI_USB_MSD_ENUMERATION_START + 0x00000072)
#define ADI_USB_MSD_EVENT_TEST_UNIT_READY_COMPLETE          (ADI_USB_MSD_ENUMERATION_START + 0x00000073)
#define ADI_USB_MSD_EVENT_MODE_SENSE6_COMPLETE              (ADI_USB_MSD_ENUMERATION_START + 0x00000074)
#define ADI_USB_MSD_EVENT_REQ_SENSE_COMPLETE                (ADI_USB_MSD_ENUMERATION_START + 0x00000075)
#define ADI_USB_MSD_EVENT_SCSI_CMD_ERROR                    (ADI_USB_MSD_ENUMERATION_START + 0x00000076)
#define ADI_USB_MSD_EVENT_SCSI_CMD_COMPLETE                 (ADI_USB_MSD_ENUMERATION_START + 0x00000077)
#define ADI_USB_MSD_EVENT_CSW_PHASE_ERROR               (ADI_USB_MSD_ENUMERATION_START + 0x00000078)
#define ADI_USB_MSD_EVENT_CSW_GARBLED_ERROR                 (ADI_USB_MSD_ENUMERATION_START + 0x00000079)


#define EndianSwap(someVal) \
    (u32)(((someVal & 0xff000000) >> 24) | ((someVal & 0x00ff0000) >> 8) | ((someVal & 0x0000ff00) << 8) | ((someVal & 0x000000ff) << 24))

typedef struct SCSICommandBlockStruct
{
    u32 LBASector;
    u16 BlockSize;
}ADI_USB_MSD_SCSI_CMD_BLOCK;

/* Define device Mass Storage Device states */
typedef enum {
    STATE_IDLE = 0,
    STATE_WAITFOR_CBW,
    STATE_WAITFOR_DATA,
    STATE_SEND_DATA,
    STATE_EP_FOR_IN_STALLED,
    STATE_CSW_SENT,
    STATE_CBW_SENT,
    STATE_WAITFOR_CSW
}COMMAND_STATUS_STATE;

/* Define MSD class specific commands */
typedef enum {
    CS_NONE = 0,
    CS_GET_MAX_LUN,
    CS_BULK_RESET
}CLASS_SPECIFIC_COMMAND;

typedef struct ObjectInfo
{
    s32 ID;
    void *pObj;
}OBJECT_INFO,*POBJECT_INFO;

typedef struct {
    u8 NumItems;
    u8 DescriptorType;
    u32 NumBlocks;
    u32 BlockSize;
} SCSI_FORMAT_CAPACITIES_DEF;

typedef struct {
    u32 NumBlocks;
    u32 BlockSize;
} SCSI_CAPACITY_10_DEF;


/* Mass Storage Device data structure */
typedef struct MassStorageDeviceData
{
    ADI_DEV_DEVICE_HANDLE   DeviceHandle;
    ADI_DMA_MANAGER_HANDLE  DMAHandle;
    ADI_DCB_CALLBACK_FN     DMCallback;

    ADI_DCB_HANDLE          DCBHandle;
    ADI_DEV_DIRECTION       Direction;
    void                    *CriticalData;

    ADI_DEV_DEVICE_HANDLE   PeripheralDevHandle;
    s32                     DeviceID;
    u32                     DeviceNumber;

    ADI_DEV_MANAGER_HANDLE  ManagerHandle;
    ADI_DEV_PDD_HANDLE      *pPDDHandle;

    volatile    u32         TransferComplete;
    volatile    u32         DeviceConfigured;

    ADI_DEV_1D_BUFFER       *pBuffer;

    ADI_DEV_BUFFER          *pCurrentBuffer;

    u32                     dwCBWTransferLength;

    u32                     dwDataNotProcessedLength;

    volatile    u32         dwDeviceStalled;
    volatile    u32         dwDataPhase;

    COMMAND_STATUS_STATE    CommandState;
    CLASS_SPECIFIC_COMMAND  CSCommand;

    u32                     SCSICommandSent;

    u32                     RemainingDataToComeIn;
    u32                     RemainingDataToSend;

    u8                      HostOutEP;
    u8                      HostInEP;

    u32                     TransferLength;

    ADI_USB_HDRC_DMA_CONFIG dmaConfig;

    SCSI_FORMAT_CAPACITIES_DEF FormatCapacities;
    SCSI_CAPACITY_10_DEF       CapacityTen;

}ADI_USB_DEV_DEF;

/* Enumerators for ATA devices for Master (0), Slave (1) devices on chain */
enum {
    PDD_DEVICE_TYPE_NONE=0,
    PDD_DEVICE_TYPE_UNKNOWN,
    PDD_DEVICE_TYPE_ATA,
    PDD_DEVICE_TYPE_ATAPI
};

/*********************************************************************************
    Command Block Wrapper Defines
*********************************************************************************/

#define CBW_LENGTH                              0x1f
#define CBW_SIGNATURE                           0x43425355
#define CBW_SIGNATURE_OFFSET                    0
#define CBW_SIGNATURE_LEN                       4
#define CBW_TAG_OFFSET                          4
#define CBW_TAG_LEN                             4
#define CBW_DATA_TRANSFER_LENGTH_OFFSET         8
#define CBW_DATA_TRANSFER_LENGTH_LEN            4
#define CBW_FLAGS_OFFSET                        12
#define CBW_FLAGS_LEN                           1
#define CBW_LUN_OFFSET                          13
#define CBW_LUN_LEN                             1
#define CBW_WCBLENGTH_OFFSET                    14
#define CBW_WCBLENGTH_LEN                       1
#define CBW_WCB_OFFSET                          15
#define CBW_WCB_LEN                             16

/* Command Block Wrapper (CBW) */
typedef struct tagCBW{
    u32 signature;
    u32 tag;
    u32 dataTransferLength;
    u8  flags;
    u8  lun;
    u8  wcbLength;
    u8  wcb[CBW_WCB_LEN];
}CBW, *PCBW;

#define CBW_FLAG_DATA_FROM_HOST_TO_DEVICE       0x00
#define CBW_FLAG_DATA_FROM_DEVICE_TO_HOST       0x80

/*********************************************************************************
    Command Status Wrapper defines
*********************************************************************************/

#define CSW_SIZE                                13
#define MAX_CSW_BUFFERS                         1

#define CSW_LENGTH                              0x0d
#define CSW_SIGNATURE                           0x53425355
#define CSW_SIGNATURE_OFFSET                    0
#define CSW_SIGNATURE_LEN                       4
#define CSW_TAG_OFFSET                          4
#define CSW_TAG_LEN                             4
#define CSW_DATA_RESIDUE_OFFSET                 8
#define CSW_DATA_RESIDUE_LEN                    4
#define CSW_STATUS_OFFSET                       12
#define CSW_STATUS_LEN                          1

#define CSW_STATUS_COMMAND_PASSED               0x00
#define CSW_STATUS_COMMAND_FAILED               0x01
#define CSW_STATUS_COMMAND_PHASE_ERROR          0x02

/* Command Status Wrapper (CSW) */
typedef struct tagCSW{
    u32 signature;
    u32 tag;
    u32 dataResidue;
    u8  status;
}CSW, *PCSW;

#define     NUM_PHYSICAL_ENDPOINTS  7
#define     MAX_USB_PKT_SIZE        512

typedef struct ActiveEPList
{
    u8  Active_EP[NUM_PHYSICAL_ENDPOINTS];
    u8  direction[NUM_PHYSICAL_ENDPOINTS];
}ACTIVE_EP_LIST,*PACTIVE_EP_LIST;

#define CLASS_REQUEST_TYPE                  0xA1
#define CLASS_REQUEST_GET_MAX_LUN           0xFE

#define CLASS_REQUEST_TYPE_RESET            0x21
#define CLASS_REQUEST_MS_BULK_RESET         0xFF

#define STD_REQ_TYPE                        0x02
#define STD_REQ_CLEAR_FEATURE               0x01

typedef struct StdRequestruct
{
    u8  bRequestType;
    u8  bRequest;
    u16 wValue;
    u16 wIndex;
    u16 wLength;
}ADI_USB_MSD_STD_REQ_CMD_BLOCK;

/* Entry point to MSD Class driver (Host Mode) */
extern ADI_DEV_PDD_ENTRY_POINT ADI_USB_Host_MassStorageClass_Entrypoint;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
