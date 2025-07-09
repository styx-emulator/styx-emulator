/*********************************************************************************

Copyright(c) 2007 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_msd_class.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:

    This is the header file for USB Mass Storage
    Class Driver (Device Mode).

*********************************************************************************/

#ifndef _ADI_USB_MSD_CLASS_H_
#define _ADI_USB_MSD_CLASS_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#define MSD_ASSERT(x) do {                                                   \
            if(x) {                                                          \
            printf("Assertion Failed at line %d in %s\n",                    \
                __LINE__,__FILE__); fflush(NULL); asm("emuexcpt;"); }        \
            }while(0)

/* NET2272 specific peripheral settings */
#ifdef _ADI_USB_NET2272_CONTROLLER_
#include <drivers\usb\controller\peripheral\plx\net2272\adi_usb_net2272.h>
#endif


/* BF54x specific peripheral settings */
#ifdef _ADI_USB_MOAB_CONTROLLER_

#include <drivers/usb/controller/otg/adi/hdrc/adi_usb_hdrc.h>
#endif

#include <drivers/pid/adi_rawpid.h>

#define EndianSwap(someVal) \
    (u32)(((someVal & 0xff000000) >> 24) | ((someVal & 0x00ff0000) >> 8) | ((someVal & 0x0000ff00) << 8) | ((someVal & 0x000000ff) << 24))

#define     ADI_MSD_CLUSTER_SIZE    4096

#define     MAX_USB_PKT_BUFFERS     1
#define     MAX_USB_PKT_SIZE        512
#define     MAX_USB_BUFFERS            1
#define     MSD_SERIAL_NUMBER       "123456789012"


/* Mass Storage Class Sub-Types */
#define USB_ATPI_CD_DVD             0x02
#define USB_QIC_157_TAPE            0x03
#define USB_FLOPPY                  0x04
#define USB_ATPI_REMOVABLE          0x05
#define USB_GENERIC_SCSI            0x06

/* Mass Storage Class Protocol Types */
#define USB_CBI_WITH_COMPLETION     0x00
#define USB_CBI_WITHOUT_COMPLETION  0x01
#define USB_BULK_ONLY               0x50

/*********************************************************************************
    bmAttributes field in Configuration Descriptor:
    - See USB 2.0: Table 9-10, bmAttributes:
*********************************************************************************/

#define CONFIG_ATTRIBUTES           ((1<<7) | \
                                    (1<<CONFIG_SELF_POWERED))

/* Maximum packet size of Endpoint Zero */
#define EP0_MAX_PACKET_SIZE         64

/* Data End Point Packet Size */
#define HS_EP_PKT_SIZE              512
#define FS_EP_PKT_SIZE              64

/*********************************************************************************
    bmAttribute bits in Configuration Descriptor
    - USB 2.0 9.6.3 (bmAttributes in Table 9-10): Bit 7 is reserved, and always set to one
*********************************************************************************/

#define CONFIG_SELF_POWERED         6
#define CONFIG_REMOTE_WAKEUP        5    /* Not to be confused with Device Remote Wakeup feature selector! */

/*********************************************************************************/

#define    MAX_INTERFACES              1
#define MAX_ENDPOINTS               2
#define MAX_ALTINTERFACES           2

#define MAX_LUN                     0

#define MASS_STORAGE_INTERFACE_NUM  0

/* Generic object info. structure */
typedef struct ObjectInfo
{
    s32 ID;
    void *pObj;
}OBJECT_INFO,*POBJECT_INFO;

/* Mass Storage Device data structure */
typedef struct MassStorageDeviceData
{
    ADI_DEV_DEVICE_HANDLE   DeviceHandle;
    ADI_DMA_MANAGER_HANDLE  DMAHandle;
    ADI_DCB_CALLBACK_FN     DMCallback;
    ADI_DCB_HANDLE          DCBHandle;
    bool                    Open;
    bool                    Started;
    ADI_DEV_DIRECTION       Direction;
    void                    *CriticalData;
    ADI_DEV_DEVICE_HANDLE   PeripheralDevHandle;
    s32                     DeviceID;
    OBJECT_INFO             ConfigObject;
    OBJECT_INFO             InterfaceObjects[MAX_INTERFACES];
    OBJECT_INFO             AltInterfaceObjects[MAX_ALTINTERFACES];
    OBJECT_INFO             EndPointObjects[MAX_ENDPOINTS];
    OBJECT_INFO             OSConfigObject;
    OBJECT_INFO             OSInterfaceObjects[MAX_INTERFACES];
    OBJECT_INFO             OSEndPointObjects[MAX_ENDPOINTS];
    int                        busSpeed;
    u32                        SCSIReadCmd;
    u32                        SCSIWriteCmd;
    u32                        PIDWrite;
    u32                        PIDRead;
    ADI_DEV_1D_BUFFER         * PIDWriteBuffer;
    u32                     WriteIndex;
    u32                     ReadIndex;
    ADI_RAWPID_MEDIA_INFO   MediaInfo;
    u32                     nClientBufferElementCount;
    ADI_DEV_1D_BUFFER       *pClientBuffer;

}ADI_USB_DEV_DEF;

#define USBMS_REQUEST_RESET         0xff
#define USBMS_REQUEST_GET_MAX_LUN     0xfe

/*********************************************************************************
    Command Block Wrapper Defines
*********************************************************************************/

#define CBW_LENGTH                                 0x1f
#define CBW_SIGNATURE                             0x43425355
#define CBW_SIGNATURE_OFFSET                     0
#define CBW_SIGNATURE_LEN                         4
#define CBW_TAG_OFFSET                             4
#define CBW_TAG_LEN                             4
#define CBW_DATA_TRANSFER_LENGTH_OFFSET         8
#define CBW_DATA_TRANSFER_LENGTH_LEN             4
#define CBW_FLAGS_OFFSET                         12
#define CBW_FLAGS_LEN                             1
#define CBW_LUN_OFFSET                             13
#define CBW_LUN_LEN                             1
#define CBW_WCBLENGTH_OFFSET                     14
#define CBW_WCBLENGTH_LEN                         1
#define CBW_WCB_OFFSET                             15
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

#define CBW_FLAG_DATA_FROM_HOST_TO_DEVICE         0x00
#define CBW_FLAG_DATA_FROM_DEVICE_TO_HOST         0x80

/*********************************************************************************
    Command Status Wrapper defines
*********************************************************************************/

#define CSW_SIZE                                 13
#define MAX_CSW_BUFFERS                            1

#define CSW_LENGTH                                 0x0d
#define CSW_SIGNATURE                             0x53425355
#define CSW_SIGNATURE_OFFSET                     0
#define CSW_SIGNATURE_LEN                         4
#define CSW_TAG_OFFSET                             4
#define CSW_TAG_LEN                             4
#define CSW_DATA_RESIDUE_OFFSET                 8
#define CSW_DATA_RESIDUE_LEN                     4
#define CSW_STATUS_OFFSET                         12
#define CSW_STATUS_LEN                             1

#define CSW_STATUS_COMMAND_PASSED                 0x00
#define CSW_STATUS_COMMAND_FAILED                 0x01
#define CSW_STATUS_COMMAND_PHASE_ERROR             0x02

/* Command Status Wrapper (CSW) */
typedef struct tagCSW{
    u32 signature;
    u32 tag;
    u32 dataResidue;
    u8  status;
}CSW, *PCSW;

/*********************************************************************************/

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

#if defined(ADI_MSD_TEST)
typedef struct tagUSBcb
{
    u32     Command;
    void *  Data;
}USBcb, *pUSBcb;
#endif

#define ADI_USB_MSD_CMD_SET_MEMORY_SIZE            (ADI_USB_MSD_ENUMERATION_START + 0x00000001)
#define ADI_USB_MSD_CMD_SCSI_INIT                (ADI_USB_MSD_ENUMERATION_START + 0x00000002)
#define ADI_USB_MSD_CMD_INIT_RAW_PID            (ADI_USB_MSD_ENUMERATION_START + 0x00000003)
#define ADI_USB_MSD_CMD_IS_DEVICE_CONFIGURED    (ADI_USB_MSD_ENUMERATION_START + 0x00000004)
#define ADI_USB_MSD_CMD_SET_VID                    (ADI_USB_MSD_ENUMERATION_START + 0x00000005)
#define ADI_USB_MSD_CMD_SET_PID                    (ADI_USB_MSD_ENUMERATION_START + 0x00000006)
#define ADI_USB_MSD_CMD_SET_SERIAL_NUMBER        (ADI_USB_MSD_ENUMERATION_START + 0x00000007)
#define ADI_USB_MSD_CMD_ENUMERATE_ENDPOINTS     (ADI_USB_MSD_ENUMERATION_START + 0x00000008)
#define ADI_USB_MSD_CMD_SET_BUFFER                (ADI_USB_MSD_ENUMERATION_START + 0x00000009)
#define ADI_USB_MSD_CMD_REGISTER_FSSPID         (ADI_USB_MSD_ENUMERATION_START + 0x0000000A)
#define ADI_USB_MSD_CMD_DEREGISTER_FSSPID       (ADI_USB_MSD_ENUMERATION_START + 0x0000000B)

#define _WRITE_ 0
#define _READ_    1

/*********************************************************************************/

/* Externals */
extern    COMMAND_STATUS_STATE      adi_msd_CommandStatusState;
extern    bool                       adi_msd_IsTransferActive;

extern void EndpointZeroCompleteCallback( void *Handle, u32  Event, void *pArg);
extern void EndpointCompleteCallback(void *Handle, u32  Event, void *pArg);
extern void Device_To_Host_TransferComplete(void *Handle, u32 Event, void *pBuf);
extern void Host_To_Device_TransferComplete(void *Handle, u32 Event, void *pBuf);

/* Entry point to MSD Class driver (Devive Mode) */
extern ADI_DEV_PDD_ENTRY_POINT ADI_USB_Device_MassStorageClass_Entrypoint;

/* Entry point to the USB device driver */
extern     ADI_DEV_PDD_ENTRY_POINT ADI_USB_NET2272_Entrypoint;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_MSD_CLASS_H_ */
