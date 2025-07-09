/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_core.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
             Header file for USB core layer.

*********************************************************************************/

#ifndef _ADI_USB_CORE_H_
#define _ADI_USB_CORE_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers\usb\usb_core\adi_usb_objects.h>

/* TODO: These values should be configurable. */
#define USB_MAX_DEVICES         2
#define USB_MAX_CONFIGURATIONS  3
#define USB_MAX_INTERFACES      8
#define USB_MAX_ENDPOINTS       16 /* logical endpoints */
#define USB_MAX_STRINGS         8

/* APIs provided by the USB core layer to the class drivers */
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
typedef enum  DevMode
{
  MODE_NONE=-1,
  MODE_DEVICE,
  MODE_OTG_HOST
}DEV_MODE;

/* Physical endpoint information is specific to the underlying controller and its
 * used to pass additional low level information about endpoint (such as FIFO size etc)
 * to the core. This information is used by the core during CreateEndpoint for the
 * best possible match.
 */
typedef struct PhysicalEpInfo
{
  s32_t  dwEpFifoSize;
}PHYSICAL_EP_INFO;

/* Logical endpoint information is supplied by the class drivers while creating the endpoint
 * objects. This information is used by the core to allocate the best possible match.
 */
typedef struct LogicalEpInfo
{
  s32_t  dwMaxEndpointSize;
  s32_t  dwConfigurationID;
}LOGICAL_EP_INFO;

typedef enum UsbObjectType
{
  USB_DEVICE_OBJECT_TYPE=0,
  USB_CONFIGURATION_OBJECT_TYPE,
  USB_INTERFACE_OBJECT_TYPE,
  USB_ENDPOINT_OBJECT_TYPE
}USB_OBJECT_TYPE;

s32_t adi_usb_CreateConfiguration(PCONFIG_OBJECT *pCf);
s32_t adi_usb_CreateInterface(PINTERFACE_OBJECT *pIf);
s32_t adi_usb_CreateEndPoint(PENDPOINT_OBJECT *pEp,LOGICAL_EP_INFO *pLogicalEpInfo);
s32_t adi_usb_CreateString(const char *pszAsciiString);
s32_t adi_usb_SetDeviceName(const s32_t wDeviceID, const char *devName);
s32_t adi_usb_GetDeviceName(const s32_t wDeviceID, char *devName);
s32_t adi_usb_AttachConfiguration(const s32_t wDeviceID,const s32_t wConfigID);
s32_t adi_usb_AttachInterface(const s32_t wConfigID,const s32_t wInterfaceID);
s32_t adi_usb_AttachEndpoint(const s32_t wInterfaceID,const s32_t wEndpointID);
s32_t adi_usb_CoreInit(void *pConfig);
s32_t adi_usb_SetPhysicalDriverHandle(ADI_DEV_PDD_HANDLE *pPDDHandle);
PDEVICE_DESCRIPTOR  adi_usb_GetDeviceDescriptor(void);
s32_t adi_usb_GetObjectFromID(const s32_t dwObjectID,USB_OBJECT_TYPE eObjectType,void **ppObject);

s32_t adi_usb_otg_SetEpZeroCallback(const s32_t dwConfigID, ADI_DCB_CALLBACK_FN CallBack);
s32_t adi_usb_otg_SetConfiguration(const s32_t dwConfigID);
s32_t adi_usb_otg_SetInterface(const s32_t dwInterfaceID,const s32_t dwAlternateSetting);
s32_t adi_usb_otg_GetStringFromIndex(const s32_t dwStringDescIndex, u8_t *pAsciiString);
s32_t adi_usb_AttachOtherSpeedConfiguration(const s32_t wConfigID,const s32_t wOtherSpeedConfigID);


/* APIs provided by the USB core layer to the peripheral drivers */
s32_t adi_usb_CreateDevice(PDEVICE_OBJECT *pDv);
s32_t  adi_usb_SetPhysicalEndPointInfo(const s32_t wNumEndPoints,PHYSICAL_EP_INFO PhysicalEndpointInfo[]);
s32_t adi_usb_GetTotalConfiguration(const s32_t wDeviceID, void *pConfigMemory ,const s32_t wLenConfigMemory);
s32_t adi_usb_GetRequiredConfigurationMemory(void);
void  adi_usb_EpZeroCallback(void *AppHandle,unsigned int wEvent,void *pArg);
s32_t  adi_usb_SetDeviceMode(DEV_MODE eDevMode);
DEV_MODE adi_usb_GetDeviceMode(void);
u32 adi_usb_ClearCoreData(void);
void  adi_usb_otg_ClearOTGHostData(void);
s32_t adi_usb_StallEpZero(void);
s32_t adi_usb_TransmitEpZeroBuffer(ADI_DEV_BUFFER *pBuffer);

#ifdef USB_DEBUG
void adi_usb_PrintDeviceDescriptor(PDEVICE_OBJECT pDevO);
void adi_usb_PrintConfigDescriptor(PCONFIG_OBJECT pCfgO);
void adi_usb_PrintInterfaceDescriptor(PINTERFACE_OBJECT pIfceO);
void adi_usb_PrintEndpointDescriptor(PENDPOINT_OBJECT pEpO);
#endif /* USB_DEBUG */

/*
 * Additional information for the EP0 control buffer.
 */
typedef struct EpZeroBufferInfo
{
  s32_t  wCoreControlCode;
  s32_t  wMaxEpZeroBufferSize;
}EP_ZERO_BUFFER_INFO,PEP_ZERO_BUFFER_INFO;

typedef struct UsbCoreData
{
  bool               isCoreInitialized;                        /* Is Core Library initialized */
  s32_t              wNumPhysicalEndpoints;                    /* Number of physical endpoints in the controller */
  DEVICE_OBJECT      *pDeviceHead;                             /* Device Head */
  ADI_DEV_PDD_HANDLE *pPddHandle;                              /* Physical Device driver handle */
  void               *pCriticalData;                           /* Data area to store Critical sections information */
  u32_t              wEventMask;                               /* Events that application is interested in */
  DEV_MODE           eDevMode;                                 /* Device Mode - Peripheral or OTG Host */
  s32_t (*StandardUsbRequestHandler)(void*,unsigned int,void*);/* Standard callback handler */
  s32_t (*BusEventHandler)(void*,unsigned int,void*);          /* Bus Event Handler */
  s32_t (*TxCompleteHandler)(void*,unsigned int,void*);        /* Transmit complete Event Handler */
  s32_t (*RxCompleteHandler)(void*,unsigned int, void*);       /* Receive complete Handler */
  s32_t (*ApplicationSpecificHandler)(void*,unsigned int, void*); /* Application specific handler */
  PHYSICAL_EP_INFO  PhysicalEndpointInfo[16];                    /* Physical endpoint information */
  u8_t   *pConfigMemoryArea;                                   /* Configuration Memory area */
}USB_CORE_DATA;


/* Callback Events from the peripheral driver */
enum USB_EPZERO_CALLBACK_EVENTS
{
    /* USB device events, raised by the peripheral driver */
    ADI_USB_EVENT_NONE=ADI_USB_ENUMERATION_START,                 /* no event */
    ADI_USB_EVENT_SETUP_PKT,            /* EP0 Data */
    ADI_USB_EVENT_START_OF_FRAME,       /* Start of frame */
    ADI_USB_EVENT_RESUME,               /* Resume */
    ADI_USB_EVENT_SUSPEND,              /* Suspend */
    ADI_USB_EVENT_ROOT_PORT_RESET,      /* Reset signaling detected */
    ADI_USB_EVENT_VBUS_TRUE,            /* cable plugged in? */
    ADI_USB_EVENT_VBUS_FALSE,           /* cable unplugged? */
    ADI_USB_EVENT_SET_CONFIG,           /* TODO: Duplicate? */
    ADI_USB_EVENT_START_DEV_ENUM,           /* OTG host mode only, start device enumeration process */

    /* USB class driver or application events */
    ADI_USB_EVENT_DATA_RX,              /* TODO: DELETE later */
    ADI_USB_EVENT_DATA_TX,              /* TODO: DELETE later */
    ADI_USB_EVENT_RX_COMPLETE,          /* Data Received */
    ADI_USB_EVENT_TX_COMPLETE,          /* Data Transmitted */
    ADI_USB_EVENT_PKT_RCVD_NO_BUFFER,          /* No buffer for the received packet */
    ADI_USB_OTG_EVENT_ENUMERATION_COMPLETE,    /* Device Enumeration completed */
    ADI_USB_OTG_EVENT_SET_CONFIG_COMPLETE,     /* Set Configuration successfully completed */
    ADI_USB_OTG_EVENT_SET_INTERFACE_COMPLETE,  /* Set Interface successfully completed */
    ADI_USB_EVENT_DISCONNECT,                  /* Disconnect Event */
    ADI_USB_EVENT_RX_STALL,                    /* RX STALL Event */
    ADI_USB_EVENT_TX_STALL,                    /* TX STALL Event */
    ADI_USB_EVENT_CONNECT,                     /* Connect Event */
    ADI_USB_EVENT_RX_NAK_TIMEOUT,              /* RX NAK Timeout reached */
    ADI_USB_EVENT_TX_NAK_TIMEOUT,              /* TX NAK Timeout reached */
    ADI_USB_EVENT_RX_ERROR,                    /* RX ERROR */
    ADI_USB_EVENT_TX_ERROR,                    /* TX ERROR */
    ADI_USB_EVENT_SET_INTERFACE                /* Host request to set an interface */
};


/* Common Commands implemented by all peripheral Drivers */
enum
{
    ADI_USB_CMD_GET_DEVICE_ID = ADI_USB_ENUMERATION_START,
    ADI_USB_CMD_ENABLE_USB,
    ADI_USB_CMD_DISABLE_USB,
    ADI_USB_CMD_SET_STALL_EP,
    ADI_USB_CMD_CLEAR_STALL_EP,
    ADI_USB_CMD_SET_DEV_ADDRESS,
    ADI_USB_CMD_GET_BUFFER_PREFIX,
    ADI_USB_CMD_SET_BUFFER_PREFIX,
    ADI_USB_CMD_UPDATE_ACTIVE_EP_LIST,
    ADI_USB_CMD_ENABLE_CNTRL_STATUS_HANDSHAKE,
    ADI_USB_CMD_OTG_REQ_IN_TOKEN,
    ADI_USB_CMD_OTG_SEND_ZERO_LEN_PKT,
    ADI_USB_CMD_SET_DEV_MODE,
    ADI_USB_CMD_GET_DEV_MODE,
    ADI_USB_CMD_BUFFERS_IN_CACHE,
    ADI_USB_CMD_CLASS_ENUMERATE_ENDPOINTS,
    ADI_USB_CMD_CLASS_SET_CONTROLLER_HANDLE,
    ADI_USB_CMD_CLASS_GET_CONTROLLER_HANDLE,
    ADI_USB_CMD_CLASS_CONFIGURE,
    ADI_USB_CMD_GET_DEV_SPEED,
    ADI_USB_CMD_SET_DEV_SPEED,
    ADI_USB_CMD_SET_IVG,
    ADI_USB_CMD_GET_IVG,
    ADI_USB_CMD_ENTER_TEST_MODE,
    ADI_USB_CMD_IS_DEVICE_PRESENT,
    ADI_USB_CMD_OTG_SET_POLL_TIMEOUT,
    ADI_USB_CMD_PEEK_EP_FIFO,
    ADI_USB_CMD_STOP_EP_TOKENS,
    ADI_USB_CMD_SETUP_RESPONSE,
    ADI_USB_CMD_HIBERNATE,
    ADI_USB_CMD_RESTORE
};

/* Net2272 specific device command enumerations */
enum
{
   ADI_USB_CMD_SET_PF=ADI_USB_NET2272_ENUMERATION_START,
   ADI_USB_CMD_SET_DMA_CHANNEL,
   ADI_USB_CMD_SET_DMA_IVG,
   ADI_USB_CMD_SET_DRIVER_SEM_HANDLE,
   ADI_USB_CMD_GET_PF,
   ADI_USB_CMD_GET_DMA_CHANNEL,
   ADI_USB_CMD_GET_DMA_IVG,
   ADI_USB_CMD_GET_DRIVER_SEM_HANDLE
};

/* BF54x specific driver enumerations */
#if defined(__ADSPBF548__)
enum
{
    ADI_USB_CMD_SET_DMA_MODE = ADI_USB_BF54X_ENUMERATION_START,
    ADI_USB_CMD_GET_DMA_MODE
};
#endif /* __ADSPBF548__ */

/* BF52x specific driver enumerations */
#if (defined(__ADSPBF527__) || defined(__ADSPBF526__))
enum
{
    ADI_USB_CMD_SET_DMA_MODE = ADI_USB_BF52X_ENUMERATION_START,
    ADI_USB_CMD_GET_DMA_MODE
};
#endif /* __ADSPBF527__ or __ADSPBF526__ */


/* setup phase responses */
enum
{
    ADI_USB_SETUP_RESPONSE_STALL,
    ADI_USB_SETUP_RESPONSE_ACK,
    ADI_USB_SETUP_RESPONSE_ACK_DATA_END
};
/* Endpoint direction */
typedef enum UsbEpDir
{
 USB_EP_OUT=0,
 USB_EP_IN
}USB_EP_DIR;
/*
 * Used by the class driver to return the enumerated endpoints.
 */
typedef struct AppEndpointInfo
{
s32_t dwEndpointID;
USB_EP_DIR  eDir;
u8_t  bAttributes;
}ADI_USB_APP_EP_INFO,*PADI_USB_APP_EP_INFO;

/*
 * Used by the applications/class driver to return the enumerated endpoints.
 */
typedef struct EnumEndpointInfo
{
ADI_USB_APP_EP_INFO   *pUsbAppEpInfo;
s32_t             dwEpTotalEntries;
s32_t             dwEpProcessedEntries;
}ADI_ENUM_ENDPOINT_INFO;


/* USB bus speeds */
typedef enum UsbDeviceSpeed
{
    ADI_USB_DEVICE_SPEED_UNKNOWN,
    ADI_USB_DEVICE_SPEED_HIGH,
    ADI_USB_DEVICE_SPEED_FULL,
    ADI_USB_DEVICE_SPEED_LOW
}ADI_USB_DEVICE_SPEED;

/* Buffer reserved locations can be used to store information */
#define BUFFER_RSVD_EP_ADDRESS  4   /* endpoint address */

/* Ep0 data that has been returned from the callback is checked to see this below
 * control code to check if we infact issued the write.
 */
#define CORE_CONTROL_CODE 0xBEEFBEEF

/* Internal Core functions used by both device and otg host */
void SetHostHandlers(void);
s32_t SendEpZeroData(DEVICE_OBJECT*,char *, int);
s32_t FreeReceivedPackets(DEVICE_OBJECT *pDevO,ADI_DEV_BUFFER *pBuffer);
s32_t UpdateActiveEpList(PDEVICE_OBJECT pDevO);


/* USB Result code */
enum
{
 ADI_USB_RESULT_SUCCESS = ADI_USB_ENUMERATION_START,
 ADI_USB_RESULT_INVALID_ID,
 ADI_USB_RESULT_FAILED,
 ADI_USB_RESULT_INVALID_INPUT
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_CORE_H_ */
