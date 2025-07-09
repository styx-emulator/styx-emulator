/*********************************************************************************

Copyright(c) 2006 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_usb_objects.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
             Contains various device objects that are buliding blocks for the USB
             system. They include device, configuration, interface and endpoint
             objects. These objects internally hold the descriptors. For upper
             class drivers there is Class Specific or Interface specific objects
             were defined.

*********************************************************************************/

#ifndef _ADI_USB_OBJECTS_H_
#define _ADI_USB_OBJECTS_H_

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers\usb\usb_core\adi_usb_common.h>
#include <drivers\adi_dev.h>

struct DeviceObject;
typedef int (*EP_STATE_MACHINE_HANDLER)(struct DeviceObject *pDevO,int,void*);

/* Usb Connection Information present in the Endpoint object */
typedef struct UsbEndpointInfo
{
  ADI_DEV_BUFFER    *pFreeRcvList;
  ADI_DEV_BUFFER    *pFreeXmtList;
  ADI_DEV_BUFFER    *pProcessedRcvList;
  ADI_DEV_BUFFER    *pQueuedXmtList;
  ADI_DCB_CALLBACK_FN   EpCallback;
  unsigned int  TransferSize;
  unsigned int  TransferMode;
  ADI_DEV_BUFFER *pTransferBuffer;
  bool          bnEpHalt;
  int           EpState;
  int           EpNumTotalBytes;
  int           EpBytesProcessed;
  int           EpDir;
  EP_STATE_MACHINE_HANDLER EpStateMachineHandler;

}USB_EP_INFO,*PUSB_EP_INFO;

/* EP mode */
enum
{
    EP_MODE_PACKET,
    EP_MODE_TRANSFER
};

/* EP State */
enum
{
    EP_STATE_IDLE,
    EP_STATE_SETUP_RQST_PHASE,
    EP_STATE_SETUP_DATA_PHASE,
    EP_STATE_SETUP_STATUS_PHASE
};

/* Endpoint Specific Configuration Object */
typedef struct EndpointSpecificObject
{
 int    length;                    /* total length of ep specific config*/
 void   *pEpSpecificData;          /* Endpoint specific data */
 struct EndpointSpecificObject *pNext; /* Next object */
}ENDPOINT_SPECIFIC_OBJECT,*PENDPOINT_SPECIFIC_OBJECT;

/* Endpoint Object */
typedef struct EndpointObject
{
  ENDPOINT_DESCRIPTOR         *pEndpointDesc;    /* Endpoint Descriptor */
  ENDPOINT_SPECIFIC_OBJECT    *pEndpointSpecificObj; /* EP-Specific Config Obj*/
  struct EndpointObject       *pNext;            /* Next Endpoint object */
  /* pNextActiveEp is used by the peripheral driver to get the currently active endpoint list */
  struct EndpointObject       *pNextActiveEpObj;        /* Points to the next peer endpoint object */
  int                         ID;                /* Endpoint ID */
  USB_EP_INFO                 EPInfo;
}ENDPOINT_OBJECT,*PENDPOINT_OBJECT;


/* Interface Specific Configuration Object */
typedef struct InterfaceSpecificObject
{
 int length;                      /* total length of interface specific config*/
 void *pIntSpecificData;          /* class specific data */
 struct InterfaceSpecificObject *pNext; /* Next object */
}INTERFACE_SPECIFIC_OBJECT,*PINTERFACE_SPECIFIC_OBJECT;

/* Interface Object */
typedef struct InterfaceObject
{
  INTERFACE_DESCRIPTOR       *pInterfaceDesc;   /* Interface Descriptor */
  ENDPOINT_OBJECT            *pEndpointObj;     /* Endpoint Object */
  INTERFACE_SPECIFIC_OBJECT  *pIntSpecificObj;  /* I-Specific Config Obj*/
  struct InterfaceObject     *pAltInterfaceObj; /* Alternate Interface Obj */
  struct InterfaceObject     *pNext;            /* Next configuration object */
  int                        ID;                /* Interface ID */
}INTERFACE_OBJECT,*PINTERFACE_OBJECT;



/* Class Specific Configuration Object */
typedef struct ClassSpecificObject
{
 int length;                         /* total length of class specific config*/
 void *pClassSpecificData;           /* class specific data */
 struct ClassSpecificObject *pNext;  /* Next object */
}CLASS_SPECIFIC_OBJECT,*PCLASS_SPECIFIC_OBJECT;

/* Configuration Object */
typedef struct ConfigObject
{
  CONFIGURATION_DESCRIPTOR *pConfigDesc;       /* Configuration Descriptor */
  INTERFACE_OBJECT         *pInterfaceObj;     /* Interface Object */
  CLASS_SPECIFIC_OBJECT    *pClassSpecificObj; /* C-Specific Config Obj*/
  struct ConfigObject      *pNext;             /* Next configuration object */
  int                       ID;                /* Configuration ID */
  ADI_DCB_CALLBACK_FN      EpZeroCallback;     /* EP0 Callback for this Config*/
  ENDPOINT_OBJECT          *pActiveEpObj;      /* Currently active Endpoint list */
  struct ConfigObject     *pOtherSpeedConfigObj; /* Other speed configuration */
}CONFIG_OBJECT,*PCONFIG_OBJECT;



#define SIZEOF_DEVICE_NAME 24

#define DEVICE_STATE_NOT_CONFIGURED     -1
#define DEVICE_STATE_ADDRESS            0
#define DEVICE_STATE_CONFIGURED         2
/* Device Object */
typedef struct DeviceObject
{
  DEVICE_DESCRIPTOR     *pDeviceDesc;               /* Device Descriptor */
  DEVICE_QUALIFIER_DESCRIPTOR *pDeviceQuaDesc;      /* Device Qualifier descriptor */
  CONFIG_OBJECT         *pConfigObj;                /* Configuration Object */
  CONFIG_OBJECT         *pOtherSpeedConfigObj;      /* Other Speed Configuration Object */
  struct DeviceObject   *pNext;                     /* Next Device Object */
  CONFIG_OBJECT         *pActiveConfigObj;          /* Active config object */
  INTERFACE_OBJECT      *pActiveInterfaceObj;       /* Active Interface object */
  ENDPOINT_OBJECT       *pEndpointZeroObj;          /* Active Interface object */
  PSTRING_DESCRIPTOR    *ppStringDescriptors;       /* String descriptors pointer */
  int               ID;                             /* Device ID */
  char              pDevName[SIZEOF_DEVICE_NAME];   /* Device Name */
  u32_t             wDeviceAddress;                 /* Device address */
  s32_t             wDeviceState;                   /* State of the device object */
  bool              bnHostWakeupEnable;             /* Ability to wakeup or suspend host */
  SETUP_PACKET      ActiveSetupPkt;                 /* Holds active setup pkt for this device */
  u8_t              *pSetupData;                    /* Holds data pointer for an active setup data phase */
  u8_t              *pSetupDataArea;                /* Internal buffer to hold Ep0 data */
  ADI_DEV_BUFFER    *pAppEpZeroBuffer;              /* Application EP0 buffer */
  u32_t             nBusSpeed;                      /* Speed that the bus is configured to */
}DEVICE_OBJECT,*PDEVICE_OBJECT;

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* _ADI_USB_OBJECTS_H_ */
