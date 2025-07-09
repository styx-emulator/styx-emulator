/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_device_access.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    Device Access - primary include file
    Device Access service for off-chip devices that supports TWI or SPI
    to access its internal registers.

Note:
    'Device' refers to the underlying device driver presently using this file
*****************************************************************************/

#ifndef __ADI_DEVICE_ACCESS_H__
#define __ADI_DEVICE_ACCESS_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*****************************************************************************

Fixed enumerations and defines

*****************************************************************************/
/* List of Access modes reported back to the 'Device' driver */
typedef enum ADI_DEVICE_ACCESS_MODE {   /* list of access modes                                 */
    ADI_DEVICE_ACCESS_PRE_READ,         /* 'Device' in pre-read mode                            */
    ADI_DEVICE_ACCESS_PRE_WRITE,        /* 'Device' in pre-write mode                           */
    ADI_DEVICE_ACCESS_PRE_ADDR_GENERATE /* 'Device' in block access (pre-address generate) mode */
}   ADI_DEVICE_ACCESS_MODE;

/*****************************************************************************
Prototype for 'Device' specific function (Device Access Callback Function)
*****************************************************************************/

/* Parameters - Client Handle, Register Address, Register Data,ADI_DEVICE_ACCESS_MODE */
typedef u32 (*ADI_DEVICE_ACCESS_CALLBACK_FN) (void*,u16*,u16,ADI_DEVICE_ACCESS_MODE);

/*********************************************************************
Table to validate 'Device' Register Field and to perform Register field access
Table structure -   'Count' of 'Device' registers containing individual fields
                    Pointer to array of 'Device' Register addresses containing individual fields,
                    Pointer to array of corresponding 'Device' register field locations,
Register field location - Bit indicating start of new field in a register will be 1
Reserved bit locations will be 1
*********************************************************************/

typedef struct ADI_DEVICE_ACCESS_REGISTER_FIELD {
    u32     Count;              /* 'Count' of Register addresses containing individual fields                   */
    u16     *RegAddr;           /* pointer to array of 'Device' register addresses containing individual fields */
    u16     *RegField;          /* pointer to array of register field locations in the corresponding registers  */
}   ADI_DEVICE_ACCESS_REGISTER_FIELD;

/*********************************************************************
Table to configure reserved bits in the 'Device' to recommended values
Table structure -   'Count' of Register addresses containing Reserved Locations
                    'Device' Register addresses containing Reserved Locations
                    Reserved bit locations in the corresponding register
                    Recommended value for the Reserved Locations
*********************************************************************/

typedef struct ADI_DEVICE_ACCESS_RESERVED_VALUES    {
    u32     Count;              /* 'Count' of Register addresses containing Reserved Locations              */
    u16     *RegAddr;           /* pointer to array of Register addresses containing Reserved Locations     */
    u16     *ReservedBits;      /* pointer to array of reserved bit locations in the corresponding register */
    u16     *ReservedBitValue;  /* pointer to array of Recommended values for the Reserved Bit locations    */
}   ADI_DEVICE_ACCESS_RESERVED_VALUES;

/*********************************************************************
Table for 'Device' Register Error check for invalid & read-only register(s) access
Structure - 'Count' of invalid Register addresses in the 'Device'
            Invalid Register addresses in the 'Device'
            'Count' of Read-only Register addresses in the 'Device'
            Read-only Register addresses in the 'Device'
*********************************************************************/

typedef struct ADI_DEVICE_ACCESS_VALIDATE_REGISTER  {
    u32     Count1;             /* 'Count' of Invalid Register addresses in the 'Device'            */
    u16     *InvalidRegs;       /* pointer to array of Invalid Register addresses in the 'Device'   */
    u32     Count2;             /* 'Count' of Read-only Register addresses in the 'Device'          */
    u16     *ReadOnlyRegs;      /* pointer to array of Read-only Register addresses in the 'Device' */
}   ADI_DEVICE_ACCESS_VALIDATE_REGISTER;

/*********************************************************************
Structure holding the list of Access type supported by this service

Note: For Devices with SPI Access & doesn't need to attach Read/Write
    bit in Device Access Service, Pass Gaddr_len & Rdata_len as zero
    and Raddr_len with the length of SPI data to be transfered/received
*********************************************************************/

typedef enum ADI_DEVICE_ACCESS_SET_DEVICE_TYPE {   /* list device structures supported by this service  */
    /* ‘Device’ with No Register address / Register data */
    ADI_DEVICE_ACCESS_LENGTH0 = 0,
    /* ‘Device’ with register address / register data of 1 byte */
    ADI_DEVICE_ACCESS_LENGTH1 = 1,
    /* ‘Device’ with register address / register data of 2 bytes */
    ADI_DEVICE_ACCESS_LENGTH2 = 2
} ADI_DEVICE_ACCESS_SET_DEVICE_TYPE;

typedef enum ADI_DEVICE_ACCESS_SET_ACCESS_TYPE {    /* list of device access methods supported by this service */
    ADI_DEVICE_ACCESS_TYPE_TWI      = 0,            /* TWI Access                                       */
    ADI_DEVICE_ACCESS_TYPE_SPI      = 0x01,         /* SPI Access (for devices with R/W flag at bit 0)  */
    ADI_DEVICE_ACCESS_TYPE_SPI_1    = 0x80,         /* SPI Access (for devices with R/W flag at bit 7)  */
    ADI_DEVICE_ACCESS_TYPE_SPI_2    = 0x8000        /* SPI Access (for devices with R/W flag at bit 15) */
} ADI_DEVICE_ACCESS_SET_ACCESS_TYPE;

typedef struct ADI_DEVICE_ACCESS_SELECT   {
    u8                                  DeviceCS;       /* Blackfin Chipselect (only for SPI) to select the corresponding 'Device'  */
    ADI_DEVICE_ACCESS_SET_DEVICE_TYPE   Gaddr_len;      /* 'Device' Global Address Length (only for SPI Access)                     */
    ADI_DEVICE_ACCESS_SET_DEVICE_TYPE   Raddr_len;      /* 'Device' Register Address Length                                         */
    ADI_DEVICE_ACCESS_SET_DEVICE_TYPE   Rdata_len;      /* 'Device' Register Data Length                                            */
    ADI_DEVICE_ACCESS_SET_ACCESS_TYPE   AccessType;     /* Access type selected for this 'Device'                                   */
}   ADI_DEVICE_ACCESS_SELECT ;

/*********************************************************************

Device Access Structure

Off-chip drivers built on top of this service should pass address of
this structure instance with the adi_device_access() function call

*********************************************************************/

typedef struct ADI_DEVICE_ACCESS_REGISTERS {
    ADI_DEV_MANAGER_HANDLE              ManagerHandle;      /* device manager handle                                                                */
    void                                *ClientHandle;      /* client handle - passed to the 'Device' specific function                             */
    u32                                 DeviceNumber;       /* device number                                                                        */
    u32                                 DeviceAddress;      /* TWI/SPI address of the device                                                        */
    ADI_DCB_HANDLE                      DCBHandle;          /* callback handle                                                                      */
    ADI_DEVICE_ACCESS_CALLBACK_FN       DeviceFunction;     /* 'Device' specific function from the corresponding 'Device' driver                    */
    u32                                 Command;            /* command ID                                                                           */
    void                                *Value;             /* command specific value                                                               */
    u32                                 FinalRegAddr;       /* Address of the last register in the Device                                           */
    ADI_DEVICE_ACCESS_REGISTER_FIELD    *RegisterField;     /* pointer to the 'Device' Register Field Error check and Register field access table   */
    ADI_DEVICE_ACCESS_RESERVED_VALUES   *ReservedValues;    /* pointer to table to configure reserved bits in the 'Device' to recommended values    */
    ADI_DEVICE_ACCESS_VALIDATE_REGISTER *ValidateRegister;  /* pointer to the table containing reserved and read-only registers in the 'Device'     */
    ADI_DEV_CMD_VALUE_PAIR              *ConfigTable;       /* TWI/SPI configuration table                                                          */
    ADI_DEVICE_ACCESS_SELECT            *SelectAccess;      /* Pointer to table containing Access type information                                  */
    void                                *pAdditionalinfo;   /* device specific pointer to additional info                                           */
}   ADI_DEVICE_ACCESS_REGISTERS;

/*****************************************************************************

Function Declerations

*****************************************************************************/

/* Function to Access Device registers via TWI or SPI */
u32 adi_device_access (
    ADI_DEVICE_ACCESS_REGISTERS     *Device     /* pointer to Device Access instance */
);

/*****************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_DEVICE_ACCESS_H__ */

/*****/
