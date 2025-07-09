/* $Id: xiic_sinit.c,v 1.1 2007/12/03 15:44:58 meinelte Exp $ */
/******************************************************************************
*
*       XILINX IS PROVIDING THIS DESIGN, CODE, OR INFORMATION "AS IS"
*       AS A COURTESY TO YOU, SOLELY FOR USE IN DEVELOPING PROGRAMS AND
*       SOLUTIONS FOR XILINX DEVICES.  BY PROVIDING THIS DESIGN, CODE,
*       OR INFORMATION AS ONE POSSIBLE IMPLEMENTATION OF THIS FEATURE,
*       APPLICATION OR STANDARD, XILINX IS MAKING NO REPRESENTATION
*       THAT THIS IMPLEMENTATION IS FREE FROM ANY CLAIMS OF INFRINGEMENT,
*       AND YOU ARE RESPONSIBLE FOR OBTAINING ANY RIGHTS YOU MAY REQUIRE
*       FOR YOUR IMPLEMENTATION.  XILINX EXPRESSLY DISCLAIMS ANY
*       WARRANTY WHATSOEVER WITH RESPECT TO THE ADEQUACY OF THE
*       IMPLEMENTATION, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OR
*       REPRESENTATIONS THAT THIS IMPLEMENTATION IS FREE FROM CLAIMS OF
*       INFRINGEMENT, IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
*       FOR A PARTICULAR PURPOSE.
*
*       (c) Copyright 2005 Xilinx Inc.
*       All rights reserved.
*
******************************************************************************/
/*****************************************************************************/
/**
*
* @file xiic_sinit.c
*
* The implementation of the Xiic component's static initialzation functionality.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- --- ------- -----------------------------------------------
* 1.02a jvb  10/13/05 release
* 1.13a wgr  03/22/07 Converted to new coding style.
* </pre>
*
****************************************************************************/

/***************************** Include Files *******************************/

#include "xstatus.h"
#include "xparameters.h"
#include "xiic_i.h"

/************************** Constant Definitions ***************************/


/**************************** Type Definitions *****************************/


/***************** Macros (Inline Functions) Definitions *******************/


/************************** Function Prototypes ****************************/

/************************** Variable Definitions **************************/


/*****************************************************************************/
/**
*
* Looks up the device configuration based on the unique device ID. The table
* IicConfigTable contains the configuration info for each device in the system.
*
* @param DeviceId is the unique device ID to look for
*
* @return
*
* A pointer to the configuration data of the device, or NULL if no match is
* found.
*
* @note
*
* None.
*
******************************************************************************/
XIic_Config *XIic_LookupConfig(u16 DeviceId)
{
	XIic_Config *CfgPtr = NULL;
	int i;

	for (i = 0; i < XPAR_XIIC_NUM_INSTANCES; i++) {
		if (XIic_ConfigTable[i].DeviceId == DeviceId) {
			CfgPtr = &XIic_ConfigTable[i];
			break;
		}
	}

	return CfgPtr;
}

/*****************************************************************************/
/**
*
* Initializes a specific XIic instance.  The initialization entails:
*
* - Check the device has an entry in the configuration table.
* - Initialize the driver to allow access to the device registers and
*   initialize other subcomponents necessary for the operation of the device.
* - Default options to:
*     - 7-bit slave addressing
*     - Send messages as a slave device
*     - Repeated start off
*     - General call recognition disabled
* - Clear messageing and error statistics
*
* The XIic_Start() function must be called after this function before the device
* is ready to send and receive data on the IIC bus.
*
* Before XIic_Start() is called, the interrupt control must connect the ISR
* routine to the interrupt handler. This is done by the user, and not
* XIic_Start() to allow the user to use an interrupt controller of their choice.
*
* @param    InstancePtr is a pointer to the XIic instance to be worked on.
* @param    DeviceId is the unique id of the device controlled by this XIic
*           instance.  Passing in a device id associates the generic XIic
*           instance to a specific device, as chosen by the caller or
*           application developer.
*
* @return
*
* - XST_SUCCESS when successful
* - XST_DEVICE_NOT_FOUND indicates the given device id isn't found
* - XST_DEVICE_IS_STARTED indicates the device is started (i.e. interrupts
*   enabled and messaging is possible). Must stop before re-initialization
*   is allowed.
*
* @note
*
* None.
*
****************************************************************************/
int XIic_Initialize(XIic * InstancePtr, u16 DeviceId)
{
	XIic_Config *ConfigPtr;	/* Pointer to configuration data */

	/*
	 * Asserts test the validity of selected input arguments.
	 */
	XASSERT_NONVOID(InstancePtr != NULL);

	/*
	 * Lookup the device configuration in the temporary CROM table. Use this
	 * configuration info down below when initializing this component.
	 */
	ConfigPtr = XIic_LookupConfig(DeviceId);
	if (ConfigPtr == NULL) {
		return XST_DEVICE_NOT_FOUND;
	}

	return XIic_CfgInitialize(InstancePtr, ConfigPtr,
				  ConfigPtr->BaseAddress);
}
