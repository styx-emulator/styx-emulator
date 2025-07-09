/* $Id: xuartlite_sinit.c,v 1.1 2007/05/15 07:00:27 mta Exp $ */
/*****************************************************************************
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
*****************************************************************************/
/****************************************************************************/
/**
*
* @file xuartlite_sinit.c
*
* The implementation of the XUartLite component's static initialzation
* functionality.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.01a jvb  10/13/05 First release
* </pre>
*
*****************************************************************************/

/***************************** Include Files ********************************/

#include "xstatus.h"
#include "xparameters.h"
#include "xuartlite_i.h"

/************************** Constant Definitions ****************************/


/**************************** Type Definitions ******************************/


/***************** Macros (Inline Functions) Definitions ********************/


/************************** Variable Definitions ****************************/


/************************** Function Prototypes *****************************/

/****************************************************************************
*
* Looks up the device configuration based on the unique device ID.  The table
* UartliteConfigTable contains the configuration info for each device in the
* system.
*
* @param	DeviceId is the unique device ID to match on.
*
* @return	A pointer to the configuration data for the device, or
*		NULL if no match was found.
*
* @note		None.
*
******************************************************************************/
XUartLite_Config *XUartLite_LookupConfig(u16 DeviceId)
{
	XUartLite_Config *CfgPtr = NULL;
	int i;

	for (i=0; i < XPAR_XUARTLITE_NUM_INSTANCES; i++) {
		if (XUartLite_ConfigTable[i].DeviceId == DeviceId) {
			CfgPtr = &XUartLite_ConfigTable[i];
			break;
		}
	}

	return CfgPtr;
}

/****************************************************************************/
/**
*
* Initialize a XUartLite instance.  The receive and transmit FIFOs of the
* UART are not flushed, so the user may want to flush them. The hardware
* device does not have any way to disable the receiver such that any valid
* data may be present in the receive FIFO.  This function disables the UART
* interrupt. The baudrate and format of the data are fixed in the hardware
* at hardware build time.
*
* @param	InstancePtr is a pointer to the XUartLite instance.
* @param	DeviceId is the unique id of the device controlled by this
*		XUartLite instance.  Passing in a device id associates the
*		generic XUartLite instance to a specific device, as chosen by
*		the caller or application developer.
*
* @return
* 		- XST_SUCCESS if everything starts up as expected.
* 		- XST_DEVICE_NOT_FOUND if the device is not found in the
*			configuration table.
*
* @note		None.
*
*****************************************************************************/
int XUartLite_Initialize(XUartLite *InstancePtr, u16 DeviceId)
{
	XUartLite_Config *ConfigPtr;

	/*
	 * Assert validates the input arguments
	 */
	XASSERT_NONVOID(InstancePtr != NULL);

	/*
	 * Lookup the device configuration in the configuration table. Use this
	 * configuration info when initializing this component.
	 */
	ConfigPtr = XUartLite_LookupConfig(DeviceId);

	if (ConfigPtr == (XUartLite_Config *)NULL) {
		return XST_DEVICE_NOT_FOUND;
	}
	return XUartLite_CfgInitialize(InstancePtr, ConfigPtr,
					ConfigPtr->RegBaseAddr);
}
