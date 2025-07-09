/* $Id: xsysace_sinit.c,v 1.1 2007/04/04 18:32:30 wre Exp $ */
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
* @file xsysace_sinit.c

* The implementation of the XSysAce component's static initialzation
* functionality.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.01a jvb  10/13/05 First release
* 1.11a wgr  07/03/20 converted to new coding style.
* </pre>
*
******************************************************************************/

/***************************** Include Files *********************************/

#include "xstatus.h"
#include "xparameters.h"
#include "xsysace.h"

/************************** Constant Definitions *****************************/


/**************************** Type Definitions *******************************/


/***************** Macros (Inline Functions) Definitions *********************/


/************************** Function Prototypes ******************************/


/************************** Variable Definitions *****************************/

/*****************************************************************************/
/**
*
* Looks up the device configuration based on the unique device ID. The table
* XSysAce_ConfigTable contains the configuration info for each device in the
* system.
*
* @param DeviceId is the unique device ID to look for.
*
* @return
*
* A pointer to the configuration data for the device, or NULL if no match is
* found.
*
* @note
*
* None.
*
******************************************************************************/
XSysAce_Config *XSysAce_LookupConfig(u16 DeviceId)
{
	extern XSysAce_Config XSysAce_ConfigTable[];
	XSysAce_Config *CfgPtr = NULL;
	int i;

	for (i = 0; i < XPAR_XSYSACE_NUM_INSTANCES; i++) {
		if (XSysAce_ConfigTable[i].DeviceId == DeviceId) {
			CfgPtr = &XSysAce_ConfigTable[i];
			break;
		}
	}

	return CfgPtr;
}

/*****************************************************************************/
/**
*
* Initialize a specific XSysAce instance. The configuration information for
* the given device ID is found and the driver instance data is initialized
* appropriately.
*
* @param InstancePtr is a pointer to the XSysAce instance to be worked on.
* @param DeviceId is the unique id of the device controlled by this XSysAce
*        instance.
*
* @return
*
* XST_SUCCESS if successful, or XST_DEVICE_NOT_FOUND if the device was not
* found in the configuration table in xsysace_g.c.
*
* @note
*
* We do not want to reset the configuration controller here since this could
* cause a reconfiguration of the JTAG target chain, depending on how the
* CFGMODEPIN of the device is wired.
*
******************************************************************************/
int XSysAce_Initialize(XSysAce * InstancePtr, u16 DeviceId)
{
	XSysAce_Config *ConfigPtr;

	XASSERT_NONVOID(InstancePtr != NULL);

	InstancePtr->IsReady = 0;

	/*
	 * Lookup configuration data in the device configuration table.
	 * Use this configuration info down below when initializing this component.
	 */
	ConfigPtr = XSysAce_LookupConfig(DeviceId);

	if (ConfigPtr == (XSysAce_Config *) NULL) {
		return XST_DEVICE_NOT_FOUND;
	}

	return XSysAce_CfgInitialize(InstancePtr, ConfigPtr,
				     ConfigPtr->BaseAddress);
}
