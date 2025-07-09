/* $Id: xsysace_selftest.c,v 1.2 2007/05/31 00:29:42 wre Exp $ */
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
*       (c) Copyright 2002 Xilinx Inc.
*       All rights reserved.
*
******************************************************************************/
/*****************************************************************************/
/**
*
* @file xsysace_selftest.c
*
* Contains diagnostic functions for the System ACE device and driver. This
* includes a self-test to make sure communication to the device is possible
* and the ability to retrieve the ACE controller version.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a rpm  06/17/02 work in progress
* 1.11a wgr  07/03/20 converted to new coding style.
* </pre>
*
******************************************************************************/

/***************************** Include Files *********************************/

#include "xsysace.h"
#include "xsysace_l.h"

/************************** Constant Definitions *****************************/


/**************************** Type Definitions *******************************/


/***************** Macros (Inline Functions) Definitions *********************/


/************************** Function Prototypes ******************************/


/************************** Variable Definitions *****************************/


/*****************************************************************************/
/**
*
* A self-test that simply proves communication to the ACE controller from the
* device driver by obtaining an MPU lock, verifying it, then releasing it.
*
* @param InstancePtr is a pointer to the XSysAce instance to be worked on.
*
* @return
*
* XST_SUCCESS if self-test passes, or XST_FAILURE if an error occurs.
*
* @note
*
* None.
*
******************************************************************************/
int XSysAce_SelfTest(XSysAce * InstancePtr)
{
	int Result;

	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);

	/*
	 * Grab a lock (expect immediate success)
	 */
	Result = XSysAce_Lock(InstancePtr, TRUE);
	if (Result != XST_SUCCESS) {
		return Result;
	}

	/*
	 * Verify the lock was retrieved
	 */
	if (!XSysAce_mIsMpuLocked(InstancePtr->BaseAddress)) {
		return XST_FAILURE;
	}

	/*
	 * Release the lock
	 */
	XSysAce_Unlock(InstancePtr);

	/*
	 * Verify the lock was released
	 */
	if (XSysAce_mIsMpuLocked(InstancePtr->BaseAddress)) {
		return XST_FAILURE;
	}

	/*
	 * If there are currently any errors on the device, fail self-test
	 */
	if (XSysAce_mGetErrorReg(InstancePtr->BaseAddress) != 0) {
		return XST_FAILURE;
	}

	return XST_SUCCESS;
}


/*****************************************************************************/
/**
*
* Retrieve the version of the System ACE device.
*
* @param InstancePtr is a pointer to the XSysAce instance to be worked on.
*
* @return
*
* A 16-bit version where the 4 most significant bits are the major version
* number, the next four bits are the minor version number, and the least
* significant 8 bits are the revision or build number.
*
* @note
*
* None.
*
******************************************************************************/
u16 XSysAce_GetVersion(XSysAce * InstancePtr)
{
	XASSERT_NONVOID(InstancePtr != NULL);
	XASSERT_NONVOID(InstancePtr->IsReady == XCOMPONENT_IS_READY);

	return XSysAce_RegRead16(InstancePtr->BaseAddress + XSA_VR_OFFSET);
}
