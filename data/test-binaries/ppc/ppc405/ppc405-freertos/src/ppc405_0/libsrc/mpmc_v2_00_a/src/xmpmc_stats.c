/* $Id: xmpmc_stats.c,v 1.2 2007/12/03 16:22:46 svemula Exp $ */
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
*       (c) Copyright 2007 Xilinx Inc.
*       All rights reserved.
*
******************************************************************************/
/**
* @file xmpmc_stats.c
*
* The implementation of the XMpmc component's functionality that is related
* to statistics. See xmpmc.h for more information about the component.
*
* @note		None.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a mta  02/24/07 First release
* </pre>
*
*****************************************************************************/

/***************************** Include Files ********************************/

#include "xmpmc.h"

/************************** Constant Definitions ****************************/

/**************************** Type Definitions ******************************/

/***************** Macros (Inline Functions) Definitions ********************/

/************************** Variable Definitions ****************************/

/************************** Function Prototypes *****************************/

/****************************************************************************/
/**
* Get the statistics of the MPMC device including the Single Error Count,
* Double Error Count, Parity Field Error Count and the address where the last
* error was detected in the memory. The counts are all contained in registers
* of the MPMC device.
*
* @param	InstancePtr is a pointer to an XMpmc instance to be worked on.
* @param	StatsPtr contains a pointer to a XMpmc_Stats data type.
*		The function puts the statistics of the device into the
*		specified data structure.
*
* @return	The statistics data type pointed to by input StatsPtr is
*		modified.
*
* @note		None.
*
*****************************************************************************/
void XMpmc_GetStatsEcc(XMpmc * InstancePtr, XMpmc_Stats * StatsPtr)
{
	u32 StatusReg;

	/*
	 * Assert arguments.
	 */
	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(StatsPtr != NULL);
	XASSERT_VOID(InstancePtr->ConfigPtr.EccSupportPresent == TRUE);

	/*
	 * Read all the error count registers and save their values in the
	 * specified statistics area.
	 */
	StatsPtr->SingleErrorCount =
		(u16) XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				     XMPMC_ECCSEC_OFFSET);
	StatsPtr->DoubleErrorCount =
		(u16) XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				     XMPMC_ECCDEC_OFFSET);
	StatsPtr->ParityErrorCount =
		(u16) XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				     XMPMC_ECCPEC_OFFSET);


	StatusReg = XMpmc_mReadReg(InstancePtr->ConfigPtr.BaseAddress,
				   XMPMC_ECCSR_OFFSET);
	if (StatusReg & (XMPMC_ECCSR_SE_MASK | XMPMC_ECCSR_DE_MASK |
			 XMPMC_ECCSR_PE_MASK)) {
		StatsPtr->LastErrorAddress =
			(u32) XMpmc_mReadReg(InstancePtr->ConfigPtr.
					     BaseAddress, XMPMC_ECCADDR_OFFSET);

		StatsPtr->EccErrorSyndrome = ((StatusReg &
					       XMPMC_ECCSR_SE_SYND_MASK) >>
					       XMPMC_ECCSR_SE_SYND_SHIFT);
		StatsPtr->EccErrorTransSize = ((StatusReg &
						XMPMC_ECCSR_ERR_SIZE_MASK) >>
					       XMPMC_ECCSR_ERR_SIZE_SHIFT);
		StatsPtr->ErrorReadWrite =
			((StatusReg & XMPMC_ECCSR_ERR_RNW_MASK) >>
				XMPMC_ECCSR_ERR_RNW_SHIFT);
	}
	else {
		StatsPtr->LastErrorAddress = 0x0;
	}
}

/****************************************************************************/
/**
* Clear the statistics of the MPMC device including the Single Error Count,
* Double Error Count, and Parity Field Error Count. The counts are all
* contained in registers of the MPMC device.
*
* @param	InstancePtr is a pointer to an XMpmc instance to be worked on.
*
* @return	None.
*
* @note		None.
*
*****************************************************************************/
void XMpmc_ClearStatsEcc(XMpmc * InstancePtr)
{
	/*
	 * Assert arguments.
	 */
	XASSERT_VOID(InstancePtr != NULL);
	XASSERT_VOID(InstancePtr->ConfigPtr.EccSupportPresent == TRUE);

	/*
	 * Clear all the error count registers in the device.
	 */
	XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
			XMPMC_ECCSEC_OFFSET, 0);
	XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
			XMPMC_ECCDEC_OFFSET, 0);
	XMpmc_mWriteReg(InstancePtr->ConfigPtr.BaseAddress,
			XMPMC_ECCPEC_OFFSET, 0);
}
