/* $Id: xuartlite_l.c,v 1.2 2007/07/16 16:54:48 moleres Exp $ */
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
*       (c) Copyright 2002-2007 Xilinx Inc.
*       All rights reserved.
*
*****************************************************************************/
/****************************************************************************/
/**
*
* @file xuartlite_l.c
*
* This file contains low-level driver functions that can be used to access the
* device.  The user should refer to the hardware device specification for more
* details of the device operation.

* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00b rpm  04/25/02 First release
* 1.12a rpm  07/16/07 Fixed arg type for RecvByte
* </pre>
*
******************************************************************************/

/***************************** Include Files *********************************/

#include "xuartlite_l.h"

/************************** Constant Definitions *****************************/


/**************************** Type Definitions *******************************/


/***************** Macros (Inline Functions) Definitions *********************/


/************************** Function Prototypes ******************************/


/************************** Variable Prototypes ******************************/


/****************************************************************************/
/**
*
* This functions sends a single byte using the UART. It is blocking in that it
* waits for the transmitter to become non-full before it writes the byte to
* the transmit register.
*
* @param	BaseAddress is the base address of the device
* @param	Data is the byte of data to send
*
* @return	None.
*
* @note		None.
*
******************************************************************************/
void XUartLite_SendByte(u32 BaseAddress, u8 Data)
{
	while (XUartLite_mIsTransmitFull(BaseAddress));

	XIo_Out32(BaseAddress + XUL_TX_FIFO_OFFSET, Data);
}


/****************************************************************************/
/**
*
* This functions receives a single byte using the UART. It is blocking in that
* it waits for the receiver to become non-empty before it reads from the
* receive register.
*
* @param	BaseAddress is the base address of the device
*
* @return	The byte of data received.
*
* @note		None.
*
******************************************************************************/
u8 XUartLite_RecvByte(u32 BaseAddress)
{
	while (XUartLite_mIsReceiveEmpty(BaseAddress));

	return (u8)XIo_In32(BaseAddress + XUL_RX_FIFO_OFFSET);
}
