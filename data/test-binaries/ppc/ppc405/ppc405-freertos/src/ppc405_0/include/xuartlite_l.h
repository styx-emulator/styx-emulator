/* $Id: xuartlite_l.h,v 1.2 2007/05/31 00:29:42 wre Exp $ */
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
*       (c) Copyright 2002 Xilinx Inc.
*       All rights reserved.
*
*****************************************************************************/
/****************************************************************************/
/**
*
* @file xuartlite_l.h
*
* This header file contains identifiers and low-level driver functions (or
* macros) that can be used to access the device.  High-level driver functions
* are defined in xuartlite.h.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -------------------------------------------------------
* 1.00b rpm  04/25/02 First release
* 1.00b rpm  07/07/03 Removed references to XUartLite_mGetControlReg macro
*                     since the control register is write-only
* 1.12a mta  03/21/07 Updated to new coding style
* </pre>
*
*****************************************************************************/

#ifndef XUARTLITE_L_H /* prevent circular inclusions */
#define XUARTLITE_L_H /* by using protection macros */

#ifdef __cplusplus
extern "C" {
#endif

/***************************** Include Files ********************************/

#include "xbasic_types.h"
#include "xio.h"

/************************** Constant Definitions ****************************/

/* UART Lite register offsets */

#define XUL_RX_FIFO_OFFSET		0	/* receive FIFO, read only */
#define XUL_TX_FIFO_OFFSET		4	/* transmit FIFO, write only */
#define XUL_STATUS_REG_OFFSET		8	/* status register, read only */
#define XUL_CONTROL_REG_OFFSET		12	/* control reg, write only */

/* control register bit positions */

#define XUL_CR_ENABLE_INTR		0x10	/* enable interrupt */
#define XUL_CR_FIFO_RX_RESET		0x02	/* reset receive FIFO */
#define XUL_CR_FIFO_TX_RESET		0x01	/* reset transmit FIFO */

/* status register bit positions */

#define XUL_SR_PARITY_ERROR		0x80
#define XUL_SR_FRAMING_ERROR		0x40
#define XUL_SR_OVERRUN_ERROR		0x20
#define XUL_SR_INTR_ENABLED		0x10	/* interrupt enabled */
#define XUL_SR_TX_FIFO_FULL		0x08	/* transmit FIFO full */
#define XUL_SR_TX_FIFO_EMPTY		0x04	/* transmit FIFO empty */
#define XUL_SR_RX_FIFO_FULL		0x02	/* receive FIFO full */
#define XUL_SR_RX_FIFO_VALID_DATA	0x01	/* data in receive FIFO */

/* the following constant specifies the size of the FIFOs, the size of the
 * FIFOs includes the transmitter and receiver such that it is the total number
 * of bytes that the UART can buffer
 */
#define XUL_FIFO_SIZE			16

/* Stop bits are fixed at 1. Baud, parity, and data bits are fixed on a
 * per instance basis
 */
#define XUL_STOP_BITS			1

/* Parity definitions
 */
#define XUL_PARITY_NONE			0
#define XUL_PARITY_ODD			1
#define XUL_PARITY_EVEN			2

/**************************** Type Definitions ******************************/

/***************** Macros (Inline Functions) Definitions ********************/

/*****************************************************************************
*
* Low-level driver macros and functions. The list below provides signatures
* to help the user use the macros.
*
* void XUartLite_mSetControlReg(u32 BaseAddress, u32 Mask)
* u32 XUartLite_mGetStatusReg(u32 BaseAddress)
*
* int XUartLite_mIsReceiveEmpty(u32 BaseAddress)
* int XUartLite_mIsTransmitFull(u32 BaseAddress)
* int XUartLite_mIsIntrEnabled(u32 BaseAddress)
*
* void XUartLite_mEnableIntr(u32 BaseAddress)
* void XUartLite_mDisableIntr(u32 BaseAddress)
*
* void XUartLite_SendByte(u32 BaseAddress, u8 Data);
* u8 XUartLite_RecvByte(u32 BaseAddress);
*
*****************************************************************************/

/****************************************************************************/
/**
*
* Set the contents of the control register. Use the XUL_CR_* constants defined
* above to create the bit-mask to be written to the register.
*
* @param	BaseAddress is the base address of the device
* @param	Mask is the 32-bit value to write to the control register
*
* @return	None.
*
* @note		C-style Signature:
*		void XUartLite_mSetControlReg(u32 BaseAddress, u32 Mask);
*
*****************************************************************************/
#define XUartLite_mSetControlReg(BaseAddress, Mask) \
		XIo_Out32((BaseAddress) + XUL_CONTROL_REG_OFFSET, (Mask))


/****************************************************************************/
/**
*
* Get the contents of the status register. Use the XUL_SR_* constants defined
* above to interpret the bit-mask returned.
*
* @param	BaseAddress is the  base address of the device
*
* @return	A 32-bit value representing the contents of the status register.
*
* @note		C-style Signature:
*		u32 XUartLite_mGetStatusReg(u32 BaseAddress);
*
*****************************************************************************/
#define XUartLite_mGetStatusReg(BaseAddress) \
		XIo_In32((BaseAddress) + XUL_STATUS_REG_OFFSET)


/****************************************************************************/
/**
*
* Check to see if the receiver has data.
*
* @param	BaseAddress is the  base address of the device
*
* @return	TRUE if the receiver is empty, FALSE if there is data present.
*
* @note		C-style Signature:
*		int XUartLite_mIsReceiveEmpty(u32 BaseAddress);
*
*****************************************************************************/
#define XUartLite_mIsReceiveEmpty(BaseAddress) \
  ((XUartLite_mGetStatusReg((BaseAddress)) & XUL_SR_RX_FIFO_VALID_DATA) != \
	XUL_SR_RX_FIFO_VALID_DATA)


/****************************************************************************/
/**
*
* Check to see if the transmitter is full.
*
* @param	BaseAddress is the  base address of the device
*
* @return	TRUE if the transmitter is full, FALSE otherwise.
*
* @note		C-style Signature:
* 		int XUartLite_mIsTransmitFull(u32 BaseAddress);
*
*****************************************************************************/
#define XUartLite_mIsTransmitFull(BaseAddress) \
	((XUartLite_mGetStatusReg((BaseAddress)) & XUL_SR_TX_FIFO_FULL) == \
	  XUL_SR_TX_FIFO_FULL)


/****************************************************************************/
/**
*
* Check to see if the interrupt is enabled.
*
* @param	BaseAddress is the  base address of the device
*
* @return	TRUE if the interrupt is enabled, FALSE otherwise.
*
* @note		C-style Signature:
*		int XUartLite_mIsIntrEnabled(u32 BaseAddress);
*
*****************************************************************************/
#define XUartLite_mIsIntrEnabled(BaseAddress) \
	((XUartLite_mGetStatusReg((BaseAddress)) & XUL_SR_INTR_ENABLED) == \
	  XUL_SR_INTR_ENABLED)


/****************************************************************************/
/**
*
* Enable the device interrupt. We cannot read the control register, so we
* just write the enable interrupt bit and clear all others. Since the only
* other ones are the FIFO reset bits, this works without side effects.
*
* @param	BaseAddress is the  base address of the device
*
* @return	None.
*
* @note		C-style Signature:
* 		void XUartLite_mEnableIntr(u32 BaseAddress);
*
*****************************************************************************/
#define XUartLite_mEnableIntr(BaseAddress) \
		XUartLite_mSetControlReg((BaseAddress), XUL_CR_ENABLE_INTR)


/****************************************************************************/
/**
*
* Disable the device interrupt. We cannot read the control register, so we
* just clear all bits. Since the only other ones are the FIFO reset bits,
* this works without side effects.
*
* @param	BaseAddress is the  base address of the device
*
* @return	None.
*
* @note		C-style Signature:
* 		void XUartLite_mDisableIntr(u32 BaseAddress);
*
*****************************************************************************/
#define XUartLite_mDisableIntr(BaseAddress) \
		XUartLite_mSetControlReg((BaseAddress), 0)


/************************** Function Prototypes *****************************/

void XUartLite_SendByte(u32 BaseAddress, u8 Data);
u8 XUartLite_RecvByte(u32 BaseAddress);

#ifdef __cplusplus
}
#endif

#endif /* end of protection macro */
