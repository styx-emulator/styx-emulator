/* $Id: xiic_multi_master.c,v 1.1 2007/12/03 15:44:58 meinelte Exp $ */
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
* @file xiic_multi_master.c
*
* Contains multi-master functions for the XIic component. This file is
* necessary if multiple masters are on the IIC bus such that arbitration can
* be lost or the bus can be busy.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- --- ------- -----------------------------------------------
* 1.01b jhl 3/27/02 Reparitioned the driver
* 1.01c ecm 12/05/02 new rev
* 1.13a wgr  03/22/07 Converted to new coding style.
* </pre>
*
****************************************************************************/

/***************************** Include Files *******************************/

#include "xiic.h"
#include "xiic_i.h"
#include "xio.h"

/************************** Constant Definitions ***************************/


/**************************** Type Definitions *****************************/


/***************** Macros (Inline Functions) Definitions *******************/


/************************** Function Prototypes ****************************/

static void BusNotBusyHandler(XIic * InstancePtr);
static void ArbitrationLostHandler(XIic * InstancePtr);

/************************** Variable Definitions **************************/


/****************************************************************************/
/**
* This function includes multi-master code such that multi-master events are
* handled properly. Multi-master events include a loss of arbitration and
* the bus transitioning from busy to not busy.  This function allows the
* multi-master processing to be optional.  This function must be called prior
* to allowing any multi-master events to occur, such as after the driver is
* initialized.
*
* @note
*
* None
*
******************************************************************************/
void XIic_MultiMasterInclude()
{
	XIic_ArbLostFuncPtr = ArbitrationLostHandler;
	XIic_BusNotBusyFuncPtr = BusNotBusyHandler;
}

/*****************************************************************************/
/**
*
* The IIC bus busy signals when a master has control of the bus. Until the bus
* is released, i.e. not busy, other devices must wait to use it.
*
* When this interrupt occurs, it signals that the previous master has released
* the bus for another user.
*
* This interrupt is only enabled when the master Tx is waiting for the bus.
*
* This interrupt causes the following tasks:
* - Disable Bus not busy interrupt
* - Enable bus Ack
*     Should the slave receive have disabled acknowledgement, enable to allow
*     acknowledgment of the sending of our address to again be addresed as slave
* - Flush Rx FIFO
*     Should the slave receive have disabled acknowledgement, a few bytes may
*     be in FIFO if Rx full did not occur because of not enough byte in FIFO
*     to have caused an interrupt.
* - Send status to user via status callback with the value:
*    XII_BUS_NOT_BUSY_EVENT
*
* @param    InstancePtr is a pointer to the XIic instance to be worked on.
*
* @return
*
* None.
*
* @note
*
* None.
*
******************************************************************************/
static void BusNotBusyHandler(XIic * InstancePtr)
{
	u32 Status;
	u8 CntlReg;

	/* Should the slave receive have disabled acknowledgement,
	 * enable to allow acknowledgment of the sending of our address to
	 * again be addresed as slave
	 */
	CntlReg = XIo_In8(InstancePtr->BaseAddress + XIIC_CR_REG_OFFSET);
	XIo_Out8(InstancePtr->BaseAddress + XIIC_CR_REG_OFFSET,
		 (CntlReg & ~XIIC_CR_NO_ACK_MASK));

	/* Flush Tx FIFO by toggling TxFIFOResetBit. FIFO runs normally at 0
	 * Do this incase needed to Tx FIFO with more than expected if what
	 * was set to Tx was less than what the Master expected - read more
	 * from this slave so FIFO had junk in it
	 */
	XIic_mFlushTxFifo(InstancePtr);

	/* Flush Rx FIFO should slave rx had a problem, sent No ack but
	 * still received a few bytes. Should the slave receive have disabled
	 * acknowledgement, clear rx FIFO
	 */
	XIic_mFlushRxFifo(InstancePtr);

	/* Send Application messaging status via callbacks. Disable either Tx or
	 * Receive interrupt. Which callback depends on messaging direction.
	 */
	Status = XIIC_READ_IIER(InstancePtr->BaseAddress);
	if (InstancePtr->RecvBufferPtr == NULL) {
		/* Slave was sending data (master was reading), disable
		 * all the transmit interrupts
		 */
		XIIC_WRITE_IIER(InstancePtr->BaseAddress,
				      (Status & ~XIIC_TX_INTERRUPTS));
	}
	else {
		/* Slave was receiving data (master was writing) disable receive
		 * interrupts
		 */
		XIIC_WRITE_IIER(InstancePtr->BaseAddress,
				      (Status & ~XIIC_INTR_RX_FULL_MASK));
	}

	/* Send Status in StatusHandler callback
	 */
	InstancePtr->StatusHandler(InstancePtr->StatusCallBackRef,
				   XII_BUS_NOT_BUSY_EVENT);
}

/*****************************************************************************/
/**
*
* When multiple IIC devices attempt to use the bus simultaneously, only
* a single device will be able to keep control as a master. Those devices
* that didn't retain control over the bus are said to have lost arbitration.
* When arbitration is lost, this interrupt occurs sigaling the user that
* the message did not get sent as expected.
*
* This function, at arbitration lost:
*   - Disables tx empty, ½ empty and Tx error interrupts
*   - Clears any tx empty, ½ empty Rx Full or tx error interrupts
*   - Clears Arbitration lost interrupt,
*   - Flush Tx FIFO
*   - Call StatusHandler callback with the value: XII_ARB_LOST_EVENT
*
* @param    InstancePtr is a pointer to the XIic instance to be worked on.
*
* @return
*
* None.
*
* @note
*
* None.
*
******************************************************************************/
static void ArbitrationLostHandler(XIic * InstancePtr)
{
	/* Disable tx empty and ½ empty and Tx error interrupts before clearing them
	 * so they won't occur again
	 */
	XIic_mDisableIntr(InstancePtr->BaseAddress, XIIC_TX_INTERRUPTS);

	/* Clear any tx empty, ½ empty Rx Full or tx error interrupts
	 */
	XIic_mClearIntr(InstancePtr->BaseAddress, XIIC_TX_INTERRUPTS);

	XIic_mFlushTxFifo(InstancePtr);

	/* Update Status via StatusHandler callback
	 */
	InstancePtr->StatusHandler(InstancePtr->StatusCallBackRef,
				   XII_ARB_LOST_EVENT);
}
