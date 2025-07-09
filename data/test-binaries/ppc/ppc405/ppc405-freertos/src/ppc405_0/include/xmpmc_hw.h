/* $Id: xmpmc_hw.h,v 1.1 2007/11/05 10:55:21 svemula Exp $ */
/******************************************************************************
*
*       XILINX IS PROVIDING THIS DESIGN, CODE, OR INFORMATION "AS IS"
*       AS A COURTESY TO YOU, SOLELY FOR USE IN DEVELOPING PROGRAMS AND
*       SOLUTIONS FOR XILINX DEVICES. BY PROVIDING THIS DESIGN, CODE,
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
/*****************************************************************************/
/**
*
* @file xmpmc_hw.h
*
* This header file contains identifiers and basic driver functions for the
* XMpmc device driver.
*
* @note		None.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a mta  02/24/07 First release
* 2.00a mta  10/24/07 Added support for Performance Monitoring and Static Phy
* </pre>
*
******************************************************************************/

#ifndef XMPMC_HW_H		/* prevent circular inclusions */
#define XMPMC_HW_H		/* by using protection macros */

#ifdef __cplusplus
extern "C" {
#endif

/***************************** Include Files *********************************/

#include "xbasic_types.h"
#include "xio.h"

/************************** Constant Definitions *****************************/

/** @name Register offsets
 * @{
 */

/* ECC Registers */
#define XMPMC_ECCCR_OFFSET	0x0  /**< ECC Control Register */
#define XMPMC_ECCSR_OFFSET	0x4  /**< ECC Status Register */
#define XMPMC_ECCSEC_OFFSET	0x8  /**< ECC Single Error Count Register */
#define XMPMC_ECCDEC_OFFSET	0xC  /**< ECC Double Error Count Register */
#define XMPMC_ECCPEC_OFFSET	0x10 /**< ECC Parity Field Error Count Reg */
#define XMPMC_ECCADDR_OFFSET	0x14 /**< ECC Error Address Register */

/* Interrupt Registers */
#define XMPMC_DGIE_OFFSET	0x1C /**< Device Global Interrupt Enable Reg */
#define XMPMC_IPISR_OFFSET	0x20 /**< IP Interrupt Status Register */
#define XMPMC_IPIER_OFFSET	0x24 /**< IP Interrupt Enable Register */

/* Static Phy */
#define XMPMC_SPIR_OFFSET	0x1000  /**< Static Phy Control Register */

/* Performance Monitor (PM) Registers */
#define XMPMC_PMCTRL_OFFSET	0x7000  /**< PM Control Register */
#define XMPMC_PMCLR_OFFSET	0x7004  /**< PM Clear Register */
#define XMPMC_PMSTATUS_OFFSET	0x7008  /**< PM Status Register */
#define XMPMC_PMGCC_OFFSET	0x7010  /**< PM Global Cycle Counter Register */
#define XMPMC_PMDCC_OFFSET	0x7020  /**< PM Dead Cycle Counter Port 0 */
#define XMPMC_PMDATABIN_OFFSET	0x8000  /**< PM Port-0 Data Bin-0 Register */

/*@}*/

/** @name ECC Control Register bitmaps and masks
 *
 * @{
 */
#define XMPMC_ECCCR_FORCE_PE_MASK 	0x10 /**< Force parity error */
#define XMPMC_ECCCR_FORCE_DE_MASK 	0x08 /**< Force double bit error */
#define XMPMC_ECCCR_FORCE_SE_MASK 	0x04 /**< Force single bit error */
#define XMPMC_ECCCR_RE_MASK		0x02 /**< ECC read enable */
#define XMPMC_ECCCR_WE_MASK		0x01 /**< ECC write enable */
/*@}*/

/** @name ECC Status Register bitmaps and masks
 *
 * @{
 */
#define XMPMC_ECCSR_ERR_SIZE_MASK	0xF000 /**< Error Transaction Size */
#define XMPMC_ECCSR_ERR_RNW_MASK	0x0800 /**< Error Transaction Rd/Wr */
#define XMPMC_ECCSR_SE_SYND_MASK	0x07F8 /**< Single bit error syndrome */
#define XMPMC_ECCSR_PE_MASK		0x0004 /**< Parity field bit error */
#define XMPMC_ECCSR_DE_MASK		0x0002 /**< Double bit error */
#define XMPMC_ECCSR_SE_MASK		0x0001 /**< Single bit error */
#define XMPMC_ECCSR_ERR_SIZE_SHIFT	12     /**< Error Transaction shift */
#define XMPMC_ECCSR_ERR_RNW_SHIFT	11     /**< Error Transc Rd/Wr shift */
#define XMPMC_ECCSR_SE_SYND_SHIFT	3      /**< Single error synd shift */

/*@}*/

/** @name Device Global Interrupt Enable Register bitmaps and masks
 *
 * Bit definitions for the global interrupt enable register.
 * @{
 */
#define XMPMC_DGIE_GIE_MASK		0x80000000  /**< Global Intr Enable */
/*@}*/

/** @name Interrupt Status and Enable Register bitmaps and masks
 *
 * Bit definitions for the interrupt status register and interrupt enable
 * registers.
 * @{
 */
#define XMPMC_IPIXR_PE_IX_MASK		0x4 /**< Parity field error interrupt */
#define XMPMC_IPIXR_DE_IX_MASK		0x2 /**< Double bit error interrupt */
#define XMPMC_IPIXR_SE_IX_MASK		0x1 /**< Single bit error interrupt */
/*@}*/


/** @name Static PHY Interface Register bitmaps and masks.
 *
 * Bit definitions for the PHY Interface Register.
 * @{
 */
#define XMPMC_SPIR_RDEN_DELAY_MASK	 0xF0000000 /**< Read Enable Delay */
#define XMPMC_SPIR_RDDATA_CLK_SEL_MASK	 0x08000000 /**< Read Data Clk Edge */
#define XMPMC_SPIR_RDDATA_SWAP_RISE_MASK 0x04000000 /**< Read Data Clk Shift */
#define XMPMC_SPIR_FIRST_RST_DONE_MASK	 0x01000000 /**< First Reset of Phy */
#define XMPMC_SPIR_DCM_PSEN_MASK	 0x00800000 /**< DCM Phase shift */
#define XMPMC_SPIR_DCM_PSINCDEC_MASK	 0x00400000 /**< DCM Phase shift
							  Increment/Decrement */
#define XMPMC_SPIR_DCM_DONE_MASK	 0x00200000 /**< DCM Phase shift Done */
#define XMPMC_SPIR_INIT_DONE_MASK	 0x00100000 /**< Init Done */
#define XMPMC_SPIR_DCM_TAP_VALUE_MASK	 0x000001FF /**< DCM Tap Value Mask */

#define XMPMC_SPIR_RDEN_DELAY_SHIFT	 28	    /**< Read Enable Delay */

/*@}*/

/** @name PM Control/Clear/Status Register bitmaps and masks
 *
 * @{
 */
#define XMPMC_PMREG_PM0_MASK 	0x80000000 /**< PM0 Mask */
#define XMPMC_PMREG_PM1_MASK 	0x40000000 /**< PM1 Mask */
#define XMPMC_PMREG_PM2_MASK 	0x20000000 /**< PM2 Mask */
#define XMPMC_PMREG_PM3_MASK 	0x10000000 /**< PM3 Mask */
#define XMPMC_PMREG_PM4_MASK 	0x08000000 /**< PM4 Mask */
#define XMPMC_PMREG_PM5_MASK 	0x04000000 /**< PM5 Mask */
#define XMPMC_PMREG_PM6_MASK 	0x02000000 /**< PM6 Mask */
#define XMPMC_PMREG_PM7_MASK 	0x01000000 /**< PM7 Mask */
#define XMPMC_PMREG_PM_ALL_MASK 0xFF000000 /**< PM All Mask */

/*@}*/

/**
 * @name Definitions for the Data bins registers of Performance Monitor
 * @{
 */
#define XMPMC_PM_DATABIN_QUAL0	0  /**< Qualifier 0 - Byte to Double words */
#define XMPMC_PM_DATABIN_QUAL1	1  /**< Qualifier 1 - Cache Line 4 */
#define XMPMC_PM_DATABIN_QUAL2	2  /**< Qualifier 2 - Cache Line 8 */
#define XMPMC_PM_DATABIN_QUAL3	3  /**< Qualifier 3 - Burst 16 */
#define XMPMC_PM_DATABIN_QUAL4	4  /**< Qualifier 4 - Burst 32 */
#define XMPMC_PM_DATABIN_QUAL5	5  /**< Qualifier 5 - Burst 64 */

#define XMPMC_PM_DATABIN_ACCESS_WRITE	0  /**< Write Access */
#define XMPMC_PM_DATABIN_ACCESS_READ	1  /**< Read Access */

#define XMPMC_PM_DATABIN_NUM_MIN	0   /**< Lowest Bin Number */
#define XMPMC_PM_DATABIN_NUM_MAX	31  /**< Highest Bin Number */

#define XMPMC_PM_DATABIN_PORT_REG_OFFSET	0x1000 /**< Address Offset
							* between data bins
							* of different Ports */

#define XMPMC_PM_DATABIN_QUAL_REG_OFFSET	0x200 /**< Address Offset
						       * between data bins
						       * of different
						       * Qualifiers */
#define XMPMC_PM_DATABIN_ACCESS_REG_OFFSET	0x100 /**< Address Offset
						       * between data bins
						       * of different
						       * Access types */


/*@}*/


/**************************** Type Definitions *******************************/

/***************** Macros (Inline Functions) Definitions *********************/

/****************************************************************************/
/**
*
* Write a value to a MPMC register. A 32 bit write is performed.
*
* @param	BaseAddress is the base address of the MPMC device.
* @param	RegOffset is the register offset from the base to write to.
* @param	Data is the data written to the register.
*
* @return	None.
*
* @note		C-style signature:
*		void XMpmc_mWriteReg(u32 BaseAddress, unsigned RegOffset,
					u32 Data);
*
****************************************************************************/
#define XMpmc_mWriteReg(BaseAddress, RegOffset, Data) \
			(XIo_Out32((BaseAddress) + (RegOffset), (u32)(Data)))

/****************************************************************************/
/**
*
* Read a value from a MPMC register. A 32 bit read is performed.
*
* @param	BaseAddress is the base address of the MPMC device.
* @param	Register is the register offset from the base to read from.
*
* @return	The value read from the register.
*
* @note		C-style signature:
*		u32 XMpmc_mReadReg(u32 BaseAddress, unsigned RegOffset);
*
****************************************************************************/
#define XMpmc_mReadReg(BaseAddress, RegOffset) \
					(XIo_In32((BaseAddress) + (RegOffset)))

/************************** Function Prototypes ******************************/

/************************** Variable Definitions *****************************/

#ifdef __cplusplus
}
#endif

#endif /* end of protection macro */
