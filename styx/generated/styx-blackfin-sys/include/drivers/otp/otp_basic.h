/*********************************************************************************

Copyright(c) 2004 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

Description:
			This is a header file for the basic OTP driver.

*********************************************************************************/

#ifndef __OTP_BASIC_H__
#define __OTP_BASIC_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_5_1:"ADI header uses long identifier names")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */

/*********************************************************************

Extensible enumerations and defines

*********************************************************************/

enum
{
	/* command IDs */
	ADI_OTP_CMD_START,					/* starting point */
    ADI_OTP_CMD_SET_ACCESS_MODE,		/* set the access mode */
    ADI_OTP_CMD_SET_TIMING,				/* set timing value */
    ADI_OTP_CMD_CLOSE,					/* close */
    ADI_OTP_CMD_INIT					/* init */
};

enum
{
	/* return codes */
	ADI_OTP_RESULT_SUCCESS,				/* starting point */
	ADI_OTP_MASTER_ERROR,
	ADI_OTP_WRITE_ERROR,
	ADI_OTP_READ_ERROR,
	ADI_OTP_ACC_VIO_ERROR,
	ADI_OTP_DATA_MULT_ERROR,
	ADI_OTP_ECC_MULT_ERROR,
	ADI_OTP_PREV_WR_ERROR,
	ADI_OTP_DATA_SB_WARN,
	ADI_OTP_ECC_SB_WARN,
	ADI_OTP_SILICON_REV_NOT_SUPPORTED,
	ADI_OTP_RESULT_NOT_SUPPORTED
};

#define	ADI_OTP_INIT			(0x00000001)
#define	ADI_OTP_CLOSE			(0x00000002)

#define ADI_OTP_LOWER_HALF      		(0x00000000)	/* select upper/lower 64-bit half (bit 0) */
#define ADI_OTP_UPPER_HALF      		(0x00000001)
#define ADI_OTP_NO_ECC 					(0x00000010)	/* do not use ECC (bit 4) */
#define ADI_OTP_LOCK 					(0x00000020)	/* sets page protection bit for page (bit 5) */
#define ADI_OTP_CHECK_FOR_PREV_WRITE 	(0x00000080)    /* for ECC corrected writes, check if page has been previously written */

#define ADI_OTP_ACCESS_READ			(0x1000)			/* read-only */
#define ADI_OTP_ACCESS_READWRITE	(0x2000)			/* read/write */


/*********************************************************************

Function prototypes

*********************************************************************/

u32 otp_basic_Open(void);
u32 otp_basic_Close(void);
u32 otp_basic_Read(u32 page, u32 flags, u64 *pData);
u32 otp_basic_Write(u32 page, u32 flags, u64 *pData);
u32 otp_basic_Control(u32 Command, void *Value);


#endif /* __OTP_BASIC_H__ */
