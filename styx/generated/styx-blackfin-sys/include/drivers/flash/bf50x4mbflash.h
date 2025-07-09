/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2009 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     bf50x4mbflash.h						                           */
/*                                                                             */
/*    PURPOSE:  This header file defines items specific to the bf50x4mbflash.  */
/*                                                                             */
/*                                                                             */
/*******************************************************************************/

#ifndef __BF50X4MBFLASH_H__
#define __BF50X4MBFLASH_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_5_1:"ADI header uses long identifier names")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */

/* application definitions */
#define FLASH_MANUFACTURER_BF50X4MBFLASH	0x20
#define FLASH_DEVICE_BF50X4MBFLASH 			0x8866

#define ERASE_TIMEOUT			50000000
#define PROGRAM_TIMEOUT			1000000

/* interface function prototypes */
ERROR_CODE bf50x4mbflash_Open(void);					/* open the flash device */
ERROR_CODE bf50x4mbflash_Close(void);					/* close the flas device */
ERROR_CODE bf50x4mbflash_Read(unsigned short *pusData,	/* read some bytes from flash */
					    unsigned long ulStartAddress,
					    unsigned int uiCount );
ERROR_CODE bf50x4mbflash_Write(unsigned short *pusData,	/* write some bytes to flash */
					     unsigned long ulStartAddress,
					     unsigned int uiCount );
ERROR_CODE bf50x4mbflash_Control(unsigned int uiCmd,	/* send a command to device */
						   COMMAND_STRUCT *pCmdStruct);

#endif	/* __BF50X4MBFLASH_H__ */
