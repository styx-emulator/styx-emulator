/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     m29w320.h						                               */
/*                                                                             */
/*    PURPOSE:  This header file defines items specific to the M29W320 flash.  */
/*                                                                             */
/*******************************************************************************/

#ifndef __M29W320_H__
#define __M29W320_H__

/* application definitions */
#define FLASH_MANUFACTURER_ST      0x20
#define FLASH_DEVCODE_ST_M29W320DB 0x22CB
#define FLASH_DEVCODE_ST_M29W320EB 0x2257

/* interface function prototypes */
ERROR_CODE m29w320_Open(void);						/* open the flash device */
ERROR_CODE m29w320_Close(void);						/* close the flas device */
ERROR_CODE m29w320_Read(unsigned short *pusData,	/* read some bytes from flash */
					    unsigned long ulStartAddress,
					    unsigned int uiCount );
ERROR_CODE m29w320_Write(unsigned short *pusData,	/* write some bytes to flash */
					     unsigned long ulStartAddress,
					     unsigned int uiCount );
ERROR_CODE m29w320_Control(unsigned int uiCmd,		/* send a command to device */
						   COMMAND_STRUCT *pCmdStruct);

#endif	/* __M29W320_H__ */
