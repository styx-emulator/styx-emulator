/*******************************************************************************/
/*                                                                             */
/*   (C) Copyright 2004 - Analog Devices, Inc.  All rights reserved.           */
/*                                                                             */
/*    FILE:     a d i _ f l a s h . h ( )     					               */
/*																			   */
/*    PURPOSE:  This header file defines the devices commands.				   */
/*                                                                             */
/*******************************************************************************/

#ifndef __ADI_FLASH_H__
#define __ADI_FLASH_H__

#ifdef _MISRA_RULES
#pragma diag(suppress:misra_rule_5_7:"ADI header will re-use identifiers")
#pragma diag(suppress:misra_rule_6_3:"ADI header allows use of basic types")
#pragma diag(suppress:misra_rule_18_4:"ADI header requires use of unions")
#pragma diag(suppress:misra_rule_19_15:"ADI header defines and/or undefines macros within a block")
#endif /* _MISRA_RULES */

/* Get-Codes data type */
typedef struct Get_Codes_Struct
{
	unsigned long	*pManCode;
	unsigned long	*pDevCode;
	unsigned long 	ulFlashStartAddr;

}GET_CODES_STRUCT;

/* Reset data type */
typedef struct Reset_Struct
{
 	unsigned long 	ulFlashStartAddr;

}RESET_STRUCT;

/* Erase-All data type */
typedef struct Erase_All_Struct
{
 	unsigned long 	ulFlashStartAddr;

}ERASE_ALL_STRUCT;

/* Erase-Sector data type */
typedef struct Erase_Sector_Struct
{
 	int 			nSectorNum;
 	unsigned long 	ulFlashStartAddr;

}ERASE_SECTOR_STRUCT;


/* Get-Sector-Number data type */
typedef struct Get_SectNum_Struct
{
	unsigned long	ulOffset;
	unsigned long	*pSectorNum;

}GET_SECTNUM_STRUCT;

/* Get-Sector-Start-End data type */
typedef struct Get_SectStartEnd_Struct
{
	int 	nSectorNum;
	unsigned long	*pStartOffset;
	unsigned long	*pEndOffset;

}GET_SECTSTARTEND_STRUCT;

/* Get-Description data type */
typedef struct Get_Desc_Struct
{
	char	*pTitle;
	char	*pDesc;
	char 	*pFlashCompany;

}GET_DESC_STRUCT;

/* Get-Num Sectors data type */
typedef struct Get_NumSectors_Struct
{
	int		*pnNumSectors;

}GET_NUM_SECTORS_STRUCT;

/* Get-Flash-Width data type */
typedef struct Get_Flash_Width_Struct
{
	int		*pnFlashWidth;

}GET_FLASH_WIDTH_STRUCT;

/* Supports-CFI data type */
typedef struct Supports_CFI_Struct
{
	bool	*pbSupportsCFI;

}SUPPORTS_CFI_STRUCT;

/* Get-CFI-Data data type */
typedef struct Get_CFI_Data_Struct
{
	void *pCFIData;
	unsigned long 	ulFlashStartAddr;

}GET_CFI_DATA_STRUCT;


/* union describing all the data types */
typedef union
{
	ERASE_ALL_STRUCT		SEraseAll;
	ERASE_SECTOR_STRUCT		SEraseSect;
	GET_CODES_STRUCT		SGetCodes;
	GET_DESC_STRUCT			SGetDesc;
	GET_SECTNUM_STRUCT		SGetSectNum;
	GET_SECTSTARTEND_STRUCT SSectStartEnd;
	RESET_STRUCT			SReset;
	GET_NUM_SECTORS_STRUCT	SGetNumSectors;
	GET_FLASH_WIDTH_STRUCT	SGetFlashWidth;
	SUPPORTS_CFI_STRUCT		SSupportsCFI;
	GET_CFI_DATA_STRUCT		SGetCFIData;
}COMMAND_STRUCT;


#endif	/* __ADI_ADI_FLASH_H__ */
