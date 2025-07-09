/*********************************************************************************

Copyright(c) 2007 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_fat.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the FAT FSD driver.

*********************************************************************************/

#ifndef __ADI_FAT_H__
#define __ADI_FAT_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <drivers/adi_dev.h>
#include <services/fss/adi_fss.h>

#if !defined(__ADI_FAT_C__)
// entry point to the device driver
extern ADI_DEV_PDD_ENTRY_POINT ADI_FAT_EntryPoint;

/*******************************************************************
* The following is the default configuration for the FAT driver.
* To use, define the _ADI_FAT_NODEF_ macro in the enclosing file.
*******************************************************************/
#if defined(_ADI_FAT_DEFAULT_DEF_)

/*******************************************************************
* definition structure for FAT driver - exported to application
*******************************************************************/
static ADI_FSS_DEVICE_DEF ADI_FAT_Def = {
    0,                                      /* N/A for FSD drivers                    */
    &ADI_FAT_EntryPoint,                    /* Entry Points for FAT Driver            */
    NULL,                                   /* Command Table to configure FAT driver  */
    NULL,                                   /* Critical region data                   */
    ADI_DEV_DIRECTION_BIDIRECTIONAL,        /* Direction (RW file system)             */
    NULL
};

#endif /* _ADI_FAT_NODEF_ */



#endif /* __ADI_FAT_C__ */

/*******************************************************************
* Device Specific control commands
*******************************************************************/
enum {
    ADI_FAT_CMD_START = ADI_FSD_CUSTOM_CMD_START,   /* (0x000B6000) */
    ADI_FAT_CMD_SET_CACHE_PERFORMANCE,  /* (0x000B6001) Set cache performance ,
                                            this control takes a
                                            ADI_FAT_CACHE_PERFORMANCE_XXX argument
                                            as the control value */
    ADI_FAT_CMD_SET_FAT_CACHE_SIZE,     /* (0x000B6001) Set FAT cache size, a value
                                            of 0 will set the FAT cache to the
                                            default, the cache size will be set to
                                            either Value or the FAT BPB FatSize
                                            argument, which ever is the smaller of
                                            the two values */
    ADI_FAT_CMD_SET_DIR_CACHE_SIZE,     /* (0x000B6002) Set directory cache size, a
                                            value of zero will set the size to the
                                            driver default value */
    ADI_FAT_CMD_SET_FILE_CACHE_SIZE,    /* (0x000B6003) Set file cache size, a
                                            value of zero will disable the file
                                            cache. This is the defualt value and
                                            what should be used if the FSS file
                                            cache is being used */
    ADI_FAT_CMD_ENABLE_ACCESS_DATE,      /* (0x000B6004) TRUE enables the updating
                                            of the file access date on opening and
                                            closing a file. FALSE disabled the access
                                            date from updating on open and close only
                                            on modify will the time be updated. */
    ADI_FAT_CMD_SHOW_HIDDEN_SYSTEM,      /* (0x000B6005) TRUE enables the reporting of
                                            the directory entry FALSE disables the
                                            reporting. Default is FALSE. */
    ADI_FAT_CMD_SET_FREE_CLUSTER_COUNT,   /* (0x000B6006) Sets the current free
                                            cluster counter */
    ADI_FAT_CMD_ENABLE_USAGE_STATS       /* (0x000B6007) Sets the current free
                                            cluster counter */
};

/*******************************************************************
* Device Specific return codes
*******************************************************************/
enum {
    ADI_FAT_RESULT_SUCCESS = 0,
    ADI_FAT_RESULT_FAILED = 1,

    ADI_FAT_RESULT_START = ADI_FSD_CUSTOM_CMD_START,    /* (0x000B6000) */
    ADI_FAT_RESULT_INVALID_ATTRIBUTE                    /* (0x000B6001) Invalid File attribute */
};

enum {
    ADI_FAT_CACHE_PERFORMANCE_FASTEST,  /* Only flush cache on Unmount */
    ADI_FAT_CACHE_PERFORMANCE_FAST,     /* Flush on close file/directory and
                                            un-mount */
    ADI_FAT_CACHE_PERFORMANCE_RELIABLE  /* Flush all changes immediatly */
};

enum {
    ADI_FAT_DIR_READONLY        = 0x01,
    ADI_FAT_DIR_HIDDEN          = 0x02,
    ADI_FAT_DIR_SYSTEM          = 0x04,
    ADI_FAT_DIR_VOLUME_LABEL    = 0x08,
    ADI_FAT_DIR_LONG_FILE_NAME  = 0x0F,
    ADI_FAT_DIR_SUBDIRECTORY    = 0x10,
    ADI_FAT_DIR_ARCHIVE         = 0x20,
    ADI_FAT_DIR_DEVICE          = 0x40,
};

#define ADI_FAT_IS_ATTR(V,A)       ( ((V)&(A))==A )

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_FAT_H__ */
