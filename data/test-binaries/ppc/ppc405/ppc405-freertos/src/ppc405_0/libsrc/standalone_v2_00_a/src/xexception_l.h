/* $Id: xexception_l.h,v 1.3.2.1 2006/01/17 19:56:32 vasanth Exp $ */
/******************************************************************************
*
* Copyright (c) 2004 Xilinx, Inc.  All rights reserved.
*
* Xilinx, Inc.
* XILINX IS PROVIDING THIS DESIGN, CODE, OR INFORMATION "AS IS" AS A
* COURTESY TO YOU.  BY PROVIDING THIS DESIGN, CODE, OR INFORMATION AS
* ONE POSSIBLE   IMPLEMENTATION OF THIS FEATURE, APPLICATION OR
* STANDARD, XILINX IS MAKING NO REPRESENTATION THAT THIS IMPLEMENTATION
* IS FREE FROM ANY CLAIMS OF INFRINGEMENT, AND YOU ARE RESPONSIBLE
* FOR OBTAINING ANY RIGHTS YOU MAY REQUIRE FOR YOUR IMPLEMENTATION.
* XILINX EXPRESSLY DISCLAIMS ANY WARRANTY WHATSOEVER WITH RESPECT TO
* THE ADEQUACY OF THE IMPLEMENTATION, INCLUDING BUT NOT LIMITED TO
* ANY WARRANTIES OR REPRESENTATIONS THAT THIS IMPLEMENTATION IS FREE
* FROM CLAIMS OF INFRINGEMENT, IMPLIED WARRANTIES OF MERCHANTABILITY
* AND FITNESS FOR A PARTICULAR PURPOSE.
*
******************************************************************************/
/*****************************************************************************/
/**
*
* @file xexception_l.h
*
* This header file contains identifiers and low-level driver functions (or
* macros) that can be used to access the device.  The user should refer to the
* hardware device specification for more details of the device operation.
*
* <pre>
* MODIFICATION HISTORY:
*
* Ver   Who  Date     Changes
* ----- ---- -------- -----------------------------------------------
* 1.00a ch   06/18/02 First release
* 1.00a st   07/21/04 Commented typedef for XException_Handler as this
*                     will be part of xbasic_types.h
* </pre>
*
******************************************************************************/

#ifndef XEXCEPTION_L_H /* prevent circular inclusions */
#define XEXCEPTION_L_H /* by using protection macros */

/***************************** Include Files ********************************/

#include "xbasic_types.h"
#include "xpseudo_asm.h"

#ifdef __cplusplus
extern "C" {
#endif

/************************** Constant Definitions ****************************/

#define XEXC_CRITICAL                      0x00020000
#define XEXC_NON_CRITICAL                  0x00008000
#define XEXC_ALL                           0x00028000

#define XEXC_ID_FIRST                      0
#define XEXC_ID_JUMP_TO_ZERO               0
#define XEXC_ID_CRITICAL_INT               1
#define XEXC_ID_MACHINE_CHECK              2
#define XEXC_ID_DATA_STORAGE_INT           3
#define XEXC_ID_INSTUCTION_STORAGE_INT     4
#define XEXC_ID_NON_CRITICAL_INT           5
#define XEXC_ID_ALIGNMENT_INT              6
#define XEXC_ID_PROGRAM_INT                7
#define XEXC_ID_FPU_UNAVAILABLE_INT        8
#define XEXC_ID_SYSTEM_CALL                9
#define XEXC_ID_APU_AVAILABLE              10
#define XEXC_ID_PIT_INT                    11
#define XEXC_ID_FIT_INT                    12
#define XEXC_ID_WATCHDOG_TIMER_INT         13
#define XEXC_ID_DATA_TLB_MISS_INT          14
#define XEXC_ID_INSTRUCTION_TLB_MISS_INT   15
#define XEXC_ID_DEBUG_INT                  16
#define XEXC_ID_LAST                       16

/**************************** Type Definitions ******************************/

//typedef void (*XExceptionHandler)(void *DataPtr);

typedef struct
{
   XExceptionHandler Handler;
   void *DataPtr;
   void *ReadOnlySDA;
   void *ReadWriteSDA;
} XExc_VectorTableEntry;

/***************** Macros (Inline Functions) Definitions ********************/

/*****************************************************************************
*
* Low-level driver macros.  The list below provides signatures to help the
* user use the macros.
*
* XExc_mEnableExceptions(EnableMask)
* XExc_mDisableExceptions(DisableMask)
*
*****************************************************************************/

/****************************************************************************/
/**
* Enable Exceptions.
*
* @param    Bitmask for exceptions to be enabled.
*
* @return   None.
*
* @note     None.
*
******************************************************************************/
#define XExc_mEnableExceptions(EnableMask) \
            mtmsr(mfmsr() | EnableMask)

/****************************************************************************/
/**
* Disable Exceptions.
*
* @param    Bitmask for exceptions to be enabled.
*
* @return   None.
*
* @note     None.
*
******************************************************************************/
#define XExc_mDisableExceptions(DisableMask) \
            mtmsr(mfmsr() & ~ DisableMask)

/************************** Variable Definitions ****************************/

/************************** Function Prototypes *****************************/
extern void * _vectorbase(void);

void XExc_Init(void);

void XExc_RegisterHandler(Xuint8 ExceptionId, XExceptionHandler Handler,
                          void *DataPtr);

void XExc_RemoveHandler(Xuint8 ExceptionId);

#ifdef __cplusplus
}
#endif

#endif
