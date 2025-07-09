//////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2004 Xilinx, Inc.  All rights reserved.
// Xilinx, Inc.
//
// XILINX IS PROVIDING THIS DESIGN, CODE, OR INFORMATION "AS IS" AS A
// COURTESY TO YOU.  BY PROVIDING THIS DESIGN, CODE, OR INFORMATION AS
// ONE POSSIBLE   IMPLEMENTATION OF THIS FEATURE, APPLICATION OR
// STANDARD, XILINX IS MAKING NO REPRESENTATION THAT THIS IMPLEMENTATION
// IS FREE FROM ANY CLAIMS OF INFRINGEMENT, AND YOU ARE RESPONSIBLE
// FOR OBTAINING ANY RIGHTS YOU MAY REQUIRE FOR YOUR IMPLEMENTATION.
// XILINX EXPRESSLY DISCLAIMS ANY WARRANTY WHATSOEVER WITH RESPECT TO
// THE ADEQUACY OF THE IMPLEMENTATION, INCLUDING BUT NOT LIMITED TO
// ANY WARRANTIES OR REPRESENTATIONS THAT THIS IMPLEMENTATION IS FREE
// FROM CLAIMS OF INFRINGEMENT, IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE.
//
// $Header: /devl/xcs/repo/env/Jobs/MDT/sw/bsp/standalone/v2_00_a/src/profile/Attic/_profile_timer_hw.h,v 1.1.2.1 2006/01/17 19:56:32 vasanth Exp $
// $Id: _profile_timer_hw.h,v 1.1.2.1 2006/01/17 19:56:32 vasanth Exp $
//
// _program_timer_hw.h:
//	Timer related functions
//
//////////////////////////////////////////////////////////////////////

#ifndef _PROFILE_TIMER_HW_H
#define _PROFILE_TIMER_HW_H

#include "profile.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef PROC_PPC
#include "xexception_l.h"
#include "xtime_l.h"
#include "xpseudo_asm.h"
#endif

#ifdef TIMER_CONNECT_INTC
#include "xintc_l.h"
#include "xintc.h"
#endif	// TIMER_CONNECT_INTC

#ifndef PPC_PIT_INTERRUPT
#include "xtmrctr_l.h"
#endif

extern unsigned int timer_clk_ticks ;

//--------------------------------------------------------------------
// PowerPC Target - Timer related functions
//--------------------------------------------------------------------
#ifdef PROC_PPC
#ifdef PPC_PIT_INTERRUPT
unsigned long timer_lo_clk_ticks ;	// Clk ticks when Timer is disabled in CG
#endif

//--------------------------------------------------------------------
// Disable the Timer - During Profiling
//
// For PIT Timer -
//	1. XTime_PITDisableInterrupt() ;
//	2. Store the remaining timer clk tick
//	3. Stop the PIT Timer
//--------------------------------------------------------------------
#ifdef PPC_PIT_INTERRUPT
#define disable_timer() 		\
	{				\
		unsigned long val;	\
		val=mfspr(XREG_SPR_TCR);	\
		mtspr(XREG_SPR_TCR, val & ~XREG_TCR_PIT_INTERRUPT_ENABLE);	\
		timer_lo_clk_ticks = mfspr(XREG_SPR_PIT);			\
		mtspr(XREG_SPR_PIT, 0);	\
	}
#else
#define disable_timer() 		\
	{				\
	XTmrCtr_mDisable(PROFILE_TIMER_BASEADDR, 0 ); \
	}
#endif



//--------------------------------------------------------------------
// Enable the Timer
//
// For PIT Timer -
//	1. Load the remaining timer clk ticks
//	2. XTime_PITEnableInterrupt() ;
//--------------------------------------------------------------------
#ifdef PPC_PIT_INTERRUPT
#define enable_timer()				\
	{					\
		unsigned long val;		\
		val=mfspr(XREG_SPR_TCR);	\
		mtspr(XREG_SPR_PIT, timer_lo_clk_ticks);	\
		mtspr(XREG_SPR_TCR, val | XREG_TCR_PIT_INTERRUPT_ENABLE); \
	}
#else
#define enable_timer()						\
	{							\
		XTmrCtr_mEnable(PROFILE_TIMER_BASEADDR, 0 );	\
	}
#endif



//--------------------------------------------------------------------
// Send Ack to Timer Interrupt
//
// For PIT Timer -
// 	1. Load the timer clk ticks
//	2. Enable AutoReload and Interrupt
//	3. Clear PIT Timer Status bits
//--------------------------------------------------------------------
#ifdef PPC_PIT_INTERRUPT
#define timer_ack()							\
	{								\
		unsigned long val;					\
		mtspr(XREG_SPR_PIT, timer_clk_ticks);			\
		mtspr(XREG_SPR_TSR, XREG_TSR_PIT_INTERRUPT_STATUS);	\
		val=mfspr(XREG_SPR_TCR);				\
		mtspr(XREG_SPR_TCR, val| XREG_TCR_PIT_INTERRUPT_ENABLE| XREG_TCR_AUTORELOAD_ENABLE); \
	}
#else
#define timer_ack()				\
	{						\
		unsigned int csr;			\
		csr = XTmrCtr_mGetControlStatusReg(PROFILE_TIMER_BASEADDR, 0);	\
		XTmrCtr_mSetControlStatusReg(PROFILE_TIMER_BASEADDR, 0, csr);	\
	}
#endif

//--------------------------------------------------------------------
#endif	// PROC_PPC
//--------------------------------------------------------------------


//--------------------------------------------------------------------
// MicroBlaze Target - Timer related functions
//--------------------------------------------------------------------
#ifdef PROC_MICROBLAZE

//--------------------------------------------------------------------
// Disable the Timer during Call-Graph Data collection
//
//--------------------------------------------------------------------
#define disable_timer()					\
	{						\
                XTmrCtr_mDisable(PROFILE_TIMER_BASEADDR, 0 );	\
        }


//--------------------------------------------------------------------
// Enable the Timer after Call-Graph Data collection
//
//--------------------------------------------------------------------
#define enable_timer()					\
	{						\
		XTmrCtr_mEnable(PROFILE_TIMER_BASEADDR, 0 ); \
	}


//--------------------------------------------------------------------
// Send Ack to Timer Interrupt
//
//--------------------------------------------------------------------
#define timer_ack()				\
	{						\
		unsigned int csr;			\
		csr = XTmrCtr_mGetControlStatusReg(PROFILE_TIMER_BASEADDR, 0);	\
		XTmrCtr_mSetControlStatusReg(PROFILE_TIMER_BASEADDR, 0, csr);	\
	}

//--------------------------------------------------------------------
#endif	// PROC_MICROBLAZE
//--------------------------------------------------------------------

#ifdef __cplusplus
}
#endif

#endif
