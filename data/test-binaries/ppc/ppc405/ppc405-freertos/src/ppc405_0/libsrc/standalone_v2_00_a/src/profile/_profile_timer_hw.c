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
// $Header: /devl/xcs/repo/env/Jobs/MDT/sw/bsp/standalone/v2_00_a/src/profile/Attic/_profile_timer_hw.c,v 1.1.2.1 2006/01/17 19:56:32 vasanth Exp $
// $Id: _profile_timer_hw.c,v 1.1.2.1 2006/01/17 19:56:32 vasanth Exp $
//
// _program_timer_hw.c:
//	Timer related functions
//
//////////////////////////////////////////////////////////////////////

#include "profile.h"

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


//--------------------------------------------------------------------
// PowerPC PIT Timer Init.
//	Defined only if PIT Timer is used for Profiling
//
//--------------------------------------------------------------------
#ifdef PPC_PIT_INTERRUPT
int ppc_pit_init( void )
{
	// 1. Register Profile_intr_handler as Interrupt handler
	// 2. Set PIT Timer Interrupt and Enable it.
	XExc_RegisterHandler( XEXC_ID_PIT_INT,
			    (XExceptionHandler)profile_intr_handler,(void *)0);
	XTime_PITSetInterval( timer_clk_ticks ) ;
	XTime_PITEnableAutoReload() ;
	return 0;
}
#endif


//--------------------------------------------------------------------
// PowerPC Timer Initialization functions.
//	For PowerPC, PIT and opb_timer can be used for Profiling. This
//	is selected by the user in standalone BSP
//
//--------------------------------------------------------------------
int powerpc405_init()
{
	XExc_Init() ;
	XExc_mDisableExceptions( XEXC_NON_CRITICAL ) ;

	// Initialize the Timer.
	// 1. If PowerPC PIT Timer has to be used, initialize PIT timer.
	// 2. Else use opb_timer. It can be directly connected or thru intc to PowerPC
#ifdef PPC_PIT_INTERRUPT
	ppc_pit_init();
#else
#ifdef TIMER_CONNECT_INTC
	XExc_RegisterHandler( XEXC_ID_NON_CRITICAL_INT,
			      (XExceptionHandler)XIntc_DeviceInterruptHandler,(void *)0);
	XIntc_RegisterHandler( INTC_BASEADDR, PROFILE_TIMER_INTR_ID,
			     (XInterruptHandler)profile_intr_handler,(void*)0);
#else
	XExc_RegisterHandler( XEXC_ID_NON_CRITICAL_INT,
			      (XExceptionHandler)profile_intr_handler,(void *)0);
#endif
	// Initialize the timer with Timer Ticks
	opb_timer_init() ;
#endif

	// Enable Interrupts in the System, if Profile Timer is the only Interrupt
	// in the System.
#ifdef ENABLE_SYS_INTR
#ifdef PPC_PIT_INTERRUPT
	XTime_PITEnableInterrupt() ;
#elif TIMER_CONNECT_INTC
	XIntc_mMasterEnable( INTC_BASEADDR );
	XIntc_SetIntrSvcOption( INTC_BASEADDR, XIN_SVC_ALL_ISRS_OPTION);
	XIntc_mEnableIntr( INTC_BASEADDR, PROFILE_TIMER_INTR_MASK );
#endif
	XExc_mEnableExceptions( XEXC_NON_CRITICAL ) ;
#endif
}

#endif	// PROC_PPC



//--------------------------------------------------------------------
// opb_timer Initialization for PowerPC and MicroBlaze. This function
// is not needed if PIT timer is used in PowerPC
//
//--------------------------------------------------------------------
#ifndef PPC_PIT_INTERRUPT
int opb_timer_init( void )
{
	// set the number of cycles the timer counts before interrupting
	XTmrCtr_mSetLoadReg(PROFILE_TIMER_BASEADDR, 0, timer_clk_ticks);

	// reset the timers, and clear interrupts
	XTmrCtr_mSetControlStatusReg(PROFILE_TIMER_BASEADDR, 0,
				     XTC_CSR_INT_OCCURED_MASK | XTC_CSR_LOAD_MASK );

	// start the timers
	XTmrCtr_mSetControlStatusReg(PROFILE_TIMER_BASEADDR, 0, XTC_CSR_ENABLE_TMR_MASK
			     | XTC_CSR_ENABLE_INT_MASK | XTC_CSR_AUTO_RELOAD_MASK | XTC_CSR_DOWN_COUNT_MASK);
	return 0;
}
#endif


//--------------------------------------------------------------------
// MicroBlaze Target - Timer related functions
//--------------------------------------------------------------------
#ifdef PROC_MICROBLAZE

//--------------------------------------------------------------------
// Initialize the Profile Timer for MicroBlaze Target.
//	For MicroBlaze, opb_timer is used. The opb_timer can be directly
//	connected to MicroBlaze or connected through Interrupt Controller.
//
//--------------------------------------------------------------------
int microblaze_init()
{
	// Register profile_intr_handler
	// 1. If timer is connected to Interrupt Controller, register the handler
	//    to Interrupt Controllers vector table.
	// 2. If timer is directly connected to MicroBlaze, register the handler
	//    as Interrupt handler
#ifdef TIMER_CONNECT_INTC
	XIntc_RegisterHandler( INTC_BASEADDR, PROFILE_TIMER_INTR_ID,
			     (XInterruptHandler)profile_intr_handler,(void*)0);
#else
	microblaze_register_handler( (XInterruptHandler)profile_intr_handler,
				     (void *)0) ;
#endif

	// Initialize the timer with Timer Ticks
	opb_timer_init() ;

	// Enable Interrupts in the System, if Profile Timer is the only Interrupt
	// in the System.
#ifdef ENABLE_SYS_INTR
#ifdef TIMER_CONNECT_INTC
	XIntc_mMasterEnable( INTC_BASEADDR );
	XIntc_SetIntrSvcOption( INTC_BASEADDR, XIN_SVC_ALL_ISRS_OPTION);
	XIntc_mEnableIntr( INTC_BASEADDR, PROFILE_TIMER_INTR_MASK );
#endif
	microblaze_enable_interrupts();
#endif
}

#endif	// PROC_MICROBLAZE
