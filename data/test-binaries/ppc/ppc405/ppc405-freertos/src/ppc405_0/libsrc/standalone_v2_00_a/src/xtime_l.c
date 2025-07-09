/*-----------------------------------------------------------------------------
//     $Date: 2006/01/17 19:56:32 $
//     $RCSfile: xtime_l.c,v $
//-----------------------------------------------------------------------------
//
// Copyright (c) 2004 Xilinx, Inc.  All rights reserved.
//
// Xilinx, Inc.
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
//---------------------------------------------------------------------------*/

#include "xtime_l.h"
#include "xpseudo_asm.h"

/****************************************************************************
*
* Set the time in the Time Base Register
*
* @param    Value to be written to the Time Base Register
*
* @return   None.
*
* @note     None.
*
*
****************************************************************************/

void XTime_SetTime(XTime Xtime)
{
  mtspr(XREG_SPR_TBL_WRITE, 0);          /* set TBL to 0 to avoid ripple */
  mtspr(XREG_SPR_TBU_WRITE, (unsigned int) (Xtime >> 32));   /* set TBU */
  mtspr(XREG_SPR_TBL_WRITE, (unsigned int) Xtime);           /* set TBL */
}

/****************************************************************************
*
* Get the time from the Time Base Register
*
* @param    Pointer to the location to be updated with the time
*
* @return   None.
*
* @note     None.
*
*
****************************************************************************/

void XTime_GetTime(XTime *Xtime)
{
  unsigned int high;
  unsigned int low;

  /* loop until we got a consistent register pair */
  do
  {
    high = mfspr(XREG_SPR_TBU_READ);
    low = mfspr(XREG_SPR_TBL_READ);
  } while (high != mfspr(XREG_SPR_TBU_READ));
  *Xtime = (((XTime) high) << 32) | (XTime) low;
}

/****************************************************************************
*
* Clear the specified bits of the Timer Status Register (TSR)
*
* @param    Bitmask that specifies the bits of the TSR to be cleared.
*           The bit masks are defined in xreg405.h
*
* @return   None.
*
* @note     None.
*
*
****************************************************************************/

void XTime_TSRClearStatusBits(unsigned long Bitmask)
{
   mtspr(XREG_SPR_TSR, Bitmask);
}

/****************************************************************************
*
* Write a value to the Programmable Interval Timer (PIT).
*
* @param    Value to be written to the PIT
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_PITSetInterval(unsigned long Interval)
{
   mtspr(XREG_SPR_PIT, Interval);
}

/****************************************************************************
*
* Enable Programmable Interval Timer (PIT) interrupts.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_PITEnableInterrupt(void)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   mtspr(XREG_SPR_TCR, val | XREG_TCR_PIT_INTERRUPT_ENABLE);
}

/****************************************************************************
*
* Disable Programmable Interval Timer (PIT) interrupts.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_PITDisableInterrupt(void)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   mtspr(XREG_SPR_TCR, val & ~XREG_TCR_PIT_INTERRUPT_ENABLE);
}

/****************************************************************************
*
* Enable Programmable Interval Timer (PIT) auto-reload mode.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_PITEnableAutoReload(void)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   mtspr(XREG_SPR_TCR, val | XREG_TCR_AUTORELOAD_ENABLE);
}

/****************************************************************************
*
* Disable Programmable Interval Timer (PIT) auto-reload mode.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_PITDisableAutoReload(void)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   mtspr(XREG_SPR_TCR, val & ~XREG_TCR_AUTORELOAD_ENABLE);
}

/****************************************************************************
*
* Clear Programmable Interval Timer (PIT) interrupt status bit.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_PITClearInterrupt(void)
{
   XTime_TSRClearStatusBits(XREG_TSR_PIT_INTERRUPT_STATUS);
}

/****************************************************************************
*
* Enable Fixed Interval Timer (FIT) interrupts.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_FITEnableInterrupt(void)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   mtspr(XREG_SPR_TCR, val | XREG_TCR_FIT_INTERRUPT_ENABLE);
}

/****************************************************************************
*
* Disable Fixed Interval Timer (FIT) interrupts.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_FITDisableInterrupt(void)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   mtspr(XREG_SPR_TCR, val & ~XREG_TCR_FIT_INTERRUPT_ENABLE);
}

/****************************************************************************
*
* Clear Fixed Interval Timer (FIT) interrupt status bit.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_FITClearInterrupt(void)
{
   XTime_TSRClearStatusBits(XREG_TSR_FIT_INTERRUPT_STATUS);
}

/****************************************************************************
*
* Set the Fixed Interval Timer (FIT) period
*
* @param    Period.  This value may be one of
*           XREG_TCR_FIT_PERIOD_11 (2^21 clocks),
*           XREG_TCR_FIT_PERIOD_10 (2^17 clocks),
*           XREG_TCR_FIT_PERIOD_01 (2^13 clocks) or
*           XREG_TCR_FIT_PERIOD_00 (2^9 clocks).
*           These values are defined in xreg405.h
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_FITSetPeriod(unsigned long Period)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   val = (val & ~XREG_TCR_FIT_PERIOD_11);
   mtspr(XREG_SPR_TCR, val | Period);
}

/****************************************************************************
*
* Enable Watchdog Timer (WDT) interrupts.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_WDTEnableInterrupt(void)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   mtspr(XREG_SPR_TCR, val | XREG_TCR_WDT_INTERRUPT_ENABLE);
}

/****************************************************************************
*
* Disable Watchdog Timer (WDT) interrupts.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_WDTDisableInterrupt(void)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   mtspr(XREG_SPR_TCR, val & ~XREG_TCR_WDT_INTERRUPT_ENABLE);
}

/****************************************************************************
*
* Clear Watchdog Timer (WDT) interrupt status bit.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_WDTClearInterrupt(void)
{
   XTime_TSRClearStatusBits(XREG_TSR_WDT_INTERRUPT_STATUS);
}

/****************************************************************************
*
* Set the period for a Watchdog Timer (WDT) event.
*
* @param    Period.  This value may be one of
*           XREG_TCR_WDT_PERIOD_11 (2^29 clocks),
*           XREG_TCR_WDT_PERIOD_10 (2^25 clocks),
*           XREG_TCR_WDT_PERIOD_01 (2^21 clocks) or
*           XREG_TCR_WDT_PERIOD_00 (2^17 clocks).
*           These values are defined in xreg405.h
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_WDTSetPeriod(unsigned long Period)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   val = (val & ~XREG_TCR_WDT_PERIOD_11);
   mtspr(XREG_SPR_TCR, val | Period);
}

/****************************************************************************
*
* Specify the type of reset that occurs as a result of a Watchdog Timer (WDT) event.
*
* @param    Reset Control.  This value may be one of
*           XREG_WDT_RESET_CONTROL_11 (System reset),
*           XREG_WDT_RESET_CONTROL_10 (Chip reset),
*           XREG_WDT_RESET_CONTROL_01 (processor reset),
*           or XREG_WDT_RESET_CONTROL_00 (no reset).
*           These values are defined in xreg405.h
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_WDTResetControl(unsigned long ControlVal)
{
   unsigned long val;
   val=mfspr(XREG_SPR_TCR);
   val = (val & ~XREG_TCR_WDT_RESET_CONTROL_11);
   mtspr(XREG_SPR_TCR, val | ControlVal);
}

/****************************************************************************
*
* Enables Watchdog Timer (WDT) event
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_WDTEnableNextWatchdog(void)
{
   XTime_TSRClearStatusBits(XREG_TSR_WDT_ENABLE_NEXT_WATCHDOG);
}

/****************************************************************************
*
* Clear Watchdog Timer (WDT) reset status bits.
*
* @param    None.
*
* @return   None.
*
* @note     None.
*
****************************************************************************/

void XTime_WDTClearResetStatus(void)
{
   XTime_TSRClearStatusBits(XREG_TSR_WDT_RESET_STATUS_11);
}
