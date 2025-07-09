/*-----------------------------------------------------------------------------
//     $Date: 2007/04/26 18:46:28 $
//     $RCSfile: usleep.c,v $
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

#include "sleep.h"
#include "xtime_l.h"
#include "xparameters.h"

void nanosleep(unsigned int nanoseconds)
{
  /* not implemented */
}

unsigned int usleep(unsigned int useconds)
{
  XTime tEnd, tCur;

  XTime_GetTime(&tCur);
  tEnd = tCur + ((XTime) useconds) * (XPAR_CPU_PPC405_CORE_CLOCK_FREQ_HZ / 1000000);
  do
  {
    XTime_GetTime(&tCur);
  } while (tCur < tEnd);

  return 0;
}
