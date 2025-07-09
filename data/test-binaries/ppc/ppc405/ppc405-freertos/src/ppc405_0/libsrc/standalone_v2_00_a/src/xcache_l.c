/*-----------------------------------------------------------------------------
//     $Date: 2007/06/01 22:30:21 $
//     $RCSfile: xcache_l.c,v $
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

#include "xcache_l.h"
#include "xpseudo_asm.h"

#define DCWR_VAL        0x0
#define SGR_VAL         0x0
/* #define SU0R_VAL        0x0 */
/* #define SLER_VAL        0x0 */
#define CCR0_VAL        0x700a00

#define DCACHE_SIZE     (16*1024)

/****************************************************************************
*
* Write to the Core-Configuration Register (CCR0)
*
* @param    Value to be written to CCR0.  The bit fields are defined
*           in xreg405.h
*
* @return   None.
*
* @note
*
* None.
*
****************************************************************************/

/* special registers */
void XCache_WriteCCR0(unsigned int val)
{
  sync;
  isync;
  mtspr(XREG_SPR_CCR0, val);
  sync;
  isync;
}


/****************************************************************************
*
* Enable the data cache.
*
* @param    Memory regions to be marked as cachable.  Each bit in the regions
*           variable stands for 128MB of memory.
*           regions    --> cached address range
*           ------------|--------------------------------------------------
*           0x80000000  | [0, 0x7FFFFFF]
*           0x00000001  | [0xF8000000, 0xFFFFFFFF]
*           0x80000001  | [0, 0x7FFFFFF],[0xF8000000, 0xFFFFFFFF]
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
*
****************************************************************************/

void XCache_EnableDCache(unsigned int regions)
{
  XCache_DisableDCache();
  /* after this point cache is disabled and invalidated */

  mtspr(XREG_SPR_SGR,  SGR_VAL);
  /* mtspr(XREG_SPR_SLER, SLER_VAL); */
  /* mtspr(XREG_SPR_SU0R, SU0R_VAL); */
  mtspr(XREG_SPR_DCWR, DCWR_VAL);
  mtspr(XREG_SPR_DCCR, regions);
  isync;
}

/****************************************************************************
*
* Disable the data cache.
*
* @param    None
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
*
****************************************************************************/
void XCache_DisableDCache(void)
{
  register unsigned int address0;
  register unsigned int ccr0;
  register unsigned int tag;
  register unsigned int i;
  unsigned int dccr;

  dccr = mfspr(XREG_SPR_DCCR);
  if (dccr != 0)
  { /* dcache is enabled; read tags and flush valid and dirty lines */
    ccr0 = mfspr(XREG_SPR_CCR0);                /* read CCR0 */
    ccr0 = (ccr0 & 0xfffffffe) | 0x10;  /* read tags from A way */
    i = 0;
    while (i < 2)
    {
      mtspr(XREG_SPR_CCR0, ccr0);
      address0 = 0x0;
      while (address0 < (DCACHE_SIZE / 2))
      {
        tag = dcread(address0);
        if ((tag & 0x30) == 0x30)       /* valid and dirty? */
          dcbf((tag & 0xfffff000) | address0);
        address0 += 32;
      }
      ccr0 |= 1;                        /* read tags from B way */
      i++;
    }
    sync;
    mtspr(XREG_SPR_DCCR, 0);
    isync;
  }
  else
  {  /* dcache is not enabled; invalidate all lines */
    address0 = 0;
    while (address0 < (DCACHE_SIZE/2))
    {
      dccci(address0);
      address0 += 32;
    }
  }
}

/****************************************************************************
*
* Flush a data cache line. If the byte specified by the address (adr)
* is cached by the data cache, the cacheline containing that byte is
* invalidated.  If the cacheline is modified (dirty), the entire
* contents of the cacheline are written to system memory before the
* line is invalidated.
*
* @param    Address to be flushed
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
*
****************************************************************************/

void XCache_FlushDCacheLine(unsigned int adr)
{
  dcbf(adr);
  sync;
  isync;
}

/****************************************************************************
*
* Invalidate a data cache line. If the byte specified by the address (adr)
* is cached by the data cache, the cacheline containing that byte is
* invalidated.  If the cacheline is modified (dirty), the modified contents
* are lost and are NOT written to system memory before the line is
* invalidated.
*
* @param    Address to be flushed
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
*
****************************************************************************/

void XCache_InvalidateDCacheLine(unsigned int adr)
{
  dcbi(adr);
  sync;
  isync;
}

/****************************************************************************
*
* Store a data cache line. If the byte specified by the address (adr)
* is cached by the data cache and the cacheline is modified (dirty),
* the entire contents of the cacheline are written to system memory.
* After the store completes, the cacheline is marked as unmodified
* (not dirty).
*
* @param    Address to be stored
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
*
****************************************************************************/

void XCache_StoreDCacheLine(unsigned int adr)
{
  dcbst(adr);
  sync;
  isync;
}

/****************************************************************************
* Flush the data cache for the given address range.
* If the bytes specified by the address (adr) are cached by the data cache,
* the cacheline containing that byte is invalidated.  If the cacheline
* is modified (dirty), the written to system memory first before the
* before the line is invalidated.
*
* @param    Start address of range to be flushed
* @param    Length of range to be flushed in bytes
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
****************************************************************************/
void XCache_FlushDCacheRange(unsigned int adr, unsigned len)
{
  const unsigned cacheline = 32;
  unsigned int end;

  if (len != 0)
  {
    /* Back the starting address up to the start of a cache line
     * perform cache operations until adr+len
     */
    end = adr + len;
    adr = adr & ~(cacheline - 1);

    while (adr < end)
    {
      XCache_FlushDCacheLine(adr);
      adr += cacheline;
    }
  }
}

/****************************************************************************
*
* Invalidate the data cache for the given address range.
* If the bytes specified by the address (adr) are cached by the data cache,
* the cacheline containing that byte is invalidated.  If the cacheline
* is modified (dirty), the modified contents are lost and are NOT
* written to system memory before the line is invalidated.
*
* @param    Start address of ragne to be invalidated
* @param    Length of range to be invalidated in bytes
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
****************************************************************************/
void XCache_InvalidateDCacheRange(unsigned int adr, unsigned len)
{
  const unsigned cacheline = 32;
  unsigned int end;

  if (len != 0)
  {
    /* Back the starting address up to the start of a cache line
     * perform cache operations until adr+len
     */
    end = adr + len;
    adr = adr & ~(cacheline - 1);

    while (adr < end)
    {
      XCache_InvalidateDCacheLine(adr);
      adr += cacheline;
    }
  }
}

/****************************************************************************
*
* Enable the instruction cache.
*
* @param    Memory regions to be marked as cachable.  Each bit in the regions
*           variable stands for 128MB of memory.
*           regions    --> cached address range
*           ------------|--------------------------------------------------
*           0x80000000  | [0, 0x7FFFFFF]
*           0x00000001  | [0xF8000000, 0xFFFFFFFF]
*           0x80000001  | [0, 0x7FFFFFF],[0xF8000000, 0xFFFFFFFF]
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
*
****************************************************************************/

void XCache_EnableICache(unsigned int regions)
{
  XCache_DisableICache();

  mtspr(XREG_SPR_SGR, SGR_VAL);
  /* mtspr(XREG_SPR_SLER, SLER_VAL); */
  /* mtspr(XREG_SPR_SU0R, SU0R_VAL); */
  iccci;
  mtspr(XREG_SPR_ICCR, regions);
  isync;
}

/****************************************************************************
*
* Disable the instruction cache.
*
* @param    None
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
*
****************************************************************************/

void XCache_DisableICache(void)
{
  iccci;
  mtspr(XREG_SPR_ICCR, 0);
  isync;
}

/****************************************************************************
*
* Invalidate the entire instruction cache.
*
* @param    None
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
*
****************************************************************************/

void XCache_InvalidateICache(void)
{
  iccci;
  isync;
}

/****************************************************************************
*
* Invalidate an instruction cache line.  If the instruction specified by the
* parameter adr is cached by the instruction cache, the cacheline containing
* that instruction is invalidated.
*
* @param    None
*
* @return   None.
*
* @note
*
* Processor must be in real mode.
*
****************************************************************************/

void XCache_InvalidateICacheLine(unsigned int adr)
{
  icbi(adr);
  isync;
}
