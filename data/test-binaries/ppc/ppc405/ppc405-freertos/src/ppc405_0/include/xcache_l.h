/*-----------------------------------------------------------------------------
//     $Date: 2007/06/01 22:30:21 $
//     $RCSfile: xcache_l.h,v $
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
//-----------------------------------------------------------------------------
// Design Notes:
//  - Processor must be in real mode!
//  - disable_dcache makes assumptions about available memory.
//  - each bit in the regions variable stands for 128MB of memory:
//      regions    --> cached address range
//      ------------|--------------------------------------------------
//      0x80000000  | [0, 0x7FFFFFF]
//      0x00000001  | [0xF8000000, 0xFFFFFFFF]
//      0x80000001  | [0, 0x7FFFFFF],[0xF8000000, 0xFFFFFFFF]
//
//---------------------------------------------------------------------------*/

#ifndef CACHE_H
#define CACHE_H

#ifdef __cplusplus
extern "C" {
#endif

void XCache_WriteCCR0(unsigned int val);

void XCache_EnableDCache(unsigned int regions);
void XCache_DisableDCache(void);
void XCache_InvalidateDCacheLine(unsigned int adr);
void XCache_FlushDCacheLine(unsigned int adr);
void XCache_StoreDCacheLine(unsigned int adr);
void XCache_InvalidateDCacheRange(unsigned int adr, unsigned len);
void XCache_FlushDCacheRange(unsigned int adr, unsigned len);

void XCache_EnableICache(unsigned int regions);
void XCache_DisableICache(void);
void XCache_InvalidateICache(void);
void XCache_InvalidateICacheLine(unsigned int adr);

#ifdef __cplusplus
}
#endif

#endif
