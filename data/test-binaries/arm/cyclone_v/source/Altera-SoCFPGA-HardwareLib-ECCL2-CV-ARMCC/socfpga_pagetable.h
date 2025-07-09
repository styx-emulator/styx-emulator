/*****************************************************************************
*
* Copyright 2014 Altera Corporation. All Rights Reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
* this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
*
* 3. Neither the name of the copyright holder nor the names of its contributors
* may be used to endorse or promote products derived from this software without
* specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
* CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
*****************************************************************************/

/*
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-ECCL2-CV-ARMCC/socfpga_pagetable.h#1 $
 */

#ifndef ___SOCFPGA_PAGETABLE_H___
#define ___SOCFPGA_PAGETABLE_H___

#include "hwlib.h"

/*!
 * This structure is used to represent a memory segment.
 */
typedef struct SOCFPGA_PAGETABLE_SEGMENT_s
{
    void * addr;
    size_t size;
}
SOCFPGA_PAGETABLE_SEGMENT_t;

/*!
 * Creates and applies a flat memory space MMU page table ocnfiguration with
 * the given memory segments. Each memory segment provided will be marked
 * cacheable while non-segment locations will be device memory.
 *
 * \param       segments
 *              Array of memory segments which will be marked cacheable.
 *              Segments must be provided in order by memory address, smallest
 *              to largest address.
 *
 * \param       count
 *              The count of the array provided.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE socfpga_pagetable_setup(SOCFPGA_PAGETABLE_SEGMENT_t * segments, size_t count);

/*!
 * Uninitializes the page table configuration.
 */
void socfpga_pagetable_cleanup(void);

#endif
