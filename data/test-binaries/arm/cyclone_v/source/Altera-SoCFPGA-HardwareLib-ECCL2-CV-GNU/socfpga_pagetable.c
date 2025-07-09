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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-ECCL2-CV-GNU/socfpga_pagetable.c#1 $
 */

#include <stdio.h>
#include "alt_mmu.h"
#include "socfpga_pagetable.h"
#include "alt_printf.h"

/*
// Memory used to store the page table data.
*/
static uint32_t __attribute__ ((aligned (0x4000))) socfpga_pagetable_store[8192];

/*
// Allocator function used by the MMU API.
*/
static void * socfpga_pagetable_alloc(const size_t size, void * context)
{
    return context;
}

#define MAX_COUNT 64
ALT_STATUS_CODE socfpga_pagetable_setup(SOCFPGA_PAGETABLE_SEGMENT_t * segments, size_t count)
{
    ALT_MMU_MEM_REGION_t regions[(MAX_COUNT * 2) + 1];
    ALT_STATUS_CODE status = ALT_E_SUCCESS;
    uint32_t * ttb1 = NULL;

    int next_region = 0;
    size_t i;

    ALT_PRINTF("INFO: Setup Page Table with %u segment(s).\n", count);

    if (count == 0 || count > MAX_COUNT)
    {
        return ALT_E_ERROR;
    }

    if (segments[0].size == 0)
    {
        return ALT_E_ERROR;
    }

    /*
    // Construct the MMU region data from the segments provided.
    */

    if (segments[0].addr != 0)
    {
        regions[next_region].va         = (void *)0x0;
        regions[next_region].pa         = (void *)0x0;
        regions[next_region].size       = (uintptr_t)segments[0].addr;
        regions[next_region].access     = ALT_MMU_AP_PRIV_ACCESS;
        regions[next_region].attributes = ALT_MMU_ATTR_DEVICE_NS;
        regions[next_region].shareable  = ALT_MMU_TTB_S_NON_SHAREABLE;
        regions[next_region].execute    = ALT_MMU_TTB_XN_DISABLE;
        regions[next_region].security   = ALT_MMU_TTB_NS_SECURE;
        next_region++;
    }
    for (i = 0; i < count - 1; ++i)
    {
        regions[next_region].va         = segments[i].addr;
        regions[next_region].pa         = segments[i].addr;
        regions[next_region].size       = segments[i].size;
        regions[next_region].access     = ALT_MMU_AP_PRIV_ACCESS;
        regions[next_region].attributes = ALT_MMU_ATTR_WBA;
        regions[next_region].shareable  = ALT_MMU_TTB_S_NON_SHAREABLE;
        regions[next_region].execute    = ALT_MMU_TTB_XN_DISABLE;
        regions[next_region].security   = ALT_MMU_TTB_NS_SECURE;
        next_region++;

        if ((uintptr_t)segments[i].addr + segments[i].size != (uintptr_t)segments[i + 1].addr)
        {
            uintptr_t ucached_addr = (uintptr_t)segments[i].addr + segments[i].size;
            size_t    ucached_size = (uintptr_t)segments[i + 1].addr - ((uintptr_t)segments[i].addr + segments[i].size);

            /* A region that describes non-pageable memory is needed between the segments. */
            regions[next_region].va         = (void *)ucached_addr;
            regions[next_region].pa         = (void *)ucached_addr;
            regions[next_region].size       = ucached_size;
            regions[next_region].access     = ALT_MMU_AP_PRIV_ACCESS;
            regions[next_region].attributes = ALT_MMU_ATTR_DEVICE_NS;
            regions[next_region].shareable  = ALT_MMU_TTB_S_NON_SHAREABLE;
            regions[next_region].execute    = ALT_MMU_TTB_XN_DISABLE;
            regions[next_region].security   = ALT_MMU_TTB_NS_SECURE;
            next_region++;
        }
    }

    /* Last segment and last non-pageable memory. */

    regions[next_region].va         = segments[count - 1].addr;
    regions[next_region].pa         = segments[count - 1].addr;
    regions[next_region].size       = segments[count - 1].size;
    regions[next_region].access     = ALT_MMU_AP_PRIV_ACCESS;
    regions[next_region].attributes = ALT_MMU_ATTR_WBA;
    regions[next_region].shareable  = ALT_MMU_TTB_S_NON_SHAREABLE;
    regions[next_region].execute    = ALT_MMU_TTB_XN_DISABLE;
    regions[next_region].security   = ALT_MMU_TTB_NS_SECURE;
    next_region++;

    if ((uintptr_t)segments[count - 1].addr + segments[count -1].size != 0x0)
    {
        uintptr_t ucached_addr = (uintptr_t)segments[count - 1].addr + segments[count - 1].size;
        size_t    ucached_size = 0xffffffff - ((uintptr_t)segments[count - 1].addr + segments[count - 1].size) + 1;

        regions[next_region].va         = (void *)ucached_addr;
        regions[next_region].pa         = (void *)ucached_addr;
        regions[next_region].size       = ucached_size;
        regions[next_region].access     = ALT_MMU_AP_PRIV_ACCESS;
        regions[next_region].attributes = ALT_MMU_ATTR_DEVICE_NS;
        regions[next_region].shareable  = ALT_MMU_TTB_S_NON_SHAREABLE;
        regions[next_region].execute    = ALT_MMU_TTB_XN_DISABLE;
        regions[next_region].security   = ALT_MMU_TTB_NS_SECURE;
        next_region++;
    }

    /*
    // Initialize and program the MMU system.
    */

    if (status == ALT_E_SUCCESS)
    {
        status = alt_mmu_init();
        if (status != ALT_E_SUCCESS)
        {
           ALT_PRINTF("DEBUG[PT]: Failure on line %d.\n", __LINE__);
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        size_t reqsize = alt_mmu_va_space_storage_required(regions,
                                                           next_region);
        if (reqsize > sizeof(socfpga_pagetable_store))
        {
           ALT_PRINTF("DEBUG[PT]: Failure on line %d: Not enough space provisioned.\n", __LINE__);
            status = ALT_E_ERROR;
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_mmu_va_space_create(&ttb1,
                                         regions, next_region,
                                         socfpga_pagetable_alloc, socfpga_pagetable_store);
        if (status != ALT_E_SUCCESS)
        {
           ALT_PRINTF("DEBUG[PT]: Failure on line %d.\n", __LINE__);
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_mmu_va_space_enable(ttb1);
        if (status != ALT_E_SUCCESS)
        {
           ALT_PRINTF("DEBUG[PT]: Failure on line %d.\n", __LINE__);
        }
    }

    return status;
}

void socfpga_pagetable_cleanup(void)
{
   ALT_PRINTF("INFO: Cleanup Page Table.\n");

    if (alt_mmu_disable() != ALT_E_SUCCESS)
    {
       ALT_PRINTF("WARN: alt_mmu_disable() returned non-SUCCESS.\n");
    }
}
