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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-ECCL2-CV-ARMCC/socfpga_eccl2.h#1 $
 */

#ifndef ___SOCFPGA_ECCL2_H___
#define ___SOCFPGA_ECCL2_H___

#include "hwlib.h"

/*!
 * Callback definition for the SERR and DERR notification. Callback will be
 * made from the ISR.
 *
 * \param       context
 *              User specified context pointer.
 */
typedef void (*socfpga_eccl2_callback_t)(void * context);

/*!
 * This structure is used by the ECC system.
 */
typedef struct SOCFPGA_ECCL2_DATA_s
{
    socfpga_eccl2_callback_t serr_callback;
    void *                   serr_context;
    socfpga_eccl2_callback_t derr_callback;
    void *                   derr_context;
}
SOCFPGA_ECCL2_DATA_t;

/*!
 * Initializes and enables the L2 ECC notification and handling system.
 *
 * \param       eccl2_data
 *              Pointer to the data used by this API.
 *
 * \param       serr_callback
 *              Callback to be used when a SERR type event is detected.
 *
 * \param       serr_context
 *              Context for the SERR event callback.
 *
 * \param       derr_callback
 *              Callback to be used when a DERR type event is detected.
 *
 * \param       derr_context
 *              Context for the DERR event callback.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE socfpga_eccl2_setup(SOCFPGA_ECCL2_DATA_t * eccl2_data,
                                    socfpga_eccl2_callback_t serr_callback, void * serr_context,
                                    socfpga_eccl2_callback_t derr_callback, void * derr_context);

/*!
 * Disables the L2 ECC notification and handling system.
 */
void socfpga_eccl2_cleanup(void);

/*!
 * Attempts to inject a single bit error in the cache line corresponding to the
 * memory provided. This memory is required to be cache aligned and sized, and
 * to be cached by the MMU. Invoking this API should cause a SERR notification
 * callback to be issued.
 *
 * \param       cache_line
 *              Cacheable memory in which to inject a single bit error.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE socfpga_eccl2_inject_serr(void * cache_line);

/*!
 * Attempts to inject a double bit error in the cache line corresponding to the
 * memory provided. This memory is required to be cache aligned and sized, and
 * to be cached by the MMU. Invoking this API should cause a DERR notification
 * callback to be issued.
 *
 * \param       cache_line
 *              Cacheable memory in which to inject a double bit error.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE socfpga_eccl2_inject_derr(void * cache_line);

#endif
