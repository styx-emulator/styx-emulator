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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-ECCL2-CV-GNU/socfpga_int.h#1 $
 */

#ifndef ___SOCFPGA_INT_H___
#define ___SOCFPGA_INT_H___

#include "alt_interrupt.h"

/*!
 * Initializes and enables the interrupt system. This API should be called
 * before calling socfpga_int_setup_list() or socfpga_int_cleanup_list().
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE socfpga_int_setup_common(void);

/*!
 * Disables and uninitializes the interrupt system.
 */
void socfpga_int_cleanup_common(void);

/*!
 * Configures and enables the interrupt with the given data provided as an
 * array. All interrupts provided will be routed to all CPUs on the system.
 *
 * \param       int_ids
 *              Array of interrupt identifier(s) of the interrupt(s) to
 *              configure and enable.
 *
 * \param       triggers
 *              Array of interrupt trigger configuration(s) for the given
 *              interrupt(s).
 *
 * \param       callbacks
 *              Array of interrupt callback(s) for the given interrupt(s).
 *
 * \param       contexts
 *              Array of interrupt context(s) for the given interrupt(s).
 *
 * \param       count
 *              The count of the array provided.
 *
 * \retval      ALT_E_SUCCESS   The operation was successful.
 * \retval      ALT_E_ERROR     The operation failed.
 */
ALT_STATUS_CODE socfpga_int_setup_list(ALT_INT_INTERRUPT_t * int_ids,
                                       ALT_INT_TRIGGER_t * triggers,
                                       alt_int_callback_t * callbacks,
                                       void ** contexts,
                                       size_t count);
/*!
 * Disables the interrupt with the given data provided as an array.
 *
 * \param       int_ids
 *              Array of interrupt identifier(s) of the interrupt(s) to
 *              disable.
 *
 * \param       count
 *              The count of the array provided.
 */
void socfpga_int_cleanup_list(ALT_INT_INTERRUPT_t * int_ids,
                              size_t count);

#endif
