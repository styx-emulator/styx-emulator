/*****************************************************************************
*
* Copyright 2013 Altera Corporation. All Rights Reserved.
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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-16550-CV-ARMCC/echo_prompt.c#1 $
 */

#include "alt_16550_buffer.h"
#include "alt_16550_prompt.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

static bool echo_prompt_quit(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                             char * argument,
                             void * context)
{
    alt_16550_prompt_stop(prompt);

    return false;
}

static bool echo_prompt_default(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                                char * argument,
                                void * context)
{
    int * showhelp = (int *) context;

    if (*showhelp)
    {
        size_t write_size;
        alt_16550_buffer_write_line(buffer,
                                    "The echo prompt will simply echo back whatever is entered in.\n"
                                    "If [quit] is entered, the prompt will exit.\n"
                                    "There will be no further help text until the prompt exits.\n",
                                    0,
                                    &write_size);

        *showhelp = 0;
    }

    return false;
}

ALT_STATUS_CODE echo_prompt(ALT_16550_BUFFER_t * buffer)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_16550_PROMPT_t prompt;

    int showhelp = 1;

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_init(&prompt, buffer);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_command_register(&prompt, "quit",
                                                   echo_prompt_quit, NULL);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_start(&prompt, echo_prompt_default, &showhelp);
    }

    alt_16550_prompt_uninit(&prompt);

    return status;
}
