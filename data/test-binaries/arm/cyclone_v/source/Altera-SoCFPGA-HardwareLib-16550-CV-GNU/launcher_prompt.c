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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-16550-CV-GNU/launcher_prompt.c#1 $
 */

#include "echo_prompt.h"
#include "launcher_prompt.h"
#include "memory_prompt.h"
#include "alt_16550_prompt.h"
#include <stdio.h>

static bool launcher_prompt_echo(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                                 char * argument,
                                 void * context)
{
    echo_prompt(buffer);

    return true;
}

static bool launcher_prompt_memory(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                                   char * argument,
                                   void * context)
{
    memory_prompt(buffer);

    return true;
}

static bool launcher_prompt_quit(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                                 char * argument,
                                 void * context)
{
    // Just exit this prompt.
    alt_16550_prompt_stop(prompt);

    return false;
}

static bool launcher_prompt_default(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                                    char * argument,
                                    void * context)
{
    // Initial / Default call:

    size_t write_size;
    alt_16550_buffer_write_line(buffer,
                                "Welcome to the Launcher. Options:\n"
                                "echo    - Echo echo echo echo ...\n"
                                "memory  - Memory interaction utility\n"
                                "quit    - Exit launcher\n"
                                "choice> ", 0,
                                &write_size);

    return false;
}

ALT_STATUS_CODE launcher_prompt(ALT_16550_BUFFER_t * buffer)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_16550_PROMPT_t prompt;

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_init(&prompt, buffer);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_command_register(&prompt,
                                                   "echo",
                                                   launcher_prompt_echo,
                                                   NULL);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_command_register(&prompt,
                                                   "memory",
                                                   launcher_prompt_memory,
                                                   NULL);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_command_register(&prompt,
                                                   "quit",
                                                   launcher_prompt_quit,
                                                   NULL);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_start(&prompt, launcher_prompt_default, NULL);
    }

    alt_16550_prompt_uninit(&prompt);

    return status;
}
