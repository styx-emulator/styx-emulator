/******************************************************************************
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
******************************************************************************/

/*
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-16550-CV-GNU/alt_16550_prompt.c#1 $
 */

#include "alt_16550_prompt.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <alt_printf.h>

/* NOTE: To enable debugging output, delete the next line and uncomment the
   line after. */
#define dprintf null_printf
/* #define dprintf printf */

ALT_STATUS_CODE alt_16550_prompt_init(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer)
{
    prompt->buffer        = buffer;
    prompt->state         = ALT_16550_PROMPT_STATE_INIT;
    prompt->handler_count = 0;

    return ALT_E_SUCCESS;
}

ALT_STATUS_CODE alt_16550_prompt_uninit(ALT_16550_PROMPT_t * prompt)
{
    if (prompt->state != ALT_16550_PROMPT_STATE_EXIT)
    {
        return ALT_E_ERROR;
    }

    return ALT_E_SUCCESS;
}

ALT_STATUS_CODE alt_16550_prompt_command_register(ALT_16550_PROMPT_t * prompt,
                                                  const char * command,
                                                  alt_16550_prompt_callback_t callback,
                                                  void * context)
{
    if (prompt->state != ALT_16550_PROMPT_STATE_INIT)
    {
        return ALT_E_ERROR;
    }

    if (prompt->handler_count == ALT_16550_PROMPT_PROVISION_HANDLER_COUNT)
    {
        return ALT_E_ERROR;
    }

    if (strlen(command) + 1 > ALT_16550_PROMPT_PROVISION_COMMAND_SIZE)
    {
        return ALT_E_ERROR;
    }

    strcpy(prompt->handler_command[prompt->handler_count], command);
    prompt->handler_callback[prompt->handler_count] = callback;
    prompt->handler_context[prompt->handler_count]  = context;

    ++prompt->handler_count;

    return ALT_E_SUCCESS;
}

ALT_STATUS_CODE alt_16550_prompt_command_execute(ALT_16550_PROMPT_t * prompt,
                                                 const char * command,
                                                 char * argument)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    alt_16550_prompt_callback_t callback = prompt->default_callback;
    void *                      context  = prompt->default_context;
    uint32_t i;
    bool call_default;

    /* Linearly search through the commands to find a matching handler.
    // Check for null pointers and fall through with defaults */
    if (command != NULL)
    {
        for (i = 0; i < prompt->handler_count; ++i)
        {
            if (strcmp(prompt->handler_command[i], command) == 0)
            {
                callback = prompt->handler_callback[i];
                context  = prompt->handler_context[i];
                break;
            }
        }
    }

    /* Call the callback. */
    call_default = callback(prompt, prompt->buffer, argument, context);

    if (call_default)
    {
        if (callback != prompt->default_callback)
        {
            prompt->default_callback(prompt, prompt->buffer, NULL, prompt->default_context);
        }
    }

    return status;
}

ALT_STATUS_CODE alt_16550_prompt_start(ALT_16550_PROMPT_t * prompt,
                                       alt_16550_prompt_callback_t default_callback,
                                       void * default_context)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    if (prompt->state != ALT_16550_PROMPT_STATE_INIT)
    {
        return ALT_E_ERROR;
    }

    prompt->default_callback = default_callback;
    prompt->default_context  = default_context;

    prompt->state = ALT_16550_PROMPT_STATE_RUNNING;

    /* Call the default prompt handler to handle any initialization tasks. */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_command_execute(prompt, NULL, NULL);
    }

    while (prompt->state == ALT_16550_PROMPT_STATE_RUNNING)
    {
        char input[ALT_16550_PROMPT_PROVISION_BUFFER_SIZE];
        size_t read_size;
        char * command  = 0;
        char * argument = 0;

        if (status != ALT_E_SUCCESS)
        {
            break;
        }

        /* Read in a line from the buffer. */
        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_buffer_read_line(prompt->buffer,
                                                input,
                                                sizeof(input),
                                                &read_size);
        }

        /* If nothing is there, continue. Else, zero terminate the line. */
        if (status == ALT_E_SUCCESS)
        {
            if (read_size == 0)
            {
                continue;
            }

            /* The string is ended with a '\r'. Zero that out. */
            input[read_size - 1] = 0;

            ALT_PRINTF("INPUT [%s].\n", input);
        }

        /* Parse the command and argument strings */

        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_prompt_parse(input, &command, &argument);
        }

        /* Execute the command handler */

        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_prompt_command_execute(prompt, command, argument);
        }
    }

    return status;
}

ALT_STATUS_CODE alt_16550_prompt_stop(ALT_16550_PROMPT_t * prompt)
{
    prompt->state = ALT_16550_PROMPT_STATE_EXIT;
    return ALT_E_SUCCESS;
}

ALT_STATUS_CODE alt_16550_prompt_parse(char * input, char ** first, char ** rest)
{
    char * command = input;
    char * argument;

    /* Remove whitespaces in front of the command */

    while (*command && isspace((int)*command))
    {
        ++command;
    }

    if (*command == 0)
    {
        /* The input string is zero or more whitespaces only. */

        *first = 0;
        *rest  = 0;
        return ALT_E_SUCCESS;
    }

    /* Now locate the start of argument. */

    argument = command + 1;

    while (*argument && !isspace((int)*argument))
    {
        ++argument;
    }

    if (*argument == 0)
    {
        /* The input string consists of only a command. */
        *first = command;
        *rest  = 0;
        return ALT_E_SUCCESS;
    }

    /* End the command string */
    *argument = 0;
    ++argument;

    /* Remove whitespaces in front of argument. */

    while (*argument && isspace((int)*argument))
    {
        ++argument;
    }

    *first = command;
    *rest  = argument;
    return ALT_E_SUCCESS;
}
