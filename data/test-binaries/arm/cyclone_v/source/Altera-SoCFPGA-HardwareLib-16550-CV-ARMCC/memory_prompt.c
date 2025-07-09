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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-16550-CV-ARMCC/memory_prompt.c#1 $
 */

#include "alt_16550_buffer.h"
#include "alt_16550_prompt.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <alt_printf.h>

static bool memory_prompt_dump(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                               char * argument,
                               void * context)
{
    size_t write_size;
    char output[BUFFER_TRANSFER_MAX];

    char * str_addr  = 0;
    char * str_count = 0;

    char * end_addr  = 0;
    char * end_count = 0;

    uint32_t addr;
    uint32_t count;
    int      width = (int)context; /* in bytes */

    int i;

    /* Isolate the address and size strings */

    alt_16550_prompt_parse(argument, &str_addr,  &argument);
    alt_16550_prompt_parse(argument, &str_count, &argument);

    if ((str_addr == 0) || (str_count == 0))
    {
        alt_16550_buffer_write_line(buffer, "Arguments not found for address and/or count string.\n", 0, &write_size);
        return true;
    }

    /* Attempt to parse the addr and size strings */

    addr  = strtoul(str_addr,  &end_addr,  0);
    count = strtoul(str_count, &end_count, 0);

    if ((*end_addr != '\0') || (*end_count != '\0'))
    {
        alt_16550_buffer_write_line(buffer, "Error parsing address and/or count string.\n", 0, &write_size);
        return true;
    }

    /* Limit the size to something small so everything will fit in the buffer without waiting for it to flush. */
    if (count > 64)
    {
        alt_16550_buffer_write_line(buffer, "Count truncated to 64 items.\n", 0, &write_size);

        count = 64;
    }

    /* Check that memory is aligned with the requested width */
    switch (width)
    {
    case 1:
        alt_snprintf(output, sizeof(output),
                 "Dumping 0x%" PRIx32 " byte(s) @ 0x%" PRIx32 ":\n",
                 count, addr);
        alt_16550_buffer_write_line(buffer, output, 0, &write_size);

        for (i = 0; i < count; ++i)
        {
            uint8_t * mem = (uint8_t *)(addr + (i * sizeof(uint8_t)));

            alt_snprintf(output, sizeof(output), "%p: 0x%02x\n", mem, *mem);
            alt_16550_buffer_write_line(buffer, output, 0, &write_size);
        }
        break;

    case 4:
        if ((addr & 0x3) != 0)
        {
            alt_16550_buffer_write_line(buffer, "Address alignment error.\n", 0, &write_size);
            return true;
        }
        alt_snprintf(output, sizeof(output),
                 "Dumping 0x%" PRIx32 " words(s) @ 0x%" PRIx32 ":\n",
                 count, addr);
        alt_16550_buffer_write_line(buffer, output, 0, &write_size);

        for (i = 0; i < count; ++i)
        {
            uint32_t * mem = (uint32_t *)(addr + (i * sizeof(uint32_t)));

            alt_snprintf(output, sizeof(output), "%p: 0x%08x\n", mem, (unsigned)*mem);
            alt_16550_buffer_write_line(buffer, output, 0, &write_size);
        }
        break;

    default:
        return false;
    }

    return true;
}

static bool memory_prompt_quit(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                               char * argument,
                               void * context)
{
    alt_16550_prompt_stop(prompt);

    return false;
}

static bool memory_prompt_default(ALT_16550_PROMPT_t * prompt, ALT_16550_BUFFER_t * buffer,
                                  char * argument,
                                  void * context)
{
    size_t write_size;
    alt_16550_buffer_write_line(buffer,
                                "dump  addr size - Alias for dumpb.\n"
                                "dumpb addr size - Dumps [size] memory at [addr] as bytes.\n"
                                "dumpw addr size - Dumps [size] memory at [addr] as words.\n"
                                "                  Address must be word aligned.\n"
                                "quit\n"
                                "choice> ", 0,
                                &write_size);

    return false;
}

ALT_STATUS_CODE memory_prompt(ALT_16550_BUFFER_t * buffer)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_16550_PROMPT_t prompt;

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_init(&prompt, buffer);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_command_register(&prompt, "dump",
                                                   memory_prompt_dump, (void *)1);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_command_register(&prompt, "dumpb",
                                                   memory_prompt_dump, (void *)1);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_command_register(&prompt, "dumpw",
                                                   memory_prompt_dump, (void *)4);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_command_register(&prompt, "quit",
                                                   memory_prompt_quit, NULL);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_prompt_start(&prompt, memory_prompt_default, NULL);
    }

    alt_16550_prompt_uninit(&prompt);

    return status;
}
