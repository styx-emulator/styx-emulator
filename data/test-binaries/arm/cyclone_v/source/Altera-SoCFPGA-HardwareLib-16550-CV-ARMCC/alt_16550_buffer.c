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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-16550-CV-ARMCC/alt_16550_buffer.c#1 $
 */

#include "alt_16550_buffer.h"
#include "alt_safec.h"
#include <string.h>
#include <stdio.h>
#include <alt_printf.h>

/* NOTE: To enable debugging output, delete the next line and uncomment the
   line after. */
#define dprintf null_printf
/* #define dprintf printf */

/* The carriage return token. */
#define ALT_CR_TOKEN '\r'
/* The line feed token */
#define ALT_LF_TOKEN '\n'

/*
// The implementation of C++'s std::min() for C's unsigned long int type.
*/
static unsigned long int stdminul(unsigned long int a, unsigned long int b)
{
    if (a > b)
    {
        return b;
    }
    else
    {
        return a;
    }
}

/*
// Counts the population of tokens [token] in the given string [str] up to the
// given length [n] or end of string character. Does not work well when
// counting the NULL token.
*/
static size_t strnpop(const char * str, size_t n, int token)
{
    /* Population of the given token. */
    size_t pop = 0;
    size_t i;

    for (i = 0; i < n; ++i)
    {
        if (str[i] == 0)
        {
            break;
        }

        if (str[i] == token)
        {
            ++pop;
        }
    }

    return pop;
}

/*
// Returns a pointer to the first instance of the given token [c] in string
// [str], searching up to [n] characters, or NULL if not found. Does not work
// well when searching for the NULL token.
*/
static const char * strnchr(const char * str, int c, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
    {
        if (*str == 0)
        {
            break;
        }

        if (*str == c)
        {
            return str;
        }

        ++str;
    }

    return NULL;
}

/*
// This helper function echos back the user provided string according to the
// echoing parameters.
*/
#define MAX_BUFFER_SIZE	256

static ALT_STATUS_CODE alt_16550_buffer_echo(ALT_16550_BUFFER_t * buffer, const char * string, size_t size)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    char output[MAX_BUFFER_SIZE];
    size_t size_left = size;

    if (buffer->echo_char == 0)
    {
        /* Echoing back user's input. */

        if (buffer->echo_inject_lf)
        {
            /* Inject a '\n' after every '\r' detected. */

            while (size_left)
            {
                /* Loop one less than the [output] array. This is to allow for the case when the
                   last character is a '\r', so the last '\n' will fit in. */
                size_t write_size = 0;
                uint32_t copy_size = stdminul(size_left, sizeof(output) - 1);
                while (write_size < copy_size)
                {
                    output[write_size] = string[size - size_left];

                    if (output[write_size] == ALT_CR_TOKEN)
                    {
                        ++write_size;
                        output[write_size] = ALT_LF_TOKEN;
                    }

                    ++write_size;
                    --size_left;
                }

                status = alt_16550_buffer_write_raw(buffer, output, write_size, &write_size);
                if (status != ALT_E_SUCCESS)
                {
                    break;
                }

                /* size_left is already decremented as part of the injection loop. */
            }
        }
        else /* if (buffer->echo_inject_lf) */
        {
            /* No injection requested. */

            while (size_left)
            {
                size_t write_size = size_left;
                status = alt_16550_buffer_write_raw(buffer, string + size - size_left, write_size, &write_size);
                if (status != ALT_E_SUCCESS)
                {
                    break;
                }

                size_left -= write_size;
            }
        }
    }
    else /* if (buffer->echo_char == 0) */
    {
        /* Echo back a constant value. */

        if (buffer->echo_inject_lf)
        {
            /* Inject '\n' after every '\r' detected. */

            while (size_left)
            {
                /* Loop one less than the [output] array. This is to allow for the case when the */
                /* last character is a '\r', so the last '\n' will fit in. */
                size_t write_size = 0;
                uint32_t copy_size = stdminul(size_left, sizeof(output) - 1);
                while (write_size < copy_size)
                {
                    if (string[size - size_left] == ALT_CR_TOKEN)
                    {
                        output[write_size] = ALT_CR_TOKEN;
                        ++write_size;
                        output[write_size] = ALT_LF_TOKEN;
                    }
                    else
                    {
                        output[write_size] = buffer->echo_char;
                    }

                    ++write_size;
                    --size_left;
                }

                status = alt_16550_buffer_write_raw(buffer, output, write_size, &write_size);
                if (status != ALT_E_SUCCESS)
                {
                    break;
                }

                /* size_left is already decremented as part of the injection loop. */
            }
        }
        else /* if (buffer->echo_inject_lf) */
        {
            /* No injection requested. */

            /* Use a small buffer to paint out the received data so as to not */
            /* constantly synchronize with the ISR. */
            memset(output, buffer->echo_char, sizeof(output));

            while (size_left)
            {
                size_t write_size = stdminul(size_left, sizeof(output));
                status = alt_16550_buffer_write_raw(buffer, output, write_size, &write_size);
                if (status != ALT_E_SUCCESS)
                {
                    break;
                }

                size_left -= write_size;
            }
        }
    }

    return status;
}

/*
// Helper function to handle UART RX interrupts.
*/
static ALT_STATUS_CODE alt_16550_buffer_int_rx(ALT_16550_BUFFER_t * buffer)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    uint32_t fifo_level_rx;
    uint32_t copy_size;

#if ALT_16550_BUFFER_ENABLE_SMP
    /* Signal we are in the RX section. */
    buffer->isr_rx = true;
#endif

    /* Gets the current level in the RX FIFO. */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_fifo_level_get_rx(buffer->handle, &fifo_level_rx);
    }

    /* Copy the RX FIFO into the RX buffer. */
    copy_size    = stdminul(fifo_level_rx, ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE - buffer->rx_level);

    if (buffer->rx_start + buffer->rx_level >= ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE)
    {
        /* Already wrapped */
        uint32_t wrapped_offset = buffer->rx_start + buffer->rx_level - ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE;

        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_fifo_read(buffer->handle,
                                         buffer->rx_buffer + wrapped_offset, copy_size);
        }

        /* Scan for NL */
        if (status == ALT_E_SUCCESS)
        {
            buffer->rx_nl_count += strnpop(buffer->rx_buffer + wrapped_offset, copy_size, ALT_CR_TOKEN);
        }

        /* Echo */
        if ((status == ALT_E_SUCCESS) && (buffer->echo_enable == true))
        {
            status = alt_16550_buffer_echo(buffer, buffer->rx_buffer + wrapped_offset, copy_size);
        }
    }
    else if (buffer->rx_start + buffer->rx_level + copy_size > ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE)
    {
        /* Will wrap */
        uint32_t copy_size_2 = buffer->rx_start + buffer->rx_level + copy_size - ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE;
        uint32_t copy_size_1 = copy_size - copy_size_2;

        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_fifo_read(buffer->handle,
                                         buffer->rx_buffer + buffer->rx_start + buffer->rx_level, copy_size_1);
        }
        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_fifo_read(buffer->handle,
                                         buffer->rx_buffer, copy_size_2);
        }

        /* Scan for NL */
        if (status == ALT_E_SUCCESS)
        {
            buffer->rx_nl_count += strnpop(buffer->rx_buffer + buffer->rx_start + buffer->rx_level, copy_size_1, ALT_CR_TOKEN);
            buffer->rx_nl_count += strnpop(buffer->rx_buffer, copy_size_2, ALT_CR_TOKEN);
        }

        /* Echo */
        if (buffer->echo_enable == true)
        {
            if (status == ALT_E_SUCCESS)
            {
                status = alt_16550_buffer_echo(buffer, buffer->rx_buffer + buffer->rx_start + buffer->rx_level, copy_size_1);
            }
            if (status == ALT_E_SUCCESS)
            {
                status = alt_16550_buffer_echo(buffer, buffer->rx_buffer, copy_size_2);
            }
        }
    }
    else
    {
        /* No wrapping */
        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_fifo_read(buffer->handle,
                                         buffer->rx_buffer + buffer->rx_start + buffer->rx_level, copy_size);
        }

        /* Scan for NL */
        if (status == ALT_E_SUCCESS)
        {
            buffer->rx_nl_count += strnpop(buffer->rx_buffer + buffer->rx_start + buffer->rx_level, copy_size, ALT_CR_TOKEN);
        }

        /* Echo */
        if ((status == ALT_E_SUCCESS) && (buffer->echo_enable == true))
        {
            status = alt_16550_buffer_echo(buffer, buffer->rx_buffer + buffer->rx_start + buffer->rx_level, copy_size);
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        buffer->rx_level += copy_size;
    }

    /* Disable RX interrupts if the RX buffer is full. */
    if ((status == ALT_E_SUCCESS) && (buffer->rx_level == ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE))
    {
        status = alt_16550_int_disable_rx(buffer->handle);
    }

#if ALT_16550_BUFFER_ENABLE_SMP
    buffer->isr_rx = false;
#endif

    return status;
}

/*
// Helper function to handle UART TX interrupts.
*/
static ALT_STATUS_CODE alt_16550_buffer_int_tx(ALT_16550_BUFFER_t * buffer)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    uint32_t fifo_level_tx;
    uint32_t copy_size;

#if ALT_16550_BUFFER_ENABLE_SMP
    buffer->isr_tx = true;
#endif

    /* Gets the current level in the TX FIFO. */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_fifo_level_get_tx(buffer->handle, &fifo_level_tx);
    }

    /* Copy the TX buffer into the TX FIFO. */
    copy_size = stdminul(buffer->fifo_size_tx - fifo_level_tx, buffer->tx_level);

    if (buffer->tx_start + copy_size > ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE)
    {
        /* Wrapping */
        uint32_t copy_size_2 = buffer->tx_start + copy_size - ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE;
        uint32_t copy_size_1 = copy_size - copy_size_2;

        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_fifo_write(buffer->handle,
                                          buffer->tx_buffer + buffer->tx_start, copy_size_1);
        }
        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_fifo_write(buffer->handle,
                                          buffer->tx_buffer, copy_size_2);
        }

        if (status == ALT_E_SUCCESS)
        {
            buffer->tx_start = copy_size_2;
        }
    }
    else
    {
        /* No wrapping */
        if (status == ALT_E_SUCCESS)
        {
            status = alt_16550_fifo_write(buffer->handle, buffer->tx_buffer + buffer->tx_start, copy_size);
        }
        if (status == ALT_E_SUCCESS)
        {
            buffer->tx_start += copy_size;
            if (buffer->tx_start == ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE)
            {
                buffer->tx_start = 0;
            }
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        buffer->tx_level -= copy_size;
    }

#if ALT_16550_BUFFER_ENABLE_SMP
    buffer->isr_tx = false;
#endif

    return status;
}

static ALT_STATUS_CODE alt_16550_buffer_int_line(ALT_16550_BUFFER_t * buffer)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    uint32_t line_status;

    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_line_status_get(buffer->handle,
                                           &line_status);
    }

    if (status == ALT_E_SUCCESS)
    {
        if (line_status & ALT_16550_LINE_STATUS_OE)
        {
            ALT_PRINTF("UART[buffer]: Overrun Error detected.\n");
            status = ALT_E_UART_OE;
        }
        else if (line_status & ALT_16550_LINE_STATUS_PE)
        {
            /* Unlikely to occur as parity is turned off. Added for completeness. */
            ALT_PRINTF("UART[buffer]: Parity Error detected.\n");
            status = ALT_E_UART_PE;
        }
        else if (line_status & ALT_16550_LINE_STATUS_FE)
        {
            ALT_PRINTF("UART[buffer]: Framing Error detected.\n");
            status = ALT_E_UART_FE;
        }
        else if (line_status & ALT_16550_LINE_STATUS_RFE)
        {
            ALT_PRINTF("UART[buffer]: Receiver FIFO Error detected.\n");
            status = ALT_E_UART_RFE;
        }
    }

    return status;
}

/*
// Callback function to for UART interrupts.
*/
static void alt_16550_buffer_int_callback(uint32_t icciar, void * context)
{
    ALT_16550_BUFFER_t * buffer = (ALT_16550_BUFFER_t *)context;

    ALT_16550_INT_STATUS_t int_status;

    if (buffer->status == ALT_E_SUCCESS)
    {
        buffer->status = alt_16550_int_status_get(buffer->handle, &int_status);
    }

    if (buffer->status == ALT_E_SUCCESS)
    {
        switch (int_status)
        {
        case ALT_16550_INT_STATUS_RX_DATA:
        case ALT_16550_INT_STATUS_RX_TIMEOUT:
            buffer->status = alt_16550_buffer_int_rx(buffer);
            break;
        case ALT_16550_INT_STATUS_TX_IDLE:
            buffer->status = alt_16550_buffer_int_tx(buffer);
            break;
        case ALT_16550_INT_STATUS_LINE:
            buffer->status = alt_16550_buffer_int_line(buffer);
            break;
        default:
            break;
        }
    }

    if (buffer->status != ALT_E_SUCCESS)
    {
        alt_int_dist_disable((ALT_INT_INTERRUPT_t)ALT_INT_ICCIAR_ACKINTID_GET(icciar));
    }
}

ALT_STATUS_CODE alt_16550_buffer_init(ALT_16550_BUFFER_t * buffer,
                                      ALT_16550_HANDLE_t * handle,
                                      ALT_INT_INTERRUPT_t int_id,
                                      uint32_t int_target)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    /*
    // Initialize contents of the buffer structure
    */

    buffer->handle = handle;
    buffer->status = ALT_E_SUCCESS;

    buffer->fifo_size_rx = 0;
    buffer->fifo_size_tx = 0;

#if ALT_16550_BUFFER_ENABLE_SMP
    buffer->isr_rx = false;
    buffer->isr_tx = false;
#endif

    buffer->rx_start    = 0;
    buffer->rx_level    = 0;
    buffer->rx_nl_count = 0;

    buffer->tx_start = 0;
    buffer->tx_level = 0;

    buffer->echo_enable = false;
    buffer->echo_char   = 0;

    /* Turn on FIFOs */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_fifo_enable(handle);
    }

    /* Set the RX and TX trigger levels */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_fifo_trigger_set_rx(handle,
                                               ALT_16550_FIFO_TRIGGER_RX_HALF_FULL);
    }
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_fifo_trigger_set_tx(handle,
                                               ALT_16550_FIFO_TRIGGER_TX_QUARTER_FULL);
    }

    /* Query the size of the RX and TX FIFOs */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_fifo_size_get_rx(handle, &buffer->fifo_size_rx);
    }
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_fifo_size_get_tx(handle, &buffer->fifo_size_tx);
    }

    /* Enable RX Interrupts on the UART. Don't enable TX until we have something to write. */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_enable_rx(handle);
    }

    /* Enable Line Interrupts on the UART. This will allow us to detect errors. */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_enable_line(handle);
    }

    /* Register our ISR */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_isr_register(int_id, alt_16550_buffer_int_callback, buffer);
    }

    if (   (status == ALT_E_SUCCESS)
        && (int_id >= 32)) /* Ignore target_set() for non-SPI interrupts. */
    {
        if (int_target == 0)
        {
            int_target = (1 << alt_int_util_cpu_count()) - 1;
        }
        status = alt_int_dist_target_set(int_id, int_target);
    }

    /* Enable interrupt */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_dist_enable(int_id);
    }

    return status;
}

ALT_STATUS_CODE alt_16550_buffer_uninit(ALT_16550_BUFFER_t * buffer, ALT_INT_INTERRUPT_t int_id)
{
    /* Disable interrupt */
    alt_int_dist_disable(int_id);

    /* Unregister ISR */
    alt_int_isr_unregister(int_id);

    /* Disable all UART interrupts */
    alt_16550_int_disable_all(buffer->handle);

    /* Turn off FIFOs */
    alt_16550_fifo_disable(buffer->handle);

    return ALT_E_SUCCESS;
}

ALT_STATUS_CODE alt_16550_buffer_size_rx(ALT_16550_BUFFER_t * buffer, uint32_t * size)
{
    *size = ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE;
    return ALT_E_SUCCESS;
}

ALT_STATUS_CODE alt_16550_buffer_size_tx(ALT_16550_BUFFER_t * buffer, uint32_t * size)
{
    *size = ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE;
    return ALT_E_SUCCESS;
}

ALT_STATUS_CODE alt_16550_buffer_level_rx(ALT_16550_BUFFER_t * buffer, uint32_t * level)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    /* Disable RX ISR */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_disable_rx(buffer->handle);
    }

#if ALT_16550_BUFFER_ENABLE_SMP
    /* Wait for the ISR to exit the RX section */
    /* This is only really needed in multi-CPU systems. */
    if (status == ALT_E_SUCCESS)
    {
        int i = 10000;
        while (--i)
        {
            if (!buffer->isr_rx)
            {
                break;
            }
        }

        if (i == 0)
        {
            status = ALT_E_TMO;
        }
    }
#endif

    if (status == ALT_E_SUCCESS)
    {
        *level = buffer->rx_level;

        if (buffer->rx_level < ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE)
        {
            status = alt_16550_int_enable_rx(buffer->handle);
        }
    }

    return status;
}

ALT_STATUS_CODE alt_16550_buffer_level_tx(ALT_16550_BUFFER_t * buffer, uint32_t * level)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    /* Disable TX ISR */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_disable_tx(buffer->handle);
    }

#if ALT_16550_BUFFER_ENABLE_SMP
    /* Wait for the ISR to exit the TX section */
    /* This is only really needed in multi-CPU systems. */
    if (status == ALT_E_SUCCESS)
    {
        int i = 10000;
        while (--i)
        {
            if (!buffer->isr_tx)
            {
                break;
            }
        }

        if (i == 0)
        {
            status = ALT_E_TMO;
        }
    }
#endif

    if (status == ALT_E_SUCCESS)
    {
        *level = buffer->tx_level;

        if (buffer->tx_level > 0)
        {
            status = alt_16550_int_enable_tx(buffer->handle);
        }
    }

    return status;
}

ALT_STATUS_CODE alt_16550_buffer_read_raw(ALT_16550_BUFFER_t * buffer,
                                          char * data,
                                          size_t size,
                                          size_t * size_read)
{
    ALT_STATUS_CODE status;
    /* Report ISR error if any. */
    if (buffer->status != ALT_E_SUCCESS)
    {
        return buffer->status;
    }

    /* User requested a 0-sized read or there is no data in the buffer to read. */
    if ((size == 0) || (buffer->rx_level == 0))
    {
        *size_read = 0;
        return ALT_E_SUCCESS;
    }
    status = ALT_E_SUCCESS;

    /* Disable RX ISR */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_disable_rx(buffer->handle);
    }

#if ALT_16550_BUFFER_ENABLE_SMP
    /* Wait for the ISR to exit the RX section */
    /* This is only really needed in multi-CPU systems. */
    if (status == ALT_E_SUCCESS)
    {
        int i = 10000;
        while (--i)
        {
            if (!buffer->isr_rx)
            {
                break;
            }
        }

        if (i == 0)
        {
            status = ALT_E_TMO;
        }
    }
#endif

    /* Copy out the read buffer into the user buffer. */
    if (status == ALT_E_SUCCESS)
    {
        uint32_t copy_size = stdminul(size, buffer->rx_level);

        if (buffer->rx_start + copy_size > ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE)
        {
            /* Wrapping */
            uint32_t copy_size_2 = buffer->rx_start + copy_size - ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE;
            uint32_t copy_size_1 = copy_size - copy_size_2;

            char * ptr = buffer->rx_buffer + buffer->rx_start;
            uint32_t i;
            for (i = 0; i < copy_size_1; i++)
            {
               *data = *ptr;
               data++;
               ptr++;
            }

            data = data+copy_size_1;
            ptr = buffer->rx_buffer;
            for (i = 0; i < copy_size_2; i++)
            {
               *data = *ptr;
               data++;
               ptr++;
            }

            buffer->rx_start = copy_size_2;
        }
        else
        {
            uint32_t i;
            /* No wrapping */

            char * ptr = buffer->rx_buffer + buffer->rx_start;
            for (i = 0; i < copy_size; i++)
            {
               *data = *ptr;
               data++;
               ptr++;
            }

            buffer->rx_start += copy_size;
            if (buffer->rx_start == ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE)
            {
                buffer->rx_start = 0;
            }
        }

        /* Decrease population of NL found */
        buffer->rx_nl_count -= strnpop(data, copy_size, ALT_CR_TOKEN);

        buffer->rx_level -= copy_size;
        *size_read = copy_size;
    }

    /* Now that there is some empty space in the buffer, enable RX interrupts. */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_enable_rx(buffer->handle);
    }

    return status;
}

ALT_STATUS_CODE alt_16550_buffer_read_line(ALT_16550_BUFFER_t * buffer,
                                           char * data,
                                           size_t size,
                                           size_t * size_read)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    /* Copy size needed to copy up to and including the next NL. */
    uint32_t size_nl = 0;

    /* Report ISR error if any. */
    if (buffer->status != ALT_E_SUCCESS)
    {
        return buffer->status;
    }

    /* User requested a 0-sized read or there is no data in the buffer to read, or no NL to read. */
    if ((size == 0) || (buffer->rx_level == 0) || (buffer->rx_nl_count == 0))
    {
        *size_read = 0;
        return ALT_E_SUCCESS;
    }

    /* Disable RX ISR */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_disable_rx(buffer->handle);
    }

#if ALT_16550_BUFFER_ENABLE_SMP
    /* Wait for the ISR to exit the RX section */
    /* This is only really needed in multi-CPU systems. */
    if (status == ALT_E_SUCCESS)
    {
        int i = 10000;
        while (--i)
        {
            if (!buffer->isr_rx)
            {
                break;
            }
        }

        if (i == 0)
        {
            status = ALT_E_TMO;
        }
    }
#endif

    /* Locate the next position of the NL */
    if (status == ALT_E_SUCCESS)
    {
        /* Scan size. Don't search the buffer more than the size requested. */
        uint32_t scan_nl = stdminul(size, buffer->rx_level);

        /* Pointer to the NL within the string. */
        const char * search_nl = NULL;

        if (buffer->rx_start + scan_nl > ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE)
        {
            /* Wrapping */
            uint32_t scan_nl_2 = buffer->rx_start + scan_nl - ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE;
            uint32_t scan_nl_1 = scan_nl - scan_nl_2;

            if ((search_nl = strnchr(buffer->rx_buffer + buffer->rx_start, ALT_CR_TOKEN, scan_nl_1)) != NULL)
            {
                /* The NL is in the first section.
                // +1 because we want to copy including the NL at [i]. */
                size_nl = search_nl - (buffer->rx_buffer + buffer->rx_start) + 1;
            }
            else if ((search_nl = strnchr(buffer->rx_buffer, ALT_CR_TOKEN, scan_nl_2)) != NULL)
            {
                /* The NL is in the wrapped section. */
                size_nl = scan_nl_1 + (search_nl - buffer->rx_buffer) + 1;
            }
        }
        else
        {
            /* No wrap */
            if ((search_nl = strnchr(buffer->rx_buffer + buffer->rx_start, ALT_CR_TOKEN, scan_nl)) != NULL)
            {
                /* +1 because we want to copy including the NL at [i]. */
                size_nl = search_nl - (buffer->rx_buffer + buffer->rx_start) + 1;
            }
        }

        if (size_nl == 0)
        {
            if (buffer->rx_level < ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE)
            {
                alt_16550_int_enable_rx(buffer->handle);
            }

            /* The copy required for the string up to the NL is larger than the buffer provided by caller. */
            status = ALT_E_BUF_OVF;
        }
    }

    /* Copy out the read buffer into the user buffer. */
    if (status == ALT_E_SUCCESS)
    {
        if (buffer->rx_start + size_nl > ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE)
        {
            uint32_t i;
            /* Wrapping */
            uint32_t copy_size_2 = buffer->rx_start + size_nl - ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE;
            uint32_t copy_size_1 = size_nl - copy_size_2;

            char * ptr = buffer->rx_buffer + buffer->rx_start;
            for (i = 0; i < copy_size_1; i++)
            {
               *data = *ptr;
               data++;
               ptr++;
            }

            data = data+copy_size_1;
            ptr = buffer->rx_buffer;
            for (i = 0; i < copy_size_2; i++)
            {
               *data = *ptr;
               data++;
               ptr++;
            }

            buffer->rx_start = copy_size_2;
        }
        else
        {
            uint32_t i;
            /* No wrapping */
            char * ptr = buffer->rx_buffer + buffer->rx_start;
            for (i = 0; i < size_nl; i++)
            {
               *data = *ptr;
               data++;
               ptr++;
            }

            buffer->rx_start += size_nl;
            if (buffer->rx_start == ALT_16550_BUFFER_PROVISION_RX_BUFFER_SIZE)
            {
                buffer->rx_start = 0;
            }
        }

        /* Decrease population of NL found. */
        /* This is always 1 as we are reading up to the next NL. */
        --buffer->rx_nl_count;

        buffer->rx_level -= size_nl;
        *size_read = size_nl;
    }

    /* Now that there is some empty space in the buffer, enable RX interrupts. */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_enable_rx(buffer->handle);
    }

    return status;
}

ALT_STATUS_CODE alt_16550_buffer_write_raw(ALT_16550_BUFFER_t * buffer,
                                           const char * data,
                                           size_t size,
                                           size_t * size_written)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    /* Report ISR error if any. */
    if (buffer->status != ALT_E_SUCCESS)
    {
        return buffer->status;
    }

    /* User requested a 0-sized write or there is no space left in the buffer. */
    if ((size == 0) || (buffer->tx_level == ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE))
    {
        *size_written = 0;
        return ALT_E_SUCCESS;
    }

    /* Disable TX ISR */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_disable_tx(buffer->handle);
    }

#if ALT_16550_BUFFER_ENABLE_SMP
    /* Wait for the ISR to exit the TX section
    // This is only really needed in multi-CPU systems. */
    if (status == ALT_E_SUCCESS)
    {
        int i = 10000;
        while (--i)
        {
            if (!buffer->isr_tx)
            {
                break;
            }
        }

        if (i == 0)
        {
            status = ALT_E_TMO;
        }
    }
#endif

    /* Copy in the user buffer into the write buffer */
    if (status == ALT_E_SUCCESS)
    {
        uint32_t copy_size = stdminul(size, ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE - buffer->tx_level);
        uint32_t i;

        if (buffer->tx_start + buffer->tx_level >= ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE)
        {
            /* Already wrapped */
            uint32_t wrapped_offset = buffer->tx_start + buffer->tx_level - ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE;
            char * ptr = buffer->tx_buffer + wrapped_offset;

            for (i = 0; i < copy_size; i++)
            {
               *ptr = *data;
               data++;
               ptr++;
            }

        }
        else if (buffer->tx_start + buffer->tx_level + copy_size > ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE)
        {
            /* Will wrap */
            uint32_t copy_size_2 = buffer->tx_start + buffer->tx_level + copy_size - ALT_16550_BUFFER_PROVISION_TX_BUFFER_SIZE;
            uint32_t copy_size_1 = copy_size - copy_size_2;

            char * ptr = buffer->tx_buffer + buffer->tx_start + buffer->tx_level;
            for (i = 0; i < copy_size_1; i++)
            {
               *ptr = *data;
               data++;
               ptr++;
            }

            data = data + copy_size_1;
            ptr = buffer->tx_buffer;
            for (i = 0; i < copy_size_2; i++)
            {
               *ptr = *data;
               data++;
               ptr++;
            }
        }
        else
        {
            /* No wrapping */

            char * ptr = buffer->tx_buffer + buffer->tx_start + buffer->tx_level;
            for (i = 0; i < copy_size; i++)
            {
               *ptr = *data;
               data++;
               ptr++;
            }
        }

        buffer->tx_level += copy_size;
        *size_written = copy_size;
    }

    /* Now that there is some data to send, enable TX interrupts */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_int_enable_tx(buffer->handle);
    }

    return status;
}

ALT_STATUS_CODE alt_16550_buffer_write_line(ALT_16550_BUFFER_t * buffer,
                                            const char * data,
                                            size_t size,
                                            size_t * size_written)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;
    size_t size_left;


    /* Report ISR error if any. */
    if (buffer->status != ALT_E_SUCCESS)
    {
        return buffer->status;
    }

    if (size == 0)
    {
        size = strnlen_s(data,BUFFER_TRANSFER_MAX);
    }

    *size_written = 0;
    size_left = size;

    while (size_left > 0)
    {
        char output[MAX_BUFFER_SIZE];

        size_t write_size = 0;
        uint32_t copy_size = stdminul(size_left, sizeof(output) - 1);

        if (status != ALT_E_SUCCESS)
        {
            break;
        }

        while (write_size < copy_size)
        {
            if (data[size - size_left] == '\n')
            {
                output[write_size] = '\r';
                ++write_size;
                output[write_size] = '\n';
            }
            else
            {
                output[write_size] = data[size - size_left];
            }

            ++write_size;
            --size_left;
        }

        status = alt_16550_buffer_write_raw(buffer,
                                            output, write_size,
                                            &write_size);
        if (status == ALT_E_SUCCESS)
        {
            *size_written += write_size;
        }
    }

    return status;
}

ALT_STATUS_CODE alt_16550_buffer_echo_enable(ALT_16550_BUFFER_t * buffer,
                                             bool inject_lf,
                                             char echo)
{
    buffer->echo_enable    = true;
    buffer->echo_inject_lf = inject_lf;
    buffer->echo_char      = echo;
    return ALT_E_SUCCESS;
}

ALT_STATUS_CODE alt_16550_buffer_echo_disable(ALT_16550_BUFFER_t * buffer)
{
    buffer->echo_enable = false;
    return ALT_E_SUCCESS;
}
