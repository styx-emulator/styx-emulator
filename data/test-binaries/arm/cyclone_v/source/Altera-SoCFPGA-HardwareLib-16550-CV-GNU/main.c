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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-16550-CV-GNU/main.c#1 $
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "alt_16550_buffer.h"
#include "alt_16550_uart.h"
#include "alt_interrupt.h"
#include "alt_safec.h"

#include "launcher_prompt.h"

#define ALT_UART_FLUSH_TMO 10000

/* enable semihosting with gcc by defining an __auto_semihosting symbol */
int __auto_semihosting;

/////

//
// Initializes and enables the interrupt controller.
//
ALT_STATUS_CODE socfpga_int_start(void)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    //
    // Initialize the global and CPU interrupt items
    //

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_global_init();
        if (status != ALT_E_SUCCESS)
        {
            printf("ERROR: alt_int_global_init() failed, %" PRIi32 ".\n", status);
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_cpu_init();
        if (status != ALT_E_SUCCESS)
        {
            printf("ERROR: alt_int_cpu_init() failed, %" PRIi32 ".\n", status);
        }
    }

    //
    // Enable the CPU and global interrupt
    //

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_cpu_enable();
        if (status != ALT_E_SUCCESS)
        {
            printf("ERROR: alt_int_cpu_enable() failed, %" PRIi32 ".\n", status);
        }
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_global_enable();
        if (status != ALT_E_SUCCESS)
        {
            printf("ERROR: alt_int_global_enable() failed, %" PRIi32 ".\n", status);
        }
    }

    return status;
}

void socfpga_int_stop(void)
{
    //
    // Disable the global, CPU, and distributor interrupt
    //

    if (alt_int_global_disable() != ALT_E_SUCCESS)
    {
        printf("WARN: alt_int_global_disable() return non-SUCCESS.");
    }

    if (alt_int_cpu_disable() != ALT_E_SUCCESS)
    {
        printf("WARN: alt_int_cpu_disable() return non-SUCCESS.");
    }

    //
    // Uninitialize the CPU and global data structures.
    //

    if (alt_int_cpu_uninit() != ALT_E_SUCCESS)
    {
        printf("WARN: alt_int_cpu_uninit() return non-SUCCESS.\n");
    }

    if (alt_int_global_uninit() != ALT_E_SUCCESS)
    {
        printf("WARN: alt_int_global_uninit() return non-SUCCESS.\n");
    }
}

//
// Initializes and enables the 16550 UART. It uses the following
// settings:
//  - 8-N-1
//  - 115200 baud
//
// Also initializes the UART buffer.
//
ALT_STATUS_CODE socfpga_16550_start(ALT_16550_HANDLE_t * handle,
                                    ALT_16550_DEVICE_t device,
                                    void * location, alt_freq_t frequency,
                                    const char * name,
                                    ALT_16550_BUFFER_t * buffer, ALT_INT_INTERRUPT_t int_id, uint32_t int_target)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    // Initialize the UART
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_init(device, location, frequency, handle);
        if (status != ALT_E_SUCCESS)
        {
            printf("ERROR: alt_16550_init(device=[%s]) failed.\n", name);
        }
    }

    // Configure for 8-N-1.
    // This is not really needed as the default configuration is 8-N-1.
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_line_config_set(handle, ALT_16550_DATABITS_8,
                                                   ALT_16550_PARITY_DISABLE,
                                                   ALT_16550_STOPBITS_1);
        if (status != ALT_E_SUCCESS)
        {
            printf("ERROR: alt_16550_line_config_set(handle=[%s]) failed.\n", name);
        }
    }

    // Configure for 115200 baud.
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_baudrate_set(handle, ALT_16550_BAUDRATE_115200);
        if (status != ALT_E_SUCCESS)
        {
            printf("ERROR: alt_16550_baudrate_set(handle=[%s], 115200) failed.\n", name);
        }
    }

    // Configure the buffering
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_buffer_init(buffer, handle, int_id, int_target);
    }
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_buffer_echo_enable(buffer, true, 0);
    }

    // Enable the UART
    if (status == ALT_E_SUCCESS)
    {
        status = alt_16550_enable(handle);
        if (status != ALT_E_SUCCESS)
        {
            printf("ERROR: alt_16550_enable(handle=[%s]) failed.\n", name);
        }
    }

    return status;
}

//
// Disables and uninitializes the 16550 UART.
//
void socfpga_16550_stop(ALT_16550_HANDLE_t * handle,
                        const char * name,
                        ALT_16550_BUFFER_t * buffer, ALT_INT_INTERRUPT_t int_id)
{
    // Disable the UART
    if (alt_16550_disable(handle) != ALT_E_SUCCESS)
    {
        printf("WARN: alt_16550_disable(handle=[%s]) failed.\n", name);
    }

    // Disable the buffering
    if (alt_16550_buffer_uninit(buffer, int_id) != ALT_E_SUCCESS)
    {
        printf("WARN: alt_16550_buffer_uninit(handle=[%s]) failed.\n", name);
    }

    // Uninitialize the UART
    if (alt_16550_uninit(handle) != ALT_E_SUCCESS)
    {
        printf("WARN: alt_16550_uninit(handle=[%s]) failed.\n", name);
    }
}

int main(int argc, char** argv)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_16550_HANDLE_t handle;
    handle.device     = ALT_16550_DEVICE_SOCFPGA_UART0;
    handle.location   = 0;
    handle.clock_freq = 0;

    ALT_16550_BUFFER_t buffer;

    // Construct the UART "friendly" name.
    char uart_name[64];

    switch (handle.device)
    {
    case ALT_16550_DEVICE_SOCFPGA_UART0:
        strncpy_s(uart_name, sizeof(uart_name) ,"SOCFPGA_UART0", sizeof("SOCFPGA_UART0"));
        break;
    case ALT_16550_DEVICE_SOCFPGA_UART1:
        strncpy_s(uart_name, sizeof(uart_name) ,"SOCFPGA_UART1", sizeof("SOCFPGA_UART1"));
        break;
    case ALT_16550_DEVICE_ALTERA_16550_UART:
        snprintf(uart_name, sizeof(uart_name), "ALTERA_16550_UART[%p]", handle.location);
        break;
    default:
        return ALT_E_BAD_ARG;
    }

    //
    // Start the interrupt system
    //
    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_int_start();
    }

    //
    // Start the UART
    //
    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_16550_start(&handle, handle.device, handle.location, handle.clock_freq, uart_name,
                                     &buffer, ALT_INT_INTERRUPT_UART0, 0);
    }
    else
    {
	return status;
    }

    /////

    //
    // Start the console app
    //

    if (status == ALT_E_SUCCESS)
    {
        printf("INFO: Starting Launch Prompt ...\n");
        status = launcher_prompt(&buffer);
    }
    else
    {
	return status;
    }

    //
    // Be polite: say "Goodbye!" to user.
    //
    if (status == ALT_E_SUCCESS)
    {
        char * text = "Goodbye!\n";
        size_t size_written = 0;
        status = alt_16550_buffer_write_line(&buffer,
                                             text, 0,
                                             &size_written);
    }

    //
    // Wait for the buffer TX to flush.
    //
    if (status == ALT_E_SUCCESS)
    {
        uint32_t flush_timeout = ALT_UART_FLUSH_TMO;

        while (--flush_timeout)
        {
            uint32_t level_tx = 0;
            status = alt_16550_buffer_level_tx(&buffer, &level_tx);

            if (status != ALT_E_SUCCESS)
            {
                break;
            }

            if (level_tx == 0)
            {
                break;
            }
        }

        if (flush_timeout == 0)
        {
            printf("ERROR: Timeout waiting for buffer TX to flush.\n");
            status = ALT_E_TMO;
        }
    }

    //
    // Wait for the UART TX to flush.
    //
    if (status == ALT_E_SUCCESS)
    {
        uint32_t flush_timeout = ALT_UART_FLUSH_TMO;

        while (--flush_timeout)
        {
            uint32_t line_status;
            status = alt_16550_line_status_get(&handle, &line_status);

            if (status != ALT_E_SUCCESS)
            {
                break;
            }
            if (line_status & ALT_16550_LINE_STATUS_TEMT)
            {
                break;
            }
        }

        if (flush_timeout == 0)
        {
            printf("ERROR: Timeout waiting for UART TX to empty.\n");
            status = ALT_E_TMO;
        }
    }

    /////

    //
    // Stop the 16550 UART
    //
    socfpga_16550_stop(&handle, uart_name, &buffer, ALT_INT_INTERRUPT_UART0);

    //
    // Stop the interrupt system
    //
    socfpga_int_stop();

    if (status == ALT_E_SUCCESS)
    {
        printf("RESULT: Example completed successfully.\n");
        return 0;
    }
    else
    {
        if (status == ALT_E_UART_OE)
        {
            printf("ERROR: UART Overrun Error detected. Bailing.\n");
        }
        else if (status == ALT_E_UART_PE)
        {
            printf("ERROR: UART Parity Error detected. Bailing.\n");
        }
        else if (status == ALT_E_UART_FE)
        {
            printf("ERROR: UART Framing Error detected. Bailing.\n");
        }
        else if (status == ALT_E_UART_RFE)
        {
            printf("ERROR: UART Receiver FIFO Error detected. Bailing.\n");
        }

        printf("RESULT: Some failures detected.\n");
        return 1;
    }
}
