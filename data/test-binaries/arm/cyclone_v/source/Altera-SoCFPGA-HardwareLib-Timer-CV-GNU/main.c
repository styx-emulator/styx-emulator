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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-Timer-CV-GNU/main.c#1 $
 */

#include "alt_printf.h"
#include "alt_clock_manager.h"
#include "alt_generalpurpose_io.h"
#include "alt_interrupt.h"
#include "alt_timers.h"
#include "alt_watchdog.h"
#include "socal/socal.h"
#include "socal/hps.h"
#include "socal/alt_rstmgr.h"

/* enable semihosting with Arm DS by defining an __auto_semihosting symbol
   will be removed by linker if semihosting is disabled */
int __auto_semihosting;

/* LED functions defined in leds_xx.c */
void setLEDS(uint8_t data);
ALT_STATUS_CODE setupLEDs(void);
ALT_STATUS_CODE cleanupLEDs(void);

/*
 * Initializes and enables the interrupt controller.
*/
ALT_STATUS_CODE socfpga_int_start(ALT_INT_INTERRUPT_t int_id,
                                  alt_int_callback_t callback,
                                  void * context)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    /*
     * Initialize the global and CPU interrupt items
    */

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_global_init();
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_cpu_init();
    }

    /*
     * Setup the interrupt specific items
    */

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_isr_register(int_id, callback, context);
    }

    if ((status == ALT_E_SUCCESS)
        && (int_id >= 32)) /* Ignore target_set() for non-SPI interrupts. */
    {
        int target = 0x3; /* 1 = CPU0, 2=CPU1 */
        status = alt_int_dist_target_set(int_id, target);
    }

    /*
     * Enable the distributor, CPU, and global interrupt
    */

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_dist_enable(int_id);
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_cpu_enable();
    }

    if (status == ALT_E_SUCCESS)
    {
        status = alt_int_global_enable();
    }

    return status;
}

void socfpga_int_stop(ALT_INT_INTERRUPT_t int_id)
{
    /*
     * Disable the global, CPU, and distributor interrupt
    */

    alt_int_global_disable();

    alt_int_cpu_disable();

    alt_int_dist_disable(int_id);

    /*
     * Unregister the ISR.
    */

    alt_int_isr_unregister(int_id);

    /*
     * Uninitialize the CPU and global data structures.
    */

    alt_int_cpu_uninit();

    alt_int_global_uninit();
}

ALT_STATUS_CODE socfpga_timer_start(ALT_GPT_TIMER_t timer, uint32_t period_in_ms)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;
    uint32_t freq;

    /*
     * Determine the frequency of the timer
    */

    if (status == ALT_E_SUCCESS)
    {
        status = alt_clk_freq_get(ALT_CLK_MPU_PERIPH, &freq);
        printf("INFO: Frequency = %" PRIu32 ".\n", freq);
    }

    /*
     * Set the counter of the timer, which determines how frequently it fires.
    */

    if (status == ALT_E_SUCCESS)
    {
        uint32_t counter = (freq / 1000) * period_in_ms;

        status = alt_gpt_counter_set(timer, counter);
        printf("INFO: Period    = %" PRIu32 " millisecond(s).\n", period_in_ms);
        printf("INFO: Counter   = %" PRIu32 ".\n", counter);
    }

    /*
     * Set to periodic, meaning it fires repeatedly.
    */

    if (status == ALT_E_SUCCESS)
    {
        status = alt_gpt_mode_set(timer, ALT_GPT_RESTART_MODE_PERIODIC);
    }

    /*
     * Set the prescaler of the timer to 0.
    */
    if (status == ALT_E_SUCCESS)
    {
        status = alt_gpt_prescaler_set(timer, 0);
    }

    /*
     * Clear pending interrupts
    */

    if (status == ALT_E_SUCCESS)
    {
        if (alt_gpt_int_if_pending_clear(timer) == ALT_E_BAD_ARG)
        {
            status = ALT_E_BAD_ARG;
        }
    }

    /*
     * Enable timer interrupts
    */

    if (status == ALT_E_SUCCESS)
    {
        status = alt_gpt_int_enable(timer);
    }

    /*
     * Start the timer.
    */

    if (status == ALT_E_SUCCESS)
    {
        status = alt_gpt_tmr_start(timer);
    }

    return status;
}

void socfpga_timer_stop(ALT_GPT_TIMER_t timer)
{
    alt_gpt_tmr_stop(timer);

    alt_gpt_int_disable(timer);
}

typedef struct ALT_TEST_TIMER_CONTEXT_s
{
    /* Number of times interrupt has been called. */
    volatile int count;

    /* Current part of the grey code to be displayed. */
    volatile int code;
}
ALT_TEST_TIMER_CONTEXT_t;

void test_timer_int_callback(uint32_t icciar, void * context)
{
    ALT_TEST_TIMER_CONTEXT_t * data = (ALT_TEST_TIMER_CONTEXT_t *) context;
    uint32_t gray;

    /*
     * Clear the timer interrupt
    */

    alt_gpt_int_if_pending_clear(ALT_GPT_CPU_PRIVATE_TMR);

    /*
     * Increment the ISR call count.
    */

    data->count++;

    /*
     * Calculate the grey code, 4 bits
    */

    gray = (data->code >> 1) ^ data->code;

    /*
     * Update the code number
    */

    data->code++;

    setLEDS(gray);
}

int main(int argc, char** argv)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;

    ALT_TEST_TIMER_CONTEXT_t data;
    data.count = 0;
    data.code  = 0;

    /*
     * Disable watchdogs
    */

    alt_wdog_stop(ALT_WDOG0);
    alt_wdog_stop(ALT_WDOG1);

    /*
     * Start the interrupt system
    */

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_int_start(ALT_INT_INTERRUPT_PPI_TIMER_PRIVATE,
                                   test_timer_int_callback, &data);
    }

    /*
     * Setup the LEDs
    */

    if (status == ALT_E_SUCCESS)
    {
        status = setupLEDs();
    }

    /*
     * Start the timer system
    */

    if (status == ALT_E_SUCCESS)
    {
        status = socfpga_timer_start(ALT_GPT_CPU_PRIVATE_TMR, 1500);
    }

    /*
     * Wait for the timer to be called X times.
    */

    if (status == ALT_E_SUCCESS)
    {
        while (data.count < 10)
        {
            ;
        }
    }

    /*
     * Stop the timer system
    */

    socfpga_timer_stop(ALT_GPT_CPU_PRIVATE_TMR);

    /*
     * Stop the LED system
    */

    cleanupLEDs();

    /*
     * Stop the interrupt system
    */

    socfpga_int_stop(ALT_INT_INTERRUPT_PPI_TIMER_PRIVATE);

    if (status == ALT_E_SUCCESS)
    {
        printf("RESULT: Example completed successfully.\n");
        return 0;
    }
    else
    {
        printf("RESULT: Some failures detected.\n");
        return 1;
    }
}
