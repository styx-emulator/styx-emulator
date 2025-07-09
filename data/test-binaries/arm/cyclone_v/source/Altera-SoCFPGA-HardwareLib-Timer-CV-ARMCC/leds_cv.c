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
 * $Id: //acds/rel/20.1std/embedded/examples/software/Altera-SoCFPGA-HardwareLib-Timer-CV-ARMCC/leds_cv.c#1 $
 */

#include <stdio.h>
#include <inttypes.h>
#include "alt_generalpurpose_io.h"
#include "socal/socal.h"
#include "socal/hps.h"

#define ALTR_5XS1_GPIO1_LED0                                  (0x00008000)        /*  GPIO 44 (44 - 29 == 15) */
#define ALTR_5XS1_GPIO1_LED1                                  (0x00004000)        /*  GPIO 43 (43 - 29 == 14) */
#define ALTR_5XS1_GPIO1_LED2                                  (0x00002000)        /*  GPIO 42 (42 - 29 == 13) */
#define ALTR_5XS1_GPIO1_LED3                                  (0x00001000)        /*  GPIO 41 (41 - 29 == 12) */
#define ALTR_5XS1_GPIO1_LED_SHIFT                             (12)

void setLEDS(uint8_t data)
{
    data = ~data;
    /* GPIO1, software port 1 */
    alt_gpio_port_data_write(ALT_GPIO_PORTB,
                             (ALTR_5XS1_GPIO1_LED0 | ALTR_5XS1_GPIO1_LED1 |
                              ALTR_5XS1_GPIO1_LED2 | ALTR_5XS1_GPIO1_LED3),
                             data << ALTR_5XS1_GPIO1_LED_SHIFT);
}

ALT_STATUS_CODE setupLEDs(void)
{
    ALT_STATUS_CODE status = ALT_E_SUCCESS;
    /*
     * Init the GPIO system
    */
    status = alt_gpio_init();
    if(status == ALT_E_SUCCESS)
    {
        status = alt_gpio_port_datadir_set(ALT_GPIO_PORTB,
            ALTR_5XS1_GPIO1_LED0 | ALTR_5XS1_GPIO1_LED1 |
            ALTR_5XS1_GPIO1_LED2 | ALTR_5XS1_GPIO1_LED3,
            ALTR_5XS1_GPIO1_LED0 | ALTR_5XS1_GPIO1_LED1 |
            ALTR_5XS1_GPIO1_LED2 | ALTR_5XS1_GPIO1_LED3);
    }
    return status;
}

ALT_STATUS_CODE cleanupLEDs(void)
{
    alt_gpio_uninit();
    return ALT_E_SUCCESS;
}
