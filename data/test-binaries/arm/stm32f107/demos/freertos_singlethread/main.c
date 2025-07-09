#define USE_STDPERIPH_DRIVER
#include "stm32_p103.h"

/* Scheduler includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"

static void setup_hardware( void );

void led_flash_task( void *pvParameters )
{
    while(1) {
        /* Toggle the LED. */
        GPIOC->ODR = GPIOC->ODR ^ 0x00001000;

        /* Wait one second. */
        vTaskDelay(100);
    }
}


int main(void)
{
    init_led();

    xTaskCreate( led_flash_task, ( signed portCHAR * ) "LED Flash", 512 /* stack size */, NULL, tskIDLE_PRIORITY + 5, NULL );

    /* Start running the task. */
    vTaskStartScheduler();

    return 0;
}

void vApplicationTickHook( void )
{
}
