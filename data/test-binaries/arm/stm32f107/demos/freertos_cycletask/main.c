#define USE_STDPERIPH_DRIVER
#include "stm32_p103.h"

/* Scheduler includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include <string.h>
#include "myprintk.h"



void cycle_task_1(void* param)
{
    TickType_t first= xTaskGetTickCount();
    TickType_t next;
    TickType_t last=xTaskGetTickCount();
    TickType_t tick;
    while(1){
        tick = xTaskGetTickCount();
        myprintf("true cycletask - TaskDelayUntil 100 : current tick : %d delta %d \n",tick,tick-last);
        last = tick;
        vTaskDelayUntil(&first,100);
    }
}

void cycle_task_2(void* param)
{
    TickType_t last=xTaskGetTickCount();
    TickType_t tick;
    while(1){
        tick = xTaskGetTickCount();
        myprintf("fake cycletask - TaskDelay 100 : current tick : %d delta %d \n",tick,tick-last);
        last=tick;
        vTaskDelay(100);
    }
}

int main(void)
{

    myprintf_init();

    xTaskCreate(cycle_task_1, ( signed portCHAR * ) "cycle", 128/* stack size */, NULL, tskIDLE_PRIORITY + 10, NULL );
    xTaskCreate(cycle_task_2, ( signed portCHAR * ) "fake", 128/* stack size */, NULL, tskIDLE_PRIORITY + 10, NULL );

    /* Start running the tasks. */
    vTaskStartScheduler();

    return 0;
}

void vApplicationTickHook( void )
{
}
