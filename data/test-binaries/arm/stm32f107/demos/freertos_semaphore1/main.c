#define USE_STDPERIPH_DRIVER
#include "stm32_p103.h"

/* Scheduler includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include <string.h>
#include "myprintk.h"


SemaphoreHandle_t bin_sem_1;

void give_task(void* param)
{
    while(1){
        xSemaphoreGive(bin_sem_1);
        myprintf("TASK1 give \n");
        vTaskDelay(300);
    }
}

void take_task(void* param)
{
    while(1){
        if ( xSemaphoreTake(bin_sem_1,20)){
            myprintf("TASK2 get bin_sem_1 \n");
        }
        else{
            myprintf("TASK2 not get bin_sem_1\n");
        }
        vTaskDelay(100);
    }
}

int main(void)
{
    myprintf_init();

    bin_sem_1 = xSemaphoreCreateBinary();
    xSemaphoreGive(bin_sem_1);

    xTaskCreate(give_task, ( signed portCHAR * ) "V", 512/* stack size */, NULL, tskIDLE_PRIORITY + 10, NULL );
    xTaskCreate(take_task, ( signed portCHAR * ) "P", 512/* stack size */, NULL, tskIDLE_PRIORITY + 10, NULL );

    /* Start running the tasks. */
    vTaskStartScheduler();

    return 0;
}

void vApplicationTickHook( void )
{
}
