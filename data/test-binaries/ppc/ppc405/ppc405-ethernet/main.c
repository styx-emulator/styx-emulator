/* Scheduler includes. */
#include "FreeRTOS.h"
#include "task.h"

/* Xilinx library includes. */
#include "xparameters.h"
#include "xcache_l.h"
#include "xintc.h"
#include "xuartlite.h"
#include "xemaclite.h"


const char* data  = "Did you ever hear the tragedy of Darth Plagueis The Wise?"
                    " I thought not. It's not a story the Jedi would tell you."
                    " It's a Sith legend. Darth Plagueis was a Dark Lord of th"
                    "e Sith, so powerful and so wise he could use the Force to"
                    " influence the midichlorians to create life… He had such "
                    "a knowledge of the dark side that he could even keep the "
                    "ones he cared about from dying. The dark side of the Forc"
                    "e is a pathway to many abilities some consider to be unna"
                    "tural. He became so powerful… the only thing he was afrai"
                    "d of was losing his power, which eventually, of course, h"
                    "e did. Unfortunately, he taught his apprentice everything"
                    " he knew, then his apprentice killed him in his sleep. Ir"
                    "onic. He could save others from death, but not himself.";

/*
 * Perform any hardware initialisation required by the demo application.
 */
static void prvSetupHardware( void );

/*-----------------------------------------------------------*/

#define EMACLITE_DEV_ID 0

#define MAX_DATA_LEN 1500

// type field is after both MAC addresses
#define LEN_FIELD_OFFSET 12

static XEmacLite xEmac;

// 00-00-5E-00-FA-CE
static const char source_mac[6] = {0x00, 0x00, 0x5E, 0x00, 0xFA, 0xCE};
static const char target_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

char frame_buffer[1536];

void init_ethernet(void) {
    XEmacLite_Initialize(&xEmac, EMACLITE_DEV_ID);
}

int prepare_and_send_data(const char* d) {
    // copy destination and source addresses into the frame buffer
    memcpy(frame_buffer, target_mac, 6);
    memcpy(frame_buffer + 6, source_mac, 6);

    // figure out the size of the data we want to send
    size_t data_len = 0;
    strlen(d, &data_len);

    if (data_len > 0x05DC) {
        // max length of data is 1500 bytes
        return 1;
    }

    // write len field to buffer
    short len_field = (short)(data_len & 0xFFFF);
    frame_buffer[LEN_FIELD_OFFSET] = (char)(len_field >> 8);
    frame_buffer[LEN_FIELD_OFFSET + 1] = (char)(len_field & 0xFF);

    // copy data into buffer
    memcpy(frame_buffer + 14, d, data_len);

    XEmacLite_Send(&xEmac, frame_buffer, data_len + 14);
}

int main( void )
{

	/* Must be called prior to installing any interrupt handlers! */
	vPortSetupInterruptController();

	/* In this case prvSetupHardware() just enables the caches and and
	configures the IO ports for the LED outputs. */
	prvSetupHardware();

	// initialize ethernet things
	init_ethernet();

    prepare_and_send_data(data);

	/* Now start the scheduler.  Following this call the created tasks should
	be executing. */
	vTaskStartScheduler();

	/* vTaskStartScheduler() will only return if an error occurs while the
	idle task is being created. */
	for( ;; );

	return 0;
}

static void prvSetupHardware( void )
{
	XCache_EnableICache( 0x80000000 );
	XCache_EnableDCache( 0x80000000 );
}

/* This hook function will get called if there is a suspected stack overflow.
An overflow can cause the task name to be corrupted, in which case the task
handle needs to be used to determine the offending task. */
void vApplicationStackOverflowHook( TaskHandle_t xTask, signed char *pcTaskName );
void vApplicationStackOverflowHook( TaskHandle_t xTask, signed char *pcTaskName )
{
/* To prevent the optimiser removing the variables. */
volatile TaskHandle_t xTaskIn = xTask;
volatile signed char *pcTaskNameIn = pcTaskName;

	/* Remove compiler warnings. */
	( void ) xTaskIn;
	( void ) pcTaskNameIn;

	for( ;; );
}
