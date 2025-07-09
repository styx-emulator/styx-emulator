/* Scheduler includes. */
#include "FreeRTOS.h"
#include "task.h"

/* Xilinx library includes. */
#include "xparameters.h"
#include "xcache_l.h"
#include "xintc.h"
#include "xuartlite.h"

typedef void * xComPortHandle;

/*
 * Perform any hardware initialisation required by the demo application.
 */
static void prvSetupHardware( void );

/*-----------------------------------------------------------*/

/* Structure that maintains information on the UART being used. */
static XUartLite xUART;
static xComPortHandle xPort = NULL;

char hello_string[] = "Hello world.\r\n";

#define RING_BUF_SIZE 32

char ring_buffer[RING_BUF_SIZE];
volatile unsigned int tx_index;
volatile unsigned int rx_index;

static void serialIRQ(XUartLite *uart);

void init_serial() {
	XUartLite_Initialize( &xUART, XPAR_RS232_UART_DEVICE_ID );
	XUartLite_ResetFifos( &xUART );
	XUartLite_DisableInterrupt( &xUART );

	if( xPortInstallInterruptHandler( XPAR_XPS_INTC_0_RS232_UART_INTERRUPT_INTR, ( XInterruptHandler )serialIRQ, (void *)&xUART ) == pdPASS )
	{
		/* xPortInstallInterruptHandler() could fail if
		vPortSetupInterruptController() has not been called prior to this
		function. */
		XUartLite_EnableInterrupt( &xUART );
	}
}

static void serialIRQ(XUartLite *uart) {
	// don't need the ref
	( void ) uart;

	char data;
	int did_something = 0;
	unsigned long status_reg = 0;

	status_reg = XIo_In32( XPAR_RS232_UART_BASEADDR + XUL_STATUS_REG_OFFSET );

	// new data available
	if ( (status_reg & XUL_SR_RX_FIFO_VALID_DATA) != 0) {
		data = ( char ) XIo_In32( XPAR_RS232_UART_BASEADDR + XUL_RX_FIFO_OFFSET );

		if (((rx_index + 1) % RING_BUF_SIZE) != tx_index)
		{
			ring_buffer[rx_index] = data;
			rx_index = (rx_index + 1) % RING_BUF_SIZE;
		}
	}
}

static portTASK_FUNCTION( uart_task, pvParameters )
{
char data;
unsigned long status_reg;

	/* Just to stop compiler warnings. */
	( void ) pvParameters;

	for( ;; )
	{
		status_reg = XIo_In32( XPAR_RS232_UART_BASEADDR + XUL_STATUS_REG_OFFSET );

		while ((status_reg & XUL_SR_TX_FIFO_EMPTY) && (rx_index != tx_index)) {
			XIo_Out32( XPAR_RS232_UART_BASEADDR + XUL_TX_FIFO_OFFSET, ring_buffer[tx_index] );
			tx_index = (tx_index + 1) % RING_BUF_SIZE;
		}
	}
}

void send_blocking(const char *data, unsigned int length) {
	unsigned long status_reg;
	while (length--) {
		while (!(XIo_In32( XPAR_RS232_UART_BASEADDR + XUL_STATUS_REG_OFFSET ) & XUL_SR_TX_FIFO_EMPTY)) {}
		XIo_Out32( XPAR_RS232_UART_BASEADDR + XUL_TX_FIFO_OFFSET, *(data++) );
	}
}

int main( void )
{

	/* Must be called prior to installing any interrupt handlers! */
	vPortSetupInterruptController();

	/* In this case prvSetupHardware() just enables the caches and and
	configures the IO ports for the LED outputs. */
	prvSetupHardware();

	// initialize uart things
	init_serial();

	// send initial message
	send_blocking(hello_string, 15);

	// create the task responsible for sending data over UART
	xTaskCreate( uart_task, "UART_TX", configMINIMAL_STACK_SIZE, NULL, tskIDLE_PRIORITY + 1, ( TaskHandle_t * ) NULL );

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
