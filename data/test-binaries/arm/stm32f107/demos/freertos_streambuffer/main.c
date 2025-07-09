#define USE_STDPERIPH_DRIVER
#include "stm32_p103.h"

/* Scheduler includes. */
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "semphr.h"
#include "stream_buffer.h"
#include <string.h>

static void setup_hardware( void );

volatile xQueueHandle serial_str_queue = NULL;
volatile xQueueHandle serial_rx_queue = NULL;
volatile xSemaphoreHandle serial_tx_wait_sem = NULL;
StreamBufferHandle_t *comm_sb;

/* Queue structure used for passing messages. */
typedef struct
{
    char str[300];
} serial_str_msg;

/* Queue structure used for passing characters. */
typedef struct
{
    char ch;
} serial_ch_msg;


int usart_output(const char *str)
{
    serial_str_msg msg;

    /* Prepare the message to be queued. */
    strcpy(msg.str, str);

    /* Post the message.  Keep on trying until it is successful. */
    while(!xQueueSendToBack(serial_str_queue, &msg, portMAX_DELAY));

}

void sender_task(void *param)
{
    int len=0,size=0;
    char buf[1024];

    do{
        if (xStreamBufferIsFull(comm_sb) == pdTRUE){
            //full
            usart_output("full\n\r");
            continue;
        }
        else{
            usart_output("SendinG\n\r");
            size = 200;
            memset(buf,0xac,size);
            len = xStreamBufferSend(comm_sb,buf,size,portMAX_DELAY);
            usart_output("send\n\r");
            vTaskDelay(30);
        }
    }while(1);
}

void reader_task(void *param)
{
    int len=0,size=0;
    char buf[1024];
    do{
        if (xStreamBufferIsEmpty(comm_sb) == pdTRUE){
            //empty
            usart_output("empty\n\r");
            continue;
        }
        else{
            usart_output("recving\n\r");
            size = 200;
            buf[198]='\n';
            buf[199]='\r';
            memset(buf,0,size);
            len = xStreamBufferReceive(comm_sb,buf,size,portMAX_DELAY);
            usart_output("recv: ");
            usart_output(buf);
            usart_output("\n\r\n\r");
            vTaskDelay(50);
        }
    }while(1);

}

/* IRQ handler to handle USART2 interrupts (both transmit and receive
 * interrupts). */
void USART2_IRQHandler(void)
{
    static signed portBASE_TYPE xHigherPriorityTaskWoken;
    serial_ch_msg rx_msg;

    /* If this interrupt is for a transmit... */
    if(USART_GetITStatus(USART2, USART_IT_TXE) != RESET) {
        /* "give" the serial_tx_wait_sem semaphore to notify processes that
         * the buffer has a spot free for the next byte.
         */
        xSemaphoreGiveFromISR(serial_tx_wait_sem, &xHigherPriorityTaskWoken);

        /* Disables the transmit interrupt. */
        USART_ITConfig(USART2, USART_IT_TXE, DISABLE);
    /* If this interrupt is for a receive... */
    } else if(USART_GetITStatus(USART2, USART_IT_RXNE) != RESET) {
        /* Receive the byte from the buffer. */
        rx_msg.ch = USART_ReceiveData(USART2);

        /* Queue the received byte. */
        if(!xQueueSendToBackFromISR(serial_rx_queue, &rx_msg, &xHigherPriorityTaskWoken)) {
            /* If there was an error queueing the received byte, freeze. */
            while(1);
        }
    } else {
        /* Only transmit and receive interrupts should be enabled.  If this is
         * another type of interrupt, freeze.
         */
        while(1);
    }

    if(xHigherPriorityTaskWoken) {
        taskYIELD();
    }
}

void send_byte_rtos(char ch)
{
    /* Wait until the RS232 port can receive another byte (this semaphore is
     * "given" by the RS232 port interrupt when the buffer has room for another
     * byte.
     */
    while(!xSemaphoreTake(serial_tx_wait_sem, portMAX_DELAY));

    /* Send the byte and enable the transmit interrupt (it is disabled by the
     * interrupt).
     */
    USART_SendData(USART2, ch);
    USART_ITConfig(USART2, USART_IT_TXE, ENABLE);
}

char receive_byte_rtos(void)
{
    serial_ch_msg msg;

    /* Wait for a byte to be queued by the receive interrupt handler. */
    while(!xQueueReceive(serial_rx_queue, &msg, portMAX_DELAY));

    return msg.ch;
}

void rs232_xmit_msg_task( void *pvParameters )
{
    serial_str_msg msg;
    int curr_char;

    while(1) {
        /* Read from the queue.  Keep trying until a message is received.  This
         * will block for a period of time (specified by portMAX_DELAY). */
        while(!xQueueReceive(serial_str_queue, &msg, portMAX_DELAY));

        /* Write each character of the message to the RS232 port. */
        curr_char = 0;
        while(msg.str[curr_char] != '\0') {
            send_byte_rtos(msg.str[curr_char]);
            curr_char++;
        }
    }
}

void serial_readwrite_task( void *pvParameters )
{
    serial_str_msg msg;
    char ch;
    int curr_char;
    int done;

    /* Prepare the response message to be queued. */
    strcpy(msg.str, "Got:");

    while(1) {
        curr_char = 4;
        done = 0;
        do {
            /* Receive a byte from the RS232 port (this call will block). */
            ch = receive_byte_rtos();

            /* If the byte is an end-of-line type character, then finish the
             * string and indicate we are done.
             */
            if((ch == '\r') || (ch == '\n')) {
                msg.str[curr_char] = '\n';
                msg.str[curr_char+1] = '\0';
                done = -1;
            /* Otherwise, add the character to the response string. */
            } else {
                msg.str[curr_char++] = ch;
            }
        } while(!done);

        /* Once we are done building the response string, queue the response to
         * be sent to the RS232 port.
         */
        while(!xQueueSendToBack(serial_str_queue, &msg, portMAX_DELAY));
    }
}


int main(void)
{
    init_rs232();
    enable_rs232_interrupts();
    enable_rs232();

    /* Create the queue to hold messages to be written to the RS232. */
    serial_str_queue = xQueueCreate( 10, sizeof( serial_str_msg ) );
    serial_rx_queue = xQueueCreate( 1, sizeof( serial_ch_msg ) );
    vSemaphoreCreateBinary(serial_tx_wait_sem);
    comm_sb = xStreamBufferCreate(1000,128);

    /* Create tasks to queue a string to be written to the RS232 port. */
    xTaskCreate( sender_task, ( signed portCHAR * ) "sender", 512 /* stack size */, "TASK1", tskIDLE_PRIORITY + 10, NULL );
    xTaskCreate( reader_task, ( signed portCHAR * ) "reader", 512 /* stack size */, "TASK2", tskIDLE_PRIORITY + 10, NULL );

    /* Create a task to write messages from the queue to the RS232 port. */
    xTaskCreate(rs232_xmit_msg_task, ( signed portCHAR * ) "Serial Xmit Str", 512 /* stack size */, NULL, tskIDLE_PRIORITY + 2, NULL );

    /* Create a task to receive characters from the RS232 port and echo them back to the RS232 port. */
    xTaskCreate(serial_readwrite_task, ( signed portCHAR * ) "Serial Read/Write", 512 /* stack size */, NULL, tskIDLE_PRIORITY + 10, NULL );

    /* Start running the tasks. */
    vTaskStartScheduler();

    return 0;
}

void vApplicationTickHook( void )
{
}
