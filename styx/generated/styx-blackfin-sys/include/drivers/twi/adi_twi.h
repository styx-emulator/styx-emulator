/******************************************************************************

Copyright (c) 2005 Analog Devices.  All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.
*******************************************************************************

$File: adi_twi.c $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Project:    TWI device driver
Title:      TWI definitions


Description:
   This is the primary include file for the TWI driver..

Note:
    The Open call will select a default bit rate of 100 kHz with a 50% duty
    cycle SCL. Master and Slave modes are exclusive. Master mode transfers are
    initiated with a Sequential I/O call. Slave buffers are submitted through
    Read and Write calls; transfers are driven by the bus master.


******************************************************************************/

#ifndef __ADI_TWI_H__
#define __ADI_TWI_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

enum {
    ADI_TWI_CMD_START=ADI_TWI_ENUMERATION_START,    //  0x40110000

    ADI_TWI_CMD_SET_HARDWARE,           // select a hardware TWI port (pass ADI_INT_PERIPHERAL_ID of hardware)
    ADI_TWI_CMD_SET_PSEUDO,             // select a pseudo TWI port (pass adi_twi_pseudo struct)
    ADI_TWI_CMD_SET_RATE,               // select the frequency and duty cycle (pass adi_twi_bit_rate struct)
    ADI_TWI_CMD_SET_SLAVE_ADDR,         // set Slave address
    ADI_TWI_CMD_SET_GCALL,              // enable slave General Call receives
    ADI_TWI_CMD_SET_SCCB,               // enable SCCB compatibility
    ADI_TWI_CMD_SET_SCLOVR,             // SCL override
    ADI_TWI_CMD_SET_SDAOVR,             // SDA override
    ADI_TWI_CMD_SET_FIFO,               // set FIFO interrupt levels
    ADI_TWI_CMD_SET_LOSTARB,            // set number of retries before reporting LOSTARB
    ADI_TWI_CMD_SET_ANAK,               // set number of retries before reporting ANAK
    ADI_TWI_CMD_SET_DNAK,               // set number of retries before reporting DNAK

    ADI_TWI_CMD_GET_SENSE               // SCL & SDA sense + BUSBUSY
};


enum {
    ADI_TWI_EVENT_START=ADI_TWI_ENUMERATION_START,  // 0x40110000

    // these events are from Master mode
    // - for the two FIFO errors, consider the current setting of ADI_TWI_CMD_FIFO
    ADI_TWI_EVENT_BUFWRERR,             // failed to drain incoming FIFO
    ADI_TWI_EVENT_BUFRDERR,             // failed to keep outgoing FIFO filled
    ADI_TWI_EVENT_DNAK,                 // Data Ack error
    ADI_TWI_EVENT_ANAK,                 // Address Ack error
    ADI_TWI_EVENT_LOSTARB,              // lost bus arb. 3 times on this packet
    ADI_TWI_EVENT_YANKED,               // buffer discarded: part of an aborted RSTART chain

    // these events are from Slave mode
    ADI_TWI_EVENT_XMT_NEED,             // need a Write buffer NOW: are holding the bus
    ADI_TWI_EVENT_XMT_PROCESSED,        // a previously submitted Write buffer is returned
    ADI_TWI_EVENT_RCV_NEED,             // need a Read buffer, FIFO is filling or full
    ADI_TWI_EVENT_RCV_PROCESSED,        // a previously submitted Read buffer is returned
    // NOTE: next three can replace ADI_TWI_EVENT_RCV_PROCESSED when a RCV buffer is returned
    ADI_TWI_EVENT_SERR,                 // Read buffer is returned after an unexpected Stop
    ADI_TWI_EVENT_SOVF,                 // Two frames of inbound data may be in one Read buffer
    ADI_TWI_EVENT_GCALL                 // General Call data received
};


enum {
    ADI_TWI_RESULT_START=ADI_TWI_ENUMERATION_START, // 0x40110000

    ADI_TWI_RESULT_BAD_RATE,            // numerous causes, from ADI_TWI_CMD_RATE
    ADI_TWI_RESULT_BAD_ADDR,            // either slave or master
    ADI_TWI_RESULT_NO_DATA,             // submitted buffer has no data and is rejected
    ADI_TWI_RESULT_SLAVE_DCB,           // OK, but driver config'd Slave mode AND deferred callbacks
    ADI_TWI_RESULT_BAD_PSEUDO           // Bad pseudo port configuration
};


/* Within the ADI_DEV_SEQ_1D_BUFFER (Master mode transfers), the Buffer
struct contains the field pAdditionalInfo. This pointer field will be
treated as a u32 by the driver. The value is taken to be the address of the
I2C slave unless the value is the following define. Within the chain of
buffers, each buffer marked with this define will be sent to the slave
address of the preceeding buffer using I2C Repeated Start framing.

Note: the TWI can't perform a Repeated Start if the preceeding transfer is
longer than 254 bytes. The driver will instead service the Buffer using the
previous address in a new frame, ie. following a Stop with a Start. */

#define ADI_TWI_RSTART ((u32)0xFF00)


// entry point to TWI driver
extern ADI_DEV_PDD_ENTRY_POINT ADITWIEntryPoint;


// structure for TWI timing info
typedef struct
{
    u16  frequency;                 // The TWI bit rate per second in kHz
    u16  duty_cycle;                // The clock duty cycle (not used in pseudo mode)
} adi_twi_bit_rate;                 // submit as ADI_TWI_CMD_SET_RATE control data


// stucture for software based TWI port
typedef struct
{
    ADI_FLAG_ID scl;                // Flag that is to be used as SCL port
    ADI_FLAG_ID sda;                // Flag that is to be used as SDA port
    u32 timer;                      // Timer that is used to clock the pseudo TWI
    ADI_INT_PERIPHERAL_ID scl_pid;  // Clock interrupt id
} adi_twi_pseudo_port;              // submit as ADI_TWI_CMD_SET_PSEUDO control data


/*****************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
