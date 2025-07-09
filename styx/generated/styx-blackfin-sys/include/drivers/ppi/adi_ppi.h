/*********************************************************************************

Copyright(c) 2004 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_ppi.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            This is the include file for the PPI driver.

*********************************************************************************/

#ifndef __ADI_PPI_H__
#define __ADI_PPI_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/* integer typedefs - for all modules */
#include <services_types.h>

/*********************************************************************

Extensible enumerations and defines

*********************************************************************/


enum {                              // Command IDs
    ADI_PPI_CMD_START=ADI_PPI_ENUMERATION_START,    // 0x400c0000   insure this order remains
    ADI_PPI_CMD_SET_CONTROL_REG,                    // set the PPI control register             (Value = ADI_PPI_CONTROL_REG)
    ADI_PPI_CMD_SET_DELAY_COUNT_REG,                // set delay count                          (Value = u16)
    ADI_PPI_CMD_SET_TRANSFER_COUNT_REG,             // set transfer count                       (Value = u16)
    ADI_PPI_CMD_SET_LINES_PER_FRAME_REG,            // set lines per frame                      (Value = u16)
    ADI_PPI_CMD_SET_FS_INVERT,                      // invert frame sync polarity               (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_CLK_INVERT,                     // invert frame sync and PPI clock polarity (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_DATA_LENGTH,                    // set data length                          (Value = u16)
    ADI_PPI_CMD_SET_SKIP_EVEN_ODD,                  // skip even elements                       (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_SKIP_ENABLE,                    // control skipping                         (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_PACK_ENABLE,                    // enable packing                           (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_ACTIVE_FIELD_SELECT,            // select active fields                     (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_PORT_CFG,                       // set port configuration                   (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_TRANSFER_TYPE,                  // select transfer type                     (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_PORT_DIRECTION,                 // set port direction                       (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_TRIPLE_FRAME_SYNC,              // set triple frame syncs                   (Value = TRUE/FALSE)
    ADI_PPI_CMD_SET_TIMER_FRAME_SYNC_1,             // set timer for frame sync 1 (PPI_FS1)     (Value = ADI_PPI_FS_TMR *)
    ADI_PPI_CMD_SET_TIMER_FRAME_SYNC_2,             // set timer for frame sync 2 (PPI_FS2)     (Value = ADI_PPI_FS_TMR *)
    ADI_PPI_CMD_SET_FRAME_SYNC_CONFIGURATION        // set frame sync Port control configuration (Value = u32)
};

enum {                              // Events
    ADI_PPI_EVENT_START=ADI_PPI_ENUMERATION_START,  // 0x400c0000
    ADI_PPI_EVENT_ERROR_INTERRUPT
};


enum {                              // Return codes
    ADI_PPI_RESULT_START=ADI_PPI_ENUMERATION_START, // 0x400c0000
    ADI_PPI_RESULT_TIMER_ERROR          // error from the timer service
};

/*
** ADI_PPI_FRAME_SYNC_CFG_MODE
**  - Enumerations of PPI Frame Port Sync Control
**    for BF527 non standard Frame Sync configurations
*/
typedef enum __eADI_PPI_FRAME_SYNC_MODE_CFG
{
    /*
    */

    /* - Standard Default Enumeration Enable use of
         _ ADI_PORTS_DIRECTIVE_PPI_FS2_MUX0
         _ ADI_PORTS_DIRECTIVE_PPI_FS3 */
    ADI_PPI_FRAME_SYNC_CFG_DEFAULT = 0,
    /* - Standard Default Enumeration Enable use of
         _ ADI_PORTS_DIRECTIVE_PPI_FS2_MUX0
         _ ADI_PORTS_DIRECTIVE_PPI_FS2_MUX2 */
    ADI_PPI_FRAME_SYNC_CFG_MUX0_MUX2 = 0x00000001,
    /* - Standard Default Enumeration Enable use of
         _ ADI_PORTS_DIRECTIVE_PPI_FS2_MUX2
         _ ADI_PORTS_DIRECTIVE_PPI_FS3 */
    ADI_PPI_FRAME_SYNC_CFG_MUX2_FS3 = 0x00000002,
    /* - Standard Default Enumeration Enable use of
         _ ADI_PORTS_DIRECTIVE_PPI_FS2_MUX0
         _ ADI_PORTS_DIRECTIVE_PPI_FS2_MUX2
         _ ADI_PORTS_DIRECTIVE_PPI_FS3 */
    ADI_PPI_FRAME_SYNC_CFG_FS_ALL = 0x00000003,

    /*ALSWASYS the final value in the list */
    ADI_PPI_FRAME_SYNC_CFG_END = 0x00000004


} eADI_PPI_FRAME_SYNC_MODE_CFG;

/*********************************************************************

Data Structures

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIPPIEntryPoint;        // entry point to the device driver

#pragma pack(2)         // needed to allow these to be 16 bit entries

typedef struct {            // PPI control register
    volatile u16 port_en    :1; // port enable
    volatile u16 port_dir   :1; // port direction
    volatile u16 xfr_type   :2; // transfer type
    volatile u16 port_cfg   :2; // port configuration
    volatile u16 fld_sel    :1; // active field select
    volatile u16 pack_en    :1; // packing mode enable
    volatile u16 dma32      :1; // 32 bit DMA width enable
    volatile u16 skip_en    :1; // skip enable
    volatile u16 skip_eo    :1; // skip even odd
    volatile u16 dlen       :3; // data length
    volatile u16 polc       :1; // clock invert
    volatile u16 pols       :1; // frame sync invert
} ADI_PPI_CONTROL_REG;


typedef struct {            // PPI status register
    volatile u16            :10;// bits 0-9 reserved
    volatile u16 fld        :1; // field indicator
    volatile u16 ft_err     :1; // frame track error
    volatile u16 ovr        :1; // FIFO overflow
    volatile u16 undr       :1; // FIFO underflow
    volatile u16 err_det    :1; // error detected
    volatile u16 err_ncor   :1; // error not corrected
} ADI_PPI_STATUS_REG;


typedef struct {            // PPI Frame Sync Timer Configuration
    u32 pulse_hi;               // TRUE for pulse high, FALSE for pulse low
    u32 emu_run;                // TRUE for timer to run when emulator halted, FALSE otherwise
    u32 period;                 // number of PPI_CLK cycles per period
    u32 width;                  // number of PPI_CLK cycles per pulse width
    u32 enable_delay;           // Number of PPI CLK delays before the timer should be enabled
} ADI_PPI_FS_TMR;

#pragma pack()

/********************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif
