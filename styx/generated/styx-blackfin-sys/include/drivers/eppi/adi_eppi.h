/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_eppi.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the include file for the EPPI.

***********************************************************************/

#ifndef __ADI_EPPI_H__
#define __ADI_EPPI_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Entry point to the EPPI device driver

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIEPPIEntryPoint;

/*********************************************************************

Extensible enumerations and defines

*********************************************************************/

enum {                                              /* EPPI Command id's                                                                            */
    ADI_EPPI_CMD_START=ADI_EPPI_ENUMERATION_START,  /* 0x40170000 - EPPI enumuration start                                                          */

    /* Commands to configure EPPI registers                                                                                                         */
    ADI_EPPI_CMD_SET_CONTROL_REG,                   /* Set the EPPI control Reg  (EPPI_CONTROL) (Value = u32)                                       */
    ADI_EPPI_CMD_SET_LINES_PER_FRAME,               /* Set Lines per Frame Reg     (EPPI_FRAME) (Value = u16)(range:0xFFFF - 0x0001)                */
    ADI_EPPI_CMD_SET_SAMPLES_PER_LINE,              /* Set Samples Per Line Reg    (EPPI_LINE)  (Value = u16)(range:0xFFFF - 0x0001)                */
    ADI_EPPI_CMD_SET_VERTICAL_DELAY,                /* Set Vertical Delay Reg      (EPPI_VDELAY)(Value = u16)(range:0xFFFF - 0x0000)                */
    ADI_EPPI_CMD_SET_VERTICAL_TX_COUNT,             /* Set Vertical Transfer Count (EPPI_VCOUNT)(Value = u16)(range:0xFFFF - 0x0000)                */
    ADI_EPPI_CMD_SET_HORIZONTAL_DELAY,              /* Set Horizontal Delay Reg    (EPPI_HDELAY)(Value = u16)(range:0xFFFF - 0x0000)                */
    ADI_EPPI_CMD_SET_HORIZONTAL_TX_COUNT,           /* Set Horizontal TransferCount(EPPI_HCOUNT)(Value = u16)(range:0xFFFF - 0x0000)                */
    ADI_EPPI_CMD_SET_CLOCK_FREQ,                    /* Set EPPI Clock Frequency                 (Value = u32)(range:SCLK/2 to SCLK/0x1FFFE,in Hertz)*/
    ADI_EPPI_CMD_SET_CLOCK_DIV,                     /* Set Clock Divide Reg    (EPPI_CLKDIV)    (Value = u16)(range:0xFFFE - 0x0000)                */
    ADI_EPPI_CMD_SET_FS1_WIDTH,                     /* Set Frame Sync 1 Width  (EPPI_FS1W_HBL)  (Value = u32)(range:0xFFFFFFFF - 0x00000000)        */
    ADI_EPPI_CMD_SET_FS2_WIDTH,                     /* Set Frame Sync 2 Width  (EPPI_FS2W_LVB)  (Value = u32)(range:0xFFFFFFFF - 0x00000000)        */
    ADI_EPPI_CMD_SET_FS1_PERIOD,                    /* Set Frame Sync 1 Period (EPPI_FS1P_AVPL) (Value = u32)(range:0xFFFFFFFF - 0x00000000)        */
    ADI_EPPI_CMD_SET_FS2_PERIOD,                    /* Set Frame Sync 2 Period (EPPI_FS2P_LAVF) (Value = u32)(range:0xFFFFFFFF - 0x00000000)        */
    ADI_EPPI_CMD_SET_CLIPPING,                      /* Set Clipping Register   (EPPI_CLIP)      (Value = u32)(range:0xFFFFFFFF - 0x00000000)        */

    /* Commands to configure individual bits/fields of EPPI registers                                                                               */
    ADI_EPPI_CMD_SET_HORIZONTAL_BLANK_PER_LINE,     /* Set Horizontal Blanking Samples per Line (Value = u16)(range:0xFFFF - 0x0000)                */
    ADI_EPPI_CMD_SET_VERTICAL_BLANK_PER_LINE,       /* Set Vertical Blanking Samples per Line   (Value = u16)(range:0xFFFF - 0x0000)                */

    /****************************************** Imperative that the below Command id's remain in exact order ****************************************/
    /* Commands to configure individual bits/fields of EPPI control register                                                                        */
    ADI_EPPI_CMD_SET_PORT_DIRECTION,                /* Set EPPI Direction            (PORT_DIR) (Value = u8) (0 for input, 1 for output)            */
    ADI_EPPI_CMD_SET_TRANSFER_TYPE,                 /* Set EPPI Transfer type        (XFR_TYPE) (Value = u8) (range: 0 to 3, Default = 0)           */
    ADI_EPPI_CMD_SET_FRAME_SYNC_CONFIG,             /* Set Frame sync configuration  (FS_CFG)   (Value = u8) (range: 0 to 3, Default = 0)           */
    ADI_EPPI_CMD_SET_FIELD_SELECT_TRIGGER,          /* Set Field select/trigger      (FLD_SEL)  (Value = u8) (range: 0 or 1, Default = 0)           */
    ADI_EPPI_CMD_SET_ITU_TYPE,                      /* Set ITU Type                  (ITU_TYPE) (Value = u8, 0 for interlace, 1 for progressive)    */
    ADI_EPPI_CMD_ENABLE_BLANKGEN,                   /* Enable Blank/preamble gen     (BLANKGEN) (Value = TRUE/FALSE) (Default=FALSE)                */
    ADI_EPPI_CMD_ENABLE_INTERNAL_CLOCK_GEN,         /* Enable Internal clock gen     (ICLKGEN)  (Value = TRUE/FALSE) (Default=FALSE)                */
    ADI_EPPI_CMD_ENABLE_INTERNAL_FS_GEN,            /* Enable Internal Frame Sync gen(IFSGEN)   (Value = TRUE/FALSE) (Default=FALSE)                */
    ADI_EPPI_CMD_SET_CLOCK_POLARITY,                /* Set clock polarity            (POLC)     (Value = u8) (range: 0 to 3, Default = 0)           */
    ADI_EPPI_CMD_SET_FRAME_SYNC_POLARITY,           /* Set Frame sync polarity       (POLS)     (Value = u8) (range: 0 to 3, Default = 0)           */
    ADI_EPPI_CMD_SET_DATA_LENGTH,                   /* Set Data length               (DLEN)     (Value = u8) (range: 0 to 6, Default = 0)           */
    ADI_EPPI_CMD_SET_SKIP_ENABLE,                   /* Set Skip enable               (SKIP_EN)  (Value = TRUE/FALSE) (Default=FALSE)                */
    ADI_EPPI_CMD_SET_SKIP_EVEN_ODD,                 /* Set Skip even or odd elements (SKIP_EO)  (Value = u8) (0 to skip odd, 1 to skip even)        */
    ADI_EPPI_CMD_SET_PACK_UNPACK_ENABLE,            /* Enable DMA pack/unpack (PACKEN/UNPACKEN) (Value = TRUE/FALSE) (Default=FALSE)                */
    ADI_EPPI_CMD_SET_SWAP_ENABLE,                   /* Set Swap enable               (SWAPEN)   (Value = TRUE/FALSE) (Default=FALSE)                */
    ADI_EPPI_CMD_SET_SIGN_EXT_SPLIT16,              /* Set Sign Extension/Split 16              (Value = u8) (0 for zero fill/disable SPLIT16,
                                                           (SIGN_EXT/SPLIT_16)                                1 for sign extension/disable SPLIT16) */
    ADI_EPPI_CMD_SET_SPLIT_EVEN_ODD,                /* Set Split Even/Odd Samples(SPLT_EVEN_ODD)(Value = u8) (0 to skip Odd, 1 to skip Even)        */
    ADI_EPPI_CMD_ENABLE_SUBSPLIT_ODD,               /* Enable Sub split odd      (SUBSPLIT_ODD) (Value = TRUE/FALSE) (Default=FALSE)                */
    ADI_EPPI_CMD_SET_DMA_CHANNEL_MODE,              /* Set DMA channel mode      (DMACFG)       (Value = u8) (0 for one channel mode,
                                                                                                              1 for two channel mode)               */
    ADI_EPPI_CMD_ENABLE_RGB_FORMATTING,             /* Enable RGB Formatting     (RGB_FMT_EN)   (Value = TRUE/FALSE) (Default=FALSE)                */
    ADI_EPPI_CMD_SET_FIFO_REGULAR_WATERMARK,        /* Set FIFO Regular watermark(FIFO_RWM)     (Value = u8) (range: 0 to 3, Default = 0)           */
    ADI_EPPI_CMD_SET_FIFO_URGENT_WATERMARK,         /* Set FIFO Urgent watermark (FIFO_UWM)     (Value = u8) (range: 0 to 3, Default = 0)           */

    /* Commands to configure individual bits/fields of vertical blanking (EPPI_FS2W_LVB) register                                                   */
    ADI_EPPI_CMD_SET_FIELD1_PRE_ACTIVE_DATA_VBLANK, /* Set number of lines of vertical blanking
                                                       before Field 1 active data               (Value = u8)(range:0xFF - 0x01)                     */
    ADI_EPPI_CMD_SET_FIELD1_POST_ACTIVE_DATA_VBLANK,/* Set number of lines of vertical blanking
                                                       after Field 1 active data                (Value = u8)(range:0xFF - 0x01)                     */
    ADI_EPPI_CMD_SET_FIELD2_PRE_ACTIVE_DATA_VBLANK, /* Set number of lines of vertical blanking
                                                       before Field 2 active data               (Value = u8)(range:0xFF - 0x01)                     */
    ADI_EPPI_CMD_SET_FIELD2_POST_ACTIVE_DATA_VBLANK,/* Set number of lines of vertical blanking
                                                       after Field 2 active data                (Value = u8)(range:0xFF - 0x01)                     */

    /* Commands to configure individual bits/fields of Lines of active video per frame (EPPI_FS2P_LAVF) register                                    */
    ADI_EPPI_CMD_SET_FIELD1_ACTIVE_DATA_LINES,          /* Set Number of lines of active data in Field 1    (Value = u16)(range:0xFFFF - 0x0001)    */
    ADI_EPPI_CMD_SET_FIELD2_ACTIVE_DATA_LINES,          /* Set Number of lines of active data in Field 2    (Value = u16)(range:0xFFFF - 0x0001)    */

    /* Commands to configure individual bits/fields of clipping (EPPI_CLIP) register                                                                */
    ADI_EPPI_CMD_SET_CHROMA_LOW_CLIP_LIMIT,             /* Set Lower clipping limit for odd bytes (Chroma)  (Value = u8)(range: 0x00 - 0xFF)        */
    ADI_EPPI_CMD_SET_CHROMA_HIGH_CLIP_LIMIT,            /* Set Higher clipping limit for odd bytes (Chroma) (Value = u8)(range: 0xFF - 0x00)        */
    ADI_EPPI_CMD_SET_LUMA_LOW_CLIP_LIMIT,               /* Set Lower clipping limit for even bytes (Luma)   (Value = u8)(range: 0x00 - 0xFF)        */
    ADI_EPPI_CMD_SET_LUMA_HIGH_CLIP_LIMIT,              /* Set Higher clipping limit for even bytes (Luma)  (Value = u8)(range: 0xFF - 0x00)        */
    /****************************************** Imperative that the above Command id's remain in exact order ****************************************/

    /* Commands to sense EPPI register bits/fields                                                                                                  */
    ADI_EPPI_CMD_GET_FIELD_RECEIVED_STATUS,             /* Get Field Received status                        (Value = u8*)
                                                               (FLD bit value in EPPI_STATUS register)      (0 means Field1 received, 1 for Field2) */
    ADI_EPPI_CMD_GET_CONTROL_REG,                       /* Get EPPI control register value                  (Value = u32)                           */


                                                        /* Add New EPPI Command(s) here                                                             */

    ADI_EPPI_CMD_END                                    /* End of EPPI specific Commands                                                            */
};

enum {                                                  /* EPPI Event id's                                                                          */
    ADI_EPPI_EVENT_START=ADI_EPPI_ENUMERATION_START,    /* 0x40170000 - EPPI enumuration start                                                      */
    /* Event id's for EPPI status register errors (EPPI_STATUS)                                                                                     */
    /****************************************** Imperative that the below Event id's remain in exact order ******************************************/
    /* Following (Callback) Events occur only if EPPI Error interrupt is enabled by the client. Callback Argument for all these events point to NULL*/
    ADI_EPPI_EVENT_CHROMA_FIFO_ERROR,                   /* 0x40170001 - Chroma FIFO Overflow/Underflow Error        (CFIFO_ERR)                     */
    ADI_EPPI_EVENT_LUMA_FIFO_ERROR,                     /* 0x40170002 - Luma FIFO Overflow/Underflow Error           (YFIFO_ERR)                    */
    ADI_EPPI_EVENT_LINE_TRACK_OVERFLOW_ERROR,           /* 0x40170003 - Line Track Overflow Error                    (LTERR_OVR)                    */
    ADI_EPPI_EVENT_LINE_TRACK_UNDERFLOW_ERROR,          /* 0x40170004 - Line Track Underflow Error                   (LTERR_UNDR)                   */
    ADI_EPPI_EVENT_FRAME_TRACK_OVERFLOW_ERROR,          /* 0x40170005 - Frame Track Overflow Error                   (FTERR_OVR)                    */
    ADI_EPPI_EVENT_FRAME_TRACK_UNDERFLOW_ERROR,         /* 0x40170006 - Frame Track Underflow Error                  (FTERR_UNDR)                   */
    ADI_EPPI_EVENT_PREAMBLE_ERROR_NOT_CORRECTED,        /* 0x40170007 - Preamble Error detected but not corrected    (ERR_NCOR)                     */
    /****************************************** Imperative that the above Event id's remain in exact order ******************************************/
    ADI_EPPI_EVENT_PREAMBLE_ERROR                       /* 0x40170008 - Preamble Error detected                      (ERR_DET)                      */
};

enum {                                                  /* EPPI Result id's                                                                         */
    ADI_EPPI_RESULT_START=ADI_EPPI_ENUMERATION_START,   /* 0x40170000 - EPPI enumuration start                                                      */
    ADI_EPPI_RESULT_PORT_SHARING_ERROR,                 /* 0x40170001 - Occurs when the selected EPPI hardware port is unavailable due to
                                                                        other EPPI device(s) operating state & port usage                           */
    ADI_EPPI_RESULT_DMA_SHARING_ERROR,                  /* 0x40170002 - Occurs when the selected EPPI device is configured to use a shared/extensible
                                                                        DMA and the shareable DMA channel is already in use                         */
    ADI_EPPI_RESULT_CLOCK_DIV_INVALID,                  /* 0x40170003 - Occurs when client provides invalid Clock Divide value (EPPI_CLKDIV)        */
    ADI_EPPI_RESULT_CLOCK_FREQ_INVALID                  /* 0x40170004 - Occurs when client provides invalid EPPI clock frequency value              */
};

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif      /* __ADI_EPPI_H__   */
