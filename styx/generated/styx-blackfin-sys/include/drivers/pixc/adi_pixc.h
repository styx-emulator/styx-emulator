/**********************************************************************

Copyright(c) Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software
you agree to the terms of the associated Analog Devices License Agreement.

$RCSfile: adi_pixc.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
    This is the include file for the Pixel Compositor.

***********************************************************************/

#ifndef __ADI_PIXC_H__
#define __ADI_PIXC_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*********************************************************************

Entry point to the PIXC device driver

*********************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIPIXCEntryPoint;

/*********************************************************************

Extensible enumerations and defines

*********************************************************************/

enum {                                              /* Pixel Compositor Command id's                                                                */
    ADI_PIXC_CMD_START=ADI_PIXC_ENUMERATION_START,  /* 0x40160000 - Pixel Compositor enumuration start                                              */

    /* Commands to configure Pixel compositor registers in selected color conversion mode                                                           */
    ADI_PIXC_CMD_SET_COLOR_CONVERSION_MODE,         /* Set PIXC registers in selected color conversion mode     (Value = ADI_PIXC_CONVERSION_MODE *)*/
    ADI_PIXC_CMD_ENABLE_ITUR656_SUPPORT,            /* Set PIXC registers to support color conversion of
                                                       ITU-R 656 (UYVY) type YUV422 frame to/from RGB888 frame  (Value = TRUE/FALSE, Default=FALSE) */

    /* Commands to configure Pixel compositor registers                                                                                             */
    ADI_PIXC_CMD_SET_CONTROL_REG,                   /* Set the PIXC control register                            (Value = u16)                       */
    ADI_PIXC_CMD_SET_PIXELS_PER_LINE,               /* Set Pixels Per Line register                             (Value = u16)(range:0xFFFF - 0x0001)*/
    ADI_PIXC_CMD_SET_LINES_PER_FRAME,               /* Set Lines per Frame register                             (Value = u16)(range:0xFFFF - 0x0001)*/
    ADI_PIXC_CMD_SET_OVERLAY_A_HSTART,              /* Set Overlay A Horizontal Start register                  (Value = u16)(range:0xFFF - 0x000)  */
    ADI_PIXC_CMD_SET_OVERLAY_A_HEND,                /* Set Overlay A Horizontal End register                    (Value = u16)(range:0xFFF - 0x000)  */
    ADI_PIXC_CMD_SET_OVERLAY_A_VSTART,              /* Set Overlay A Vertical Start register                    (Value = u16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_OVERLAY_A_VEND,                /* Set Overlay A Vertical End register                      (Value = u16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_OVERLAY_A_TRANSPARENCY,        /* Set Overlay A Transparency value register                (Value = u16)(range:0xF - 0x0)      */
    ADI_PIXC_CMD_SET_OVERLAY_B_HSTART,              /* Set Overlay B Horizontal Start register                  (Value = u16)(range:0xFFF - 0x000)  */
    ADI_PIXC_CMD_SET_OVERLAY_B_HEND,                /* Set Overlay B Horizontal End register                    (Value = u16)(range:0xFFF - 0x000)  */
    ADI_PIXC_CMD_SET_OVERLAY_B_VSTART,              /* Set Overlay B Vertical Start register                    (Value = u16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_OVERLAY_B_VEND,                /* Set Overlay B Vertical End register                      (Value = u16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_OVERLAY_B_TRANSPARENCY,        /* Set Overlay B Transparency value register                (Value = u16)(range:0xF - 0x0)      */
    ADI_PIXC_CMD_SET_RY_CONVERSION_COEFFICIENT,     /* Set R/Y coefficients for color space conversion matrix   (Value = s32)                       */
    ADI_PIXC_CMD_SET_GU_CONVERSION_COEFFICIENT,     /* Set G/U coefficients for color space conversion matrix   (Value = s32)                       */
    ADI_PIXC_CMD_SET_BV_CONVERSION_COEFFICIENT,     /* Set B/V coefficients for color space conversion matrix   (Value = s32)                       */
    ADI_PIXC_CMD_SET_COLOR_CONVERSION_BIAS,         /* Set color conversion bias for color conversion matrix    (Value = s32)                       */
    ADI_PIXC_CMD_SET_TRANSPARENCY_COLOR,            /* Set Transparency color value register                    (Value = u32)                       */

    /* Commands to configure individual bits/fields of Pixel compositor registers                                                                   */
    /* Commands to configure individual bits/fields of Pixel compositor control register                                                            */
    ADI_PIXC_CMD_SET_OVERLAY_A_ENABLE,              /* Set Overlay A Enable                                     (Value = TRUE/FALSE)(Default=FALSE) */
    ADI_PIXC_CMD_SET_OVERLAY_B_ENABLE,              /* Set Overlay B Enable                                     (Value = TRUE/FALSE)(Default=FALSE) */
    ADI_PIXC_CMD_SET_TRANSPARENCY_COLOR_ENABLE,     /* Set Transparency color enable                            (Value = TRUE/FALSE)(Default=FALSE) */
    /* Imperative that the following commands remain in this exact order                                                                            */
    /**** Order start ****/
    ADI_PIXC_CMD_SET_IMAGE_DATA_YUV,                /* Set Image Data format to YUV                             (Value = NULL)                      */
    ADI_PIXC_CMD_SET_OVERLAY_DATA_YUV,              /* Set Overlay Data format to YUV                           (Value = NULL)                      */
    ADI_PIXC_CMD_SET_OUTPUT_DATA_YUV,               /* Set Output Data format to YUV                            (Value = NULL)                      */
    ADI_PIXC_CMD_SET_RESAMPLE_MODE_DUPLICATE,       /* Set resampling mode to duplicate for up and downsampling (Value = NULL)                      */
    ADI_PIXC_CMD_SET_IMAGE_DATA_RGB,                /* Set Image Data format to RGB                             (Value = NULL)                      */
    ADI_PIXC_CMD_SET_OVERLAY_DATA_RGB,              /* Set Overlay Data format to RGB                           (Value = NULL)                      */
    ADI_PIXC_CMD_SET_OUTPUT_DATA_RGB,               /* Set Output Data format to RGB                            (Value = NULL)                      */
    ADI_PIXC_CMD_SET_RESAMPLE_MODE_AVERAGE,         /* Set resampling mode to average for up and downsampling   (Value = NULL)                      */
    /**** Order end ****/

    /* Commands to configure RY conversion coefficient register                                                                                     */
    /* Imperative that the following commands remain in this exact order                                                                            */
    /**** Order start ****/
    ADI_PIXC_CMD_SET_RY_CONVERSION_ELEMENT1,        /* Set RY conversion coefficient element 1  (A11)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_RY_CONVERSION_ELEMENT2,        /* Set RY conversion coefficient element 2  (A12)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_RY_CONVERSION_ELEMENT3,        /* Set RY conversion coefficient element 3  (A13)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_RY_MULTIPLY4_ENABLE,           /* Set RY multiply by 4 factor enable                       (Value = TRUE/FALSE)(Default=FALSE) */
    /**** Order end ****/

    /* Commands to configure GU conversion coefficient register                                                                                     */
    /* Imperative that the following commands remain in this exact order                                                                            */
    /**** Order start ****/
    ADI_PIXC_CMD_SET_GU_CONVERSION_ELEMENT1,        /* Set GU conversion coefficient element 1  (A21)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_GU_CONVERSION_ELEMENT2,        /* Set GU conversion coefficient element 2  (A22)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_GU_CONVERSION_ELEMENT3,        /* Set GU conversion coefficient element 3  (A23)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_GU_MULTIPLY4_ENABLE,           /* Set GU multiply by 4 factor enable                       (Value = TRUE/FALSE)(Default=FALSE) */
    /**** Order end ****/

    /* Commands to configure BV conversion coefficient register                                                                                     */
    /* Imperative that the following commands remain in this exact order                                                                            */
    /**** Order start ****/
    ADI_PIXC_CMD_SET_BV_CONVERSION_ELEMENT1,        /* Set BV conversion coefficient element 1  (A31)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_BV_CONVERSION_ELEMENT2,        /* Set BV conversion coefficient element 2  (A32)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_BV_CONVERSION_ELEMENT3,        /* Set BV conversion coefficient element 3  (A33)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_BV_MULTIPLY4_ENABLE,           /* Set BV multiply by 4 factor enable                       (Value = TRUE/FALSE)(Default=FALSE) */
    /**** Order end ****/

    /* Commands to configure color conversion bias register                                                                                         */
    /* Imperative that the following commands remain in this exact order                                                                            */
    /**** Order start ****/
    ADI_PIXC_CMD_SET_CONVERSION_BIAS_VECTOR1,       /* Set color conversion bias vector 1       (A14)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_CONVERSION_BIAS_VECTOR2,       /* Set color conversion bias vector 2       (A24)           (Value = s16)(range:0x3FF - 0x000)  */
    ADI_PIXC_CMD_SET_CONVERSION_BIAS_VECTOR3,       /* Set color conversion bias vector 3       (A34)           (Value = s16)(range:0x3FF - 0x000)  */
    /**** Order end ****/

    /* Commands to configure Transparency color value register                                                                                      */
    /* Imperative that the following commands remain in this exact order                                                                            */
    /**** Order start ****/
    ADI_PIXC_CMD_SET_TRANSPARENT_COLOR_RY,          /* Set Transparent color for RY component                   (Value = u8)(range:0xFF - 0x00)     */
    ADI_PIXC_CMD_SET_TRANSPARENT_COLOR_GU,          /* Set Transparent color for GU component                   (Value = u8)(range:0xFF - 0x00)     */
    ADI_PIXC_CMD_SET_TRANSPARENT_COLOR_BV,          /* Set Transparent color for BV component                   (Value = u8)(range:0xFF - 0x00)     */
    /**** Order end ****/

    /* Commands to Enable PIXC interrupt status report (Enable Overlay complete and Frame Complete IRQs                                             */
    ADI_PIXC_CMD_ENABLE_STATUS_REPORT,              /* Enable PIXC interrupt status report                      (Value = TRUE/FALSE)(Default=FALSE) */

    /* Commands to sense Pixel compositor register bits/fields                                                                                      */
    ADI_PIXC_CMD_GET_WATERMARK_LEVEL,               /* Get Watermark level of Pixel compositor FIFOs            (Value = u8*)                       */
    ADI_PIXC_CMD_GET_OVERLAY_FIFO_STATUS,           /* Get Overlay FIFO status                                  (Value = u8*)                       */
    ADI_PIXC_CMD_GET_IMAGE_FIFO_STATUS,             /* Get Image FIFO status                                    (Value = u8*)                       */

                                                    /* Add New PIXC Command(s) here                                                                 */

    ADI_PIXC_CMD_END                                /* End of PIXC specific Commands                                                                */
};

enum {                                                  /* Pixel Compositor Event id's                                                              */
    ADI_PIXC_EVENT_START=ADI_PIXC_ENUMERATION_START,    /* 0x40160000 - Pixel Compositor enumuration start                                          */
    ADI_PIXC_EVENT_OVERLAY_COMPLETE,                    /* 0x40160001 - Overlay interrupt occured (PIXC has completed processing an overlay frame)  */
    ADI_PIXC_EVENT_FRAME_COMPLETE                       /* 0x40160002 - Frame interrupt occured (PIXC has completed processing a whole frame)       */
};

enum {                                                  /* Pixel Compositor Result id's                                                             */
    ADI_PIXC_RESULT_START=ADI_PIXC_ENUMERATION_START,   /* 0x40160000 - Pixel Compositor enumuration start                                          */
    ADI_PIXC_RESULT_FRAME_TYPE_INVALID,                 /* 0x40160001 - Occurs when client provides invalid color conversion mode frame type(s)     */
    ADI_PIXC_RESULT_PIXEL_PER_LINE_INVALID,             /* 0x40160002 - Occurs when client provides invalid Pixel Per Line value                    */
    ADI_PIXC_RESULT_LINES_PER_FRAME_INVALID             /* 0x40160003 - Occurs when client provides invalid Lines Per Frame value                   */
};

/*********************************************************************

Data Structures specific to PIXC color conversion mode

*********************************************************************/

typedef enum {                                          /* List of frame type(s) supported by this driver                                           */
    ADI_PIXC_FRAME_YUV422,                              /* YUV422 formated frame                                                                    */
    ADI_PIXC_FRAME_RGB888,                              /* RGB888 formated frame                                                                    */
    ADI_PIXC_FRAME_YUV444,                              /* YUV444 formated frame (for special usage cases)                                          */
    ADI_PIXC_FRAME_DISABLE                              /* Disable this section of input frame (applicable only for Overlay A & B Frames)           */
} ADI_PIXC_FRAME_TYPE;

typedef struct {                                        /* Data structure to hold Frame (color) conversion information                              */
    ADI_PIXC_FRAME_TYPE     InputFrame;                 /* Input Image frame type                                                                   */
    ADI_PIXC_FRAME_TYPE     OverlayAFrame;              /* Overlay A frame type                                                                     */
    ADI_PIXC_FRAME_TYPE     OverlayBFrame;              /* Overlay B frame type                                                                     */
    ADI_PIXC_FRAME_TYPE     OutputFrame;                /* Output Image frame type                                                                  */
} ADI_PIXC_CONVERSION_MODE;

/*********************************** Supported Color conversion/Overlay modes ***********************************/
/*                                                                                                              */
/* ##       ImageFrame              OverlayAFrame               OverlayBFrame               OutputFrame         */
/*                                                                                                              */
/*  1   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_RGB888   */
/*  2   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_YUV422   */
/*  3   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_RGB888   */
/*  4   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_RGB888   */
/*  5   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_RGB888   */
/*  6   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_YUV422   */
/*  7   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_YUV422   */
/*  8   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_YUV422   */
/*  9   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_RGB888   */
/* 10   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_RGB888   */
/* 11   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_RGB888   */
/* 12   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_YUV422   */
/* 13   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422   */
/* 14   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_YUV422   */
/* 15   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422   */
/* 16   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_RGB888   */
/* 17   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_RGB888   */
/* 18   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_RGB888   */
/* 19   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_RGB888   */
/* 20   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_YUV422   */
/* 21   ADI_PIXC_FRAME_RGB888   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422   */
/* 22   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_RGB888       ADI_PIXC_FRAME_YUV422   */
/*                                                                                                              */
/*                                            Special usage cases                                               */
/*                                                                                                              */
/* 23   ADI_PIXC_FRAME_YUV444   ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_DISABLE      ADI_PIXC_FRAME_YUV422   */
/* 24   ADI_PIXC_FRAME_YUV444   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422   */
/* 25   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_YUV444       ADI_PIXC_FRAME_YUV444       ADI_PIXC_FRAME_YUV422   */
/* 26   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV444   */
/* 27   ADI_PIXC_FRAME_YUV422   ADI_PIXC_FRAME_YUV444       ADI_PIXC_FRAME_YUV444       ADI_PIXC_FRAME_YUV444   */
/* 28   ADI_PIXC_FRAME_YUV444   ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV422       ADI_PIXC_FRAME_YUV444   */
/* 29   ADI_PIXC_FRAME_YUV444   ADI_PIXC_FRAME_YUV444       ADI_PIXC_FRAME_YUV444       ADI_PIXC_FRAME_YUV444   */
/*                                                                                                              */
/****************************************************************************************************************/

/*
    Example code to set Pixel compositor conversion mode # 3

    ADI_PIXC_CONVERSION_MODE    PixcMode;               // structure to hold Pixel compositor coversion mode

    PixcMode.InputFrame     = ADI_PIXC_FRAME_YUV422;    // Input image is in YUV422 format
    PixcMode.OverlayAFrame  = ADI_PIXC_FRAME_YUV422;    // Overlay A is in YUV422 format
    PixcMode.OverlayBFrame  = ADI_PIXC_FRAME_DISABLE;   // Overlay B is not required
    PixcMode.OutputFrame    = ADI_PIXC_FRAME_RGB888;    // Output must be in RGB888 format

    adi_dev_Control(PixcHandle,ADI_PIXC_CMD_SET_COLOR_CONVERSION_MODE, (void *) &PixcMode);

*/

/********************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif      /* __ADI_PIXC_H__   */
