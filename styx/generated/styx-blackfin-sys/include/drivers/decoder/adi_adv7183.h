/*****************************************************************************

Copyright (c) 2005 Analog Devices.  All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.
******************************************************************************

$File: adi_ad7183.h $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Project:    AD7183 video decoder device driver
Title:      AD7183 definitions
Author(s):  SS
Revised by:

Description:
   This is the primary include file for the AD7183 video decoder drivers..

References:
******************************************************************************

Modification History:
====================
Revision 1.00

*****************************************************************************/

#ifndef __ADI_AD7183_H__
#define __ADI_AD7183_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

/*****************************************************************************

Fixed enumerations and defines

*****************************************************************************/
#define NTSC_FORMAT 0
#define PAL_FORMAT  1

#define ADV7183_TWI_ADDR0       0x20    // AD7183 TWI address, when ALSB = 0
#define ADV7183_TWI_ADDR1       0x21    // AD7183 TWI address, when ALSB = 1

/********************************************
 ADV7183 Registers and register fields
**********************************************/
// Register name            Address    Dir  Reset Value
#define     ADV7183_INPUT_CTR           0x00    // RW   0x00
// register fields
#define ADV7183_VID_SEL     0x04    // input video standard selection
#define ADV7183_INSEL       0x00    // input channel & input format selection
// Register Field locations 0x11


// Register name            Address    Dir  Reset Value
#define     ADV7183_VIDEO_SELECTION             0x01    // RW   0xC8
// register fields
#define ADV7183_ENHSPLL     0x06    // disable/enable HSync processor
#define ADV7183_BETACAM     0x05    // standard video input/Betacam input enable
#define ADV7183_ENVSPROC    0x03    // disable/enable VSync processor
// Register Field locations 0xFF
//ReservedBit   0x97
//ReservedValue 0x80


// Reserved address locations       0x02    ******************************

// Register name            Address    Dir  Reset Value
#define     ADV7183_OUTPUT_CTR          0x03    // RW   0x0C
// register fields
#define ADV7183_VBI_EN      0x07    //VBI data filtering
#define ADV7183_TOD     0x06    //three state output drivers
#define ADV7183_OF_SEL      0x02    // 16bit@LLC1 / 8bit@LLC1 ITU-R BT.656
#define ADV7183_SD_DUP_AV   0x00    //Duplicate AV codes from luma into chroma path
// Register Field locations 0xFF
//ReservedBit   0x02
//ReservedValue 0x00


// Register name            Address    Dir  Reset Value
#define     ADV7183_EXTENDED_OUTPUT_CTR     0x04    // RW   0x45
// register fields
#define ADV7183_BT656_4     0x07
#define ADV7183_TIM_OE      0x03
#define ADV7183_BL_C_VBI    0x02    //
#define ADV7183_EN_SFL_PI   0x01    // SFL output
#define ADV7183_RANGE       0x00    // ITU-R BT.656/ Extended range
// Register Field locations 0xFF
//ReservedBit   0x70
//ReservedValue 0x00

// Reserved address locations       0x05    *******************************
// Reserved address locations       0x06    *******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_AUTODETECT_ENABLE           0x07    // RW   0x7F
// register fields
#define ADV7183_AD_SEC525_EN        0x07    //disable/enable
#define ADV7183_AD_SECAM_EN     0x06    //disable/enable
#define ADV7183_AD_N443_EN      0x05    //disable/enable
#define ADV7183_ADP60_EN        0x04    //disable/enable
#define ADV7183_AD_PALN_EN      0x03    //disable/enable
#define ADV7183_AD_PALM_EN      0x02    //disable/enable
#define ADV7183_AD_NTSC_EN      0x01    //disable/enable
#define ADV7183_AD_PAL_EN       0x00    //disable/enable
// Register Field locations 0xFF


// Register name            Address    Dir  Reset Value
#define     ADV7183_CONTRAST                0x08    // RW   0x80
// register fields
#define ADV7183_CON         0x00    //luma gain
// Register Field locations 0x01


// Reserved address locations       0x09    ******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_BRIGHTNESS              0x0A    // RW   0x00
// register fields
#define ADV7183_BRI         0x00    //brighness of video signal
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_HUE                 0x0B    // RW   0x00
// register fields
#define ADV7183_HUE0            0x00    //color hue adjustment
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_DEF_VALUE_Y         0x0C    // RW   0x36
// register fields
#define ADV7183_DEF_Y           0x02    //Y default value
#define ADV7183_DEF_VAL_AUTO_EN     0x01    //default value
#define ADV7183_DEF_VAL_EN      0x00    //default value enable
// Register Field locations 0x07


// Register name            Address    Dir  Reset Value
#define     ADV7183_DEF_VALUE_C         0x0D    // RW   0x7C
// register fields
#define ADV7183_DEF_C           0x00    // The Cr,Cb default value
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_ADI_CTR             0x0E    // RW   0x00
// register fields
#define ADV7183_SUB_USR_EN      0x05    //enable the user to access the interrupt map
// Register Field locations 0xFF
//ReservedBit   0xDF
//ReservedValue 0x00



// Register name            Address    Dir  Reset Value
#define     ADV7183_POWER_MGM               0x0F    // RW   0x00
// register fields
#define ADV7183_RES         0x07    //normal/start reset sequence
#define ADV7183_PWRDN           0x05    //full power down mode
#define ADV7183_PDBP            0x02    //power down bit priority
// Register Field locations 0xFF
//ReservedBit   0x5B
//ReservedValue 0x00



// Register name            Address    Dir  Reset Value
#define     ADV7183_STATUS1_RO              0x10    // R
// register fields
#define ADV7183_COL_KILL        0x07
#define ADV7183_AD_RESULT2      0x06
#define ADV7183_AD_RESULT1      0x05
#define ADV7183_AD_RESULT0      0x04
#define ADV7183_FOLLOW_PW       0x03
#define ADV7183_FSC_LOCK        0x02
#define ADV7183_LOST_LOCK       0x01
#define ADV7183_IN_LOCK         0x00
// Register Field locations 0xFF


// Register name            Address    Dir  Reset Value
#define     ADV7183_IDENT_RO            0x11    // R
// register fields
#define ADV7183_IDENT           0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_STATUS2_RO              0x12    // R
// register fields
#define ADV7183_FSCNSTD         0x05
#define ADV7183_LLNSTD          0x04
#define ADV7183_MVAGCDET        0x03
#define ADV7183_MVPSDET         0x02
#define ADV7183_MVCST3          0x01
#define ADV7183_MVCSDET         0x00
// Register Field locations 0xFF
//ReservedBit   0x80
//ReservedValue 0x00



// Register name            Address    Dir  Reset Value
#define     ADV7183_STATUS3_RO              0x13    // R
// register fields
#define ADV7183_PALSWLOCK       0x07
#define ADV7183_INTERLACE       0x06
#define ADV7183_STDFLDLEN       0x05
#define ADV7183_FREE_RUN_ACT        0x04
#define ADV7183_SD_OP_50HZ      0x02
#define ADV7183_GEMD            0x01
#define ADV7183_INST_HLOCK      0x00
// Register Field locations 0xFF
//ReservedBit   0x08
//ReservedValue 0x00



// Register name            Address    Dir  Reset Value
#define     ADV7183_ANALOG_CLAMP_CTR    0x14    // RW   0x12
// register fields
#define ADV7183_CCLEN           0x04    //current sources switch-off/enable
// Register Field locations 0xFF
//ReservedBit   0xEF
//ReservedValue 0x02



// Register name            Address    Dir  Reset Value
#define     ADV7183_DIGITAL_CLAMP_CTR1  0x15    // RW   0x40
// register fields
#define ADV7183_DCT         0x05    //digital clamp timing
// Register Field locations 0xFF
//ReservedBit   0x9F
//ReservedValue 0x00

// Reserved address locations       0x16    ******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_SHAPING_FILTER_CTR  0x17    // RW   0x01
// register fields
#define ADV7183_CSFM            0x05    //C shaping filter mode
#define ADV7183_YSFM            0x00    //select Y shaping filter mode
// Register Field locations 0x21


// Register name            Address    Dir  Reset Value
#define     ADV7183_SHAPING_FILTER_CTR2 0x18    // RW   0x93
// register fields
#define ADV7183_WYSFMOVR        0x07    //auto/manual select filter
#define ADV7183_WYSFM           0x00    //wideband Y shaping filter mode
// Register Field locations 0xFF
//ReservedBit   0x60
//ReservedValue 0x00



// Register name            Address    Dir  Reset Value
#define     ADV7183_COMB_FILTER_CTR     0x19    // RW   0xF1
// register fields
#define ADV7183_NSFSEL          0x02    //controls the signal bandwidth(NTSC)
#define ADV7183_PSFSEL          0x00    //controls the signal bandwidth(PAL)
// Register Field locations 0xFF
//ReservedBit   0xF0
//ReservedValue 0xF0

// Reserved address locations       0x1A    ******************************
// Reserved address locations       0x1B    ******************************
// Reserved address locations       0x1C    ******************************



// Register name            Address    Dir  Reset Value
#define     ADV7183_ADI_CTR2            0x1D    // RW   0x00
// register fields
#define ADV7183_TRI_LLC         0x07    //LLC pin active/three-stated
#define ADV7183_EN28XTAL        0x06    //27/28Mhz crystal
#define ADV7183_VS_JIT_COMP_EN      0x05    // enable/disable
// Register Field locations 0xFF
//ReservedBit   0x1F
//ReservedValue 0x00

// Reserved address locations       0x1E    ******************************
// Reserved address locations       0x1F    ******************************
// Reserved address locations       0x20    ******************************
// Reserved address locations       0x21    ******************************
// Reserved address locations       0x22    ******************************
// Reserved address locations       0x23    ******************************
// Reserved address locations       0x24    ******************************
// Reserved address locations       0x25    ******************************
// Reserved address locations       0x26    ******************************



// Register name            Address    Dir  Reset Value
#define     ADV7183_PIXEL_DELAY_CTR         0x27    // RW   0x58
// register fields
#define ADV7183_SWPC            0x07    //allows Cr and Cb samples to be swapped
#define ADV7183_AUTO_PDC_EN     0x06    //auto LTA/CTA value
#define ADV7183_CTA         0x03    //chroma timing adjust
#define ADV7183_LTA         0x00    //luma timing adjust
// Register Field locations 0xFF
//ReservedBit   0x02
//ReservedValue 0x00

// Reserved address locations       0x28    ******************************
// Reserved address locations       0x29    ******************************
// Reserved address locations       0x2A    ******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_MISC_GAIN_CTR       0x2B    // RW   0xE1
// register fields
#define ADV7183_CKE         0x06    //color kill enable/disable
#define ADV7183_PW_UPD          0x00    //peak white update
// Register Field locations 0xFF
//ReservedBit   0xBE
//ReservedValue 0xA0



// Register name            Address    Dir  Reset Value
#define     ADV7183_AGC_MODE_CTR        0x2C    // RW   0xAE
// register fields
#define ADV7183_LAGC            0X04    //luma automatic gain control
#define ADV7183_CAGC            0x00    //chroma automatic gain control
// Register Field locations 0xFF
//ReservedBit   0x8C
//ReservedValue 0x8C



// Register name            Address    Dir  Reset Value
#define     ADV7183_CHROMA_GAIN_CTR1        0x2D    // RW   0xF4
// register fields
#define ADV7183_CAGT            0x07    //chroma automatic gain timing
#define ADV7183_CMG8            0x00    //chroma manual gain
// Register Field locations 0xFF
//ReservedBit   0x70
//ReservedValue 0x70



// Register name            Address    Dir  Reset Value
#define     ADV7183_CHROMA_GAIN_CTR2        0x2E    // RW   0x00
// register fields
#define ADV7183_CMG0            0x00    //chroma manual gain lower 8 bits
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_LUMA_GAIN_CTR1      0x2F    // RW   0xFx
// register fields
#define ADV7183_LAGT            0x06    //luma automatic gain timing
#define ADV7183_LMG8            0x00    //luma manual gain
// Register Field locations 0xFF
//ReservedBit   0x70
//ReservedValue 0x70



// Register name            Address    Dir  Reset Value
#define     ADV7183_LUMA_GAIN_CTR2      0x30    // RW   0xxx
// register fields
#define ADV7183_LMG0            0x00    //luma manual gain lower 8 bits
// Register Field locations 0x01



// Register name            Address    Dir  Reset Value
#define     ADV7183_VSYNC_FIELD_CTR1        0x31    // RW   0x12
// register fields
#define ADV7183_NEWAVMODE       0x04    //sets the EAV/SAV mode
#define ADV7183_HVSTIM          0x03    //HSync end/begin
// Register Field locations 0xFF
//ReservedBit   0xE7
//ReservedValue 0x02



// Register name            Address    Dir  Reset Value
#define     ADV7183_VSYNC_FIELD_CTR2        0x32    // RW   0x41
// register fields
#define ADV7183_VSBHO           0x07
#define ADV7183_VSBHE           0x06
// Register Field locations 0xFF
//ReservedBit   0x3F
//ReservedValue 0x01



// Register name            Address    Dir  Reset Value
#define     ADV7183_VSYNC_FIELD_CTR3        0x33    // RW   0x84
// register fields
#define ADV7183_VSEHO           0x07
#define ADV7183_VSEHE           0x06
// Register Field locations 0xFF
//ReservedBit   0xE7
//ReservedValue 0x04


// Register name            Address    Dir  Reset Value
#define     ADV7183_HSYNC_POS_CTR1     0x34     // RW   0x00
#define ADV7183_HSB8            0x04
#define ADV7183_HSE8            0x00
// Register Field locations 0xFF
//ReservedBit   0x88
//ReservedValue 0x00


// Register name            Address    Dir  Reset Value
#define     ADV7183_HSYNC_POS_CTR2     0x35     // RW   0x02
// register fields
#define ADV7183_HSB0            0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_HSYNC_POS_CTR3     0x36     // RW   0x00
// register fields
#define ADV7183_HSE0            0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_POLARITY            0x37    // RW   0x01
// register fields
#define ADV7183_PHS         0x07    //sets the HS polarity
#define ADV7183_PVS         0x05    //sets the VS polarity
#define ADV7183_PF          0x03    //sets the FIELD polarity
#define ADV7183_PCLK            0x00    //sets the polariry of LLC1
// Register Field locations 0xFF
//ReservedBit   0x56
//ReservedValue 0x00



// Register name            Address    Dir  Reset Value
#define     ADV7183_NTSC_COMB_CTR       0x38    // RW   0x80
// register fields
#define ADV7183_CTAPSN          0x06    //chroma comb taps,NTSC
#define ADV7183_CCMN            0x03    //chroma comb mode,NTSC
#define ADV7183_YCMN            0x00    //luma comb mode,NTSC
// Register Field locations 0x49


// Register name            Address    Dir  Reset Value
#define     ADV7183_PAL_COMB_CTR        0x39    // RW   0xC0
// register fields
#define ADV7183_CTAPSP          0x06    //chroma comb taps,PAL
#define ADV7183_CCMP            0x03    //chroma comb mode,PAL
#define ADV7183_YCMP            0x00    //luma comb mode, PAL
// Register Field locations 0x49


// Register name            Address    Dir  Reset Value
#define     ADV7183_ADC_CTR             0x3A    // RW   0x10
// register fields
#define ADV7183_PWRDN_ADC0      0x03    //ADC0 normal/power-down
#define ADV7183_PWRDN_ADC1      0x02    //ADC1 normal/power-down
#define ADV7183_PWRDN_ADC2      0x01    //ADC2 normal/power-down
// Register Field locations 0xFF
//ReservedBit   0xF1
//ReservedValue 0x10

// Reserved address locations       0x3B    ******************************
// Reserved address locations       0x3C    ******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_MANUAL_WINDOW_CTR       0x3D    // RW   0x43
// register fields
#define ADV7183_CKILLTHR        0x04    //color kill
// Register Field locations 0xFF
//ReservedBit   0x8F
//ReservedValue 0x03


// Reserved address locations       0x3E    ******************************
// Reserved address locations       0x3F    ******************************
// Reserved address locations       0x40    ******************************

// Register name            Address    Dir  Reset Value
#define     ADV7183_RESAMPLE_CTR        0x41    // RW   0x41
// register fields
#define ADV7183_SFL_INV         0x06    //SFL compatibility
// Register Field locations 0xFF
//ReservedBit   0xBF
//ReservedValue 0x10


// Reserved address locations       0x42    ******************************
// Reserved address locations       0x43    ******************************
// Reserved address locations       0x44    ******************************
// Reserved address locations       0x45    ******************************
// Reserved address locations       0x46    ******************************
// Reserved address locations       0x47    ******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_GEMSTAR_CTR1            0x48    // RW   0x00
// register fields
#define ADV7183_CDECEL8         0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_GEMSTAR_CTR2            0x49    // RW   0x00
// register fields
#define ADV7183_CDECEL0         0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_GEMSTAR_CTR3            0x4A    // RW   0x00
// register fields
#define ADV7183_CDECOL8         0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_GEMSTAR_CTR4            0x4B    // RW   0x00
// register fields
#define ADV7183_CDECOL0         0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_GEMSTAR_CTR5            0x4C    // RW   0x00
// register fields
#define ADV7183_CDECAD          0x00
// Register Field locations 0xFF
//ReservedBit   0xFE
//ReservedValue 0x00


// Register name            Address    Dir  Reset Value
#define     ADV7183_CTIDNR_CTR1             0x4D    // RW   0xEF
// register fields
#define ADV7183_DNR_EN          0x05    //bypass/enable the DNR block
#define ADV7183_CTI_AB          0x02    //controls the behavior of the alpha-blend circultry
#define ADV7183_CTI_AB_EN       0x01    //disable/enable CTI alpha blender
#define ADV7183_CTI_EN          0x00    //CTI disable/enable
// Register Field locations 0xFF
//ReservedBit   0xD0
//ReservedValue 0xC0


// Register name            Address    Dir  Reset Value
#define     ADV7183_CTIDNR_CTR2             0x4E    // RW   0x08
// register fields
#define ADV7183_CTI_TH          0x00
// Register Field locations 0x01


// Reserved address locations       0x4F    ******************************



// Register name            Address    Dir  Reset Value
#define     ADV7183_CTIDNR_CTR4             0x50    // RW   0x08
// register fields
#define ADV7183_DNR_TH          0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_LOCK_COUNT          0x51    // RW   0x24
// register fields
#define ADV7183_FSCLE           0x07    //Fsc lock enable
#define ADV7183_SRLS            0x06    //select raw lock signal
#define ADV7183_COL         0x03    //count out of lock
#define ADV7183_CIL         0x00    //count into lock
// Register Field locations 0xC9


// Reserved address locations       0x52 to 0x8E    ******************************




// Register name            Address    Dir  Reset Value
#define     ADV7183_FREERUN_LINE_LENGTH1        0x8F    // W    0x00
// register fields
#define ADV7183_LLC_PAD_SEL     0x04
// Register Field locations 0xFF
//ReservedBit   0x8F
//ReservedValue 0x00



// Register name            Address    Dir  Reset Value
#define     ADV7183_VBI_INFO_RO             0x90    // R
// register fields
#define ADV7183_CGMSD           0x03    //CGMS
#define ADV7183_EDTVD           0x02    //EDTV sequence no detect/detect
#define ADV7183_CCAPD           0x01    //CCAP no detect/detect
#define ADV7183_WSSD            0x00    //WSS no detect/detect
// Register Field locations 0xFF
//ReservedBit   0xF0
//ReservedValue 0x00



// Register name            Address    Dir  Reset Value
#define     ADV7183_WSS1_RO             0x91    // R
// register fields
#define ADV7183_WSS1            0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_WSS2_RO             0x92    // R
// register fields
#define ADV7183_WSS2            0x00
// Register Field locations 0x01



// Register name            Address    Dir  Reset Value
#define     ADV7183_EDTV1_RO            0x93    // R
// register fields
#define ADV7183_EDTV1           0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_EDTV2_RO            0x94    // R
// register fields
#define ADV7183_EDTV2           0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_EDTV3_RO            0x95    // R
// register fields
#define ADV7183_EDTV3           0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_CGMS1_RO            0x96    // R
// register fields
#define ADV7183_CGMS1           0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_CGMS2_RO            0x97    // R
// register fields
#define ADV7183_CGMS2           0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_CGMS3_RO            0x98    // R
// register fields
#define ADV7183_CGMS3           0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_CCAP1_RO            0x99    // R
// register fields
#define ADV7183_CCAP1           0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_CCAP2_RO            0x9A    // R
// register fields
#define ADV7183_CCAP2           0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_LETTERBOX1_RO       0x9B    // R
// register fields
#define ADV7183_LB_LCT          0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_LETTERBOX2_RO       0x9C    // R
// register fields
#define ADV7183_LB_LCM          0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_LETTERBOX3_RO       0x9D    // R
// register fields
#define ADV7183_LB_LCB          0x00
// Register Field locations 0x01


// Reserved address locations       0x9E to 0xB1    ******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_CRC_ENABLE_WR           0xB2    // RW   0x1C
// register fields
#define ADV7183_CRC_ENABLE      0x02    //enable CRC checksum
// Register Field locations 0xFF
//ReservedBit   0xFB
//ReservedValue 0x18

// Reserved address locations       0xB3 to 0xC2    ******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_ADC_SWITCH1         0xC3    // RW   0xx
// register fields
#define ADV7183_ADC1_SW         0x04    //manual muxing control for ADC1
#define ADV7183_ADCO_SW         0x00    //manual muxing control for ADC0
// Register Field locations 0x11



// Register name            Address    Dir  Reset Value
#define     ADV7183_ADC_SWITCH2         0xC4    // RW   0x0x
// register fields
#define ADV7183_ADC_SW_MAN      0x07    //disable/enable manual setting of the input signal muxing
#define ADV7183_ADC2_SW         0x00    //manual muxing control fot ADC2
// Register Field locations 0xFF
//ReservedBit   0x70
//ReservedValue 0x00

// Reserved address locations       0xC5 to 0xDB    ******************************



// Register name            Address    Dir  Reset Value
#define     ADV7183_LETTERBOX_CTR1      0xDC    // RW   0xAC
// register fields
#define ADV7183_LB_TH           0x00    //sets the threshold value fot detection of black line
// Register Field locations 0xFF
//ReservedBit   0xE0
//ReservedValue 0xA0


// Register name            Address    Dir  Reset Value
#define     ADV7183_LETTERBOX_CTR2      0xDD    // RW   0x4C
// register fields
#define ADV7183_LB_SL           0x04    //
#define ADV7183_LB_EL           0x00
// Register Field locations 0x11


// Reserved address locations       0xDE    ******************************
// Reserved address locations       0xDF    ******************************
// Reserved address locations       0xE0    ******************************



// Register name            Address    Dir  Reset Value
#define     ADV7183_SD_OFFSET_CB        0xE1    // RW   0x80
// register fields
#define ADV7183_SD_OFF_CB       0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_SD_OFFSET_CR        0xE2    // RW   0x80
// register fields
#define ADV7183_SD_OFF_CR       0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_SD_SATURATION_CB        0xE3    // RW   0x80
// register fields
#define ADV7183_SD_SAT_CB       0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_SD_SATURATION_CR        0xE4    // RW   0x80
// register fields
#define ADV7183_SD_SAT_CR       0x00
// Register Field locations 0x01


// Register name            Address    Dir  Reset Value
#define     ADV7183_NTSC_VBIT_BEGIN         0xE5    // RW   0x25
// register fields
#define ADV7183_NVBEGDELO       0x07
#define ADV7183_NVBEGDELE       0x06
#define ADV7183_NVBEGSIGN       0x05
#define ADV7183_NVBEG           0x00
// Register Field locations 0xE1



// Register name            Address    Dir  Reset Value
#define     ADV7183_NTSC_VBIT_END       0xE6    // RW   0x04
// register fields
#define ADV7183_NVENDDELO       0x07
#define ADV7183_NVENDDELE       0x06
#define ADV7183_NVENDSIGN       0x05
#define ADV7183_NVEND           0x00
// Register Field locations 0xE1

// Register name            Address    Dir  Reset Value
#define     ADV7183_NTSC_FBIT_TOGGLE        0xE7    // RW   0x63
// register fields
#define ADV7183_NFTOGDELO       0x07
#define ADV7183_NFTOGDELE       0x06
#define ADV7183_NFTOGSIGN       0x05
#define ADV7183_NFTOG           0x00
// Register Field locations 0xE1

// Register name            Address    Dir  Reset Value
#define     ADV7183_PAL_VBIT_BEGIN          0xE8    // RW   0x65
// register fields
#define ADV7183_PVBEGDELO       0x07
#define ADV7183_PVBEGDELE       0x06
#define ADV7183_PVBEGSIGN       0x05
#define ADV7183_PVBEG           0x00
// Register Field locations 0xE1


// Register name            Address    Dir  Reset Value
#define     ADV7183_PAL_VBIT_END        0xE9    // RW   0x14
// register fields
#define ADV7183_PVENDDELO       0x07
#define ADV7183_PVENDDELE       0x06
#define ADV7183_PVENDSIGN       0x05
#define ADV7183_PVEND           0x00
// Register Field locations 0xE1



// Register name            Address    Dir  Reset Value
#define     ADV7183_PAL_FBIT_TOGGLE         0xEA    // RW   0x63
// register fields
#define ADV7183_PFTOGDELO       0x07
#define ADV7183_PFTOGDELE       0x06
#define ADV7183_PFTOGSIGN       0x05
#define ADV7183_PFTOG           0x00
// Register Field locations 0xE1


// Reserved address locations       0xEB to 0xF3    ******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_DRIVE_STRENGTH          0xF4    // RW   0x15
// register fields
#define ADV7183_DR_STR          0x04
#define ADV7183_DR_STR_C        0x02
#define ADV7183_DR_STR_S        0x00
// Register Field locations 0xFF
//ReservedBit   0xC0
//ReservedValue 0x00


// Reserved address locations       0xF5 to 0xF7    ******************************


// Register name            Address    Dir  Reset Value
#define     ADV7183_IF_COMP_CTR         0xF8    // RW   0x00
// register fields
#define ADV7183_IFFILTSEL       0x00
// Register Field locations 0xFF
//ReservedBit   0xF8
//ReservedValue 0x00


// Register name            Address    Dir  Reset Value
#define     ADV7183_VS_MODE_CTR         0xF9    // RW   0x00
// register fields
#define ADV7183_VS_COAST_MODE       0x02
#define ADV7183_EXTEND_VS_MIN_FREQ  0x01
#define ADV7183_EXTEND_VS_MAX_FREQ  0x00
// Register Field locations 0xFF
//ReservedBit   0xF0
//ReservedValue 0x00



/****************** Page 2 registers  ************************************/
// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_CONFIG0             0x140   // RW
// register fields
#define ADV7183_INTRQ_DUR_SEL       0x06    //interrupt duration select
#define ADV7183_MV_INTRQ_SEL        0x04    //Microvision interrupt select
#define ADV7183_MPU_STIM_INTRQ      0x02    //manual interrupt set mode
#define ADV7183_INTRO_OP_SEL        0x00    //interrupt drive level select
// Register Field locations 0xFF
//ReservedBit   0x08
//ReservedValue 0x00

// Reserved address locations       0x141 ******************************





// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_STATUS1         0x142   // R
// register fields
#define ADV7183_MV_PS_CS_Q      0x06
#define ADV7183_SD_FR_CHNG_Q        0x05
#define ADV7183_SD_UNLOCK_Q     0x01
#define ADV7183_SD_LOCK_Q       0x00
// Register Field locations 0xFF
//ReservedBit   0x9C
//ReservedValue 0x00



// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_CLEAR1      0x143   // W
// register fields
#define ADV7183_MV_PS_CS_CLR        0x06
#define ADV7183_SD_FR_CHNG_CLR      0x05
#define ADV7183_SD_UNLOCK_CLR       0x01
#define ADV7183_SD_LOCK_CLR     0x00
// Register Field locations 0xFF
//ReservedBit   0x9C
//ReservedValue 0x00



// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_MASK1       0x144   // RW
// register fields
#define ADV7183_MV_PS_CS_MSKB       0x06
#define ADV7183_SD_FR_CHNG_MSKB     0x05
#define ADV7183_SD_UNLOCK_MSKB      0x01
#define ADV7183_SD_LOCK_MSKB        0x00
// Register Field locations 0xFF
//ReservedBit   0x9C
//ReservedValue 0x00


// Reserved address locations       0x145   ******************************


// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_STATUS2         0x146   // R
// register fields
#define ADV7183_MPU_STIM_INTRQ_Q    0x07
#define ADV7183_WSS_CHNGD_Q     0x03
#define ADV7183_CGMS_CHNGD_Q        0x02
#define ADV7183_CEMD_Q          0x01
#define ADV7183_CCAPD_Q         0x00
// Register Field locations 0xFF
//ReservedBit   0x70
//ReservedValue 0x00


// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_CLEAR2      0x147   // W
// register fields
#define ADV7183_MPU_STIM_INTRQ_CLR  0x07
#define ADV7183_WSS_CHNGD_CLR       0x03
#define ADV7183_CGMS_CHNGD_CLR      0x02
#define ADV7183_CEMD_CLR        0x01
#define ADV7183_CCAPD_CLR       0x00
// Register Field locations 0xFF
//ReservedBit   0x70
//ReservedValue 0x00



// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_MASK2       0x148   // RW
// register fields
#define ADV7183_MPU_STIM_INTRQ_MSKB 0x07
#define ADV7183_WSS_CHNGD_MSKB      0x03
#define ADV7183_CGMS_CHNGD_MSKB     0x02
#define ADV7183_CEMD_MSKB       0x01
#define ADV7183_CCAPD_MSKB      0x00
// Register Field locations 0xFF
//ReservedBit   0x70
//ReservedValue 0x00



// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_RAW_STATUS3         0x149   // R
// register fields
#define ADV7183_SCM_LOCK        0x04
#define ADV7183_SD_H_LOCK       0x02
#define ADV7183_SD_V_LOCK       0x01
#define ADV7183_SD_OP_50HZ_RS   0x00
// Register Field locations 0xFF
//ReservedBit   0xE8
//ReservedValue 0x00



// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_STATUS3         0x14A   // R
// register fields
#define ADV7183_PAL_SW_LK_CHNG_Q    0x05
#define ADV7183_SCM_LOCK_CHNG_Q     0x04
#define ADV7183_SD_AD_CHNG_Q        0x03
#define ADV7183_SD_H_LOCK_CHNG_Q    0x02
#define ADV7183_SD_V_LOCK_CHNG_Q    0x01
#define ADV7183_SD_OP_CHNG_Q        0x00
// Register Field locations 0xFF
//ReservedBit   0xC0
//ReservedValue 0x00

// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_CLEAR3      0x14B   // W
// register fields
#define ADV7183_PAL_SW_LK_CHNG_CLR  0x05
#define ADV7183_SCM_LOCK_CHNG_CLR   0x04
#define ADV7183_SD_AD_CHNG_CLR      0x03
#define ADV7183_SD_H_LOCK_CHNG_CLR  0x02
#define ADV7183_SD_V_LOCK_CHNG_CLR  0x01
#define ADV7183_SD_OP_CHNG_CLR      0x00
// Register Field locations 0xFF
//ReservedBit   0xC0
//ReservedValue 0x00


// Interrupt Register name(page2)   Address    Dir
#define     ADV7183_INT_MASK3       0x14C   // RW
// register fields
#define ADV7183_PAL_SW_LK_CHNG_MSKB 0x05
#define ADV7183_SCM_LOCK_CHNG_MSKB  0x04
#define ADV7183_SD_AD_CHNG_MSKB     0x03
#define ADV7183_SD_H_LOCK_CHNG_MSKB 0x02
#define ADV7183_SD_V_LOCK_CHNG_MSKB 0x01
#define ADV7183_SD_OP_CHNG_MSKB     0x00
// Register Field locations 0xFF
//ReservedBit   0xC0
//ReservedValue 0x00

/****************** End of Page 2 registers  ************************************/


#define ADV7183REGADDR00_3F \
                ADV7183_INPUT_CTR, ADV7183_VIDEO_SELECTION, ADV7183_OUTPUT_CTR, \
                ADV7183_EXTENDED_OUTPUT_CTR, ADV7183_AUTODETECT_ENABLE, ADV7183_CONTRAST, \
                ADV7183_BRIGHTNESS, ADV7183_HUE, ADV7183_DEF_VALUE_Y, ADV7183_DEF_VALUE_C, \
                ADV7183_ADI_CTR, ADV7183_POWER_MGM, ADV7183_STATUS1_RO, ADV7183_IDENT_RO,ADV7183_STATUS2_RO,\
                ADV7183_STATUS3_RO, ADV7183_ANALOG_CLAMP_CTR, ADV7183_DIGITAL_CLAMP_CTR1, \
                ADV7183_SHAPING_FILTER_CTR, ADV7183_SHAPING_FILTER_CTR2,\
                ADV7183_COMB_FILTER_CTR, ADV7183_ADI_CTR2, ADV7183_PIXEL_DELAY_CTR,\
                ADV7183_MISC_GAIN_CTR, ADV7183_AGC_MODE_CTR, ADV7183_CHROMA_GAIN_CTR1,\
                ADV7183_CHROMA_GAIN_CTR2, ADV7183_LUMA_GAIN_CTR1, ADV7183_LUMA_GAIN_CTR2,\
                ADV7183_VSYNC_FIELD_CTR1, ADV7183_VSYNC_FIELD_CTR2, ADV7183_VSYNC_FIELD_CTR3,\
                ADV7183_HSYNC_POS_CTR1, ADV7183_HSYNC_POS_CTR2,ADV7183_HSYNC_POS_CTR3,\
                ADV7183_POLARITY, ADV7183_NTSC_COMB_CTR, ADV7183_PAL_COMB_CTR, ADV7183_ADC_CTR,\
                ADV7183_MANUAL_WINDOW_CTR
/*********************************************************************

Global Registers
ADV7183 has 2 pages of registers, to access to page 2 registers,
register address 0x0E must be programmed to 01b
*********************************************************************/

#define ADV7183REGFIELD00_3F    0x11, 0xFF, 0xFF, 0xFF, 0xFF, \
                0x01, 0x01, 0x01, 0x07, 0x01, \
                0xFF, 0xFF, 0xFF, 0x01, 0xFF, \
                0xFF, 0xFF, 0xFF, 0x21, 0xFF, \
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, \
                0xFF, 0x01, 0xFF, 0x01, 0xFF, \
                0xFF, 0xFF, 0xFF, 0x01, 0x01, \
                0xFF, 0x49, 0x49, 0xFF, 0xFF


// ADV7183 Register address 0x00 to 0x3F containing Reserved Locations
#define ADV7183REGRESVADDR00_3F     ADV7183_VIDEO_SELECTION, ADV7183_OUTPUT_CTR, ADV7183_EXTENDED_OUTPUT_CTR, ADV7183_ADI_CTR,\
                    ADV7183_POWER_MGM,ADV7183_STATUS2_RO, ADV7183_STATUS3_RO, ADV7183_ANALOG_CLAMP_CTR, \
                    ADV7183_DIGITAL_CLAMP_CTR1, ADV7183_SHAPING_FILTER_CTR2,ADV7183_COMB_FILTER_CTR, \
                    ADV7183_ADI_CTR2, ADV7183_PIXEL_DELAY_CTR, ADV7183_MISC_GAIN_CTR, ADV7183_AGC_MODE_CTR, \
                    ADV7183_CHROMA_GAIN_CTR1, ADV7183_LUMA_GAIN_CTR1, ADV7183_VSYNC_FIELD_CTR1, ADV7183_VSYNC_FIELD_CTR2, \
                    ADV7183_VSYNC_FIELD_CTR3, ADV7183_HSYNC_POS_CTR1, ADV7183_POLARITY, ADV7183_ADC_CTR, \
                    ADV7183_MANUAL_WINDOW_CTR


// ADV71831 register Reserved Bit locations address 0x00 to 0x3F
#define ADV7183RESERVEDBITS00_3F    0x97, 0x02, 0x70, 0xDF, 0x5B,\
                    0x80, 0x08, 0xEF, 0x9F, 0x60,\
                    0xF0, 0x1F, 0x02, 0xBE, 0x8C,\
                    0x70, 0x70, 0xE7, 0x3F, 0xE7,\
                    0x88, 0x56, 0xF1, 0x8F


// Recommended values for the Reserved Bit locations address 0x00 to 0x3F
#define ADV7183RESERVEDVALUES00_3F  0x80, 0x00, 0x00, 0x00, 0x00,\
                    0x00, 0x00, 0x02, 0x00, 0x00,\
                    0x00, 0x00, 0x00, 0xA0, 0x8C,\
                    0x70, 0x70, 0x02, 0x01, 0x04,\
                    0x00, 0x00, 0x10, 0x03


// array of read-only registers address 0x00 to 0x3F.
#define ADV7183READONLYREGS00_3F    ADV7183_STATUS1_RO,ADV7183_IDENT_RO,ADV7183_STATUS2_RO,ADV7183_STATUS3_RO


// array of invalid registers address 0x00 to 0x3F.
#define ADV7183INVALIDREGS00_3F     0x02, 0x05, 0x06, 0x09, 0x16, 0x1A, 0x1B, \
                    0x1C, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, \
                    0x25, 0x26, 0x28, 0x29, 0x2A, 0x3B, 0x3C, 0x3E, 0x3F





#define ADV7183REGADDR4D_F9     ADV7183_CTIDNR_CTR1, ADV7183_CTIDNR_CTR2, ADV7183_CTIDNR_CTR4, ADV7183_LOCK_COUNT,\
                ADV7183_FREERUN_LINE_LENGTH1, ADV7183_VBI_INFO_RO, ADV7183_WSS1_RO, ADV7183_WSS2_RO, \
                ADV7183_EDTV1_RO, ADV7183_EDTV2_RO, ADV7183_EDTV3_RO, ADV7183_CGMS1_RO, \
                ADV7183_CGMS2_RO, ADV7183_CGMS3_RO, ADV7183_CCAP1_RO, ADV7183_CCAP2_RO, \
                ADV7183_LETTERBOX1_RO, ADV7183_LETTERBOX2_RO, ADV7183_LETTERBOX3_RO, ADV7183_CRC_ENABLE_WR, \
                ADV7183_ADC_SWITCH1, ADV7183_ADC_SWITCH2, ADV7183_LETTERBOX_CTR1, ADV7183_LETTERBOX_CTR2, \
                ADV7183_SD_OFFSET_CB, ADV7183_SD_OFFSET_CR, ADV7183_SD_SATURATION_CB, ADV7183_SD_SATURATION_CR, \
                ADV7183_NTSC_VBIT_BEGIN, ADV7183_NTSC_VBIT_END, ADV7183_NTSC_FBIT_TOGGLE, ADV7183_PAL_VBIT_BEGIN, \
                ADV7183_PAL_VBIT_END, ADV7183_PAL_FBIT_TOGGLE, ADV7183_DRIVE_STRENGTH, ADV7183_IF_COMP_CTR, \
                ADV7183_VS_MODE_CTR


#define  ADV7183REGFIELD4D_F9   0xF7, 0x01, 0x01, 0xC9, \
                0x9F, 0xFF, 0x01, 0x01, \
                0x01, 0x01, 0x01, 0x01, \
                0x01, 0x01, 0x01, 0x01, \
                0x01, 0x01, 0x01, 0xFF, \
                0x11, 0xF1, 0xE1, 0x11, \
                0x01, 0x01, 0x01, 0x01, \
                0xE1, 0xE1, 0xE1, 0xE1, \
                0xE1, 0xE1, 0xD5, 0xF1, \
                0xF7


// ADV7183 Register address 0x4D to 0xF9 containing Reserved Locations
#define  ADV7183REGRESVADDR4D_F9    ADV7183_CTIDNR_CTR1, ADV7183_FREERUN_LINE_LENGTH1, ADV7183_VBI_INFO_RO, \
                    ADV7183_CRC_ENABLE_WR,  ADV7183_ADC_SWITCH2, ADV7183_LETTERBOX_CTR1, \
                    ADV7183_DRIVE_STRENGTH, ADV7183_IF_COMP_CTR, ADV7183_VS_MODE_CTR

// ADV71831 register Reserved Bit locations address 0x4D to 0xF9
#define ADV7183RESERVEDBITS4D_F9    0xD0, 0x8F, 0xF0, 0xFB, 0x70,\
                    0xE0, 0xC0, 0xF8, 0xF0


// Recommended values for the Reserved Bit locations address 0x4D to 0xF9
#define ADV7183RESERVEDVALUES4D_F9  0xC0, 0x00, 0x00, 0x18, 0x00,\
                    0xA0, 0x00, 0x00, 0x00


// array of read-only registers address 0x4D to 0xF9.
#define ADV7183READONLYREGS4D_F9    ADV7183_VBI_INFO_RO, ADV7183_WSS1_RO, ADV7183_WSS2_RO, ADV7183_EDTV1_RO, ADV7183_EDTV2_RO,\
                    ADV7183_EDTV3_RO, ADV7183_CGMS1_RO, ADV7183_CGMS2_RO, ADV7183_CGMS3_RO, ADV7183_CCAP1_RO,\
                    ADV7183_CCAP2_RO, ADV7183_LETTERBOX1_RO, ADV7183_LETTERBOX2_RO, ADV7183_LETTERBOX3_RO


// array of invalid registers address 0x4D to 0xF9.
#define  ADV7183INVALIDREGS4D_F9    0x4F, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64,\
                    0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,\
                    0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,\
                    0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82,\
                    0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C,\
                    0x8D, 0x8E, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,\
                    0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,\
                    0xB0, 0xB1, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA,\
                    0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC5, 0xC6,\
                    0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,\
                    0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,\
                    0xDB, 0xDE, 0xDF, 0xE0, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,\
                    0xF1, 0xF2, 0xF3, 0xF5, 0xF6, 0xF7



/*****************************************************************************

Extensible enumerations and defines

*****************************************************************************/

enum    {                                               // Command IDs

        ADI_AD7183_CMD_START=ADI_ADV7183_ENUMERATION_START, // 0x40090000

        // PPI/EPPI Configuration
        ADI_AD7183_CMD_OPEN_PPI,                    // Set PPI Device Number that will be opened
        ADI_AD7183_CMD_SET_VIDEO_FORMAT,            // Set PPI control register to RX,ITU-R656 Number of lines to 625(PALor 525(NTSC)

        // PPI related commands (Commands applicable only for PPI based devices)
        ADI_AD7183_CMD_SET_ACTIVE_VIDEO,            // set PPI control register to receive active field only
        ADI_AD7183_CMD_SET_VERTICAL_BLANKING,       // set PPI control register to receive vertical blanking only
                                                    /* For EPPI driven devices, client must use EPPI driver commands to configure EPPI
                                                       for required input mode (Active filed only, VBI only, etc., */
        // TWI Configuration
        ADI_AD7183_CMD_SET_TWI_DEVICE,              // Set TWI Device Number that will be used to access AD7183 registers (Value = u32)
        ADI_AD7183_CMD_SET_TWI_CONFIG_TABLE,        // Set TWI Configuration table specific to the application (Value = ADI_DEV_CMD_VALUE_PAIR)
        ADI_AD7183_CMD_SET_TWI_ADDRESS              // Set TWI address for the AD7183 device (Value = u32)

        };

enum    {              // Events
        ADI_AD7183_EVENT_START=ADI_ADV7183_ENUMERATION_START    // 0x40090000
        };

enum    {        // Return codes
        ADI_AD7183_RESULT_START=ADI_ADV7183_ENUMERATION_START,  // 0x40090000
        ADI_AD7183_RESULT_CMD_NOT_SUPPORTED,   // Write or Sequential I/O command not supported
        ADI_AD7183_RESULT_PPI_NOT_OPENED,       // Set DataFlow or DataFlow-Method when PPI is not opened
        ADI_AD7183_RESULT_BAD_VIDEO_FORMAT      // Set wrong video format, only 0(NTSC) or 1(PAL) is valid
        };

/*****************************************************************************

Data Structures

*****************************************************************************/

extern ADI_DEV_PDD_ENTRY_POINT ADIADV7183EntryPoint;  // entry point to AD7183 device driver

/*****************************************************************************/

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif /* __ADI_AD7183_H__ */
