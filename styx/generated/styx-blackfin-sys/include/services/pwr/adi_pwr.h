/*********************************************************************************

Copyright(c) 2010 Analog Devices, Inc. All Rights Reserved.

This software is proprietary and confidential.  By using this software you agree
to the terms of the associated Analog Devices License Agreement.


$RCSfile: adi_pwr.h,v $
$Revision: 3492 $
$Date: 2010-10-07 09:34:20 -0400 (Thu, 07 Oct 2010) $

Description:
            Dynamic Power Management Header File

*********************************************************************************/

#ifndef __ADI_PWR_H__
#define __ADI_PWR_H__

/* disable misra diagnostics as necessary */
#ifdef _MISRA_RULES
#pragma diag(push)
#include <services/services_misra_suppress.h>
#endif /* _MISRA_RULES */

#include <services/services.h>

#if !defined(_LANGUAGE_ASM)


/*********************************************************************************
* Result codes
*********************************************************************************/
typedef enum ADI_PWR_RESULT {
    ADI_PWR_RESULT_SUCCESS,                                    // Successful completion
    ADI_PWR_RESULT_FAILED,                                    // Generic Failure

    ADI_PWR_RESULT_START=ADI_PWR_ENUMERATION_START,

    ADI_PWR_RESULT_NO_MEMORY,                   // Insufficient memory to perform the operation
    ADI_PWR_RESULT_BAD_COMMAND,                 // The command in not recognized or the value is incorrect
    ADI_PWR_RESULT_NOT_INITIALIZED,                // power service has not been initialized
    ADI_PWR_RESULT_INVALID_CSEL,                // An Invalid CSEL value has been supplied
    ADI_PWR_RESULT_INVALID_SSEL,                // An Invalid SSEL value has been supplied
    ADI_PWR_RESULT_INVALID_CSEL_SSEL_COMBINATION,    // An Invalid SSEL/CSEL combination has been supplied
    ADI_PWR_RESULT_INVALID_VLEV,                // An Invalid internal voltage level
    ADI_PWR_RESULT_INVALID_VDDEXT,                // An Invalid external voltage level
    ADI_PWR_RESULT_INVALID_VR_FREQ,             // An invalid switching frequency value

#if !defined(__ADSP_KOOKABURRA__) && !defined(__ADSP_MOCKINGBIRD__) && !defined(__ADSP_BRODIE__)
    ADI_PWR_RESULT_INVALID_VR_GAIN,             // An invalid Voltage regulator GAIN value
#endif
    ADI_PWR_RESULT_INVALID_VR_WAKE,             // An invalid Voltage regulator WAKE value
    ADI_PWR_RESULT_INVALID_MODE,                // An invalid operating mode has been specified
    ADI_PWR_RESULT_INVALID_PROCESSOR,            // The processor type specified is invalid
    ADI_PWR_RESULT_INVALID_IVG,                 // The IVG level supplied is invalid
    ADI_PWR_RESULT_INVALID_INPUT_DELAY,            // The input delay value is invalid
    ADI_PWR_RESULT_INVALID_OUTPUT_DELAY,        // The output delay value is invalid
    ADI_PWR_RESULT_INVALID_LOCKCNT,             // The PLL lock count value is invalid
    ADI_PWR_RESULT_VOLTAGE_REGULATOR_BYPASSED,  // The onboard VR is bypassed
    ADI_PWR_RESULT_INVALID_EZKIT,               // Invalid EZKIT revision number
    ADI_PWR_RESULT_VDDINT_MUST_BE_SUPPLIED,     // For external voltage regulation.

    ADI_PWR_RESULT_NO_CALLBACK_INSTALLED,       // Tried to remove a callback that was not installed
    ADI_PWR_RESULT_EXCEEDED_MAX_CALLBACKS,      // Could not install a callback because reached max
    ADI_PWR_RESULT_CANNOT_INSTALL_CALLBACK,     // Could not install a callback for some other reason


#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)  || defined(__ADSP_BRODIE__)  || defined(__ADSP_MOY__)
    ADI_PWR_RESULT_INVALID_VR_PHYWE=60+ADI_PWR_ENUMERATION_START,        // Invalid PHYWE value
#endif
#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_MOAB__) || defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)
    ADI_PWR_RESULT_INVALID_VR_CANWE,                            // Invalid CAN wakeup value
#endif

#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_MOAB__)
    ADI_PWR_RESULT_INVALID_VR_USBWE,                            // Invalid USB wakeup value
#endif

#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_MOAB__) || defined(__ADSP_BRODIE__)|| defined(__ADSP_MOY__)
    ADI_PWR_RESULT_INVALID_VR_CLKBUFOE,                            // Invalid CLKBUFOE value
    ADI_PWR_RESULT_INVALID_VR_CKELOW,                             // Invalid CKELOW value
    ADI_PWR_RESULT_INVALID_PC133_COMPLIANCE,                        // Invalid PC-133 compliance value
#endif

#if defined(__ADSP_TETON__) && !defined(ADI_SSL_SINGLE_CORE)
    ADI_PWR_RESULT_CANT_HOOK_SUPPLEMENTAL_INTERRUPT,                // Cannot hook supplemental interrupt
#endif
    ADI_PWR_RESULT_NOT_SUPPORTED,                                // requested action is not supported
    ADI_PWR_RESULT_ALREADY_INITIALIZED,                            // power service has not been initialized

    /***********  obsoleted enumerations ***********/
    ADI_PWR_RESULT_CALL_IGNORED = ADI_PWR_RESULT_NOT_INITIALIZED,    // obsoleted

#if defined(__ADSP_MOAB__)
    ADI_PWR_RESULT_INVALID_VR_GPWE_MXVRWE,                           // Invalid GPWE_MXVRWE/MXVRWE wakeup value
#endif
    ADI_PWR_RESULT_LAST_ENTRY

} ADI_PWR_RESULT;

/*********************************************************************************
* Command values
*********************************************************************************/
typedef enum ADI_PWR_COMMAND {
    ADI_PWR_CMD_START=ADI_PWR_ENUMERATION_START,

    ADI_PWR_CMD_END,
    ADI_PWR_CMD_PAIR,
    ADI_PWR_CMD_TABLE,
    ADI_PWR_CMD_SET_EZKIT,
    ADI_PWR_CMD_SET_PROC_VARIANT,
    ADI_PWR_CMD_SET_PACKAGE,
    ADI_PWR_CMD_SET_CLKIN,
    ADI_PWR_CMD_SET_VDDINT,
    ADI_PWR_CMD_SET_VDDEXT,
#if !defined(__ADSP_MOY__)
    ADI_PWR_CMD_SET_VR_VLEV,
#endif
    ADI_PWR_CMD_SET_VR_FREQ,
#if !defined(__ADSP_KOOKABURRA__) && !defined(__ADSP_MOCKINGBIRD__) && !defined(__ADSP_BRODIE__)
    ADI_PWR_CMD_SET_VR_GAIN,
#endif
    ADI_PWR_CMD_SET_VR_WAKE,
    ADI_PWR_CMD_SET_IVG,
    ADI_PWR_CMD_SET_INPUT_DELAY,
    ADI_PWR_CMD_SET_OUTPUT_DELAY,
    ADI_PWR_CMD_SET_PLL_LOCKCNT,
    ADI_PWR_CMD_FORCE_DATASHEET_VALUES,
    ADI_PWR_CMD_SET_CCLK_TABLE,
    ADI_PWR_CMD_GET_VDDINT,
    ADI_PWR_CMD_GET_VR_VLEV,
    ADI_PWR_CMD_GET_VR_FREQ,
#if !defined(__ADSP_KOOKABURRA__) && !defined(__ADSP_MOCKINGBIRD__) && !defined(__ADSP_BRODIE__)
    ADI_PWR_CMD_GET_VR_GAIN,
#endif
    ADI_PWR_CMD_GET_VR_WAKE,
    ADI_PWR_CMD_GET_PLL_LOCKCNT,
    ADI_PWR_CMD_SET_CRITICAL_REGION_DATA,
    ADI_PWR_CMD_INSTALL_CLK_CLIENT_CALLBACK,
    ADI_PWR_CMD_REMOVE_CLK_CLIENT_CALLBACK,
    ADI_PWR_CMD_SET_CLK_CLIENT_HANDLE,
    ADI_PWR_CMD_SET_FREQ_AS_MHZ,
#if defined(__ADSP_TETON__) && !defined(ADI_SSL_SINGLE_CORE)
    ADI_PWR_CMD_SET_COREB_SUPP_INT0_IVG=(40+ADI_PWR_ENUMERATION_START),
    ADI_PWR_CMD_SET_AUTO_SYNC_ENABLED,
    ADI_PWR_CMD_SET_SYNC_LOCK_VARIABLE,        // Sets the lock variable pointer
#endif

#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_BRODIE__) || defined(__ADSP_MOY__)
    ADI_PWR_CMD_SET_PC133_COMPLIANCE=(60+ADI_PWR_ENUMERATION_START),
    ADI_PWR_CMD_SET_VR_PHYWE,
#endif

#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_MOAB__) || defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)
    ADI_PWR_CMD_SET_VR_CANWE,
#endif

#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_MOAB__)
    ADI_PWR_CMD_SET_VR_USBWE,
#endif

#if defined(__ADSP_BRAEMAR__) ||  defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_MOAB__) || defined(__ADSP_BRODIE__)|| defined(__ADSP_MOY__)
    ADI_PWR_CMD_SET_VR_CLKBUFOE,
    ADI_PWR_CMD_SET_VR_CKELOW,
#endif
#if defined(__ADSP_BRAEMAR__) ||  defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_BRODIE__) || defined(__ADSP_MOY__)
    ADI_PWR_CMD_GET_VR_PHYWE,
#endif
#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_MOAB__) ||  defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)
    ADI_PWR_CMD_GET_VR_CANWE,
#endif

#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_MOAB__)
    ADI_PWR_CMD_GET_VR_USBWE,
#endif

#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_MOAB__) || defined(__ADSP_BRODIE__)  || defined(__ADSP_MOY__)
    ADI_PWR_CMD_GET_VR_CLKBUFOE,
    ADI_PWR_CMD_GET_VR_CKELOW,
#endif

#if defined(__ADSP_MOAB__)  // however, not for the BF549
    ADI_PWR_CMD_SET_VR_GPWE_MXVRWE,
    ADI_PWR_CMD_GET_VR_GPWE_MXVRWE,
#endif
    ADI_PWR_CMD_LAST_ENTRY

} ADI_PWR_COMMAND;


/********************************************************************************
* Synchronisation lock structure
*********************************************************************************/

typedef struct {
    testset_t flag;
    u32 command;
} ADI_PWR_SYNC_LOCK;

#define ADI_PWR_CMD_SET_EZKIT_REVISION ADI_PWR_CMD_SET_EZKIT

typedef struct ADI_PWR_COMMAND_PAIR {
    ADI_PWR_COMMAND kind;
    void* value;
} ADI_PWR_COMMAND_PAIR;

/*********************************************************************
* Macros for a client's Callback functions
*********************************************************************/

// this macro should be used for handler function definitions
// the function is a simple 'C' function taking a single argument
#define ADI_PWR_CALLBACK(NAME) void NAME (void *ClientHandle, u32 sclk)

// this macro is used in argument lists
typedef void (*ADI_PWR_CALLBACK_FN) (void *ClientHandle, u32 sclk);




/*********************************************************************

 callback entry structure used to install a SCLK  change callback

*********************************************************************/

typedef struct ADI_PWR_CLK_CALLBACK_ENTRY
{
    void *ClientHandle;                 /* defined by the app; passed to callbacks */
    ADI_PWR_CALLBACK_FN ClientCallback; /* name of client callback function */
} ADI_PWR_CALLBACK_ENTRY, *pADI_PWR_CALLBACK_ENTRY;




/*********************************************************************************
* POWER CONFIGURATION setting structure handle and size of the config structure
*********************************************************************************/
typedef void* ADI_PWR_CONFIG_HANDLE;
#define ADI_PWR_SIZEOF_CONFIG 108

/*********************************************************************************
* Power mode enumerator
*********************************************************************************/
typedef enum ADI_PWR_MODE {
    ADI_PWR_MODE_FULL_ON,
    ADI_PWR_MODE_ACTIVE,   // PLL ENABLED BUT BYPASSED
    ADI_PWR_MODE_ACTIVE_PLLDISABLED,
    ADI_PWR_MODE_SLEEP,
    ADI_PWR_MODE_DEEP_SLEEP,
    ADI_PWR_MODE_HIBERNATE,
    ADI_PWR_NUM_STATES
} ADI_PWR_MODE;

/*********************************************************************************
* PLL Control Register (PLL_CTL) bit value enumerators (those permitted to be
* changed directly by client applications)
*********************************************************************************/

/*********************************************************************************
* PLL Input divider enumerator
*********************************************************************************/
typedef enum ADI_PWR_DF {
    ADI_PWR_DF_NONE=-1,
    ADI_PWR_DF_OFF,
    ADI_PWR_DF_ON,
    ADI_PWR_NUM_DF
} ADI_PWR_DF;

/*********************************************************************************
* PLL_CTL PLL_OFF bit
*********************************************************************************/
typedef enum ADI_PWR_PLL_PWR {
    ADI_PWR_PLL_ON,
    ADI_PWR_PLL_OFF
} ADI_PWR_PLL_PWR;


/*********************************************************************************
* Input Delay Bit
*********************************************************************************/
typedef enum ADI_PWR_INPUT_DELAY {
    ADI_PWR_INPUT_DELAY_DISABLE,
    ADI_PWR_INPUT_DELAY_ENABLE
} ADI_PWR_INPUT_DELAY;

/*********************************************************************************
* Output Delay Bit
*********************************************************************************/
typedef enum ADI_PWR_OUTPUT_DELAY {
    ADI_PWR_OUTPUT_DELAY_DISABLE,
    ADI_PWR_OUTPUT_DELAY_ENABLE
} ADI_PWR_OUTPUT_DELAY;


/*********************************************************************************
* PLL SCLK select values (SSEL).
* For ADSP-BF535 this is the CLK divider ratio
* For others it is the VCO divider ratio
*********************************************************************************/
typedef enum ADI_PWR_SSEL {
    ADI_PWR_SSEL_NONE=-1,
    ADI_PWR_SSEL_1=1,
    ADI_PWR_SSEL_2,
    ADI_PWR_SSEL_3,
    ADI_PWR_SSEL_4,
    ADI_PWR_SSEL_5,
    ADI_PWR_SSEL_6,
    ADI_PWR_SSEL_7,
    ADI_PWR_SSEL_8,
    ADI_PWR_SSEL_9,
    ADI_PWR_SSEL_10,
    ADI_PWR_SSEL_11,
    ADI_PWR_SSEL_12,
    ADI_PWR_SSEL_13,
    ADI_PWR_SSEL_14,
    ADI_PWR_SSEL_15,
    ADI_PWR_NUM_SSEL
} ADI_PWR_SSEL;

/*********************************************************************************
* PLL CCLK select values (CSEL). (values are actual register field values)
*********************************************************************************/
typedef enum ADI_PWR_CSEL {
    ADI_PWR_CSEL_NONE=-1,
    ADI_PWR_CSEL_1=0,
    ADI_PWR_CSEL_2,
    ADI_PWR_CSEL_4,
    ADI_PWR_CSEL_8,
    ADI_PWR_NUM_CSEL
} ADI_PWR_CSEL;

/*********************************************************************************
* Voltage Regulator Configuration register values
*********************************************************************************/

/*********************************************************************************
* Switching Frequency
*********************************************************************************/
typedef enum ADI_PWR_VR_FREQ {
    ADI_PWR_VR_FREQ_POWERDOWN=0,   // Internal Voltage Regulator is bypassed.
    ADI_PWR_VR_FREQ_333KHZ,
    ADI_PWR_VR_FREQ_667KHZ,
    ADI_PWR_VR_FREQ_1MHZ=3
} ADI_PWR_VR_FREQ;


/*********************************************************************************
* On Kookaburra/Mockingbird there is no GAIN field.
*********************************************************************************/

#if !defined(__ADSP_KOOKABURRA__) && !defined(__ADSP_MOCKINGBIRD__) && !defined(__ADSP_BRODIE__)

/*********************************************************************************
* Voltage Regulator internal loop gain values, for other processors besides Kookaburra/Mockingbird
*********************************************************************************/
typedef enum ADI_PWR_VR_GAIN {
    ADI_PWR_VR_GAIN_5=0,
    ADI_PWR_VR_GAIN_10,
    ADI_PWR_VR_GAIN_20,
    ADI_PWR_VR_GAIN_50
} ADI_PWR_VR_GAIN;

#endif  /* not Kook, Mock, Brodie */


/*********************************************************************************
* RTC Wake up enable control bit values
*********************************************************************************/
typedef enum ADI_PWR_VR_WAKE {
    ADI_PWR_VR_WAKE_DISABLED=0,
    ADI_PWR_VR_WAKE_ENABLED
} ADI_PWR_VR_WAKE;

#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_BRODIE__) || defined(__ADSP_MOY__)

/*********************************************************************************
* PHY Wake up control bit values
*********************************************************************************/
typedef enum ADI_PWR_VR_PHYWE {
    ADI_PWR_VR_PHYWE_DISABLED=0,
    ADI_PWR_VR_PHYWE_ENABLED
} ADI_PWR_VR_PHYWE;
#define ADI_PWR_VR_PHYWE_DEFAULT ADI_PWR_VR_PHYWE_DISABLED

#endif

#if defined(__ADSP_MOAB__)

/*********************************************************************************
* General Purpose Wake up control bit values
*********************************************************************************/
typedef enum ADI_PWR_VR_GPWE_MXVRWE {
    ADI_PWR_VR_GPWE_MXVRWE_DISABLED=0,
    ADI_PWR_VR_GPWE_MXVRWE_ENABLED
} ADI_PWR_VR_GPWE_MXVRWE;
#define ADI_PWR_VR_GPWE_MXVRWE_DEFAULT ADI_PWR_VR_GPWE_MXVRWE_DISABLED

#endif


#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_MOAB__) || defined(__ADSP_BRODIE__) || defined(__ADSP_MOY__)

/*********************************************************************************
* CLKBUFOE CLOCK OUTPUT ENABLE control bit values
*********************************************************************************/
typedef enum ADI_PWR_VR_CLKBUFOE {
    ADI_PWR_VR_CLKBUFOE_DISABLED=0,
    ADI_PWR_VR_CLKBUFOE_ENABLED
} ADI_PWR_VR_CLKBUFOE;
#define ADI_PWR_VR_CLKBUFOE_DEFAULT ADI_PWR_VR_CLKBUFOE_DISABLED

/*********************************************************************************
* DRIVE CKE LOW DURING RESET control bit values
*********************************************************************************/
typedef enum ADI_PWR_VR_CKELOW {
    ADI_PWR_VR_CKELOW_DISABLED=0,
    ADI_PWR_VR_CKELOW_ENABLED
} ADI_PWR_VR_CKELOW;

//NB. The default assumes PC133 compliance
#define ADI_PWR_VR_CKELOW_DEFAULT ADI_PWR_VR_CKELOW_DISABLED

/*********************************************************************************
* The  command to
*********************************************************************************/
typedef enum ADI_PWR_PC133_COMPLIANCE {
    ADI_PWR_PC133_COMPLIANCE_DISABLED=0,
    ADI_PWR_PC133_COMPLIANCE_ENABLED
} ADI_PWR_PC133_COMPLIANCE;

#endif  /* both Kook and Braemar */



#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_MOAB__) || defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)

/*********************************************************************************
* CAN Wake up enable control bit values
*********************************************************************************/
typedef enum ADI_PWR_VR_CANWE {
    ADI_PWR_VR_CANWE_DISABLED=0,
    ADI_PWR_VR_CANWE_ENABLED
} ADI_PWR_VR_CANWE;
#define ADI_PWR_VR_CANWE_DEFAULT ADI_PWR_VR_CANWE_DISABLED

#endif  /* Braemar, moab, kook */

#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_MOAB__)

/*********************************************************************************
* USB Wake up enable control bit values
*********************************************************************************/
typedef enum ADI_PWR_VR_USBWE {
    ADI_PWR_VR_USBWE_DISABLED=0,
    ADI_PWR_VR_USBWE_ENABLED
} ADI_PWR_VR_USBWE;
#define ADI_PWR_VR_USBWE_DEFAULT ADI_PWR_VR_USBWE_DISABLED

#endif  /* Kook, moab */


/*********************************************************************************
* Voltage levels
*********************************************************************************/


#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_BRODIE__)


/* VLEV encodings for the BF52X */

typedef enum ADI_PWR_VLEV {
    ADI_PWR_VLEV_NONE=-2,
    ADI_PWR_VLEV_INVALID=-1,
    ADI_PWR_VLEV_085=4,
    ADI_PWR_VLEV_090=5,
    ADI_PWR_VLEV_095=6,
    ADI_PWR_VLEV_100=7,
    ADI_PWR_VLEV_105=8,
    ADI_PWR_VLEV_110=9,
    ADI_PWR_VLEV_115=10,
    ADI_PWR_VLEV_120=11,
    ADI_PWR_VLEV_125=12,
    ADI_PWR_VLEV_130=13,
    ADI_PWR_VLEV_135=14,
    ADI_PWR_VLEV_140=15,
    ADI_PWR_TOT_VLEVS
} ADI_PWR_VLEV;


#else

/* VLEV encodings for all others */

typedef enum ADI_PWR_VLEV {
    ADI_PWR_VLEV_NONE=-2,
    ADI_PWR_VLEV_INVALID=-1,


#if defined (__ADSP_STIRLING__)
    ADI_PWR_VLEV_080=5,
#endif
#if !defined(__ADSP_MOAB__)
    ADI_PWR_VLEV_085=6,
    ADI_PWR_VLEV_090=7,
#endif

    ADI_PWR_VLEV_095=8,
    ADI_PWR_VLEV_100=9,
    ADI_PWR_VLEV_105=10,
    ADI_PWR_VLEV_110=11,
    ADI_PWR_VLEV_115=12,
    ADI_PWR_VLEV_120=13,
    ADI_PWR_VLEV_125=14,
    ADI_PWR_VLEV_130=15,
    ADI_PWR_VLEV_135=16,
    ADI_PWR_VLEV_140=17,
    ADI_PWR_TOT_VLEVS
} ADI_PWR_VLEV;

#endif


#if defined(__ADSP_MOAB__)

#define ADI_PWR_VOLTS(V)        (0.95 + (V-ADI_PWR_VLEV_095)* 0.05)
#define ADI_PWR_MILLIVOLTS(V)    (950 + (V-ADI_PWR_VLEV_095) * 50)

#else

#define ADI_PWR_VOLTS(V)        (0.85 + (V-ADI_PWR_VLEV_085)*0.05)
#define ADI_PWR_MILLIVOLTS(V)    (850 + (V-ADI_PWR_VLEV_085)*50)

#endif


//#define ADI_PWR_VLEV_DEFAULT    ADI_PWR_VLEV_120

typedef enum ADI_PWR_VDDEXT {
    ADI_PWR_VDDEXT_330,
    ADI_PWR_VDDEXT_250,
    ADI_PWR_VDDEXT_180
} ADI_PWR_VDDEXT;

/*********************************************************************************
* Processor variants
*********************************************************************************/

#if defined (__ADSP_TETON__)

typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF561SKBCZ_6A,
    ADI_PWR_PROC_BF561SKBCZ500X,
    ADI_PWR_PROC_BF561SKBCZ600X,
    ADI_PWR_PROC_BF561SBB600,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;

#endif

#if defined(__ADSP_EDINBURGH__)

// variants as far as clock frequencies are concerned
typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF533SKBC750=0,
    ADI_PWR_PROC_BF533SKBC600,
    ADI_PWR_PROC_BF533SBBC500,
    ADI_PWR_PROC_BF531_OR_BF532,
    ADI_PWR_PROC_BF533SKBC600_6V,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;

#endif

#if defined(__ADSP_BRAEMAR__)




// variants as far as clock frequencies are concerned
typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF537SKBC1600=0,
    ADI_PWR_PROC_BF537SBBC1500,
    ADI_PWR_PROC_BF536SBBC1400,
    ADI_PWR_PROC_BF536SBBC1300,
    ADI_PWR_PROC_BF537BBCZ_5AV,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;


#endif


#if defined(__ADSP_MOAB__)

/* variants as far as clock frequencies are concerned */
/* Note: The BF541, 542, 544, 549 are defined as equivalent to the 548 */

typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF548SKBC1600=0,
    ADI_PWR_PROC_BF548SBBC1533,
    ADI_PWR_PROC_BF548SBBC1400,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;


#endif

#if defined(__ADSP_KOOKABURRA__)

/* variants as far as clock frequencies are concerned */

typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF527SBBC1600=0,
    ADI_PWR_PROC_BF527SBBC1533,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;


#endif

#if defined(__ADSP_MOCKINGBIRD__)

/* variants as far as clock frequencies are concerned */

typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF526SBBC1400,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;


#endif

#if defined(__ADSP_BRODIE__)

/* variants as far as clock frequencies are concerned */

typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF512SBBC1300,
    ADI_PWR_PROC_BF512SBBC1400,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;

#endif



#if defined(__ADSP_MOY__)

/* variants as far as clock frequencies are concerned */

typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF506FBSWZ_ENG,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;

#endif

#if defined(__ADSP_DELTA__)

/* variants as far as clock frequencies are concerned */

typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF592FBSWZ_ENG,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;


#if 0
// FIXME - this makes no sense for DELTA and other parts as MBGA and LQFP are not the only package types
typedef enum ADI_PWR_PACKAGE_KIND {
    ADI_PWR_PACKAGE_LFCSP,
    ADI_PWR_NUM_PKG_KINDS
} ADI_PWR_PACKAGE_KIND;
#endif


#endif


#if defined(__ADSP_STIRLING__)

// variants as far as clock frequencies are concerned
typedef enum ADI_PWR_PROC_KIND {
    ADI_PWR_PROC_BF538BBCZ500=0,
    ADI_PWR_PROC_BF538BBCZ400,
    ADI_PWR_PROC_BF539BBCZ500,
    ADI_PWR_PROC_BF539BBCZ400,
    ADI_PWR_NUM_PROC_KINDS
} ADI_PWR_PROC_KIND;

typedef enum ADI_PWR_PACKAGE_KIND {
    ADI_PWR_PACKAGE_MBGA,
    ADI_PWR_NUM_PKG_KINDS
} ADI_PWR_PACKAGE_KIND;

#elif defined(__ADSP_BRODIE__)

typedef enum ADI_PWR_PACKAGE_KIND {
    ADI_PWR_PACKAGE_MBGA = 0,         /* Do not use. BRODIE MBGA package is not available */
                                      /* Initial release of the BRODIE power service used */
                                      /* this value. Left in for legacy reasons           */
    ADI_PWR_PACKAGE_LQFP = 0,
    ADI_PWR_PACKAGE_CSP_BGA,
    ADI_PWR_NUM_PKG_KINDS
} ADI_PWR_PACKAGE_KIND;

#else

typedef enum ADI_PWR_PACKAGE_KIND {
    ADI_PWR_PACKAGE_MBGA,
    ADI_PWR_PACKAGE_LQFP,
    ADI_PWR_NUM_PKG_KINDS
} ADI_PWR_PACKAGE_KIND;

#endif



/*********************************************************************************
* EZ-KIT revisions
*********************************************************************************/
#if defined(__ADSP_EDINBURGH__)

typedef enum ADI_PWR_EZKIT {
    ADI_PWR_EZKIT_BF533_750MHZ,
    ADI_PWR_EZKIT_BF533_600MHZ
} ADI_PWR_EZKIT;

#endif

#if defined(__ADSP_BRAEMAR__)

typedef enum ADI_PWR_EZKIT {
    ADI_PWR_EZKIT_BF537_600MHZ
} ADI_PWR_EZKIT;

#endif


#if defined(__ADSP_TETON__)

typedef enum ADI_PWR_EZKIT {
    ADI_PWR_EZKIT_BF561_600MHZ,
    ADI_PWR_EZKIT_BF561_500MHZ
} ADI_PWR_EZKIT;

#endif

#if defined(__ADSP_STIRLING__)

typedef enum ADI_PWR_EZKIT {
    ADI_PWR_EZKIT_BF538_500MHZ
//    ADI_PWR_EZKIT_BF538_400MHZ,
} ADI_PWR_EZKIT;

#endif

/*********************************************************************************
* API prototypes
*********************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

ADI_PWR_RESULT adi_pwr_Init(            // Initialize the module
        const ADI_PWR_COMMAND_PAIR *table            // table of commands to configure the module
);

ADI_PWR_RESULT
adi_pwr_Control(                        // Control function
        ADI_PWR_COMMAND Command,                    // Command
        void *Value                                    // Associated value
);

size_t adi_pwr_GetConfigSize(void);        // Returns size of the module's config structure

ADI_PWR_RESULT
adi_pwr_SaveConfig(                        // Save the current configuration
        ADI_PWR_CONFIG_HANDLE hConfig,                // Handle to memory location to store the config details
        const size_t szConfig                        // size of memeory provided
);

ADI_PWR_RESULT
adi_pwr_LoadConfig(                                    // Save the current configuration
        const ADI_PWR_CONFIG_HANDLE hConfig,         // Handle to memory location containing the config details
        const size_t szConfig                        // size of memeory provided
);
void adi_pwr_Reset(void);                // Sets all PLL and VR registers to reset values

ADI_PWR_RESULT
adi_pwr_SetVoltageRegulator(            // Adjusts the built-in voltage regulator
        ADI_PWR_COMMAND Command,                     // Command
        void *Value                                    // Associated value
);

/* Moy does not support internal voltage regulation */
#if !defined(__ADSP_MOY__)
ADI_PWR_RESULT
adi_pwr_SetMaxFreqForVolt(                // calcs and sets PLL to give the max core clock frequency
                                        // for the given voltage level
        const ADI_PWR_VLEV vlev                        // Voltage level
);
#endif


ADI_PWR_RESULT
adi_pwr_SetFreq (                    // sets PLL to be as close to desired values as possible
        const u32 fcclk,                            // Requested Core Clock Frequency (Hz or MHz)
        const u32 fsclk,                             // Requested System Clock Frequency (Hz or MHz)
        const ADI_PWR_DF df                            // input divider bit
);

ADI_PWR_RESULT
adi_pwr_AdjustFreq(                        // Sets the PLL Dividor register to adjust CCLK and/or SCLK
    ADI_PWR_CSEL csel,                        // required CSEL value
    ADI_PWR_SSEL ssel                        // required SSEL value
);

ADI_PWR_RESULT
adi_pwr_GetFreq(                    // Interrogates the PLL and returns the CCLK SCLK and VCO frequencies
    u32 *fcclk,                                // on return, contains the CCLK frequency (Hz)
    u32 *fsclk,                                // on return, contains the SCLK frequency (Hz)
    u32 *fvco                                // on return, contains the VCO frequency (Hz)
);

ADI_PWR_RESULT
adi_pwr_SetPowerMode(                    // Places the core in the required operating mode
    const ADI_PWR_MODE Mode                    // mode to be set
);

ADI_PWR_MODE
adi_pwr_GetPowerMode(                    // Returns the current operating mode
    void
);
u32
adi_pwr_GetPowerSaving(                    // returns the theoretical percentage power saving for full utilization at lower VLEV
    void
);

ADI_PWR_RESULT
adi_pwr_Terminate(                        //Resets the initialized flag, and unhooks supplemental interrupt (BF561)
    void
);


#ifdef __cplusplus
}
#endif


#else  // END OF C/C++ section

/****************************************************************************************
* Assembler Section - This section has been reinstated solely for the benefit of the
* CRTGen "Custom Clock & Powersettings, a feature which is not supported, from Moab onward.
****************************************************`**********************************/
#if defined(__ADSP_TETON__) || defined(__ADSP_EDINBURGH__) || defined(__ADSP_BRAEMAR__) || defined(__ADSP_STIRLING__)

/*********************************************************************************
* Result codes
*********************************************************************************/
#define ADI_PWR_RESULT_SUCCESS                     0                        // Successful completion
#define ADI_PWR_RESULT_FAILED                      1                        // Generic Failure
#define ADI_PWR_RESULT_NO_MEMORY                    (1 + ADI_PWR_ENUMERATION_START)    // Insufficient memory to perform the operation
#define ADI_PWR_RESULT_BAD_COMMAND                  (2 + ADI_PWR_ENUMERATION_START)    // The command in not recognized or the value is incorrect
#define ADI_PWR_RESULT_NOT_INITIALIZED              (3 + ADI_PWR_ENUMERATION_START)    // A function call has been ignored with no action taken

#define ADI_PWR_RESULT_INVALID_CSEL                 (4 + ADI_PWR_ENUMERATION_START)    // An Invalid CSEL value has been supplied
#define ADI_PWR_RESULT_INVALID_SSEL                 (5 + ADI_PWR_ENUMERATION_START)    // An Invalid SSEL value has been supplied
#define ADI_PWR_RESULT_INVALID_CSEL_SSEL_COMBINATION    (6 + ADI_PWR_ENUMERATION_START)    // An Invalid SSEL/CSEL combination has been supplied
#define ADI_PWR_RESULT_INVALID_VLEV                 (7 + ADI_PWR_ENUMERATION_START)    // An Invalid internal voltage level
#define ADI_PWR_RESULT_INVALID_VDDEXT               (8 + ADI_PWR_ENUMERATION_START)    // An Invalid external voltage level
#define ADI_PWR_RESULT_INVALID_VR_FREQ              (9 + ADI_PWR_ENUMERATION_START)    // An invalid switching frequency value
#define ADI_PWR_RESULT_INVALID_VR_GAIN              (10 + ADI_PWR_ENUMERATION_START)    // An invalid Voltage regulator GAIN value
#define ADI_PWR_RESULT_INVALID_VR_WAKE              (11 + ADI_PWR_ENUMERATION_START)    // An invalid Voltage regulator WAKE value
#define ADI_PWR_RESULT_INVALID_MODE                 (12 + ADI_PWR_ENUMERATION_START)    // An invalid operating mode has been specified
#define ADI_PWR_RESULT_INVALID_PROCESSOR            (13 + ADI_PWR_ENUMERATION_START)    // The processor type specified is invalid
#define ADI_PWR_RESULT_INVALID_IVG                  (14 + ADI_PWR_ENUMERATION_START)    // The IVG level supplied is invalid
#define ADI_PWR_RESULT_INVALID_INPUT_DELAY          (15 + ADI_PWR_ENUMERATION_START)    // The input delay value is invalid
#define ADI_PWR_RESULT_INVALID_OUTPUT_DELAY         (16 + ADI_PWR_ENUMERATION_START)    // The output delay value is invalid
#define ADI_PWR_RESULT_INVALID_LOCKCNT              (17 + ADI_PWR_ENUMERATION_START)    // The PLL lock count value is invalid
#define ADI_PWR_RESULT_VOLTAGE_REGULATOR_BYPASSED   (18 + ADI_PWR_ENUMERATION_START)    // The onboard VR is bypassed

/* soon to be obsoleted */
#define ADI_PWR_RESULT_INVALID_EZKIT                 (19 + ADI_PWR_ENUMERATION_START)    // Invalid EZKIT revision number

#define    ADI_PWR_RESULT_VDDINT_MUST_BE_SUPPLIED    (20 + ADI_PWR_ENUMERATION_START)    // For external voltage regulation.

#define    ADI_PWR_RESULT_NO_CALLBACK_INSTALLED      (21 + ADI_PWR_ENUMERATION_START)    // Tried to remove a callback that was not installed
#define    ADI_PWR_RESULT_EXCEEDED_MAX_CALLBACKS     (22 + ADI_PWR_ENUMERATION_START)    // Could not install a callback because reached max
#define    ADI_PWR_RESULT_CANNOT_INSTALL_CALLBACK    (23 + ADI_PWR_ENUMERATION_START)    // Could not install a callback for some other reason

#if defined(__ADSP_BRAEMAR__)
#define ADI_PWR_RESULT_INVALID_VR_PHYWE              (60 + ADI_PWR_ENUMERATION_START)    // Invalid PHYWE value
#define ADI_PWR_RESULT_INVALID_VR_CANWE              (61 + ADI_PWR_ENUMERATION_START)    // Invalid CAN wakeup value
#define ADI_PWR_RESULT_INVALID_VR_CLKBUFOE           (62 + ADI_PWR_ENUMERATION_START)    // Invalid CLKBUFOE value
#define ADI_PWR_RESULT_INVALID_VR_CKELOW             (63 + ADI_PWR_ENUMERATION_START)    // Invalid CKELOW value
#endif

#define    ADI_PWR_RESULT_CALL_IGNORED  ADI_PWR_RESULT_NOT_INITIALIZED    // obsolete


/*********************************************************************************
* Command values
*********************************************************************************/
#define ADI_PWR_CMD_END                         (1 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_PAIR                        (2 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_TABLE                       (3 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_EZKIT                   (4 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_PROC_VARIANT            (5 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_PACKAGE                 (6 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_CLKIN                   (7 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_VDDINT                  (8 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_VDDEXT                  (9 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_VR_VLEV                 (10 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_VR_FREQ                 (11 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_VR_GAIN                 (12 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_VR_WAKE                 (13 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_IVG                     (14 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_INPUT_DELAY             (15 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_OUTPUT_DELAY            (16 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_PLL_LOCKCNT             (17 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_FORCE_DATASHEET_VALUES      (18 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_CCLK_TABLE              (19 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_GET_VDDINT                  (20 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_GET_VR_VLEV                 (21 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_GET_VR_FREQ                 (22 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_GET_VR_GAIN                 (23 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_GET_VR_WAKE                 (24 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_GET_PLL_LOCKCNT             (25 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_CRITICAL_REGION_DATA    (26 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_FIRST_CLIENT_CALLBACK   (27 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_SECOND_CLIENT_CALLBACK  (28 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_CLIENT_HANDLE           (29 + ADI_PWR_ENUMERATION_START)
#if defined(__ADSP_TETON__)
#define ADI_PWR_CMD_SET_COREB_SUPP_INT0_IVG     (40 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_AUTO_SYNC_ENABLED       (41 + ADI_PWR_ENUMERATION_START)
#endif
#if defined(__ADSP_BRAEMAR__)
#define ADI_PWR_CMD_SET_PC133_COMPLIANCE        (60 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_VR_PHYWE                (61 + ADI_PWR_ENUMERATION_START)
#endif
#if defined(__ADSP_BRAEMAR__)
#define ADI_PWR_CMD_SET_VR_CANWE                (62 + ADI_PWR_ENUMERATION_START)
#endif

//#if defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_MOAB__)
#define ADI_PWR_CMD_SET_VR_USBWE                (62 + ADI_PWR_ENUMERATION_START)
//#endif

#if defined(__ADSP_BRAEMAR__)
#define ADI_PWR_CMD_SET_VR_CLKBUFOE            (63 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_SET_VR_CKELOW              (64 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_GET_VR_PHYWE               (65 + ADI_PWR_ENUMERATION_START)
#endif

#if defined(__ADSP_BRAEMAR__)
#define ADI_PWR_CMD_GET_VR_CANWE               (66 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_GET_VR_CLKBUFOE            (67 + ADI_PWR_ENUMERATION_START)
#define ADI_PWR_CMD_GET_VR_CKELOW              (68 + ADI_PWR_ENUMERATION_START)
#endif

/*********************************************************************************
* Power mode enumerator
*********************************************************************************/
#define ADI_PWR_MODE_FULL_ON                  0    // Full-on
#define ADI_PWR_MODE_ACTIVE                   1    // ACTIVE PLL ENABLED BUT BYPASSED
#define ADI_PWR_MODE_ACTIVE_PLLDISABLED       2    // ACTIVE PLL DISABLED
#define ADI_PWR_MODE_SLEEP                    3    // Sleep
#define ADI_PWR_MODE_DEEP_SLEEP               4
#define ADI_PWR_MODE_HIBERNATE                5
#define ADI_PWR_NUM_STATES                    6

/*********************************************************************************
* PLL Control Register (PLL_CTL) bit value enumerators (those permitted to be
* changed directly by client applications)
*********************************************************************************/

/*********************************************************************************
* PLL Input divider enumerator
*********************************************************************************/
#define ADI_PWR_DF_NONE      -1
#define ADI_PWR_DF_OFF        0
#define ADI_PWR_DF_ON         1

/*********************************************************************************
* PLL_CTL PLL_OFF bit
*********************************************************************************/
#define ADI_PWR_PLL_ON        0
#define ADI_PWR_PLL_OFF       1


/*********************************************************************************
* Input Delay Bit
*********************************************************************************/
#define ADI_PWR_INPUT_DELAY_DISABLE   0
#define ADI_PWR_INPUT_DELAY_ENABLE    1

/*********************************************************************************
* Output Delay Bit
*********************************************************************************/
#define ADI_PWR_OUTPUT_DELAY_DISABLE 0
#define ADI_PWR_OUTPUT_DELAY_ENABLE  1

/*********************************************************************************
* PLL SCLK select values (SSEL).
* For ADSP-BF535 this is the CLK divider ratio
* For others it is the VCO divider ratio
*********************************************************************************/
#define ADI_PWR_SSEL_NONE        -1
#define ADI_PWR_SSEL_1            1
#define ADI_PWR_SSEL_2            2
#define ADI_PWR_SSEL_3            3
#define ADI_PWR_SSEL_4            4
#define ADI_PWR_SSEL_5            5
#define ADI_PWR_SSEL_6            6
#define ADI_PWR_SSEL_7            7
#define ADI_PWR_SSEL_8            8
#define ADI_PWR_SSEL_9            9
#define ADI_PWR_SSEL_10           10
#define ADI_PWR_SSEL_11           11
#define ADI_PWR_SSEL_12           12
#define ADI_PWR_SSEL_13           13
#define ADI_PWR_SSEL_14           14
#define ADI_PWR_SSEL_15           15

#define ADI_PWR_NUM_SSEL          15

/*********************************************************************************
* PLL CCLK select values (CSEL). (values are actual register field values)
* Not applicable for ADSP-BF535
*********************************************************************************/
#define ADI_PWR_CSEL_NONE        -1
#define ADI_PWR_CSEL_1            0
#define ADI_PWR_CSEL_2            1
#define ADI_PWR_CSEL_4            2
#define ADI_PWR_CSEL_8            3

#define ADI_PWR_NUM_CSEL         4


/*********************************************************************************
* Voltage Regulator Configuration register values
* Not applicable for ADSP-BF535
*********************************************************************************/

/*********************************************************************************
* Switching Frequency
*********************************************************************************/
#define ADI_PWR_VR_FREQ_POWERDOWN     0    // Internal Voltage Regulator is bypassed.
#define ADI_PWR_VR_FREQ_333KHZ        1
#define ADI_PWR_VR_FREQ_667KHZ        2
#define ADI_PWR_VR_FREQ_1MHZ          3

/*********************************************************************************
* Voltage Regulator internal loop gain values
*********************************************************************************/
#define ADI_PWR_VR_GAIN_5             0
#define ADI_PWR_VR_GAIN_10            1
#define ADI_PWR_VR_GAIN_20            2
#define ADI_PWR_VR_GAIN_50            3

/*********************************************************************************
* RTC Wake up enable control bit values
*********************************************************************************/
#define ADI_PWR_VR_WAKE_DISABLED    0
#define ADI_PWR_VR_WAKE_ENABLED     1

#if defined(__ADSP_BRAEMAR__)

/*********************************************************************************
* PHY Wake up control bit values
*********************************************************************************/
#define ADI_PWR_VR_PHYWE_DISABLED   0
#define ADI_PWR_VR_PHYWE_ENABLED    1
#define ADI_PWR_VR_PHYWE_DEFAULT    ADI_PWR_VR_PHYWE_DISABLED

/*********************************************************************************
* PHY CLOCK OUTPUT ENABLE control bit values
*********************************************************************************/
#define ADI_PWR_VR_CLKBUFOE_DISABLED    0
#define ADI_PWR_VR_CLKBUFOE_ENABLED     1
#define ADI_PWR_VR_CLKBUFOE_DEFAULT     ADI_PWR_VR_CLKBUFOE_DISABLED

/*********************************************************************************
* DRIVE CKE LOW DURING RESET control bit values
*********************************************************************************/
#define ADI_PWR_VR_CKELOW_DISABLED           0
#define ADI_PWR_VR_CKELOW_ENABLED            1

//NB. The default assumes PC133 compliance
#define ADI_PWR_VR_CKELOW_DEFAULT        ADI_PWR_VR_CKELOW_DISABLED

#endif  /* Braemar */

#if defined(__ADSP_BRAEMAR__)
/*********************************************************************************
* CAN Wake up enable control bit values
*********************************************************************************/
#define ADI_PWR_VR_CANWE_DISABLED   0
#define ADI_PWR_VR_CANWE_ENABLED    1
#define ADI_PWR_VR_CANWE_DEFAULT    ADI_PWR_VR_CANWE_DISABLED
#endif  /* Braemar */


/*********************************************************************************
* Voltage levels
*********************************************************************************/
#define ADI_PWR_VLEV_NONE        -2
#define ADI_PWR_VLEV_INVALID     -1

#if defined (__ADSP_STIRLING__)
#define ADI_PWR_VLEV_080         5
#endif

#define ADI_PWR_VLEV_085        6
#define ADI_PWR_VLEV_090        7
#define ADI_PWR_VLEV_095        8
#define ADI_PWR_VLEV_100        9
#define ADI_PWR_VLEV_105        10
#define ADI_PWR_VLEV_110        11
#define ADI_PWR_VLEV_115        12
#define ADI_PWR_VLEV_120        13
#define ADI_PWR_VLEV_125        14
#define ADI_PWR_VLEV_130        15
#define ADI_PWR_VLEV_135        16
#define ADI_PWR_VLEV_140        17

#define ADI_PWR_VDDEXT_330      0
#define ADI_PWR_VDDEXT_250      1
#define ADI_PWR_VDDEXT_180      2
/*********************************************************************************
* Processor variants
*********************************************************************************/
#if defined (__ADSP_TETON__)

#define ADI_PWR_PROC_BF561SKBCZ_6A       0
#define ADI_PWR_PROC_BF561SKBCZ500X      1
#define ADI_PWR_PROC_BF561SKBCZ600X      2
#define ADI_PWR_PROC_BF561SBB600         3

#endif

#if defined(__ADSP_EDINBURGH__)

// variants as far as clock frequencies are concerned
#define ADI_PWR_PROC_BF533SKBC750        0
#define ADI_PWR_PROC_BF533SKBC600        1
#define ADI_PWR_PROC_BF533SBBC500        2
#define ADI_PWR_PROC_BF531_OR_BF532      3

#endif

#if defined(__ADSP_BRAEMAR__)

// variants as far as clock frequencies are concerned
#define ADI_PWR_PROC_BF537SKBC1600        0
#define ADI_PWR_PROC_BF537SBBC1500        1
#define ADI_PWR_PROC_BF536SBBC1400        2
#define ADI_PWR_PROC_BF536SBBC1300        3
#define ADI_PWR_PROC_BF537BBCZ_5AV        4

// defined as equivalents
//#define ADI_PWR_PROC_BF534SBBC1500        4
//#define ADI_PWR_PROC_BF534SBBC1400        5

#endif


#if defined (__ADSP_STIRLING__)
#define ADI_PWR_PROC_BF538BBCZ500        0
#define ADI_PWR_PROC_BF538BBCZ400        1
#define ADI_PWR_PROC_BF539BBCZ500        2
#define ADI_PWR_PROC_BF539BBCZ400        3
#endif

#define ADI_PWR_PACKAGE_MBGA            0
#define ADI_PWR_PACKAGE_LQFP            1
#if defined (__ADSP_STIRLING__)
#define ADI_PWR_NUM_PKG_KINDS           1
#else
#define ADI_PWR_NUM_PKG_KINDS           2
#endif
/*********************************************************************************
* EZ-KIT revisions
*********************************************************************************/
#if defined(__ADSP_EDINBURGH__)
#define ADI_PWR_EZKIT_BF533_750MHZ       0
#define ADI_PWR_EZKIT_BF533_600MHZ       1
#endif

#if defined(__ADSP_BRAEMAR__)
#define ADI_PWR_EZKIT_BF537_600MHZ       0
#endif


#if defined(__ADSP_TETON__)
#define ADI_PWR_EZKIT_BF561_600MHZ      0
#define ADI_PWR_EZKIT_BF561_500MHZ      1
#endif

#if defined(__ADSP_STIRLING__)
#define ADI_PWR_EZKIT_BF538_500MHZ     0
#endif

/*********************************************************************************
* API prototypes (see C/C++ section for arguments
*********************************************************************************/

.extern _adi_pwr_Init;
    .type _adi_pwr_Init,STT_FUNC;

.extern _adi_pwr_Control;
    .type _adi_pwr_Control,STT_FUNC;

.extern _adi_pwr_GetConfigSize;
    .type _adi_pwr_GetConfigSize,STT_FUNC;

.extern _adi_pwr_SaveConfig;
    .type _adi_pwr_SaveConfig,STT_FUNC;

.extern _adi_pwr_LoadConfig;
    .type _adi_pwr_LoadConfig,STT_FUNC;

.extern _adi_pwr_Reset;
    .type _adi_pwr_Reset,STT_FUNC;

.extern _adi_pwr_SetVoltageRegulator;
    .type _adi_pwr_SetVoltageRegulator,STT_FUNC;

.extern _adi_pwr_SetMaxFreqForVolt;
    .type _adi_pwr_SetMaxFreqForVolt,STT_FUNC;

.extern _adi_pwr_SetFreq;
    .type _adi_pwr_SetFreq,STT_FUNC;

.extern _adi_pwr_AdjustFreq;
    .type _adi_pwr_AdjustFreq,STT_FUNC;

.extern _adi_pwr_GetFreq;
    .type _adi_pwr_GetFreq,STT_FUNC;

.extern _adi_pwr_SetPowerMode;
    .type _adi_pwr_SetPowerMode,STT_FUNC;

.extern _adi_pwr_GetPowerMode;
    .type _adi_pwr_GetPowerMode,STT_FUNC;

.extern _adi_pwr_GetPowerSaving;
    .type _adi_pwr_GetPowerSaving,STT_FUNC;

.extern _adi_pwr_Terminate;
    .type _adi_pwr_Terminate,STT_FUNC;


#endif // Assembler section not supported from Moab onward
#endif   //END OF ASSEMBLER SECTION



/*********************************************************************************
* Register Reset values
*********************************************************************************/

#if defined(__ADSP_KOOKABURRA__)
#define ADI_PLL_CTL_RESET        0x0A00

/* first rev of kookaburra used a different value for PLL_DIV
   but starting with rev 0.2 PLL_DIV reset value is 0x04 */

#if defined (__SILICON_REVISION__) && (__SILICON_REVISION__> 0x01 )
#define ADI_PWR_PLL_DIV_RESET    0x0004
#else
#define ADI_PWR_PLL_DIV_RESET    0x0014
#endif


#elif defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_BRODIE__) || defined(__ADSP_MOY__)
#define ADI_PLL_CTL_RESET        0x0A00
#define ADI_PWR_PLL_DIV_RESET    0x0004
#else
#define ADI_PLL_CTL_RESET        0x1400
#define ADI_PWR_PLL_DIV_RESET    0x0005
#endif

#if defined(__ADSP_BRAEMAR__) || defined(__ADSP_MOAB__)
#define ADI_PWR_VR_CTL_RESET        0x40DB
#elif defined(__ADSP_KOOKABURRA__) || defined(__ADSP_MOCKINGBIRD__)
#define ADI_PWR_VR_CTL_RESET        0x7070
#elif defined(__ADSP_BRODIE__) || defined(__ADSP_MOY__)
#define ADI_PWR_VR_CTL_RESET        0x70B0

#else
#define ADI_PWR_VR_CTL_RESET        0x00DB
#endif

#define ADI_PWR_PLL_STAT_RESET        0x00A2
#define ADI_PWR_PLL_LOCKCNT_RESET    0x0200


/*********************************************************************************
* EZ-KIT CLKIN frequencies  Voltages
*********************************************************************************/

#if defined(__ADSP_EDINBURGH__)
#define ADI_PWR_CLKIN_EZKIT_BF533    27      // Hz
#define ADI_PWR_VDEXT_EZKIT_BF533    ADI_PWR_VDDEXT_330  // 3.3V
#endif

#if defined(__ADSP_BRAEMAR__)
#define ADI_PWR_CLKIN_EZKIT_BF537    25      // Hz
#define ADI_PWR_VDEXT_EZKIT_BF537    ADI_PWR_VDDEXT_330  // 3.3V
#endif


#if defined(__ADSPBF561__)
#define ADI_PWR_CLKIN_EZKIT_BF561    30      // Hz
#define ADI_PWR_VDEXT_EZKIT_BF561    ADI_PWR_VDDEXT_330  // 3.3V
#endif

#if defined(__ADSP_STIRLING__)
#define ADI_PWR_CLKIN_EZKIT_BF538    25      // Hz
#define ADI_PWR_VDEXT_EZKIT_BF538    ADI_PWR_VDDEXT_330  // 3.3V
#endif

/*********************************************************************************
* Max, Min, default and equivalent values
*********************************************************************************/

#define ADI_PWR_SSEL_MAX            ADI_PWR_SSEL_15

#define ADI_PWR_VR_FREQ_MIN            ADI_PWR_VR_FREQ_POWERDOWN
#define ADI_PWR_VR_FREQ_MAX            ADI_PWR_VR_FREQ_1MHZ
#define ADI_PWR_VR_FREQ_DEFAULT        ADI_PWR_VR_FREQ_1MHZ

#define ADI_PWR_VR_GAIN_MIN            ADI_PWR_VR_GAIN_5
#define ADI_PWR_VR_GAIN_MAX            ADI_PWR_VR_GAIN_50
#define ADI_PWR_VR_GAIN_DEFAULT        ADI_PWR_VR_GAIN_20

#define ADI_PWR_VR_WAKE_MIN            ADI_PWR_VR_WAKE_DISABLED
#define ADI_PWR_VR_WAKE_MAX            ADI_PWR_VR_WAKE_ENABLED
#define ADI_PWR_VR_WAKE_DEFAULT        ADI_PWR_VR_WAKE_DISABLED


#if defined (__ADSP_STIRLING__)
#define ADI_PWR_VLEV_MIN            ADI_PWR_VLEV_080
#define ADI_PWR_VLEV_MAX            ADI_PWR_VLEV_140
#define ADI_PWR_VLEV_DEFAULT        ADI_PWR_VLEV_120

#elif defined(__ADSP_KOOKABURRA__)
#define ADI_PWR_VLEV_MIN            ADI_PWR_VLEV_100
#define ADI_PWR_VLEV_MAX            ADI_PWR_VLEV_120
#define ADI_PWR_VLEV_DEFAULT        ADI_PWR_VLEV_110

#elif defined(__ADSP_MOCKINGBIRD__) || defined(__ADSP_BRODIE__)
#define ADI_PWR_VLEV_MIN            ADI_PWR_VLEV_115
#define ADI_PWR_VLEV_MAX            ADI_PWR_VLEV_140
#define ADI_PWR_VLEV_DEFAULT        ADI_PWR_VLEV_120

#elif  defined(__ADSP_MOY__)
#define ADI_PWR_VLEV_MIN            ADI_PWR_VLEV_120
#define ADI_PWR_VLEV_MAX            ADI_PWR_VLEV_140
#define ADI_PWR_VLEV_DEFAULT        ADI_PWR_VLEV_140

#elif  defined(__ADSP_DELTA__)
#define ADI_PWR_VLEV_MIN            ADI_PWR_VLEV_120
#define ADI_PWR_VLEV_MAX            ADI_PWR_VLEV_140
#define ADI_PWR_VLEV_DEFAULT        ADI_PWR_VLEV_140

#elif defined(__ADSP_MOAB__)
#define ADI_PWR_VLEV_MIN            ADI_PWR_VLEV_095
#define ADI_PWR_VLEV_MAX            ADI_PWR_VLEV_140
//#define ADI_PWR_VLEV_MAX            ADI_PWR_VLEV_130
#define ADI_PWR_VLEV_DEFAULT        ADI_PWR_VLEV_120

#else  /* for external voltage regulators, this VLEV field refers to VDDINT */
// ADSP_EDINBURGH, ADSP_BRAEMAR,  ADSP_TETON, MOY
#define ADI_PWR_VLEV_MIN            ADI_PWR_VLEV_085
#define ADI_PWR_VLEV_MAX            ADI_PWR_VLEV_130
#define ADI_PWR_VLEV_DEFAULT        ADI_PWR_VLEV_120
#endif
#define ADI_PWR_NUM_VLEVS            ADI_PWR_VLEV_MAX-ADI_PWR_VLEV_MIN+1



// equivalents
#if defined(__ADSP_EDINBURGH__)

#define ADI_PWR_PROC_BF533SKBCZ600    ADI_PWR_PROC_BF533SKBC600
#define ADI_PWR_PROC_BF533SBBZ500    ADI_PWR_PROC_BF533SBBC500

#define ADI_PWR_PROC_BF532SBBC400    ADI_PWR_PROC_BF531_OR_BF532
#define ADI_PWR_PROC_BF532SBST400    ADI_PWR_PROC_BF531_OR_BF532
#define ADI_PWR_PROC_BF532SBBZ400    ADI_PWR_PROC_BF531_OR_BF532

#define ADI_PWR_PROC_BF531SBBC400    ADI_PWR_PROC_BF531_OR_BF532
#define ADI_PWR_PROC_BF531SBST400    ADI_PWR_PROC_BF531_OR_BF532
#define ADI_PWR_PROC_BF531SBSTZ400    ADI_PWR_PROC_BF531_OR_BF532
#define ADI_PWR_PROC_BF531SBBZ400    ADI_PWR_PROC_BF531_OR_BF532


#elif defined(__ADSP_BRAEMAR__)

#define ADI_PWR_PROC_BF534SBBC1500  ADI_PWR_PROC_BF537SBBC1500
#define ADI_PWR_PROC_BF534SBBC1400  ADI_PWR_PROC_BF536SBBC1400

#define ADI_PWR_PROC_BF537SKBC600    ADI_PWR_PROC_BF537SKBC1600
#define ADI_PWR_PROC_BF537SKBC1Z600    ADI_PWR_PROC_BF537SKBC1600
#define ADI_PWR_PROC_BF537SKBC2Z600    ADI_PWR_PROC_BF537SKBC1600

#define ADI_PWR_PROC_BF537SBBC1Z500    ADI_PWR_PROC_BF537SBBC1500
#define ADI_PWR_PROC_BF537SBBC2Z500    ADI_PWR_PROC_BF537SBBC1500

#define ADI_PWR_PROC_BF536SBBC1Z400    ADI_PWR_PROC_BF536SBBC1400
#define ADI_PWR_PROC_BF536SBBC2Z400    ADI_PWR_PROC_BF536SBBC1400

#define ADI_PWR_PROC_BF536SBBC1Z300    ADI_PWR_PROC_BF536SBBC1300
#define ADI_PWR_PROC_BF536SBBC2Z300    ADI_PWR_PROC_BF536SBBC1300

#define ADI_PWR_PROC_BF534SBBC1Z400 ADI_PWR_PROC_BF534SBBC1400
#define ADI_PWR_PROC_BF534SBBC2Z400 ADI_PWR_PROC_BF534SBBC1400

#define ADI_PWR_PROC_BF534SBBC1Z500 ADI_PWR_PROC_BF534SBBC1500
#define ADI_PWR_PROC_BF534SBBC2Z500 ADI_PWR_PROC_BF534SBBC1500
#define ADI_PWR_PROC_BF537BBCZ5BVX  ADI_PWR_PROC_BF537BBCZ_5AV
#define ADI_PWR_PROC_BF537KBCZ6BVX  ADI_PWR_PROC_BF537KBCZ_6AV
#define ADI_PWR_PROC_BF537KBCZ_6AV  ADI_PWR_PROC_BF537SKBC1600

#define ADI_PWR_PROC_BF534BBC_4A   ADI_PWR_PROC_BF534SBBC1400
#define ADI_PWR_PROC_BF534BBCZ_4A  ADI_PWR_PROC_BF534SBBC1400

#define ADI_PWR_PROC_BF534BBCZ_4B   ADI_PWR_PROC_BF534SBBC1400
#define ADI_PWR_PROC_BF534BBCZ_5B    ADI_PWR_PROC_BF534SBBC1500
#define ADI_PWR_PROC_BF534BBC_5A      ADI_PWR_PROC_BF534SBBC1500
#define ADI_PWR_PROC_BF534BBCZ_5A   ADI_PWR_PROC_BF534SBBC1500
#define ADI_PWR_PROC_BF537BBC_5A    ADI_PWR_PROC_BF534SBBC1500
#define ADI_PWR_PROC_BF537BBCZ_5A     ADI_PWR_PROC_BF534SBBC1500
#define ADI_PWR_PROC_BF537BBCZ_5B    ADI_PWR_PROC_BF534SBBC1500

#define ADI_PWR_PROC_BF535PBB_300    ADI_PWR_PROC_BF536SBBC1300
#define ADI_PWR_PROC_BF535PKB_300    ADI_PWR_PROC_BF536SBBC1300
#define ADI_PWR_PROC_BF535PKBZ_300    ADI_PWR_PROC_BF536SBBC1300

// To be added when data is available
//#define ADI_PWR_PROC_BF535PKB_350
//#define ADI_PWR_PROC_BF535PKBZ_350
//#define ADI_PWR_PROC_BF535PBB_200
//#define ADI_PWR_PROC_BF535PBBZ_200

#define ADI_PWR_PROC_BF536BBC_3A     ADI_PWR_PROC_BF536SBBC1300
#define ADI_PWR_PROC_BF536BBCZ_3A   ADI_PWR_PROC_BF536SBBC1300
#define ADI_PWR_PROC_BF536BBCZ_3B   ADI_PWR_PROC_BF536SBBC1300

#define ADI_PWR_PROC_BF536BBC_4A    ADI_PWR_PROC_BF534SBBC1400
#define ADI_PWR_PROC_BF536BBCZ_4A   ADI_PWR_PROC_BF534SBBC1400
#define ADI_PWR_PROC_BF536BBCZ_4B   ADI_PWR_PROC_BF534SBBC1400


#define ADI_PWR_PROC_BF537KBCZ6BVX ADI_PWR_PROC_BF537KBCZ_6AV



#elif defined(__ADSP_MOAB__)

/* The 541,542,544,549 are functionally equivalent to the 548 */


#define ADI_PWR_PROC_BF541SKBC1600 ADI_PWR_PROC_BF548SKBC1600
#define ADI_PWR_PROC_BF541SBBC1533 ADI_PWR_PROC_BF548SBBC1533
#define ADI_PWR_PROC_BF541SBBC1400 ADI_PWR_PROC_BF548SBBC1400

#define ADI_PWR_PROC_BF542SKBC1600 ADI_PWR_PROC_BF548SKBC1600
#define ADI_PWR_PROC_BF542SBBC1533 ADI_PWR_PROC_BF548SBBC1533
#define ADI_PWR_PROC_BF542SBBC1400 ADI_PWR_PROC_BF548SBBC1400

#define ADI_PWR_PROC_BF544SKBC1600 ADI_PWR_PROC_BF548SKBC1600
#define ADI_PWR_PROC_BF544SBBC1533 ADI_PWR_PROC_BF548SBBC1533
#define ADI_PWR_PROC_BF544SBBC1400 ADI_PWR_PROC_BF548SBBC1400

#define ADI_PWR_PROC_BF549SKBC1600 ADI_PWR_PROC_BF548SKBC1600
#define ADI_PWR_PROC_BF549SBBC1533 ADI_PWR_PROC_BF548SBBC1533
#define ADI_PWR_PROC_BF549SBBC1400 ADI_PWR_PROC_BF548SBBC1400


#define ADI_PWR_PROC_BF548MBBCZ_5M  ADI_PWR_PROC_BF548SBBC1533
#define ADI_PWR_PROC_BF542MBBCZ_5M  ADI_PWR_PROC_BF548MBBCZ_5M
#define ADI_PWR_PROC_BF544MBBCZ_5M  ADI_PWR_PROC_BF548MBBCZ_5M
#define ADI_PWR_PROC_BF547MBBCZ_5M  ADI_PWR_PROC_BF548MBBCZ_5M

#define ADI_PWR_PROC_BF547BBCZ_5A   ADI_PWR_PROC_BF548SBBC1533
#define ADI_PWR_PROC_BF548BBCZ_5A   ADI_PWR_PROC_BF548SBBC1533
#define ADI_PWR_PROC_BF544BBCZ_5A   ADI_PWR_PROC_BF548SBBC1533
#define ADI_PWR_PROC_BF542BBCZ_5A   ADI_PWR_PROC_BF548SBBC1533

#define ADI_PWR_PROC_BF544BBCZ_4A   ADI_PWR_PROC_BF548SBBC1400

#define ADI_PWR_PROC_BF547KBCZ_6A   ADI_PWR_PROC_BF548SKBC1600
#define ADI_PWR_PROC_BF542BBCZ_6A   ADI_PWR_PROC_BF548SKBC1600


#elif defined(__ADSP_TETON__)
/* These processor variants are functionally equivalent */

#define ADI_PWR_PROC_BF561SKB500      ADI_PWR_PROC_BF561SKBCZ500X
#define ADI_PWR_PROC_BF561SKBZ500     ADI_PWR_PROC_BF561SKBCZ500X
#define ADI_PWR_PROC_BF561SBB500      ADI_PWR_PROC_BF561SKBCZ500X
#define ADI_PWR_PROC_BF561SBBZ500     ADI_PWR_PROC_BF561SKBCZ500X
#define ADI_PWR_PROC_BF561WBBZ_5A    ADI_PWR_PROC_BF561SKBCZ500X
#define ADI_PWR_PROC_BF561SKB600      ADI_PWR_PROC_BF561SKBZ600
#define ADI_PWR_PROC_BF561SKBZ600     ADI_PWR_PROC_BF561SBB600
#define ADI_PWR_PROC_BF561SBBZ600     ADI_PWR_PROC_BF561SBB600
#define ADI_PWR_PROC_BF561SBBCZ_6A    ADI_PWR_PROC_BF561SKBCZ_6A  // except oper temp
#define ADI_PWR_PROC_BF561SKBCZ_5A    ADI_PWR_PROC_BF561SKBCZ500X
#define ADI_PWR_PROC_BF561SBBCZ_5A    ADI_PWR_PROC_BF561SKBCZ500X
#define ADI_PWR_PROC_BF561SKBCZ_5V    ADI_PWR_PROC_BF561SKBCZ500X
#define ADI_PWR_PROC_BF561SKBCZ_6V  ADI_PWR_PROC_BF561SKBCZ600X



#elif defined(__ADSP_KOOKABURRA__)

#define ADI_PWR_PROC_BF523SBBC1600  ADI_PWR_PROC_BF527SBBC1600
#define ADI_PWR_PROC_BF523SBBC1600  ADI_PWR_PROC_BF527SBBC1600

#define ADI_PWR_PROC_BF523SBBC1533  ADI_PWR_PROC_BF527SBBC1533
#define ADI_PWR_PROC_BF523SBBC1533  ADI_PWR_PROC_BF527SBBC1533

#define ADI_PWR_PROC_BF525SBBC1600  ADI_PWR_PROC_BF527SBBC1600
#define ADI_PWR_PROC_BF525SBBC1600  ADI_PWR_PROC_BF527SBBC1600

#define ADI_PWR_PROC_BF525SBBC1533  ADI_PWR_PROC_BF527SBBC1533
#define ADI_PWR_PROC_BF525SBBC1533  ADI_PWR_PROC_BF527SBBC1533


#define ADI_PWR_PROC_BF527KBCZ_6X  ADI_PWR_PROC_BF527SBBC1600
#define ADI_PWR_PROC_BF527KBCZ_6AX  ADI_PWR_PROC_BF527SBBC1600
#define ADI_PWR_PROC_BF527BBCZ_5AX  ADI_PWR_PROC_BF527SBBC1533

//#elif defined(__ADSP_MOCKINGBIRD__)


#elif defined(__ADSP_BRODIE__)

#define ADI_PWR_PROC_BF514SBBC1300  ADI_PWR_PROC_BF512SBBC1300
#define ADI_PWR_PROC_BF516SBBC1300  ADI_PWR_PROC_BF512SBBC1300
#define ADI_PWR_PROC_BF518SBBC1300  ADI_PWR_PROC_BF512SBBC1300

#define ADI_PWR_PROC_BF514SBBC1400    ADI_PWR_PROC_BF512SBBC1400
#define ADI_PWR_PROC_BF516SBBC1400  ADI_PWR_PROC_BF512SBBC1400
#define ADI_PWR_PROC_BF518SBBC1400  ADI_PWR_PROC_BF512SBBC1400


#elif defined(__ADSP_MOY__)
/* ADSP-BF504, ADSP-BF504F, and ADSP-BF506F */

#define ADI_PWR_PROC_BF504SBBC400  ADI_PWR_PROC_BF506FBSWZ_ENG
#define ADI_PWR_PROC_BF504FSBBC400 ADI_PWR_PROC_BF506FBSWZ_ENG
#define ADI_PWR_PROC_BF506SBBC400  ADI_PWR_PROC_BF506FBSWZ_ENG
#define ADI_PWR_PROC_BF506FSBBC400  ADI_PWR_PROC_BF506FBSWZ_ENG

#endif  /* end of proc variant equivalents section */




#define ADI_PWR_PACKAGE_PBGA        ADI_PWR_PACKAGE_MBGA

#ifdef _MISRA_RULES
#pragma diag(pop)
#endif /* _MISRA_RULES */

#endif  /*__ADI_PWR_H__ */
