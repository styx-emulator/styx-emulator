
// define devices
#define __ADSPBF512__
#define __ADSPBF51x__
#define __ADSPLPBLACKFIN__
#define __ADSPBLACKFIN__

// _LANGUAGE_C gives us bit structs
#define _LANGUAGE_C

// avoid building things that require compiler builtins
#define __DEFINED_DIVQ
#define __NO_BUILTIN
#define __TIME_DEFINED

// need this for services.h to include defBF5xx.h
#define __ECC__

#include <services/services.h>
#include <drivers/adi_dev.h>

#include <drivers/sport/adi_sport.h>
