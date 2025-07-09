/* fips_test.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */




#ifndef WOLF_CRYPT_FIPS_TEST_H
#define WOLF_CRYPT_FIPS_TEST_H

#include <cyassl/ctaocrypt/types.h>


#ifdef __cplusplus
    extern "C" {
#endif

/* Known Answer Test string inputs are hex, internal */
CYASSL_LOCAL int DoKnownAnswerTests(char*, int);


/* FIPS failure callback */
typedef void(*wolfCrypt_fips_cb)(int ok, int err, const char* hash);

/* Public set function */
CYASSL_API int wolfCrypt_SetCb_fips(wolfCrypt_fips_cb cbf);

/* Public get status functions */
CYASSL_API int wolfCrypt_GetStatus_fips(void);
CYASSL_API const char* wolfCrypt_GetCoreHash_fips(void);

#ifdef HAVE_FORCE_FIPS_FAILURE
    /* Public function to force failure mode for operational testing */
    CYASSL_API int wolfCrypt_SetStatus_fips(int);
#endif


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_FIPS_TEST_H */
