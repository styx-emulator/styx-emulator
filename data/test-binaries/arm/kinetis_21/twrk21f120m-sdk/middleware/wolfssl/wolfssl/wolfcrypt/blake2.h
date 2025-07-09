/* blake2.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */





#ifndef WOLF_CRYPT_BLAKE2_H
#define WOLF_CRYPT_BLAKE2_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_BLAKE2

#include <wolfssl/wolfcrypt/blake2-int.h>

/* call old functions if using fips for the sake of hmac @wc_fips */
#ifdef HAVE_FIPS
    /* Since hmac can call blake functions provide original calls */
    #define wc_InitBlake2b   InitBlake2b
    #define wc_Blake2bUpdate Blake2bUpdate
    #define wc_Blake2bFinal  Blake2bFinal
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* in bytes, variable digest size up to 512 bits (64 bytes) */
enum {
    BLAKE2B_ID  = 7,   /* hash type unique */
    BLAKE2B_256 = 32   /* 256 bit type, SSL default */
};


/* BLAKE2b digest */
typedef struct Blake2b {
    blake2b_state S[1];         /* our state */
    word32        digestSz;     /* digest size used on init */
} Blake2b;


WOLFSSL_API int wc_InitBlake2b(Blake2b*, word32);
WOLFSSL_API int wc_Blake2bUpdate(Blake2b*, const byte*, word32);
WOLFSSL_API int wc_Blake2bFinal(Blake2b*, byte*, word32);



#ifdef __cplusplus
    }
#endif

#endif  /* HAVE_BLAKE2 */
#endif  /* WOLF_CRYPT_BLAKE2_H */
