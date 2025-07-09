/* sha256.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */



/* code submitted by raphael.huck@efixo.com */

#ifndef WOLF_CRYPT_SHA256_H
#define WOLF_CRYPT_SHA256_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_SHA256

#ifdef HAVE_FIPS
    /* for fips @wc_fips */
    #include <cyassl/ctaocrypt/sha256.h>
#endif

#if defined(FREESCALE_LTC_SHA)
    #include "fsl_ltc.h"
#elif defined(FREESCALE_LPC_SHA)
    #include "fsl_sha.h"
#endif


#ifdef __cplusplus
    extern "C" {
#endif

#ifndef HAVE_FIPS /* avoid redefinition of structs */
#ifdef WOLFSSL_PIC32MZ_HASH
    #include "port/pic32/pic32mz-crypt.h"
#endif

/* in bytes */
enum {
    SHA256              =  2,   /* hash type unique */
    SHA256_BLOCK_SIZE   = 64,
    SHA256_DIGEST_SIZE  = 32,
    SHA256_PAD_SIZE     = 56
};

#ifndef WOLFSSL_TI_HASH

/* Sha256 digest */
#ifndef FREESCALE_SHA256_STRUCT_ALT
typedef struct Sha256 {
    #if defined(FREESCALE_LTC_SHA)
        ltc_hash_ctx_t ctx;
    #elif defined(FREESCALE_LPC_SHA)
        sha_ctx_t ctx;
    #else
        word32  buffLen;   /* in bytes          */
        word32  loLen;     /* length in bytes   */
        word32  hiLen;     /* length in bytes   */
        word32  digest[SHA256_DIGEST_SIZE / sizeof(word32)];
        word32  buffer[SHA256_BLOCK_SIZE  / sizeof(word32)];
        #ifdef WOLFSSL_PIC32MZ_HASH
        pic32mz_desc desc ; /* Crypt Engine descriptor */
        #endif
    #endif /* FREESCALE_LTC_SHA */
} Sha256;
#else
typedef struct Sha256 Sha256;
#endif /* FREESCALE_SHA256_STRUCT_ALT */

#else /* WOLFSSL_TI_HASH */
    #include "wolfssl/wolfcrypt/port/ti/ti-hash.h"
#endif

#endif /* HAVE_FIPS */

WOLFSSL_API int wc_InitSha256(Sha256*);
WOLFSSL_API int wc_Sha256Update(Sha256*, const byte*, word32);
WOLFSSL_API int wc_Sha256Final(Sha256*, byte*);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_SHA256 */
#endif /* WOLF_CRYPT_SHA256_H */
