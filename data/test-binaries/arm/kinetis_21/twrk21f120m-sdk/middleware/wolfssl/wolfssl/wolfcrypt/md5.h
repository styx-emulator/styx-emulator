/* md5.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */



#ifndef WOLF_CRYPT_MD5_H
#define WOLF_CRYPT_MD5_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_MD5

#ifdef HAVE_FIPS
    #define wc_InitMd5   InitMd5
    #define wc_Md5Update Md5Update
    #define wc_Md5Final  Md5Final
    #define wc_Md5Hash   Md5Hash
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* in bytes */
enum {
#ifdef STM32F2_HASH
    MD5_REG_SIZE    =  4,      /* STM32 register size, bytes */
#endif
    MD5             =  0,      /* hash type unique */
    MD5_BLOCK_SIZE  = 64,
    MD5_DIGEST_SIZE = 16,
    MD5_PAD_SIZE    = 56
};

#if defined(WOLFSSL_PIC32MZ_HASH)
#include "port/pic32/pic32mz-crypt.h"
#endif

#ifndef WOLFSSL_TI_HASH

/* MD5 digest */
typedef struct Md5 {
    word32  buffLen;   /* in bytes          */
    word32  loLen;     /* length in bytes   */
    word32  hiLen;     /* length in bytes   */
    word32  buffer[MD5_BLOCK_SIZE  / sizeof(word32)];
    #if !defined(WOLFSSL_PIC32MZ_HASH)
    word32  digest[MD5_DIGEST_SIZE / sizeof(word32)];
    #else
    word32  digest[PIC32_HASH_SIZE / sizeof(word32)];
    pic32mz_desc desc ; /* Crypt Engine descriptor */
    #endif
} Md5;

#else /* WOLFSSL_TI_HASH */
    #include "wolfssl/wolfcrypt/port/ti/ti-hash.h"
#endif

WOLFSSL_API void wc_InitMd5(Md5*);
WOLFSSL_API void wc_Md5Update(Md5*, const byte*, word32);
WOLFSSL_API void wc_Md5Final(Md5*, byte*);
WOLFSSL_API int  wc_Md5Hash(const byte*, word32, byte*);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_MD5 */
#endif /* WOLF_CRYPT_MD5_H */
