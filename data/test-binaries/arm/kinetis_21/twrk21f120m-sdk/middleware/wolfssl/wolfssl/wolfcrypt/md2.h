/* md2.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */



#ifndef WOLF_CRYPT_MD2_H
#define WOLF_CRYPT_MD2_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_MD2

#ifdef __cplusplus
    extern "C" {
#endif

/* in bytes */
enum {
    MD2             =  6,    /* hash type unique */
    MD2_BLOCK_SIZE  = 16,
    MD2_DIGEST_SIZE = 16,
    MD2_PAD_SIZE    = 16,
    MD2_X_SIZE      = 48
};


/* Md2 digest */
typedef struct Md2 {
    word32  count;   /* bytes % PAD_SIZE  */
    byte    X[MD2_X_SIZE];
    byte    C[MD2_BLOCK_SIZE];
    byte    buffer[MD2_BLOCK_SIZE];
} Md2;


WOLFSSL_API void wc_InitMd2(Md2*);
WOLFSSL_API void wc_Md2Update(Md2*, const byte*, word32);
WOLFSSL_API void wc_Md2Final(Md2*, byte*);
WOLFSSL_API int  wc_Md2Hash(const byte*, word32, byte*);


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_MD2 */
#endif /* WOLF_CRYPT_MD2_H */
