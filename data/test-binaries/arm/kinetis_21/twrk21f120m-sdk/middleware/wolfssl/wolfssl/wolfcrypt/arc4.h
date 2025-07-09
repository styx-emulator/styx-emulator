/* arc4.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */




#ifndef WOLF_CRYPT_ARC4_H
#define WOLF_CRYPT_ARC4_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

#define WOLFSSL_ARC4_CAVIUM_MAGIC 0xBEEF0001

enum {
	ARC4_ENC_TYPE   = 4,    /* cipher unique type */
    ARC4_STATE_SIZE = 256
};

/* ARC4 encryption and decryption */
typedef struct Arc4 {
    byte x;
    byte y;
    byte state[ARC4_STATE_SIZE];
#ifdef HAVE_CAVIUM
    int    devId;           /* nitrox device id */
    word32 magic;           /* using cavium magic */
    word64 contextHandle;   /* nitrox context memory handle */
#endif
} Arc4;

WOLFSSL_API void wc_Arc4Process(Arc4*, byte*, const byte*, word32);
WOLFSSL_API void wc_Arc4SetKey(Arc4*, const byte*, word32);

#ifdef HAVE_CAVIUM
    WOLFSSL_API int  wc_Arc4InitCavium(Arc4*, int);
    WOLFSSL_API void wc_Arc4FreeCavium(Arc4*);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* WOLF_CRYPT_ARC4_H */
