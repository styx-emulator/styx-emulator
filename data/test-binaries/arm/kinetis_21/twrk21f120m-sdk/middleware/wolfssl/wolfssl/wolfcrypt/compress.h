/* compress.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.  All rights reserved.
 *
 * This file is part of wolfSSL.
 *
 * Contact licensing@wolfssl.com with any questions or comments.
 *
 * http://www.wolfssl.com
 */



#ifndef WOLF_CRYPT_COMPRESS_H
#define WOLF_CRYPT_COMPRESS_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_LIBZ

#ifdef __cplusplus
    extern "C" {
#endif


#define COMPRESS_FIXED 1


WOLFSSL_API int wc_Compress(byte*, word32, const byte*, word32, word32);
WOLFSSL_API int wc_DeCompress(byte*, word32, const byte*, word32);


#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* HAVE_LIBZ */
#endif /* WOLF_CRYPT_COMPRESS_H */
