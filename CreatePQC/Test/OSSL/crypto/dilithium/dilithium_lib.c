/* crypto/dilithium/dilithium_lib.c based off of crypto/dsa/dsa_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* Original version from Steven Schoch <schoch@sheba.arc.nasa.gov> */

#include <stdio.h>
#include <stdint.h>
#include "cryptlib.h"
#include <openssl/bn.h>
#include <openssl/dilithium.h>
#include <openssl/asn1.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif

#ifdef OPENSSL_FIPS
# include <openssl/fips.h>
#endif

const char DILITHIUM_version[] = "DILITHIUM" OPENSSL_VERSION_PTEXT;


DILITHIUM *DILITHIUM_new(void) {
    return DILITHIUM_new_with_engine(NULL);
}

DILITHIUM *DILITHIUM_new_with_engine(ENGINE *engine)
{
    DILITHIUM *ret;

    ret = (DILITHIUM *)OPENSSL_malloc(sizeof(DILITHIUM));
    if (ret == NULL) {
        DILITHIUMerr(DILITHIUM_F_DILITHIUM_NEW_WITH_ENGINE, DILITHIUM_R_MALLOC_FAILURE);
        return (NULL);
    }
    if (engine) {
        if (!ENGINE_init(engine)) {
            DILITHIUMerr(DILITHIUM_F_DILITHIUM_NEW_WITH_ENGINE, DILITHIUM_R_ENGINE_INIT_FAILURE);
            OPENSSL_free(ret);
            return NULL;
        }
        ret->engine = engine;
    } else {

        /*
         * It appears that there is some situation in the current setup where 
         * OpenSSL_free will NOT memset this to 0. This results in some leftover
         * value that ENGINE_finish tries to use below...
         */

        ret->engine = NULL;
    }

    ret->pad = 0;
    ret->version = 0;
    ret->write_params = 1;
    ret->parameter_set = -1;
    ret->pub_key = NULL;
    ret->priv_key = NULL;

    ret->references = 1;
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DILITHIUM, ret, &ret->ex_data);
    return (ret);
}

void DILITHIUM_free(DILITHIUM *r)
{
    int i;

    if (r == NULL)
        return;

    i = CRYPTO_add(&r->references, -1, CRYPTO_LOCK_DILITHIUM);
#ifdef REF_PRINT
    REF_PRINT("DILITHIUM", r);
#endif
    if (i > 0)
        return;
#ifdef REF_CHECK
    if (i < 0) {
        fprintf(stderr, "DILITHIUM_free, bad reference count\n");
        abort();
    }
#endif

#ifndef OPENSSL_NO_ENGINE
    if (r->engine)
        ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DILITHIUM, r, &r->ex_data);

    if (r->pub_key != NULL)
        ASN1_OCTET_STRING_free(r->pub_key);
    if (r->priv_key != NULL) {
        OPENSSL_cleanse(r->priv_key->data, (size_t)r->priv_key->length);
        ASN1_OCTET_STRING_free(r->priv_key);
    }

    OPENSSL_free(r);
}

int DILITHIUM_up_ref(DILITHIUM *r)
{
    int i = CRYPTO_add(&r->references, 1, CRYPTO_LOCK_DILITHIUM);
#ifdef REF_PRINT
    REF_PRINT("DILITHIUM", r);
#endif
#ifdef REF_CHECK
    if (i < 2) {
        fprintf(stderr, "DILITHIUM_up_ref, bad reference count\n");
        abort();
    }
#endif
    return ((i > 1) ? 1 : 0);
}

