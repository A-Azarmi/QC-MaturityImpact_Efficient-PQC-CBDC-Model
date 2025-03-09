/* crypto/rainbow/rainbow.h based off of crypto/dsa/dsa.h */
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

/*
 * The DSS routines are based on patches supplied by
 * Steven Schoch <schoch@sheba.arc.nasa.gov>.  He basically did the
 * work and I have just tweaked them a little to fit into my
 * stylistic vision for SSLeay :-) */

#ifndef HEADER_RAINBOW_H
# define HEADER_RAINBOW_H

# include <openssl/e_os2.h>

# ifdef OPENSSL_NO_RAINBOW
#  error RAINBOW is disabled.
# endif

# ifndef OPENSSL_NO_BIO
#  include <openssl/bio.h>
# endif
# include <openssl/crypto.h>
# include <openssl/ossl_typ.h>

#include <openssl/asn1.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define EVP_PKEY_CTRL_RAINBOW_PARAMETER_SET (EVP_PKEY_ALG_CTRL + 2)
#define set_parameter_set_ctrl_string       "parameter_set"

#define RAINBOW_IIIC_STD_R2                 1
#define RAINBOW_VC_STD_R2                   2

struct rainbow_st {
    /* This first variable is used to pick up errors where a RAINBOW is passed
     * instead of a EVP_PKEY. These first 2 members are standard for all
     *  the algorithms.
     */
    int pad;
    long version;

    /* The parameters of RAINBOW.  Please see the spec */
    long parameter_set;

    /* public key */
    ASN1_OCTET_STRING *pub_key;
    /* private key */
    ASN1_OCTET_STRING *priv_key;

    int flags;
    int references;

    CRYPTO_EX_DATA ex_data;

    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
};

/* memory management methods for the RAINBOW struct */
RAINBOW *RAINBOW_new(void);
RAINBOW *RAINBOW_new_with_engine(ENGINE *engine);
void RAINBOW_free(RAINBOW *r);
int RAINBOW_up_ref(RAINBOW *r);

/* ASN.1 for public key */
RAINBOW *d2i_RAINBOWPublicKey(RAINBOW **a, const unsigned char **pp, long length);
int i2d_RAINBOWPublicKey(const RAINBOW *a, unsigned char **pp);

/* ASN.1 for private key */
RAINBOW *d2i_RAINBOWPrivateKey(RAINBOW **a, const unsigned char **pp, long length);
int i2d_RAINBOWPrivateKey(const RAINBOW *a, unsigned char **pp);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_RAINBOW_strings(void);

/* Error codes for the RAINBOW functions. */

/* Function codes. */
# define RAINBOW_F_RAINBOW_NEW_WITH_ENGINE                        100

/* Reason codes. */
# define RAINBOW_R_ENGINE_INIT_FAILURE                        100
# define RAINBOW_R_MALLOC_FAILURE                             101

#ifdef  __cplusplus
}
#endif
#endif
