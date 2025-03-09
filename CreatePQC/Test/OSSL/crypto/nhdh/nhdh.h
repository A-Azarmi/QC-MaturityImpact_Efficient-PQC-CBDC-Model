/* crypto/nhdh/nhdh.h loosly based crypto/dsa/dsa.h */
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

#ifndef HEADER_NHDH_H
# define HEADER_NHDH_H

# include <openssl/e_os2.h>

# if defined(OPENSSL_NO_NHDH)
#  error NewHope Family is disabled.
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

#define set_parameter_set_ctrl_string "parameter_set"
#define EVP_PKEY_CTRL_NHDH_ROLE_SET (EVP_PKEY_ALG_CTRL + 1)
#define EVP_PKEY_CTRL_NHDH_PARAMETER_SET (EVP_PKEY_ALG_CTRL + 2)

/*
 * Although NHDH currently has only one parameter, the following macro is
 * added to facilitate NHDH TLS parameter negotiation.
 */
#define NHDH_1024_V0 1

struct nhdh_st {
    /*
     * This first variable is used to pick up errors where a NHDH is passed
     * instead of a EVP_PKEY
     */
    int pad;
    long version;
    int write_params;
    unsigned int flags;

    int nid;
    int initiator;

    /* After information generation, if I'm the initiator, then my_public_key
     * will point to the public key created by libcrypto.  If I'm the responder,
     * it will remain untouched.
     *
     * After secret generation, if I'm the initiator, then my_public_key will
     * be untouched.  If I'm the responder, it will point to the public key
     * created by libcrypto.
     *
     * Note that since libcrypto is providing what my_public_key points to,
     * libcrypto will own that memory.  To be as explicit as possible, you, the
     * user, are expected to not manage the memory.
     */
    ASN1_OCTET_STRING *my_public_key;

    /* NHDH parameter.  Please see the spec. */
    long parameter_set;

    int references;

    /* not sure we even need this */
    CRYPTO_EX_DATA ex_data;

    /* functional reference if 'meth' is ENGINE-provided */
    ENGINE *engine;
};

NHDH *NHDH_new(void);
NHDH *NHDH_new_with_engine(ENGINE *engine);
void NHDH_free(NHDH *r);
int NHDH_up_ref(NHDH *r);

/* I don't think i2d and d2i are required as NHDH enforces ephermeralness
 * therefore nothing is to be saved. I don't think we need any of the
 * ex_ stuff either.  No params, so no param printing either. 
 * 
 * On the other hand, public keys get passed around in TLS buffers and then
 * then are supposed to be paired up with the peer key via
 * EVP_PKEY_derive_set_peer().  This can only happen if the public key as a
 * buffer can be transformed into a EVP_PKEY.  This would suggest that we
 * require ameth methods for the public keys.
 */

/* ASN.1 for public key
 * Expanded version of DECLARE_ASN1_ENCODE_FUNCTIONS_const(NHDH, NHDHPublicKey)
 */
NHDH *d2i_NHDHPublicKey(NHDH **a, const unsigned char **pp, long length);
int i2d_NHDHPublicKey(const NHDH *a, unsigned char **pp);

/* BEGIN ERROR CODES */
/*
 * The following lines are auto generated by the script mkerr.pl. Any changes
 * made after this point may be overwritten when the script is next run.
 */
void ERR_load_NHDH_strings(void);

/* Error codes for the NHDH functions. */

/* Function codes. */
# define NHDH_F_NHDH_NEW_WITH_ENGINE                          100

/* Reason codes. */
# define NHDH_R_ENGINE_INIT_FAILURE                         100
# define NHDH_R_MALLOC_FAILURE                              101

#ifdef  __cplusplus
}
#endif
#endif
