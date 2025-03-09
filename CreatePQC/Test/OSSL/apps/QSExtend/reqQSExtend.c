/** @file reqQSExtend.c Load QS keypair and traditional CSR and use them to create multiple public key algorithm CSR.
 *
 * @copyright Copyright (C) 2017-2019, ISARA Corporation, All Rights Reserved.
 */

/* Modified.  Was genpkey.c.
 */

/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../apps/apps.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

static X509_ATTRIBUTE *create_SAPKI_ATTRIBUTE(SUBJECT_ALT_PUBLIC_KEY_INFO *sapki) {
    unsigned char *p = NULL;
    unsigned char *data = NULL;
    ASN1_STRING *astr = NULL;
    int i = 0;
    X509_ATTRIBUTE *attr = NULL;

    i = i2d_SUBJECT_ALT_PUBLIC_KEY_INFO(sapki, NULL);
    if (i < 0) {
        fprintf(stderr, "Failed to get ASN.1 size of SAPKI attribute.\n");
        goto end;
    }

    data = OPENSSL_malloc(i);
    if (data == NULL) {
        fprintf(stderr, "Memory failure during SAPKI attribute creation.\n");
        goto end;
    }

    p=data;
    i = i2d_SUBJECT_ALT_PUBLIC_KEY_INFO(sapki, &p);
    if (i < 0) {
        fprintf(stderr, "Failed to ASN.1 encode the SAPKI attribute.\n");
        goto end;
    }

    astr = ASN1_STRING_new();
    if (!ASN1_STRING_set(astr, data, i)) {
        ASN1_STRING_free(astr);
        fprintf(stderr, "Failed to alloc/set string for SAPKI attribute.\n");
        goto end;
    }

    attr = X509_ATTRIBUTE_create(NID_subjectAltPublicKeyInfo, V_ASN1_SEQUENCE, astr);
    if (attr == NULL) {
        ASN1_STRING_free(astr);
        fprintf(stderr, "Failed to create the SAPKI attribute.\n");
        goto end;
    }

end:
    OPENSSL_free(data);
    return attr;
}

static X509_ATTRIBUTE *create_ALTSIG_ATTRIBUTE(ASN1_BIT_STRING *altsig) {
    X509_ATTRIBUTE *attr = NULL;

    attr = X509_ATTRIBUTE_create(NID_altSignatureValue, V_ASN1_BIT_STRING, altsig);
    if (attr == NULL) {
        fprintf(stderr, "Failed to create the ALTSIG attribute.\n");
        goto end;
    }

end:
    return attr;
}

static X509_ATTRIBUTE *create_ALTSIGALG_ATTRIBUTE(X509_ALGOR *altsigalg) {
    X509_ATTRIBUTE *attr = NULL;
    unsigned char *p = NULL;
    unsigned char *data = NULL;
    ASN1_STRING *astr = NULL;
    int i = 0;

    i = i2d_X509_ALGOR(altsigalg, NULL);
    if (i < 0) {
        fprintf(stderr, "Failed to get ASN.1 size of ALTSIGALG attribute.\n");
        goto end;
    }

    data = OPENSSL_malloc(i);
    if (data == NULL) {
        fprintf(stderr, "Memory failure during ALTSIGALG attribute creation.\n");
        goto end;
    }

    p=data;
    i = i2d_X509_ALGOR(altsigalg, &p);
    if (i < 0) {
        fprintf(stderr, "Failed to ASN.1 encode the ALTSIGALG attribute.\n");
        goto end;
    }

    astr = ASN1_STRING_new();
    if (!ASN1_STRING_set(astr, data, i)) {
        fprintf(stderr, "Failed to alloc/set string for ALTSIGALG attribute.\n");
        ASN1_STRING_free(astr);
        goto end;
    }

    attr = X509_ATTRIBUTE_create(NID_altSignatureAlgorithm, V_ASN1_SEQUENCE, astr);
    if (attr == NULL) {
        ASN1_STRING_free(astr);
        fprintf(stderr, "Failed to create the ALTSIGALG attribute.\n");
        goto end;
    }

end:
    OPENSSL_free(data);
    return attr;
}

#undef PROG
#define PROG    reqQSExtend_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    char **args = NULL;
    int badarg = 0;
    int ret = 1;
    char *passin = NULL;
    char *pass_qs = NULL;
    char *passargin = NULL;
    char *passarg_qs = NULL;

    ENGINE *e = NULL;
    EVP_PKEY_CTX *tmpctx = NULL;
    EVP_PKEY *pkey_qs_priv = NULL;
    EVP_PKEY *pkey_qs_pub = NULL;
    EVP_PKEY *classical_privkey = NULL;

    int qs_pub_key_ind = -1;
    int qs_sigval_ind = -1;
    int qs_sigalg_ind = -1;
    int qs_key_format = FORMAT_PEM;

    BIO *bio_reqin = NULL;
    BIO *bio_reqout = NULL;
    BIO *bio_privqsout = NULL;

    const char *file_priv = NULL;
    const char *file_qs_pub = NULL;
    const char *file_qs_priv = NULL;
    const char *file_reqin = NULL;
    const char *file_reqout = NULL;
    char *file_qs_priv_out = NULL;

    X509_REQ *req = NULL;
    ASN1_BIT_STRING *qs_sigval_as_asn1bitstring = NULL;

    X509_ALGOR *qssig_algor = NULL;
    ASN1_BIT_STRING *qssig = NULL;
    X509_ATTRIBUTE *attr_qssig = NULL;

    X509_ATTRIBUTE *attr_qssigalg = NULL;

    X509_PUBKEY *x509_pub_qs = NULL;
    X509_PUBKEY *x509_sig_qs = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki = NULL;
    X509_ATTRIBUTE *attr_sapki = NULL;

    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);

    const EVP_CIPHER *cipher = NULL;

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

    if (!load_config(bio_err, NULL))
        goto end;

    CRYPTO_malloc_debug_init();
    CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    ERR_load_crypto_strings();
    ENGINE_load_dynamic();

    args = argv + 1;
    while (!badarg && *args && *args[0] == '-') {
        if (strcmp(*args, "-engine") == 0) {
            if (!args[1])
                goto bad;
            e = setup_engine(bio_err, *(++args), 0);
        } else if (strcmp(*args, "-reqin") == 0) {
            if (!args[1])
                goto bad;
            file_reqin = *(++args);
        } else if (strcmp(*args, "-reqout") == 0) {
            if (!args[1])
                goto bad;
            file_reqout = *(++args);
        } else if (strcmp(*args, "-privin") == 0) {
            if (!args[1])
                goto bad;
            file_priv = *(++args);
        } else if (strcmp(*args, "-pubqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_pub = *(++args);
        } else if (strcmp(*args, "-privqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_priv = *(++args);
        } else if (strcmp(*args, "-privqs_engine") == 0) {
            qs_key_format = FORMAT_ENGINE;
        } else if (strcmp(*args, "-passin") == 0) {
            if (--argc < 1)
                goto bad;
            passargin = *(++args);
        } else if (strcmp(*args, "-passqs") == 0) {
            if (--argc < 1)
                goto bad;
            passarg_qs = *(++args);
        } else {
            cipher = EVP_get_cipherbyname(*args + 1);
            if (cipher == NULL) {
                BIO_printf(bio_err, "Unknown cipher %s\n", *args + 1);
                badarg = 1;
            }
        }
        args++;
    }

    if (file_priv == NULL)
        badarg = 1;

    if (file_reqin == NULL)
        badarg = 1;

    if (file_reqout == NULL)
        badarg = 1;

    if (file_qs_priv == NULL)
        badarg = 1;

    if (badarg) {
bad:
        BIO_printf(bio_err, "Usage: openssl reqQSExtend [options]\n");
        BIO_printf(bio_err, "where options may be\n");
        BIO_printf(bio_err,
                   "-engine e          Use IQR Engine library <e>.\n");
        BIO_printf(bio_err,
                   "-reqin file        The CSR in pem format.\n");
        BIO_printf(bio_err,
                   "-reqout file       The CSR in pem format with new ALT extensions.\n");
        BIO_printf(bio_err,
                   "-privin file       The private key used to sign the original CSR in pem format.\n");
        BIO_printf(bio_err,
                   "-pubqs file        The public QS key.\n");
        BIO_printf(bio_err,
                   "-privqs file       The private QS key. Will be rewritten to contain the classical key and QS key.\n");
        BIO_printf(bio_err,
                   "-privqs_engine     The private QS key should be loaded via the engine. Optional.\n");
        BIO_printf(bio_err,
                   "-passin            The private key password source. Optional.\n");
        BIO_printf(bio_err,
                   "-passqs            The private QS key password source. Optional.\n");
        BIO_printf(bio_err,
                   "-<cipher>          Use cipher <cipher> to encrypt the key. Optional.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passargin, NULL, &passin, NULL)) {
        BIO_printf(bio_err, "Error getting password for the private key.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passarg_qs, NULL, &pass_qs, NULL)) {
        BIO_printf(bio_err, "Error getting password for the QS private key.\n");
        goto end;
    }

    /* Read in the the classical req. */
    bio_reqin = BIO_new_file(file_reqin, "rb");
    req = PEM_read_bio_X509_REQ(bio_reqin, NULL, NULL, NULL);
    if (req == NULL) {
        BIO_printf(bio_err, "Bad CSR\n");
        goto end;
    }
    BIO_free_all(bio_reqin);
    bio_reqin = NULL;

    /* Ensure this certificate signing request does not already have alternative
     * attributes.
     */
    qs_pub_key_ind = X509_REQ_get_attr_by_NID(req, NID_subjectAltPublicKeyInfo, -1);
    qs_sigval_ind = X509_REQ_get_attr_by_NID(req, NID_altSignatureValue, -1);
    qs_sigalg_ind = X509_REQ_get_attr_by_NID(req, NID_altSignatureAlgorithm, -1);
    if ((qs_pub_key_ind != -1) || (qs_sigalg_ind != -1) || (qs_sigval_ind != -1)) {
        BIO_puts(bio_err, "The input certificate signing request already has alternative attributes.\n");
        goto end;
    }

    /* Read in the classical private key.  We'll need it to sign the
     * QS req again.
     */
    classical_privkey = load_key(bio_err, file_priv, FORMAT_PEM, 0, passin, e, "Classical Private Key");
    if (classical_privkey == NULL) {
        /* load_key() has already printed an appropriate message. */
        goto end;
    }

    /* Read in the QS private key so we can create a QS signature */
    pkey_qs_priv = load_key(bio_err, file_qs_priv, qs_key_format, 0, pass_qs, e, "QS Private Key");
    if (pkey_qs_priv == NULL) {
        /* load_key() has already printed an appropriate message. */
        goto end;
    }

    /* Ensure the private key is actually a QS key */
    if (!EVP_PKEY_is_QS_auth(EVP_PKEY_id(pkey_qs_priv))) {
        BIO_puts(bio_err, "The provided private key is not compatible with a quantum-safe algorithm.\n");
        goto end;
    }

    /* Read the QS Public key to be embedded in the QS req if it was specified.
     * If not check the private key.
     */
    if (file_qs_pub == NULL) {
        pkey_qs_pub = pkey_qs_priv;
    } else {
        pkey_qs_pub = load_pubkey(bio_err, file_qs_pub, FORMAT_PEM, 0, NULL, e, "QS Public Key");
        if (pkey_qs_pub == NULL) {
            /* load_pubkey() has already printed an appropriate message. */
            goto end;
        }
    }

    /* Ensure the public key is actually a QS key */
    if (!EVP_PKEY_is_QS_auth(EVP_PKEY_id(pkey_qs_pub))) {
        BIO_puts(bio_err, "The provided public key is not compatible with a quantum-safe algorithm.\n");
        goto end;
    }

    /* Convert the private key into an x509 public key.  This lets us
     * get the algorithm identifier of the private key so we can associate
     * it with the signature.
     */
    X509_PUBKEY_set(&x509_sig_qs, pkey_qs_priv);

    /* Convert the pkey in to an x509 public key.  This is the standard way
     * of doing it for x509 subject public key.
     */
    X509_PUBKEY_set(&x509_pub_qs, pkey_qs_pub);

    sapki = SUBJECT_ALT_PUBLIC_KEY_INFO_new();
    if (sapki == NULL) {
        BIO_puts(bio_err, "Error converting public key to x509 pubkey\n");
        goto end;
    }

    X509_ALGOR_free(sapki->algor);
    ASN1_BIT_STRING_free(sapki->public_key);

    sapki->algor = x509_pub_qs->algor;
    sapki->public_key = x509_pub_qs->public_key;

    /* Create and insert QS public key as an extension */
    attr_sapki = create_SAPKI_ATTRIBUTE(sapki);
    sapki->algor = NULL;
    sapki->public_key = NULL;
    if (attr_sapki == NULL) {
        BIO_puts(bio_err, "Error converting x509 pubkey to extension.\n");
        goto end;
    }

    /* Add the ALT public key extension so the signing process includes it.
     */
    if (X509_REQ_add1_attr(req, attr_sapki) == 0) {
        BIO_puts(bio_err, "Error adding public key as extension\n");
        goto end;
    }

    qssig_algor = X509_ALGOR_dup(x509_sig_qs->algor);
    if (qssig_algor == NULL) {
        BIO_puts(bio_err, "Error duplicating signature algor.\n");
        goto end;
    }

    if (X509_ALGOR_set0(qssig_algor, OBJ_nid2obj(EVP_PKEY_id(pkey_qs_priv)), ASN1_get_sigparam(pkey_qs_priv), NULL) == 0) {
        BIO_puts(bio_err, "Error setting algorithm object ID.\n");
        goto end;
    }

    attr_qssigalg = create_ALTSIGALG_ATTRIBUTE(qssig_algor);

    /* Add the ALT signature algorithm extension so the signing process includes it.
     */
    if (X509_REQ_add1_attr(req, attr_qssigalg) == 0) {
        BIO_puts(bio_err, "Error adding signature algorithm as extension\n");
        goto end;
    }

    req->req_info->enc.modified = 1;

    /* Sign the req with the QS private key. */
    if (EVP_DigestSignInit(&mctx, NULL, NULL, NULL, pkey_qs_priv) < 1) {
        BIO_puts(bio_err, "Error doing EVP digest initialization\n");
        goto end;
    }

    /* Prepare an ASN1 bit string for the ALT signature extension. */
    qs_sigval_as_asn1bitstring = ASN1_BIT_STRING_new();
    if (qs_sigval_as_asn1bitstring == NULL) {
         BIO_puts(bio_err, "ASN1 bit string memory allocation error.\n");
         goto end;
    }

    if (ASN1_item_sign_ctx(ASN1_ITEM_rptr(X509_REQ_INFO), NULL, NULL, qs_sigval_as_asn1bitstring, req->req_info, &mctx) <= 0) {
        BIO_puts(bio_err, "Quantum-safe signing operation failed.\n");
        goto end;
    }

    qs_sigval_as_asn1bitstring->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    qs_sigval_as_asn1bitstring->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    attr_qssig = create_ALTSIG_ATTRIBUTE(qs_sigval_as_asn1bitstring);
    if (attr_qssig == NULL) {
        BIO_puts(bio_err, "Error creating signature extension.\n");
        goto end;
    }
    qs_sigval_as_asn1bitstring = NULL;

    if (X509_REQ_add1_attr(req, attr_qssig) == 0) {
        BIO_puts(bio_err, "Error adding signature as extension\n");
        goto end;
    }

    req->req_info->enc.modified = 1;

    /* Re-sign the req with the original classical private key. */
    if (X509_REQ_sign(req, classical_privkey, NULL) == 0) {
        BIO_puts(bio_err, "Error generating classical signature.\n");
        goto end;
    }

    /* Write the new signed req with extensions in it. */
    bio_reqout = BIO_new_file(file_reqout, "wb");
    if (PEM_write_bio_X509_REQ(bio_reqout, req) == 0) {
        BIO_puts(bio_err, "Error writing new CSR.\n");
        goto end;
    }

    if (qs_key_format == FORMAT_ENGINE) {
        char *tmp = strstr(file_qs_priv, "::");
        if (tmp == NULL) {
            BIO_puts(bio_err, "Engine private key, but no state separator (::).\n");
            goto end;
        }

        file_qs_priv_out = OPENSSL_malloc((int)(tmp - file_qs_priv + 1));
        if (file_qs_priv_out == NULL) {
            BIO_puts(bio_err, "Memory allocation failure.\n");
            goto end;
        }

        memcpy(file_qs_priv_out, file_qs_priv, tmp - file_qs_priv);
        file_qs_priv_out[tmp - file_qs_priv] = '\0';
        bio_privqsout = BIO_new_file(file_qs_priv_out, "wb");
    } else {
        bio_privqsout = BIO_new_file(file_qs_priv, "wb");
    }

    /* Write the combined private key.  Encrypt BOTH with the QS password. */
    if (PEM_write_bio_PKCS8PrivateKey(bio_privqsout, classical_privkey, cipher, NULL, 0, NULL, pass_qs) == 0) {
        BIO_puts(bio_err, "Error writing classical private key to the combined file.\n");
        goto end;
    }

    if (PEM_write_bio_ALT_PKCS8PrivateKey(bio_privqsout, pkey_qs_priv, cipher, NULL, 0, NULL, pass_qs) == 0) {
        BIO_puts(bio_err, "Error writing QS private key to the combined file.\n");
        goto end;
    }

    ret = 0;

 end:
    if (ret != 0)
        ERR_print_errors(bio_err);

    EVP_MD_CTX_cleanup(&mctx);
    if (tmpctx)
        EVP_PKEY_CTX_free(tmpctx);
    if (bio_reqin)
        BIO_free_all(bio_reqin);
    if (bio_privqsout)
        BIO_free_all(bio_privqsout);
    if (bio_reqout)
        BIO_free_all(bio_reqout);
    if (req)
        X509_REQ_free(req);
    if (pkey_qs_pub == pkey_qs_priv)
        pkey_qs_pub = NULL;
    if (pkey_qs_pub)
        EVP_PKEY_free(pkey_qs_pub);
    if (pkey_qs_priv)
        EVP_PKEY_free(pkey_qs_priv);
    if (classical_privkey)
        EVP_PKEY_free(classical_privkey);
    if (x509_pub_qs)
        X509_PUBKEY_free(x509_pub_qs);
    if (x509_sig_qs)
        X509_PUBKEY_free(x509_sig_qs);
    if (qssig_algor)
        X509_ALGOR_free(qssig_algor);
    if (sapki)
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki);
    if (qssig)
        ASN1_BIT_STRING_free(qssig);
    if (file_qs_priv_out)
        OPENSSL_free(file_qs_priv_out);

    /* Note that we use OPENSSL_malloc() to allocate these so we don't use
     * the custom free functions to free them.
     */
    if (qs_sigval_as_asn1bitstring)
        ASN1_BIT_STRING_free(qs_sigval_as_asn1bitstring);
    if (attr_sapki)
        X509_ATTRIBUTE_free(attr_sapki);
    if (attr_qssig)
        X509_ATTRIBUTE_free(attr_qssig);
    if (attr_qssigalg)
        X509_ATTRIBUTE_free(attr_qssigalg);

    if (passargin && passin)
        OPENSSL_free(passin);
    if (passarg_qs && pass_qs)
        OPENSSL_free(pass_qs);
    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

