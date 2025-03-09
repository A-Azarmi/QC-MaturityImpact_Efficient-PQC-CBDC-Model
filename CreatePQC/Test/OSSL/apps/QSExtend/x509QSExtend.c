/** @file x509QSExtend.c Load QS CSR and traditional X.509 certificate and use them to create a multiple public key algorithm certificate.
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
#include <openssl/asn1_mac.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/x509v3.h>

static SUBJECT_ALT_PUBLIC_KEY_INFO *get_SAPKI_from_ATTRIBUTE(X509_ATTRIBUTE *attr) {

    ASN1_TYPE *so = NULL;
    ASN1_OBJECT *o = OBJ_nid2obj(NID_subjectAltPublicKeyInfo);
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki = NULL;
    ASN1_STRING *s = NULL;
    const unsigned char *data = NULL;
    long length = 0;

    if (OBJ_cmp(attr->object, o) != 0) {
        fprintf (stderr, "Unexpected Object ID\n") ;
        goto err;
    }

    if (!attr->single && sk_ASN1_TYPE_num(attr->value.set)) {
        so = sk_ASN1_TYPE_value(attr->value.set, 0);
    } else {
        fprintf (stderr, "Attribute format error.\n") ;
        goto err;
    }

    if ((so == NULL) || (so->type != V_ASN1_SEQUENCE)) {
        fprintf (stderr, "Attribute ASN.1 format error.\n") ;
        goto err;
    }

    s = so->value.sequence;
    data = ASN1_STRING_data(s);
    length = ASN1_STRING_length(s);
    sapki = d2i_SUBJECT_ALT_PUBLIC_KEY_INFO(NULL, &data, length);
    return sapki;

err:
    return NULL;
}

static ASN1_BIT_STRING *get_ALTSIG_from_ATTRIBUTE(X509_ATTRIBUTE *attr) {

    ASN1_TYPE *so = NULL;
    ASN1_OBJECT *o = OBJ_nid2obj(NID_altSignatureValue);
    ASN1_BIT_STRING *altsig = NULL;

    if (OBJ_cmp(attr->object, o) != 0) {
        fprintf (stderr, "Unexpected Object ID\n") ;
        goto err;
    }

    if (!attr->single && sk_ASN1_TYPE_num(attr->value.set)) {
        so = sk_ASN1_TYPE_value(attr->value.set, 0);
    } else {
        fprintf (stderr, "Attribute format error.\n") ;
        goto err;
    }

    if ((so == NULL) || (so->type != V_ASN1_BIT_STRING)) {
        fprintf (stderr, "Attribute ASN.1 format error.\n") ;
        goto err;
    }

    altsig = X509_ATTRIBUTE_get0_data(attr, 0, V_ASN1_BIT_STRING, NULL);
    if (altsig == NULL) {
        fprintf (stderr, "Couldn't get ASN1 data from attribute.\n") ;
        goto err;
    }

    return altsig;

err:
    return NULL;
}

static X509_ALGOR *get_ALTSIGALG_from_ATTRIBUTE(X509_ATTRIBUTE *attr) {

    ASN1_TYPE *so = NULL;
    ASN1_OBJECT *o = OBJ_nid2obj(NID_altSignatureAlgorithm);
    X509_ALGOR *altsigalg = NULL;
    ASN1_STRING *s = NULL;
    const unsigned char *data = NULL;
    long length = 0;

    if (OBJ_cmp(attr->object, o) != 0) {
        fprintf (stderr, "Unexpected Object ID\n") ;
        goto err;
    }

    if (!attr->single && sk_ASN1_TYPE_num(attr->value.set)) {
        so = sk_ASN1_TYPE_value(attr->value.set, 0);
    } else {
        fprintf (stderr, "Attribute format error.\n") ;
        goto err;
    }

    if ((so == NULL) || (so->type != V_ASN1_SEQUENCE)) {
        fprintf (stderr, "Attribute ASN.1 format error.\n") ;
        goto err;
    }

    s = so->value.sequence;
    data = ASN1_STRING_data(s);
    length = ASN1_STRING_length(s);
    altsigalg = d2i_X509_ALGOR(NULL, &data, length);
    return altsigalg;

err:
    return NULL;
}

#undef PROG
#define PROG    x509QSExtend_main

int MAIN(int, char **);

int MAIN(int argc, char **argv)
{
    char **args = NULL;
    int badarg = 0;
    int ret = 1;
    char *passin_qs = NULL;
    char *passargin_qs = NULL;

    ENGINE *e = NULL;
    EVP_PKEY_CTX *tmpctx = NULL;
    EVP_PKEY *pkey_qs_priv = NULL;
    EVP_PKEY *pkey_qs_pub = NULL;
    EVP_PKEY *classical_privkey = NULL;
    X509_REQ *req = NULL;
    X509_REQ *tmpreq = NULL;
    EVP_PKEY *tmppkey = NULL;

    BIO *bio_x509in = NULL;
    BIO *bio_x509out = NULL;
    BIO *bio_req = NULL;
    const char *file_qs_priv = NULL;
    const char *file_x509in = NULL;
    const char *file_x509out = NULL;

    X509_ALGOR *algor_for_qssigalg = NULL;
    X509_EXTENSION *ext_qssigalg = NULL;

    X509 *cert = NULL;
    ASN1_BIT_STRING *qs_sigval_as_asn1bitstring = NULL;

    int alg_nid = -1;
    X509_EXTENSION *ext_qssig = NULL;
    X509_ALGOR *qssig_algor = NULL;

    X509_PUBKEY *x509_pub_qs = NULL;
    X509_PUBKEY *x509_sig_qs = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki_in = NULL;
    SUBJECT_ALT_PUBLIC_KEY_INFO *sapki_out = NULL;
    X509_EXTENSION *ext_sapki = NULL;

    X509_ATTRIBUTE *qs_pub_key_attr = NULL;
    int qs_pub_key_ind = -1;

    X509_ATTRIBUTE *qs_sigval_attr = NULL;
    int qs_sigval_ind = -1;
    int qs_key_format = FORMAT_PEM;

    X509_ATTRIBUTE *qs_sigalg_attr = NULL;
    int qs_sigalg_ind = -1;

    EVP_MD_CTX mctx;
    EVP_MD_CTX_init(&mctx);

    ASN1_BIT_STRING *req_qssig = NULL;
    X509_ALGOR *req_qssigalg = NULL;

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
        } else if (strcmp(*args, "-x509in") == 0) {
            if (!args[1])
                goto bad;
            file_x509in = *(++args);
        } else if (strcmp(*args, "-x509out") == 0) {
            if (!args[1])
                goto bad;
            file_x509out = *(++args);
        } else if (strcmp(*args, "-reqin") == 0) {
            if (!args[1])
                goto bad;
            bio_req = BIO_new_file(*(++args), "rb");
        } else if (strcmp(*args, "-privqs") == 0) {
            if (!args[1])
                goto bad;
            file_qs_priv = *(++args);
        } else if (strcmp(*args, "-privqs_engine") == 0) {
            qs_key_format = FORMAT_ENGINE;
        } else if (strcmp(*args, "-passinqs") == 0) {
            if (--argc < 1)
                goto bad;
            passargin_qs = *(++args);
        } else {
            badarg = 1;
        }
        args++;
    }

    if (file_x509in == NULL)
        badarg = 1;

    if (file_x509out == NULL)
        badarg = 1;

    if (bio_req == NULL)
        badarg = 1;

    if (file_qs_priv == NULL)
        badarg = 1;

    if (badarg) {
bad:
        BIO_printf(bio_err, "Usage: openssl x509QSExtend [options]\n");
        BIO_printf(bio_err, "where options may be\n");
        BIO_printf(bio_err,
                   "-engine e          Use IQR Engine library <e>.\n");
        BIO_printf(bio_err,
                   "-x509in file       The X509 certificate in pem format.\n");
        BIO_printf(bio_err,
                   "-x509out file      The X509 MPKA certificate in pem format with new ALT extensions.\n");
        BIO_printf(bio_err,
                   "-reqin file        The certificate signing request containing the ALT public key extension.\n");
        BIO_printf(bio_err,
                   "-privqs file       The private QS key. \n");
        BIO_printf(bio_err,
                   "-privqs_engine     The private QS key should be loaded via the engine. Optional.\n");
        BIO_printf(bio_err,
                   "-passinqs          The private QS key password source. Optional.\n");
        goto end;
    }

    if (!app_passwd(bio_err, passargin_qs, NULL, &passin_qs, NULL)) {
        BIO_printf(bio_err, "Error getting password for the QS private key.\n");
        goto end;
    }

    /* Read in the req which contains the public key */
    req = PEM_read_bio_X509_REQ(bio_req, NULL, NULL, NULL);
    if (req == NULL) {
        BIO_printf(bio_err, "Bad certificate signing request.\n");
        goto end;
    }

    /* Get the ALT public key attribute. */
    qs_pub_key_ind = X509_REQ_get_attr_by_NID(req, NID_subjectAltPublicKeyInfo, -1);
    if (qs_pub_key_ind < 0) {
        fprintf(stderr, "Error finding the req's ALT public key attribute.\n");
        goto end;
    }

    qs_pub_key_attr = X509_REQ_get_attr(req, qs_pub_key_ind);
    if (qs_pub_key_attr == NULL) {
        fprintf(stderr, "Error getting the req's ALT public key attribute.\n");
        goto end;
    }

    sapki_in = get_SAPKI_from_ATTRIBUTE(qs_pub_key_attr);
    if (sapki_in == NULL) {
        fprintf(stderr, "Error converting the req's ALT public key attribute into ASN.1.\n");
        goto end;
    }

    /* Convert the ALT public key attribute to a pkey. */
    x509_pub_qs = X509_PUBKEY_new();
    if (x509_pub_qs == NULL) {
        fprintf(stderr, "Memory allocation error.\n");
        goto end;
    }

    X509_ALGOR_free(x509_pub_qs->algor);
    ASN1_BIT_STRING_free(x509_pub_qs->public_key);

    x509_pub_qs->algor = sapki_in->algor;
    x509_pub_qs->public_key = sapki_in->public_key;
    x509_pub_qs->pkey = NULL;

    pkey_qs_pub = X509_PUBKEY_get(x509_pub_qs);

    x509_pub_qs->algor = NULL;
    x509_pub_qs->public_key = NULL;
    X509_PUBKEY_free(x509_pub_qs);
    x509_pub_qs = NULL;

    if (pkey_qs_pub == NULL) {
        BIO_printf(bio_err, "Bad QS public key.\n");
        goto end;
    }

    /* Get the ALT signature attribute. */
    qs_sigval_ind = X509_REQ_get_attr_by_NID(req, NID_altSignatureValue, -1);
    if (qs_sigval_ind < 0) {
        fprintf(stderr, "Error finding the req's ALT signature attribute.\n");
        goto end;
    }

    qs_sigval_attr = X509_REQ_get_attr(req, qs_sigval_ind);
    if (qs_sigval_attr == NULL) {
        fprintf(stderr, "Error getting the req's ALT signature attribute.\n");
        goto end;
    }

    /* Remove the ALT signature attribute to make it look the same as when it
     * was signed.
     */
    if (X509_REQ_delete_attr(req, qs_sigval_ind) == 0) {
        fprintf(stderr, "Error getting the req's ALT signature attribute.\n");
        goto end;
    }

    req_qssig = get_ALTSIG_from_ATTRIBUTE(qs_sigval_attr);
    if (req_qssig == NULL) {
        fprintf(stderr, "Error converting the req's ALT signature attribute into ASN.1.\n");
        goto end;
    }

    /* Get the ALT signature algorithm attribute. */
    qs_sigalg_ind = X509_REQ_get_attr_by_NID(req, NID_altSignatureAlgorithm, -1);
    if (qs_sigalg_ind < 0) {
        fprintf(stderr, "Error finding the req's ALT signature algorithm attribute index.\n");
        goto end;
    }

    qs_sigalg_attr = X509_REQ_get_attr(req, qs_sigalg_ind);
    if (qs_sigalg_attr == NULL) {
        fprintf(stderr, "Error getting the req's ALT signature algorithm attribute.\n");
        goto end;
    }

    req_qssigalg = get_ALTSIGALG_from_ATTRIBUTE(qs_sigalg_attr);
    if (req_qssigalg == NULL) {
        fprintf(stderr, "Error converting the req's ALT signature attribute into ASN.1.\n");
        goto end;
    }

    /* Ensure that the signature algorithm of the sig and the algorithm of the public key
     * match. We can't use X509_ALGOR_cmp() because the OIDs don't match. The
     * signature OID includes information about the digest. We don't worry about digest
     * and parameter mismatch as the actual verification will catch that.
     */
    if (OBJ_find_sigid_algs(OBJ_obj2nid(req_qssigalg->algorithm), NULL, &alg_nid) == 0) {
        fprintf(stderr, "Couldn't get the algorithm ID from the ALT signature.\n");
        goto end;
    }

    if (alg_nid != OBJ_obj2nid(sapki_in->algor->algorithm)) {
        fprintf(stderr, "Issuer public key algorithm does not match signature algorithm\n");
        fprintf(stderr, "Issuer: %s\n", OBJ_nid2ln(OBJ_obj2nid(sapki_in->algor->algorithm)));
        fprintf(stderr, "Current: %s\n", OBJ_nid2ln(OBJ_obj2nid(req_qssigalg->algorithm)));
        goto end;
    }

    req->req_info->enc.modified = 1;

    if (ASN1_item_verify(ASN1_ITEM_rptr(X509_REQ_INFO), req_qssigalg,
                         req_qssig, req->req_info, pkey_qs_pub) <= 0) {
        printf("QS verification FAILED!\n");
        goto end;
    }

    /* We do not do verification of the classical signature as we assume it was
     * done during the creation of the classical chain. Now that the req is
     * verified, we can construct the cert.
     */

    /* Read in the classical cert. */
    bio_x509in = BIO_new_file(file_x509in, "rb");
    cert = PEM_read_bio_X509(bio_x509in, NULL, NULL, NULL);
    if (cert == NULL) {
        BIO_printf(bio_err, "Bad certificate\n");
        goto end;
    }
    BIO_free_all(bio_x509in);
    bio_x509in = NULL;

    /* Ensure this certificate does not already have alternative extensions. */
    qs_pub_key_ind = X509_get_ext_by_NID(cert, NID_subjectAltPublicKeyInfo, -1);
    qs_sigalg_ind = X509_get_ext_by_NID(cert, NID_altSignatureAlgorithm, -1);
    qs_sigval_ind = X509_get_ext_by_NID(cert, NID_altSignatureValue, -1);
    if ((qs_pub_key_ind != -1) || (qs_sigalg_ind != -1) || (qs_sigval_ind != -1)) {
        BIO_puts(bio_err, "The input certificate already has alternative extensions.\n");
        goto end;
    }

    /* Read in the classical private key that will be used to re-sign
     * this cert. If an engine is being used to read in the private key there
     * will be extra stuff for the state.  Remove it.
     */
    if (qs_key_format == FORMAT_ENGINE) {
        char *tmp1 = strstr(file_qs_priv, "::");
        if (tmp1 == NULL) {
            BIO_puts(bio_err, "Engine private key, but no state separator (::).\n");
            goto end;
        }

        char *tmp2 = OPENSSL_malloc((int)(tmp1 - file_qs_priv + 1));
        if (tmp2 == NULL) {
            BIO_puts(bio_err, "Memory allocation failure.\n");
            goto end;
        }

        memcpy(tmp2, file_qs_priv, tmp1 - file_qs_priv);
        tmp2[tmp1 - file_qs_priv] = '\0';
        classical_privkey = load_key(bio_err, tmp2, FORMAT_PEM, 0, passin_qs, e, "Classical Private Key");
        OPENSSL_free(tmp2);
    } else {
        classical_privkey = load_key(bio_err, file_qs_priv, FORMAT_PEM, 0, passin_qs, e, "Classical Private Key");
    }

    if (classical_privkey == NULL) {
        /* load_key() has already printed an appropriate message. */
        goto end;
    }

    /* Read in the QS private key that will be used to create the QS
     * signature.
     */
    pkey_qs_priv = load_alt_key(bio_err, file_qs_priv, qs_key_format, 0, passin_qs, e, "QS Private Key");
    if (pkey_qs_priv == NULL) {
        /* load_alt_key() has already printed an appropriate message. */
        goto end;
    }

    /* Ensure the private key is actually a QS key */
    if (!EVP_PKEY_is_QS_auth(EVP_PKEY_id(pkey_qs_priv))) {
        BIO_puts(bio_err, "The provided private key is not compatible with a quantum-safe algorithm.\n");
        goto end;
    }

    /* Make sure the public key is actually QS. */
    if (!EVP_PKEY_is_QS_auth(EVP_PKEY_id(pkey_qs_pub))) {
        BIO_puts(bio_err, "The provided public key is not compatible with a quantum-safe algorithm.\n");
        goto end;
    }

    /* Convert the private key into an x509 public key.  This lets us
     * get the algorithm identifier of the private key so we can associate
     * it with the signature.
     */
    X509_PUBKEY_set(&x509_sig_qs, pkey_qs_priv);

    /* Convert the pkey into an x509 format public key. */
    X509_PUBKEY_set(&x509_pub_qs, pkey_qs_pub);

    sapki_out = SUBJECT_ALT_PUBLIC_KEY_INFO_new();
    X509_ALGOR_free(sapki_out->algor);
    ASN1_BIT_STRING_free(sapki_out->public_key);
    sapki_out->algor = x509_pub_qs->algor;
    sapki_out->public_key = x509_pub_qs->public_key;

    /* The next few blocks of code create and insert the QS signature algorithm
     * as an extension.
     */

    /* Duplicate the algorithm for the signature. */
    algor_for_qssigalg = X509_ALGOR_dup(x509_sig_qs->algor);
    if (algor_for_qssigalg == NULL) {
        BIO_puts(bio_err, "Error duplicating signature algor.\n");
        goto end;
    }

    /* Set the Object ID based on the NID and then convert into an extension. */
    if (X509_ALGOR_set0(algor_for_qssigalg, OBJ_nid2obj(EVP_PKEY_id(pkey_qs_priv)), ASN1_get_sigparam(pkey_qs_priv), NULL) == 0) {
        BIO_puts(bio_err, "Error setting algorithm object ID.\n");
        goto end;
    }

    ext_qssigalg = X509V3_EXT_i2d(NID_altSignatureAlgorithm, 0, algor_for_qssigalg);
    if (ext_qssigalg == NULL) {
        BIO_puts(bio_err, "Error creating signature algorithm extension.\n");
        goto end;
    }

    /* Insert QS signature algorithm as an extension. */
    if (X509_add_ext(cert, ext_qssigalg, -1) == 0) {
        BIO_puts(bio_err, "Error adding signature algorithm extension.\n");
        goto end;
    }

    /* Create and insert QS public key as an extension. */
    ext_sapki = X509V3_EXT_i2d(NID_subjectAltPublicKeyInfo, 0, sapki_out);
    sapki_out->algor = NULL;
    sapki_out->public_key = NULL;
    if (ext_sapki == NULL) {
        BIO_puts(bio_err, "Error converting x509 pubkey to extension.\n");
        goto end;
    }

    /* Add the ALT public key extension to the cert. */
    if (X509_add_ext(cert, ext_sapki, -1) == 0) {
        BIO_puts(bio_err, "Error adding public key as extension\n");
        goto end;
    }

    /* Sign the cert with the QS private key. */
    if (EVP_DigestSignInit(&mctx, NULL, NULL, NULL, pkey_qs_priv) < 1) {
        BIO_puts(bio_err, "Error doing EVP digest initialization\n");
        goto end;
    }

    /* We could call X509_sign_ctx() here, but the following code in
     * ASN1_item_sign_ctx() made that a bad idea:
     *
     *   if (algor1)
     *       X509_ALGOR_set0(algor1, OBJ_nid2obj(signid), paramtype, NULL);
     *   if (algor2)
     *       X509_ALGOR_set0(algor2, OBJ_nid2obj(signid), paramtype, NULL);
     *
     * Those lines were modifying AlgorithmIdentifier in the X509 cert.
     * That would change the resulting digest result which is a side effect
     * we would like to avoid.
     *
     * X509_sign_ctx() just sets the modified flag and calls
     * ASN1_item_sign_ctx().  We can do that and instead of passing the
     * algors, we just pass NULL and a custom signature BISTRING.
     */

    cert->cert_info->enc.modified = 1;

    qs_sigval_as_asn1bitstring = ASN1_BIT_STRING_new();
    if (qs_sigval_as_asn1bitstring == NULL) {
         BIO_puts(bio_err, "ASN1 bit string memory allocation error.\n");
         goto end;
    }

    if (ASN1_item_sign_ctx(ASN1_ITEM_rptr(X509_PCINF), NULL, NULL, qs_sigval_as_asn1bitstring, cert->cert_info, &mctx) <= 0) {
        BIO_puts(bio_err, "Quantum-safe signing operation failed.\n");
        goto end;
    }

    qs_sigval_as_asn1bitstring->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    qs_sigval_as_asn1bitstring->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    /* Create QS signature as an extension. */
    ext_qssig = X509V3_EXT_i2d(NID_altSignatureValue, 0, qs_sigval_as_asn1bitstring);
    if (ext_qssig == NULL) {
        BIO_puts(bio_err, "Error creating signature extension.\n");
        goto end;
    }

    /* Insert QS signature as an extension. */
    if (X509_add_ext(cert, ext_qssig, -1) == 0) {
        BIO_puts(bio_err, "Error adding signature extension\n");
        goto end;
    }

    /* Re-sign the certificate with the original classical private key. */
    if (X509_sign(cert, classical_privkey, NULL) == 0) {
        BIO_puts(bio_err, "Error generating classical signature.\n");
        goto end;
    }

    /* write the new signed certificate with extensions in it. */
    bio_x509out = BIO_new_file(file_x509out, "wb");
    if (PEM_write_bio_X509(bio_x509out, cert) == 0) {
        BIO_puts(bio_err, "Error writing new certificate.\n");
        goto end;
    }

    ret = 0;

 end:
    if (ret != 0)
        ERR_print_errors(bio_err);

    EVP_MD_CTX_cleanup(&mctx);
    if (tmpctx)
        EVP_PKEY_CTX_free(tmpctx);
    if (tmpreq)
        X509_REQ_free(tmpreq);
    if (tmppkey)
        EVP_PKEY_free(tmppkey);
    if (bio_req)
        BIO_free_all(bio_req);
    if (bio_x509in)
        BIO_free_all(bio_x509in);
    if (bio_x509out)
        BIO_free_all(bio_x509out);
    if (cert)
        X509_free(cert);
    if (pkey_qs_pub)
        EVP_PKEY_free(pkey_qs_pub);
    if (pkey_qs_priv)
        EVP_PKEY_free(pkey_qs_priv);
    if (classical_privkey)
        EVP_PKEY_free(classical_privkey);
    if (req)
        X509_REQ_free(req);

    if (sapki_in)
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki_in);
    if (sapki_out)
        SUBJECT_ALT_PUBLIC_KEY_INFO_free(sapki_out);
    if (algor_for_qssigalg)
        X509_ALGOR_free(algor_for_qssigalg);
    if (req_qssigalg)
        X509_ALGOR_free(req_qssigalg);
    if (x509_pub_qs)
        X509_PUBKEY_free(x509_pub_qs);
    if (x509_sig_qs)
        X509_PUBKEY_free(x509_sig_qs);
    if (qssig_algor)
        X509_ALGOR_free(qssig_algor);
    if (qs_sigval_as_asn1bitstring)
        ASN1_BIT_STRING_free(qs_sigval_as_asn1bitstring);
    if (ext_sapki)
        X509_EXTENSION_free(ext_sapki);
    if (ext_qssig)
        X509_EXTENSION_free(ext_qssig);
    if (ext_qssigalg)
        X509_EXTENSION_free(ext_qssigalg);

    if (qs_sigval_attr)
        X509_ATTRIBUTE_free(qs_sigval_attr);

    /* I don't need to free qs_sigalg_attr because it is still referenced by
     * the req.
     */
    if (passargin_qs && passin_qs)
        OPENSSL_free(passin_qs);

    release_engine(e);
    OBJ_cleanup();
    apps_shutdown();
    OPENSSL_EXIT(ret);
}

