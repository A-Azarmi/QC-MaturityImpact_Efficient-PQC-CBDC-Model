/* crypto/bio/bf_store.c */
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

#include <stdio.h>
#include <errno.h>
#include "cryptlib.h"
#include <openssl/bio.h>

static int store_write(BIO *h, const char *buf, int num);
static int store_read(BIO *h, char *buf, int size);
static int store_puts(BIO *h, const char *str);
static int store_gets(BIO *h, char *str, int size);
static long store_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int store_new(BIO *h);
static int store_free(BIO *data);
static BIO_METHOD store_method = {
    BIO_TYPE_STORE,
    "storage buffer",
    store_write,
    store_read,
    store_puts,
    store_gets,
    store_ctrl,
    store_new,
    store_free,
    NULL,
};

BIO_METHOD *BIO_f_store(void)
{
    return (&store_method);
}

static int store_new(BIO *bi)
{
    BUF_MEM *b;

    if ((b = BUF_MEM_new()) == NULL)
        return (0);
    bi->shutdown = 1;
    bi->init = 1;
    bi->num = -1;
    bi->ptr = (char *)b;
    return (1);
}

static int store_free(BIO *a)
{
    if (a == NULL)
        return (0);
    if (a->shutdown) {
        if ((a->init) && (a->ptr != NULL)) {
            BUF_MEM *b = (BUF_MEM *)a->ptr;
            BUF_MEM_free(b);
            a->ptr = NULL;
        }
    }
    return (1);
}

static int store_write(BIO *b, const char *in, int inl)
{
    int ret = -1;
    int blen;
    BUF_MEM *bm = (BUF_MEM *)b->ptr;

    if ((in == NULL) || (inl <= 0))
        return (0);
    if (b->next_bio == NULL)
        return (0);

    ret = BIO_write(b->next_bio, in, inl);
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    if (ret <= 0)
        return ret;

    blen = bm->length;
    if (BUF_MEM_grow_clean(bm, blen + inl) != (blen + inl))
        return -1;
    memcpy(&(bm->data[blen]), in, inl);
    return inl;
}

static int store_read(BIO *b, char *out, int outl)
{
    int ret = -1;
    int blen;
    BUF_MEM *bm = (BUF_MEM *)b->ptr;

    if ((out == NULL) || (outl <= 0))
        return (0);
    if (b->next_bio == NULL)
        return (0);

    ret = BIO_read(b->next_bio, out, outl);
    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);
    if (ret <= 0)
        return ret;

    blen = bm->length;
    if (BUF_MEM_grow_clean(bm, blen + ret) != (blen + ret))
        return -1;
    memcpy(&(bm->data[blen]), out, ret);
    return ret;
}

static int store_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = store_write(bp, str, n);
    return (ret);
}

static int store_gets(BIO *bp, char *buf, int size)
{
    return store_read(bp, buf, size);
}

static long store_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 0;
    char **pptr;

    BUF_MEM *bm = (BUF_MEM *)b->ptr;

    switch (cmd) {
    case BIO_CTRL_INFO:
        ret = (long)bm->length;
        if (ptr != NULL) {
            pptr = (char **)ptr;
            *pptr = (char *)&(bm->data[0]);
        }
        break;
    default:
        ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
        break;
    }
    return (ret);
}
