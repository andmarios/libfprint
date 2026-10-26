/*
 * TLS-PSK channel for the Goodix GXFP5187 sensor
 *
 * Copyright (C) 2026 Benjamin Allègre (https://github.com/Sigfrodr)
 * Copyright (C) 2026 Marios Andreopoulos <opensource@andmarios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Modified in September 2026 by Marios Andreopoulos: key derivation through
 * OpenSSL's TLS1-PRF KDF, a single BIO method per process, only the key
 * material in use is kept.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>

#include "goodix_tls.h"

/* The plain-PSK TLS 1.2 suites whose records gx_tls_decrypt_record() can
 * open. Firmware GF3288_ST411SEC_APP_11033 offers PSK-AES128-CBC-SHA256 only;
 * other revisions offer something else, and the sensor's pick wins. */
#define GX_TLS_CIPHERS \
  "PSK-AES128-CBC-SHA256:PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:" \
  "PSK-AES256-CBC-SHA384:PSK-AES128-CBC-SHA:PSK-AES256-CBC-SHA:" \
  "PSK-AES128-CCM:PSK-AES256-CCM:PSK-AES128-CCM8:PSK-AES256-CCM8:@SECLEVEL=0"

/* AEAD suites: a 4-byte implicit nonce from the key block, then an 8-byte
 * explicit one in front of each record (RFC 5288, RFC 6655). */
#define AEAD_FIXED_IV_LEN    4
#define AEAD_EXPLICIT_IV_LEN 8

struct _GxTls
{
  SSL_CTX   *ctx;
  SSL       *ssl;

  GxTlsSend  send;
  GxTlsRecv  recv;
  gpointer   user;

  guint8     psk[64];
  gsize      psk_len;
  gchar     *identity;

  /* What the sensor's ClientHello offered, for the logs. */
  gchar     *offered;

  /* Derived once the handshake completes, for the negotiated suite. The
   * sensor is the client, so its records are protected with the
   * client_write_* material; our own records go through OpenSSL, which keeps
   * the server_write_* half. */
  const EVP_CIPHER *cipher;
  const EVP_MD     *mac_md;                 /* NULL for AEAD suites */
  int        mode;                          /* EVP_CIPH_{CBC,GCM,CCM}_MODE */
  gsize      mac_key_len;
  gsize      tag_len;
  guint8     client_mac[EVP_MAX_MD_SIZE];
  guint8     client_key[EVP_MAX_KEY_LENGTH];
  guint8     client_iv[AEAD_FIXED_IV_LEN];
  guint64    read_seq;
  gboolean   keys_ready;
};

/* ------------------------------------------------------------------ */
/*  Transport glue                                                     */
/* ------------------------------------------------------------------ */

static int
bio_write_cb (BIO *b, const char *buf, int len)
{
  GxTls *t = BIO_get_data (b);
  int r = t->send (t->user, (const guint8 *) buf, len);

  BIO_clear_retry_flags (b);
  return r > 0 ? r : -1;
}

static int
bio_read_cb (BIO *b, char *buf, int len)
{
  GxTls *t = BIO_get_data (b);
  int r = t->recv (t->user, (guint8 *) buf, len);

  BIO_clear_retry_flags (b);
  return r > 0 ? r : -1;
}

static long
bio_ctrl_cb (BIO *b, int cmd, long num, void *ptr)
{
  return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

static int
bio_create_cb (BIO *b)
{
  BIO_set_init (b, 1);
  return 1;
}

/* The BIO method is created once per process: each BIO_get_new_index() call
 * consumes one of only 127 custom BIO type numbers, and fprintd is a
 * long-lived daemon that runs a handshake per operation. */
static BIO_METHOD *
bio_method (void)
{
  static gsize once = 0;
  static BIO_METHOD *method;

  if (g_once_init_enter (&once))
    {
      method = BIO_meth_new (BIO_get_new_index () | BIO_TYPE_SOURCE_SINK,
                             "goodix-spi");
      BIO_meth_set_write (method, bio_write_cb);
      BIO_meth_set_read (method, bio_read_cb);
      BIO_meth_set_ctrl (method, bio_ctrl_cb);
      BIO_meth_set_create (method, bio_create_cb);
      g_once_init_leave (&once, 1);
    }
  return method;
}

/* ------------------------------------------------------------------ */
/*  Key derivation (TLS 1.2 PRF with SHA-256)                          */
/* ------------------------------------------------------------------ */

/* TLS 1.2 PRF (RFC 5246 section 5) with the suite's digest, from OpenSSL's
 * KDF: the seed is the concatenation of the label and the two randoms. */
static gboolean
tls_prf (const EVP_MD *md, const guint8 *secret, gsize secret_len,
         const gchar *label,
         const guint8 *seed1, gsize seed1_len,
         const guint8 *seed2, gsize seed2_len,
         guint8 *out, gsize out_len)
{
  EVP_KDF *kdf = EVP_KDF_fetch (NULL, "TLS1-PRF", NULL);
  EVP_KDF_CTX *kctx = kdf ? EVP_KDF_CTX_new (kdf) : NULL;
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string (OSSL_KDF_PARAM_DIGEST,
                                      (char *) EVP_MD_get0_name (md), 0),
    OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SECRET, (void *) secret, secret_len),
    OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SEED, (void *) label, strlen (label)),
    OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SEED, (void *) seed1, seed1_len),
    OSSL_PARAM_construct_octet_string (OSSL_KDF_PARAM_SEED, (void *) seed2, seed2_len),
    OSSL_PARAM_construct_end (),
  };
  gboolean ok = kctx && EVP_KDF_derive (kctx, out, out_len, params) > 0;

  EVP_KDF_CTX_free (kctx);
  EVP_KDF_free (kdf);
  return ok;
}

/* Picks the record protection of the negotiated suite. */
static gboolean
select_suite (GxTls *t, const SSL_CIPHER *suite, GError **error)
{
  const gchar *name = SSL_CIPHER_get_name (suite);

  t->cipher = EVP_get_cipherbynid (SSL_CIPHER_get_cipher_nid (suite));
  t->mode = t->cipher ? EVP_CIPHER_get_mode (t->cipher) : 0;
  if (t->mode == EVP_CIPH_CBC_MODE)
    {
      t->mac_md = EVP_get_digestbynid (SSL_CIPHER_get_digest_nid (suite));
      t->mac_key_len = t->mac_md ? (gsize) EVP_MD_get_size (t->mac_md) : 0;
      t->tag_len = 0;
      if (t->mac_key_len > 0)
        return TRUE;
    }
  else if (t->mode == EVP_CIPH_GCM_MODE || t->mode == EVP_CIPH_CCM_MODE)
    {
      t->mac_md = NULL;
      t->mac_key_len = 0;
      t->tag_len = g_str_has_suffix (name, "CCM8") ? 8 : 16;
      return TRUE;
    }
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
               "cannot decrypt records of suite %s", name);
  return FALSE;
}

static gboolean
derive_keys (GxTls *t, GError **error)
{
  SSL_SESSION *sess = SSL_get_session (t->ssl);
  const SSL_CIPHER *suite = SSL_get_current_cipher (t->ssl);
  const EVP_MD *prf_md;
  guint8 master[48], cr[32], sr[32];
  guint8 kb[2 * EVP_MAX_MD_SIZE + 2 * EVP_MAX_KEY_LENGTH + 2 * AEAD_FIXED_IV_LEN];
  gsize enc_key_len, fixed_iv_len, kb_len;
  gboolean ok;
  gsize n;

  if (!sess || !suite)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "no TLS session");
      return FALSE;
    }
  if (!select_suite (t, suite, error))
    return FALSE;
  prf_md = SSL_CIPHER_get_handshake_digest (suite);
  if (!prf_md)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "no PRF digest");
      return FALSE;
    }
  /* Suites older than TLS 1.2 report the MD5+SHA-1 PRF of TLS 1.0; under
   * TLS 1.2 they use SHA-256 (RFC 5246 section 5). */
  if (EVP_MD_get_type (prf_md) == NID_md5_sha1)
    prf_md = EVP_sha256 ();
  enc_key_len = (gsize) EVP_CIPHER_get_key_length (t->cipher);
  fixed_iv_len = t->mode == EVP_CIPH_CBC_MODE ? 0 : AEAD_FIXED_IV_LEN;
  kb_len = 2 * t->mac_key_len + 2 * enc_key_len + 2 * fixed_iv_len;
  n = SSL_SESSION_get_master_key (sess, master, sizeof master);
  if (n != sizeof master)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "unexpected master secret length %zu", n);
      return FALSE;
    }
  if (SSL_get_client_random (t->ssl, cr, sizeof cr) != sizeof cr ||
      SSL_get_server_random (t->ssl, sr, sizeof sr) != sizeof sr)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "cannot read randoms");
      return FALSE;
    }

  /* key_block = PRF(master_secret, "key expansion",
   *                 server_random + client_random)  — note the order.
   * Layout: client MAC key, server MAC key, client key, server key, client
   * IV, server IV. Only AEAD suites use the IVs: CBC ones carry theirs in
   * each record. */
  ok = tls_prf (prf_md, master, sizeof master, "key expansion", sr, sizeof sr,
                cr, sizeof cr, kb, kb_len);
  OPENSSL_cleanse (master, sizeof master);
  if (!ok)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "key derivation failed");
      return FALSE;
    }
  memcpy (t->client_mac, kb, t->mac_key_len);
  memcpy (t->client_key, kb + 2 * t->mac_key_len, enc_key_len);
  memcpy (t->client_iv, kb + 2 * t->mac_key_len + 2 * enc_key_len, fixed_iv_len);
  OPENSSL_cleanse (kb, sizeof kb);

  /* Sequence numbers restart at zero when the cipher state changes, and the
   * Finished message is the first record under the new keys. Application data
   * from the sensor therefore starts at 1. The MAC check below will tell us
   * loudly if that assumption ever stops holding. */
  t->read_seq = 1;
  t->keys_ready = TRUE;
  return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Handshake                                                          */
/* ------------------------------------------------------------------ */

static unsigned int
psk_server_cb (SSL *ssl, const char *identity, unsigned char *psk,
               unsigned int max_psk_len)
{
  GxTls *t = SSL_get_ex_data (ssl, 0);

  if (!t || t->psk_len > max_psk_len)
    return 0;
  memcpy (psk, t->psk, t->psk_len);
  return (unsigned int) t->psk_len;
}

/* Notes the version and suites the sensor offers: firmware revisions differ
 * in them, and "no shared cipher" alone does not say which one to add. */
static int
client_hello_cb (SSL *ssl, int *al, void *arg)
{
  GxTls *t = arg;
  const unsigned char *ids;
  gsize n = SSL_client_hello_get0_ciphers (ssl, &ids);
  GString *s = g_string_new (NULL);

  g_string_printf (s, "TLS %04x, suites",
                   SSL_client_hello_get0_legacy_version (ssl));
  for (gsize i = 0; i + 1 < n; i += 2)
    g_string_append_printf (s, " %02x%02x", ids[i], ids[i + 1]);
  g_free (t->offered);
  t->offered = g_string_free (s, FALSE);
  return SSL_CLIENT_HELLO_SUCCESS;
}

GxTls *
gx_tls_new (const guint8 *psk, gsize psk_len, const gchar *identity,
            GxTlsSend send, GxTlsRecv recv, gpointer user)
{
  GxTls *t;

  if (!psk || psk_len == 0 || psk_len > sizeof t->psk)
    return NULL;

  t = g_new0 (GxTls, 1);
  memcpy (t->psk, psk, psk_len);
  t->psk_len = psk_len;
  t->identity = g_strdup (identity);
  t->send = send;
  t->recv = recv;
  t->user = user;
  return t;
}

gboolean
gx_tls_handshake_run (GxTls *t, GError **error)
{
  BIO *bio;
  int r;

  t->ctx = SSL_CTX_new (TLS_server_method ());
  if (!t->ctx)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "SSL_CTX_new failed");
      return FALSE;
    }

  /* The sensor only speaks TLS 1.2 with plain-PSK suites. Some are below
   * OpenSSL's default security level, hence SECLEVEL=0 — appropriate here,
   * where the cipher choice is the peer's and not ours to improve. */
  SSL_CTX_set_min_proto_version (t->ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (t->ctx, TLS1_2_VERSION);
  if (!SSL_CTX_set_cipher_list (t->ctx, GX_TLS_CIPHERS))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "no PSK suite available in this OpenSSL build");
      return FALSE;
    }
  /* Records are opened by hand, MAC-then-encrypt as the sensor does it. */
  SSL_CTX_set_options (t->ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
  SSL_CTX_set_psk_server_callback (t->ctx, psk_server_cb);
  SSL_CTX_set_client_hello_cb (t->ctx, client_hello_cb, t);
  if (t->identity)
    SSL_CTX_use_psk_identity_hint (t->ctx, t->identity);

  t->ssl = SSL_new (t->ctx);
  if (!t->ssl)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED, "SSL_new failed");
      return FALSE;
    }
  SSL_set_ex_data (t->ssl, 0, t);

  bio = BIO_new (bio_method ());
  BIO_set_data (bio, t);
  SSL_set_bio (t->ssl, bio, bio);          /* SSL takes ownership */

  r = SSL_accept (t->ssl);
  if (r != 1)
    {
      unsigned long e = ERR_get_error ();
      char buf[256] = "";

      if (e)
        ERR_error_string_n (e, buf, sizeof buf);
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "TLS handshake failed (%d/%d) %s; sensor offered %s", r,
                   SSL_get_error (t->ssl, r), buf,
                   t->offered ? t->offered : "nothing");
      return FALSE;
    }
  return derive_keys (t, error);
}

const gchar *
gx_tls_ciphersuite (GxTls *t)
{
  return t && t->ssl ? SSL_get_cipher (t->ssl) : "none";
}

const gchar *
gx_tls_offered (GxTls *t)
{
  return t && t->offered ? t->offered : "nothing";
}

gboolean
gx_tls_write (GxTls *t, const guint8 *buf, gsize len)
{
  return t && t->ssl && SSL_write (t->ssl, buf, (int) len) == (int) len;
}

/* ------------------------------------------------------------------ */
/*  Record decryption                                                  */
/* ------------------------------------------------------------------ */

/* The record header the MAC or AEAD tag covers:
 * seq_num || type || version || plaintext length. */
static void
record_header (guint8 hdr[13], guint64 seq, const guint8 *raw, gsize len)
{
  for (int i = 0; i < 8; i++)
    hdr[i] = (guint8) (seq >> (56 - 8 * i));
  hdr[8] = raw[0];
  hdr[9] = raw[1];
  hdr[10] = raw[2];
  hdr[11] = (guint8) (len >> 8);
  hdr[12] = (guint8) len;
}

/* AES-GCM or AES-CCM: explicit nonce || ciphertext || tag. */
static gssize
decrypt_aead (GxTls *t, const guint8 *raw, gsize body_len,
              guint8 *out, gsize out_cap)
{
  const guint8 *body = raw + 5;
  const guint8 *ct = body + AEAD_EXPLICIT_IV_LEN;
  gboolean ccm = t->mode == EVP_CIPH_CCM_MODE;
  guint8 nonce[AEAD_FIXED_IV_LEN + AEAD_EXPLICIT_IV_LEN], hdr[13];
  EVP_CIPHER_CTX *c;
  gsize ct_len;
  int len = 0;
  gboolean ok;

  if (body_len < AEAD_EXPLICIT_IV_LEN + t->tag_len)
    return -1;
  ct_len = body_len - AEAD_EXPLICIT_IV_LEN - t->tag_len;
  if (ct_len > out_cap)
    return -1;
  memcpy (nonce, t->client_iv, AEAD_FIXED_IV_LEN);
  memcpy (nonce + AEAD_FIXED_IV_LEN, body, AEAD_EXPLICIT_IV_LEN);
  record_header (hdr, t->read_seq, raw, ct_len);

  c = EVP_CIPHER_CTX_new ();
  if (!c)
    return -1;
  ok = EVP_DecryptInit_ex (c, t->cipher, NULL, NULL, NULL) &&
       EVP_CIPHER_CTX_ctrl (c, EVP_CTRL_AEAD_SET_IVLEN, sizeof nonce, NULL) > 0;
  /* CCM wants the expected tag before the key, and the message length
   * before the additional data; it checks the tag in the final update. */
  if (ok && ccm)
    ok = EVP_CIPHER_CTX_ctrl (c, EVP_CTRL_AEAD_SET_TAG, (int) t->tag_len,
                              (void *) (ct + ct_len)) > 0;
  ok = ok && EVP_DecryptInit_ex (c, NULL, NULL, t->client_key, nonce);
  if (ok && ccm)
    ok = EVP_DecryptUpdate (c, NULL, &len, NULL, (int) ct_len);
  ok = ok && EVP_DecryptUpdate (c, NULL, &len, hdr, sizeof hdr) &&
       EVP_DecryptUpdate (c, out, &len, ct, (int) ct_len);
  if (ok && !ccm)
    ok = EVP_CIPHER_CTX_ctrl (c, EVP_CTRL_AEAD_SET_TAG, (int) t->tag_len,
                              (void *) (ct + ct_len)) > 0 &&
         EVP_DecryptFinal_ex (c, out + len, &len) > 0;
  EVP_CIPHER_CTX_free (c);
  if (!ok)
    {
      OPENSSL_cleanse (out, ct_len);
      return -1;
    }
  return (gssize) ct_len;
}

/* AES-CBC with HMAC: explicit IV || E(content || MAC || padding). */
static gssize
decrypt_cbc (GxTls *t, const guint8 *raw, gsize body_len,
             guint8 *out, gsize out_cap)
{
  EVP_CIPHER_CTX *c;
  const guint8 *body = raw + 5;
  gsize iv_len = (gsize) EVP_CIPHER_get_iv_length (t->cipher);
  gsize mac_len = t->mac_key_len;
  int plain_len = 0, tmp = 0;
  g_autofree guint8 *plain = NULL;
  guint8 mac[EVP_MAX_MD_SIZE], want[EVP_MAX_MD_SIZE], hdr[13];
  unsigned int want_len = 0;
  gsize content_len, pad;

  if (body_len < iv_len + mac_len || (body_len - iv_len) % iv_len != 0)
    return -1;

  plain = g_malloc (body_len);
  c = EVP_CIPHER_CTX_new ();
  if (!c)
    return -1;
  EVP_DecryptInit_ex (c, t->cipher, NULL, t->client_key, body);
  EVP_CIPHER_CTX_set_padding (c, 0);        /* TLS padding, not PKCS#7 */
  if (!EVP_DecryptUpdate (c, plain, &plain_len, body + iv_len,
                          (int) (body_len - iv_len)) ||
      !EVP_DecryptFinal_ex (c, plain + plain_len, &tmp))
    {
      EVP_CIPHER_CTX_free (c);
      return -1;
    }
  EVP_CIPHER_CTX_free (c);
  plain_len += tmp;

  /* plaintext = content || MAC || padding, where every padding byte carries
   * the padding length and the final byte is that length. */
  pad = (gsize) plain[plain_len - 1] + 1;
  if ((gsize) plain_len < pad + mac_len)
    return -1;
  content_len = (gsize) plain_len - pad - mac_len;
  if (content_len > out_cap)
    return -1;
  memcpy (mac, plain + content_len, mac_len);

  /* MAC covers seq_num || type || version || length || content. */
  record_header (hdr, t->read_seq, raw, content_len);
  {
    g_autofree guint8 *msg = g_malloc (sizeof hdr + content_len);

    memcpy (msg, hdr, sizeof hdr);
    memcpy (msg + sizeof hdr, plain, content_len);
    HMAC (t->mac_md, t->client_mac, (int) t->mac_key_len, msg,
          sizeof hdr + content_len, want, &want_len);
  }
  if (want_len != mac_len || CRYPTO_memcmp (want, mac, mac_len) != 0)
    return -1;

  memcpy (out, plain, content_len);
  return (gssize) content_len;
}

gssize
gx_tls_decrypt_record (GxTls *t, const guint8 *raw, gsize raw_len,
                       guint8 *out, gsize out_cap)
{
  gsize body_len;
  gssize n;

  if (!t || !t->keys_ready || raw_len < 5)
    return -1;
  if (raw[0] != 23)                         /* application data */
    return -1;
  body_len = ((gsize) raw[3] << 8) | raw[4];
  if (body_len + 5 > raw_len)
    return -1;

  /* Checking the MAC or tag also confirms the sequence number is in step; a
   * mismatch here is the loud failure that would otherwise show up as
   * silently corrupt images. */
  n = t->mode == EVP_CIPH_CBC_MODE
      ? decrypt_cbc (t, raw, body_len, out, out_cap)
      : decrypt_aead (t, raw, body_len, out, out_cap);
  if (n >= 0)
    t->read_seq++;
  return n;
}

void
gx_tls_close (GxTls *t)
{
  if (t && t->ssl)
    SSL_shutdown (t->ssl);
}

void
gx_tls_free (GxTls *t)
{
  if (!t)
    return;
  if (t->ssl)
    SSL_free (t->ssl);                      /* frees the BIO too */
  if (t->ctx)
    SSL_CTX_free (t->ctx);
  OPENSSL_cleanse (t->psk, sizeof t->psk);
  OPENSSL_cleanse (t->client_key, sizeof t->client_key);
  OPENSSL_cleanse (t->client_mac, sizeof t->client_mac);
  OPENSSL_cleanse (t->client_iv, sizeof t->client_iv);
  g_free (t->identity);
  g_free (t->offered);
  g_free (t);
}
