/*
 * Goodix GXFP5187 SPI (TLS-PSK) driver for libfprint
 *
 * Copyright (C) 2026 Benjamin Allègre (https://github.com/Sigfrodr)
 * Copyright (C) 2026 Marios Andreopoulos <opensource@andmarios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Based on libfprint-goodixtls by Benjamin Allègre
 * (https://github.com/Sigfrodr/libfprint-goodixtls), originally a libfprint
 * TOD module. Modified in September 2026 by Marios Andreopoulos: built as an
 * in-tree driver; SPI reads gated on the sensor's interrupt line; an idle gap
 * before every write; TLS unlock (0xD5) and TLS-OK (0xD4) commands; framing
 * kept intact on oversized frames; TLS session kept across opens; state
 * machine, worker threads and verification flow reworked.
 *
 * Protocol facts behind those changes come from public research by others,
 * none of whose code is used here: lexakimov/goodix51c0_spi-reversing (the
 * 0xD5 unlock, interrupt-driven receive), delitdesnoyers06-del/goodix-gxfp-
 * protocol (0xD4 after the handshake), szlukabence/goodix-fingerprint-spi-
 * linux (analysis of the vendor driver) and goodix-fp-linux-dev/goodix-fp-dump
 * (the reset command).
 *
 * Driver for the SPI fingerprint sensor found in the Huawei MateBook X Pro,
 * whose protocol was reverse-engineered for this work. The chain is: an SPI
 * dialogue where one frame is exactly one transfer and reads are gated on the
 * sensor's interrupt line, opening the command gate by uploading a
 * configuration blob, a TLS-PSK channel whose key is read out of the sensor's
 * own RAM, and a 132x112 image in packed 12-bit samples (six bytes carry four
 * interleaved pixels) calibrated by subtracting a background frame.
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
 * License along with this library; if not, see <https://www.gnu.org/licenses/>.
 */

#define FP_COMPONENT "goodixtls"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <glib-unix.h>
#include <math.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <linux/gpio.h>
#include <linux/spi/spidev.h>

#include "goodixtls.h"
#include "goodix_sift.h"
#include "goodix_tls.h"

/* Largest frame body we ever receive: the image, at about 22 kB. */
#define GX_RX_MAX            24000

/* Finger-presence threshold on the contrast (standard deviation) of the
 * background-minus-frame difference: about 5 with no finger, 200+ with one. */
#define GX_MIN_CONTRAST      50.0

/* Protocol timing. The gaps below were measured on hardware; the ones marked
 * "measured" have been seen to fail when shortened. */
#define GX_FRAME_GAP_US      1000    /* idle before every write (measured: frames
                                        sent back to back are dropped) */
#define GX_NOP_GAP_US        8000    /* NOP preamble -> command */
#define GX_CFG_NOP_GAP_US    15000   /* NOP preamble -> configuration upload */
#define GX_SEQ_GAP_US        30000   /* between capture-sequence commands
                                        (measured under the old transport) */
#define GX_MCU_STATE_GAP_US  80000   /* after the MCU-state query over TLS */
#define GX_TLS_OK_SETTLE_US  50000   /* our Finished -> 0xD4 (too soon and the
                                        MCU does not advance its TLS state) */
#define GX_HDR_BODY_US       200     /* header read -> body read */
#define GX_RESET_PULSE_US    10000
#define GX_RESET_SETTLE_US   120000

/* Receive timeouts. */
#define GX_ACK_TIMEOUT_MS    200
#define GX_TLS_RX_TIMEOUT_MS 3000    /* the image takes a while to produce */
#define GX_DRAIN_FIRST_MS    300
#define GX_DRAIN_SILENCE_MS  60

/* GPIO lines of the MateBook X Pro, used when the ACPI tables cannot be read. */
#define GX_IRQ_LINE_DEFAULT   23
#define GX_RESET_LINE_DEFAULT 58

#define GX_TLS_ATTEMPTS      3
#define GX_PSK_ATTEMPTS      3
#define GX_FW_ATTEMPTS       3

/* What differs between the firmware revisions the driver knows, matched on the
 * exact version string. The first entry is also the layout tried on a
 * revision that is not listed: the only one the driver knew before 11034. */
typedef struct
{
  const gchar *version;
  guint32      psk_addr;
  gboolean     psk_after_enable;  /* key only settled once the chip is enabled */
} GxFirmware;

static const GxFirmware gx_firmwares[] = {
  { "GF3288_ST411SEC_APP_11033", GOODIX_PSK_ADDR,       FALSE },
  { "GF3288_ST411SEC_APP_11034", GOODIX_PSK_ADDR_11034, TRUE },
};

struct _FpiDeviceGoodixTls
{
  FpDevice parent;

  int           spi_fd;
  int           irq_fd;       /* GPIO line request for the sensor's IRQ */
  gchar        *gpiochip;     /* chip holding the reset and IRQ lines */
  guint         reset_line;
  gint64        last_xfer;    /* monotonic time the last SPI transaction ended */
  gint64        quiet_until;  /* no write before this (command spacing) */

  /* TLS stack. Note the sensor is the client and we are the server. */
  GxTls        *tls;
  gboolean      tls_up;
  guint8        psk[GOODIX_PSK_LEN];
  const GxFirmware *fw;       /* identified at open */

  /* One TLS record, consumed by the BIO recv callback or the image decoder. */
  guint8        tls_rx[GX_RX_MAX];
  int           tls_rxlen, tls_rxpos;

  guint16      *bg_frame;     /* background, NULL until calibrated */
  int           fdt_base[12]; /* finger-detection baseline (finger absent) */
  int           fdt_abs;      /* per-unit absolute floor, derived from baseline */
  gboolean      bg_dirty;     /* background taken with a finger down */
};

G_DECLARE_FINAL_TYPE (FpiDeviceGoodixTls, fpi_device_goodixtls, FPI,
                      DEVICE_GOODIXTLS, FpDevice)
G_DEFINE_TYPE (FpiDeviceGoodixTls, fpi_device_goodixtls, FP_TYPE_DEVICE)

#ifdef TOD_LIBRARY
G_MODULE_EXPORT GType
fpi_tod_shared_driver_get_type (void)
{
  return fpi_device_goodixtls_get_type ();
}
#endif

static const FpIdEntry goodixtls_id_table[] = {
  { .udev_types = FPI_DEVICE_UDEV_SUBTYPE_SPIDEV, .spi_acpi_id = "GXFP5187" },
  { .udev_types = 0 }
};

/* Fixed commands, byte-for-byte as validated against the sensor. A command
 * body is [cmd][len16 = payload + 1][payload][checksum]; see gx_build_cmd(). */

/* NOP (no checksum: 0x88 marker). The vendor driver sends one ahead of every
 * command group. */
static const guint8 GX_NOP[] = { 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88 };
static const guint8 GX_FW_VERSION[] = { 0xa8, 0x03, 0x00, 0x70, 0xdc, 0xb3 };
static const guint8 GX_ENABLE[] = { 0x96, 0x03, 0x00, 0x01, 0x00, 0x10 };
static const guint8 GX_REQTLS[] = { 0xd0, 0x03, 0x00, 0x00, 0x00, 0xd7 };
/* "Force unlock TLS": drops whatever TLS state the MCU still holds from an
 * earlier, possibly abandoned, session. The command byte is odd, and odd
 * commands take a checksum one higher than the usual formula. The MCU still
 * acknowledges it, as "d4": status 01 when a session was torn down, 03 when
 * there was none. */
static const guint8 GX_TLS_UNLOCK[] = { 0xd5, 0x03, 0x00, 0x00, 0x00, 0xd3 };
/* "TLS successfully established": tells the MCU the host side is done. */
static const guint8 GX_TLS_OK[] = { 0xd4, 0x03, 0x00, 0x00, 0x00, 0xd3 };
/* Finger detection ("FDT manual") with the reference levels of the capture
 * sequence below; the reply carries twelve 16-bit zone values. */
static const guint8 GX_FDT_PROBE[] = {
  0x36, 0x23, 0x00, 0x0d, 0x01, 0xa6, 0xa6, 0xb9, 0xb9, 0xbc, 0xbc, 0xb7,
  0xb7, 0xa8, 0xa8, 0xba, 0xba, 0xb7, 0xb7, 0xb8, 0xb8, 0xa8, 0xa8, 0xc1,
  0xc1, 0xba, 0xba, 0xb5, 0xb5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x4d
};

/* Configuration blob, defined in config_pcap.c. */
extern const guint8 CONFIG_PCAP[];
extern const gsize CONFIG_PCAP_LEN;

/* ------------------------------------------------------------------ */
/*  SPI transport                                                      */
/* ------------------------------------------------------------------ */

/* Every SPI transaction goes through here, so that the idle gap before the
 * next write is measured from the end of whatever happened last. */
static gboolean
gx_spi_xfer (FpiDeviceGoodixTls *self, const guint8 *tx, guint8 *rx, gsize len)
{
  struct spi_ioc_transfer x = {
    .tx_buf = (unsigned long) tx,
    .rx_buf = (unsigned long) rx,
    .len = len,
  };
  int r = ioctl (self->spi_fd, SPI_IOC_MESSAGE (1), &x);

  self->last_xfer = g_get_monotonic_time ();
  return r == (int) len;
}

/* Keeps the bus silent for at least @us from now. */
static void
gx_quiet (FpiDeviceGoodixTls *self, gint64 us)
{
  self->quiet_until = MAX (self->quiet_until, g_get_monotonic_time () + us);
}

/* Writes one frame: a 4-byte transport header then the body, in ONE transfer
 * (chip select held). The Windows driver logs them as two writes, but this
 * part ignores a split frame.
 *
 * The sensor needs a moment to re-arm its receiver after every transaction:
 * frames sent back to back — the three records of the ServerHello flight, or
 * a record right after reading the ClientHello — are silently dropped and the
 * handshake stalls. Hence the idle gap before every write. */
static gboolean
gx_write_frame (FpiDeviceGoodixTls *self, guint8 type,
                const guint8 *body, gsize n)
{
  g_autofree guint8 *buf = g_malloc (n + 4);
  gint64 ready, now;

  buf[0] = type;
  buf[1] = n & 0xff;
  buf[2] = (n >> 8) & 0xff;
  buf[3] = buf[0] + buf[1] + buf[2];
  memcpy (buf + 4, body, n);

  ready = MAX (self->last_xfer + GX_FRAME_GAP_US, self->quiet_until);
  now = g_get_monotonic_time ();
  if (now < ready)
    g_usleep (ready - now);
  return gx_spi_xfer (self, buf, NULL, n + 4);
}

/* Clocks one frame out of the sensor. Returns the body length, or -1 when
 * nothing valid was queued or the frame did not fit. Once a header has been
 * accepted the whole body is always read, so that a frame too large for the
 * caller's buffer cannot be left in the sensor to shift every later read.
 * Only call this when the IRQ line says a frame is pending (see gx_recv). */
static int
gx_read_frame (FpiDeviceGoodixTls *self, guint8 *out_type,
               guint8 *rx, gsize rx_cap)
{
  guint8 hdr[4] = { 0 };
  guint16 n;

  if (!gx_spi_xfer (self, NULL, hdr, sizeof hdr))
    return -1;
  /* Header checksum: a plain sum of the first three bytes, or the 0x88
   * "no checksum" marker. An idle bus reads back the last byte repeated. */
  if ((hdr[0] != GOODIX_PKT_PLAIN && hdr[0] != GOODIX_PKT_TLS) ||
      (hdr[3] != (guint8) (hdr[0] + hdr[1] + hdr[2]) && hdr[3] != 0x88))
    return -1;
  n = hdr[1] | (hdr[2] << 8);
  if (n == 0)
    return -1;

  g_usleep (GX_HDR_BODY_US);          /* let the sensor stage the body */
  if (n > rx_cap)
    {
      g_autofree guint8 *junk = g_malloc (n);

      gx_spi_xfer (self, NULL, junk, n);
      fp_warn ("dropped a %u-byte frame (type %02x, cmd %02x): larger than "
               "the %zu-byte buffer", n, hdr[0], junk[0], rx_cap);
      return -1;
    }
  if (!gx_spi_xfer (self, NULL, rx, n))
    return -1;
  *out_type = hdr[0];
  return n;
}

/* --- the sensor's interrupt line ------------------------------------
 *
 * The sensor pulls its GpioInt line LOW while it has a frame queued for the
 * host, and releases it once that frame has been clocked out. The vendor
 * driver only ever reads from its ISR, i.e. when the line says so.
 *
 * Reading blindly instead — clocking a header "just to see" — is not harmless
 * on this part: a read that lands while the MCU is still parsing the frames we
 * just sent is taken as a (garbage) incoming frame, and the TLS state machine
 * stalls. Repeated, that damage accumulated until the sensor wedged
 * completely, and only a full power-off brought it back. So every read is
 * gated on the line, and the driver refuses to run without it. */

static gboolean
gx_irq_pending (FpiDeviceGoodixTls *self)
{
  struct gpio_v2_line_values v = { .mask = 1 };

  return ioctl (self->irq_fd, GPIO_V2_LINE_GET_VALUES_IOCTL, &v) == 0 &&
         !(v.bits & 1);
}

/* Waits until the line says a frame is queued, or @deadline passes. */
static gboolean
gx_wait_irq (FpiDeviceGoodixTls *self, gint64 deadline)
{
  for (;;)
    {
      struct gpio_v2_line_event ev[16];
      struct pollfd pfd = { .fd = self->irq_fd, .events = POLLIN };
      gint64 left;

      /* Only the level matters; the edge events are just the wake-up. */
      while (read (self->irq_fd, ev, sizeof ev) > 0)
        ;
      if (gx_irq_pending (self))
        return TRUE;
      left = deadline - g_get_monotonic_time ();
      if (left <= 0)
        return FALSE;
      /* Capped, so that a missed edge only costs a few milliseconds. */
      poll (&pfd, 1, (int) MIN ((left + 999) / 1000, 5));
    }
}

/* Waits until the line is released (or @deadline passes). */
static void
gx_wait_irq_release (FpiDeviceGoodixTls *self, gint64 deadline)
{
  while (gx_irq_pending (self) && g_get_monotonic_time () < deadline)
    g_usleep (1000);
}

/* Receives one frame, waiting up to @timeout_ms for the sensor to raise its
 * interrupt. Returns the body length, or 0 on timeout.
 *
 * The line can read "pending" with nothing queued — seen right after a reset
 * pulse with a finger resting on the sensor. A read then finds no valid
 * header. Reading again while the line stays low would be exactly the blind
 * polling that wedges this part, so wait for the line to be released and
 * raised again by a real frame, and give up after a few misfires. */
static int
gx_recv (FpiDeviceGoodixTls *self, guint8 *out_type, guint8 *rx, gsize rx_cap,
         int timeout_ms)
{
  gint64 deadline = g_get_monotonic_time () + (gint64) timeout_ms * 1000;
  int misfires = 0;

  while (gx_wait_irq (self, deadline))
    {
      int r = gx_read_frame (self, out_type, rx, rx_cap);

      if (r > 0)
        return r;
      if (++misfires >= 4)
        break;
      gx_wait_irq_release (self, deadline);
    }
  return 0;
}

/* Throws away whatever the sensor still has queued: frames left over from an
 * interrupted exchange survive a reset pulse and would be taken for the reply
 * to the next command. */
static void
gx_flush_rx (FpiDeviceGoodixTls *self)
{
  g_autofree guint8 *junk = g_malloc (GX_RX_MAX);
  guint8 ty;
  int i;

  for (i = 0; i < 16; i++)
    {
      int r = gx_recv (self, &ty, junk, GX_RX_MAX, 5);

      if (r <= 0)
        break;
      fp_dbg ("flushed a stale %s frame, %d bytes (%02x)",
              ty == GOODIX_PKT_TLS ? "TLS" : "plain", r, junk[0]);
    }
}

/* ------------------------------------------------------------------ */
/*  Plaintext commands                                                 */
/* ------------------------------------------------------------------ */

/* Builds a command body into @out (payload + 4 bytes); returns its length. */
static gsize
gx_build_cmd (guint8 *out, guint8 cmd, const guint8 *payload, gsize len)
{
  out[0] = cmd;
  out[1] = (len + 1) & 0xff;
  out[2] = ((len + 1) >> 8) & 0xff;
  memcpy (out + 3, payload, len);
  out[3 + len] = goodix_body_cksum (out, 3 + len);
  return len + 4;
}

static gboolean
gx_is_ack (const guint8 *rx, int r, guint8 cmd)
{
  return r >= 5 && rx[0] == 0xb0 && rx[3] == (cmd & 0xfe);
}

/* Sends the NOP preamble, then a plaintext command. */
static gboolean
gx_send_cmd (FpiDeviceGoodixTls *self, const guint8 *body, gsize n,
             gint64 nop_gap_us)
{
  if (!gx_write_frame (self, GOODIX_PKT_PLAIN, GX_NOP, sizeof GX_NOP))
    return FALSE;
  g_usleep (nop_gap_us);
  return gx_write_frame (self, GOODIX_PKT_PLAIN, body, n);
}

/* Sends a command and waits for its ACK (b0 03 00 <cmd> <status>). The
 * status byte is stored in @status when given. */
static gboolean
gx_command (FpiDeviceGoodixTls *self, const guint8 *body, gsize n,
            gint64 nop_gap_us, int timeout_ms, guint8 *status)
{
  guint8 ty, rx[64];
  int r;

  if (!gx_send_cmd (self, body, n, nop_gap_us))
    return FALSE;
  r = gx_recv (self, &ty, rx, sizeof rx, timeout_ms);
  if (r > 0 && ty == GOODIX_PKT_PLAIN && gx_is_ack (rx, r, body[0]))
    {
      if (status)
        *status = rx[4];
      return TRUE;
    }
  fp_dbg ("no ACK for command %02x", body[0]);
  return FALSE;
}

/* Sends a command, waits for its ACK, then for the data reply carrying the
 * same command byte. Returns the reply length, or -1. */
static int
gx_query (FpiDeviceGoodixTls *self, const guint8 *body, gsize n,
          guint8 *reply, gsize cap)
{
  guint8 ty;
  int r;

  if (!gx_command (self, body, n, GX_NOP_GAP_US, GX_ACK_TIMEOUT_MS, NULL))
    return -1;
  r = gx_recv (self, &ty, reply, cap, GX_ACK_TIMEOUT_MS);
  if (r <= 0 || ty != GOODIX_PKT_PLAIN || reply[0] != body[0])
    return -1;
  return r;
}

/* Reads the firmware version, which also proves the SPI dialogue works. */
static gboolean
gx_read_fw_version (FpiDeviceGoodixTls *self, gchar *out, gsize cap)
{
  guint8 rx[64];
  gsize len;
  int n;

  n = gx_query (self, GX_FW_VERSION, sizeof GX_FW_VERSION, rx, sizeof rx);
  if (n <= 4)
    return FALSE;
  /* [a8][len16][string, NUL-padded][checksum]. The sensor's bytes are not
   * trusted to be terminated. */
  len = MIN ((gsize) n - 4, cap - 1);
  memcpy (out, rx + 3, len);
  out[len] = '\0';
  return TRUE;
}

/* Arbitrary memory read (0xF2): this is how the pre-shared key is obtained.
 * Returns the number of bytes copied to @out, or -1. */
static int
gx_mem_read (FpiDeviceGoodixTls *self, guint32 addr, guint32 len, guint8 *out)
{
  guint32 a = addr - 0x08000000;
  guint8 payload[8] = {
    a & 0xff, (a >> 8) & 0xff, (a >> 16) & 0xff, (a >> 24) & 0xff,
    len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, (len >> 24) & 0xff,
  };
  guint8 cmd[12], rx[512];
  int n;

  gx_build_cmd (cmd, GOODIX_CMD_MEM_READ, payload, sizeof payload);
  n = gx_query (self, cmd, sizeof cmd, rx, sizeof rx);
  if (n <= 4)
    return -1;
  n = MIN (n - 4, (int) len);           /* [f2][len16][data...][checksum] */
  memcpy (out, rx + 3, n);
  explicit_bzero (rx, sizeof rx);
  return n;
}

/* Force-unlocks TLS on the MCU. */
static void
gx_tls_unlock (FpiDeviceGoodixTls *self)
{
  guint8 status;

  if (gx_command (self, GX_TLS_UNLOCK, sizeof GX_TLS_UNLOCK, GX_NOP_GAP_US,
                  50, &status))
    fp_dbg ("TLS unlock: status %02x", status);
}

/* ------------------------------------------------------------------ */
/*  Transport glue: TLS records travel inside 0xB0 SPI frames          */
/* ------------------------------------------------------------------ */

/* Fills tls_rx with the next TLS record, skipping cleartext frames. */
static gboolean
gx_fetch_tls_record (FpiDeviceGoodixTls *self)
{
  gint64 deadline = g_get_monotonic_time () + GX_TLS_RX_TIMEOUT_MS * 1000;
  guint8 ty;

  self->tls_rxlen = self->tls_rxpos = 0;
  for (;;)
    {
      int left = (int) ((deadline - g_get_monotonic_time ()) / 1000);
      int r;

      if (left <= 0)
        break;
      r = gx_recv (self, &ty, self->tls_rx, sizeof self->tls_rx, left);
      if (r <= 0)
        break;
      if (ty == GOODIX_PKT_TLS)
        {
          self->tls_rxlen = r;
          return TRUE;
        }
      fp_dbg ("skipped a cleartext frame (%02x) while waiting for a TLS record",
              self->tls_rx[0]);
    }
  fp_dbg ("no TLS record from the sensor");
  return FALSE;
}

static int
gx_bio_send (gpointer ctx, const guint8 *b, gsize l)
{
  FpiDeviceGoodixTls *self = ctx;
  gsize off = 0;

  /* One TLS record per 0xB0 frame. OpenSSL batches several records into a
   * single write — the ServerHello group comes out as one 121-byte call — but
   * the sensor expects exactly one record per frame and silently ignores a
   * frame carrying two. Split on the record headers. */
  while (off + 5 <= l)
    {
      gsize rec = 5 + (((gsize) b[off + 3] << 8) | b[off + 4]);

      if (off + rec > l)
        break;
      if (!gx_write_frame (self, GOODIX_PKT_TLS, b + off, rec))
        return -1;
      off += rec;
    }
  if (off != l)
    {
      /* OpenSSL hands over whole records; a partial one would have to be
       * buffered, and dropping it silently would stall the handshake. */
      fp_warn ("TLS write of %zu bytes is not a whole number of records", l);
      return -1;
    }
  return (int) l;
}

static int
gx_bio_recv (gpointer ctx, guint8 *b, gsize l)
{
  FpiDeviceGoodixTls *self = ctx;
  int take;

  if (self->tls_rxpos >= self->tls_rxlen && !gx_fetch_tls_record (self))
    return -1;
  take = MIN ((int) l, self->tls_rxlen - self->tls_rxpos);
  memcpy (b, self->tls_rx + self->tls_rxpos, take);
  self->tls_rxpos += take;
  return take;
}

/* ------------------------------------------------------------------ */
/*  GPIO: reset and interrupt lines                                    */
/* ------------------------------------------------------------------ */

/* Best-effort discovery of the GPIO lines from the ACPI _CRS, so they are not
 * hardcoded across units. Reads the DSDT, finds the sensor device, and decodes
 * the Intel GNUM-encoded globals its _CRS feeds to GpioInt and GpioIo:
 *     pin = (enc & 0xFFFF) + ((enc >> 16) & 0xFF) * 24
 * then picks the gpiochip with enough lines. Intel-platform specific. (The
 * kernel parses the GpioInt for the SPI core but exposes neither pin to
 * userspace, and the reset GpioIo is not used by any kernel driver.) */
static guint
gx_gnum_decode (guint32 enc)
{
  return (enc & 0xFFFF) + (((enc >> 16) & 0xFF) * 24);
}

static gboolean
gx_discover_gpios (gchar **chip_out, guint *reset_out, guint *irq_out)
{
  g_autofree gchar *dsdt = NULL;
  const guint8 *d;
  gsize len = 0, off, end, k;
  gboolean found = FALSE, has_io = FALSE;
  guint32 seen[8], globs[8];
  int nseen = 0, count[8] = { 0 }, ng = 0, s, n;

  if (!g_file_get_contents ("/sys/firmware/acpi/tables/DSDT", &dsdt, &len, NULL))
    return FALSE;
  d = (const guint8 *) dsdt;
  for (off = 0; off + 8 <= len; off++)
    if (memcmp (d + off, "GXFP5187", 8) == 0)
      {
        found = TRUE;
        break;
      }
  if (!found)
    return FALSE;
  end = MIN (off + 700, len);

  for (k = off; k + 5 < end; k++)
    if (d[k] == 0x8C && d[k + 3] == 1 && d[k + 4] == 1)
      {
        has_io = TRUE;
        break;
      }
  if (!has_io)
    return FALSE;

  /* GNUM-encoded globals are DWordConst (0x0C + LE u32) referenced twice (SHPO
   * in _INI, GNUM in _CRS). First-seen order: [0] = GpioInt (IRQ), [1] =
   * GpioIo (reset). */
  for (k = off; k + 5 < end; k++)
    {
      guint32 v;
      int idx = -1;

      if (d[k] != 0x0C)
        continue;
      v = d[k + 1] | (d[k + 2] << 8) | (d[k + 3] << 16) | ((guint32) d[k + 4] << 24);
      if (((v >> 16) & 0xFF) >= 0x10 || (v & 0xFFFF) >= 0x400 || gx_gnum_decode (v) >= 512)
        continue;
      for (s = 0; s < nseen; s++)
        if (seen[s] == v)
          idx = s;
      if (idx < 0 && nseen < 8)
        {
          seen[nseen] = v;
          idx = nseen++;
        }
      if (idx >= 0)
        count[idx]++;
    }
  for (s = 0; s < nseen; s++)
    if (count[s] >= 2 && ng < 8)
      globs[ng++] = seen[s];
  if (ng < 2)
    return FALSE;
  *irq_out = gx_gnum_decode (globs[0]);
  *reset_out = gx_gnum_decode (globs[1]);

  for (n = 0; n < 8; n++)
    {
      g_autofree gchar *path = g_strdup_printf ("/dev/gpiochip%d", n);
      struct gpiochip_info ci = { 0 };
      gboolean ok;
      int fd = open (path, O_RDONLY | O_CLOEXEC);

      if (fd < 0)
        continue;
      ok = ioctl (fd, GPIO_GET_CHIPINFO_IOCTL, &ci) >= 0 &&
           ci.lines > MAX (*reset_out, *irq_out);
      close (fd);
      if (ok)
        {
          *chip_out = g_steal_pointer (&path);
          return TRUE;
        }
    }
  return FALSE;
}

/* Resolves the GPIO lines and requests the IRQ line. */
static gboolean
gx_open_gpios (FpiDeviceGoodixTls *self, GError **error)
{
  struct gpio_v2_line_request req = { 0 };
  guint irq_line;
  int chip;

  g_clear_pointer (&self->gpiochip, g_free);
  if (gx_discover_gpios (&self->gpiochip, &self->reset_line, &irq_line))
    {
      fp_dbg ("gpio: %s reset %u irq %u, from ACPI _CRS", self->gpiochip,
              self->reset_line, irq_line);
    }
  else
    {
      self->gpiochip = g_strdup ("/dev/gpiochip0");
      self->reset_line = GX_RESET_LINE_DEFAULT;
      irq_line = GX_IRQ_LINE_DEFAULT;
      fp_warn ("gpio: ACPI lookup failed; using the MateBook X Pro lines "
               "(reset %u, irq %u)", self->reset_line, irq_line);
    }

  chip = open (self->gpiochip, O_RDWR | O_CLOEXEC);
  if (chip < 0)
    {
      /* fprintd's DeviceAllow= policy denies this even to root. */
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                   "cannot open %s: %s (DeviceAllow=%s rw missing from "
                   "fprintd.service?)", self->gpiochip, g_strerror (errno),
                   self->gpiochip);
      return FALSE;
    }
  req.num_lines = 1;
  req.offsets[0] = irq_line;
  /* Edge detection is not just for the wake-ups: requesting it makes the
   * Intel pinctrl driver put the pad back into a sane input configuration.
   * After an S3 resume the firmware leaves this pad with its input buffer
   * DISABLED and no pull-up — it then reads 0 forever, i.e. "frame pending". */
  req.config.flags = GPIO_V2_LINE_FLAG_INPUT | GPIO_V2_LINE_FLAG_BIAS_PULL_UP |
                     GPIO_V2_LINE_FLAG_EDGE_FALLING | GPIO_V2_LINE_FLAG_EDGE_RISING;
  g_strlcpy (req.consumer, "goodixtls-irq", sizeof req.consumer);
  if (ioctl (chip, GPIO_V2_GET_LINE_IOCTL, &req) < 0 || req.fd < 0)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                   "cannot request IRQ line %u on %s: %s", irq_line,
                   self->gpiochip, g_strerror (errno));
      close (chip);
      return FALSE;
    }
  close (chip);
  self->irq_fd = req.fd;
  g_unix_set_fd_nonblocking (self->irq_fd, TRUE, NULL);
  return TRUE;
}

/* Hardware reset through the ACPI-declared GpioIo: a short PULSE. Holding the
 * line down was measured to be counter-productive, recovery failing where a
 * pulse succeeds. (It does not reset the MCU core, whose TLS state survives
 * it: see gx_tls_unlock.) */
static void
gx_gpio_reset (FpiDeviceGoodixTls *self)
{
  struct gpio_v2_line_request req = { 0 };
  struct gpio_v2_line_values val = { .mask = 1 };
  int chip = open (self->gpiochip, O_RDWR | O_CLOEXEC);

  if (chip < 0)
    {
      fp_warn ("reset: cannot open %s: %s", self->gpiochip, g_strerror (errno));
      return;
    }
  req.num_lines = 1;
  req.offsets[0] = self->reset_line;
  req.config.flags = GPIO_V2_LINE_FLAG_OUTPUT;
  g_strlcpy (req.consumer, "goodixtls", sizeof req.consumer);
  if (ioctl (chip, GPIO_V2_GET_LINE_IOCTL, &req) < 0 || req.fd < 0)
    {
      fp_warn ("reset: cannot request line %u: %s", self->reset_line,
               g_strerror (errno));
      close (chip);
      return;
    }
  close (chip);

  val.bits = 0;                                       /* assert */
  if (ioctl (req.fd, GPIO_V2_LINE_SET_VALUES_IOCTL, &val) < 0)
    fp_warn ("reset: cannot assert line: %s", g_strerror (errno));
  g_usleep (GX_RESET_PULSE_US);
  val.bits = 1;                                       /* release */
  if (ioctl (req.fd, GPIO_V2_LINE_SET_VALUES_IOCTL, &val) < 0)
    fp_warn ("reset: cannot release line: %s", g_strerror (errno));
  close (req.fd);
  g_usleep (GX_RESET_SETTLE_US);

  /* A reset pulse does not empty the sensor's transmit queue. */
  gx_flush_rx (self);
}

/* ------------------------------------------------------------------ */
/*  TLS session                                                        */
/* ------------------------------------------------------------------ */

/* Reads the pre-shared key out of the sensor's RAM. Between attempts, either
 * resets the sensor or, where a reset would undo the chip enable, only drops
 * whatever a late reply left queued. self->psk is only ever replaced by a
 * complete key. */
static gboolean
gx_read_psk (FpiDeviceGoodixTls *self, gboolean reset_between)
{
  guint8 key[GOODIX_PSK_LEN];
  gboolean ok = FALSE;
  int att;

  for (att = 1; att <= GX_PSK_ATTEMPTS; att++)
    {
      if (gx_mem_read (self, self->fw->psk_addr, GOODIX_PSK_LEN, key) ==
          GOODIX_PSK_LEN)
        {
          memcpy (self->psk, key, GOODIX_PSK_LEN);
          ok = TRUE;
          break;
        }
      fp_info ("PSK read attempt %d failed", att);
      if (reset_between)
        gx_gpio_reset (self);
      else
        gx_flush_rx (self);
    }
  explicit_bzero (key, sizeof key);
  return ok;
}

/* Resets the sensor, clears any TLS state the MCU kept, uploads the
 * configuration blob (which opens the command gate), then enables the chip
 * and requests a TLS session. The sensor's ClientHello follows. */
static gboolean
gx_upload_config_and_reqtls (FpiDeviceGoodixTls *self)
{
  g_autofree guint8 *cfg = g_malloc (CONFIG_PCAP_LEN + 4);
  gsize n;

  gx_gpio_reset (self);

  /* A session abandoned half-way (a failed handshake, a killed process)
   * otherwise lingers on the MCU, and every later handshake gets less likely
   * to go through. */
  gx_tls_unlock (self);

  n = gx_build_cmd (cfg, GOODIX_CMD_UPLOAD_CFG, CONFIG_PCAP, CONFIG_PCAP_LEN);
  if (!gx_command (self, cfg, n, GX_CFG_NOP_GAP_US, 300, NULL))
    fp_dbg ("configuration upload not acknowledged");
  if (!gx_command (self, GX_ENABLE, sizeof GX_ENABLE, GX_NOP_GAP_US,
                   GX_ACK_TIMEOUT_MS, NULL))
    fp_dbg ("enable not acknowledged");

  /* Where the key is only settled once the chip is enabled (11034), read it
   * now: request-TLS below closes memory reads, and by this point the unlock
   * above has dropped any session an earlier process left on the MCU. No
   * reset between attempts, which would undo enable. Without the key, give
   * this attempt up rather than run a handshake that is bound to fail. */
  if (self->fw->psk_after_enable && !gx_read_psk (self, FALSE))
    {
      fp_warn ("cannot read the TLS key after enable");
      return FALSE;
    }

  if (!gx_command (self, GX_REQTLS, sizeof GX_REQTLS, GX_NOP_GAP_US,
                   GX_ACK_TIMEOUT_MS, NULL))
    {
      fp_warn ("request-TLS not acknowledged");
      return FALSE;
    }
  return TRUE;
}

/* Runs the TLS-PSK handshake, with us as the server. */
static gboolean
gx_tls_handshake (FpiDeviceGoodixTls *self)
{
  g_autoptr(GError) err = NULL;

  self->tls_rxlen = self->tls_rxpos = 0;
  g_clear_pointer (&self->tls, gx_tls_free);
  self->tls = gx_tls_new (self->psk, GOODIX_PSK_LEN, GOODIX_TLS_IDENTITY,
                          gx_bio_send, gx_bio_recv, self);
  if (!self->tls)
    {
      fp_warn ("cannot set up the TLS channel");
      return FALSE;
    }
  if (!gx_tls_handshake_run (self->tls, &err))
    {
      fp_warn ("%s", err->message);
      return FALSE;
    }
  fp_info ("TLS-PSK session up (%s; sensor offered %s)",
           gx_tls_ciphersuite (self->tls), gx_tls_offered (self->tls));
  self->tls_up = TRUE;

  g_usleep (GX_TLS_OK_SETTLE_US);
  if (!gx_command (self, GX_TLS_OK, sizeof GX_TLS_OK, GX_NOP_GAP_US,
                   GX_ACK_TIMEOUT_MS, NULL))
    fp_dbg ("TLS-OK (0xD4) not acknowledged");
  return TRUE;
}

static void
gx_tls_teardown (FpiDeviceGoodixTls *self)
{
  if (self->tls_up)
    {
      gx_tls_close (self->tls);
      self->tls_up = FALSE;
    }
  g_clear_pointer (&self->tls, gx_tls_free);

  /* Leave the MCU without TLS state, whatever happened to the session: the
   * close_notify above may not have been processed, and a half-open session
   * left on the MCU is what degrades the next handshakes. */
  if (self->spi_fd >= 0 && self->irq_fd >= 0)
    {
      gx_flush_rx (self);
      gx_tls_unlock (self);
    }
}

/* Establishes the TLS channel. It does not depend on when the finger arrives,
 * so it is done once per open and kept. */
static gboolean
gx_tls_session (FpiDeviceGoodixTls *self)
{
  int att;

  for (att = 1; !self->tls_up && att <= GX_TLS_ATTEMPTS; att++)
    {
      if (fpi_device_action_is_cancelled (FP_DEVICE (self)))
        {
          fp_info ("TLS setup cancelled by the caller");
          break;
        }
      if (gx_upload_config_and_reqtls (self) && gx_tls_handshake (self))
        break;
      gx_tls_teardown (self);
      fp_info ("handshake attempt %d failed", att);
    }
  if (!self->tls_up)
    fp_warn ("no TLS session; if this persists the sensor needs a full "
             "power-off (charger unplugged) to recover");
  return self->tls_up;
}

/* ------------------------------------------------------------------ */
/*  Image capture                                                      */
/* ------------------------------------------------------------------ */

/* Capture sequence, byte for byte as observed on the wire from the vendor
 * driver: MCU state, two rounds of finger-detection setup (reference levels,
 * then raw levels), a navigation frame, two register reads, then the image. */
static const guint8 SEQ_MCU[] = { 0xae, 0x0b, 0x00, 0x06, 0x00, 0xff, 0xff, 0x00, 0x08, 0xff, 0x01, 0x00, 0x1a, 0xcb };
static const guint8 SEQ_FDT_A2[] = { 0x36, 0x25, 0x00, 0x00, 0x01, 0x00, 0x00, 0x4e, 0x01, 0x75, 0x01, 0x7a, 0x01, 0x71, 0x01, 0x52, 0x01, 0x75, 0x01, 0x70, 0x01, 0x72, 0x01, 0x52, 0x01, 0x83, 0x01, 0x77, 0x01, 0x6c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33 };
static const guint8 SEQ_NAV[] = { 0x50, 0x03, 0x00, 0x01, 0x00, 0x56 };
static const guint8 SEQ_FDT_B1[] = { 0x36, 0x23, 0x00, 0x0d, 0x01, 0xa7, 0xa7, 0xba, 0xba, 0xbd, 0xbd, 0xb8, 0xb8, 0xa9, 0xa9, 0xba, 0xba, 0xb8, 0xb8, 0xb9, 0xb9, 0xa9, 0xa9, 0xc1, 0xc1, 0xbb, 0xbb, 0xb6, 0xb6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x39 };
static const guint8 SEQ_FDT_B2[] = { 0x36, 0x25, 0x00, 0x00, 0x01, 0x00, 0x00, 0x4d, 0x01, 0x74, 0x01, 0x79, 0x01, 0x70, 0x01, 0x51, 0x01, 0x74, 0x01, 0x6f, 0x01, 0x71, 0x01, 0x51, 0x01, 0x83, 0x01, 0x76, 0x01, 0x6b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e };
static const guint8 SEQ_REG_A[] = { 0x82, 0x06, 0x00, 0x00, 0x82, 0x00, 0x02, 0x00, 0x9e };
static const guint8 SEQ_REG_B[] = { 0x82, 0x03, 0x00, 0x14, 0x80, 0x91 };
static const guint8 SEQ_IMAGE[] = { 0x20, 0x03, 0x00, 0x01, 0x00, 0x86 };

static const struct { const guint8 *body; gsize len; } gx_capture_seq[] = {
  { SEQ_MCU, sizeof SEQ_MCU },
  { GX_FDT_PROBE, sizeof GX_FDT_PROBE },
  { SEQ_FDT_A2, sizeof SEQ_FDT_A2 },
  { SEQ_NAV, sizeof SEQ_NAV },
  { SEQ_FDT_B1, sizeof SEQ_FDT_B1 },
  { SEQ_FDT_B2, sizeof SEQ_FDT_B2 },
  { SEQ_REG_A, sizeof SEQ_REG_A },
  { SEQ_REG_B, sizeof SEQ_REG_B },
  { SEQ_IMAGE, sizeof SEQ_IMAGE },
};

/* Sends one capture-sequence command and consumes its replies: the ACK, then
 * the data reply carrying the same command byte or — for the image command —
 * the TLS record, which is left in tls_rx for gx_capture_frame(). The next
 * command must not follow within GX_SEQ_GAP_US: at 10 ms every capture failed
 * and the sensor wedged (measured with the original transport, 19 out of 19). */
static void
gx_send_seq_cmd (FpiDeviceGoodixTls *self, const guint8 *body, gsize n)
{
  g_autofree guint8 *rx = g_malloc (GX_RX_MAX);
  guint8 ty;
  int got = 0;

  gx_send_cmd (self, body, n, GX_NOP_GAP_US);
  for (;;)
    {
      int r = gx_recv (self, &ty, rx, GX_RX_MAX,
                       got ? GX_DRAIN_SILENCE_MS : GX_DRAIN_FIRST_MS);

      if (r <= 0)
        break;                                 /* silence: exchange over */
      if (ty == GOODIX_PKT_TLS)
        {
          memcpy (self->tls_rx, rx, r);
          self->tls_rxlen = r;
          self->tls_rxpos = 0;
          break;
        }
      got++;
      if (rx[0] == body[0])
        break;                                 /* the data reply: complete */
    }
  gx_quiet (self, GX_SEQ_GAP_US);
}

/* Decodes the 12-bit samples: six bytes carry four pixels, interleaved. */
static void
gx_decode_12bit (const guint8 *data, gsize len, guint16 *out, gsize n)
{
  gsize i, o = 0;

  for (i = 0; i + 6 <= len && o + 4 <= n; i += 6)
    {
      const guint8 *c = data + i;

      out[o++] = ((c[0] & 0xf) << 8) | c[1];
      out[o++] = (c[3] << 4) | (c[0] >> 4);
      out[o++] = ((c[5] & 0xf) << 8) | c[2];
      out[o++] = (c[4] << 4) | (c[5] >> 4);
    }
}

/* Captures one full image, assuming a TLS session is up, and fills
 * px[GOODIX_IMG_PIXELS] with 12-bit samples. */
static gboolean
gx_capture_frame (FpiDeviceGoodixTls *self, guint16 *px)
{
  g_autofree guint8 *img = g_malloc (GX_RX_MAX);
  guint8 st = 0x55, cmd[5];
  gssize got;
  gsize i;

  /* After a failed capture the session is dropped (below): bring it back. */
  if (!self->tls_up && !gx_tls_session (self))
    return FALSE;

  /* MCU state query, over TLS. */
  gx_build_cmd (cmd, GOODIX_CMD_MCU_STATE, &st, 1);
  if (!gx_tls_write (self->tls, cmd, sizeof cmd))
    {
      gx_tls_teardown (self);
      return FALSE;
    }
  gx_quiet (self, GX_MCU_STATE_GAP_US);

  self->tls_rxlen = self->tls_rxpos = 0;
  for (i = 0; i < G_N_ELEMENTS (gx_capture_seq); i++)
    gx_send_seq_cmd (self, gx_capture_seq[i].body, gx_capture_seq[i].len);

  /* The image arrives as ONE record larger than TLS allows, so it is decrypted
   * here rather than handed to OpenSSL, which would reject it outright. It has
   * normally been picked up by the last command of the sequence. */
  if (self->tls_rxpos >= self->tls_rxlen && !gx_fetch_tls_record (self))
    {
      fp_warn ("no image record from the sensor");
      gx_tls_teardown (self);
      return FALSE;
    }
  got = gx_tls_decrypt_record (self->tls, self->tls_rx + self->tls_rxpos,
                               self->tls_rxlen - self->tls_rxpos,
                               img, GX_RX_MAX);
  self->tls_rxlen = self->tls_rxpos = 0;
  /* 8-byte header, then 12 bits per pixel. */
  if (got < 8 + GOODIX_IMG_PIXELS * 3 / 2)
    {
      /* A lost or undecryptable record leaves our record sequence number out
       * of step with the sensor's for good: drop the session, so that the
       * next capture starts a fresh one instead of failing forever. */
      fp_warn ("cannot decrypt the image record, or incomplete image (%zd)", got);
      gx_tls_teardown (self);
      return FALSE;
    }
  /* Header is a tag, a 16-bit length and five zero bytes, then the 12-bit
   * samples: skip 8 bytes. */
  gx_decode_12bit (img + 8, got - 8, px, GOODIX_IMG_PIXELS);
  return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Finger detection                                                   */
/* ------------------------------------------------------------------ */

/* Native finger detection: twelve 16-bit values, one per sensor zone, in about
 * 30 ms — much faster than capturing an image. A finger pulls those values
 * DOWN by roughly 100 counts, which is what makes cheap polling possible. */
static gboolean
gx_fdt_probe (FpiDeviceGoodixTls *self, int *out12)
{
  guint8 rx[64];
  int k;

  if (gx_query (self, GX_FDT_PROBE, sizeof GX_FDT_PROBE, rx, sizeof rx) < 31)
    return FALSE;
  for (k = 0; k < 12; k++)
    out12[k] = rx[7 + 2 * k] | (rx[8 + 2 * k] << 8);
  return TRUE;
}

/* Mean of the twelve values: an absolute test needing no baseline. */
static int
gx_fdt_mean (const int *v)
{
  int k, s = 0;

  for (k = 0; k < 12; k++)
    s += v[k];
  return s / 12;
}

/* Mean drop against the baseline. */
static int
gx_fdt_drop (const int *base, const int *cur)
{
  int k, d = 0;

  for (k = 0; k < 12; k++)
    d += base[k] - cur[k];
  return d / 12;
}

static gboolean
gx_fdt_is_finger (FpiDeviceGoodixTls *self, const int *cur)
{
  return gx_fdt_drop (self->fdt_base, cur) > GOODIX_FDT_DROP ||
         gx_fdt_mean (cur) < self->fdt_abs;
}

/* Lifted: the hysteresis keeps a light, wobbling press from flickering. */
static gboolean
gx_fdt_is_lifted (FpiDeviceGoodixTls *self, const int *cur)
{
  return gx_fdt_drop (self->fdt_base, cur) < GOODIX_FDT_DROP / 2 &&
         gx_fdt_mean (cur) >= self->fdt_abs;
}

static gboolean
gx_finger_present (FpiDeviceGoodixTls *self)
{
  int cur[12];

  return gx_fdt_probe (self, cur) && gx_fdt_is_finger (self, cur);
}

/* ------------------------------------------------------------------ */
/*  Session: TLS setup, background frame, detection baseline           */
/* ------------------------------------------------------------------ */

/* How long to wait for the finger to be lifted before taking the background. */
#define GX_BG_WAIT_MS 2000

/* Takes the background with the finger LIFTED. A finger left resting on the
 * sensor when the operation starts ends up in the background, the difference
 * then cancels out, and the capture is worthless — observed as verifications
 * collapsing from about 100 matches to 6. So wait for the finger to go (probe
 * first: a probe costs 30 ms, a background capture 0.6 s), capture, and redo
 * it if a finger landed during the capture. The presence test is the ABSOLUTE
 * one: the relative baseline is precisely what comes next. */
static gboolean
gx_take_background (FpiDeviceGoodixTls *self)
{
  int cur[12], waited = 0;
  gboolean timeout = FALSE;

  for (;;)
    {
      while (!timeout && gx_fdt_probe (self, cur) &&
             gx_fdt_mean (cur) < self->fdt_abs)
        {
          if (waited >= GX_BG_WAIT_MS)
            timeout = TRUE;
          else
            {
              g_usleep (200 * 1000);
              waited += 200;
            }
        }

      if (!gx_capture_frame (self, self->bg_frame))
        return FALSE;
      if (!gx_fdt_probe (self, cur) || gx_fdt_mean (cur) >= self->fdt_abs)
        break;                                     /* no finger: good */
      if (timeout)
        {
          fp_warn ("finger still down after %d ms: background degraded",
                   GX_BG_WAIT_MS);
          self->bg_dirty = TRUE;
          break;
        }
    }
  if (waited)
    fp_info ("background delayed %d ms (finger was down)", waited);
  return TRUE;
}

/* Detection baseline; taken right after the background, finger absent. The
 * absolute floor is derived from THIS unit's idle level rather than a fixed
 * number: a finger only ever pulls the mean down, so the floor sits a fixed
 * margin below idle wherever idle happens to be. */
static gboolean
gx_calibrate_fdt (FpiDeviceGoodixTls *self)
{
  int t[12], acc[12] = { 0 }, nb = 0, q, k;

  for (q = 0; q < 4; q++)
    if (gx_fdt_probe (self, t))
      {
        for (k = 0; k < 12; k++)
          acc[k] += t[k];
        nb++;
      }
  if (!nb)
    return FALSE;
  for (k = 0; k < 12; k++)
    self->fdt_base[k] = acc[k] / nb;
  self->fdt_abs = gx_fdt_mean (self->fdt_base) - GOODIX_FDT_ABS_MARGIN;
  fp_dbg ("FDT calibrated: idle mean=%d -> floor=%d (drop>%d)",
          gx_fdt_mean (self->fdt_base), self->fdt_abs, GOODIX_FDT_DROP);
  return TRUE;
}

/* Brings the sensor to "ready to capture": TLS up (kept across operations),
 * then a fresh background and detection baseline. These two must be taken
 * JUST BEFORE each operation: the baseline drifts, and a background a few tens
 * of seconds old collapses the score (measured: 11-28 matches with a fresh one
 * against 2-4). */
static gboolean
gx_session_start (FpiDeviceGoodixTls *self)
{
  gint64 t0 = g_get_monotonic_time ();

  if (!gx_tls_session (self))
    return FALSE;
  self->bg_dirty = FALSE;
  if (!self->bg_frame)
    self->bg_frame = g_new (guint16, GOODIX_IMG_PIXELS);
  if (!gx_take_background (self))
    return FALSE;
  /* A finger was still down: the operation fails with "remove finger", and
   * the detection baseline must not be recalibrated from finger-down values. */
  if (self->bg_dirty)
    return TRUE;
  if (!gx_calibrate_fdt (self))
    return FALSE;
  fp_dbg ("session ready in %d ms", (int) ((g_get_monotonic_time () - t0) / 1000));
  return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Pre-processing and descriptors                                     */
/* ------------------------------------------------------------------ */

static int
gx_cmp_dbl (const void *a, const void *b)
{
  double x = *(const double *) a - *(const double *) b;

  return (x > 0) - (x < 0);
}

/* Subtracts the background, then removes row and column banding with a
 * median. */
static double *
gx_preprocess (FpiDeviceGoodixTls *self, const guint16 *px)
{
  const int W = GOODIX_IMG_WIDTH, H = GOODIX_IMG_HEIGHT;
  double *d = g_new (double, GOODIX_IMG_PIXELS);
  double buf[MAX (GOODIX_IMG_WIDTH, GOODIX_IMG_HEIGHT)];
  int x, y, i;

  for (i = 0; i < GOODIX_IMG_PIXELS; i++)
    d[i] = (double) self->bg_frame[i] - px[i];
  for (y = 0; y < H; y++)
    {
      for (x = 0; x < W; x++)
        buf[x] = d[y * W + x];
      qsort (buf, W, sizeof (double), gx_cmp_dbl);
      for (x = 0; x < W; x++)
        d[y * W + x] -= buf[W / 2];
    }
  for (x = 0; x < W; x++)
    {
      for (y = 0; y < H; y++)
        buf[y] = d[y * W + x];
      qsort (buf, H, sizeof (double), gx_cmp_dbl);
      for (y = 0; y < H; y++)
        d[y * W + x] -= buf[H / 2];
    }
  return d;
}

/* Dumps captures for offline evaluation. Only active while the directory
 * exists — root creates it by hand, inside fprintd's RuntimeDirectory — and
 * never on a normal install. pN.bin holds the raw frame as 16-bit samples and
 * pN.bin.bg the matching background. These ARE fingerprint images: delete the
 * directory when done. */
#define GX_DUMP_DIR "/run/goodixtls/dump"

static void
gx_dump_capture (FpiDeviceGoodixTls *self, const guint16 *px)
{
  static int seq = 0;
  g_autofree gchar *p = NULL, *b = NULL;

  if (!g_file_test (GX_DUMP_DIR, G_FILE_TEST_IS_DIR))
    return;
  do
    {
      g_free (p);
      p = g_strdup_printf ("%s/p%03d.bin", GX_DUMP_DIR, ++seq);
    }
  while (g_file_test (p, G_FILE_TEST_EXISTS) && seq < 9999);
  b = g_strdup_printf ("%s.bg", p);
  if (g_file_set_contents_full (p, (const gchar *) px,
                                sizeof (guint16) * GOODIX_IMG_PIXELS,
                                G_FILE_SET_CONTENTS_NONE, 0600, NULL) &&
      g_file_set_contents_full (b, (const gchar *) self->bg_frame,
                                sizeof (guint16) * GOODIX_IMG_PIXELS,
                                G_FILE_SET_CONTENTS_NONE, 0600, NULL))
    fp_info ("capture saved: %s", p);
}

/* Captures one press and extracts its descriptors, or returns NULL when the
 * image is unusable. */
static GxSiftFeatures *
gx_capture_features (FpiDeviceGoodixTls *self)
{
  guint16 px[GOODIX_IMG_PIXELS];
  g_autofree double *img = NULL;
  double m = 0, v = 0;
  GxSiftFeatures *f;
  int i;

  if (!gx_capture_frame (self, px))
    return NULL;
  gx_dump_capture (self, px);
  img = gx_preprocess (self, px);

  /* This quality gate is ESSENTIAL. The keypoint detector always returns
   * maxima, even on pure noise, so the number of points says nothing about
   * whether a capture is usable. What separates them is contrast. Without this
   * check a failed press enters the template and degrades it permanently. */
  for (i = 0; i < GOODIX_IMG_PIXELS; i++)
    m += img[i];
  m /= GOODIX_IMG_PIXELS;
  for (i = 0; i < GOODIX_IMG_PIXELS; i++)
    v += (img[i] - m) * (img[i] - m);
  v = sqrt (v / GOODIX_IMG_PIXELS);
  if (v < GX_MIN_CONTRAST)
    {
      fp_info ("capture rejected: contrast %.0f (no finger?)", v);
      return NULL;
    }
  f = gx_sift_extract (img, GOODIX_IMG_WIDTH, GOODIX_IMG_HEIGHT);
  if (f->n < 8)
    g_clear_pointer (&f, gx_sift_free);
  return f;
}

/* ------------------------------------------------------------------ */
/*  Matching                                                           */
/* ------------------------------------------------------------------ */

/* Decision threshold: how many points of the capture the template explains,
 * with the rigid geometric check of goodix_sift.c (rotation up to 20 degrees,
 * clusters of at least 4 points).
 *
 * BEWARE — THE FUSED SCORE GROWS WITH HOW RICH THE TEMPLATE IS, for a foreign
 * finger as well as the right one, so this must be re-measured against a
 * varied impostor set whenever enrolment or matching changes. A threshold set
 * on a handful of samples from one foreign finger once let false accepts
 * through as soon as the set was widened.
 *
 * Measured with one-to-one pairs, on a 30-view enrolment with 16 captures of
 * four other fingers: every impostor at 0, also with 16 adaptive views on
 * top; genuine normal presses 14-79. Against a deliberately wide template
 * (42 pooled captures, rotated presses included) the impostor maximum was 7:
 * re-measure after an enrolment that covers much more of the finger. */
#define GX_MATCH_THRESHOLD 12

/* Fused score: the number of capture points that AT LEAST ONE template view
 * explains. A press often overlaps several views without covering any of them
 * decisively; taking the best single view threw that distributed evidence
 * away. Chance matches from a foreign finger do not accumulate the same way:
 * they fail the geometric check. */
static int
gx_fused_score (GPtrArray *views, const GxSiftFeatures *probe)
{
  g_autofree guint8 *seen = g_new0 (guint8, probe->n);
  int score = 0;
  guint i;

  for (i = 0; i < views->len; i++)
    gx_sift_match_mask (g_ptr_array_index (views, i), probe, seen);
  for (i = 0; i < probe->n; i++)
    score += seen[i];
  return score;
}

/* What determines template quality is the number of DISTINCT presses, not the
 * raw number of captures: two captures back to back show almost the same area.
 * Coverage is the dominant factor. */
#define GX_ENROLL_STAGES 15   /* presses asked of the user */
#define GX_VIEWS_PER_STAGE 2  /* a second view adds slight variation for free */

/* ------------------------------------------------------------------ */
/*  Serialising a set of views into an FpPrint                         */
/* ------------------------------------------------------------------ */

static GVariant *
gx_views_to_variant (GPtrArray *views)
{
  GVariantBuilder b;
  guint i;

  g_variant_builder_init (&b, G_VARIANT_TYPE ("aay"));
  for (i = 0; i < views->len; i++)
    {
      g_autoptr(GByteArray) ba = gx_sift_serialize (g_ptr_array_index (views, i));

      g_variant_builder_add_value (
        &b, g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, ba->data, ba->len, 1));
    }
  return g_variant_new ("aay", &b);
}

/* Appends the views stored in @print to @views. */
static void
gx_views_from_print (FpPrint *print, GPtrArray *views)
{
  g_autoptr(GVariant) data = NULL;
  GVariantIter it;
  GVariant *child;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_is_of_type (data, G_VARIANT_TYPE ("aay")))
    return;
  g_variant_iter_init (&it, data);
  while ((child = g_variant_iter_next_value (&it)))
    {
      gsize len = 0;
      const guint8 *raw = g_variant_get_fixed_array (child, &len, 1);
      GxSiftFeatures *f = gx_sift_deserialize (raw, len);

      if (f)
        g_ptr_array_add (views, f);
      g_variant_unref (child);
    }
}

/* ------------------------------------------------------------------ */
/*  Adaptive store: widening coverage as the sensor gets used          */
/* ------------------------------------------------------------------ */

/* libfprint offers no way to hand back an enriched template: verify completion
 * takes no FpPrint, and fprintd only writes a template from the enrol path. So
 * the driver keeps its own store alongside fprintd's — never inside it, since
 * fprintd scans its own directory and would mistake our files for templates.
 *
 * SAFETY — the rule that makes adaptation harmless: the acquisition threshold
 * sits strictly ABOVE the decision threshold. Anyone triggering an acquisition
 * is therefore already authenticating with a comfortable margin, so adaptation
 * never lowers the bar for an attacker; it only widens the coverage of someone
 * who already passes. Without that rule a doubtful accept would be written
 * permanently into the template, which is template poisoning. */
#define GX_ADAPT_MIN      (2 * GX_MATCH_THRESHOLD)
/* Novelty ceiling, as a FRACTION of the capture's points: the score scales
 * with template richness, so a fixed ceiling would stop qualifying anything as
 * the template improves. Above 60 % the area is already well covered. */
#define GX_ADAPT_MAX_FRAC 0.60
#define GX_ADAPT_VIEWS    20     /* cap, bounding verification time */
/* Inside fprintd's state directory: its unit declares ProtectSystem=strict
 * with StateDirectory=fprint, leaving the rest of the filesystem read-only.
 * The leading dot keeps it from ever being taken for a user directory. */
#define GX_ADAPT_DIR      "/var/lib/fprint/.goodixtls-adapt"

/* Store path for a given template, or NULL when the template carries no usable
 * identity. The user name comes from fprintd; reject anything that could escape
 * the directory. */
static gchar *
gx_adapt_path (FpPrint *print)
{
  const gchar *user = print ? fp_print_get_username (print) : NULL;

  if (!user || !*user || strchr (user, '/') || user[0] == '.')
    return NULL;
  return g_strdup_printf ("%s/%s.%d.views", GX_ADAPT_DIR, user,
                          (int) fp_print_get_finger (print));
}

/* Appends the stored views to @views and returns how many there were. The
 * file is a sequence of length-prefixed blocks, each one a view serialised
 * exactly as in an fprintd template. */
static guint
gx_adapt_load (const gchar *path, GPtrArray *views)
{
  g_autofree gchar *raw = NULL;
  gsize len = 0, off = 0;
  guint n = 0;

  if (!path || !g_file_get_contents (path, &raw, &len, NULL))
    return 0;
  while (off + 4 <= len)
    {
      guint32 sz;
      GxSiftFeatures *f;

      memcpy (&sz, raw + off, 4);
      off += 4;
      if (sz > len - off)
        break;                          /* truncated file: keep what we have */
      f = gx_sift_deserialize ((const guint8 *) raw + off, sz);
      if (f)
        {
          g_ptr_array_add (views, f);
          n++;
        }
      off += sz;
    }
  return n;
}

static gboolean
gx_adapt_append (const gchar *path, const GxSiftFeatures *f)
{
  g_autoptr(GByteArray) blob = NULL;
  guint32 sz;
  gboolean ok;
  int fd;

  if (!path)
    return FALSE;
  blob = gx_sift_serialize (f);
  if (g_mkdir_with_parents (GX_ADAPT_DIR, 0700) != 0)
    {
      fp_warn ("adaptive store: cannot create %s: %s", GX_ADAPT_DIR,
               g_strerror (errno));
      return FALSE;
    }
  /* Append only: a view already written is never rewritten, so a crash mid
   * write can only damage the last one, which the reader then skips. */
  fd = open (path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0)
    {
      fp_warn ("adaptive store: %s: %s", path, g_strerror (errno));
      return FALSE;
    }
  sz = blob->len;
  ok = write (fd, &sz, 4) == 4 &&
       write (fd, blob->data, blob->len) == (gssize) blob->len;
  if (close (fd) != 0 || !ok)
    {
      fp_warn ("adaptive store: short write to %s", path);
      return FALSE;
    }
  return TRUE;
}

/* Clears the store when its template is re-enrolled: acquired views must not
 * outlive the template that authorised them. */
static void
gx_adapt_clear (FpPrint *print)
{
  g_autofree gchar *path = gx_adapt_path (print);

  if (path && g_unlink (path) == 0)
    fp_info ("adaptive store cleared (%s)", path);
}

/* fprintd deletes the template itself and NEVER tells the driver: our prints
 * are host-stored, and libfprint's delete vfunc only covers templates kept on
 * the device. Without this sweep, deleting a fingerprint in the desktop
 * settings would leave its descriptors on disk indefinitely — a privacy
 * problem, not merely untidiness. So catch up at open time: any store whose
 * fprintd template has vanished is removed. */
static void
gx_adapt_sweep (void)
{
  GDir *d = g_dir_open (GX_ADAPT_DIR, 0, NULL);
  const gchar *name;

  if (!d)
    return;
  while ((name = g_dir_read_name (d)))
    {
      g_autofree gchar *stem = NULL, *userdir = NULL, *finger = NULL;
      gboolean found = FALSE;
      gchar *dot;
      GDir *dd;

      if (!g_str_has_suffix (name, ".views"))
        continue;
      stem = g_strndup (name, strlen (name) - strlen (".views"));
      /* Split "<user>.<finger>" at the LAST dot: a user name may contain one. */
      dot = strrchr (stem, '.');
      if (!dot || !dot[1])
        continue;
      *dot = '\0';
      /* Our name carries the finger number in decimal; fprintd names the
       * template file after it in hex (finger 10 is "a"). */
      finger = g_strdup_printf ("%x", (guint) g_ascii_strtoull (dot + 1, NULL, 10));

      /* The template lives under <user>/<driver id>/<device id>/<finger>. */
      userdir = g_build_filename ("/var/lib/fprint", stem, "goodixtls", NULL);
      dd = g_dir_open (userdir, 0, NULL);
      if (dd)
        {
          const gchar *devid;

          while (!found && (devid = g_dir_read_name (dd)))
            {
              g_autofree gchar *p = g_build_filename (userdir, devid, finger, NULL);

              found = g_file_test (p, G_FILE_TEST_EXISTS);
            }
          g_dir_close (dd);
        }
      if (!found)
        {
          g_autofree gchar *victim = g_build_filename (GX_ADAPT_DIR, name, NULL);

          if (g_unlink (victim) == 0)
            fp_info ("removed orphaned adaptive store %s", name);
        }
    }
  g_dir_close (d);
}

/* ------------------------------------------------------------------ */
/*  Enrolment and verification state machine                          */
/* ------------------------------------------------------------------ */

typedef struct
{
  gboolean        verifying;
  GPtrArray      *views;      /* enrol: views so far; verify: template + store */
  guint           n_adapt;    /* verify: how many of @views come from the store */
  gchar          *adapt_path; /* verify: the template's adaptive store */
  GxSiftFeatures *probe;      /* verify: the capture being scored */
  int             score;      /* verify: its fused score */
  int             stage;      /* enrol: presses accepted so far */
  int             polls;      /* detection polls in the current wait state */
  GxSiftIsland   *island;     /* enrol: coverage map, for guidance logs */
} GxTask;

static void
gx_task_free (GxTask *t)
{
  g_clear_pointer (&t->views, g_ptr_array_unref);
  g_clear_pointer (&t->adapt_path, g_free);
  g_clear_pointer (&t->probe, gx_sift_free);
  g_clear_pointer (&t->island, gx_sift_island_free);
  g_free (t);
}

enum {
  GX_ST_SESSION,       /* TLS, background and detection baseline */
  GX_ST_WAIT_ON,       /* poll until the finger is down */
  GX_ST_CAPTURE,       /* capture, then extract descriptors (and score) */
  GX_ST_WAIT_OFF,      /* poll until the finger is lifted */
  GX_ST_DONE,
  GX_ST_NUM,
};

#define GX_POLL_MS     100     /* detection polling period */
#define GX_POLL_MAX    300     /* about 30 s before giving up */
#define GX_POLL_OFF    100     /* about 10 s to wait for release */

/* --- off-loading the blocking work -----------------------------------
 *
 * Session setup (TLS handshake plus a background capture) and image capture
 * take most of a second each and go through OpenSSL's blocking API over a
 * synchronous SPI descriptor. Run inline they froze fprintd's main loop, so
 * they run in a worker thread, the result coming back on the main loop.
 * libfprint runs one operation at a time and the state machine waits for the
 * callback, so nothing else touches the device meanwhile. Finger detection
 * polls stay on the main loop: about 30 ms each. */

typedef struct
{
  FpiSsm         *ssm;       /* NULL for open and close */
  FpDevice       *dev;
  GxSiftFeatures *feat;      /* capture result, NULL on failure */
  GPtrArray      *extra;     /* enrol: additional views of the same press */
  int             score;     /* verify: fused score of @feat */
  gboolean        ok;
  GError         *error;     /* open: why it failed */
} GxWork;

static void
gx_work_free (GxWork *w)
{
  g_clear_pointer (&w->feat, gx_sift_free);
  g_clear_pointer (&w->extra, g_ptr_array_unref);
  g_clear_error (&w->error);
  g_free (w);
}

static void
gx_session_thread (GTask *task, gpointer src, gpointer data, GCancellable *c)
{
  GxWork *w = data;

  w->ok = gx_session_start (FPI_DEVICE_GOODIXTLS (w->dev));
  g_task_return_boolean (task, TRUE);
}

static void
gx_capture_thread (GTask *task, gpointer src, gpointer data, GCancellable *c)
{
  GxWork *w = data;
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (w->dev);
  GxTask *t = fpi_ssm_get_data (w->ssm);
  int extra;

  w->feat = gx_capture_features (self);
  w->ok = w->feat != NULL;
  if (!w->ok)
    goto out;

  if (t->verifying)
    {
      /* Scored here rather than on the main loop: matching against up to
       * fifty views takes tens of milliseconds. t->views is read-only while
       * the capture runs. */
      w->score = gx_fused_score (t->views, w->feat);
      goto out;
    }

  /* Several views per press: the finger shifts slightly between captures,
   * which enriches the template without asking for more gestures. */
  w->extra = g_ptr_array_new_with_free_func ((GDestroyNotify) gx_sift_free);
  for (extra = 1; extra < GX_VIEWS_PER_STAGE && gx_finger_present (self); extra++)
    {
      GxSiftFeatures *g = gx_capture_features (self);

      if (g)
        g_ptr_array_add (w->extra, g);
    }
out:
  g_task_return_boolean (task, TRUE);
}

/* Runs @fn on a worker thread, then @done on the main loop. The device is
 * only ever touched by one of them at a time. */
static void
gx_run_async (FpiSsm *ssm, FpDevice *dev, GTaskThreadFunc fn,
              GAsyncReadyCallback done)
{
  GTask *task = g_task_new (dev, NULL, done, NULL);
  GxWork *w = g_new0 (GxWork, 1);

  w->ssm = ssm;
  w->dev = dev;
  g_task_set_task_data (task, w, (GDestroyNotify) gx_work_free);
  g_task_run_in_thread (task, fn);
  g_object_unref (task);
}

static void
gx_session_done (GObject *src, GAsyncResult *res, gpointer user_data)
{
  GxWork *w = g_task_get_task_data (G_TASK (res));
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (w->dev);
  GxTask *t = fpi_ssm_get_data (w->ssm);

  if (!w->ok)
    {
      fpi_ssm_mark_failed (w->ssm, fpi_device_error_new_msg (
        FP_DEVICE_ERROR_PROTO, "sensor initialisation failed"));
      return;
    }
  if (self->bg_dirty)
    {
      /* Better to ask for the finger to be removed than to return a collapsed
       * score the user could not possibly explain. */
      fpi_ssm_mark_failed (w->ssm,
        fpi_device_retry_new (FP_DEVICE_RETRY_REMOVE_FINGER));
      return;
    }
  t->polls = 0;
  fpi_ssm_next_state (w->ssm);
}

/* Records an enrolment view and logs where it landed on the coverage map. The
 * log lines are the only guidance there is: enrol progress carries no
 * message, and the desktop dialogue shows nothing but a counter. */
static void
gx_enroll_add_view (FpDevice *dev, GxTask *t, GxSiftFeatures *f)
{
  int dx = 0, dy = 0, sc = 0, x0, y0, x1, y1;
  guint np = 0;
  gboolean placed;

  g_ptr_array_add (t->views, f);
  t->stage++;
  if (!t->island)
    t->island = gx_sift_island_new ();
  placed = gx_sift_island_add (t->island, f, &dx, &dy, &sc);
  gx_sift_island_extent (t->island, &x0, &y0, &x1, &y1, &np);
  if (placed)
    fp_info ("enroll: stage=%d at=%d,%d overlap=%d extent=%dx%d points=%u",
             t->stage, dx, dy, sc, x1 - x0, y1 - y0, np);
  else
    fp_info ("enroll: stage=%d at=? overlap=%d extent=%dx%d points=%u "
             "(disjoint area)", t->stage, sc, x1 - x0, y1 - y0, np);
  fpi_device_enroll_progress (dev, t->stage, NULL, NULL);
}

static void
gx_capture_done (GObject *src, GAsyncResult *res, gpointer user_data)
{
  GxWork *w = g_task_get_task_data (G_TASK (res));
  FpiSsm *ssm = w->ssm;
  FpDevice *dev = w->dev;
  GxTask *t = fpi_ssm_get_data (ssm);

  if (!w->ok)
    {
      /* Tell the two causes apart: they call for opposite gestures. A finger
       * pressed and lifted at once does trigger detection, but the image is
       * taken once it has gone. */
      FpDeviceRetry why = gx_finger_present (FPI_DEVICE_GOODIXTLS (dev))
                            ? FP_DEVICE_RETRY_CENTER_FINGER
                            : FP_DEVICE_RETRY_TOO_SHORT;

      if (t->verifying)
        {
          fpi_ssm_mark_failed (ssm, fpi_device_retry_new (why));
          return;
        }
      fpi_device_enroll_progress (dev, t->stage, NULL, fpi_device_retry_new (why));
    }
  else if (t->verifying)
    {
      /* Scored ONCE. Re-capturing while the score stays below the threshold
       * would turn one decision into the maximum of several draws — and
       * pam_fprintd multiplies that again with its own retries. Measured: a
       * foreign finger scored 3 on a first capture and 20 on a second. Retries
       * happen on image quality only (above), never on the score. */
      t->probe = g_steal_pointer (&w->feat);
      t->score = w->score;
    }
  else
    {
      g_ptr_array_extend_and_steal (t->views, g_steal_pointer (&w->extra));
      gx_enroll_add_view (dev, t, g_steal_pointer (&w->feat));
    }

  /* PRESENT without NEEDED is the "you may lift now" signal. */
  fpi_device_report_finger_status (dev, FP_FINGER_STATUS_PRESENT);

  /* A verification is decided now: reporting it only once the finger has
   * been lifted held the unlock back for as long as the finger rested on the
   * sensor. (A finger still down when the next operation starts is handled by
   * its background wait.) Enrolment does need the lift between presses. */
  if (t->verifying)
    {
      fpi_ssm_jump_to_state (ssm, GX_ST_DONE);
      return;
    }
  t->polls = 0;
  fpi_ssm_jump_to_state_delayed (ssm, GX_ST_WAIT_OFF, GX_POLL_MS);
}

/* Fails the state machine if the caller cancelled the operation — that is how
 * fprintd stops us when the prompt is dismissed or the password is used. */
static gboolean
gx_cancelled (FpDevice *dev, FpiSsm *ssm)
{
  if (!fpi_device_action_is_cancelled (dev))
    return FALSE;
  fp_info ("operation cancelled by the caller");
  fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NONE);
  fpi_ssm_mark_failed (ssm, g_error_new (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                         "operation cancelled"));
  return TRUE;
}

/* One detection poll per entry; the state re-enters itself until the finger
 * is down. The delayed jump must be the last thing done. */
static void
gx_wait_on (FpiSsm *ssm, FpDevice *dev, GxTask *t)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  int cur[12];

  if (gx_cancelled (dev, ssm))
    return;
  if (t->polls == 0)
    fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NEEDED);
  if (gx_fdt_probe (self, cur))
    {
      if (t->polls % 10 == 0)
        fp_dbg ("wait-on: mean=%d drop=%d (floor %d / drop %d)",
                gx_fdt_mean (cur), gx_fdt_drop (self->fdt_base, cur),
                self->fdt_abs, GOODIX_FDT_DROP);
      if (gx_fdt_is_finger (self, cur))
        {
          /* Keep NEEDED asserted: the capture still takes ~0.6 s and the
           * finger must stay down for it. */
          fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NEEDED |
                                                FP_FINGER_STATUS_PRESENT);
          fpi_ssm_jump_to_state (ssm, GX_ST_CAPTURE);
          return;
        }
    }
  if (++t->polls > GX_POLL_MAX)
    {
      fpi_ssm_mark_failed (ssm, fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      return;
    }
  fpi_ssm_jump_to_state_delayed (ssm, GX_ST_WAIT_ON, GX_POLL_MS);
}

static void
gx_wait_off (FpiSsm *ssm, FpDevice *dev, GxTask *t)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  int cur[12];

  if (gx_cancelled (dev, ssm))
    return;
  if ((gx_fdt_probe (self, cur) && gx_fdt_is_lifted (self, cur)) ||
      ++t->polls > GX_POLL_OFF)
    {
      fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NONE);
      t->polls = 0;
      fpi_ssm_jump_to_state (ssm, t->stage >= GX_ENROLL_STAGES ? GX_ST_DONE
                                                              : GX_ST_WAIT_ON);
      return;
    }
  fpi_ssm_jump_to_state_delayed (ssm, GX_ST_WAIT_OFF, GX_POLL_MS);
}

static void
gx_run_state (FpiSsm *ssm, FpDevice *dev)
{
  GxTask *t = fpi_ssm_get_data (ssm);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case GX_ST_SESSION:
      gx_run_async (ssm, dev, gx_session_thread, gx_session_done);
      break;

    case GX_ST_WAIT_ON:
      gx_wait_on (ssm, dev, t);
      break;

    case GX_ST_CAPTURE:
      gx_run_async (ssm, dev, gx_capture_thread, gx_capture_done);
      break;

    case GX_ST_WAIT_OFF:
      gx_wait_off (ssm, dev, t);
      break;

    case GX_ST_DONE:
      fpi_ssm_mark_completed (ssm);
      break;
    }
}

static void
gx_enroll_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  GxTask *t = fpi_ssm_get_data (ssm);
  FpPrint *print = NULL;

  if (error)
    {
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }
  if (t->views->len < 3)
    {
      fpi_device_enroll_complete (dev, NULL,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "too few usable views"));
      return;
    }

  fpi_device_get_enroll_data (dev, &print);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, FALSE);
  g_object_set (print, "fpi-data", gx_views_to_variant (t->views), NULL);

  /* The template changes: views acquired under the authority of the old one
   * are no longer legitimate. */
  gx_adapt_clear (print);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
gx_verify_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  GxTask *t = fpi_ssm_get_data (ssm);

  if (error)
    {
      if (error->domain == FP_DEVICE_RETRY)
        fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, g_steal_pointer (&error));
      fpi_device_verify_complete (dev, error);
      return;
    }
  if (!t->probe)
    {
      fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
        fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
      fpi_device_verify_complete (dev, NULL);
      return;
    }

  fp_info ("verify: %d matches (threshold %d, %u views + %u acquired)",
           t->score, GX_MATCH_THRESHOLD, t->views->len - t->n_adapt, t->n_adapt);

  /* Acquisition window. The lower bound means certain identity; the upper
   * bound means the area is already well covered. Weak poses — precisely the
   * ones missing from the template — are excluded on purpose, being too
   * uncertain to trust. */
  if (t->score >= GX_ADAPT_MIN &&
      t->score <= (int) (GX_ADAPT_MAX_FRAC * t->probe->n) &&
      t->n_adapt < GX_ADAPT_VIEWS &&
      gx_adapt_append (t->adapt_path, t->probe))
    fp_info ("adaptive store: view acquired (%u/%d)", t->n_adapt + 1, GX_ADAPT_VIEWS);

  fpi_device_verify_report (dev, t->score >= GX_MATCH_THRESHOLD ? FPI_MATCH_SUCCESS
                                                                : FPI_MATCH_FAIL,
                            NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

static void
gx_dev_enroll (FpDevice *dev)
{
  FpiSsm *ssm = fpi_ssm_new (dev, gx_run_state, GX_ST_NUM);
  GxTask *t = g_new0 (GxTask, 1);
  FpPrint *print = NULL;
  FpiPrintType ptype = FPI_PRINT_UNDEFINED;

  t->views = g_ptr_array_new_with_free_func ((GDestroyNotify) gx_sift_free);

  /* Updating an existing print keeps its views. (fprintd never does this: its
   * enrol always supplies a fresh FpPrint, so re-enrolling REPLACES.) */
  fpi_device_get_enroll_data (dev, &print);
  if (print)
    g_object_get (print, "fpi-type", &ptype, NULL);
  if (ptype != FPI_PRINT_UNDEFINED)
    {
      gx_views_from_print (print, t->views);
      fp_info ("enroll: kept %u existing views", t->views->len);
    }
  fpi_ssm_set_data (ssm, t, (GDestroyNotify) gx_task_free);
  fpi_ssm_start (ssm, gx_enroll_done);
}

static void
gx_dev_verify (FpDevice *dev)
{
  FpiSsm *ssm = fpi_ssm_new (dev, gx_run_state, GX_ST_NUM);
  GxTask *t = g_new0 (GxTask, 1);
  FpPrint *tmpl = NULL;

  /* Load the template and its adaptive store once, up front. */
  t->verifying = TRUE;
  t->views = g_ptr_array_new_with_free_func ((GDestroyNotify) gx_sift_free);
  fpi_device_get_verify_data (dev, &tmpl);
  gx_views_from_print (tmpl, t->views);
  t->adapt_path = gx_adapt_path (tmpl);
  t->n_adapt = gx_adapt_load (t->adapt_path, t->views);

  fpi_ssm_set_data (ssm, t, (GDestroyNotify) gx_task_free);
  fpi_ssm_start (ssm, gx_verify_done);
}

/* ------------------------------------------------------------------ */
/*  Open / close                                                       */
/* ------------------------------------------------------------------ */

/* Reads the firmware version, resetting between attempts, and looks it up in
 * gx_firmwares. Returns NULL only when the version cannot be read at all. */
static const GxFirmware *
gx_identify_firmware (FpiDeviceGoodixTls *self)
{
  const GxFirmware *f;
  gchar fw[64];
  gsize i;
  int att;

  for (att = 1; !gx_read_fw_version (self, fw, sizeof fw); att++)
    {
      fp_info ("firmware version read attempt %d failed", att);
      if (att == GX_FW_ATTEMPTS)
        return NULL;
      gx_gpio_reset (self);
    }

  for (i = 0; i < G_N_ELEMENTS (gx_firmwares); i++)
    {
      f = &gx_firmwares[i];
      if (g_str_equal (fw, f->version))
        {
          fp_info ("GXFP5187 firmware: %s (key at 0x%08x, read %s enable)",
                   fw, f->psk_addr, f->psk_after_enable ? "after" : "before");
          return f;
        }
    }
  f = &gx_firmwares[0];
  fp_warn ("unknown GXFP5187 firmware %s; trying the key layout of %s "
           "(0x%08x). If the TLS handshake fails, this firmware needs support.",
           fw, f->version, f->psk_addr);
  return f;
}

static void
gx_close_fds (FpiDeviceGoodixTls *self)
{
  if (self->spi_fd >= 0)
    close (self->spi_fd);
  if (self->irq_fd >= 0)
    close (self->irq_fd);
  self->spi_fd = self->irq_fd = -1;
}

/* Is the TLS session kept from the previous open still live on the sensor?
 * The first byte of the MCU state reads 6 while the image path is up. */
static gboolean
gx_session_alive (FpiDeviceGoodixTls *self)
{
  guint8 rx[64];
  int n = gx_query (self, SEQ_MCU, sizeof SEQ_MCU, rx, sizeof rx);

  return n > 4 && rx[3] == 6;
}

/* Brings the sensor up. Runs on a worker thread.
 *
 * The TLS session is KEPT across opens (fprintd opens the device for every
 * authentication): a session costs the sensor's MCU something it never gives
 * back — after a couple of hundred sessions since power-on it stopped
 * answering altogether, and only a full power-off revived it. The vendor
 * driver sets its session up once. So if the one we kept is still live,
 * reuse it; otherwise reset, read the firmware version and the TLS key, and
 * let the next operation start a fresh session. */
static void
gx_open_thread (GTask *task, gpointer src, gpointer data, GCancellable *c)
{
  GxWork *w = data;
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (w->dev);

  /* Drop stores whose fprintd template was deleted meanwhile. */
  gx_adapt_sweep ();

  if (self->tls_up)
    {
      if (gx_session_alive (self))
        {
          fp_dbg ("reusing the TLS session");
          w->ok = TRUE;
          g_task_return_boolean (task, TRUE);
          return;
        }
      /* Lost (a power cycle, another program resetting the sensor): forget
       * it locally; the next handshake starts by unlocking the MCU's side. */
      fp_info ("kept TLS session no longer live; starting over");
      g_clear_pointer (&self->tls, gx_tls_free);
      self->tls_up = FALSE;
    }

  gx_gpio_reset (self);
  self->fw = gx_identify_firmware (self);
  if (!self->fw)
    {
      w->error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
        "cannot read the sensor's firmware version; if this persists the "
        "sensor needs a full power-off (charger unplugged)");
      g_task_return_boolean (task, TRUE);
      return;
    }
  /* A key only settled after enable is read there instead, once the MCU's TLS
   * state has been unlocked (gx_upload_config_and_reqtls): a value read here
   * would be thrown away, and a session that an earlier process left on the
   * MCU can keep memory reads closed until that unlock. */
  w->ok = self->fw->psk_after_enable || gx_read_psk (self, TRUE);
  if (!w->ok)
    w->error = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
      "cannot read the sensor's TLS key; if this persists the sensor needs "
      "a full power-off (charger unplugged)");
  g_task_return_boolean (task, TRUE);
}

static void
gx_open_done (GObject *src, GAsyncResult *res, gpointer user_data)
{
  GxWork *w = g_task_get_task_data (G_TASK (res));

  if (!w->ok)
    gx_close_fds (FPI_DEVICE_GOODIXTLS (w->dev));
  fpi_device_open_complete (w->dev, g_steal_pointer (&w->error));
}

static void
gx_dev_open (FpDevice *dev)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (dev);
  GError *err = NULL;
  const gchar *path;
  guint8 mode = SPI_MODE_0, bits = 8;
  guint32 speed = 10000000;

  path = fpi_device_get_udev_data (dev, FPI_DEVICE_UDEV_SUBTYPE_SPIDEV);
  self->spi_fd = open (path, O_RDWR | O_CLOEXEC);
  if (self->spi_fd < 0)
    {
      g_set_error (&err, G_IO_ERROR, g_io_error_from_errno (errno),
                   "cannot open spidev node %s: %s", path, g_strerror (errno));
      fpi_device_open_complete (dev, err);
      return;
    }

  /* Exclusive lock: two interleaved dialogues corrupt frame boundaries.
   * Refusing the open is better than corrupting the bus. */
  if (flock (self->spi_fd, LOCK_EX | LOCK_NB) != 0)
    {
      gx_close_fds (self);
      fpi_device_open_complete (dev, fpi_device_error_new_msg (
        FP_DEVICE_ERROR_BUSY, "sensor already in use by another process"));
      return;
    }
  if (ioctl (self->spi_fd, SPI_IOC_WR_MODE, &mode) < 0 ||
      ioctl (self->spi_fd, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0 ||
      ioctl (self->spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) < 0 ||
      !gx_open_gpios (self, &err))
    {
      if (!err)
        g_set_error (&err, G_IO_ERROR, g_io_error_from_errno (errno),
                     "cannot configure %s: %s", path, g_strerror (errno));
      gx_close_fds (self);
      fpi_device_open_complete (dev, err);
      return;
    }
  gx_run_async (NULL, dev, gx_open_thread, gx_open_done);
}

/* Releases the device nodes but keeps the TLS session (and the key it needs)
 * for the next open: see gx_open_thread. */
static void
gx_dev_close (FpDevice *dev)
{
  gx_close_fds (FPI_DEVICE_GOODIXTLS (dev));
  fpi_device_close_complete (dev, NULL);
}

/* ------------------------------------------------------------------ */

static void
fpi_device_goodixtls_init (FpiDeviceGoodixTls *self)
{
  self->spi_fd = -1;
  self->irq_fd = -1;
  /* Fallback floor until the first calibration measures this unit; the
   * measured value is kept across opens (fprintd keeps the device object). */
  self->fdt_abs = GOODIX_FDT_ABS;
}

static void
fpi_device_goodixtls_finalize (GObject *object)
{
  FpiDeviceGoodixTls *self = FPI_DEVICE_GOODIXTLS (object);

  g_clear_pointer (&self->tls, gx_tls_free);
  gx_close_fds (self);
  explicit_bzero (self->psk, sizeof self->psk);
  g_clear_pointer (&self->gpiochip, g_free);
  g_clear_pointer (&self->bg_frame, g_free);
  G_OBJECT_CLASS (fpi_device_goodixtls_parent_class)->finalize (object);
}

static void
fpi_device_goodixtls_class_init (FpiDeviceGoodixTlsClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id = "goodixtls";
  dev_class->full_name = "Goodix GXFP5187 SPI (TLS-PSK)";
  dev_class->type = FP_DEVICE_TYPE_UDEV;
  dev_class->id_table = goodixtls_id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = GX_ENROLL_STAGES;
  dev_class->temp_hot_seconds = -1;   /* slow capture: no thermal throttling */

  dev_class->open = gx_dev_open;
  dev_class->close = gx_dev_close;
  dev_class->enroll = gx_dev_enroll;
  dev_class->verify = gx_dev_verify;

  G_OBJECT_CLASS (klass)->finalize = fpi_device_goodixtls_finalize;

  /* Must come after the vfuncs: derives the advertised features from them.
   * FpImageDevice did this for us; deriving from FpDevice makes it ours. */
  fpi_device_class_auto_initialize_features (dev_class);
  dev_class->features |= FP_DEVICE_FEATURE_UPDATE_PRINT;
}
