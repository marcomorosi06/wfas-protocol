/* -----------------------------------------------------------------------------
 * wfascli — a complete command line front-end for the WFAS v2 C reference
 *           implementation (wfas.c / wfas.h).
 *
 * Streams raw signed 16-bit little-endian PCM over UDP, so it composes with
 * any tool that speaks PCM on a pipe:
 *
 *     wfascli client 192.168.1.42 | aplay -f S16_LE -r 48000 -c 2 -
 *     arecord -f S16_LE -r 48000 -c 2 - | wfascli server --announce
 *     wfascli client 192.168.1.42 --wav --out capture.wav
 *     wfascli discover
 *
 * Build:  make            (or: cc -std=c99 -O2 -o wfascli wfascli.c wfas.c)
 *
 * Portable C99 + POSIX (BSD sockets, poll). No dynamic allocation.
 * The protocol itself lives entirely in wfas.c / wfas.h; this file only drives
 * it and never changes what goes on the wire.
 *
 * SPDX-License-Identifier: MIT
 * ------------------------------------------------------------------------- */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "wfas.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define WFASCLI_VERSION "1.1"

/* -- Defaults --------------------------------------------------------------- */

#define DEF_STREAM_PORT     9090
#define DEF_DISCOVERY_PORT  9091
#define DEF_GROUP           "239.255.0.1"
#define DEF_RATE            48000
#define DEF_CHANNELS        2
#define DEF_FRAMES          240          /* 5 ms @ 48 kHz — 960 B of PCM      */

#define HANDSHAKE_TIMEOUT_MS 15000       /* client gives up connecting        */
#define HELLO_RETRY_MS        1000       /* client re-sends HELLO this often  */
#define PING_INTERVAL_MS      1000       /* server -> client keep-alive       */
#define PING_TIMEOUT_MS       3000       /* client declares the server gone   */
#define BEACON_INTERVAL_MS     400       /* multicast key beacon (spec §8)    */
#define MCAST_SILENCE_MS      6000       /* keyed group: nothing heard -> out */
#define DISCOVERY_INTERVAL_MS 3000       /* presence beacon                   */
#define INPUT_STALL_MS         500       /* no input this long -> send silence*/
#define MAX_LAG_MS            1000       /* further behind than this: resync  */
#define MAX_CHALLENGES           4       /* concurrent pending handshakes     */
#define KEY_MAX               1024       /* longest key accepted from a file  */

#define DISCOVERY_MSG "WIFI_AUDIO_STREAMER_DISCOVERY"

/* Exit codes (documented in the README). */
enum {
    RC_OK            = 0,
    RC_ERROR         = 1,   /* bad option, I/O error, socket error          */
    RC_NO_RESPONSE   = 2,   /* also: usage error                            */
    RC_DOWNGRADE     = 3,   /* keyed client, server skipped the handshake   */
    RC_KEY_REQUIRED  = 4,
    RC_BAD_SERVER    = 5,   /* server proof invalid                         */
    RC_UNAUTHORIZED  = 6,
    RC_BUSY          = 7,
    RC_INCOMPATIBLE  = 8,
    RC_TIMEOUT       = 9,   /* server went silent                           */
    RC_UNDECRYPTABLE = 10   /* keyed group: audio arrives, none decrypts    */
};

/* -- Options ---------------------------------------------------------------- */

typedef struct {
    const char *key;          /* pre-shared secret, NULL = no auth/no crypto  */
    int   encrypt;            /* latch the session as encrypted               */
    int   port;               /* unicast stream port / multicast audio port   */
    int   dport;              /* discovery port                               */
    const char *group;        /* multicast audio group                        */
    const char *dgroup;       /* discovery (presence beacon) group            */
    const char *iface;        /* local interface address for multicast        */
    int   rate;
    int   channels;
    int   frames;             /* frames per packet (server)                   */
    const char *out_path;
    const char *in_path;
    int   wav;                /* prepend a WAV header on the client output    */
    int   announce;           /* server: send presence beacons                */
    const char *name;         /* server: hostname announced in the beacon     */
    int   quiet;
    int   verbose;
    int   stats;              /* print a periodic stats line to stderr        */
    int   ttl;
    unsigned set;             /* OPT_* bits: options given on the command line */
} opts;

/* One bit per option, to warn about options that do nothing for a command. */
enum {
    OPT_RATE = 1u << 0,  OPT_CHANNELS = 1u << 1, OPT_FRAMES = 1u << 2,
    OPT_OUT = 1u << 3,   OPT_IN = 1u << 4,       OPT_WAV = 1u << 5,
    OPT_PORT = 1u << 6,  OPT_DPORT = 1u << 7,    OPT_GROUP = 1u << 8,
    OPT_DGROUP = 1u << 9, OPT_IFACE = 1u << 10,  OPT_TTL = 1u << 11,
    OPT_ANNOUNCE = 1u << 12, OPT_NAME = 1u << 13, OPT_KEY = 1u << 14,
    OPT_ENCRYPT = 1u << 15
};

static void opts_defaults(opts *o)
{
    memset(o, 0, sizeof *o);
    o->port     = DEF_STREAM_PORT;
    o->dport    = DEF_DISCOVERY_PORT;
    o->group    = DEF_GROUP;
    o->dgroup   = DEF_GROUP;
    o->rate     = DEF_RATE;
    o->channels = DEF_CHANNELS;
    o->frames   = DEF_FRAMES;
    o->stats    = 1;
    o->ttl      = 4;
}

/* -- Small helpers ---------------------------------------------------------- */

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

static long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int64_t now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000000 + (int64_t)(t.tv_nsec / 1000);
}

static const opts *g_o = NULL;
static int g_midline = 0;     /* a \r stats line is on screen, unterminated */

static void logv(const char *fmt, ...)
{
    va_list ap;
    if (!g_o || !g_o->verbose) return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void loginfo(const char *fmt, ...)
{
    va_list ap;
    if (g_o && g_o->quiet) return;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/* Warnings are not progress: -q does not hide them. */
static void logwarn(const char *fmt, ...)
{
    va_list ap;
    if (g_midline) { fputc('\n', stderr); g_midline = 0; }  /* leave the \r stats line */
    fprintf(stderr, "wfascli: warning: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "wfascli: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(RC_ERROR);
}

/* Nonces and the multicast salt must be unpredictable and must never repeat:
 * a repeated salt means a repeated key with the AEAD counter starting again at
 * 0, i.e. keystream reuse. There is no acceptable fallback, so refuse to run. */
static void random_bytes(uint8_t *b, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) die("cannot open /dev/urandom: %s", strerror(errno));
    if (fread(b, 1, n, f) != n) { fclose(f); die("short read from /dev/urandom"); }
    fclose(f);
}

/* 16 random bytes as a 32-char lowercase hex nonce. */
static void gen_nonce(char out[WFAS_NONCE_HEX + 1])
{
    static const char hexd[] = "0123456789abcdef";
    uint8_t b[WFAS_NONCE_BYTES];
    size_t i;

    random_bytes(b, sizeof b);
    for (i = 0; i < sizeof b; i++) {
        out[i * 2]     = hexd[b[i] >> 4];
        out[i * 2 + 1] = hexd[b[i] & 0x0F];
    }
    out[WFAS_NONCE_HEX] = '\0';
}

static void trim_ascii(char *s, ssize_t *n)
{
    while (*n > 0 && (s[*n - 1] == '\n' || s[*n - 1] == '\r' || s[*n - 1] == ' '))
        s[--(*n)] = '\0';
}

static int udp_socket(void)
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) die("socket: %s", strerror(errno));
    return s;
}

static void set_rcvtimeo(int s, long ms)
{
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
}

static void sendto_addr(int s, const struct sockaddr_in *a,
                        const void *buf, size_t len)
{
    static int last_err = 0;
    if (sendto(s, buf, len, 0, (const struct sockaddr *)a, sizeof *a) < 0) {
        /* UDP send errors are transient (no route yet, interface down...):
         * keep going, but say so once per distinct error. */
        if (errno != last_err) {
            last_err = errno;
            logwarn("sending to %s:%d failed: %s", inet_ntoa(a->sin_addr),
                    ntohs(a->sin_port), strerror(errno));
        }
    } else {
        last_err = 0;
    }
}

static void send_str(int s, const struct sockaddr_in *a, const char *msg)
{
    sendto_addr(s, a, msg, strlen(msg));
}

static int same_ip(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static int same_endpoint(const struct sockaddr_in *a, const struct sockaddr_in *b)
{
    return same_ip(a, b) && a->sin_port == b->sin_port;
}

static int resolve_v4(const char *host, struct in_addr *out)
{
    struct addrinfo hints, *res = NULL;
    if (inet_pton(AF_INET, host, out) == 1) return 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return -1;
    *out = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    freeaddrinfo(res);
    return 0;
}

static int is_multicast(const char *addr, struct in_addr *out)
{
    struct in_addr a;
    if (inet_pton(AF_INET, addr, &a) != 1) return 0;
    if ((ntohl(a.s_addr) & 0xF0000000u) != 0xE0000000u) return 0;   /* 224/4 */
    if (out) *out = a;
    return 1;
}

/* Apply TTL and outgoing interface to a multicast sending socket. The
 * interface must be a local address: fail loudly rather than fall back to
 * the default route, which is where the packets were not supposed to go. */
static void mcast_sender_setup(int s, const opts *o)
{
    unsigned char ttl = (unsigned char)o->ttl;
    if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl) < 0)
        die("cannot set --ttl %d: %s", o->ttl, strerror(errno));
    if (o->iface) {
        struct in_addr ifa;
        if (resolve_v4(o->iface, &ifa) != 0) die("cannot resolve --iface '%s'", o->iface);
        if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof ifa) < 0)
            die("cannot send multicast from --iface %s: %s", o->iface, strerror(errno));
    }
}

/* Remaining time until `deadline` (ms clock), clamped to [0, cap]. */
static long until_ms(long deadline, long cap)
{
    long d = deadline - now_ms();
    if (d < 0) d = 0;
    return d < cap ? d : cap;
}

/* -- Key loading ------------------------------------------------------------ */

static char g_keybuf[KEY_MAX + 2];

/* First line of the file, without the trailing newline. Keeps the secret out
 * of `ps` and of the shell history, unlike --key. */
static const char *load_key_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    size_t n;

    if (!f) die("cannot open key file %s: %s", path, strerror(errno));
    n = fread(g_keybuf, 1, KEY_MAX + 1, f);
    fclose(f);
    g_keybuf[n] = '\0';
    g_keybuf[strcspn(g_keybuf, "\r\n")] = '\0';
    if (strlen(g_keybuf) > KEY_MAX)
        die("the key in %s is longer than %d bytes", path, KEY_MAX);
    if (g_keybuf[0] == '\0') die("key file %s is empty", path);
    return g_keybuf;
}

/* -- WAV output ------------------------------------------------------------- */

/* A streaming WAV header: the two size fields are patched on close if the
 * output turns out to be seekable, and left at 0xFFFFFFFF otherwise. Players
 * that read sequentially (aplay, ffmpeg, VLC) accept the unpatched form. */
static void put_le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v & 0xFF);         p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF); p[3] = (unsigned char)((v >> 24) & 0xFF);
}

static void put_le16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)(v & 0xFF); p[1] = (unsigned char)((v >> 8) & 0xFF);
}

static void wav_write_header(FILE *f, int rate, int channels)
{
    unsigned char h[44];

    memcpy(h + 0, "RIFF", 4);  put_le32(h + 4, 0xFFFFFFFFu);
    memcpy(h + 8, "WAVE", 4);
    memcpy(h + 12, "fmt ", 4); put_le32(h + 16, 16u);
    put_le16(h + 20, 1);                                   /* PCM             */
    put_le16(h + 22, (uint16_t)channels);
    put_le32(h + 24, (uint32_t)rate);
    put_le32(h + 28, (uint32_t)rate * (uint32_t)channels * 2u);
    put_le16(h + 32, (uint16_t)(channels * 2));
    put_le16(h + 34, 16);                                  /* bits per sample */
    memcpy(h + 36, "data", 4); put_le32(h + 40, 0xFFFFFFFFu);

    fwrite(h, 1, sizeof h, f);
}

/* hdr_pos is where the header was written (-1 if unknown). Only a regular
 * file opened without O_APPEND is patched: in append mode every write lands at
 * the end whatever the seek, and a pipe or terminal cannot seek at all. */
static void wav_patch_sizes(FILE *f, long hdr_pos, uint64_t data_bytes)
{
    unsigned char b[4];
    struct stat stt;
    int fl;

    if (hdr_pos < 0 || data_bytes > 0xFFFFFFFFull - 36ull) return;
    if (fstat(fileno(f), &stt) != 0 || !S_ISREG(stt.st_mode)) return;
    fl = fcntl(fileno(f), F_GETFL);
    if (fl < 0 || (fl & O_APPEND)) return;

    fflush(f);
    put_le32(b, (uint32_t)data_bytes + 36u);
    if (fseek(f, hdr_pos + 4, SEEK_SET) == 0) fwrite(b, 1, 4, f);
    put_le32(b, (uint32_t)data_bytes);
    if (fseek(f, hdr_pos + 40, SEEK_SET) == 0) fwrite(b, 1, 4, f);
    fflush(f);
}

/* -- Stats ------------------------------------------------------------------ */

typedef struct {
    long     t0, last_print;
    uint64_t packets, bytes;
    uint64_t lost, reordered, dropped;
    int      have_last_seq;
    uint16_t last_seq;
} stats;

static void stats_init(stats *st)
{
    memset(st, 0, sizeof *st);
    st->t0 = st->last_print = now_ms();
}

/* seq is a 16-bit wrapping counter, so "newer" means the forward distance is
 * the short way round the circle. Anything else is a late or duplicate packet. */
static void stats_seq(stats *st, uint16_t seq)
{
    uint16_t gap;

    if (!st->have_last_seq) {
        st->have_last_seq = 1;
        st->last_seq = seq;
        return;
    }
    gap = (uint16_t)(seq - st->last_seq);
    if (gap == 0) {
        st->reordered++;                     /* duplicate                     */
    } else if (gap < 0x8000) {
        if (gap > 1) st->lost += (uint64_t)(gap - 1);
        st->last_seq = seq;
    } else {
        st->reordered++;                     /* arrived out of order          */
    }
}

static void stats_tick(stats *st, const opts *o)
{
    long n = now_ms();
    double sec;

    if (!o->stats || o->quiet) return;
    if (n - st->last_print < 1000) return;
    st->last_print = n;
    sec = (double)(n - st->t0) / 1000.0;
    if (sec <= 0) return;

    fprintf(stderr, "\r[stats] %6.1fs  %8llu pkt  %7.1f kbit/s  lost %llu  reord %llu",
            sec,
            (unsigned long long)st->packets,
            ((double)st->bytes * 8.0 / 1000.0) / sec,
            (unsigned long long)st->lost,
            (unsigned long long)st->reordered);
    if (st->dropped)
        fprintf(stderr, "  dropped %llu", (unsigned long long)st->dropped);
    fflush(stderr);
    g_midline = 1;
}

static void stats_final(stats *st, const opts *o)
{
    double sec = (double)(now_ms() - st->t0) / 1000.0;
    if (o->quiet) return;
    if (g_midline) { fprintf(stderr, "\n"); g_midline = 0; }
    fprintf(stderr, "[done] %.1fs  %llu packets  %llu bytes  lost %llu  reordered %llu",
            sec,
            (unsigned long long)st->packets,
            (unsigned long long)st->bytes,
            (unsigned long long)st->lost,
            (unsigned long long)st->reordered);
    if (st->dropped)
        fprintf(stderr, "  dropped %llu", (unsigned long long)st->dropped);
    fprintf(stderr, "\n");
}

/* -- Audio sink shared by both client modes --------------------------------- */

typedef struct {
    FILE    *f;
    int      fd;              /* --out file, opened before connecting         */
    int      created;         /* we created it: remove it if we never start   */
    const char *path;
    uint64_t written;
    int      wav;
    long     hdr_pos;         /* offset of the WAV header, -1 if unknown      */
    size_t   silence_bytes;   /* how much one silence frame stands for        */
} sink;

/* Open --out now, so an unwritable path fails before we take a server's only
 * unicast slot. Nothing is truncated or written until sink_start(). */
static void sink_prepare(sink *sk, const opts *o)
{
    struct stat stt;

    memset(sk, 0, sizeof *sk);
    sk->fd = -1;
    sk->hdr_pos = -1;
    sk->wav = o->wav;
    /* Until the first audio packet tells us the server's packet size. */
    sk->silence_bytes = (size_t)o->frames * (size_t)o->channels * 2u;
    if (o->out_path && strcmp(o->out_path, "-") != 0) {
        sk->path = o->out_path;
        sk->created = stat(o->out_path, &stt) != 0;
        sk->fd = open(o->out_path, O_WRONLY | O_CREAT, 0666);
        if (sk->fd < 0) die("cannot open %s: %s", o->out_path, strerror(errno));
    }
}

static void sink_start(sink *sk, const opts *o)
{
    struct stat stt;

    if (sk->fd >= 0) {
        if (fstat(sk->fd, &stt) == 0 && S_ISREG(stt.st_mode) && ftruncate(sk->fd, 0) != 0)
            die("cannot truncate %s: %s", sk->path, strerror(errno));
        sk->f = fdopen(sk->fd, "wb");
        if (!sk->f) die("cannot open %s: %s", sk->path, strerror(errno));
        sk->fd = -1;
    } else {
        sk->f = stdout;
    }
    if (sk->wav) {
        sk->hdr_pos = ftell(sk->f);
        wav_write_header(sk->f, o->rate, o->channels);
        fflush(sk->f);
    }
}

/* The session never started: leave no empty file behind. */
static void sink_abort(sink *sk)
{
    if (sk->fd >= 0) {
        close(sk->fd);
        sk->fd = -1;
        if (sk->created) unlink(sk->path);
    }
}

static void sink_write(sink *sk, const void *pcm, size_t len)
{
    if (len == 0) return;
    /* Flushed per packet: stdio would otherwise hold several packets back
     * when stdout is a pipe, which is pure added latency for a player. */
    if (fwrite(pcm, 1, len, sk->f) != len || fflush(sk->f) != 0) {
        /* Downstream went away (pipe closed): stop cleanly rather than
         * spinning on a dead descriptor. */
        g_stop = 1;
        return;
    }
    sk->written += len;
}

/* A silence frame carries no payload and its header does not say how long it
 * lasts (sample_pos does not advance). Assume it stands for one packet of the
 * size the server has been sending, and write that many zeros so the timeline
 * downstream stays continuous instead of jumping. */
static void sink_write_silence(sink *sk)
{
    static const unsigned char zeros[1024] = { 0 };
    size_t want = sk->silence_bytes;
    while (want > 0 && !g_stop) {
        size_t chunk = want < sizeof zeros ? want : sizeof zeros;
        sink_write(sk, zeros, chunk);
        want -= chunk;
    }
}

static void sink_close(sink *sk)
{
    if (!sk->f) return;
    fflush(sk->f);
    if (sk->wav) wav_patch_sizes(sk->f, sk->hdr_pos, sk->written);
    if (sk->f != stdout) fclose(sk->f);
    sk->f = NULL;
}

/* -- Receive path shared by both client modes ------------------------------- */

typedef struct {
    int                 encrypted;   /* latched: from config or a verified beacon */
    wfas_crypto_dir    *dir;
    wfas_replay_window *win;
    const char         *sealed_hint; /* shown once if sealed audio arrives unkeyed */
    int                 warned_sealed, warned_clear, warned_frames;
    long                last_ok;     /* last packet that was accepted             */
    uint64_t            fails_since_ok;
} rx_state;

/* Handle one datagram already classified as WFAS_PKT_AUDIO.
 * Returns 1 if it was accepted and written out, 0 if it was dropped. */
static int rx_audio(const opts *o, rx_state *rs, sink *sk, stats *st,
                    const uint8_t *buf, size_t len)
{
    uint8_t plain[WFAS_MAX_PAYLOAD];
    const uint8_t *pcm;
    size_t pl, frame_bytes = (size_t)o->channels * 2u;
    wfas_header h;
    int sealed = wfas_is_encrypted(buf, len);

    if (rs->encrypted) {
        int m;
        /* A keyed session never carries cleartext audio. Anything without
         * the flag is forged — dropping it is what keeps the AEAD meaningful. */
        if (!sealed) {
            st->dropped++;
            if (!rs->warned_clear) {
                rs->warned_clear = 1;
                logwarn("dropping unencrypted audio — this session "
                        "is encrypted, so cleartext is refused");
            }
            return 0;
        }
        m = wfas_decrypt_packet(rs->dir, rs->win, buf, len, &h, NULL,
                                plain, sizeof plain);
        if (m < 0) {
            st->dropped++;
            if (m == -1) rs->fails_since_ok++;  /* bad tag; replays do not count */
            return 0;
        }
        pcm = plain;
        pl  = (size_t)m;
    } else {
        /* Sealed audio without a session key is ciphertext: written out as
         * PCM it is full-scale white noise. Never play it. */
        if (sealed) {
            st->dropped++;
            if (!rs->warned_sealed) {
                rs->warned_sealed = 1;
                logwarn("the stream is encrypted — %s", rs->sealed_hint);
            }
            return 0;
        }
        if (wfas_parse_audio(buf, len, &h, &pcm, &pl) != 0) {
            st->dropped++;
            return 0;
        }
    }

    if (!(h.flags & WFAS_FLAG_SILENCE) && pl % frame_bytes != 0) {
        /* Not a whole number of frames for our channel count: writing it would
         * shift every following sample onto the wrong channel. */
        st->dropped++;
        if (!rs->warned_frames) {
            rs->warned_frames = 1;
            logwarn("packet of %zu bytes is not a whole number of "
                    "%d-channel frames — check --channels", pl, o->channels);
        }
        return 0;
    }

    rs->last_ok = now_ms();
    rs->fails_since_ok = 0;
    stats_seq(st, h.seq);
    st->packets++;
    st->bytes += (uint64_t)pl;
    if (h.flags & WFAS_FLAG_SILENCE) {
        sink_write_silence(sk);
    } else {
        if (pl > 0) sk->silence_bytes = pl;
        sink_write(sk, pcm, pl);
    }
    return 1;
}

/* -- Discovery -------------------------------------------------------------- */

static int join_group(int s, const char *group, const char *iface)
{
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof mreq);
    if (inet_pton(AF_INET, group, &mreq.imr_multiaddr) != 1) return -1;
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (iface && resolve_v4(iface, &mreq.imr_interface) != 0) return -1;
    return setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof mreq);
}

static int cmd_discover(const opts *o)
{
    int s = udp_socket();
    int yes = 1;
    struct sockaddr_in loc, from;
    socklen_t fl;
    char buf[2048];

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    memset(&loc, 0, sizeof loc);
    loc.sin_family      = AF_INET;
    loc.sin_addr.s_addr = htonl(INADDR_ANY);
    loc.sin_port        = htons((uint16_t)o->dport);
    if (bind(s, (struct sockaddr *)&loc, sizeof loc) < 0)
        die("bind %d: %s", o->dport, strerror(errno));

    if (join_group(s, o->dgroup, o->iface) < 0)
        die("cannot join %s%s%s: %s", o->dgroup, o->iface ? " on " : "",
            o->iface ? o->iface : "", strerror(errno));

    loginfo("listening for WFAS servers on %s:%d — Ctrl-C to stop\n",
            o->dgroup, o->dport);
    set_rcvtimeo(s, 500);

    while (!g_stop) {
        ssize_t n;
        fl = sizeof from;
        n = recvfrom(s, buf, sizeof buf - 1, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) continue;
        buf[n] = '\0';
        trim_ascii(buf, &n);
        if (strncmp(buf, DISCOVERY_MSG, strlen(DISCOVERY_MSG)) != 0) continue;

        {
            /* WIFI_AUDIO_STREAMER_DISCOVERY;<host>;<mode>;<port>;protocols=... */
            char copy[2048], *p, *fld[4];
            char sr[16] = "", ch[8] = "", auth[16] = "", enc[8] = "", mic[8] = "";
            const char *host, *mode, *port;
            int field;

            /* Split by hand: strtok would merge an empty field with the next
             * one and shift host/mode/port. */
            snprintf(copy, sizeof copy, "%s", buf);
            for (field = 0, p = copy; field < 4; field++) {
                fld[field] = p;
                p = p ? strchr(p, ';') : NULL;
                if (p) *p++ = '\0';
            }
            host = (fld[1] && fld[1][0]) ? fld[1] : "?";
            mode = (fld[2] && fld[2][0]) ? fld[2] : "?";
            port = (fld[3] && fld[3][0]) ? fld[3] : "?";
            wfas_get_token(buf, "sr",   sr,   sizeof sr);
            wfas_get_token(buf, "ch",   ch,   sizeof ch);
            wfas_get_token(buf, "auth", auth, sizeof auth);
            wfas_get_token(buf, "enc",  enc,  sizeof enc);
            wfas_get_token(buf, "mic",  mic,  sizeof mic);

            printf("%-15s  %-18s  %-9s  port=%-5s", inet_ntoa(from.sin_addr),
                   host, mode, port);
            if (sr[0])   printf("  %s Hz", sr);
            if (ch[0])   printf("  %s ch", ch);
            if (auth[0]) printf("  auth=%s", auth);
            if (enc[0])  printf("  enc=%s", enc);
            if (mic[0])  printf("  mic=%s", mic);
            printf("\n");
            fflush(stdout);
        }
    }
    close(s);
    return RC_OK;
}

/* Presence beacon for --announce. The advisory tokens are display hints only;
 * the spec is explicit that they must not drive a security decision. */
static void announce_once(int s, const opts *o, const char *mode)
{
    struct sockaddr_in dst;
    char host[128], msg[512];

    if (o->name) snprintf(host, sizeof host, "%s", o->name);
    else if (gethostname(host, sizeof host) != 0) snprintf(host, sizeof host, "wfascli");
    host[sizeof host - 1] = '\0';

    snprintf(msg, sizeof msg,
             "%s;%s;%s;%d;protocols=WFAS;sr=%d;ch=%d;bd=16;auth=%s;enc=%d",
             DISCOVERY_MSG, host, mode, o->port, o->rate, o->channels,
             o->key ? "KEY" : "OFF", o->encrypt ? 1 : 0);

    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port   = htons((uint16_t)o->dport);
    if (!is_multicast(o->dgroup, &dst.sin_addr)) return;   /* checked in main */
    send_str(s, &dst, msg);
}

static int announce_socket(const opts *o)
{
    int s = udp_socket();
    mcast_sender_setup(s, o);
    return s;
}

/* -- Unicast client --------------------------------------------------------- */

static int cmd_client(const opts *o, const char *host)
{
    int s;
    struct sockaddr_in srv, from;
    socklen_t fl;
    char cnonce[WFAS_NONCE_HEX + 1], snonce[WFAS_NONCE_HEX + 1] = "";
    char hello[256], rx[2048];
    int connected = 0, proved = 0, rc = RC_OK;
    long start, last_hello;
    sink sk;
    stats st;
    rx_state rs;

    /* Crypto state. `encrypted` is latched here, from configuration, and never
     * from what happens to arrive — see "No cleartext in a keyed session". */
    int encrypted = (o->key && o->encrypt) ? 1 : 0;
    wfas_crypto_dir c2s, s2c;
    wfas_replay_window win;

    if (o->encrypt && !o->key) die("--encrypt requires a key (--key, --key-file or WFAS_KEY)");

    memset(&srv, 0, sizeof srv);
    srv.sin_family = AF_INET;
    srv.sin_port   = htons((uint16_t)o->port);
    if (resolve_v4(host, &srv.sin_addr) != 0) die("cannot resolve '%s'", host);

    sink_prepare(&sk, o);
    s = udp_socket();
    gen_nonce(cnonce);
    snprintf(hello, sizeof hello, "%s;v=%d;cnonce=%s",
             WFAS_MSG_HELLO, WFAS_PROTOCOL_VERSION, cnonce);

    loginfo("connecting to %s:%d  auth=%s  enc=%s\n",
            inet_ntoa(srv.sin_addr), o->port,
            o->key ? "key" : "off", encrypted ? "on" : "off");

    set_rcvtimeo(s, 250);
    start = now_ms();
    last_hello = start - HELLO_RETRY_MS;       /* send the first one at once   */

    while (!connected && !g_stop && now_ms() - start < HANDSHAKE_TIMEOUT_MS) {
        ssize_t n;
        wfas_packet_type t;

        if (now_ms() - last_hello >= HELLO_RETRY_MS) {
            send_str(s, &srv, hello);
            last_hello = now_ms();
        }
        fl = sizeof from;
        n = recvfrom(s, rx, sizeof rx - 1, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) continue;
        /* Only the server we asked may answer: otherwise any host on the LAN
         * could end the handshake with a forged BUSY or UNAUTHORIZED. */
        if (!same_ip(&from, &srv)) {
            logv("[client] ignoring datagram from %s\n", inet_ntoa(from.sin_addr));
            continue;
        }
        rx[n] = '\0';
        trim_ascii(rx, &n);
        t = wfas_classify((const uint8_t *)rx, (size_t)n);

        switch (t) {
        case WFAS_PKT_HELLO_ACK:
            /* Anti-downgrade: we hold a key, so a server that never challenged
             * us is either misconfigured or impersonating one. */
            if (o->key && !proved) {
                fprintf(stderr, "wfascli: ABORT: server accepted us without "
                                "authenticating — possible downgrade attack\n");
                close(s);
                sink_abort(&sk);
                return RC_DOWNGRADE;
            }
            connected = 1;
            break;

        case WFAS_PKT_AUTH_REQUIRED: {
            char sproof[WFAS_PROOF_HEX + 1], expect[WFAS_PROOF_HEX + 1];
            char cproof[WFAS_PROOF_HEX + 1];

            if (!o->key) {
                fprintf(stderr, "wfascli: server requires a key "
                                "(--key, --key-file or WFAS_KEY)\n");
                close(s);
                sink_abort(&sk);
                return RC_KEY_REQUIRED;
            }
            if (!wfas_get_token(rx, "snonce", snonce, sizeof snonce) ||
                !wfas_get_token(rx, "sproof", sproof, sizeof sproof)) {
                logv("[client] malformed challenge, retrying\n");
                continue;
            }
            /* Verify the server before proving ourselves: mutual auth. */
            wfas_auth_proof(o->key, 'S', cnonce, snonce, expect);
            if (!wfas_proof_equal(sproof, expect)) {
                fprintf(stderr, "wfascli: ABORT: server proof invalid "
                                "(wrong key, or a rogue server)\n");
                close(s);
                sink_abort(&sk);
                return RC_BAD_SERVER;
            }
            wfas_auth_proof(o->key, 'C', cnonce, snonce, cproof);
            snprintf(hello, sizeof hello, "%s;v=%d;cnonce=%s;cproof=%s",
                     WFAS_MSG_HELLO, WFAS_PROTOCOL_VERSION, cnonce, cproof);
            if (!proved) loginfo("server authenticated, sending proof\n");
            proved = 1;
            last_hello = now_ms() - HELLO_RETRY_MS;   /* answer right away     */
            break;
        }

        case WFAS_PKT_PENDING:
            loginfo("waiting for the operator to allow this device...\n");
            /* Keep waiting: the server re-sends this while the prompt is open.
             * Extend the deadline so an attended approval is not cut off. */
            start = now_ms();
            break;

        case WFAS_PKT_UNAUTHORIZED:
            fprintf(stderr, "wfascli: UNAUTHORIZED (wrong key, or refused)\n");
            close(s);
            sink_abort(&sk);
            return RC_UNAUTHORIZED;

        case WFAS_PKT_BUSY:
            /* Normative: BUSY is final. Do not retry. */
            fprintf(stderr, "wfascli: server is already streaming to another "
                            "client\n");
            close(s);
            sink_abort(&sk);
            return RC_BUSY;

        case WFAS_PKT_INCOMPATIBLE:
            fprintf(stderr, "wfascli: protocol mismatch — server speaks v%d, "
                            "this build speaks v%d\n",
                    wfas_parse_version(rx), WFAS_PROTOCOL_VERSION);
            close(s);
            sink_abort(&sk);
            return RC_INCOMPATIBLE;

        default:
            break;
        }
    }

    if (!connected) {
        close(s);
        sink_abort(&sk);
        if (g_stop) return RC_OK;
        fprintf(stderr, "wfascli: no usable response from %s:%d\n", host, o->port);
        return RC_NO_RESPONSE;
    }

    memset(&rs, 0, sizeof rs);
    rs.encrypted   = encrypted;
    rs.sealed_hint = o->key ? "rerun with --encrypt"
                            : "rerun with a key (--key, --key-file or WFAS_KEY) and --encrypt";
    if (encrypted) {
        if (snonce[0] == '\0') {
            fprintf(stderr, "wfascli: --encrypt was requested but the server "
                            "never ran the keyed handshake\n");
            close(s);
            sink_abort(&sk);
            return RC_DOWNGRADE;
        }
        wfas_derive_unicast_keys(o->key, cnonce, snonce, &c2s, &s2c);
        (void)c2s;               /* this tool only receives                   */
        wfas_replay_init(&win);
        rs.dir = &s2c;
        rs.win = &win;
        loginfo("session keys derived, playback gated on the encrypted flag\n");
    }

    loginfo("connected — streaming (Ctrl-C to stop)\n");
    sink_start(&sk, o);
    stats_init(&st);

    {
        long last_ping = now_ms();

        while (!g_stop) {
            ssize_t n;
            long tnow;

            fl = sizeof from;
            n = recvfrom(s, rx, sizeof rx, 0, (struct sockaddr *)&from, &fl);
            tnow = now_ms();

            if (n > 0 && same_ip(&from, &srv)) {
                wfas_packet_type t = wfas_classify((const uint8_t *)rx, (size_t)n);

                if (t == WFAS_PKT_AUDIO) {
                    /* Only audio we could actually play counts as proof of life. */
                    if (rx_audio(o, &rs, &sk, &st, (const uint8_t *)rx, (size_t)n))
                        last_ping = tnow;
                } else if (t == WFAS_PKT_PING) {
                    last_ping = tnow;
                } else if (t == WFAS_PKT_BYE) {
                    loginfo("\nserver said goodbye\n");
                    break;
                } else if (encrypted) {
                    /* Keyed session: an unrecognised datagram is not PCM. */
                    st.dropped++;
                }
            } else if (n > 0) {
                st.dropped++;            /* not from our server               */
            }

            if (tnow - last_ping > PING_TIMEOUT_MS) {
                logwarn("server stopped responding");
                rc = RC_TIMEOUT;
                break;
            }
            stats_tick(&st, o);
        }
    }

    send_str(s, &srv, WFAS_MSG_CLIENT_BYE);
    stats_final(&st, o);
    sink_close(&sk);
    close(s);
    return rc;
}

/* -- Multicast client ------------------------------------------------------- */

static int cmd_mclient(const opts *o)
{
    int s = udp_socket();
    int yes = 1, rc = RC_OK, warned_nokey = 0, warned_mac = 0, warned_clear = 0;
    struct sockaddr_in loc;
    char rx[2048];
    sink sk;
    stats st;
    rx_state rs;

    /* In a group there is no handshake: the key beacon is what proves the
     * group is keyed, and it is also the only heartbeat. */
    uint64_t last_epoch = 0;
    wfas_crypto_dir dir;
    wfas_replay_window win;
    long last_heard;

    if (o->encrypt && !o->key) die("--encrypt requires a key (--key, --key-file or WFAS_KEY)");

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    memset(&loc, 0, sizeof loc);
    loc.sin_family      = AF_INET;
    loc.sin_addr.s_addr = htonl(INADDR_ANY);
    loc.sin_port        = htons((uint16_t)o->port);
    if (bind(s, (struct sockaddr *)&loc, sizeof loc) < 0)
        die("bind %d: %s", o->port, strerror(errno));
    if (join_group(s, o->group, o->iface) < 0)
        die("cannot join %s%s%s: %s", o->group, o->iface ? " on " : "",
            o->iface ? o->iface : "", strerror(errno));

    loginfo("joined %s:%d  key=%s — waiting for audio\n",
            o->group, o->port, o->key ? "yes" : "no");

    memset(&rs, 0, sizeof rs);
    rs.dir = &dir;
    rs.win = &win;
    rs.sealed_hint = "rerun with a key (--key, --key-file or WFAS_KEY)";
    if (o->key) {
        loginfo("holding a key: audio is ignored until a valid beacon arrives\n");
        wfas_replay_init(&win);
    }

    sink_prepare(&sk, o);
    sink_start(&sk, o);
    stats_init(&st);
    set_rcvtimeo(s, 250);
    last_heard = now_ms();

    while (!g_stop) {
        ssize_t n = recvfrom(s, rx, sizeof rx, 0, NULL, NULL);
        long tnow = now_ms();

        if (n > 0) {
            wfas_packet_type t = wfas_classify((const uint8_t *)rx, (size_t)n);

            if (t == WFAS_PKT_MCAST_ENC) {
                uint64_t epoch, ts;
                uint8_t salt[WFAS_SALT_BYTES];
                size_t slen = 0;
                char msg[1024];
                int r;

                if (!o->key) {
                    if (!warned_nokey) {
                        warned_nokey = 1;
                        logwarn("this group is encrypted — pass a key "
                                "(--key, --key-file or WFAS_KEY) to listen");
                    }
                    continue;
                }
                snprintf(msg, sizeof msg, "%.*s", (int)n, rx);
                r = wfas_parse_mcast_beacon(o->key, msg, last_epoch,
                                            &epoch, &ts, salt,
                                            sizeof salt, &slen);
                if (r == -1) {                              /* bad MAC       */
                    st.dropped++;
                    if (!warned_mac) {
                        warned_mac = 1;
                        logwarn("key beacon does not verify — wrong key?");
                    }
                    continue;
                }
                if (r == -2) { last_heard = tnow; continue; }  /* same epoch  */

                /* A newer epoch (or the first beacon): derive the group key. */
                wfas_derive_multicast_key(o->key, salt, slen, &dir);
                wfas_replay_init(&win);
                last_epoch     = epoch;
                rs.encrypted   = 1;          /* latched by a verified beacon  */
                rs.last_ok     = tnow;
                rs.fails_since_ok = 0;
                loginfo("\ngroup key accepted (epoch %llu)\n",
                        (unsigned long long)epoch);
                last_heard = tnow;
                continue;
            }

            if (t == WFAS_PKT_AUDIO) {
                if (o->key && !rs.encrypted) {
                    /* We hold a key but no beacon has proved the group yet:
                     * refuse to treat this as plaintext PCM. */
                    st.dropped++;
                    if (!warned_clear && !wfas_is_encrypted((const uint8_t *)rx, (size_t)n)) {
                        warned_clear = 1;
                        logwarn("this group is sending unencrypted audio, which is "
                                "ignored while holding a key — run without a key "
                                "to listen to it");
                    }
                    continue;
                }
                if (rx_audio(o, &rs, &sk, &st, (const uint8_t *)rx, (size_t)n))
                    last_heard = tnow;
            } else if (t == WFAS_PKT_BYE) {
                loginfo("\nserver said goodbye\n");
                break;
            }
        }

        /* A keyed group beacons every ~400 ms, so silence is meaningful.
         * An unencrypted group has no heartbeat at all in v2 — a receiver
         * cannot tell a quiet server from a dead one, so we do not guess. */
        if (rs.encrypted && tnow - last_heard > MCAST_SILENCE_MS) {
            logwarn("no beacon for %d s — assuming the server is gone",
                    MCAST_SILENCE_MS / 1000);
            rc = RC_TIMEOUT;
            break;
        }

        /* Beacons still verify but audio has stopped decrypting: the sender
         * changed its group key without a newer epoch (typically a server
         * restart). Accepting an older epoch would re-open the replay hole the
         * epoch exists to close, so the honest move is to stop and say so. */
        if (rs.encrypted && rs.fails_since_ok >= 20 &&
            tnow - rs.last_ok > MCAST_SILENCE_MS) {
            logwarn("audio is arriving but none of it has decrypted for %d s — "
                    "the server was probably restarted; restart this receiver",
                    MCAST_SILENCE_MS / 1000);
            rc = RC_UNDECRYPTABLE;
            break;
        }
        stats_tick(&st, o);
    }

    stats_final(&st, o);
    sink_close(&sk);
    close(s);
    return rc;
}

/* -- Server ----------------------------------------------------------------- */

typedef struct {
    int  used;
    long t;
    struct sockaddr_in addr;
    char cnonce[WFAS_NONCE_HEX + 1];
    char snonce[WFAS_NONCE_HEX + 1];
} challenge;

typedef struct {
    challenge ch[MAX_CHALLENGES];     /* handshakes in progress                */
    struct sockaddr_in peer;          /* the accepted client                   */
    char cnonce[WFAS_NONCE_HEX + 1];  /* its handshake nonces (keyed mode)     */
    char snonce[WFAS_NONCE_HEX + 1];
} server_state;

static void send_hello_ack(int s, const struct sockaddr_in *to)
{
    char ack[32];
    snprintf(ack, sizeof ack, "%s;v=%d", WFAS_MSG_HELLO_ACK, WFAS_PROTOCOL_VERSION);
    send_str(s, to, ack);
}

static challenge *challenge_find(server_state *ss, const struct sockaddr_in *cl,
                                 const char *cnonce)
{
    int i;
    for (i = 0; i < MAX_CHALLENGES; i++) {
        challenge *c = &ss->ch[i];
        if (c->used && same_endpoint(&c->addr, cl) && strcmp(c->cnonce, cnonce) == 0)
            return c;
    }
    return NULL;
}

static challenge *challenge_alloc(server_state *ss)
{
    int i, oldest = 0;
    for (i = 0; i < MAX_CHALLENGES; i++) {
        if (!ss->ch[i].used) return &ss->ch[i];
        if (ss->ch[i].t < ss->ch[oldest].t) oldest = i;
    }
    return &ss->ch[oldest];
}

/* A HELLO_FROM_CLIENT from a host that is not yet our client.
 * Returns 1 when the handshake completes and the host becomes the client. */
static int server_hello(int s, const opts *o, server_state *ss,
                        const struct sockaddr_in *cl, const char *rx)
{
    char cnonce[WFAS_NONCE_HEX + 1] = "", cproof[WFAS_PROOF_HEX + 1];
    char sproof[WFAS_PROOF_HEX + 1], expect[WFAS_PROOF_HEX + 1], m[256];
    challenge *c;
    int v = wfas_parse_version(rx);

    if (v > 0 && v != WFAS_PROTOCOL_VERSION) {
        snprintf(m, sizeof m, "%s;v=%d", WFAS_MSG_INCOMPATIBLE, WFAS_PROTOCOL_VERSION);
        send_str(s, cl, m);
        loginfo("rejected %s: speaks v%d\n", inet_ntoa(cl->sin_addr), v);
        return 0;
    }

    if (!o->key) {
        send_hello_ack(s, cl);
        ss->peer = *cl;
        loginfo("client %s connected\n", inet_ntoa(cl->sin_addr));
        return 1;
    }

    wfas_get_token(rx, "cnonce", cnonce, sizeof cnonce);
    if (cnonce[0] == '\0') {
        logv("[server] %s sent no cnonce: cannot run the keyed handshake\n",
             inet_ntoa(cl->sin_addr));
        return 0;
    }
    c = challenge_find(ss, cl, cnonce);

    if (!wfas_get_token(rx, "cproof", cproof, sizeof cproof)) {
        /* A retransmitted HELLO (same host, same cnonce) gets the very same
         * challenge back. A fresh snonce here would invalidate the proof the
         * client may already be computing, and UNAUTHORIZED is final. */
        if (!c) {
            c = challenge_alloc(ss);
            memset(c, 0, sizeof *c);
            c->used = 1;
            c->addr = *cl;
            snprintf(c->cnonce, sizeof c->cnonce, "%s", cnonce);
            gen_nonce(c->snonce);
        }
        c->t = now_ms();
        wfas_auth_proof(o->key, 'S', c->cnonce, c->snonce, sproof);
        snprintf(m, sizeof m, "%s;snonce=%s;sproof=%s",
                 WFAS_MSG_AUTH_REQUIRED, c->snonce, sproof);
        send_str(s, cl, m);
        logv("[server] challenge sent to %s\n", inet_ntoa(cl->sin_addr));
        return 0;
    }

    if (!c) {
        /* Proof for a challenge we never issued to this host. */
        send_str(s, cl, WFAS_MSG_UNAUTHORIZED);
        return 0;
    }
    wfas_auth_proof(o->key, 'C', c->cnonce, c->snonce, expect);
    if (!wfas_proof_equal(cproof, expect)) {
        send_str(s, cl, WFAS_MSG_UNAUTHORIZED);
        loginfo("client %s failed authentication\n", inet_ntoa(cl->sin_addr));
        c->used = 0;
        return 0;
    }

    send_hello_ack(s, cl);
    ss->peer = *cl;
    snprintf(ss->cnonce, sizeof ss->cnonce, "%s", c->cnonce);
    snprintf(ss->snonce, sizeof ss->snonce, "%s", c->snonce);
    c->used = 0;
    loginfo("client %s authenticated\n", inet_ntoa(cl->sin_addr));
    return 1;
}

/* A HELLO from the client we are already serving means our HELLO_ACK was lost
 * and it is still waiting: acknowledge again. In keyed mode only a HELLO that
 * carries a valid proof for this session's nonces is acknowledged. */
static void server_rehello(int s, const opts *o, const server_state *ss,
                           const struct sockaddr_in *cl, const char *rx)
{
    char cnonce[WFAS_NONCE_HEX + 1] = "", cproof[WFAS_PROOF_HEX + 1] = "";
    char expect[WFAS_PROOF_HEX + 1];

    if (!o->key) { send_hello_ack(s, cl); return; }
    if (!wfas_get_token(rx, "cnonce", cnonce, sizeof cnonce) ||
        !wfas_get_token(rx, "cproof", cproof, sizeof cproof) ||
        strcmp(cnonce, ss->cnonce) != 0)
        return;
    wfas_auth_proof(o->key, 'C', ss->cnonce, ss->snonce, expect);
    if (wfas_proof_equal(cproof, expect)) {
        send_hello_ack(s, cl);
        logv("[server] HELLO_ACK re-sent to %s\n", inet_ntoa(cl->sin_addr));
    }
}

/* Reads PCM from a file or stdin, paces it at the configured sample rate and
 * sends it to one unicast client, or to the multicast group.
 *
 * Everything runs off one poll() loop and nothing in it blocks: a capture
 * that stalls must not take PING, the key beacon, the presence beacon or the
 * CLIENT_BYE check down with it. While the input is stalled the receiver gets
 * silence frames, so its timeline keeps moving. */
static int cmd_server(const opts *o, int multicast)
{
    int s, announce_fd = -1, in_fd = STDIN_FILENO, rc = RC_OK;
    struct sockaddr_in loc, dst;
    stats st;
    uint8_t pkt[WFAS_MTU];
    uint8_t inbuf[WFAS_MAX_PAYLOAD];              /* raw little-endian PCM     */
    int16_t samples[WFAS_MAX_PAYLOAD / 2];
    size_t pcm_bytes, have = 0;
    long last_ping, last_announce, last_beacon, last_input;
    int have_client = 0, in_eof = 0, stalled = 0;
    int64_t base_us;
    uint64_t slot;                                /* packets sent since base   */
    server_state ss;

    /* Crypto state (server side). */
    wfas_crypto_dir c2s, s2c, mdir, *edir = NULL;
    uint8_t msalt[WFAS_SALT_BYTES];
    /* Epoch is fixed at 1 in this release: see "Known limitations" in the
     * README before changing it — it touches the multicast key semantics. */
    uint64_t epoch = 1;
    int encrypted = (o->key && o->encrypt) ? 1 : 0;

    wfas_sender tx;

    if (o->encrypt && !o->key) die("--encrypt requires a key (--key, --key-file or WFAS_KEY)");
    if (multicast && o->key && !o->encrypt)
        die("multicast has no handshake: a key only takes effect with --encrypt");

    pcm_bytes = (size_t)o->frames * (size_t)o->channels * 2u;
    if (pcm_bytes > (encrypted ? (size_t)WFAS_MAX_ENC_PAYLOAD
                               : (size_t)WFAS_MAX_PAYLOAD))
        die("--frames %d is too large for one packet (max %zu bytes of PCM); "
            "lower it", o->frames,
            (size_t)(encrypted ? WFAS_MAX_ENC_PAYLOAD : WFAS_MAX_PAYLOAD));

    if (o->in_path && strcmp(o->in_path, "-") != 0) {
        in_fd = open(o->in_path, O_RDONLY);
        if (in_fd < 0) die("cannot open %s: %s", o->in_path, strerror(errno));
    }

    s = udp_socket();
    memset(&loc, 0, sizeof loc);
    loc.sin_family      = AF_INET;
    loc.sin_addr.s_addr = htonl(INADDR_ANY);
    loc.sin_port        = htons((uint16_t)(multicast ? 0 : o->port));
    /* No SO_REUSEADDR: on UDP it would let a second server bind the same port
     * and silently steal part of the traffic. A unicast port has one owner. */
    if (bind(s, (struct sockaddr *)&loc, sizeof loc) < 0)
        die("bind %d: %s", multicast ? 0 : o->port, strerror(errno));

    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    memset(&ss, 0, sizeof ss);

    if (multicast) {
        dst.sin_port = htons((uint16_t)o->port);
        if (!is_multicast(o->group, &dst.sin_addr))
            die("--group %s is not an IPv4 multicast address", o->group);
        mcast_sender_setup(s, o);
        have_client = 1;
        loginfo("streaming to %s:%d  %d Hz  %d ch  enc=%s\n",
                o->group, o->port, o->rate, o->channels,
                encrypted ? "on" : "off");

        if (encrypted) {
            random_bytes(msalt, sizeof msalt);
            wfas_derive_multicast_key(o->key, msalt, sizeof msalt, &mdir);
            edir = &mdir;
        }
    } else {
        loginfo("listening on UDP %d  %d Hz  %d ch  auth=%s  enc=%s\n",
                o->port, o->rate, o->channels,
                o->key ? "key" : "off", encrypted ? "on" : "off");
    }

    if (o->announce) {
        announce_fd = announce_socket(o);
        loginfo("announcing presence on %s:%d every %d ms\n",
                o->dgroup, o->dport, DISCOVERY_INTERVAL_MS);
    }

    wfas_sender_init(&tx);
    last_announce = last_beacon = now_ms() - 100000L;   /* fire at once       */

    /* -- Unicast: wait for a client ----------------------------------------- */
    if (!multicast) {
        char rx[2048];
        struct sockaddr_in cl;
        socklen_t cn;

        set_rcvtimeo(s, 250);
        while (!have_client && !g_stop) {
            ssize_t n;
            wfas_packet_type t;

            if (o->announce && now_ms() - last_announce >= DISCOVERY_INTERVAL_MS) {
                announce_once(announce_fd, o, "UNICAST");
                last_announce = now_ms();
            }

            cn = sizeof cl;
            n = recvfrom(s, rx, sizeof rx - 1, 0, (struct sockaddr *)&cl, &cn);
            if (n <= 0) continue;
            rx[n] = '\0';
            trim_ascii(rx, &n);
            t = wfas_classify((const uint8_t *)rx, (size_t)n);

            if (t == WFAS_PKT_MODE_PROBE) {
                send_str(s, &cl, WFAS_MSG_UNICAST);
                continue;
            }
            if (t != WFAS_PKT_HELLO) continue;
            have_client = server_hello(s, o, &ss, &cl, rx);
        }
        if (g_stop) goto done;

        dst = ss.peer;
        if (encrypted) {
            wfas_derive_unicast_keys(o->key, ss.cnonce, ss.snonce, &c2s, &s2c);
            (void)c2s;    /* we only send; the client->server direction
                           * is unused by this tool */
            edir = &s2c;
        }
    }

    /* -- Streaming loop ----------------------------------------------------- */
    loginfo("streaming (Ctrl-C to stop)\n");
    stats_init(&st);
    last_ping  = now_ms();
    last_input = now_ms();
    base_us    = now_us();
    slot       = 0;

    while (!g_stop) {
        struct pollfd pfd[2];
        int nfds = 0, in_idx = -1, sock_idx = -1;
        int64_t tnow = now_us();
        /* Deadline of the next packet, from the total frame count since `base`
         * rather than a rounded per-packet step: 240 frames at 44.1 kHz is
         * 5.442 ms, and rounding that to 5 ms streams 8.8 % too fast. */
        int64_t due = base_us + (int64_t)((slot * (uint64_t)o->frames * 1000000u)
                                          / (uint64_t)o->rate);
        long timeout;

        /* 1. Timers that must never depend on the input. They go first so that a
         *    keyed group hears its beacon before the first sealed packet. */
        if (!multicast && now_ms() - last_ping >= PING_INTERVAL_MS) {
            send_str(s, &dst, WFAS_MSG_PING);
            last_ping = now_ms();
        }
        if (multicast && encrypted && now_ms() - last_beacon >= BEACON_INTERVAL_MS) {
            char bc[512];
            int bl = wfas_build_mcast_beacon(o->key, epoch, (uint64_t)time(NULL),
                                             msalt, sizeof msalt, bc, sizeof bc);
            if (bl > 0) sendto_addr(s, &dst, bc, (size_t)bl);
            last_beacon = now_ms();
        }
        if (o->announce && now_ms() - last_announce >= DISCOVERY_INTERVAL_MS) {
            announce_once(announce_fd, o, multicast ? "MULTICAST" : "UNICAST");
            last_announce = now_ms();
        }

        /* 2. Send whatever is due. */
        if (tnow >= due) {
            int silence = -1;                        /* -1 = nothing to send  */

            if (tnow - due > (int64_t)MAX_LAG_MS * 1000) {
                base_us = tnow;                      /* too far behind: resync */
                slot = 0;
            }
            if (have == pcm_bytes || (in_eof && have > 0)) {
                if (have < pcm_bytes) memset(inbuf + have, 0, pcm_bytes - have);
                silence = 0;
            } else if (in_eof) {
                loginfo("\ninput ended\n");
                break;
            } else if (stalled || now_ms() - last_input >= INPUT_STALL_MS) {
                if (!stalled) {
                    stalled = 1;
                    base_us = tnow;
                    slot = 0;
                    logv("\n[server] input stalled: sending silence frames\n");
                }
                silence = 1;
            }

            if (silence >= 0) {
                int len;
                if (edir) {
                    len = wfas_encrypt_packet(edir, pkt, sizeof pkt,
                                              tx.seq, tx.sample_pos, silence,
                                              silence ? NULL : inbuf,
                                              silence ? 0 : pcm_bytes);
                    /* wfas_encrypt_packet advances only the AEAD counter, so
                     * the protocol-level seq / sample_pos are ours to keep,
                     * with the same rules as wfas_build_audio/_silence. */
                    tx.seq = (uint16_t)(tx.seq + 1);
                    if (!silence) tx.sample_pos += (uint32_t)o->frames;
                } else if (silence) {
                    len = wfas_build_silence(&tx, pkt, sizeof pkt);
                } else {
                    /* The input is little-endian bytes; wfas_build_audio wants
                     * host-order samples. Convert explicitly so this also runs
                     * correctly on a big-endian host. */
                    size_t i, n = pcm_bytes / 2;
                    for (i = 0; i < n; i++) samples[i] = wfas_pcm_get(inbuf, i);
                    len = wfas_build_audio(&tx, pkt, sizeof pkt, samples,
                                           o->frames, o->channels);
                }
                if (len > 0) {
                    sendto_addr(s, &dst, pkt, (size_t)len);
                    st.packets++;
                    if (!silence) st.bytes += (uint64_t)pcm_bytes;
                }
                if (!silence) have = 0;
                slot++;
            }
        }

        /* 3. Sleep until the next thing to do, or until input/control arrives. */
        timeout = 250;
        if (have == pcm_bytes || in_eof || stalled) {
            int64_t d = base_us + (int64_t)((slot * (uint64_t)o->frames * 1000000u)
                                            / (uint64_t)o->rate) - now_us();
            long dm = d <= 0 ? 0 : (long)((d + 999) / 1000);
            if (dm < timeout) timeout = dm;
        } else {
            timeout = until_ms(last_input + INPUT_STALL_MS, timeout);
        }
        if (!multicast) timeout = until_ms(last_ping + PING_INTERVAL_MS, timeout);
        if (multicast && encrypted) timeout = until_ms(last_beacon + BEACON_INTERVAL_MS, timeout);
        if (o->announce) timeout = until_ms(last_announce + DISCOVERY_INTERVAL_MS, timeout);

        if (!in_eof && have < pcm_bytes) {
            pfd[nfds].fd = in_fd; pfd[nfds].events = POLLIN; pfd[nfds].revents = 0;
            in_idx = nfds++;
        }
        if (!multicast) {
            pfd[nfds].fd = s; pfd[nfds].events = POLLIN; pfd[nfds].revents = 0;
            sock_idx = nfds++;
        }
        if (poll(pfd, (nfds_t)nfds, (int)timeout) < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "wfascli: poll: %s\n", strerror(errno));
            rc = RC_ERROR;
            break;
        }

        /* 4. Input. */
        if (in_idx >= 0 && (pfd[in_idx].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t r = read(in_fd, inbuf + have, pcm_bytes - have);
            if (r > 0) {
                have += (size_t)r;
                last_input = now_ms();
                if (stalled) {
                    stalled = 0;
                    base_us = now_us();              /* resume on a fresh clock */
                    slot = 0;
                    logv("\n[server] input resumed\n");
                }
            } else if (r == 0) {
                in_eof = 1;
            } else if (errno != EINTR && errno != EAGAIN) {
                fprintf(stderr, "\nwfascli: read error: %s\n", strerror(errno));
                rc = RC_ERROR;
                break;
            }
        }

        /* 5. Control messages (unicast only). */
        if (sock_idx >= 0 && (pfd[sock_idx].revents & POLLIN)) {
            char rx[1024];
            struct sockaddr_in from;
            socklen_t fl;
            ssize_t n;
            int end = 0;

            for (;;) {
                wfas_packet_type t;
                fl = sizeof from;
                n = recvfrom(s, rx, sizeof rx - 1, MSG_DONTWAIT,
                             (struct sockaddr *)&from, &fl);
                if (n <= 0) break;
                rx[n] = '\0';
                trim_ascii(rx, &n);
                t = wfas_classify((const uint8_t *)rx, (size_t)n);

                if (same_endpoint(&from, &dst)) {
                    if (t == WFAS_PKT_HELLO)            server_rehello(s, o, &ss, &from, rx);
                    else if (t == WFAS_PKT_MODE_PROBE)  send_str(s, &from, WFAS_MSG_UNICAST);
                    else if (t == WFAS_PKT_CLIENT_BYE) { end = 1; break; }
                } else if (same_ip(&from, &dst) && t == WFAS_PKT_CLIENT_BYE) {
                    /* Same host, another socket: still our client saying bye. */
                    end = 1;
                    break;
                } else if (t == WFAS_PKT_HELLO || t == WFAS_PKT_MODE_PROBE) {
                    /* Someone else — including a second process on the same
                     * host. Tell them we are taken so they stop retrying, and
                     * ignore anything else they say: acting on a stranger's
                     * CLIENT_BYE would let any host tear down this session. */
                    send_str(s, &from, WFAS_MSG_BUSY);
                    logv("[server] %s:%d rejected: busy\n",
                         inet_ntoa(from.sin_addr), ntohs(from.sin_port));
                }
            }
            if (end) {
                loginfo("\nclient disconnected\n");
                break;
            }
        }

        stats_tick(&st, o);
    }

    /* BYE is a courtesy, not a guarantee: it is an unacknowledged datagram and
     * receivers are told not to rely on it. Send it anyway. */
    if (have_client) send_str(s, &dst, WFAS_MSG_BYE);
    stats_final(&st, o);

done:
    if (announce_fd >= 0) close(announce_fd);
    if (in_fd != STDIN_FILENO) close(in_fd);
    close(s);
    return rc;
}

/* -- Usage ------------------------------------------------------------------ */

static void usage(FILE *f)
{
    fprintf(f,
"wfascli " WFASCLI_VERSION " — WFAS v2 audio streaming over UDP\n"
"\n"
"USAGE\n"
"  wfascli <command> [options]      (the command comes first)\n"
"\n"
"COMMANDS\n"
"  discover                 list WFAS servers announcing on the LAN\n"
"  client <host>            connect to a unicast server, write PCM out\n"
"  mclient                  join a multicast group, write PCM out\n"
"  server                   read PCM in, serve one unicast client\n"
"  mserver                  read PCM in, stream to a multicast group\n"
"  version                  print the protocol and tool version\n"
"\n"
"AUDIO\n"
"  --rate N                 sample rate in Hz (default %d)\n"
"  --channels N             channel count (default %d)\n"
"  --frames N               frames per packet for servers (default %d, or\n"
"                           less when that would not fit one packet);\n"
"                           clients only use it to size silence frames\n"
"                           until the first audio packet arrives\n"
"  --out FILE               write PCM here instead of stdout ('-' = stdout)\n"
"  --in FILE                read PCM here instead of stdin ('-' = stdin)\n"
"  --wav                    prepend a WAV header to the client output\n"
"\n"
"NETWORK\n"
"  --port N                 audio port (default %d)\n"
"  --discovery-port N       beacon port (default %d)\n"
"  --group ADDR             multicast audio group (default %s)\n"
"  --discovery-group ADDR   presence beacon group (default %s)\n"
"  --iface ADDR             local address to use for multicast\n"
"  --ttl N                  multicast TTL (default 4)\n"
"  --announce               servers: send a presence beacon\n"
"  --name NAME              servers: name to announce (default: hostname)\n"
"\n"
"SECURITY\n"
"  --key-file FILE          read the pre-shared key from FILE (first line)\n"
"  --key SECRET             pre-shared key on the command line (visible in\n"
"                           ps and shell history: prefer --key-file)\n"
"  WFAS_KEY=SECRET          environment fallback when neither is given\n"
"  --encrypt                encrypt the media (ChaCha20-Poly1305); needs a key\n"
"\n"
"OUTPUT\n"
"  -q, --quiet              suppress progress on stderr (not warnings)\n"
"  -v, --verbose            print protocol detail\n"
"      --no-stats           do not print the periodic stats line\n"
"  -h, --help               this text\n"
"\n"
"NOTES\n"
"  PCM is signed 16-bit little-endian, interleaved. Sample rate and channel\n"
"  count are not carried in the audio header, so both ends must agree: in\n"
"  multicast they are advertised in the discovery beacon, in unicast you set\n"
"  them by hand.\n"
"\n"
"  --encrypt is a decision you make once, before any audio arrives. A client\n"
"  told to expect encryption drops every packet that is not sealed, which is\n"
"  what stops an attacker from clearing one header bit and walking past the\n"
"  authentication entirely. A client without it drops sealed packets rather\n"
"  than play ciphertext as noise.\n"
"\n"
"EXIT STATUS\n"
"  0 ok  1 error  2 usage/no response  3 downgrade  4 key required\n"
"  5 bad server proof  6 unauthorized  7 busy  8 incompatible\n"
"  9 server went silent  10 group audio no longer decrypts\n"
"\n"
"EXAMPLES\n"
"  wfascli discover\n"
"  wfascli client 192.168.1.42 | aplay -f S16_LE -r 48000 -c 2 -\n"
"  wfascli client 192.168.1.42 --wav --out capture.wav\n"
"  wfascli client 192.168.1.42 --key-file ~/.wfas.key --encrypt | aplay -f S16_LE -r 48000 -c 2 -\n"
"  arecord -f S16_LE -r 48000 -c 2 - | wfascli server --announce\n"
"  wfascli mclient --group 239.255.0.1 --port 9090 --key-file ~/.wfas.key\n"
"  wfascli client 192.168.1.42 -q | cava -p /etc/cava.conf\n",
    DEF_RATE, DEF_CHANNELS, DEF_FRAMES, DEF_STREAM_PORT, DEF_DISCOVERY_PORT,
    DEF_GROUP, DEF_GROUP);
}

/* -- Argument parsing ------------------------------------------------------- */

static int need_arg(int i, int argc, char **argv)
{
    if (i + 1 >= argc) die("%s needs a value", argv[i]);
    return i + 1;
}

static int parse_int(const char *s, const char *what, int lo, int hi)
{
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (!end || end == s || *end != '\0' || v < lo || v > hi)
        die("invalid %s: '%s' (expected %d..%d)", what, s, lo, hi);
    return (int)v;
}

/* Which options mean something for which command. An option that would be
 * silently ignored is worth a warning: `server --wav` or `discover --key`
 * look like they do something and do not. */
static void check_options(opts *o, const char *cmd)
{
    static const struct { unsigned bit; const char *name; } names[] = {
        { OPT_RATE, "--rate" }, { OPT_CHANNELS, "--channels" }, { OPT_FRAMES, "--frames" },
        { OPT_OUT, "--out" }, { OPT_IN, "--in" }, { OPT_WAV, "--wav" },
        { OPT_PORT, "--port" }, { OPT_DPORT, "--discovery-port" }, { OPT_GROUP, "--group" },
        { OPT_DGROUP, "--discovery-group" }, { OPT_IFACE, "--iface" }, { OPT_TTL, "--ttl" },
        { OPT_ANNOUNCE, "--announce" }, { OPT_NAME, "--name" }, { OPT_KEY, "a key" },
        { OPT_ENCRYPT, "--encrypt" }
    };
    const unsigned audio = OPT_RATE | OPT_CHANNELS | OPT_FRAMES | OPT_PORT | OPT_KEY | OPT_ENCRYPT;
    const unsigned beacon = OPT_ANNOUNCE | OPT_NAME | OPT_DPORT | OPT_DGROUP | OPT_IFACE | OPT_TTL;
    int is_client = strcmp(cmd, "client") == 0, is_mclient = strcmp(cmd, "mclient") == 0;
    int is_server = strcmp(cmd, "server") == 0, is_mserver = strcmp(cmd, "mserver") == 0;
    int is_discover = strcmp(cmd, "discover") == 0;
    unsigned ok = 0, bad;
    size_t i;

    if (is_client)   ok = audio | OPT_OUT | OPT_WAV;
    if (is_mclient)  ok = audio | OPT_OUT | OPT_WAV | OPT_GROUP | OPT_IFACE;
    if (is_server)   ok = audio | OPT_IN | OPT_ANNOUNCE | (o->announce ? beacon : 0);
    if (is_mserver)  ok = audio | OPT_IN | OPT_ANNOUNCE | OPT_GROUP | OPT_IFACE | OPT_TTL
                         | (o->announce ? beacon : 0);
    if (is_discover) ok = OPT_DPORT | OPT_DGROUP | OPT_IFACE;
    if (!(is_client || is_mclient || is_server || is_mserver || is_discover)) return;

    bad = o->set & ~ok;
    for (i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (!(bad & names[i].bit)) continue;
        if ((names[i].bit & beacon) && (is_server || is_mserver))
            logwarn("%s has no effect without --announce", names[i].name);
        else if (names[i].bit == OPT_GROUP && (is_discover || is_server))
            logwarn("--group has no effect with '%s' (the presence beacon uses "
                    "--discovery-group)", cmd);
        else
            logwarn("%s has no effect with '%s'", names[i].name, cmd);
    }

    /* Addresses: only the ones this command will actually use. */
    if ((is_mclient || is_mserver) && !is_multicast(o->group, NULL))
        die("--group %s is not an IPv4 multicast address (224.0.0.0/4)", o->group);
    if ((is_discover || ((is_server || is_mserver) && o->announce)) &&
        !is_multicast(o->dgroup, NULL))
        die("--discovery-group %s is not an IPv4 multicast address (224.0.0.0/4)", o->dgroup);
    if (o->iface && (ok & OPT_IFACE)) {
        struct in_addr ifa;
        if (resolve_v4(o->iface, &ifa) != 0) die("cannot resolve --iface '%s'", o->iface);
    }

    /* The announced name is a field of a ';'-separated beacon. */
    if (o->name && (ok & OPT_NAME)) {
        const unsigned char *p;
        if (o->name[0] == '\0') die("--name is empty");
        if (strlen(o->name) > 63) die("--name is longer than 63 bytes");
        for (p = (const unsigned char *)o->name; *p; p++)
            if (*p == ';' || *p < 0x20 || *p == 0x7F)
                die("--name may not contain ';' or control characters");
    }

    /* Default packet size: 240 frames, or whatever fits when many channels
     * would make that exceed one packet. An explicit --frames is checked by
     * the server and never adjusted. */
    if (!(o->set & OPT_FRAMES)) {
        size_t cap = (o->key && o->encrypt) ? WFAS_MAX_ENC_PAYLOAD : WFAS_MAX_PAYLOAD;
        size_t fit = cap / ((size_t)o->channels * 2u);
        if ((size_t)o->frames > fit) o->frames = (int)fit;
    }

    if (is_mserver && o->announce && strcmp(o->group, o->dgroup) != 0)
        logwarn("the presence beacon does not say which group the audio is on: "
                "receivers must be given --group %s", o->group);
}

int main(int argc, char **argv)
{
    opts o;
    const char *cmd, *host = NULL, *key_arg = NULL, *key_file = NULL;
    int i, rc;
    struct sigaction sa;

    opts_defaults(&o);
    g_o = &o;

    if (argc < 2) { usage(stderr); return RC_NO_RESPONSE; }

    cmd = argv[1];
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "help") == 0) { usage(stdout); return RC_OK; }
    if (cmd[0] == '-') {
        fprintf(stderr, "wfascli: the command comes first: wfascli <command> [options] "
                        "(try --help)\n");
        return RC_NO_RESPONSE;
    }
    if (strcmp(cmd, "version") == 0) {
        printf("wfascli %s — WFAS protocol v%d\n", WFASCLI_VERSION, WFAS_PROTOCOL_VERSION);
        return RC_OK;
    }

    for (i = 2; i < argc; i++) {
        const char *a = argv[i];

        if      (strcmp(a, "--key") == 0)            { key_arg  = argv[i = need_arg(i, argc, argv)]; o.set |= OPT_KEY; }
        else if (strcmp(a, "--key-file") == 0)       { key_file = argv[i = need_arg(i, argc, argv)]; o.set |= OPT_KEY; }
        else if (strcmp(a, "--encrypt") == 0)        { o.encrypt = 1; o.set |= OPT_ENCRYPT; }
        else if (strcmp(a, "--port") == 0)           { o.port  = parse_int(argv[i = need_arg(i, argc, argv)], "--port", 1, 65535); o.set |= OPT_PORT; }
        else if (strcmp(a, "--discovery-port") == 0) { o.dport = parse_int(argv[i = need_arg(i, argc, argv)], "--discovery-port", 1, 65535); o.set |= OPT_DPORT; }
        else if (strcmp(a, "--group") == 0)          { o.group = argv[i = need_arg(i, argc, argv)]; o.set |= OPT_GROUP; }
        else if (strcmp(a, "--discovery-group") == 0){ o.dgroup = argv[i = need_arg(i, argc, argv)]; o.set |= OPT_DGROUP; }
        else if (strcmp(a, "--iface") == 0)          { o.iface = argv[i = need_arg(i, argc, argv)]; o.set |= OPT_IFACE; }
        else if (strcmp(a, "--ttl") == 0)            { o.ttl   = parse_int(argv[i = need_arg(i, argc, argv)], "--ttl", 1, 255); o.set |= OPT_TTL; }
        else if (strcmp(a, "--rate") == 0)           { o.rate  = parse_int(argv[i = need_arg(i, argc, argv)], "--rate", 8000, 384000); o.set |= OPT_RATE; }
        else if (strcmp(a, "--channels") == 0)       { o.channels = parse_int(argv[i = need_arg(i, argc, argv)], "--channels", 1, 8); o.set |= OPT_CHANNELS; }
        else if (strcmp(a, "--frames") == 0)         { o.frames   = parse_int(argv[i = need_arg(i, argc, argv)], "--frames", 1, 8192); o.set |= OPT_FRAMES; }
        else if (strcmp(a, "--out") == 0)            { o.out_path = argv[i = need_arg(i, argc, argv)]; o.set |= OPT_OUT; }
        else if (strcmp(a, "--in") == 0)             { o.in_path  = argv[i = need_arg(i, argc, argv)]; o.set |= OPT_IN; }
        else if (strcmp(a, "--wav") == 0)            { o.wav = 1; o.set |= OPT_WAV; }
        else if (strcmp(a, "--announce") == 0)       { o.announce = 1; o.set |= OPT_ANNOUNCE; }
        else if (strcmp(a, "--name") == 0)           { o.name = argv[i = need_arg(i, argc, argv)]; o.set |= OPT_NAME; }
        else if (strcmp(a, "--no-stats") == 0)       o.stats = 0;
        else if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0)   o.quiet = 1;
        else if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) o.verbose = 1;
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0)  { usage(stdout); return RC_OK; }
        else if (a[0] == '-')                        die("unknown option '%s' (try --help)", a);
        else if (!host && strcmp(cmd, "client") == 0) host = a;
        else                                         die("unexpected argument '%s'", a);
    }

    if (key_arg && key_file) die("use either --key or --key-file, not both");
    if (key_file)      o.key = load_key_file(key_file);
    else if (key_arg)  o.key = key_arg;
    else {
        const char *env = getenv("WFAS_KEY");
        if (env && env[0]) o.key = env;
    }
    if (o.key && o.key[0] == '\0') die("the key is empty");

    check_options(&o, cmd);

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);   /* a closed pipe is handled in sink_write */

    if      (strcmp(cmd, "discover") == 0) rc = cmd_discover(&o);
    else if (strcmp(cmd, "client")   == 0) {
        if (!host) die("client needs a server address (try --help)");
        rc = cmd_client(&o, host);
    }
    else if (strcmp(cmd, "mclient")  == 0) rc = cmd_mclient(&o);
    else if (strcmp(cmd, "server")   == 0) rc = cmd_server(&o, 0);
    else if (strcmp(cmd, "mserver")  == 0) rc = cmd_server(&o, 1);
    else { fprintf(stderr, "wfascli: unknown command '%s'\n\n", cmd); usage(stderr); return RC_NO_RESPONSE; }

    return rc;
}
