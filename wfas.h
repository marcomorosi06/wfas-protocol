#ifndef WFAS_H
#define WFAS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Protocol constants. The header is a fixed 10 bytes; payload is signed 16-bit
 * PCM. WFAS_MAX_PAYLOAD is the largest PCM payload that still fits one datagram
 * (MTU minus the header) and is the upper bound enforced by wfas_build_audio. */
#define WFAS_PROTOCOL_VERSION 2
#define WFAS_MAGIC_0          0x57
#define WFAS_MAGIC_1          0x46
#define WFAS_HEADER_SIZE      10
#define WFAS_FLAG_SILENCE     0x01
#define WFAS_MTU              1400
#define WFAS_MAX_PAYLOAD      (WFAS_MTU - WFAS_HEADER_SIZE)

/* ASCII control messages, sent on the same socket as audio. */
#define WFAS_MSG_MODE_PROBE   "MODE_PROBE"
#define WFAS_MSG_UNICAST      "UNICAST"
#define WFAS_MSG_HELLO        "HELLO_FROM_CLIENT"
#define WFAS_MSG_HELLO_ACK    "HELLO_ACK"
#define WFAS_MSG_INCOMPATIBLE "WFAS_INCOMPATIBLE"
#define WFAS_MSG_PING         "PING"
#define WFAS_MSG_BYE          "BYE"
#define WFAS_MSG_CLIENT_BYE   "CLIENT_BYE"

/* Result of wfas_classify(): what kind of datagram was received. */
typedef enum {
    WFAS_PKT_INVALID = 0,
    WFAS_PKT_AUDIO,
    WFAS_PKT_PING,
    WFAS_PKT_BYE,
    WFAS_PKT_HELLO,
    WFAS_PKT_HELLO_ACK,
    WFAS_PKT_INCOMPATIBLE,
    WFAS_PKT_MODE_PROBE,
    WFAS_PKT_UNICAST,
    WFAS_PKT_CLIENT_BYE,
    WFAS_PKT_OTHER
} wfas_packet_type;

/* Decoded audio-packet header, filled by wfas_parse_header/wfas_parse_audio. */
typedef struct {
    uint8_t  version;
    uint8_t  flags;
    uint16_t seq;
    uint32_t sample_pos;
} wfas_header;

/* Per-stream server state: the running seq and sample_pos counters.
 * Keep one per outgoing stream and reset it with wfas_sender_init. */
typedef struct {
    uint16_t seq;
    uint32_t sample_pos;
} wfas_sender;

/* Reset a sender's counters to 0. Call once before you start streaming. */
void wfas_sender_init(wfas_sender *s);

/* Serialize just the 10-byte header into out (big-endian seq/sample_pos).
 * Low-level: most servers use wfas_build_audio instead.
 * Returns WFAS_HEADER_SIZE, or -1 if out_cap < WFAS_HEADER_SIZE. */
int wfas_write_header(uint8_t *out, size_t out_cap,
                      uint16_t seq, uint32_t sample_pos, int silence);

/* Build one full audio packet (header + interleaved int16 PCM) into out,
 * stamping the sender's current seq/sample_pos and then advancing them.
 * frames = samples per channel; PCM is written little-endian on any host.
 * Returns the total bytes written, or -1 (bad args, payload > WFAS_MAX_PAYLOAD,
 * or out too small). Split larger blocks across several calls. */
int wfas_build_audio(wfas_sender *s, uint8_t *out, size_t out_cap,
                     const int16_t *pcm, int frames, int channels);

/* Build a header-only silence frame (silence flag set), advancing seq only.
 * Send while the source is idle/muted to keep the stream and timing alive.
 * Returns WFAS_HEADER_SIZE, or -1 if out_cap < WFAS_HEADER_SIZE. */
int wfas_build_silence(wfas_sender *s, uint8_t *out, size_t out_cap);

/* Inspect a received datagram and tell audio apart from each control message.
 * Cheap first dispatch on the receive path; does not decode the header. */
wfas_packet_type wfas_classify(const uint8_t *buf, size_t len);

/* Validate the magic bytes and decode the 10-byte header into hdr (may be NULL).
 * Returns 0 on success, or -1 if buf is not a valid WFAS audio packet. */
int wfas_parse_header(const uint8_t *buf, size_t len, wfas_header *hdr);

/* Like wfas_parse_header, and also point *pcm and *pcm_len at the PCM payload
 * inside buf (no copy). hdr/pcm/pcm_len may each be NULL. Returns 0 or -1. */
int wfas_parse_audio(const uint8_t *buf, size_t len, wfas_header *hdr,
                     const uint8_t **pcm, size_t *pcm_len);

/* Read PCM sample at sample_index as a host int16_t (decodes little-endian).
 * Use on big-endian or alignment-sensitive CPUs instead of casting the bytes. */
int16_t wfas_pcm_get(const uint8_t *pcm, size_t sample_index);

/* Extract the integer n from a ";v=<n>" control message (e.g. HELLO_ACK;v=2).
 * Returns n, 0 if no version is present (legacy peer), or -1 if msg is NULL. */
int wfas_parse_version(const char *msg);

#ifdef __cplusplus
}
#endif

#endif