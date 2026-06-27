#ifndef WFAS_H
#define WFAS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WFAS_PROTOCOL_VERSION 2
#define WFAS_MAGIC_0          0x57
#define WFAS_MAGIC_1          0x46
#define WFAS_HEADER_SIZE      10
#define WFAS_FLAG_SILENCE     0x01
#define WFAS_MTU              1400
#define WFAS_MAX_PAYLOAD      (WFAS_MTU - WFAS_HEADER_SIZE)

#define WFAS_MSG_MODE_PROBE     "MODE_PROBE"
#define WFAS_MSG_UNICAST        "UNICAST"
#define WFAS_MSG_HELLO          "HELLO_FROM_CLIENT"
#define WFAS_MSG_HELLO_ACK      "HELLO_ACK"
#define WFAS_MSG_INCOMPATIBLE   "WFAS_INCOMPATIBLE"
#define WFAS_MSG_PING           "PING"
#define WFAS_MSG_BYE            "BYE"
#define WFAS_MSG_CLIENT_BYE     "CLIENT_BYE"

/* Security handshake (protocol Section 7). */
#define WFAS_MSG_PENDING        "WFAS_PENDING"
#define WFAS_MSG_AUTH_REQUIRED  "WFAS_AUTH_REQUIRED"
#define WFAS_MSG_UNAUTHORIZED   "WFAS_UNAUTHORIZED"
#define WFAS_NONCE_BYTES        16
#define WFAS_NONCE_HEX          32
#define WFAS_PROOF_HEX          64

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
    WFAS_PKT_PENDING,
    WFAS_PKT_AUTH_REQUIRED,
    WFAS_PKT_UNAUTHORIZED,
    WFAS_PKT_OTHER
} wfas_packet_type;

typedef struct { uint8_t version; uint8_t flags; uint16_t seq; uint32_t sample_pos; } wfas_header;
typedef struct { uint16_t seq; uint32_t sample_pos; } wfas_sender;

void wfas_sender_init(wfas_sender *s);
int  wfas_write_header(uint8_t *out, size_t out_cap, uint16_t seq, uint32_t sample_pos, int silence);
int  wfas_build_audio(wfas_sender *s, uint8_t *out, size_t out_cap, const int16_t *pcm, int frames, int channels);
int  wfas_build_silence(wfas_sender *s, uint8_t *out, size_t out_cap);
wfas_packet_type wfas_classify(const uint8_t *buf, size_t len);
int  wfas_parse_header(const uint8_t *buf, size_t len, wfas_header *hdr);
int  wfas_parse_audio(const uint8_t *buf, size_t len, wfas_header *hdr, const uint8_t **pcm, size_t *pcm_len);
int16_t wfas_pcm_get(const uint8_t *pcm, size_t sample_index);
int  wfas_parse_version(const char *msg);

/* HMAC-SHA256 of msg under key, into out[32]. Self-contained, no deps. */
void wfas_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* Compute an auth proof (Section 7.3) as a 64-char lowercase hex string.
 * side is 'S' (server proof) or 'C' (client proof); nonces are hex strings.
 * out_hex must hold at least WFAS_PROOF_HEX + 1 bytes. */
void wfas_auth_proof(const char *key, char side,
                     const char *cnonce_hex, const char *snonce_hex,
                     char *out_hex);

/* Constant-time comparison of two NUL-terminated hex proofs. 1 if equal. */
int  wfas_proof_equal(const char *a, const char *b);

/* Extract the value of ";<token>=<value>" from an ASCII control message.
 * Copies up to out_cap-1 bytes (stops at ';' or end). Returns the length, 0 if absent. */
int  wfas_get_token(const char *msg, const char *token, char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif
#endif
