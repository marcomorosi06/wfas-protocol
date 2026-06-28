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

/* ── Encryption (protocol Section 8): ChaCha20-Poly1305 AEAD ────────────────
 * Per-packet AEAD over UDP. The 10-byte header travels in clear and is bound as
 * associated data; an explicit 8-byte counter (the low part of the 96-bit nonce)
 * travels in clear so the receiver can reconstruct the nonce despite loss/reorder.
 * Encrypted packet layout:
 *   [header 10B] [counter 8B big-endian] [ciphertext] [Poly1305 tag 16B]
 * nonce(12B) = nonce_prefix(4B, per-direction) || counter(8B big-endian).        */
#define WFAS_FLAG_ENCRYPTED   0x02
#define WFAS_KEY_BYTES        32
#define WFAS_AEAD_TAG_BYTES   16
#define WFAS_COUNTER_BYTES    8
#define WFAS_NONCE_PREFIX_BYTES 4
#define WFAS_AEAD_OVERHEAD    (WFAS_COUNTER_BYTES + WFAS_AEAD_TAG_BYTES) /* 24 */
#define WFAS_MAX_ENC_PAYLOAD  (WFAS_MAX_PAYLOAD - WFAS_AEAD_OVERHEAD)
#define WFAS_SALT_BYTES       16
#define WFAS_MSG_MCAST_ENC    "WFAS_MCAST_ENC"

/* ChaCha20-Poly1305 AEAD (RFC 8439). nonce is 12 bytes. tag is 16 bytes.
 * Encrypt never fails; decrypt returns 0 if the tag is valid, -1 otherwise. */
void wfas_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
        const uint8_t *aad, size_t aad_len, const uint8_t *plaintext, size_t pt_len,
        uint8_t *ciphertext, uint8_t tag[16]);
int  wfas_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
        const uint8_t *aad, size_t aad_len, const uint8_t *ciphertext, size_t ct_len,
        const uint8_t tag[16], uint8_t *plaintext);

/* HKDF-SHA256 (RFC 5869), extract+expand in one call. info may be NULL. */
void wfas_hkdf_sha256(const uint8_t *salt, size_t salt_len,
        const uint8_t *ikm, size_t ikm_len,
        const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);

/* Per-direction key material + outgoing packet counter. */
typedef struct {
    uint8_t  key[WFAS_KEY_BYTES];
    uint8_t  nonce_prefix[WFAS_NONCE_PREFIX_BYTES];
    uint64_t send_counter;
} wfas_crypto_dir;

/* Anti-replay sliding window (bitmask). Sized well above the jitter buffer depth
 * so legitimately late packets are never mistaken for replays. */
#define WFAS_REPLAY_BITS  1024
#define WFAS_REPLAY_WORDS (WFAS_REPLAY_BITS / 64)
typedef struct {
    uint64_t max_counter;
    uint64_t seen[WFAS_REPLAY_WORDS];
    int      initialized;
} wfas_replay_window;

void wfas_replay_init(wfas_replay_window *w);
/* Pre-check (no state change): 1 = acceptable, 0 = too old or already seen (drop). */
int  wfas_replay_check(const wfas_replay_window *w, uint64_t counter);
/* Commit only AFTER successful authentication. */
void wfas_replay_commit(wfas_replay_window *w, uint64_t counter);

/* Derive unicast session keys from the pre-shared key and the two handshake
 * nonces (hex strings from Section 7). Separate keys per direction. */
void wfas_derive_unicast_keys(const char *key, const char *cnonce_hex, const char *snonce_hex,
        wfas_crypto_dir *c2s, wfas_crypto_dir *s2c);

/* Derive the multicast key from the pre-shared key and the session salt. */
void wfas_derive_multicast_key(const char *key, const uint8_t *salt, size_t salt_len,
        wfas_crypto_dir *dir);

/* Build an encrypted audio packet (header+counter+ciphertext+tag). Increments
 * dir->send_counter. Returns total length or -1. pcm_len may be 0 (silence). */
int  wfas_encrypt_packet(wfas_crypto_dir *dir, uint8_t *out, size_t out_cap,
        uint16_t seq, uint32_t sample_pos, int silence,
        const uint8_t *pcm, size_t pcm_len);

/* Decrypt a received encrypted packet. Verifies the tag (header as AAD) and the
 * anti-replay window. Returns plaintext length (>=0), -1 on auth/format failure,
 * or -2 if dropped as replay/too-old. Fills hdr and counter when non-NULL. */
int  wfas_decrypt_packet(const wfas_crypto_dir *dir, wfas_replay_window *win,
        const uint8_t *buf, size_t len, wfas_header *hdr, uint64_t *counter,
        uint8_t *out_pcm, size_t out_cap);

/* Multicast beacon: "WFAS_MCAST_ENC;epoch=<n>;time=<unix>;salt=<hex>;mac=<hex>".
 * The MAC is HMAC(key, "WFAS-MCAST:epoch=..;time=..;salt=..") so epoch/time/salt
 * cannot be forged. Build returns length or -1. */
int  wfas_build_mcast_beacon(const char *key, uint64_t epoch, uint64_t timestamp,
        const uint8_t *salt, size_t salt_len, char *out, size_t out_cap);
/* Verify the beacon MAC and that epoch > last_epoch (defeats whole-session replay).
 * Returns 0 and fills epoch/timestamp/salt; -1 bad format/MAC; -2 stale epoch. */
int  wfas_parse_mcast_beacon(const char *key, const char *msg, uint64_t last_epoch,
        uint64_t *epoch, uint64_t *timestamp, uint8_t *salt, size_t salt_cap, size_t *salt_len);

#ifdef __cplusplus
}
#endif
#endif
