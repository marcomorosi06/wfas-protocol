#include "wfas.h"
#include <string.h>

static uint16_t rd_be16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]); }
static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static void wr_be16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xFF); }
static void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)(v & 0xFF);
}
static int eq(const uint8_t *b, size_t l, const char *s) { size_t n = strlen(s); return l == n && memcmp(b, s, n) == 0; }
static int starts(const uint8_t *b, size_t l, const char *s) { size_t n = strlen(s); return l >= n && memcmp(b, s, n) == 0; }

void wfas_sender_init(wfas_sender *s) { s->seq = 0; s->sample_pos = 0; }

int wfas_write_header(uint8_t *out, size_t cap, uint16_t seq, uint32_t pos, int silence) {
    if (!out || cap < WFAS_HEADER_SIZE) return -1;
    out[0] = WFAS_MAGIC_0; out[1] = WFAS_MAGIC_1; out[2] = WFAS_PROTOCOL_VERSION;
    out[3] = silence ? WFAS_FLAG_SILENCE : 0;
    wr_be16(out + 4, seq); wr_be32(out + 6, pos);
    return WFAS_HEADER_SIZE;
}

int wfas_build_audio(wfas_sender *s, uint8_t *out, size_t cap, const int16_t *pcm, int frames, int channels) {
    if (!s || !out || !pcm || frames <= 0 || channels <= 0) return -1;
    size_t samples = (size_t)frames * (size_t)channels;
    size_t payload = samples * 2;
    if (payload > WFAS_MAX_PAYLOAD || cap < WFAS_HEADER_SIZE + payload) return -1;
    wfas_write_header(out, cap, s->seq, s->sample_pos, 0);
    uint8_t *p = out + WFAS_HEADER_SIZE;
    for (size_t i = 0; i < samples; i++) {
        uint16_t u = (uint16_t)pcm[i];
        p[i * 2] = (uint8_t)(u & 0xFF);
        p[i * 2 + 1] = (uint8_t)(u >> 8);
    }
    s->seq = (uint16_t)(s->seq + 1);
    s->sample_pos += (uint32_t)frames;
    return (int)(WFAS_HEADER_SIZE + payload);
}

int wfas_build_silence(wfas_sender *s, uint8_t *out, size_t cap) {
    if (!s || !out || cap < WFAS_HEADER_SIZE) return -1;
    wfas_write_header(out, cap, s->seq, s->sample_pos, 1);
    s->seq = (uint16_t)(s->seq + 1);
    return WFAS_HEADER_SIZE;
}

/* Control messages are checked before the audio magic: the WFAS_* messages
 * begin with 'W''F' (0x57 0x46), the same two bytes as the audio magic, so the
 * textual prefixes must win. A real audio packet's third byte is the version,
 * never 'A', so it never matches "WFAS_...". */
wfas_packet_type wfas_classify(const uint8_t *b, size_t l) {
    if (!b || l == 0) return WFAS_PKT_INVALID;
    if (eq(b, l, WFAS_MSG_PING))             return WFAS_PKT_PING;
    if (eq(b, l, WFAS_MSG_BYE))              return WFAS_PKT_BYE;
    if (eq(b, l, WFAS_MSG_CLIENT_BYE))       return WFAS_PKT_CLIENT_BYE;
    if (eq(b, l, WFAS_MSG_MODE_PROBE))       return WFAS_PKT_MODE_PROBE;
    if (eq(b, l, WFAS_MSG_UNICAST))          return WFAS_PKT_UNICAST;
    if (eq(b, l, WFAS_MSG_PENDING))          return WFAS_PKT_PENDING;
    if (starts(b, l, WFAS_MSG_AUTH_REQUIRED))return WFAS_PKT_AUTH_REQUIRED;
    if (eq(b, l, WFAS_MSG_UNAUTHORIZED))     return WFAS_PKT_UNAUTHORIZED;
    if (starts(b, l, WFAS_MSG_HELLO_ACK))    return WFAS_PKT_HELLO_ACK;
    if (starts(b, l, WFAS_MSG_INCOMPATIBLE)) return WFAS_PKT_INCOMPATIBLE;
    if (starts(b, l, WFAS_MSG_HELLO))        return WFAS_PKT_HELLO;
    if (b[0] == WFAS_MAGIC_0 && l >= 2 && b[1] == WFAS_MAGIC_1) {
        if (l < WFAS_HEADER_SIZE) return WFAS_PKT_INVALID;
        return WFAS_PKT_AUDIO;
    }
    return WFAS_PKT_OTHER;
}

int wfas_parse_header(const uint8_t *b, size_t l, wfas_header *h) {
    if (!b || l < WFAS_HEADER_SIZE) return -1;
    if (b[0] != WFAS_MAGIC_0 || b[1] != WFAS_MAGIC_1) return -1;
    if (h) { h->version = b[2]; h->flags = b[3]; h->seq = rd_be16(b + 4); h->sample_pos = rd_be32(b + 6); }
    return 0;
}

int wfas_parse_audio(const uint8_t *b, size_t l, wfas_header *h, const uint8_t **pcm, size_t *pl) {
    if (wfas_parse_header(b, l, h) != 0) return -1;
    if (pcm) *pcm = b + WFAS_HEADER_SIZE;
    if (pl)  *pl = l - WFAS_HEADER_SIZE;
    return 0;
}

int16_t wfas_pcm_get(const uint8_t *pcm, size_t i) {
    const uint8_t *p = pcm + i * 2;
    return (int16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

int wfas_parse_version(const char *m) {
    if (!m) return -1;
    const char *p = strstr(m, "v=");
    if (!p) return 0;
    p += 2;
    int v = 0, any = 0;
    while (*p >= '0' && *p <= '9') { v = v * 10 + (*p - '0'); p++; any = 1; }
    return any ? v : 0;
}

/* ── SHA-256 / HMAC-SHA256 (FIPS 180-4 / RFC 2104), self-contained ───────────*/
typedef struct { uint32_t s[8]; uint64_t bits; uint8_t buf[64]; size_t n; } wfas_sha;
static const uint32_t WK[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
#define WROR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_blk(wfas_sha *c, const uint8_t *p) {
    uint32_t w[64], a, b, d, e, f, g, h, t1, t2, cc;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i*4] << 24 | (uint32_t)p[i*4+1] << 16 | (uint32_t)p[i*4+2] << 8 | p[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = WROR(w[i-15],7) ^ WROR(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t s1 = WROR(w[i-2],17) ^ WROR(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=c->s[0]; b=c->s[1]; cc=c->s[2]; d=c->s[3]; e=c->s[4]; f=c->s[5]; g=c->s[6]; h=c->s[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = WROR(e,6) ^ WROR(e,11) ^ WROR(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + WK[i] + w[i];
        uint32_t S0 = WROR(a,2) ^ WROR(a,13) ^ WROR(a,22);
        uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = S0 + mj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->s[0]+=a; c->s[1]+=b; c->s[2]+=cc; c->s[3]+=d; c->s[4]+=e; c->s[5]+=f; c->s[6]+=g; c->s[7]+=h;
}
static void sha_init(wfas_sha *c) {
    c->s[0]=0x6a09e667; c->s[1]=0xbb67ae85; c->s[2]=0x3c6ef372; c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f; c->s[5]=0x9b05688c; c->s[6]=0x1f83d9ab; c->s[7]=0x5be0cd19;
    c->bits = 0; c->n = 0;
}
static void sha_upd(wfas_sha *c, const uint8_t *p, size_t n) {
    c->bits += (uint64_t)n * 8;
    while (n) {
        size_t k = 64 - c->n;
        if (k > n) k = n;
        memcpy(c->buf + c->n, p, k);
        c->n += k; p += k; n -= k;
        if (c->n == 64) { sha_blk(c, c->buf); c->n = 0; }
    }
}
static void sha_fin(wfas_sha *c, uint8_t o[32]) {
    uint64_t b = c->bits;
    uint8_t pad = 0x80, z = 0, L[8];
    int i;
    sha_upd(c, &pad, 1);
    while (c->n != 56) sha_upd(c, &z, 1);
    for (i = 0; i < 8; i++) L[i] = (uint8_t)(b >> (56 - i*8));
    sha_upd(c, L, 8);
    for (i = 0; i < 8; i++) {
        o[i*4]   = (uint8_t)(c->s[i] >> 24); o[i*4+1] = (uint8_t)(c->s[i] >> 16);
        o[i*4+2] = (uint8_t)(c->s[i] >> 8);  o[i*4+3] = (uint8_t)c->s[i];
    }
}

void wfas_hmac_sha256(const uint8_t *key, size_t kl, const uint8_t *m, size_t ml, uint8_t out[32]) {
    uint8_t k[64], ip[64], op[64], ih[32];
    size_t i;
    wfas_sha c;
    memset(k, 0, 64);
    if (kl > 64) { sha_init(&c); sha_upd(&c, key, kl); sha_fin(&c, k); }
    else memcpy(k, key, kl);
    for (i = 0; i < 64; i++) { ip[i] = (uint8_t)(k[i] ^ 0x36); op[i] = (uint8_t)(k[i] ^ 0x5c); }
    sha_init(&c); sha_upd(&c, ip, 64); sha_upd(&c, m, ml); sha_fin(&c, ih);
    sha_init(&c); sha_upd(&c, op, 64); sha_upd(&c, ih, 32); sha_fin(&c, out);
}

static void to_hex(const uint8_t *b, size_t n, char *o) {
    const char *h = "0123456789abcdef";
    size_t i;
    for (i = 0; i < n; i++) { o[i*2] = h[b[i] >> 4]; o[i*2+1] = h[b[i] & 15]; }
    o[n*2] = 0;
}

void wfas_auth_proof(const char *key, char side, const char *cn, const char *sn, char *out) {
    char in[8 + WFAS_NONCE_HEX + 1 + WFAS_NONCE_HEX + 1];
    uint8_t mac[32];
    size_t n = 0, i;
    const char *pre = "WFAS-";
    for (i = 0; pre[i]; i++) in[n++] = pre[i];
    in[n++] = side;
    in[n++] = ":"[0];
    for (i = 0; cn[i] && n < sizeof in - 1; i++) in[n++] = cn[i];
    in[n++] = ":"[0];
    for (i = 0; sn[i] && n < sizeof in - 1; i++) in[n++] = sn[i];
    in[n] = 0;
    wfas_hmac_sha256((const uint8_t *)key, strlen(key), (const uint8_t *)in, n, mac);
    to_hex(mac, 32, out);
}

int wfas_proof_equal(const char *a, const char *b) {
    if (!a || !b) return 0;
    size_t la = strlen(a), lb = strlen(b);
    if (la != lb) return 0;
    unsigned d = 0;
    size_t i;
    for (i = 0; i < la; i++) d |= (unsigned)((unsigned char)a[i] ^ (unsigned char)b[i]);
    return d == 0;
}

int wfas_get_token(const char *msg, const char *token, char *out, size_t cap) {
    if (!msg || !token || !out || cap == 0) return 0;
    char needle[64];
    size_t tn = strlen(token);
    if (tn + 2 >= sizeof needle) return 0;
    needle[0] = ';';
    memcpy(needle + 1, token, tn);
    needle[tn + 1] = '=';
    needle[tn + 2] = 0;
    const char *p = strstr(msg, needle);
    if (!p) return 0;
    p += tn + 2;
    size_t i = 0;
    while (p[i] && p[i] != ';' && i < cap - 1) { out[i] = p[i]; i++; }
    out[i] = 0;
    return (int)i;
}

/* ── ChaCha20 (RFC 8439 Section 2.3) ─────────────────────────────────────────*/
static uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wr_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint64_t rd_be64(const uint8_t *p) {
    uint64_t v = 0; int i; for (i = 0; i < 8; i++) v = (v << 8) | p[i]; return v;
}
static void wr_be64(uint8_t *p, uint64_t v) {
    int i; for (i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
#define ROTL32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
static void chacha_qr(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL32(x[d], 16);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL32(x[b], 12);
    x[a] += x[b]; x[d] ^= x[a]; x[d] = ROTL32(x[d], 8);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = ROTL32(x[b], 7);
}
static void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
    static const uint32_t C[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
    uint32_t s[16], x[16];
    int i;
    s[0] = C[0]; s[1] = C[1]; s[2] = C[2]; s[3] = C[3];
    for (i = 0; i < 8; i++) s[4 + i] = rd_le32(key + i * 4);
    s[12] = counter;
    s[13] = rd_le32(nonce + 0); s[14] = rd_le32(nonce + 4); s[15] = rd_le32(nonce + 8);
    for (i = 0; i < 16; i++) x[i] = s[i];
    for (i = 0; i < 10; i++) {
        chacha_qr(x, 0, 4, 8, 12); chacha_qr(x, 1, 5, 9, 13);
        chacha_qr(x, 2, 6, 10, 14); chacha_qr(x, 3, 7, 11, 15);
        chacha_qr(x, 0, 5, 10, 15); chacha_qr(x, 1, 6, 11, 12);
        chacha_qr(x, 2, 7, 8, 13); chacha_qr(x, 3, 4, 9, 14);
    }
    for (i = 0; i < 16; i++) wr_le32(out + i * 4, x[i] + s[i]);
}
static void chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                         const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t blk[64];
    size_t i = 0, j;
    while (i < len) {
        chacha20_block(key, counter, nonce, blk);
        counter++;
        size_t n = len - i; if (n > 64) n = 64;
        for (j = 0; j < n; j++) out[i + j] = in[i + j] ^ blk[j];
        i += n;
    }
}

/* ── Poly1305 (RFC 8439 Section 2.5), 32-bit "donna" implementation ──────────*/
typedef struct {
    uint32_t r[5], h[5], pad[4];
    size_t leftover;
    uint8_t buffer[16];
    uint8_t final;
} poly1305_ctx;

static void poly1305_init(poly1305_ctx *st, const uint8_t key[32]) {
    st->r[0] = (rd_le32(key + 0)) & 0x3ffffff;
    st->r[1] = (rd_le32(key + 3) >> 2) & 0x3ffff03;
    st->r[2] = (rd_le32(key + 6) >> 4) & 0x3ffc0ff;
    st->r[3] = (rd_le32(key + 9) >> 6) & 0x3f03fff;
    st->r[4] = (rd_le32(key + 12) >> 8) & 0x00fffff;
    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;
    st->pad[0] = rd_le32(key + 16); st->pad[1] = rd_le32(key + 20);
    st->pad[2] = rd_le32(key + 24); st->pad[3] = rd_le32(key + 28);
    st->leftover = 0; st->final = 0;
}
static void poly1305_blocks(poly1305_ctx *st, const uint8_t *m, size_t bytes) {
    const uint32_t hibit = st->final ? 0 : (1u << 24);
    uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    while (bytes >= 16) {
        uint64_t d0, d1, d2, d3, d4; uint32_t c;
        h0 += (rd_le32(m + 0)) & 0x3ffffff;
        h1 += (rd_le32(m + 3) >> 2) & 0x3ffffff;
        h2 += (rd_le32(m + 6) >> 4) & 0x3ffffff;
        h3 += (rd_le32(m + 9) >> 6) & 0x3ffffff;
        h4 += (rd_le32(m + 12) >> 8) | hibit;
        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        m += 16; bytes -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}
static void poly1305_update(poly1305_ctx *st, const uint8_t *m, size_t bytes) {
    size_t i;
    if (st->leftover) {
        size_t want = 16 - st->leftover; if (want > bytes) want = bytes;
        for (i = 0; i < want; i++) st->buffer[st->leftover + i] = m[i];
        bytes -= want; m += want; st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16);
        st->leftover = 0;
    }
    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        poly1305_blocks(st, m, want);
        m += want; bytes -= want;
    }
    if (bytes) {
        for (i = 0; i < bytes; i++) st->buffer[st->leftover + i] = m[i];
        st->leftover += bytes;
    }
}
static void poly1305_finish(poly1305_ctx *st, uint8_t mac[16]) {
    uint32_t h0, h1, h2, h3, h4, c, g0, g1, g2, g3, g4, mask;
    uint64_t f;
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < 16; i++) st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, 16);
    }
    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1u << 26);
    mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    h0 = ((h0) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;
    f = (uint64_t)h0 + st->pad[0]; h0 = (uint32_t)f;
    f = (uint64_t)h1 + st->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + st->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + st->pad[3] + (f >> 32); h3 = (uint32_t)f;
    wr_le32(mac + 0, h0); wr_le32(mac + 4, h1); wr_le32(mac + 8, h2); wr_le32(mac + 12, h3);
}

/* ── ChaCha20-Poly1305 AEAD (RFC 8439 Section 2.8) ───────────────────────────*/
static void poly1305_pad16(poly1305_ctx *st, size_t len) {
    static const uint8_t z[16] = { 0 };
    size_t rem = len % 16;
    if (rem) poly1305_update(st, z, 16 - rem);
}
static void aead_tag(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct, size_t ct_len, uint8_t tag[16]) {
    uint8_t otk[64], lenbuf[16];
    poly1305_ctx st;
    chacha20_block(key, 0, nonce, otk);
    poly1305_init(&st, otk);
    if (aad_len) { poly1305_update(&st, aad, aad_len); poly1305_pad16(&st, aad_len); }
    if (ct_len)  { poly1305_update(&st, ct, ct_len);   poly1305_pad16(&st, ct_len); }
    wr_le32(lenbuf + 0, (uint32_t)aad_len); wr_le32(lenbuf + 4, (uint32_t)((uint64_t)aad_len >> 32));
    wr_le32(lenbuf + 8, (uint32_t)ct_len);  wr_le32(lenbuf + 12, (uint32_t)((uint64_t)ct_len >> 32));
    poly1305_update(&st, lenbuf, 16);
    poly1305_finish(&st, tag);
}
void wfas_chacha20_poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12],
        const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t pt_len,
        uint8_t *ct, uint8_t tag[16]) {
    if (pt_len) chacha20_xor(key, 1, nonce, pt, ct, pt_len);
    aead_tag(key, nonce, aad, aad_len, ct, pt_len, tag);
}
int wfas_chacha20_poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12],
        const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
        const uint8_t tag[16], uint8_t *pt) {
    uint8_t calc[16];
    unsigned d = 0; size_t i;
    aead_tag(key, nonce, aad, aad_len, ct, ct_len, calc);
    for (i = 0; i < 16; i++) d |= (unsigned)(calc[i] ^ tag[i]);
    if (d != 0) return -1;
    if (ct_len) chacha20_xor(key, 1, nonce, ct, pt, ct_len);
    return 0;
}

/* ── HKDF-SHA256 (RFC 5869) ──────────────────────────────────────────────────*/
void wfas_hkdf_sha256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                      const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len) {
    uint8_t prk[32], t[32], zero[32], buf[32 + 128 + 1];
    size_t done = 0, tlen = 0;
    uint8_t ctr = 1;
    if (!salt || salt_len == 0) { memset(zero, 0, 32); salt = zero; salt_len = 32; }
    if (info_len > 128) info_len = 128;
    wfas_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    while (done < out_len) {
        size_t n = 0, take;
        if (tlen) { memcpy(buf, t, tlen); n = tlen; }
        if (info && info_len) { memcpy(buf + n, info, info_len); n += info_len; }
        buf[n++] = ctr;
        wfas_hmac_sha256(prk, 32, buf, n, t);
        tlen = 32;
        take = out_len - done; if (take > 32) take = 32;
        memcpy(out + done, t, take);
        done += take; ctr++;
    }
}

/* ── Session-key derivation ──────────────────────────────────────────────────*/
void wfas_derive_unicast_keys(const char *key, const char *cn, const char *sn,
        wfas_crypto_dir *c2s, wfas_crypto_dir *s2c) {
    uint8_t salt[WFAS_NONCE_HEX * 2 + 2];
    size_t sl = 0, i;
    size_t kl = strlen(key);
    for (i = 0; cn[i] && sl < sizeof salt; i++) salt[sl++] = (uint8_t)cn[i];
    for (i = 0; sn[i] && sl < sizeof salt; i++) salt[sl++] = (uint8_t)sn[i];
    wfas_hkdf_sha256(salt, sl, (const uint8_t *)key, kl, (const uint8_t *)"WFAS c2s key", 12, c2s->key, 32);
    wfas_hkdf_sha256(salt, sl, (const uint8_t *)key, kl, (const uint8_t *)"WFAS c2s iv", 11, c2s->nonce_prefix, 4);
    wfas_hkdf_sha256(salt, sl, (const uint8_t *)key, kl, (const uint8_t *)"WFAS s2c key", 12, s2c->key, 32);
    wfas_hkdf_sha256(salt, sl, (const uint8_t *)key, kl, (const uint8_t *)"WFAS s2c iv", 11, s2c->nonce_prefix, 4);
    c2s->send_counter = 0; s2c->send_counter = 0;
}
void wfas_derive_multicast_key(const char *key, const uint8_t *salt, size_t salt_len, wfas_crypto_dir *d) {
    size_t kl = strlen(key);
    wfas_hkdf_sha256(salt, salt_len, (const uint8_t *)key, kl, (const uint8_t *)"WFAS mcast key", 14, d->key, 32);
    wfas_hkdf_sha256(salt, salt_len, (const uint8_t *)key, kl, (const uint8_t *)"WFAS mcast iv", 13, d->nonce_prefix, 4);
    d->send_counter = 0;
}

/* ── Anti-replay window ──────────────────────────────────────────────────────*/
void wfas_replay_init(wfas_replay_window *w) { memset(w, 0, sizeof *w); }
int wfas_replay_check(const wfas_replay_window *w, uint64_t c) {
    if (!w->initialized) return 1;
    if (c > w->max_counter) return 1;
    uint64_t off = w->max_counter - c;
    if (off >= WFAS_REPLAY_BITS) return 0;
    return ((w->seen[off / 64] >> (off % 64)) & 1ULL) ? 0 : 1;
}
static void replay_shift(uint64_t *seen, uint64_t shift) {
    if (shift == 0) return;
    if (shift >= WFAS_REPLAY_BITS) { memset(seen, 0, WFAS_REPLAY_WORDS * sizeof(uint64_t)); return; }
    unsigned ws = (unsigned)(shift / 64), bs = (unsigned)(shift % 64);
    int i;
    for (i = WFAS_REPLAY_WORDS - 1; i >= 0; i--) {
        uint64_t v = 0;
        int src = i - (int)ws;
        if (src >= 0) {
            v = seen[src] << bs;
            if (bs && src - 1 >= 0) v |= seen[src - 1] >> (64 - bs);
        }
        seen[i] = v;
    }
}
void wfas_replay_commit(wfas_replay_window *w, uint64_t c) {
    if (!w->initialized) { w->initialized = 1; w->max_counter = c; w->seen[0] = 1ULL; return; }
    if (c > w->max_counter) {
        replay_shift(w->seen, c - w->max_counter);
        w->max_counter = c;
        w->seen[0] |= 1ULL;
    } else {
        uint64_t off = w->max_counter - c;
        if (off < WFAS_REPLAY_BITS) w->seen[off / 64] |= (1ULL << (off % 64));
    }
}

/* ── Encrypted packet build/parse ────────────────────────────────────────────*/
int wfas_encrypt_packet(wfas_crypto_dir *dir, uint8_t *out, size_t cap,
        uint16_t seq, uint32_t pos, int silence, const uint8_t *pcm, size_t pcm_len) {
    if (!dir || !out) return -1;
    if (pcm_len > WFAS_MAX_ENC_PAYLOAD) return -1;
    size_t total = WFAS_HEADER_SIZE + WFAS_COUNTER_BYTES + pcm_len + WFAS_AEAD_TAG_BYTES;
    if (cap < total) return -1;
    out[0] = WFAS_MAGIC_0; out[1] = WFAS_MAGIC_1; out[2] = WFAS_PROTOCOL_VERSION;
    out[3] = (uint8_t)((silence ? WFAS_FLAG_SILENCE : 0) | WFAS_FLAG_ENCRYPTED);
    wr_be16(out + 4, seq); wr_be32(out + 6, pos);
    wr_be64(out + WFAS_HEADER_SIZE, dir->send_counter);
    uint8_t nonce[12];
    memcpy(nonce, dir->nonce_prefix, 4);
    memcpy(nonce + 4, out + WFAS_HEADER_SIZE, 8);
    uint8_t *ct = out + WFAS_HEADER_SIZE + WFAS_COUNTER_BYTES;
    wfas_chacha20_poly1305_encrypt(dir->key, nonce, out, WFAS_HEADER_SIZE, pcm, pcm_len, ct, ct + pcm_len);
    dir->send_counter += 1;
    return (int)total;
}
int wfas_decrypt_packet(const wfas_crypto_dir *dir, wfas_replay_window *win,
        const uint8_t *buf, size_t len, wfas_header *hdr, uint64_t *counter,
        uint8_t *out_pcm, size_t out_cap) {
    if (!dir || !buf) return -1;
    if (len < WFAS_HEADER_SIZE + WFAS_COUNTER_BYTES + WFAS_AEAD_TAG_BYTES) return -1;
    if (buf[0] != WFAS_MAGIC_0 || buf[1] != WFAS_MAGIC_1) return -1;
    if (!(buf[3] & WFAS_FLAG_ENCRYPTED)) return -1;
    if (hdr) { hdr->version = buf[2]; hdr->flags = buf[3]; hdr->seq = rd_be16(buf + 4); hdr->sample_pos = rd_be32(buf + 6); }
    uint64_t ctr = rd_be64(buf + WFAS_HEADER_SIZE);
    if (counter) *counter = ctr;
    if (win && !wfas_replay_check(win, ctr)) return -2;
    size_t ct_len = len - WFAS_HEADER_SIZE - WFAS_COUNTER_BYTES - WFAS_AEAD_TAG_BYTES;
    if (ct_len > out_cap) return -1;
    const uint8_t *ct = buf + WFAS_HEADER_SIZE + WFAS_COUNTER_BYTES;
    uint8_t nonce[12];
    memcpy(nonce, dir->nonce_prefix, 4);
    memcpy(nonce + 4, buf + WFAS_HEADER_SIZE, 8);
    if (wfas_chacha20_poly1305_decrypt(dir->key, nonce, buf, WFAS_HEADER_SIZE, ct, ct_len, ct + ct_len, out_pcm) != 0)
        return -1;
    if (win) wfas_replay_commit(win, ctr);
    return (int)ct_len;
}

/* ── Multicast beacon ────────────────────────────────────────────────────────*/
static size_t u64_to_dec(uint64_t v, char *out) {
    char tmp[20]; size_t n = 0, i;
    if (v == 0) { out[0] = '0'; out[1] = 0; return 1; }
    while (v) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    for (i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    out[n] = 0; return n;
}
static uint64_t dec_to_u64(const char *s) {
    uint64_t v = 0; while (*s >= '0' && *s <= '9') { v = v * 10 + (uint64_t)(*s - '0'); s++; } return v;
}
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static size_t sappend(char *dst, size_t pos, size_t cap, const char *s) {
    while (*s && pos < cap - 1) dst[pos++] = *s++;
    dst[pos] = 0; return pos;
}
/* Build "epoch=<e>;time=<t>;salt=<hex>" into fields (canonical, MAC-covered). */
static size_t build_beacon_fields(uint64_t epoch, uint64_t ts, const char *salthex,
                                  char *fields, size_t cap) {
    char num[24];
    size_t n = 0;
    n = sappend(fields, n, cap, "epoch=");
    u64_to_dec(epoch, num); n = sappend(fields, n, cap, num);
    n = sappend(fields, n, cap, ";time=");
    u64_to_dec(ts, num); n = sappend(fields, n, cap, num);
    n = sappend(fields, n, cap, ";salt=");
    n = sappend(fields, n, cap, salthex);
    return n;
}
int wfas_build_mcast_beacon(const char *key, uint64_t epoch, uint64_t ts,
        const uint8_t *salt, size_t salt_len, char *out, size_t cap) {
    if (!key || !salt || !out || salt_len > WFAS_SALT_BYTES) return -1;
    char salthex[WFAS_SALT_BYTES * 2 + 1];
    char fields[96], macin[128], machex[65];
    uint8_t mac[32];
    size_t n;
    to_hex(salt, salt_len, salthex);
    build_beacon_fields(epoch, ts, salthex, fields, sizeof fields);
    n = sappend(macin, 0, sizeof macin, "WFAS-MCAST:");
    sappend(macin, n, sizeof macin, fields);
    wfas_hmac_sha256((const uint8_t *)key, strlen(key), (const uint8_t *)macin, strlen(macin), mac);
    to_hex(mac, 32, machex);
    n = sappend(out, 0, cap, WFAS_MSG_MCAST_ENC);
    n = sappend(out, n, cap, ";");
    n = sappend(out, n, cap, fields);
    n = sappend(out, n, cap, ";mac=");
    n = sappend(out, n, cap, machex);
    return (int)n;
}
int wfas_parse_mcast_beacon(const char *key, const char *msg, uint64_t last_epoch,
        uint64_t *epoch_out, uint64_t *ts_out, uint8_t *salt, size_t salt_cap, size_t *salt_len) {
    if (!key || !msg) return -1;
    if (!starts((const uint8_t *)msg, strlen(msg), WFAS_MSG_MCAST_ENC)) return -1;
    char ev[24], tv[24], sh[WFAS_SALT_BYTES * 2 + 1], mv[65];
    char fields[96], macin[128], machex[65];
    uint8_t mac[32];
    size_t n, i, shl;
    if (!wfas_get_token(msg, "epoch", ev, sizeof ev)) return -1;
    if (!wfas_get_token(msg, "time", tv, sizeof tv)) return -1;
    if (!wfas_get_token(msg, "salt", sh, sizeof sh)) return -1;
    if (!wfas_get_token(msg, "mac", mv, sizeof mv)) return -1;
    build_beacon_fields(dec_to_u64(ev), dec_to_u64(tv), sh, fields, sizeof fields);
    n = sappend(macin, 0, sizeof macin, "WFAS-MCAST:");
    sappend(macin, n, sizeof macin, fields);
    wfas_hmac_sha256((const uint8_t *)key, strlen(key), (const uint8_t *)macin, strlen(macin), mac);
    to_hex(mac, 32, machex);
    if (!wfas_proof_equal(machex, mv)) return -1;
    uint64_t e = dec_to_u64(ev);
    if (e <= last_epoch) return -2;
    shl = strlen(sh);
    if (shl % 2 || shl / 2 > salt_cap) return -1;
    for (i = 0; i < shl / 2; i++) {
        int hi = hexval(sh[i * 2]), lo = hexval(sh[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        salt[i] = (uint8_t)((hi << 4) | lo);
    }
    if (salt_len) *salt_len = shl / 2;
    if (epoch_out) *epoch_out = e;
    if (ts_out) *ts_out = dec_to_u64(tv);
    return 0;
}
