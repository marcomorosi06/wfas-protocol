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
