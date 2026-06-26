#include "wfas.h"
#include <string.h>

static uint16_t rd_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static void wr_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

static void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFF);
}

static int eq(const uint8_t *buf, size_t len, const char *s) {
    size_t n = strlen(s);
    return len == n && memcmp(buf, s, n) == 0;
}

static int starts(const uint8_t *buf, size_t len, const char *s) {
    size_t n = strlen(s);
    return len >= n && memcmp(buf, s, n) == 0;
}

void wfas_sender_init(wfas_sender *s) {
    s->seq = 0;
    s->sample_pos = 0;
}

int wfas_write_header(uint8_t *out, size_t out_cap,
                      uint16_t seq, uint32_t sample_pos, int silence) {
    if (out == NULL || out_cap < WFAS_HEADER_SIZE) return -1;
    out[0] = WFAS_MAGIC_0;
    out[1] = WFAS_MAGIC_1;
    out[2] = WFAS_PROTOCOL_VERSION;
    out[3] = silence ? WFAS_FLAG_SILENCE : 0;
    wr_be16(out + 4, seq);
    wr_be32(out + 6, sample_pos);
    return WFAS_HEADER_SIZE;
}

int wfas_build_audio(wfas_sender *s, uint8_t *out, size_t out_cap,
                     const int16_t *pcm, int frames, int channels) {
    if (s == NULL || out == NULL || pcm == NULL) return -1;
    if (frames <= 0 || channels <= 0) return -1;

    size_t samples = (size_t)frames * (size_t)channels;
    size_t payload = samples * 2;
    if (payload > WFAS_MAX_PAYLOAD) return -1;
    if (out_cap < WFAS_HEADER_SIZE + payload) return -1;

    wfas_write_header(out, out_cap, s->seq, s->sample_pos, 0);

    uint8_t *p = out + WFAS_HEADER_SIZE;
    for (size_t i = 0; i < samples; i++) {
        uint16_t u = (uint16_t)pcm[i];
        p[i * 2]     = (uint8_t)(u & 0xFF);
        p[i * 2 + 1] = (uint8_t)(u >> 8);
    }

    s->seq = (uint16_t)(s->seq + 1);
    s->sample_pos += (uint32_t)frames;
    return (int)(WFAS_HEADER_SIZE + payload);
}

int wfas_build_silence(wfas_sender *s, uint8_t *out, size_t out_cap) {
    if (s == NULL || out == NULL || out_cap < WFAS_HEADER_SIZE) return -1;
    wfas_write_header(out, out_cap, s->seq, s->sample_pos, 1);
    s->seq = (uint16_t)(s->seq + 1);
    return WFAS_HEADER_SIZE;
}

wfas_packet_type wfas_classify(const uint8_t *buf, size_t len) {
    if (buf == NULL || len == 0) return WFAS_PKT_INVALID;

    if (buf[0] == WFAS_MAGIC_0 && len >= 2 && buf[1] == WFAS_MAGIC_1) {
        if (len < WFAS_HEADER_SIZE) return WFAS_PKT_INVALID;
        return WFAS_PKT_AUDIO;
    }

    if (eq(buf, len, WFAS_MSG_PING))              return WFAS_PKT_PING;
    if (eq(buf, len, WFAS_MSG_BYE))               return WFAS_PKT_BYE;
    if (eq(buf, len, WFAS_MSG_CLIENT_BYE))        return WFAS_PKT_CLIENT_BYE;
    if (eq(buf, len, WFAS_MSG_MODE_PROBE))        return WFAS_PKT_MODE_PROBE;
    if (eq(buf, len, WFAS_MSG_UNICAST))           return WFAS_PKT_UNICAST;
    if (starts(buf, len, WFAS_MSG_HELLO_ACK))     return WFAS_PKT_HELLO_ACK;
    if (starts(buf, len, WFAS_MSG_INCOMPATIBLE))  return WFAS_PKT_INCOMPATIBLE;
    if (starts(buf, len, WFAS_MSG_HELLO))         return WFAS_PKT_HELLO;

    return WFAS_PKT_OTHER;
}

int wfas_parse_header(const uint8_t *buf, size_t len, wfas_header *hdr) {
    if (buf == NULL || len < WFAS_HEADER_SIZE) return -1;
    if (buf[0] != WFAS_MAGIC_0 || buf[1] != WFAS_MAGIC_1) return -1;
    if (hdr != NULL) {
        hdr->version    = buf[2];
        hdr->flags      = buf[3];
        hdr->seq        = rd_be16(buf + 4);
        hdr->sample_pos = rd_be32(buf + 6);
    }
    return 0;
}

int wfas_parse_audio(const uint8_t *buf, size_t len, wfas_header *hdr,
                     const uint8_t **pcm, size_t *pcm_len) {
    if (wfas_parse_header(buf, len, hdr) != 0) return -1;
    if (pcm != NULL)     *pcm = buf + WFAS_HEADER_SIZE;
    if (pcm_len != NULL) *pcm_len = len - WFAS_HEADER_SIZE;
    return 0;
}

int16_t wfas_pcm_get(const uint8_t *pcm, size_t sample_index) {
    const uint8_t *p = pcm + sample_index * 2;
    return (int16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

int wfas_parse_version(const char *msg) {
    if (msg == NULL) return -1;
    const char *p = strstr(msg, "v=");
    if (p == NULL) return 0;
    p += 2;
    int value = 0;
    int any = 0;
    while (*p >= '0' && *p <= '9') {
        value = value * 10 + (*p - '0');
        p++;
        any = 1;
    }
    return any ? value : 0;
}
