#include "wfas.h"
#include <stdio.h>
#include <string.h>

#define CHANNELS 2
#define FRAMES   320

static uint8_t g_wire[WFAS_MTU];
static size_t  g_wire_len;

static int transport_send(const uint8_t *buf, size_t len, void *user) {
    (void)user;
    if (len > sizeof g_wire) return -1;
    memcpy(g_wire, buf, len);
    g_wire_len = len;
    return 0;
}

int main(void) {
    int16_t pcm[FRAMES * CHANNELS];
    int i;
    for (i = 0; i < FRAMES * CHANNELS; i++) {
        pcm[i] = (int16_t)(i - 16384);
    }

    wfas_sender server;
    wfas_sender_init(&server);

    uint32_t expected_seq = 0;
    uint32_t expected_pos = 0;
    int ok = 1;
    int p;

    for (p = 0; p < 5; p++) {
        uint8_t packet[WFAS_MTU];
        int n = wfas_build_audio(&server, packet, sizeof packet, pcm, FRAMES, CHANNELS);
        if (n < 0) {
            printf("build failed\n");
            return 1;
        }
        transport_send(packet, (size_t)n, NULL);

        if (wfas_classify(g_wire, g_wire_len) != WFAS_PKT_AUDIO) ok = 0;

        wfas_header h;
        const uint8_t *payload;
        size_t payload_len;
        if (wfas_parse_audio(g_wire, g_wire_len, &h, &payload, &payload_len) != 0) ok = 0;

        size_t samples = payload_len / 2;
        int16_t first = wfas_pcm_get(payload, 0);
        int16_t last  = wfas_pcm_get(payload, samples - 1);

        printf("pkt %d  seq=%u  samplePos=%u  payload=%zuB  frames=%zu  v=%u  silence=%d  first=%d  last=%d\n",
               p, h.seq, h.sample_pos, payload_len, samples / CHANNELS, h.version,
               (h.flags & WFAS_FLAG_SILENCE) ? 1 : 0, first, last);

        if (h.seq != (uint16_t)expected_seq) ok = 0;
        if (h.sample_pos != expected_pos) ok = 0;
        if (first != pcm[0] || last != pcm[FRAMES * CHANNELS - 1]) ok = 0;

        expected_seq = (expected_seq + 1) & 0xFFFF;
        expected_pos += FRAMES;
    }

    const char *ack = "HELLO_ACK;v=2";
    printf("control  classify=%d  version=%d\n",
           (int)wfas_classify((const uint8_t *)ack, strlen(ack)),
           wfas_parse_version(ack));

    printf("%s\n", ok ? "ROUND-TRIP OK" : "ROUND-TRIP FAILED");
    return ok ? 0 : 1;
}
