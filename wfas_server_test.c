#define _DEFAULT_SOURCE
#include "wfas.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define STREAM_PORT     9090
#define DISCOVERY_PORT  9091
#define MCAST_GROUP     "239.255.0.1"
#define SAMPLE_RATE     48000
#define CHANNELS        2
#define FRAMES_PER_PKT  480
#define TONE_HZ         440.0
#define WFAS_PI         3.14159265358979323846

static double g_phase = 0.0;

static void fill_tone(int16_t *pcm, int frames) {
    double step = 2.0 * WFAS_PI * TONE_HZ / (double)SAMPLE_RATE;
    int i, c;
    for (i = 0; i < frames; i++) {
        int16_t s = (int16_t)(sin(g_phase) * 8000.0);
        for (c = 0; c < CHANNELS; c++) pcm[i * CHANNELS + c] = s;
        g_phase += step;
        if (g_phase > 2.0 * WFAS_PI) g_phase -= 2.0 * WFAS_PI;
    }
}

static void msleep(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void send_to(int sock, const struct sockaddr_in *to, const void *buf, size_t len) {
    sendto(sock, buf, len, 0, (const struct sockaddr *)to, sizeof *to);
}

static void send_beacon(int sock) {
    char host[64];
    char msg[256];
    struct sockaddr_in grp;
    if (gethostname(host, sizeof host) != 0) strcpy(host, "wfas-c-test");
    host[sizeof host - 1] = '\0';
    snprintf(msg, sizeof msg,
        "WIFI_AUDIO_STREAMER_DISCOVERY;%s;UNICAST;%d;protocols=WFAS;sr=%d;ch=%d;bd=16",
        host, STREAM_PORT, SAMPLE_RATE, CHANNELS);
    memset(&grp, 0, sizeof grp);
    grp.sin_family = AF_INET;
    grp.sin_port = htons(DISCOVERY_PORT);
    inet_pton(AF_INET, MCAST_GROUP, &grp.sin_addr);
    send_to(sock, &grp, msg, strlen(msg));
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    int yes = 1, ttl = 4;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);

    struct sockaddr_in local;
    memset(&local, 0, sizeof local);
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(STREAM_PORT);
    if (bind(sock, (struct sockaddr *)&local, sizeof local) < 0) { perror("bind"); return 1; }

    printf("WFAS C test server on UDP %d (unicast), tone %.0f Hz, %d Hz / %d ch.\n",
           STREAM_PORT, TONE_HZ, SAMPLE_RATE, CHANNELS);
    printf("On the phone: open the app in CLIENT mode. It should discover this host,\n");
    printf("or connect manually to this PC's LAN IP. Ctrl-C to stop.\n");

    int16_t pcm[FRAMES_PER_PKT * CHANNELS];
    uint8_t pkt[WFAS_MTU];
    char rx[512];

    for (;;) {
        struct sockaddr_in client;
        socklen_t clen;
        long last_beacon = 0;
        int connected = 0;

        printf("[waiting] announcing and waiting for a client...\n");
        while (!connected) {
            if (now_ms() - last_beacon > 1500) { send_beacon(sock); last_beacon = now_ms(); }

            struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 300000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

            clen = sizeof client;
            ssize_t n = recvfrom(sock, rx, sizeof rx - 1, 0, (struct sockaddr *)&client, &clen);
            if (n <= 0) continue;
            rx[n] = '\0';
            while (n > 0 && (rx[n-1] == '\n' || rx[n-1] == '\r' || rx[n-1] == ' ')) rx[--n] = '\0';

            if (strcmp(rx, WFAS_MSG_MODE_PROBE) == 0) {
                send_to(sock, &client, WFAS_MSG_UNICAST, strlen(WFAS_MSG_UNICAST));
            } else if (strncmp(rx, WFAS_MSG_HELLO, strlen(WFAS_MSG_HELLO)) == 0) {
                char ack[32];
                snprintf(ack, sizeof ack, "%s;v=%d", WFAS_MSG_HELLO_ACK, WFAS_PROTOCOL_VERSION);
                send_to(sock, &client, ack, strlen(ack));
                printf("[connected] client %s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
                connected = 1;
            }
        }

        wfas_sender tx;
        wfas_sender_init(&tx);
        long last_ping = now_ms();
        long target = now_ms();
        int alive = 1;

        while (alive) {
            fill_tone(pcm, FRAMES_PER_PKT);
            int len = wfas_build_audio(&tx, pkt, sizeof pkt, pcm, FRAMES_PER_PKT, CHANNELS);
            if (len > 0) send_to(sock, &client, pkt, (size_t)len);

            if (now_ms() - last_ping >= 1000) {
                send_to(sock, &client, WFAS_MSG_PING, strlen(WFAS_MSG_PING));
                last_ping = now_ms();
            }

            struct sockaddr_in from;
            socklen_t flen = sizeof from;
            ssize_t n = recvfrom(sock, rx, sizeof rx - 1, MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
            if (n > 0) {
                rx[n] = '\0';
                if (strncmp(rx, WFAS_MSG_CLIENT_BYE, strlen(WFAS_MSG_CLIENT_BYE)) == 0) {
                    printf("[bye] client disconnected\n");
                    alive = 0;
                }
            }

            target += 1000L * FRAMES_PER_PKT / SAMPLE_RATE;
            long d = target - now_ms();
            if (d > 0) msleep(d); else target = now_ms();
        }
    }
    return 0;
}
