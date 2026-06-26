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
#define FRAMES_PER_PKT  240
#define TONE_HZ         440.0
#define WFAS_PI         3.14159265358979323846

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void msleep(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static void send_to(int sock, const struct sockaddr_in *to, const void *buf, size_t len) {
    sendto(sock, buf, len, 0, (const struct sockaddr *)to, sizeof *to);
}

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

static void send_beacon(int sock) {
    char host[64], msg[256];
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

static int run_server(void) {
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

    printf("[server] UDP %d, tone %.0f Hz, %d Hz / %d ch. Phone in CLIENT mode (48 kHz/stereo).\n",
           STREAM_PORT, TONE_HZ, SAMPLE_RATE, CHANNELS);

    int16_t pcm[FRAMES_PER_PKT * CHANNELS];
    uint8_t pkt[WFAS_MTU];
    char rx[512];

    for (;;) {
        struct sockaddr_in client;
        socklen_t clen;
        long last_beacon = 0;
        int connected = 0;
        printf("[server] waiting for a client...\n");
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
                printf("[server] connected: %s:%d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));
                connected = 1;
            }
        }
        wfas_sender tx;
        wfas_sender_init(&tx);
        long last_ping = now_ms(), target = now_ms();
        int alive = 1;
        while (alive) {
            fill_tone(pcm, FRAMES_PER_PKT);
            int len = wfas_build_audio(&tx, pkt, sizeof pkt, pcm, FRAMES_PER_PKT, CHANNELS);
            if (len > 0) send_to(sock, &client, pkt, (size_t)len);
            if (now_ms() - last_ping >= 1000) {
                send_to(sock, &client, WFAS_MSG_PING, strlen(WFAS_MSG_PING));
                last_ping = now_ms();
            }
            struct sockaddr_in from; socklen_t flen = sizeof from;
            ssize_t n = recvfrom(sock, rx, sizeof rx - 1, MSG_DONTWAIT, (struct sockaddr *)&from, &flen);
            if (n > 0) {
                rx[n] = '\0';
                if (strncmp(rx, WFAS_MSG_CLIENT_BYE, strlen(WFAS_MSG_CLIENT_BYE)) == 0) {
                    printf("[server] client disconnected\n");
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

static int run_client(const char *ip, int play) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    struct sockaddr_in server;
    memset(&server, 0, sizeof server);
    server.sin_family = AF_INET;
    server.sin_port = htons(STREAM_PORT);
    if (inet_pton(AF_INET, ip, &server.sin_addr) != 1) {
        fprintf(stderr, "[client] bad IP: %s\n", ip);
        return 1;
    }

    char hello[64], rx[2048];
    snprintf(hello, sizeof hello, "%s;v=%d", WFAS_MSG_HELLO, WFAS_PROTOCOL_VERSION);
    struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    fprintf(stderr, "[client] connecting to %s:%d ...\n", ip, STREAM_PORT);
    int connected = 0;
    long start = now_ms();
    while (!connected && now_ms() - start < 15000) {
        send_to(sock, &server, hello, strlen(hello));
        ssize_t n = recvfrom(sock, rx, sizeof rx - 1, 0, NULL, NULL);
        if (n <= 0) continue;
        rx[n] = '\0';
        if (strncmp(rx, WFAS_MSG_HELLO_ACK, strlen(WFAS_MSG_HELLO_ACK)) == 0) {
            int v = wfas_parse_version(rx);
            if (v != WFAS_PROTOCOL_VERSION) {
                fprintf(stderr, "[client] incompatible server v=%d (mine v=%d)\n", v, WFAS_PROTOCOL_VERSION);
                return 1;
            }
            connected = 1;
        } else if (strncmp(rx, WFAS_MSG_INCOMPATIBLE, strlen(WFAS_MSG_INCOMPATIBLE)) == 0) {
            fprintf(stderr, "[client] server rejected: %s\n", rx);
            return 1;
        }
    }
    if (!connected) { fprintf(stderr, "[client] no response from %s:%d\n", ip, STREAM_PORT); return 1; }
    fprintf(stderr, "[client] connected, receiving%s ...\n", play ? " (PCM -> stdout)" : "");

    long last_ping = now_ms(), last_stat = now_ms(), t0 = now_ms();
    long audio = 0, bytes = 0, lost = 0, reord = 0;
    int expected = -1, last_seq = 0, running = 1;
    uint32_t last_pos = 0;

    while (running) {
        ssize_t n = recvfrom(sock, rx, sizeof rx, 0, NULL, NULL);
        long now = now_ms();
        if (n > 0) {
            switch (wfas_classify((const uint8_t *)rx, (size_t)n)) {
                case WFAS_PKT_AUDIO: {
                    wfas_header h; const uint8_t *pcm; size_t pl;
                    if (wfas_parse_audio((const uint8_t *)rx, (size_t)n, &h, &pcm, &pl) == 0) {
                        audio++; bytes += (long)pl; last_pos = h.sample_pos; last_seq = h.seq;
                        if (expected < 0) expected = h.seq;
                        int gap = (h.seq - expected) & 0xFFFF;
                        if (gap != 0) { if (gap < 0x8000) lost += gap; else reord++; }
                        if (gap < 0x8000) expected = (h.seq + 1) & 0xFFFF;
                        if (play && pl > 0) { fwrite(pcm, 1, pl, stdout); }
                    }
                    break;
                }
                case WFAS_PKT_PING: last_ping = now; break;
                case WFAS_PKT_BYE:  fprintf(stderr, "[client] server said BYE\n"); running = 0; break;
                default: break;
            }
        }
        if (now - last_ping > 3000) { fprintf(stderr, "[client] timeout: no PING for 3 s\n"); running = 0; }
        if (now - last_stat >= 1000) {
            double sec = (now - t0) / 1000.0;
            double kbps = sec > 0 ? (bytes * 8.0 / 1000.0) / sec : 0;
            fprintf(stderr, "[client] audio=%ld bytes=%ld %.0f kbit/s lost=%ld reorder=%ld lastSeq=%d samplePos=%u\n",
                    audio, bytes, kbps, lost, reord, last_seq, last_pos);
            last_stat = now;
        }
    }
    send_to(sock, &server, WFAS_MSG_CLIENT_BYE, strlen(WFAS_MSG_CLIENT_BYE));
    return 0;
}

static int usage(const char *prog) {
    fprintf(stderr,
        "usage:\n"
        "  %s server                 stream a test tone (act as WFAS server)\n"
        "  %s client <server-ip>     connect and print receive stats\n"
        "  %s client <server-ip> --play   ... and write raw PCM to stdout\n"
        "\nplay example:  %s client 192.168.1.50 --play | aplay -f S16_LE -r 48000 -c 2\n",
        prog, prog, prog, prog);
    return 2;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc >= 2 && strcmp(argv[1], "server") == 0) return run_server();
    if (argc >= 3 && strcmp(argv[1], "client") == 0) {
        int play = (argc >= 4 && strcmp(argv[3], "--play") == 0);
        return run_client(argv[2], play);
    }
    return usage(argv[0]);
}
