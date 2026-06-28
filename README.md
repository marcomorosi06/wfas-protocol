# WFAS v2 — C reference implementation

A tiny, dependency-free C implementation of the **WiFi Audio Streaming (WFAS) v2**
wire protocol: the packet format used by the WFAS desktop and Android apps to
stream raw 16-bit PCM audio over UDP on a local network.

This is meant as a drop-in starting point for **embedded / firmware** developers
(ESP32, STM32, RP2040, Linux SBCs, …) who want a device to act as a WFAS server
(audio source) or client (audio sink) and interoperate with the apps.

- **C99**, no dynamic allocation, no libc beyond `<stdint.h>` / `<string.h>`.
- **Transport-agnostic**: this library only builds and parses bytes. You provide
  the UDP socket (lwIP, BSD sockets, an RTOS stack, whatever you have).
- **Endianness-safe**: the header is serialized big-endian and the PCM payload
  little-endian by hand, so the same code runs identically on big- or
  little-endian MCUs.
- Two files to vendor: `wfas.c` + `wfas.h`.

It targets `WFAS_PROTOCOL_VERSION = 2`. Keep this repo tagged to the protocol
version so the reference never drifts from the spec.

## Quick start

```sh
make run      # builds and runs the round-trip self-test in example.c
```

To use it in your project, copy `wfas.h` and `wfas.c` in and `#include "wfas.h"`.

### Server side (audio source)

```c
wfas_sender tx;
wfas_sender_init(&tx);

uint8_t packet[WFAS_MTU];

for (;;) {
    int16_t *pcm; int frames;          /* your capture: interleaved int16 */
    capture_audio(&pcm, &frames);      /* frames = samples per channel    */

    int n = wfas_build_audio(&tx, packet, sizeof packet, pcm, frames, CHANNELS);
    if (n > 0) udp_send(packet, (size_t)n);   /* your transport */
}
```

`wfas_build_audio` writes the 10-byte header (with the running `seq` and
`sample_pos`) followed by the PCM, advances the counters, and returns the total
length. Keep `frames * channels * 2 <= WFAS_MAX_PAYLOAD` (split larger blocks
across several packets, or pass fewer frames). Send `wfas_build_silence` while
the source is idle/muted to keep the stream and timing alive.

### Client side (audio sink)

```c
uint8_t buf[WFAS_MTU];
size_t  len = udp_recv(buf, sizeof buf);    /* your transport */

switch (wfas_classify(buf, len)) {
    case WFAS_PKT_AUDIO: {
        wfas_header h;
        const uint8_t *pcm; size_t pcm_len;
        wfas_parse_audio(buf, len, &h, &pcm, &pcm_len);
        /* h.seq, h.sample_pos let you detect loss/reorder and conceal gaps. */
        play(pcm, pcm_len);             /* PCM is signed 16-bit little-endian */
        break;
    }
    case WFAS_PKT_PING: /* reset your keep-alive timer */ break;
    case WFAS_PKT_BYE:  /* server stopped */             break;
    default: break;
}
```

`pcm` points straight into your receive buffer (no copy). Read samples with
`wfas_pcm_get(pcm, i)` if your CPU is big-endian or unaligned-sensitive;
otherwise the bytes are already little-endian.

## API

| Function | Purpose |
|---|---|
| `wfas_sender_init(s)` | Reset a sender's `seq` and `sample_pos` to 0. |
| `wfas_write_header(out, cap, seq, pos, silence)` | Serialize just the 10-byte header. Returns 10 or -1. |
| `wfas_build_audio(s, out, cap, pcm, frames, channels)` | Header + PCM; advances counters. Returns total bytes or -1. |
| `wfas_build_silence(s, out, cap)` | Header-only silence frame; advances `seq`. Returns 10 or -1. |
| `wfas_classify(buf, len)` | Tell audio vs each control message apart. |
| `wfas_parse_header(buf, len, hdr)` | Validate magic and decode the header. Returns 0 or -1. |
| `wfas_parse_audio(buf, len, hdr, &pcm, &pcm_len)` | Header + a pointer/length into the PCM payload. Returns 0 or -1. |
| `wfas_pcm_get(pcm, i)` | Read PCM sample `i` as a host `int16_t` (little-endian). |
| `wfas_parse_version(msg)` | Extract `<n>` from a `...;v=<n>` control message. |

`seq` increments per packet and wraps at `0xFFFF`. `sample_pos` is the monotonic
per-channel sample index and advances by `frames` on each audio packet (silence
frames advance `seq` only). Every server **must** fill both on every packet.

## Security & encryption (optional)

Both layers use a pre-shared key and need no asymmetric crypto. They are optional:
a peer that wants neither stays fully conformant.

**Authentication** (who may connect) — mutual HMAC-SHA256 challenge-response:

| Function | Purpose |
|---|---|
| `wfas_hmac_sha256(key,kl,msg,ml,out)` | HMAC-SHA256, self-contained (RFC 2104). |
| `wfas_auth_proof(key,side,cnonce,snonce,out)` | Compute the `'S'`/`'C'` proof hex. |
| `wfas_proof_equal(a,b)` | Constant-time hex compare. |
| `wfas_get_token(msg,token,out,cap)` | Read `;token=value` from a control message. |

**Encryption** (what is sent) — ChaCha20-Poly1305 (RFC 8439) per packet, keys via
HKDF-SHA256 (RFC 5869):

| Function | Purpose |
|---|---|
| `wfas_derive_unicast_keys(key,cnonce,snonce,&c2s,&s2c)` | Per-direction session keys from the handshake nonces. |
| `wfas_derive_multicast_key(key,salt,len,&dir)` | Group key from the beacon salt. |
| `wfas_encrypt_packet(&dir,out,cap,seq,pos,silence,pcm,len)` | Seal a packet; advances the counter. |
| `wfas_decrypt_packet(&dir,&win,buf,len,&hdr,&ctr,out,cap)` | Open + anti-replay; returns len, -1 (auth), -2 (replay). |
| `wfas_replay_init/check/commit(&win,...)` | 1024-wide anti-replay window. |
| `wfas_build_mcast_beacon / wfas_parse_mcast_beacon(...)` | Signed multicast key beacon with monotonic `epoch`. |

Encrypted packet = `[header 10B (AAD)] [counter 8B] [ciphertext] [Poly1305 tag 16B]`;
the header flags byte sets bit1 (`0x02`, encrypted) alongside bit0 (silence), and
`nonce = prefix(4B) || counter(8B)`. See `WFAS_PROTOCOL.md` Sections 7–8 for the
normative details. The bundled `wfas_test selftest` checks all of the above against
the RFC 8439 / 5869 / 4231 test vectors.

## The wire protocol (summary)

Raw 16-bit PCM over UDP. Three phases: discovery (the server announces itself via
UDP multicast), connection (a HELLO/ACK handshake in unicast; a group join in
multicast) and streaming (a continuous flow of audio packets with PING/BYE
control messages interleaved on the same socket).

**Audio packet** = 10-byte header + PCM payload:

```
 byte  0   1   2   3   4   5   6   7   8   9   10 ...
      +---+---+---+---+---+---+---+---+---+---+----------------+
      | W | F | V | F | seq   | sample position | PCM payload  |
      +---+---+---+---+---+---+---+---+---+---+----------------+
```

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 1 | magic 0 | `0x57` `'W'` |
| 1 | 1 | magic 1 | `0x46` `'F'` |
| 2 | 1 | version | `0x02` for v2 |
| 3 | 1 | flags | bit0 = silence frame |
| 4–5 | 2 | seq | big-endian uint16, wraps at 0xFFFF |
| 6–9 | 4 | sample position | big-endian uint32, monotonic per-channel index |
| 10… | n | PCM payload | signed 16-bit **little-endian**, interleaved |

Payload length is chosen by the server, per packet: a whole number of frames
(`channels * 2` bytes), never more than `WFAS_MAX_PAYLOAD` (`MTU - 10`, i.e. 1390
on a standard 1500-byte MTU). A receiver must accept any size within these
bounds — it is not fixed, and a constrained device may stream small packets.

Control messages are plain ASCII and never start with `0x57 0x46`, so audio and
control are told apart by the two magic bytes alone:

```
MODE_PROBE                 client -> server   "are you unicast?"
UNICAST                    server -> client   reply to MODE_PROBE
HELLO_FROM_CLIENT;v=<n>    client -> server   connect, carries client version
HELLO_ACK;v=<n>            server -> client   accept, carries server version
WFAS_INCOMPATIBLE;v=<n>    server -> client   reject: version mismatch
PING                       server -> client   keep-alive (~1 s, 3 s timeout)
BYE / CLIENT_BYE                              clean disconnect
```

Discovery beacon (UDP multicast `239.255.0.1:9091`, every ~3 s):

```
WIFI_AUDIO_STREAMER_DISCOVERY;<host>;<MULTICAST|UNICAST>;<port>;protocols=...;sr=..;ch=..;bd=..[;auth=OFF|ASK|KEY][;enc=0|1]
```

The optional `auth=` and `enc=` tokens are advisory display hints (let a client
badge a server as encrypted / key-protected); they are unauthenticated and must
not drive any security decision. Unknown tokens are ignored, so they are
backward-compatible.

The full normative specification lives in the app repositories
(`WFAS_PROTOCOL.md`). This implementation is the executable companion to it.

## Notes for embedded targets

- **No allocation, no globals**: every buffer is caller-provided. A `wfas_sender`
  is 8 bytes; you can keep one per stream on the stack.
- **Buffer sizing**: a `uint8_t[WFAS_MTU]` (1400 B) holds any packet. If you only
  ever send small packets, size your buffer to `WFAS_HEADER_SIZE + your_payload`.
- **Audio format must match the peer**: sample rate and channel count are not
  carried in the audio header. In multicast they are advertised in the discovery
  beacon (`sr` / `ch`); in unicast both ends must agree out of band. PCM is always
  signed 16-bit.
- **Thread/ISR split**: building and parsing are pure and reentrant; only the
  `wfas_sender` counters are mutable, so guard a sender if two contexts share it.

## License

MIT — see `LICENSE`. Use it in closed-source firmware freely. The apps themselves
are licensed separately (EUPL); this reference is intentionally permissive to make
adopting WFAS v2 friction-free.
