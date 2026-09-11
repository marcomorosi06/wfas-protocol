<div align="center">
  <img src="https://github.com/marcomorosi06/WiFiAudioStreaming-Desktop/blob/master/src/main/resources/wfas_protocol.png?raw=true" alt="WFAS Icon" width="120" />
  <h1>WFAS v2 - C reference implementation</h1>

  ![C99](https://img.shields.io/badge/std-C99-blue)
  ![No malloc](https://img.shields.io/badge/malloc-0-success)
  ![Endianness safe](https://img.shields.io/badge/endianness-safe-orange)
  ![Dependency-free](https://img.shields.io/badge/dependencies-0-brightgreen)
</div>
<br/>

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
- Comes with **`wfascli`**, a command line client/server built on the library
  that streams raw PCM over stdin/stdout. `wfascli` is **only an implementation
  example**: it works and can be used, but it is not hardened — read the
  [notice below](#wfascli-notice) before relying on it.

It targets `WFAS_PROTOCOL_VERSION = 2`. Keep this repo tagged to the protocol
version so the reference never drifts from the spec.

---

## ⚠️ Security & Encryption Notice

The optional WFAS encryption feature is provided **"AS IS"** and is intended primarily as a lightweight privacy and traffic-protection layer for trusted local networks (LAN/P2P).

It is **not intended to provide protection against high-threat attackers, hostile networks, or security-critical environments**, and it should not be relied upon as a substitute for a dedicated secure transport or other security mechanisms where stronger guarantees are required.

Users and integrators are responsible for evaluating whether WFAS's security properties and their network environment are appropriate for their intended use.

The WFAS protocol and its reference implementations are provided under the terms of their respective open-source licenses. No additional security guarantees are implied beyond those explicitly documented by the protocol and implementation.

Security issues should be reported to the project maintainers so they can be investigated and addressed in future releases.

---

<a id="wfascli-notice"></a>
## ⚠️ `wfascli` is an implementation example

`wfascli` exists to **show how the library is used**: a complete, readable WFAS v2
peer built on `wfas.c` / `wfas.h`. That is its only purpose. It works and you can
use it, but it is an example, not a hardened or production-grade tool.

It is **not immune to attacks or defects** of any kind:

- **cryptographic** — how it handles keys, nonces, the handshake, session state
  and the multicast key beacon;
- **ordinary code problems** — parsing, input and output handling, timing,
  resource use and edge cases nobody thought of.

It has been tested, but tests do not prove the absence of bugs, and it has not
had an independent security review. The limitations known today are listed under
[Known limitations](#known-limitations); there may be others.

If you need a WFAS peer in a real product, treat `wfascli` as reference code to
read and adapt, and review it — together with the choices it makes — against your
own requirements. The Security & Encryption Notice above applies to it in full.

---

## Quick start

```sh
make                                                   # builds ./wfascli
./wfascli server --in music.raw                        # serve s16le PCM (48 kHz, stereo) on UDP 9090
./wfascli client <ip> | aplay -f S16_LE -r 48000 -c 2 -  # connect and play it
```

Add `--key-file <file>` to both sides to exercise the authenticated handshake,
and `--encrypt` to seal the audio as well.

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

        if (encrypted_session) {
            /* A keyed stream never carries cleartext audio, so anything
               without the flag is forged: drop it. See "Security &
               encryption" — skipping this check voids the whole AEAD. */
            uint8_t plain[WFAS_MAX_ENC_PAYLOAD];
            int n;
            if (!wfas_is_encrypted(buf, len)) break;
            n = wfas_decrypt_packet(&dir, &win, buf, len, &h, NULL,
                                    plain, sizeof plain);
            if (n < 0) break;           /* bad tag, or replayed: drop */
            play(plain, (size_t)n);
        } else {
            const uint8_t *pcm; size_t pcm_len;
            wfas_parse_audio(buf, len, &h, &pcm, &pcm_len);
            play(pcm, pcm_len);         /* PCM is signed 16-bit little-endian */
        }
        /* h.seq, h.sample_pos let you detect loss/reorder and conceal gaps. */
        break;
    }
    case WFAS_PKT_MCAST_ENC:
        /* Group key beacon: wfas_parse_mcast_beacon, derive, then latch
           encrypted_session = 1. Also your only multicast heartbeat. */
        break;
    case WFAS_PKT_PING: /* reset your keep-alive timer */ break;
    case WFAS_PKT_BYE:  /* server stopped */             break;
    case WFAS_PKT_BUSY: /* server has another client: give up, do not retry */ break;
    default: break;
}
```

`encrypted_session` is yours to decide, **once per session, before any audio
arrives**: set it because you were configured with a key, or because a beacon
whose MAC verified proved the group is keyed. Never re-derive it per packet from
what just arrived — that hands the choice to whoever is sending. If you never use
a key it stays 0 and the encrypted branch never runs.

In the cleartext branch `pcm` points straight into your receive buffer (no copy).
Read samples with `wfas_pcm_get(pcm, i)` if your CPU is big-endian or
unaligned-sensitive; otherwise the bytes are already little-endian.

**Do not rely on `WFAS_PKT_BYE` to notice that the server is gone.** `BYE` is an
unacknowledged UDP datagram, and in multicast there is no handshake and no `PING`
to fall back on. Wi-Fi sends multicast unreliably at the lowest basic rate, so
every copy can be lost — and a server that is killed never sends one at all.

In unicast the 3-second `PING` timeout covers this. In multicast the only
heartbeat is the **encryption beacon**, sent every 400 ms when a key is in use: if
you are decrypting a group, give your receive call a timeout and stop after 6
seconds with nothing received. An *unencrypted* multicast group has no heartbeat
at all — there is no keep-alive packet in v2 — so a receiver simply cannot tell a
silent server from a dead one, and should not guess.

If you are writing a server: send that beacon from a timer of its own, never from
inside your audio-capture loop. A capture that blocks when the machine is silent
will take the beacon down with it, and the group goes quiet while your server
still believes it is streaming.

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
| `wfas_is_encrypted(buf,len)` | 1 if this audio packet is sealed. Gate playback on it. |

Encrypted packet = `[header 10B (AAD)] [counter 8B] [ciphertext] [Poly1305 tag 16B]`;
the header flags byte sets bit1 (`0x02`, encrypted) alongside bit0 (silence), and
`nonce = prefix(4B) || counter(8B)`. See `WFAS_PROTOCOL.md` Sections 7–8 for the
normative details.

### No cleartext in a keyed session

**Once a receiver knows the stream is encrypted, it MUST drop every audio packet
that does not carry `0x02`.** This is normative, and it is the one rule an
implementation is most likely to get wrong.

The flag lives in the header, which travels in the clear so the AEAD can bind it
as associated data. That also means an attacker can *clear* it. If your receive
path is "encrypted? decrypt : play", a forged packet with the bit off never
reaches the tag check and goes straight to the speaker: one flipped bit walks
past ChaCha20-Poly1305 entirely, and the attacker needs no key to do it. Both
the group key and the anti-replay window become decoration.

So decide once per session — from your configuration, or from a beacon whose MAC
verified — and latch it. A sender is not allowed a vote, and "it arrived
unencrypted, so this must be a plaintext stream" is exactly the reasoning the
attack relies on. The same applies to any datagram that is not a WFAS packet at
all: `wfas_classify` returns `WFAS_PKT_OTHER`, and a keyed receiver drops it
rather than treating it as raw PCM.

Senders need no change: `wfas_encrypt_packet` always sets the flag, so nothing
conformant is refused by this rule.

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

Control messages are plain ASCII, and the `WFAS_*` ones **do** begin with the
same `0x57 0x46` as the audio magic — so the two magic bytes alone are *not*
enough to tell audio from control. Match the textual prefixes first and fall back
to the magic, which is what `wfas_classify` does. The reverse case is safe on its
own: a real audio packet's third byte is the protocol version, never `'A'`, so it
can never match `WFAS_…`.

```
MODE_PROBE                 client -> server   "are you unicast?"
UNICAST                    server -> client   reply to MODE_PROBE
HELLO_FROM_CLIENT;v=<n>    client -> server   connect, carries client version
HELLO_ACK;v=<n>            server -> client   accept, carries server version
WFAS_INCOMPATIBLE;v=<n>    server -> client   reject: version mismatch
WFAS_BUSY                  server -> client   reject: unicast session already taken
WFAS_PENDING               server -> client   held: waiting for the operator to allow you
WFAS_AUTH_REQUIRED;...     server -> client   challenge: snonce + server proof
WFAS_UNAUTHORIZED          server -> client   reject: bad proof, or refused
WFAS_MCAST_ENC;...         server -> group    signed group key beacon (~400 ms)
PING                       server -> client   keep-alive (~1 s, 3 s timeout)
BYE / CLIENT_BYE                              clean disconnect
```

Discovery beacon (UDP multicast `239.255.0.1:9091`, every ~3 s):

```
WIFI_AUDIO_STREAMER_DISCOVERY;<host>;<MULTICAST|UNICAST>;<port>;protocols=...;sr=..;ch=..;bd=..[;auth=OFF|ASK|KEY][;enc=0|1][;mic=tx|rx|txrx]
```

The optional `auth=`, `enc=` and `mic=` tokens are advisory display hints (let a
client badge a server as encrypted / key-protected, and show whether it streams
its microphone (`tx`) or accepts the client's mic / talk-back (`rx`)); they are
unauthenticated and must not drive any security decision. Unknown tokens are
ignored, so they are backward-compatible.

**One client at a time (unicast).** A unicast server is bound to a single client
for the whole session. Once the handshake completes, check the source address of
every datagram you receive:

* `HELLO_FROM_CLIENT` / `MODE_PROBE` from another address → reply `WFAS_BUSY` to
  it and carry on serving the current client. Without this the newcomer keeps
  retrying blindly until it times out.
* `CLIENT_BYE` from another address → **discard it**. Acting on it lets any host
  on the LAN tear down someone else's session.

As a client, treat `WFAS_BUSY` as a final answer: stop retrying and tell the user
the server is busy. `WFAS_BUSY` is additive — a minimal server may omit it (the
peer then just times out) and an old client that does not know it falls back to
its generic handshake-failed path — so it does not break interoperability.

Multicast has no session state: any number of receivers may join the group.

The full normative specification lives in the app repositories
(`WFAS_PROTOCOL.md`, Section 5.6). This implementation is the executable
companion to it.

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

## wfascli — command line tool

> **Implementation example.** `wfascli` works and can be used, but it is an
> example of how to use the library and is not immune to attacks or bugs,
> cryptographic or otherwise. See [the notice at the top](#wfascli-notice).

`wfascli.c` is a complete WFAS v2 peer built on this library: it discovers
servers, connects as a unicast or multicast client, or serves audio to one
unicast client or a multicast group. Audio is raw signed 16-bit little-endian
interleaved PCM on stdin/stdout, so it composes with `arecord`, `aplay`,
`ffmpeg`, `sox`, `cava` and friends. It uses only C99 + POSIX (BSD sockets,
`poll`), no dynamic allocation, and never changes what goes on the wire: all of
the protocol lives in `wfas.c` / `wfas.h`.

```sh
make                          # ./wfascli
make static                   # statically linked, for SBCs with another libc
make install PREFIX=/usr/local
```

### Commands

| Command | What it does |
|---|---|
| `discover` | List the servers announcing on the discovery group, with their advertised format and hints. |
| `client <host>` | Connect to a unicast server and write the PCM to stdout (or `--out`). |
| `mclient` | Join a multicast group and write the PCM to stdout (or `--out`). |
| `server` | Read PCM from stdin (or `--in`) and serve one unicast client. |
| `mserver` | Read PCM from stdin (or `--in`) and stream it to a multicast group. |
| `version` | Print the tool and protocol version. |

### Options

The command comes first; options follow it in any order. An option that has no
effect with the chosen command (for example `--wav` on a server, or a key on
`discover`) is reported with a warning rather than silently ignored.

| Option | Default | Meaning |
|---|---|---|
| `--rate N` | 48000 | Sample rate in Hz. Not carried in the audio header: both ends must agree. |
| `--channels N` | 2 | Channel count. Same rule as `--rate`. |
| `--frames N` | 240 | Frames per packet (servers). When not given, lowered to what fits one packet: 86 at 8 channels, 85 when encrypted. An explicit value that does not fit is an error. Clients only use it to size silence until the first audio packet. |
| `--in FILE` / `--out FILE` | stdin / stdout | PCM source (servers) / destination (clients). `-` means stdin/stdout. |
| `--wav` | off | Clients: prepend a WAV header. Its sizes are filled in on close when the output is a regular file, including `> file.wav`; on a pipe, or with `>>`, they stay at the streaming value. |
| `--port N` | 9090 | Unicast stream port, or multicast audio port. |
| `--discovery-port N` | 9091 | Presence beacon port (`discover`, and servers with `--announce`). |
| `--discovery-group ADDR` | 239.255.0.1 | Presence beacon group (`discover`, and servers with `--announce`). |
| `--group ADDR` | 239.255.0.1 | Multicast audio group (`mclient`, `mserver`). |
| `--iface ADDR` | any | Local address used for multicast. Must belong to this machine. |
| `--ttl N` | 4 | TTL of everything sent to a multicast group: audio, key beacon, presence beacon. |
| `--announce` / `--name NAME` | off / hostname | Servers: send the presence beacon, optionally under another name (at most 63 bytes, no `;` or control characters). |
| `--key-file FILE` | — | Pre-shared key, first line of FILE. Preferred way to pass the key. |
| `--key SECRET` | — | Pre-shared key on the command line. Visible in `ps` and the shell history. |
| `WFAS_KEY` | — | Environment fallback used when neither option above is given. |
| `--encrypt` | off | Seal the audio with ChaCha20-Poly1305. Needs a key. |
| `-q`/`--quiet`, `-v`/`--verbose`, `--no-stats`, `-h`/`--help` | | Quiet (hides progress only: warnings and errors are still printed), verbose protocol trace, no periodic stats line on stderr, usage. |

### Examples

```sh
wfascli discover
wfascli client 192.168.1.42 | aplay -f S16_LE -r 48000 -c 2 -
wfascli client 192.168.1.42 --wav --out capture.wav
wfascli client 192.168.1.42 --key-file ~/.wfas.key --encrypt | aplay -f S16_LE -r 48000 -c 2 -
arecord -f S16_LE -r 48000 -c 2 - | wfascli server --announce
arecord -f S16_LE -r 48000 -c 2 - | wfascli mserver --key-file ~/.wfas.key --encrypt --announce
wfascli mclient --key-file ~/.wfas.key | aplay -f S16_LE -r 48000 -c 2 -
arecord -f S16_LE -r 48000 -c 8 - | wfascli server --channels 8   # --frames adapts by itself
ffmpeg -i song.flac -f s16le -ar 44100 -ac 2 - | wfascli server --rate 44100
```

### Behaviour worth knowing

- **Encryption is decided once, never per packet.** A unicast client started with
  `--encrypt` drops every audio packet that is not sealed (see
  [No cleartext in a keyed session](#no-cleartext-in-a-keyed-session)). A client
  started without it drops sealed packets instead of writing ciphertext out as
  full-scale noise, and says once which option is missing. `mclient` latches
  encryption when a beacon verifies; while it holds a key and has not seen one,
  it plays nothing.
- **Keyed clients refuse a downgrade.** A client holding a key aborts if the
  server accepts it without running the challenge, and verifies the server's
  proof before sending its own.
- **Servers never block on their input.** Pacing comes from the total number of
  frames sent at `--rate` (no per-packet rounding), and `PING`, the key beacon and
  the presence beacon run from timers of their own. If the input produces
  nothing for 500 ms the server sends silence frames until it resumes, so a paused
  capture does not look like a dead server.
- **Silence frames on the client** become zeros for as long as the last audio
  packet the server sent, so the output timeline stays continuous.
- **One unicast client at a time.** The client is identified by address and port.
  A repeated `HELLO_FROM_CLIENT` from it (its `HELLO_ACK` was lost) is
  acknowledged again — in keyed mode only with a valid proof for the session's
  nonces. Any other host, or another process on the same host, gets `WFAS_BUSY`.
  `CLIENT_BYE` is honoured only from the client's host. A retransmitted keyed
  HELLO gets the same challenge back, so a duplicate datagram cannot make a
  correct proof fail.
- **A unicast client only listens to its server's address.** Datagrams from
  anyone else are dropped, during the handshake as well as while streaming.
- **Addresses are checked up front.** `--group` and `--discovery-group` must be
  IPv4 multicast addresses (224.0.0.0/4), and `--iface` must resolve to an
  address of this machine; anything else is an error instead of packets quietly
  going out another way. A unicast `--port` has a single owner: a second
  `server` on the same port fails to start.
- **Presence beacons use the discovery group, not the audio group.** An
  `mserver` whose `--group` differs from `--discovery-group` warns that the beacon
  does not carry the audio group, so receivers must be given `--group` by hand.
- **`--out` is checked before connecting.** An unwritable path fails before the
  client takes the server's only unicast slot. An existing file is left untouched
  if the handshake fails, and a file created for the session is removed.
- A key file holds one key on its first line, at most 1024 bytes; a longer key
  is an error rather than being cut short.
- Nonces and the multicast salt come from `/dev/urandom`; if it cannot be read
  the tool exits rather than fall back to a weak source.

### Exit status

| Code | Meaning |
|---:|---|
| 0 | Normal end (input ended, `BYE`, Ctrl-C). |
| 1 | Error: bad option, I/O or socket failure. |
| 2 | Usage error, or no usable response from the server. |
| 3 | Downgrade refused: keyed client accepted without a challenge, or `--encrypt` without a keyed handshake. |
| 4 | The server requires a key. |
| 5 | The server's proof is invalid (wrong key, or a rogue server). |
| 6 | `WFAS_UNAUTHORIZED`. |
| 7 | `WFAS_BUSY`: the server already has a client. |
| 8 | `WFAS_INCOMPATIBLE`: protocol version mismatch. |
| 9 | The server went silent (no `PING` for 3 s, or no beacon for 6 s in a keyed group). |
| 10 | Keyed group: audio keeps arriving but has not decrypted for 6 s (see below). |

### Known limitations

- **A unicast server cannot tell a crashed client from a quiet one.** v2 has no
  client-to-server keep-alive, so if `CLIENT_BYE` never arrives the server keeps
  streaming until its input ends, answering `WFAS_BUSY` to everyone else. Restart
  the server in that case.
- **The multicast epoch starts at 1 on every run.** A receiver that heard a
  previous run of `mserver` treats the restarted server's beacons as stale, so it
  cannot derive the new group key; `mclient` detects this and exits with status 10
  so it can be restarted. For the same reason a recording of an earlier session
  can be replayed to a freshly started receiver. Fixing this means choosing the
  epoch differently and is pending review against `WFAS_PROTOCOL.md` Section 8.
- An **unencrypted multicast group has no heartbeat**, so `mclient` runs until
  `BYE` or Ctrl-C.
- `PING` and `BYE` are unauthenticated control messages in v2, including in an
  encrypted session.
- While a unicast server waits for its client it does not read its input, so a
  live source such as `arecord` backs up in the pipe and the first fraction of a
  second the client hears is stale.
- IPv4 only.

## License

MIT — see `LICENSE`. Use it in closed-source firmware freely. The apps themselves
are licensed separately (EUPL); this reference is intentionally permissive to make
adopting WFAS v2 friction-free.
