# `sysupd` — not Torii, not Mirai: an original DDoS booter

**TL;DR.** A Linux **DDoS booter** caught in a honeypot, wearing two misleading labels. MalwareBazaar calls it
**Torii** (off its persistence strings); its `127.0.0.1:48101` single-instance lock screams **Mirai** (that's
Mirai's port). **Both are wrong.** At the code level it's an **independent, largely-original booter** — its own
PRNG, checksum, flood routines and dispatch, plus a bespoke plaintext C2. It shares Mirai's *lock-port
convention*, not its *code*, and shares nothing with Torii but an aggressive persistence style. Detection was
low (15/74) at capture. Shape-labelled **`sysupd-booter`**.

Analysis below is static RE + a **contained dynamic detonation** (packet captures of every attack method) + a
**direct code-diff against the leaked Mirai source**. Nothing was run outside an isolated, no-egress lab.

---

## Two false labels — and why both fail

This sample is a small case study in labelling malware off a single surface artifact. It carries two, and
neither survives contact with the code.

**"Torii" (MalwareBazaar) — a persistence-string mislabel.** Real Torii (Avast, 2018) was a **Go** stealth
data-exfil **RAT** with encrypted comms and **no DDoS**. The only thing this sample shares with it is the
aggressive multi-init **"sysupd"** persistence — which is exactly what the AV signature keyed on. This bot is
not a RAT and exfiltrates nothing; it's a flooder.

**"Mirai" (the lock port) — a port-number mislabel.** The bot does `bind(127.0.0.1:48101)` — Mirai's canonical
single-instance lock port, and the *one* concrete Mirai artifact in the whole binary. Tempting to call that
lineage. But a direct diff against the leaked Mirai source (`mirai/bot/`) says **it is not a Mirai fork (~15%),
and not even a copy-paste of Mirai's flood code:**

| Component | Mirai | This sample |
|---|---|---|
| PRNG | xorshift `rand_next` (`t^=t<<11; t^=t>>8; w^=w>>19`) | **glibc `random()`** — the 11/8/19 constants are *absent* |
| Checksum | `checksum_generic` (word reads, 2-statement fold) | **different** (byte-pair read + looping fold) |
| TCP flood | `attack_tcp_syn` with a 40-byte TCP-options block | **no TCP options at all** |
| Dispatch | double-fork + dynamic `attack_parse`/method-table | **single-fork → compiled jump table** |
| Scanner / XOR config / `\x00\x00\x00\x01` reg | present | **all absent** |
| `127.0.0.1:48101` lock | yes | **yes — the only shared artifact** |

The PRNG and checksum are the decisive discriminators — distinctive, and essentially never rewritten in a
genuine fork. Both come back independent. Nobody rewrites the PRNG, the checksum, *and* the whole dispatch
framework while keeping only a lock port. So: **an independent DDoS booter that cargo-culted Mirai's lock port
and general flood ideas — not a Mirai variant.**

The takeaway cuts both ways: a persistence string said "Torii," a port number said "Mirai," and the code said
neither. **Identify by code, not by one constant.**

## The bespoke-but-plaintext C2 — and why

The author wrote their own C2 protocol yet left it entirely in the clear. That's not a contradiction once you
read "bespoke" as *minimal and self-owned*, not *sophisticated*:

- Obfuscating the C2 is mostly theatre — the bot **must** connect to it, so any sandbox run reveals the address
  regardless. XOR/encryption only beats a lazy `strings`.
- The evasion here is **novelty, not crypto** — 15/74 on a fresh codebase, *with* a plaintext protocol. No
  signatures exist yet, so plaintext costs nothing.
- A plaintext, 3-opcode protocol is **easy to operate** — trivial C2 server, no key management, no crypto bugs.

It reads as a booter operator optimising for simplicity and control, not a malware author optimising for
stealth. The one custom flourish — the CPU-count byte in the beacon — is an *operational* optimisation, not an
evasion one.

### Registration beacon

```
A1 71 4E 01 02 | <nproc> | <hostlen> | <hostname…>
   5-byte magic   1 byte     1 byte      N bytes
```

The byte after the magic is the host's **CPU count** (`sysconf(_SC_NPROCESSORS_ONLN)`) — the operator gauges
each bot's flood capacity at check-in.

### Framing & opcodes

`[type u8][length u16 BE][body]`, length ≤ 2048, **length 0 = keepalive**.

- `0x01` **ping** → bot replies `02 00 00` (pong). The only keepalive; CNC-driven.
- `0x10` **launch** (body below).
- `0x11` **stop** → by attack-key IP; `FF FF FF FF` = stop all.

### `0x10` launch body (15-byte header, confirmed on-wire)

```
[0:4]   attack-key IPv4     (handle used by 0x11 STOP-by-target)
[4]     method (1–5)
[5:7]   duration (BE, 1–3600 s)
[7:11]  flood-destination IPv4
[11:13] destination port (BE)
[13:15] payload length (BE, ≤1024)
[15:]   payload
```

Note the **two IP fields** — an attack handle (for `0x11` stop) and the actual flood target.

## Attack methods (observed on the wire)

- **1 — UDP, random volumetric:** randomised packet sizes (≈560–1400 B); ignores any supplied payload.
- **2 — UDP, fixed:** 16-byte payload.
- **3 — UDP, operator payload:** sends the attacker-supplied payload verbatim.
- **4 — TCP SYN flood, spoofed:** `SOCK_RAW` + `IP_HDRINCL`, hand-built IP/TCP headers, **source IP randomised
  per packet** (~83k distinct sources across ~84k packets — effectively unique-per-packet, full range).
- **5 — TCP ACK flood, spoofed:** same raw path, ACK instead of SYN.

Each method forks multiple flood workers. Strictly L3/L4 volumetric — **no HTTP/L7 method**.

## What it does *not* do

No scanner/propagation, no proxy/relay, no data-exfil command, no shell/exec over C2, no loader or
self-update. `execve` appears **only** in the startup persistence installer. A single-purpose flooder.

## Persistence

The running process masquerades as **`udhcpc`**, and installs a self-copy (`/usr/bin/.sysupd`, byte-identical
to the sample) as **`sysupd`** via every mechanism at once:

- systemd unit (`sysupd.service`, `Restart=always`)
- SysV `init.d` (`/etc/init.d/sysupd` + `S90sysupd`), OpenRC
- cron: `/etc/cron.d/sysupd`, a `@reboot` line, and a `*/5 * * * *` **root respawn**
- `/etc/profile.d/sysupd.sh`, `~/.bashrc`, `~/.profile`
- XDG autostart `.desktop`, `rc.local`

It also opens `/dev/watchdog` (IoT anti-reboot). Respawn pidfile: `/tmp/.ash.pid`.

## Analyst note — a *verified* false-positive

A 128-byte high-entropy blob in `.data` (`0x50f3a0`) looks like a key or encrypted config, but it's glibc's
static **`randtbl`** PRNG initial-state table: the first word is `TYPE_3`, the 128 bytes are byte-for-byte
identical to upstream glibc, and the region is referenced *only* by the statically-linked `random_r` machinery
— glibc's `struct random_data` pointers (`state`/`fptr`/`rptr`/`end_ptr`) walk exactly this array. A benign
libc artefact, flagged because it's an easy false-positive when you're hunting for a config key. (Fittingly,
this is *also* the only piece of glibc `random()` in the binary — the same fact that proves the flood code
isn't Mirai's.)

## Detection

**Network (Suricata-style):**

```
alert tcp any any -> any any ( \
  msg:"sysupd-booter registration beacon"; \
  flow:established,to_server; dsize:>7; \
  content:"|a1 71 4e 01 02|"; offset:0; depth:5; \
  classtype:trojan-activity; sid:1000001; rev:1; )
```

**Host IOCs:**

- Masquerades: process `udhcpc`; install name `sysupd` / `.sysupd`
- Paths: `/usr/bin/.sysupd`, `/etc/init.d/sysupd`, `/etc/cron.d/sysupd`, `/etc/profile.d/sysupd.sh`,
  `sysupd.service`, `/tmp/.ash.pid`
- Single-instance lock: `bind 127.0.0.1:48101` (cargo-culted Mirai constant — **not** proof of Mirai lineage)
- Beacon magic: `A1 71 4E 01 02`

**Sample:**

- SHA-256 `4a5a96612e7316586a4c61a4d7dd28dfadf087be9ccfa2c04b06206cca610de7`
  (x86-64 ELF, statically linked, stripped, GCC 4.1.2)

**C2 omitted** — the live infrastructure is still active and under observation.

## Naming

No self-ID, version, or author strings in the binary. Named **`sysupd-booter`** after its persistence artefact
(shape-based). It's **not a known family**: not Torii (a persistence-string mislabel), not Mirai (a lock-port
mislabel), and not a fork of either — an independent implementation with a bespoke C2. A descriptive name beats
two borrowed and wrong ones.

---

*Static analysis + a contained lab detonation (isolated, no-egress; the C2 was redirected to a lab sink and the
sample never contacted the real operator) + a code-diff against the leaked Mirai source. Detection content above
is free for defenders to use.*
