# `sysupd` — a Mirai booter in Torii's clothes

**TL;DR.** A Linux **DDoS booter** caught in a honeypot. MalwareBazaar labels it **Torii** — it isn't.
Under the hood it's **Mirai-lineage**: it keeps Mirai's single-instance lock and multi-arch spoofed-flood
engine, but has had the scanner and config system **stripped out**, a **bespoke plaintext C2 protocol** bolted
on, and **Torii-style "sysupd" persistence** grafted over the top. The "Torii" name comes from that
persistence, not from the code's actual lineage. Detection was low (15/74) at capture. Shape-labelled
**`sysupd-booter`**.

Analysis below is static RE **plus a contained dynamic detonation** (packet captures of every attack method).
Nothing was run outside an isolated, no-egress lab.

---

## Lineage: Mirai, not Torii

The giveaway is at runtime: the bot does **`bind(127.0.0.1:48101)`** — Mirai's canonical single-instance lock
port, inherited from the leaked source, not a number you pick by accident. Add the fork-per-attack worker
model, the duration-bounded attack children, and the raw-socket spoofed SYN/ACK flood with hand-built headers
+ checksums, and the attack engine is clearly Mirai-derived.

What was changed — which is why it doesn't *look* like Mirai to a signature:

| | Stock Mirai | This sample |
|---|---|---|
| Single-instance lock | `127.0.0.1:48101` | **`127.0.0.1:48101`** (kept) |
| Attack engine | UDP + raw-socket floods | **kept** (UDP ×3 + spoofed TCP SYN/ACK ×2) |
| C2 protocol | `\x00\x00\x00\x01`+id, XOR config table | **replaced** — bespoke plaintext (below) |
| Scanner / telnet spread | yes | **removed** |
| Persistence | minimal (memory-resident) | **Torii-style multi-init "sysupd"** |

And it's **not Torii** either: real Torii (Avast, 2018) was a **Go** stealth data-exfil RAT with encrypted
comms and **no DDoS**. The only thing shared with Torii is the aggressive persistence — which is exactly what
the AV signature keyed on. Label by capability, not by install strings.

## The bespoke-but-plaintext C2 — and why

The author replaced Mirai's C2 with their own protocol, yet left it entirely in the clear. That's not a
contradiction once you read "bespoke" as *minimal and self-owned*, not *sophisticated*:

- Obfuscating the C2 (Mirai's XOR config table) is mostly theatre — the bot **must** connect to its C2, so any
  sandbox run reveals the address regardless. XOR only beats a lazy `strings`.
- The evasion here is **novelty, not crypto** — 15/74 on a fresh codebase, *with* a plaintext protocol. No
  signatures exist yet, so plaintext costs nothing.
- A plaintext, 3-opcode protocol is **easy to operate** — a trivial C2 server, no key management, no crypto bugs.

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

Note the **two IP fields** — an attack handle (for `0x11` stop) and the actual flood target. (An easy field to
misread from static analysis alone; the lab run pinned it.)

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
libc artefact, flagged here because it's an easy false-positive when you're hunting for a config key.

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
- Single-instance lock: `bind 127.0.0.1:48101` (Mirai heritage)
- Beacon magic: `A1 71 4E 01 02`

**Sample:**

- SHA-256 `4a5a96612e7316586a4c61a4d7dd28dfadf087be9ccfa2c04b06206cca610de7`
  (x86-64 ELF, statically linked, stripped, GCC 4.1.2)

**C2 omitted** — the live infrastructure is still active and under observation.

## Naming

No self-ID, version, or author strings in the binary. Named **`sysupd-booter`** after its persistence artefact
(shape-based). It's **Mirai-lineage by code** (the `48101` lock + the attack engine) but with a bespoke C2, no
scanner, and Torii-style persistence — so a stock family name doesn't fit cleanly ("Mirai" alone understates
the rewrite; "Torii," the AV label, is a capability mislabel). A descriptive name beats a borrowed one.

---

*Static analysis plus a contained lab detonation (isolated, no-egress; the C2 was redirected to a lab sink and
the sample never contacted the real operator). Detection content above is free for defenders to use.*
