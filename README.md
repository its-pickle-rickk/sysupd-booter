# `sysupd` — a Linux DDoS booter wearing Torii's clothes

**TL;DR.** A bespoke, C-written Linux **DDoS booter** caught in a honeypot. MalwareBazaar labels it
**Torii** — it isn't. Classic Torii (Avast, 2018) was a *Go* stealth-exfil RAT with **no DDoS**. This sample
is a Mirai-class flooder (UDP + raw-socket spoofed TCP SYN/ACK) that merely *borrows* Torii's aggressive
multi-init **"sysupd"** persistence — which is almost certainly why the AV signature misfires. Detection was
low (15/74) at capture. Shape-labelled **`sysupd-booter`**.

Everything below is from static analysis of the captured binary. Nothing was executed.

---

## Not Torii — why the label is wrong

| | Classic Torii (2018) | This sample |
|---|---|---|
| Language | Go | **C** (GCC 4.1.2, static) |
| C2 comms | multi-layer encrypted | **plaintext** bespoke binary protocol |
| Purpose | stealth data-exfil RAT, modular | **pure DDoS booter** |
| DDoS | none | UDP + raw-socket spoofed TCP floods |
| Shared | — | the **"sysupd" multi-init persistence** |

The *only* real overlap is the persistence suite. That's the lesson: an AV signature keyed on persistence
strings will happily paste a famous family name onto an unrelated bot. Label by **capability**, not by
install artefacts.

---

## The registration beacon (the fun part)

On connect the bot sends a fixed-shape beacon:

```
A1 71 4E 01 02 | <nproc> | <hostlen> | <hostname…>
   5-byte magic   1 byte     1 byte     N bytes
```

The byte right after the 5-byte magic is the infected host's **CPU count**
(`sysconf(_SC_NPROCESSORS_ONLN)`). The operator harvests per-bot core counts *at check-in* — a crude way to
gauge each bot's flood capacity before tasking it. Uncommon, and a clean network fingerprint.

---

## Protocol

Framing (server → bot): `[type u8][length u16 BE][body]`, length capped at 2048, **length 0 = keepalive**.
Just three opcodes:

- **`0x01` ping** → bot replies `02 00 00` (pong). The only keepalive; the bot never self-initiates one.
- **`0x10` launch attack** → body = target IPv4 + duration (clamped ≤ 3600 s) + port + method (1–5) +
  optional payload (≤ 1024 B). The bot `fork()`s a child per attack and tracks up to **256 concurrent
  attacks** in a table keyed by target IP (killing any prior child on the same target first).
- **`0x11` stop** → by target IP; `0xFFFFFFFF` = stop everything. Classic booter ergonomics.

---

## Attack methods (5)

- **Methods 1–3 — UDP flood.** `SOCK_DGRAM`, 1 MB send buffer, fixed or per-packet-random destination
  port, payload either attacker-supplied or ~1400 B of randomness.
- **Methods 4–5 — raw-socket TCP flood.** `SOCK_RAW` + `IP_HDRINCL`, hand-built IP/TCP headers, **spoofed
  random source IP** per packet, randomised sequence numbers, internet checksums computed in-binary
  (SYN / ACK variants).

Strictly L3/L4 volumetric. **No HTTP/L7 method.**

## What it does *not* do

No scanner/propagation, no proxy/relay, no data-exfil command, no shell/exec over C2, no loader or
self-update. `execve` appears **only** in the startup persistence installer, never in the command loop.
It is a single-purpose flooder.

---

## Persistence

Masquerades as **`sysupd`** / **`.sysupd`** ("system update") and installs itself via *every* mechanism it
can, run all at once at first launch:

- systemd unit (`sysupd.service`)
- SysV `init.d` (`/etc/init.d/sysupd` + `S90sysupd`)
- OpenRC
- cron: `/etc/cron.d/sysupd`, a `@reboot` crontab line, and a `*/5 * * * *` respawn
- `/etc/profile.d/sysupd.sh`, `~/.bashrc`, `~/.profile`
- XDG autostart `.desktop`
- `rc.local`

It also opens `/dev/watchdog` (IoT anti-reboot). Respawn-shell pidfile: `/tmp/.ash.pid`.

---

## Analyst note — one red herring

A 128-byte high-entropy blob in `.data` looks like an embedded key/config. It's **glibc's `randtbl` PRNG
state** (`TYPE_3` marker + 31 seed words). Don't waste time on it.

---

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

- Names / paths: `sysupd`, `.sysupd`, `/etc/init.d/sysupd`, `/etc/cron.d/sysupd`,
  `/etc/profile.d/sysupd.sh`, `/tmp/.ash.pid`
- Beacon magic: `A1 71 4E 01 02`

**Sample:**

- SHA-256 `4a5a96612e7316586a4c61a4d7dd28dfadf087be9ccfa2c04b06206cca610de7`
  (x86-64 ELF, statically linked, stripped, GCC 4.1.2)

**C2 omitted** — the live infrastructure is still active and under observation.

---

## Naming

No self-ID, version, or author strings in the binary. Named **`sysupd-booter`** after its persistence
artefact (shape-based). No primary source attributes these TTPs to a named family, and the single AV label
present ("Torii") is contradicted by the capability set — so it gets a descriptive name, not a borrowed one.

---

*Static analysis only; the sample was never run. Published for defenders — detection content above is free to
use.*
