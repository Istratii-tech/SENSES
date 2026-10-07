# ISTRATII_TECH SENSES — QEMU source distribution

[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/istratii_tech ) [![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/5HWuRWdKwt)

This repository exists to satisfy the **GNU GPL version 2** obligations that
come with distributing a modified QEMU.

The `ISTRATII_TECH SENSES` Android application runs an ARM32 Android system on
an ARM64 phone by translating its individual processes — there is no guest
kernel. The translator is a modified QEMU, and **that is what this repository
contains**: our patches, our added source files, and the script that builds it.

MADE WITH CLAUDE CODE

Repository: `https://github.com/Istratii-tech/Senses`.
Requests for sources: issues of this repository
(`https://github.com/Istratii-tech/Senses/issues`) or `https://t.me/istratii_tech`.

## What is *not* here

* **No firmware.** The application ships none, and neither does this
  repository. The user supplies their own archive; the application unpacks it
  on the device.
* **No links to download firmware.** Deliberately.
* **Not the application's own source.** The application is a separate program:
  it starts QEMU as a separate process and talks to it over sockets, arguments
  and files. No QEMU code is loaded into its process. See `NOTICE`, section 4.

## Your firmware

You are responsible for having the right to use the firmware you supply, and to
have a modified copy of it made on your own device. The application changes
that copy on the device (patched code, re-signed packages with a key generated
on the device, removed vendor modules) and runs a local TLS proxy whose root
certificate is generated on the device and added to the trust store of the copy.
Nothing is sent anywhere. Details: `NOTICE`, section 5.

## Building

Requires an **aarch64 Linux** host with root. The script mounts `/proc` and
`/dev`, unpacks a minimal Alpine root into a chroot and builds there — Alpine
is used because it ships a static `glib`, which QEMU needs and most other
distributions do not provide.

```bash
sudo ./qemu/build-android.sh
```

Output: `qemu/build/qemu-arm-android` — a fully static aarch64 binary. It has
to be static: Android's linker will not load a foreign dynamic loader, so a
dynamically linked build simply would not start on the phone.

The build is **pinned**; the script refuses to continue if a download does not
match:

| input | pinned to | sha256 |
|---|---|---|
| QEMU source | `qemu-8.2.4.tar.xz` (132694904 bytes), from `https://download.qemu.org/` | `ecf5537feab92641b99d7482f551f2195d3a5bd34acef9d52bfbff353a607397` |
| Alpine root | `alpine-minirootfs-3.20.10-aarch64.tar.gz` (branch `v3.20`) | `61ac877fdbcee6914731bc22a4ed5668ea3470f201f97a7078931c48b71bbeec` |

The packages installed into that root are the ones Alpine `v3.20` serves on the
day of the build, so the script records exactly what it used. When it finishes
it writes `qemu/build/BUILD-MANIFEST.txt`: the QEMU version and archive sum, the
Alpine root and its sum, the output of `apk info -v` in the chroot, the compiler
version, the number of patches with the sha256 of each, and the sha256 of the
resulting binary. Keep that file together with the binary you distribute.

To build another QEMU version or another Alpine root you must give its checksum
as well (`VER`, `QEMU_SHA256`, `BR`, `ALPINE_ROOTFS`, `ALPINE_SHA256`); the
patches in this repository are written for QEMU 8.2.4.

## Layout

```
COPYING                 GNU GPL version 2, full text
NOTICE                  what is third-party, under which licence, where its source is
licenses/               licence texts of the other third-party components
qemu/build-android.sh   downloads upstream QEMU, applies patches, builds
qemu/patches/           94 patches against QEMU 8.2.4
qemu/src/               39 files we added to linux-user/, GPL-2.0-or-later
```

Each patch starts with a description of the symptom it exists for — that is
usually more useful than the diff itself.

## Licences

* **QEMU and our changes to it** — GNU GPL version 2 or later. `COPYING`.
  QEMU's own statement on the licences of its files: `licenses/QEMU-LICENSE.txt`.
* **Libraries linked statically into the binary** — GLib and GNU gettext
  (LGPL-2.1 or later, `licenses/LGPL-2.1.txt`), musl libc (MIT,
  `licenses/musl-COPYRIGHT.txt`), zlib (`licenses/zlib.txt`), libgcc (GPL-3.0
  or later with the GCC Runtime Library Exception). Versions and where to get
  their sources: `NOTICE`, section 1.3.
* **Bouncy Castle 1.70** — Bouncy Castle Licence. `licenses/BouncyCastle.txt`.
* **Kotlin standard library and JetBrains annotations** — Apache License 2.0.
  `licenses/Apache-2.0.txt`.
* **Android Open Source Project headers** — Apache License 2.0.
  `licenses/Apache-2.0.txt`.

Modification notices required by GPLv2 §2(a) are written into each changed QEMU
file **at build time**, not in the patches themselves: a notice inside a patch
would shift the start of the file and break the context of the next patch.

## Trademarks

Android is a trademark of Google LLC. All other product names, logos and brands
are property of their respective owners. This project is independent and is not
affiliated with, endorsed by, or sponsored by any of them.

## Contact

`https://github.com/Istratii-tech/Senses` (issues: `https://github.com/Istratii-tech/Senses/issues`),
`https://t.me/istratii_tech`
