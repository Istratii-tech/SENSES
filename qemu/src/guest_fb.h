// SPDX-License-Identifier: GPL-2.0-or-later
//
// ★ PART OF A MODIFIED QEMU. This file was ADDED to the QEMU sources
// (linux-user) by the ISTRATII_TECH SENSES project and is compiled into
// qemu-arm, therefore it is distributed under the terms of the GNU General
// Public License version 2 or (at your option) any later version.
//
// Full licence text: see COPYING in the project root.
// Everything changed in QEMU is listed in NOTICE.
//
// Copyright (c) 2026 istratiitech <https://github.com/istratiitech>
// Changed: 2026-08-29

/* guest_fb.h — ioctl кадрового буфера гостя. */
#ifndef GUEST_FB_H
#define GUEST_FB_H

int guest_fb_ioctl(int fd, unsigned long req, abi_ulong arg, abi_long *ret);
void guest_fb_forget(int fd);

#endif
