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
// Changed: 2026-08-29 … 2026-10-09

/* guest_binder.h — точки входа шима /dev/binder для linux-user. */
#ifndef GUEST_BINDER_H
#define GUEST_BINDER_H

/* ★ syscall.c знает только этот заголовок: трасса (0062) — через него же. */
#include "guest_trace.h"
/* ★ Р-130: и ashmem — do_mmap зовёт guest_ashmem_mmap_prep (патч 0097), отдельный include в syscall.c не нужен. */
#include "guest_ashmem.h"

int guest_binder_try_open(const char *path, int flags, int *fd);
int guest_binder_owns(int fd);
int guest_binder_ioctl(int fd, unsigned long req, abi_ulong arg, abi_long *ret);
int guest_binder_mmap(int fd, abi_ulong len, abi_ulong *addr);
void guest_binder_close(int fd);

#endif
