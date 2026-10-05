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
// Changed: 2026-10-05

/* guest_alarm.h — точки входа /dev/alarm для linux-user (Р-120). Звать их по общему образцу guest_input.h
 * из guest_binder_try_open / guest_binder_ioctl / guest_binder_close. */
#ifndef GUEST_ALARM_H
#define GUEST_ALARM_H

int guest_alarm_try_open(const char *path, int *fd);
int guest_alarm_ioctl(int fd, unsigned long req, abi_ulong arg, abi_long *ret);
void guest_alarm_close(int fd);

#endif
