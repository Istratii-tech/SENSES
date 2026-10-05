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

/* guest_fs.h — подмена сведений о разделе для гостя. */
#ifndef GUEST_FS_H
#define GUEST_FS_H

struct statfs;
void guest_fs_fake(const char *path, struct statfs *st);
int guest_fs_try_open(const char *path, int *fd);

#endif
