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
// Changed: 2026-09-23

/* guest_trace.h — трасса гостя на шкале времени хозяина (см. guest_trace.c). */
#ifndef GUEST_TRACE_H
#define GUEST_TRACE_H

/* Открытие: 1 — это файл отметок atrace, в *fd лежит результат. */
int guest_trace_try_open(const char *path, int *fd);

/* После open/openat (патч 0062): поставить переводчик записи на описатель. */
void guest_trace_opened(const char *path, abi_long fd);

/* Идёт ли сейчас запись трассы (дёшево: файл проверяется раз в 200 мс). */
int guest_trace_on(void);

/* Своя отметка: B — начало, E — конец, N — мгновение. */
void guest_trace_mark(char kind, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#endif
