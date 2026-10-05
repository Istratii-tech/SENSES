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
// Changed: 2026-10-04

/* guest_kill.h — журнал сигналов гостя «кто → кому» (GUEST_KILL_LOG, патч 0090;
 * устройство и оговорки — в guest_kill.c).
 *
 * ★ Без GUEST_KILL_LOG ни один вызов не делается: begin смотрит на один int и
 * больше ничего, end — на один флаг. */
#ifndef GUEST_KILL_H
#define GUEST_KILL_H

#include <stdbool.h>

/* Какой вызов (формат цели в строке журнала различается). */
enum {
    GUEST_KILL_KILL = 0,    /* kill(pid, sig): цель — pid, -pgid, 0 или -1 */
    GUEST_KILL_SIGQ,        /* rt_sigqueueinfo(pid, sig, …): как kill */
    GUEST_KILL_TKILL,       /* tkill(tid, sig): в журнале tid дважды (pid цели вызов не знает) */
    GUEST_KILL_TGKILL,      /* tgkill(tgid, tid, sig) */
    GUEST_KILL_TGSIGQ,      /* rt_tgsigqueueinfo(tgid, tid, sig, …): как tgkill */
};

/* Включён ли журнал: 1, если при старте процесса была задана GUEST_KILL_LOG (guest_kill.c). */
extern int guest_kill_on;

typedef struct GuestKill {
    bool on;                /* вызов будет записан (переменная есть, сигнал не 0) */
    int kind;
    int a, b;               /* первый и второй номер — как в вызове */
    int sig;                /* гостевой номер сигнала */
    long long ms;           /* когда гость позвал */
} GuestKill;

void guest_kill_begin_slow(GuestKill *k, int kind, long a, long b, long sig);
void guest_kill_end_slow(GuestKill *k, long ret);

/* ДО передачи вызова хозяину. a — pid/tid/tgid, b — tid (tgkill, rt_tgsigqueueinfo),
 * sig — гостевой номер сигнала. Для kill и tkill b не нужен (0). */
static inline void guest_kill_begin(GuestKill *k, int kind, long a, long b, long sig)
{
    k->on = false;
    if (__builtin_expect(guest_kill_on, 0)) {
        guest_kill_begin_slow(k, kind, a, b, sig);
    }
}

/* ПОСЛЕ ответа хозяина: ret — то, что получит гость (0 или -errno). */
static inline void guest_kill_end(GuestKill *k, long ret)
{
    if (k->on) {
        guest_kill_end_slow(k, ret);
    }
}

#endif
