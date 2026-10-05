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

/* guest_procpath.h — разбор гостевого пути /proc: чей это процесс и что за хвост (Р-116).
 *
 * ★★ Зачем. Транслятор подменяет записи СВОЕГО процесса — maps, smaps, stat, auxv,
 * cmdline, exe (qemu, is_proc_myself), список fd (guest_proc.c), oom_adj (guest_oom.c) —
 * и узнавал их только по путям /proc/self/<X> и /proc/<свой pid>/<X>. Ядро же отдаёт то же
 * самое и по /proc/<pid>/task/<tid>/<X> и /proc/thread-self/<X>; такой путь уходил к
 * хозяину, и гость видел карту памяти ХОЗЯИНА. bionic 6.0 ищет стек главного потока строкой
 * « [stack]» именно в /proc/self/task/<getpid()>/maps и находил чужой стек — зигота и
 * dex2oat падали в ART (№18, №19, 6.0.1):
 *
 *   art/runtime/thread.cc:712] Check failed: &stack_variable > reinterpret_cast<void*>(tlsPtr_.stack_end)
 *   (&stack_variable=0x407ffab0, …stack_end=0xea3d4000)
 *
 * Здесь — ОДНО решение «чей путь» для всех подмен: /proc/<кто>/[task/<tid>/]<хвост>, где кто —
 * self, thread-self или номер. Номер — как у ядра (fs/proc: name_to_int): только цифры, без
 * ведущего нуля, не больше INT_MAX; иначе это не каталог процесса. Принадлежит ли поток tid
 * процессу pid, решает вызывающий (у хозяина — по /proc/<pid>/task/<tid>): здесь только разбор,
 * без системных вызовов.
 *
 * ★ Файл не зависит от qemu: только libc. Гоняется хостовым cc на Маке
 * (native/test/test_procpath.c). Всё — static inline.
 */
#ifndef GUEST_PROCPATH_H
#define GUEST_PROCPATH_H

#include <stddef.h>
#include <string.h>

typedef struct {
    long pid;           /* процесс (группа потоков); у self и thread-self — наш */
    long tid;           /* поток: из task/<tid>/ или наш у thread-self; 0 — путь без потока */
    int mine;           /* путь о НАШЕМ процессе (self, thread-self, наш номер) */
    const char *rest;   /* хвост после «/proc/<кто>/[task/<tid>/]», не пуст */
} GuestProcPath;

/* Номер процесса или потока, как у ядра: цифры до «/» или конца, без ведущего нуля, ≤ INT_MAX. */
static inline const char *guest_proc_num(const char *s, long *v)
{
    long n = 0;
    const char *p = s;

    if (*p < '1' || *p > '9') {
        return NULL;
    }
    for (; *p >= '0' && *p <= '9'; p++) {
        n = n * 10 + (*p - '0');
        if (n > 0x7fffffffL) {
            return NULL;
        }
    }
    if (*p != '/' && *p != '\0') {
        return NULL;
    }
    *v = n;
    return p;
}

/*
 * 1 — путь вида /proc/<self|thread-self|номер>/[task/<номер>/]<хвост> с непустым хвостом;
 * поля out заполнены. 0 — иное. mypid и mytid — наши процесс и поток (для self и thread-self).
 * ⚠️ После thread-self вставки task/<tid>/ нет (у ядра там её нет): «task/…» — просто хвост.
 */
static inline int guest_proc_path(const char *p, long mypid, long mytid, GuestProcPath *out)
{
    const char *s;

    if (p == NULL || strncmp(p, "/proc/", 6) != 0) {
        return 0;
    }
    p += 6;
    out->tid = 0;
    if (strncmp(p, "self/", 5) == 0) {
        out->pid = mypid;
        out->mine = 1;
        p += 5;
    } else if (strncmp(p, "thread-self/", 12) == 0) {
        out->pid = mypid;
        out->tid = mytid;
        out->mine = 1;
        out->rest = p + 12;
        return *out->rest != '\0';
    } else {
        s = guest_proc_num(p, &out->pid);
        if (s == NULL || *s != '/') {
            return 0;
        }
        out->mine = out->pid == mypid;
        p = s + 1;
    }
    if (strncmp(p, "task/", 5) == 0) {
        s = guest_proc_num(p + 5, &out->tid);
        if (s != NULL && *s == '/') {
            p = s + 1;
        } else {
            out->tid = 0;               /* «task», «task/<номер>» без хвоста, мусор — сам хвост */
        }
    }
    out->rest = p;
    return *p != '\0';
}

#endif /* GUEST_PROCPATH_H */
