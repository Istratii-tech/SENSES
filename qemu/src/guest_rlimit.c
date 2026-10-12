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
// Changed: 2026-10-12

// guest_rlimit.c — setrlimit() и prlimit64() гостя: подъём предела выше жёсткого предела хозяина прощается (Р-156).
//
// ★ Зачем и что отвечает — в шапке guest_rlimit.h (там же всё решение: сперва хозяину как прежде, отказ EPERM при подъёме жёсткого
// предела — повтор с жёстким пределом хозяина, строка раз на процесс и ресурс). Здесь — только то, что знает о qemu и хозяине: сами вызовы
// хозяина (musl setrlimit()/getrlimit(); prlimit64 — тем же `sys_prlimit64` из syscall.c, его передаёт вызывающий) и строки в журнал.
//
// Звать из syscall.c (патч 0101): `get_errno(guest_setrlimit(resource, rlim.rlim_cur, rlim.rlim_max))` вместо
// `get_errno(setrlimit(resource, &rlim))` и `get_errno(guest_prlimit64(sys_prlimit64, arg1, resource, rnewp, arg4 ? &rold : 0))` вместо
// `get_errno(sys_prlimit64(arg1, resource, rnewp, arg4 ? &rold : 0))` — ответ того же вида, что у вызова хозяина (-1 и errno при отказе;
// иначе 0). RLIMIT_AS, RLIMIT_DATA и RLIMIT_STACK сюда не доходят (их syscall.c отвечает «успех», ничего не ставя, как и прежде).
//
// ⚠️ Строки идут и в stderr (как у прощения mlock, патч 0029: так их видно в журнале службы без включения слежки), и — когда она
// включена (GUEST_PAGE_LOG, guest_pagelog.c) — в журнал слежки (как у личности гостя, патч 0100). Раз на процесс и ресурс.

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "guest_pagelog.h"

#include <sys/resource.h>

// Решение. У него своя `struct host_rlimit64` (то же определение, что в syscall.c; прототипы user-internals.h называют её).
#include "guest_rlimit.h"

static int host_set(void *ctx, int resource, const GrLim *lim)
{
    struct rlimit r;

    (void)ctx;
    r.rlim_cur = lim->rlim_cur;
    r.rlim_max = lim->rlim_max;
    return setrlimit(resource, &r);
}

static int host_get(void *ctx, int resource, GrLim *lim)
{
    struct rlimit r;

    (void)ctx;
    if (getrlimit(resource, &r) != 0) {
        return -1;
    }
    lim->rlim_cur = r.rlim_cur;
    lim->rlim_max = r.rlim_max;
    return 0;
}

// Хозяйское prlimit64 — функция, что передал syscall.c (его sys_prlimit64: то же системное обращение, что и прежде).
typedef struct {
    GuestPrlimit64Fn fn;
} HostPrlimit;

static int host_prlimit(void *ctx, int pid, int resource, const GrLim *new_lim, GrLim *old_lim)
{
    return ((HostPrlimit *)ctx)->fn((pid_t)pid, resource, new_lim, old_lim);
}

static long host_pid(void *ctx)
{
    (void)ctx;
    return (long)getpid();
}

// Число в строку: бесконечность (все единицы) — «∞», остальное — десятичным.
static const char *lim_str(uint64_t v, char *buf, size_t n)
{
    if (v == UINT64_MAX) {
        return "∞";
    }
    snprintf(buf, n, "%llu", (unsigned long long)v);
    return buf;
}

static void host_note(void *ctx, int resource, const GrLim *asked, const GrLim *kept)
{
    char b1[24], b2[24], b3[24], b4[24], line[256];

    (void)ctx;
    snprintf(line, sizeof line, "предел %d поднять выше жёсткого хозяина нельзя (просили %s/%s, оставлено %s/%s) — прощаем",
             resource, lim_str(asked->rlim_cur, b1, sizeof b1), lim_str(asked->rlim_max, b2, sizeof b2),
             lim_str(kept->rlim_cur, b3, sizeof b3), lim_str(kept->rlim_max, b4, sizeof b4));
    fprintf(stderr, "guest: %s\n", line);
    if (guest_plog_on()) {
        guest_plog("%s", line);
    }
}

static const GrHost g_host = { NULL, host_set, host_get, host_prlimit, host_pid, host_note };

static GrState g_gr = GR_STATE_INITIALIZER;

int guest_setrlimit(int resource, uint64_t cur, uint64_t max)
{
    GrLim ask;

    ask.rlim_cur = cur;
    ask.rlim_max = max;
    return gr_setrlimit(&g_gr, &g_host, resource, &ask);
}

int guest_prlimit64(GuestPrlimit64Fn host_prlimit64, int pid, int resource, const struct host_rlimit64 *new_limit,
                    struct host_rlimit64 *old_limit)
{
    HostPrlimit hp;
    GrHost h = g_host;

    hp.fn = host_prlimit64;
    h.ctx = &hp;
    return gr_prlimit(&g_gr, &h, pid, resource, new_limit, old_limit);
}
