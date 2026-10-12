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

// guest_persona.c — personality() гостя: личность PER_LINUX32 изображает транслятор (Р-154).
//
// ★ Зачем и что отвечает — в шапке guest_persona.h (там же всё решение: сперва хозяину как прежде, отказ EINVAL на базе
// PER_LINUX32 — то же без базы, значение гостя помнится здесь, в слове процесса). Здесь — только то, что знает о qemu: сам
// вызов хозяина (musl personality()) и строка в журнал слежки.
//
// Звать из syscall.c (`case TARGET_NR_personality:`, патч 0100): get_errno(guest_persona(arg1)) — ответ того же вида, что у
// personality() хозяина (-1 и errno при отказе; иначе значение).
//
// ⚠️ Журнал — журнал слежки GUEST_PAGE_LOG (guest_pagelog.c), как у личности READ_IMPLIES_EXEC (патч 0098): без переменной
// ни одной лишней команды.

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "guest_pagelog.h"

#include <sys/personality.h>

#define GP_LOG_EMULATED() \
    do { \
        if (guest_plog_on()) { \
            guest_plog("личность PER_LINUX32 изображена: у хозяина нет 32-битного режима"); \
        } \
    } while (0)

#include "guest_persona.h"

static GpState g_gp = GP_STATE_INITIALIZER;

int guest_persona(unsigned long arg)
{
    return gp_personality(&g_gp, arg);
}
