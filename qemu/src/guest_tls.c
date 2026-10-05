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

/* guest_tls.c — чтение legacy-слота TLS (0xffff0ff0) по факту обращения.
 *
 * Зачем. Прошивка собрана с `ARCH_ARM_HAVE_TLS_REGISTER := false`: её код берёт
 * указатель TLS из слова по адресу 0xffff0ff0, а не из регистра TPIDRURO.
 * Статически такие места правятся (tools/tls_scan.py — 620 мест в 14 файлах),
 * но НЕ ВСЕ: там, где загрузка константы и чтение по ней не идут подряд,
 * заменить нечего — инструкции нельзя сдвигать, на них могут быть переходы.
 * Осталось 60 таких мест, из них 57 в libGLES_android.so и 3 в libEGL.so, и
 * ровно на них падал SurfaceFlinger: SIGSEGV по адресу 0xc (NULL+12) в
 * libEGL.so+0x4578.
 *
 * ★ Почему нельзя просто «положить значение в слот». Слот один на адресное
 * пространство, а гостевых потоков много, и у каждого свой TLS. В полносистемном
 * эталоне (Э0) это лечилось патчем ядра и запретом SMP; здесь гостевые потоки —
 * это настоящие потоки хозяина, они идут одновременно, и любое общее слово
 * оказалось бы гонкой.
 *
 * Что делаем. Страницу помощников ядра (0xffff0000) закрываем целиком, а чтение
 * из неё перехватываем в обработчике отказа доступа. Обработчик работает В ТОМ
 * ЖЕ ПОТОКЕ, что и упавшая инструкция, поэтому берёт TLS именно этого потока —
 * из cp15.tpidrro_el0, куда его положил set_tls. Это точная семантика, а не
 * приближение.
 *
 * ⚠️ Цена. Каждое такое чтение — отказ доступа хозяина, восстановление
 * состояния и перетрансляция: единицы микросекунд. Для редких мест это
 * незаметно, для горячих точек входа GL — нет. Поэтому статическая правка
 * остаётся первой линией, а это — сеть безопасности и способ идти дальше, не
 * останавливаясь на трамплинах. Если графика окажется медленной ИМЕННО из-за
 * этого (сначала измерить!), горячие места надо будет пропатчить трамплинами.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
// ⚠️ qemu.h ДО user-internals.h: там объявлен TaskState, без него заголовок
// не собирается («unknown type name TaskState»).
#include "qemu.h"
#include "user-internals.h"
// Штатный помощник qemu: он же учитывает «безопасный» режим процессора.
#include "target_cpu.h"

#include "guest_tls.h"

/* Страница помощников ядра и слово с версией — числа ядра, не наши. */
#define KUSER_PAGE     0xffff0000u
#define KUSER_TLS_SLOT 0xffff0ff0u
#define KUSER_VERSION  0xffff0ffcu
#define KUSER_HELPER_VERSION 5

static uint32_t slot_value(CPUARMState *env, uint32_t addr)
{
    switch (addr) {
    case KUSER_TLS_SLOT:
        /*
         * Тот самый указатель TLS — ЭТОГО потока. Берём тем же помощником, что
         * и сам qemu (cpu_get_tls рядом с cpu_set_tls, который его и пишет при
         * системном вызове set_tls): поле называется tpidrro_el[0], а в
         * «безопасном» режиме процессора — вообще другое.
         */
        return (uint32_t)cpu_get_tls(env);
    case KUSER_VERSION:
        return KUSER_HELPER_VERSION;
    default:
        /* Остальная страница у настоящего ядра нулевая. */
        return 0;
    }
}

/*
 * Разбор инструкции чтения слова. Возвращает 1 и заполняет rt/len, если это
 * понятная нам загрузка слова; иначе 0 — тогда гость честно получит SIGSEGV, и
 * мы громко скажем, какую форму не разобрали.
 */
static int decode_load(CPUARMState *env, uint32_t pc, int thumb, int *rt, int *len)
{
    if (!thumb) {
        uint32_t insn;

        if (get_user_u32(insn, pc)) {
            return 0;
        }
        /* cond 010 P U 0 W 1 Rn Rd imm12 — загрузка слова по смещению. */
        if (((insn >> 26) & 3) == 1 && !((insn >> 25) & 1) &&
            !((insn >> 22) & 1) && ((insn >> 20) & 1)) {
            *rt = (insn >> 12) & 0xf;
            *len = 4;
            return *rt != 15;                 /* загрузку в PC не трогаем */
        }
        return 0;
    }

    uint16_t hw1;

    if (get_user_u16(hw1, pc)) {
        return 0;
    }
    /* T1: ldr Rt,[Rn,#imm5*4] */
    if ((hw1 & 0xf800) == 0x6800) {
        *rt = hw1 & 7;
        *len = 2;
        return 1;
    }
    /* T2: ldr Rt,[SP,#imm8*4] — база не наша, но форма возможна. */
    if ((hw1 & 0xf800) == 0x9800) {
        *rt = (hw1 >> 8) & 7;
        *len = 2;
        return 1;
    }
    /* T3/T4: ldr.w Rt,[Rn,#imm] — 32-битная инструкция. */
    if ((hw1 & 0xfff0) == 0xf8d0 || (hw1 & 0xfff0) == 0xf850) {
        uint16_t hw2;

        if (get_user_u16(hw2, pc + 2)) {
            return 0;
        }
        *rt = (hw2 >> 12) & 0xf;
        *len = 4;
        return *rt != 15;
    }
    return 0;
}

bool guest_tls_fault(CPUState *cs, uint64_t addr, int is_load, uintptr_t ra)
{
    if (!is_load || (addr & ~(uint64_t)0xfff) != KUSER_PAGE) {
        return false;
    }

    CPUARMState *env = cpu_env(cs);
    int rt = 0, len = 0;

    /*
     * Состояние гостя восстанавливаем ДО разбора: до этого env->regs[15] ещё
     * не соответствует упавшей инструкции.
     */
    cpu_restore_state(cs, ra);

    uint32_t pc = env->regs[15];
    int thumb = (env->thumb != 0);

    if (!decode_load(env, pc, thumb, &rt, &len)) {
        static int told;

        if (!told) {
            told = 1;
            fprintf(stderr, "guest_tls: не разобрал чтение слота по адресу "
                    "0x%08x (pc=0x%08x, %s) — гость получит SIGSEGV\\n",
                    (unsigned)addr, pc, thumb ? "thumb" : "arm");
        }
        return false;
    }

    env->regs[rt] = slot_value(env, (uint32_t)addr);
    env->regs[15] = pc + len;
    return true;
}
