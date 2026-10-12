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

/* guest_persona.h — личность гостя (personality), которую изображает транслятор (Р-154): решение, без qemu.
 *
 * ★★ Беда Р-154 (телефон без 32-битного режима процессора). Библиотека C Android 6.0 и новее при старте КАЖДОЙ программы
 * зовёт personality(PER_LINUX32) и при отказе завершается кодом 1 с единственной строкой «error setting PER_LINUX32
 * personality: Invalid argument». Транслятор передавал вызов ХОЗЯИНУ (`get_errno(personality(arg1))`), а ядро arm64 без
 * поддержки AArch32 на личность с базой PER_LINUX32 отвечает EINVAL (arch/arm64/kernel/sys.c: база PER_LINUX32 и нет
 * system_supports_32bit_el0() → -EINVAL). Первая же программа — servicemanager — уходила с кодом 1, и контейнеры 6.0, 6.0.1 и 7.1.x
 * не поднимались вовсе («служба servicemanager вышла (код 1)»). У телефона с 32-битным режимом ядро соглашается — там всё
 * работало; 4.x и 5.x вызова не делают.
 *
 * ★ Что делает решение. Личность гостя — НЕ личность процесса транслятора: хозяйская личность гостю ничего не даёт (гостевой
 * код исполняет сам транслятор, адресное пространство и права страниц гостя — его дело; патч 0098 от неё тоже не зависит), а
 * 32-битный режим хозяина гостю не нужен вовсе. Поэтому, когда хозяин не принимает базу PER_LINUX32, транслятор
 * принимает её за него и помнит значение, которое гость считает своей личностью:
 *   1. СПЕРВА ВСЁ КАК ПРЕЖДЕ: вызов (то же слово, что дал гость) уходит хозяину. Принял — ответ хозяина гостю как есть, пока
 *      личность не изображалась ни разу (телефон с 32-битным режимом так и остаётся: ни состояния, ни лишних вызовов, ответы
 *      побайтно прежние);
 *   2. отказ EINVAL и база установки — PER_LINUX32 (`arg & PER_MASK == 8`; так же PER_LINUX32_3GB: база та же): хозяину то же
 *      без базы (`arg & ~PER_MASK` — флаги вроде ADDR_NO_RANDOMIZE и READ_IMPLIES_EXEC остаются хозяину, как просил гость).
 *      Принял — гостю успех: значение гостя запоминается как `arg`, а в ответ уходит ПРЕЖНЕЕ значение гостя;
 *   3. любой иной отказ (не EINVAL, или база не PER_LINUX32, или отказала и повторная установка) — ошибка гостю, как прежде
 *      (при отказе повтора — прежняя EINVAL, а не вторая);
 *   4. когда личность уже изображается: запрос `0xffffffff` отвечает значением гостя, установка, которую хозяин принял, тоже
 *      возвращает прежнее значение гостя и запоминает новое.
 *
 * ★ Первое значение гостя — личность хозяина в миг первой изображённой установки. Её даёт сам ответ повторной установки (ядро
 * отвечает прежним значением): это ровно то, что показал бы personality(0xffffffff) за миг до неё, но без лишнего вызова — к
 * хозяину уходят только слова, которые гость и сам назвал (или они же без базы), а не новое слово, о котором песочница
 * приложения Android, быть может, судит по доводу.
 *
 * ★ Состояние — одно слово на процесс: младшие 32 бита — значение гостя, бит 32 (GP_EMUL) — «изображаем». Ноль — не
 * изображали ничего. Читают и пишут атомарно, БЕЗ замка: гостевые потоки делят слово, а замок, взятый другим потоком в миг
 * fork, остался бы у потомка навсегда. fork копирует слово (как ядро наследует личность потомку); execve заводит новый процесс
 * транслятора с нулём — как у ядра ARM, которое при exec ставит базу PER_LINUX (флаги остаются, а они — у хозяина).
 *
 * ★ Строка в отладочный журнал транслятора — ОДНА на процесс (по номеру процесса: потомок fork пишет свою), через GP_LOG_EMULATED
 * (guest_persona.c: журнал слежки GUEST_PAGE_LOG; без неё — ни одной лишней команды): «личность PER_LINUX32 изображена: у хозяина
 * нет 32-битного режима».
 *
 * ⚠️ Предел: личность у ядра — свойство ПОТОКА, здесь — процесса. Программы Android ставят её один раз при старте, до потоков.
 * ⚠️ Личность гостя на гостевые страницы и права НЕ действует (кроме READ_IMPLIES_EXEC, который патч 0098 берёт из заголовков
 * программы, а не из этого вызова): здесь она только отвечается и передаётся хозяину в его части.
 *
 * ★ Файл не зависит от qemu: только libc. Вызов хозяина и журнал — через GP_* (по умолчанию personality(), без журнала), поэтому
 * решение гоняется хостовым cc на Маке с заглушкой хозяина (native/test/test_persona.c). Всё — static inline.
 */
#ifndef GUEST_PERSONA_H
#define GUEST_PERSONA_H

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#define GP_PER_MASK     0x000000ffu     /* PER_MASK: база личности — младший байт */
#define GP_PER_LINUX32  0x00000008u     /* PER_LINUX32 (PER_LINUX32_3GB — та же база и флаг ADDR_LIMIT_3GB) */
#define GP_QUERY        0xffffffffu     /* personality(0xffffffff): только спросить */
#define GP_EMUL         (1ull << 32)    /* в слове состояния: личность изображается; младшие 32 бита — значение гостя */

/* Вызов хозяина: int personality(unsigned long) — -1 и errno при отказе, иначе прежнее значение хозяина. */
#ifndef GP_HOST
#include <sys/personality.h>
#define GP_HOST(arg) personality(arg)
#endif
/* Строка в журнал: личность изображена (зовётся не чаще раза на процесс). */
#ifndef GP_LOG_EMULATED
#define GP_LOG_EMULATED() ((void)0)
#endif
/* Номер процесса: «раз на процесс» для строки журнала. */
#ifndef GP_PID
#define GP_PID() ((long)getpid())
#endif

typedef struct {
    uint64_t word;          /* 0 — не изображали; иначе GP_EMUL | значение гостя */
    long logged_pid;        /* процесс, в котором строка уже записана (0 — нигде) */
} GpState;

#define GP_STATE_INITIALIZER { 0, 0 }

/* personality() гостя: ответ как у вызова хозяина — -1 и errno при отказе, иначе значение (прежнее значение гостя). raw —
 * довод гостя как есть (слово гостя, расширенное знаком до unsigned long, как раньше при `personality(arg1)`): хозяину уходит
 * оно же; решает младшее слово — ядро берёт из довода unsigned int, так и мы. */
static inline int gp_personality(GpState *s, unsigned long raw)
{
    uint32_t a = (uint32_t)raw;
    int r = GP_HOST(raw);                           /* ★ сперва — как прежде */

    if (r >= 0) {
        uint64_t w = __atomic_load_n(&s->word, __ATOMIC_ACQUIRE);

        if (!(w & GP_EMUL)) {
            return r;                               /* не изображали: ответ хозяина — ровно как прежде */
        }
        /* Изображаем: хозяин принял и этот довод (запрос или установка), но «прежнее значение» — гостя. */
        if (a != GP_QUERY) {
            w = __atomic_exchange_n(&s->word, (uint64_t)a | GP_EMUL, __ATOMIC_ACQ_REL);
        }
        return (int)(uint32_t)w;
    }

    int e = errno;                                  /* ответ хозяина, как он был: его вернём при любом ином отказе */

    if (e == EINVAL && (a & GP_PER_MASK) == GP_PER_LINUX32) {
        /* У хозяина нет 32-битного режима: то же слово без базы — флаги остаются хозяину. */
        int r2 = GP_HOST((unsigned long)(a & ~GP_PER_MASK));

        if (r2 >= 0) {
            uint64_t w = __atomic_exchange_n(&s->word, (uint64_t)a | GP_EMUL, __ATOMIC_ACQ_REL);
            long pid = GP_PID();

            if (__atomic_exchange_n(&s->logged_pid, pid, __ATOMIC_RELAXED) != pid) {
                GP_LOG_EMULATED();
            }
            /* Прежнее значение гостя: своё, если уже изображали; иначе — прежнее значение хозяина (его ответ r2). */
            return (w & GP_EMUL) ? (int)(uint32_t)w : r2;
        }
    }
    errno = e;
    return -1;
}

#endif /* GUEST_PERSONA_H */
