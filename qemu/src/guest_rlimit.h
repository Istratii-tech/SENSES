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

/* guest_rlimit.h — подъём предела ресурса гостем выше жёсткого предела хозяина: решение, без qemu (Р-156).
 *
 * ★★ Беда Р-156 (телефон без 32-битного режима процессора, Android 16; прошивка 2.3.5 с `--rlimit` memlock). system_server этой
 * прошивки стартует с доводом `--rlimit=8,67108864,67108864` — RLIMIT_MEMLOCK, мягкий = жёсткий = 64 МБ. Dalvik при forkSystemServer
 * зовёт setrlimit(8, {64 МБ, 64 МБ}), а у процесса приложения на этом телефоне предел заблокированной памяти — 65536/65536 (жёсткий
 * тоже): поднять жёсткий предел выше текущего без CAP_SYS_RESOURCE ядро не даёт, EPERM. Отказ → «cannot setrlimit(): Operation not
 * permitted» → dvmAbort() → «Zygote Exit zygote because system server has terminated»: system_server умирает за 16 с. На телефоне с
 * Android 9 жёсткий предел приложения выше, и тот же контейнер шёл до экрана; прошивка 2.3.3 без `--rlimit` грузится и на этом телефоне.
 *
 * ★ Что делает решение — тот же класс прощения, что у mlock (патч 0029) и setpriority (патч 0023): предел ресурса гостя — не тот предел,
 * который нужен самому гостю. Dalvik ставит memlock 64 МБ, чтобы потом лочить образы dex; а отказ самого mlock мы и так прощаем (0029).
 * Поэтому отказ «нельзя поднять жёсткий предел» гостю незачем показывать:
 *   1. СПЕРВА ВСЁ КАК ПРЕЖДЕ: вызов (те же числа, тот же ресурс) уходит хозяину. Принял — ответ хозяина гостю как есть, ни одного
 *      лишнего вызова (телефон, где жёсткий предел выше, — побайтно прежний);
 *   2. отказ EPERM и ЖЁСТКИЙ предел гостя больше текущего жёсткого предела хозяина по этому ресурсу (его читаем уже после отказа:
 *      getrlimit — у setrlimit, prlimit64 без нового предела — у prlimit64): повтор хозяину с rlim_max = жёсткий хозяина и
 *      rlim_cur = min(просимый мягкий, жёсткий хозяина). Повтор удался — гостю 0 (у prlimit64 с указателем на прежние значения —
 *      прежние значения из ПОВТОРА, как дало бы ядро: «до этой установки»); не удался — гостю ИСХОДНАЯ ошибка;
 *   3. любой иной отказ — гостю как прежде и без повтора: EINVAL (мягкий больше жёсткого и тому подобное, до проверки прав его даёт
 *      ядро), EPERM без подъёма жёсткого (там отказал не предел: чужой процесс, SELinux, nr_open у NOFILE), EFAULT, ESRCH и прочее.
 *
 * ★ prlimit64 — ТОЛЬКО для себя: pid 0 или свой номер (гость видит номера хозяина — qemu-user номеров не подменяет). Чужой процесс
 * или отрицательное число — как прежде, без повтора: решать за чужой процесс, какой предел ему оставить, нечем.
 *
 * ★ RLIMIT_AS, RLIMIT_DATA и RLIMIT_STACK сюда не доходят: их qemu уже сам отвечает гостю «успех», ничего не ставя (syscall.c: пределы
 * памяти хозяина были бы и пределами самого транслятора). Решение их не знает и не должно знать.
 *
 * ★ Что гость прочтёт потом getrlimit — НАСТОЯЩИЕ значения хозяина (65536/65536 при повторе из примера выше), не обещанные. Изображать
 * обещанное значило бы вести второе состояние на процесс (и на потомков fork, и обнулять при exec), а гость, получивший 0, полагается
 * на предел ровно настолько, насколько он нужен ему — Dalvik после setrlimit предела не читает, а отказ mlock под ним мы прощаем (0029).
 * Настоящие значения честнее: программа, спросившая предел, увидит, что реально может.
 *
 * ★ Строка в отладочный журнал — ОДНА на процесс и ресурс (по номеру процесса: потомок fork, унаследовавший слова состояния, пишет свою):
 * «предел <номер> поднять выше жёсткого хозяина нельзя (просили <мягкий>/<жёсткий>, оставлено <мягкий>/<жёсткий>) — прощаем». Состояние —
 * по слову на ресурс, атомарно, БЕЗ замка (замок, взятый потоком в миг fork, остался бы у потомка навсегда). Строку пишет guest_rlimit.c.
 *
 * ★ Файл не зависит от qemu: только libc (errno, stdint). Все вызовы хозяина (setrlimit, getrlimit, prlimit64), номер процесса и строка
 * в журнал — через таблицу GrHost с указателями на функции, поэтому решение гоняется хостовым cc на Маке с заглушками хозяина
 * (native/test/test_rlimit.c). Всё — static inline.
 */
#ifndef GUEST_RLIMIT_H
#define GUEST_RLIMIT_H

#include <errno.h>
#include <stdint.h>

/* Предел как его принимает и отдаёт ядро (struct rlimit64: два слова по 64 бита). Имя и раскладка — те же, что у `struct host_rlimit64` в
 * syscall.c (там — для sys_prlimit64): разные единицы трансляции, одинаковое определение. Бесконечность — все единицы (RLIM_INFINITY). */
struct host_rlimit64 {
    uint64_t rlim_cur;
    uint64_t rlim_max;
};
typedef struct host_rlimit64 GrLim;

#define GR_NRES 32      /* ресурсов ядро знает 16 (RLIM_NLIMITS); с запасом. Номер вне 0…31 — ядро отвечает EINVAL, прощать нечего. */

/* Таблица вызовов хозяина. Все функции — как у libc/ядра: 0 при успехе, -1 и errno при отказе. */
typedef struct {
    void *ctx;
    /* setrlimit(resource, lim) хозяина. */
    int (*set)(void *ctx, int resource, const GrLim *lim);
    /* getrlimit(resource, lim) хозяина. */
    int (*get)(void *ctx, int resource, GrLim *lim);
    /* prlimit64(pid, resource, new_lim или NULL, old_lim или NULL) хозяина (то же системное обращение, что у sys_prlimit64 в syscall.c). */
    int (*prlimit)(void *ctx, int pid, int resource, const GrLim *new_lim, GrLim *old_lim);
    /* Номер своего процесса (звать только когда он нужен: на пути отказа). */
    long (*pid)(void *ctx);
    /* Строка в журнал: прощено. asked — что просил гость, kept — что оставлено хозяину (зовётся не чаще раза на процесс и ресурс). */
    void (*note)(void *ctx, int resource, const GrLim *asked, const GrLim *kept);
} GrHost;

typedef struct {
    long logged_pid[GR_NRES];   /* по ресурсам: процесс, в котором строка уже записана (0 — нигде) */
} GrState;

#define GR_STATE_INITIALIZER { { 0 } }

/* Годна ли сама просьба к прощению: ресурс в пределах таблицы и мягкий не больше жёсткого (иначе ядро ответило бы EINVAL, а не EPERM, и
 * это уже не наш случай). Хозяина не спрашивает. */
static inline int gr_askable(int resource, const GrLim *ask)
{
    return resource >= 0 && resource < GR_NRES && ask->rlim_cur <= ask->rlim_max;
}

/* ЖЁСТКИЙ предел гостя больше жёсткого предела хозяина — отказ был именно из-за подъёма. */
static inline int gr_above(const GrLim *ask, const GrLim *have)
{
    return ask->rlim_max > have->rlim_max;
}

/* Повтор: жёсткий — хозяина, мягкий — просимый, но не выше жёсткого хозяина. */
static inline void gr_retry_lim(const GrLim *ask, const GrLim *have, GrLim *retry)
{
    retry->rlim_max = have->rlim_max;
    retry->rlim_cur = ask->rlim_cur < have->rlim_max ? ask->rlim_cur : have->rlim_max;
}

/* Строка — раз на процесс и ресурс. Ресурс уже проверен gr_askable (в пределах таблицы). */
static inline void gr_note_once(GrState *s, const GrHost *h, int resource, const GrLim *ask, const GrLim *kept)
{
    long pid = h->pid(h->ctx);

    if (__atomic_exchange_n(&s->logged_pid[resource], pid, __ATOMIC_RELAXED) != pid) {
        h->note(h->ctx, resource, ask, kept);
    }
}

/* setrlimit() гостя (для ресурсов, которые qemu передаёт хозяину): ответ как у вызова хозяина — 0, либо -1 и errno. */
static inline int gr_setrlimit(GrState *s, const GrHost *h, int resource, const GrLim *ask)
{
    GrLim have, retry;
    int e;

    if (h->set(h->ctx, resource, ask) == 0) {              /* ★ сперва — как прежде */
        return 0;
    }
    e = errno;                                              /* ответ хозяина, как он был: его вернём при любом ином исходе */
    if (e == EPERM && gr_askable(resource, ask) && h->get(h->ctx, resource, &have) == 0 && gr_above(ask, &have)) {
        gr_retry_lim(ask, &have, &retry);
        if (h->set(h->ctx, resource, &retry) == 0) {
            gr_note_once(s, h, resource, ask, &retry);
            return 0;
        }
    }
    errno = e;
    return -1;
}

/* prlimit64() гостя (ask — новый предел или NULL, old — куда прежний или NULL; для ресурсов, которые qemu передаёт хозяину):
 * ответ как у вызова хозяина — 0, либо -1 и errno. На успехе повтора old — значения до повтора (его даёт повтор, а не отказавший вызов). */
static inline int gr_prlimit(GrState *s, const GrHost *h, int pid, int resource, const GrLim *ask, GrLim *old)
{
    GrLim have, retry;
    int e;

    if (h->prlimit(h->ctx, pid, resource, ask, old) == 0) { /* ★ сперва — как прежде */
        return 0;
    }
    e = errno;
    if (ask != NULL && e == EPERM && gr_askable(resource, ask) && (pid == 0 || (long)pid == h->pid(h->ctx))
        && h->prlimit(h->ctx, pid, resource, NULL, &have) == 0 && gr_above(ask, &have)) {
        gr_retry_lim(ask, &have, &retry);
        if (h->prlimit(h->ctx, pid, resource, &retry, old) == 0) {
            gr_note_once(s, h, resource, ask, &retry);
            return 0;
        }
    }
    errno = e;
    return -1;
}

#endif /* GUEST_RLIMIT_H */
