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

/*
 * guest_kill.c — ЖУРНАЛ СИГНАЛОВ ГОСТЯ «КТО → КОМУ» (регресс Р-80, патч 0090).
 *
 * ★ Зачем. Процесс гостя бывает убит ТИХО: демон binder видит закрытие всех его
 * соединений разом, строки выхода у транслятора нет (журнал выходов, патч 0070,
 * SIGKILL не видит: его исполняет ядро без нас), диспетчер активностей о снятии
 * не писал, телефон отказа не записал. Значит, сигнал послал какой-то процесс
 * гостя — и узнать КАКОЙ может только транслятор: гостевые kill, tkill, tgkill,
 * rt_sigqueueinfo и rt_tgsigqueueinfo проходят через него.
 *
 * ★ Что пишем. При заданной GUEST_KILL_LOG (абсолютный путь файла стенда) — по
 * строке на каждый такой вызов с сигналом, отличным от 0 (сигнал 0 — проверка
 * «жив ли», он ничего не доставляет):
 *
 *   <время_мс> <pid отправителя> <tid отправителя> <имя отправителя> → <цель> [<tid цели>] сигнал <номер> = <результат>
 *
 *  - цель — как в вызове: pid, -pgid, 0 или -1; у tgkill и rt_tgsigqueueinfo за ней
 *    tid цели; у tkill pid цели вызов не знает — tid идёт дважды;
 *  - номер сигнала — ГОСТЕВОЙ, как позвал гость;
 *  - имя — последние до 15 знаков имени процесса (/proc/self/comm), как называет его
 *    журнал выходов (при GUEST_FWINIT=1 это гостевая программа, патч 0077);
 *  - результат — то, что вернул хозяин и получит гость: 0 или -errno; «?» — см. ниже.
 *
 * ★★ Строка пишется ДО вызова, когда вызов может не вернуться. Процесс, который
 * убивает САМ СЕБЯ сигналом 9 (Process.killProcess(myPid()) — привычный конец
 * процесса приложения), не получит от хозяина ответа: ядро снимет его внутри
 * вызова, и строка «после» не появилась бы никогда — а это ровно тот случай,
 * ради которого журнал заведён. Поэтому для сигнала 9, который может достать
 * отправителя (kill в свой pid, свой tid, 0, свою группу; tkill/tgkill/rt_* в
 * поток своего процесса), строка уходит до вызова с результатом «?» («исход не
 * известен: вызов не вернулся»). Всё прочее пишется после — с настоящим ответом.
 *
 * ★ Что НЕ пишется. Сигналы, которые транслятор шлёт сам себе внутри (завершение
 * потоков, прерывание исполнения, возвращение из обработчика), в этот журнал не
 * попадают: он стоит на гостевых системных вызовах, а транслятор свои посылает
 * мимо них. pidfd_send_signal не пишется: у ядер прошивок (2.3–7.0) его нет.
 *
 * ⚠️ Без GUEST_KILL_LOG ничего не меняется и ничего не стоит: переменная читается
 * один раз, при старте процесса (конструктор), а на каждом вызове — одно чтение int
 * (guest_kill.h), без вызовов.
 * ⚠️ Файл открывается на КАЖДУЮ строку с дозаписью, строка уходит одним write —
 * как у журнала выходов (патч 0070): процессы гостя — форки, общий описатель через
 * fork держать нельзя, а строки разных процессов не смешиваются (строка короче
 * PIPE_BUF). Нельзя открыть файл — молча без строки: журнал не должен мешать гостю.
 * ⚠️ Путь — АБСОЛЮТНЫЙ (его кладёт стенд). Относительный после гостевого chdir
 * указал бы уже не туда.
 * ⚠️ Вызов, прерванный сигналом до исполнения (-QEMU_ERESTARTSYS), не пишется: он
 * будет повторён и запишется при повторе — хозяин его ещё не исполнял.
 * ⚠️ Строка «до» окончательная: если вызов вопреки расчёту всё же вернулся, второй
 * строки с ответом не будет, останется «?». На деле не бывает — SIGKILL, достающий
 * отправителя, снимает его внутри вызова.
 */
#include "qemu/osdep.h"
#include <sys/prctl.h>
#include <sys/syscall.h>
#include "special-errno.h"

#include "guest_kill.h"

#define KILL_SIGKILL 9          /* гостевой (ARM) номер SIGKILL */

int guest_kill_on;
static char *kill_path;

/*
 * Переменную читаем ОДИН раз — при старте процесса, до main (конструктор), чтобы у
 * первого же kill не было ни getenv, ни pthread_once. Окружение хозяина тут уже то,
 * что положил стенд: гостевой execve пересобирает транслятор заново (патч 0005,
 * новый процесс — новый конструктор), а fork наследует решение.
 */
static void __attribute__((constructor)) kill_setup(void)
{
    const char *p = getenv("GUEST_KILL_LOG");

    if (p && *p) {
        kill_path = strdup(p);
        guest_kill_on = kill_path != NULL;
    }
}

static long long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static pid_t my_tid(void)
{
    return (pid_t)syscall(SYS_gettid);
}

/*
 * Имя отправителя — /proc/self/comm: имя ПРОЦЕССА (comm ведущего потока). Журнал
 * выходов (патч 0070) берёт имя потока, вызвавшего выход; у обычного процесса они
 * совпадают, а имя процесса понятнее в разборе «кто убил». Не прочлось — имя потока
 * из ядра, и «?», если нет и его.
 * Управляющие знаки — в «?»: строка журнала должна остаться одной строкой.
 */
static void sender_name(char *name, size_t cap)
{
    ssize_t n = 0;
    size_t i;
    int fd = open("/proc/self/comm", O_RDONLY | O_CLOEXEC);

    if (fd >= 0) {
        n = read(fd, name, cap - 1);
        close(fd);
    }
    if (n <= 0) {
        memset(name, 0, cap);
        prctl(PR_GET_NAME, (unsigned long)name, 0, 0, 0);
        n = (ssize_t)strlen(name);
    }
    name[n > 0 ? n : 0] = '\0';
    while (n > 0 && name[n - 1] == '\n') {
        name[--n] = '\0';
    }
    if (n > 15) {
        name[15] = '\0';
        n = 15;
    }
    for (i = 0; i < (size_t)n; i++) {
        if ((unsigned char)name[i] < 0x20 || name[i] == 0x7f) {
            name[i] = '?';
        }
    }
    if (n == 0) {
        strcpy(name, "?");
    }
}

/*
 * Может ли этот вызов достать самого отправителя. Только для SIGKILL и только
 * точно: лишняя строка «?» дала бы неверный результат вызова, который ещё
 * вернётся (kill в чужой pid отвечает хозяин, и это пишется после).
 *  - kill: свой pid или tid, 0 (своя группа), -pgid своей группы. -1 хозяин
 *    шлёт всем, КРОМЕ процесса-отправителя (kill_something_info);
 *  - rt_sigqueueinfo: свой pid или tid;
 *  - tkill: tid потока своего процесса; tgkill и rt_tgsigqueueinfo: tgid свой
 *    и tid потока своего процесса. Принадлежность потока узнаём тем же
 *    tgkill с сигналом 0 — он ничего не доставляет, только проверяет.
 */
static bool hits_self(const GuestKill *k, pid_t pid, pid_t tid)
{
    switch (k->kind) {
    case GUEST_KILL_KILL:
        return k->a == pid || k->a == tid || k->a == 0 ||
               (k->a < -1 && -(long long)k->a == (long long)getpgrp());
    case GUEST_KILL_SIGQ:
        return k->a == pid || k->a == tid;
    case GUEST_KILL_TKILL:
        return syscall(SYS_tgkill, pid, k->a, 0) == 0;
    default:        /* tgkill, rt_tgsigqueueinfo */
        return k->a == pid && syscall(SYS_tgkill, pid, k->b, 0) == 0;
    }
}

/* Одна строка в файл стенда; have_ret — результат известен. */
static void emit(const GuestKill *k, bool have_ret, long ret)
{
    char name[32], tgt[48], res[24], line[256];
    int fd, n;

    sender_name(name, sizeof name);
    switch (k->kind) {
    case GUEST_KILL_TKILL:
        snprintf(tgt, sizeof tgt, "%d %d", k->a, k->a);
        break;
    case GUEST_KILL_TGKILL:
    case GUEST_KILL_TGSIGQ:
        snprintf(tgt, sizeof tgt, "%d %d", k->a, k->b);
        break;
    default:
        snprintf(tgt, sizeof tgt, "%d", k->a);
        break;
    }
    if (have_ret) {
        snprintf(res, sizeof res, "%ld", ret);
    } else {
        strcpy(res, "?");
    }
    n = snprintf(line, sizeof line, "%lld %d %d %s → %s сигнал %d = %s\n",
                 k->ms, (int)getpid(), (int)my_tid(), name, tgt, k->sig, res);
    if (n <= 0 || n >= (int)sizeof line) {
        return;
    }
    fd = open(kill_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    if (write(fd, line, (size_t)n) < 0) {
        /* журнал — подсказка разбору, гостю он не помеха */
    }
    close(fd);
}

void guest_kill_begin_slow(GuestKill *k, int kind, long a, long b, long sig)
{
    if ((int)sig == 0) {
        return;
    }
    k->on = true;
    k->kind = kind;
    k->a = (int)a;
    k->b = (int)b;
    k->sig = (int)sig;
    k->ms = now_ms();
    if (k->sig == KILL_SIGKILL && hits_self(k, getpid(), my_tid())) {
        emit(k, false, 0);              /* хозяин из этого вызова не вернёт */
        k->on = false;
    }
}

void guest_kill_end_slow(GuestKill *k, long ret)
{
    k->on = false;
    if (ret == -QEMU_ERESTARTSYS) {
        return;
    }
    emit(k, true, ret);
}
