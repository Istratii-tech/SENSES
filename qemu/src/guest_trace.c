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

/*
 * guest_trace.c — ТРАССА ГОСТЯ: отметки прошивки и наши на одной шкале времени.
 *
 * ★ Зачем (книга 3.4.9, 9.29). Кадр стола пальцем — это цепочка: синхроимпульс
 * композитора → главный поток стола → вызовы моста GL и binder → композитор. Какое
 * звено держит кадр, не видно ни по доле ядра, ни по отчёту моста: главный поток
 * стола 45 % времени спит в epoll, а кадры идут по 20 мс вместо 16. Нужна
 * трасса, как systrace на живом аппарате.
 *
 * ★ Как. У прошивки уже есть свои отметки — atrace (`ATRACE_*`, `Trace.traceBegin`):
 * они пишутся строками «B|pid|имя» / «E» в /sys/kernel/debug/tracing/trace_marker,
 * а время и поток к ним добавляет ядро. Ядра хозяина у нас нет, поэтому этот
 * путь гостю отдаём мы: `/dev/null` с переводчиком записи (fd_trans), который
 * сам ставит время CLOCK_MONOTONIC хозяина, pid и tid и кладёт строку в
 * `trace.txt` рядом с журналом шима binder. Туда же пишут шим binder (вызов с
 * ответом — от посылки до ответа) и гостевая половина моста GL (ожидание ответа
 * хозяина). Часы у всех одни — те же, что у `dumpsys SurfaceFlinger --latency`.
 *
 * ★ Выключатель — САМ ФАЙЛ. Нет `trace.txt` — не пишется ничего, а гость на
 * записи получает ноль (мост GL по нулю понимает, что трасса выключена, и
 * своих отметок не ставит). Что пишет прошивка, решают её же свойства
 * (`debug.atrace.tags.enableflags`); включает и снимает всё вместе
 * `./tools/phone-app.sh trace`.
 *
 * ⚠️ Потолок — TRACE_CAP: трасса пишет сотни килобайт в секунду, а журналы
 * стенда обязаны иметь предел (книга 3.19.1).
 * ⚠️ Описатель файла трассы живёт в общей с гостем таблице описателей: его
 * номер уводим повыше и раз в 200 мс сверяем узел — если гость закрыл и занял
 * номер своим файлом, писать туда перестаём.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "fd-trans.h"

#include <pthread.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "guest_trace.h"

#define TRACE_CAP (128LL << 20)
#define TRACE_RECHECK_US 200000

static char g_path[512];
static int g_path_done;
static int g_tfd = -1;
static ino_t g_ino;
static int g_on, g_busy;
static int64_t g_next;
static int g_pid;
static __thread int t_tid;
static __thread ino_t t_named;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

static int64_t mono_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

/* ⚠️ После fork у ребёнка другой pid и tid, а флаг проверки мог остаться
 * поднятым потоком, которого в ребёнке нет. */
static void at_child(void) { g_pid = 0; t_tid = 0; t_named = 0; g_busy = 0; g_next = 0; }
static void once(void) { pthread_atfork(NULL, NULL, at_child); }

/* Файл трассы — рядом с журналом шима binder (GUEST_BINDER_LOG). */
static void path_init(void)
{
    if (g_path_done) return;
    g_path_done = 1;
    const char *l = getenv("GUEST_BINDER_LOG");
    const char *sl = l ? strrchr(l, '/') : NULL;
    if (!sl || sl - l + 16 >= (long)sizeof g_path) return;
    memcpy(g_path, l, sl - l);
    strcpy(g_path + (sl - l), "/trace.txt");
}

static void recheck(int64_t now)
{
    if (__atomic_exchange_n(&g_busy, 1, __ATOMIC_ACQUIRE)) return;
    pthread_once(&g_once, once);
    __atomic_store_n(&g_next, now + TRACE_RECHECK_US, __ATOMIC_RELAXED);
    path_init();
    int on = 0;
    struct stat st, fs;
    if (g_tfd >= 0 && (fstat(g_tfd, &fs) != 0 || fs.st_ino != g_ino)) {
        g_tfd = -1;                /* номер занял гость: не закрываем, не пишем */
    }
    if (g_path[0] && stat(g_path, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_size < TRACE_CAP) {
        if (g_tfd < 0 || st.st_ino != g_ino) {
            int nfd = open(g_path, O_WRONLY | O_APPEND | O_CLOEXEC);
            if (nfd >= 0) {
                if (g_tfd < 0) {
                    int hi = fcntl(nfd, F_DUPFD_CLOEXEC, 700);
                    if (hi >= 0) { close(nfd); g_tfd = hi; } else { g_tfd = nfd; }
                } else {
                    /* ★ Подмена файла под тем же номером: пишущий поток попадёт
                     * либо в старый файл, либо в новый — но не в чужой. */
                    dup3(nfd, g_tfd, O_CLOEXEC);
                    close(nfd);
                }
                g_ino = st.st_ino;
            }
        }
        on = g_tfd >= 0;
    }
    __atomic_store_n(&g_on, on, __ATOMIC_RELAXED);
    __atomic_store_n(&g_busy, 0, __ATOMIC_RELEASE);
}

int guest_trace_on(void)
{
    int64_t now = mono_us();
    if (now >= __atomic_load_n(&g_next, __ATOMIC_RELAXED)) recheck(now);
    return __atomic_load_n(&g_on, __ATOMIC_RELAXED);
}

/* Строка трассы: «секунды.микросекунды pid tid отметка». */
static void emit(const char *pay, size_t n)
{
    char line[1024];
    int fd = g_tfd;
    if (fd < 0) return;
    if (!g_pid) g_pid = getpid();
    if (!t_tid) t_tid = (int)syscall(SYS_gettid);
    int64_t us = mono_us();
    /* ★ Имя потока — один раз на поток и на файл: по нему разбор узнаёт
     * главный поток стола и потоки композитора. */
    if (t_named != g_ino) {
        char nm[17] = { 0 };
        prctl(PR_GET_NAME, nm, 0, 0, 0);
        int k = snprintf(line, sizeof line, "%lld.%06lld %d %d M|%s\n",
                         (long long)(us / 1000000), (long long)(us % 1000000),
                         g_pid, t_tid, nm);
        if (k > 0 && write(fd, line, (size_t)k) == k) t_named = g_ino;
    }
    int k = snprintf(line, sizeof line, "%lld.%06lld %d %d ",
                     (long long)(us / 1000000), (long long)(us % 1000000), g_pid, t_tid);
    if (k <= 0) return;
    if ((size_t)k + n + 1 > sizeof line) n = sizeof line - (size_t)k - 1;
    memcpy(line + k, pay, n);
    k += (int)n;
    line[k++] = '\n';
    ssize_t r = write(fd, line, (size_t)k);
    (void)r;
}

void guest_trace_mark(char kind, const char *fmt, ...)
{
    if (!guest_trace_on()) return;
    char pay[512];
    int k;
    if (kind == 'E') {
        k = snprintf(pay, sizeof pay, "E");
    } else {
        if (!g_pid) g_pid = getpid();
        k = snprintf(pay, sizeof pay, "%c|%d|", kind, g_pid);
        if (k > 0 && k < (int)sizeof pay) {
            va_list ap;
            va_start(ap, fmt);
            int m = vsnprintf(pay + k, sizeof pay - (size_t)k, fmt, ap);
            va_end(ap);
            if (m > 0) k += m;
        }
    }
    if (k <= 0) return;
    if (k >= (int)sizeof pay) k = (int)sizeof pay - 1;
    emit(pay, (size_t)k);
}

/*
 * Переводчик записи в trace_marker: время и поток ставим сами.
 * ⚠️ Возврат 0 — «трасса выключена»: qemu тогда пишет в /dev/null ноль байт, и
 * гость видит 0. libcutils возврат не смотрит, мост GL по нему решает, ставить
 * ли свои отметки.
 */
static abi_long trace_write(void *buf, size_t len)
{
    if (!guest_trace_on()) return 0;
    const char *p = (const char *)buf;
    size_t n = len;
    while (n && (p[n - 1] == '\n' || p[n - 1] == 0)) n--;
    if (n) emit(p, n);
    return (abi_long)len;
}

static TargetFdTrans trace_trans = { .target_to_host_data = trace_write };

static int is_marker(const char *path)
{
    return path && (!strcmp(path, "/sys/kernel/debug/tracing/trace_marker") ||
                    !strcmp(path, "/sys/kernel/tracing/trace_marker"));
}

int guest_trace_try_open(const char *path, int *fd)
{
    if (!is_marker(path)) return 0;
    /* ⚠️ Без O_CLOEXEC, как настоящий trace_marker у atrace: ребёнок зиготы
     * наследует и описатель, и переводчик (таблица qemu копируется с fork). */
    *fd = open("/dev/null", O_WRONLY);
    return 1;
}

/*
 * ⚠️★★ Переводчик — ПОСЛЕ открытия (патч 0062): ветки open/openat сразу за
 * do_guest_openat снимают переводчик с нового описателя, и поставленный внутри
 * перехвата пропадал — прошивка и мост писали в голый /dev/null.
 */
void guest_trace_opened(const char *path, abi_long fd)
{
    if (fd >= 0 && is_marker(path)) fd_trans_register((int)fd, &trace_trans);
}
