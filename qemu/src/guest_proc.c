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

/* guest_proc.c — гость видит в /proc/self/task ТОЛЬКО свои потоки.
 *
 * ★★★ Зачем. Зигота 4.1 перед fork() ждёт, пока в процессе не останется один
 * поток, и считает их по каталогу /proc/self/task:
 *
 *   open("/proc/self/task",O_RDONLY|O_DIRECTORY) = 27
 *   getdents64(27,…) = 96          ← «.», «..» и ДВА потока
 *   close(27)
 *   futex(…,FUTEX_WAIT,…,{tv_nsec = 9921302}) = ETIMEDOUT   ← спим 10 мс
 *   … и так вечно
 *
 * Своих потоков у Dalvik к этому времени не осталось (в трассировке видно, как
 * освобождаются их стёки: munmap(…,16384)), но каталог всё равно показывает
 * два: второй — служебный поток САМОЙ ТРАНСЛЯЦИИ (qemu поднимает поток RCU).
 * Гость его не создавал, а увидев — ждёт его завершения до конца времён:
 * system_server не запускается, а в логе при этом НИ ОДНОЙ строки об ошибке.
 *
 * ⚠️ Подменой пути (`-L`) это не лечится: qemu перед подстановкой раскрывает
 * путь через realpath, и «/proc/self/task» превращается в «/proc/<pid>/task» —
 * такого каталога в дереве нет и быть не может, номер процесса заранее
 * неизвестен.
 *
 * Что делаем. При выдаче содержимого каталога /proc/<наш pid>/task прячем
 * записи, чей номер НЕ принадлежит ни одному гостевому процессору (то есть ни
 * одному потоку гостя). Записи «.» и «..» остаются, файлы внутри
 * (/proc/self/task/<tid>/stat и прочие) не затрагиваются вовсе — их гость
 * читает у хозяина как раньше.
 *
 * ★ Это не обман, а восстановление правды: гостю показывается ровно то, что он
 * сам породил. Потоки трансляции — часть нашей реализации, гостю о них знать
 * не полагается.
 *
 * ★★ Патч 0094 (Р-101, 7.x): ТО ЖЕ — ДЛЯ ОПИСАТЕЛЕЙ. Зигота 7.x перед
 * ветвлением обходит /proc/self/fd и сверяет каждый описатель с белым списком;
 * чужой — смерть всей зиготы:
 *
 *   E Zygote: Not whitelisted : /guest.owners
 *   F art: … Zygote.cpp:467: Unable to construct file descriptor table.
 *
 * Служебные описатели стенда (журналы транслятора в доме стенда, карта
 * владельцев и прочие `<корень>/guest.*`, трубы и область свойств из
 * GUEST_PLUMB) гость не открывал — в каталоге /proc/<наш pid>/fd их записи
 * прячутся так же, как потоки трансляции. Сами описатели живы и в потомках:
 * зигота их не видит и потому не трогает. Описатели ФАЙЛОВ ДЕРЕВА и общей
 * папки — гостя, их видно всегда (решение — path_is_stand_plumbing, util/path.c).
 * ⚠️ Каталог узнаётся по пути при открытии — после realpath (do_guest_openat
 * сводит /proc-пути: косая в конце, thread-self → <pid>/task/<tid>): /proc/self/fd,
 * /proc/<наш pid>/fd и (Р-116) …/task/<поток этого процесса>/fd. Мимо идёт только
 * openat(каталог, "fd") относительным именем: там список — как прежде, без пряток
 * (граница записана в заголовке патча 0094).
 *
 * ⚠️ Оговорка: поток гостя попадает в список процессоров чуть позже своего
 * появления в ядре (внутри clone). Долю секунды такой поток будет спрятан.
 * Для счётчиков вида «остался ли я один» это безопасно: гость в это время сам
 * держит свой замок списка потоков.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
/* ⚠️ qemu.h ДО user-internals.h: TaskState объявлен там (см. guest_tls.c). */
#include "qemu.h"
#include "user-internals.h"
#include "hw/core/cpu.h"

#include "qemu/path.h"
#include "guest_proc.h"
#include "guest_procpath.h"

/*
 * Дескрипторы, за которыми стоит /proc/<наш pid>/task (и, патч 0094, …/fd). Их единицы:
 * каталог открывают на один обход и сразу закрывают. Ячейка хранит номер + 1 (ноль —
 * свободна) и берётся атомарно, без замка (проверка r100, мелкое 3): два потока, разом
 * открывшие такие каталоги, не запишут за край таблицы, а замок пережил бы fork
 * запертым. Таблица полна — каталог показывается как прежде, без пряток.
 */
#define GUEST_PROC_MAXFD 16
static int task_fds[GUEST_PROC_MAXFD];
/* ★ 0094: дескрипторы, за которыми стоит /proc/<наш pid>/fd. */
static int fdir_fds[GUEST_PROC_MAXFD];

/*
 * ★ Р-116: поток tid — в процессе pid? У ядра это каталог /proc/<pid>/task/<tid>; свой
 * текущий поток — без обращения к ядру. Нужно, чтобы путь через task/<чужой поток> не
 * получил подмену: ядро ответило бы ENOENT, пусть и отвечает.
 */
static bool tid_in_process(long pid, long tid)
{
    char b[64];
    struct stat st;

    if (pid == (long)getpid() && tid == (long)qemu_get_thread_id()) {
        return true;
    }
    snprintf(b, sizeof(b), "/proc/%ld/task/%ld", pid, tid);
    return stat(b, &st) == 0;
}

/*
 * ★ Р-116: одно решение «чей путь /proc» для всех подмен транслятора. Ядро отдаёт записи
 * процесса и по /proc/<pid>/task/<tid>/<X>, и по /proc/thread-self/<X>; подмены узнавали
 * только /proc/self/<X> и /proc/<свой pid>/<X>, и путь через task/ уходил к хозяину (bionic
 * 6.0 ищет стек главного потока в /proc/self/task/<getpid()>/maps и находил стек хозяина).
 * Разбор — guest_procpath.h (без qemu, гоняется на Маке).
 */
const char *guest_proc_mine_rest(const char *path)
{
    GuestProcPath pp;

    if (path == NULL || strncmp(path, "/proc/", 6) != 0) {
        return NULL;                    /* горячая дорога: каждый open гостя */
    }
    if (!guest_proc_path(path, (long)getpid(), (long)qemu_get_thread_id(), &pp) || !pp.mine) {
        return NULL;
    }
    return (pp.tid == 0 || tid_in_process(pp.pid, pp.tid)) ? pp.rest : NULL;
}

bool guest_proc_is_mine(const char *path, const char *entry)
{
    const char *rest, *last;

    if (path == NULL || strncmp(path, "/proc/", 6) != 0) {
        return false;                   /* горячая дорога: каждый open гостя */
    }
    /* Последнее звено не то — без getpid/gettid (is_proc_myself зовут на каждый open по разу на запись). */
    last = strrchr(path, '/');
    if (!strchr(entry, '/') && strcmp(last + 1, entry) != 0) {
        return false;
    }
    rest = guest_proc_mine_rest(path);
    return rest != NULL && strcmp(rest, entry) == 0;
}

bool guest_proc_owner_path(const char *path, long *pid, const char **rest)
{
    GuestProcPath pp;

    if (path == NULL || strncmp(path, "/proc/", 6) != 0) {
        return false;
    }
    if (!guest_proc_path(path, (long)getpid(), (long)qemu_get_thread_id(), &pp)) {
        return false;
    }
    if (pp.tid != 0 && !tid_in_process(pp.pid, pp.tid)) {
        return false;
    }
    *pid = pp.pid;
    *rest = pp.rest;
    return true;
}

/* «/proc/<self|thread-self|наш pid>/[task/<наш tid>/]<sub>». */
static bool path_is_own_dir(const char *p, const char *sub)
{
    return guest_proc_is_mine(p, sub);
}

static bool path_is_own_task_dir(const char *p)
{
    return path_is_own_dir(p, "task");
}

static bool table_has(const int *tab, int fd)
{
    int i;

    for (i = 0; i < GUEST_PROC_MAXFD; i++) {
        if (__atomic_load_n(&tab[i], __ATOMIC_ACQUIRE) == fd + 1) {
            return true;
        }
    }
    return false;
}

static void table_add(int *tab, int fd)
{
    int i;

    if (table_has(tab, fd)) {
        return;
    }
    for (i = 0; i < GUEST_PROC_MAXFD; i++) {
        int none = 0;

        if (__atomic_compare_exchange_n(&tab[i], &none, fd + 1, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            return;
        }
    }
}

static void table_del(int *tab, int fd)
{
    int i;

    for (i = 0; i < GUEST_PROC_MAXFD; i++) {
        int mine = fd + 1;

        __atomic_compare_exchange_n(&tab[i], &mine, 0, false,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
}

void guest_proc_open(const char *path, int fd)
{
    if (fd < 0) {
        return;
    }
    if (path_is_own_task_dir(path)) {
        table_add(task_fds, fd);
    } else if (path_is_own_dir(path, "fd")) {
        table_add(fdir_fds, fd);
    }
}

void guest_proc_close(int fd)
{
    table_del(task_fds, fd);
    table_del(fdir_fds, fd);
}

static bool fd_is_task_dir(int fd)
{
    return table_has(task_fds, fd);
}

/* Номер потока — только цифры и не пусто. */
static bool name_is_tid(const char *name, long *out)
{
    const char *p = name;
    long v = 0;

    if (*p == '\0') {
        return false;
    }
    for (; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return false;
        }
        v = v * 10 + (*p - '0');
        if (v > 0x7fffffff) {
            return false;
        }
    }
    *out = v;
    return true;
}

static bool tid_is_guest_thread(long tid)
{
    CPUState *cpu;
    bool found = false;

    cpu_list_lock();
    CPU_FOREACH(cpu) {
        TaskState *ts = (TaskState *)cpu->opaque;

        if (ts != NULL && (long)ts->ts_tid == tid) {
            found = true;
            break;
        }
    }
    cpu_list_unlock();
    return found;
}

/*
 * ★ 0094: проводка запускателя — узлы из GUEST_PLUMB («устройство:узел» через
 * запятую, десятичные): трубы stdio, которые завёл стенд, и область свойств.
 * Разбирается один раз (pthread_once — поток-соперник не увидит таблицу
 * недозаполненной, проверка r100, мелкое 2); потомки получают её копией памяти,
 * потомки после execve — той же переменной (GUEST_* досылаются дочернему qemu).
 * Разбор строгий: запись — цифры, «:», цифры; первая же неверная обрывает список
 * (что успело разобраться — в силе), мусор не роняет и не прячет лишнего.
 */
#define PLUMB_MAX 8
static unsigned long long plumb_dev[PLUMB_MAX], plumb_ino[PLUMB_MAX];
static int plumb_n;
static pthread_once_t plumb_once = PTHREAD_ONCE_INIT;

/* Десятичное число без знака в начале s: true и *v, *end — за ним; нет цифры — false. */
static bool plumb_num(const char *s, unsigned long long *v, const char **end)
{
    char *e;

    if (*s < '0' || *s > '9') {
        return false;
    }
    errno = 0;
    *v = strtoull(s, &e, 10);
    if (errno != 0) {
        return false;
    }
    *end = e;
    return true;
}

static void plumb_parse(void)
{
    const char *e = getenv("GUEST_PLUMB");
    int n = 0;

    while (e && *e && n < PLUMB_MAX) {
        unsigned long long d, i;
        const char *end;

        if (!plumb_num(e, &d, &end) || *end != ':' || !plumb_num(end + 1, &i, &end)) {
            break;
        }
        plumb_dev[n] = d;
        plumb_ino[n] = i;
        n++;
        if (*end != ',') {
            break;
        }
        e = end + 1;
    }
    plumb_n = n;
}

static bool fd_is_plumb(long num)
{
    struct stat st;
    int i;

    pthread_once(&plumb_once, plumb_parse);
    if (plumb_n == 0 || fstat((int)num, &st) != 0) {
        return false;
    }
    for (i = 0; i < plumb_n; i++) {
        if ((unsigned long long)st.st_dev == plumb_dev[i] &&
            (unsigned long long)st.st_ino == plumb_ino[i]) {
            return true;
        }
    }
    return false;
}

/* ★ 0094: описатель [num] этого процесса ведёт в служебное стенда. */
static bool fd_is_stand_plumbing(long num)
{
    char link[48], host[PATH_MAX];
    ssize_t n;

    if (fd_is_plumb(num)) {
        return true;
    }

    snprintf(link, sizeof(link), "/proc/self/fd/%ld", num);
    n = readlink(link, host, sizeof(host) - 1);     /* хозяйский ответ, без перевода */
    if (n <= 0) {
        return false;
    }
    host[n] = '\0';
    return path_is_stand_plumbing(host);
}

bool guest_proc_hide_dent(int dirfd, const char *name)
{
    long num;

    if (!name_is_tid(name, &num)) {
        return false;               /* «.» и «..» оставляем как есть */
    }
    if (fd_is_task_dir(dirfd)) {
        return !tid_is_guest_thread(num);
    }
    if (table_has(fdir_fds, dirfd)) {
        return fd_is_stand_plumbing(num);
    }
    return false;
}
