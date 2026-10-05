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
// Changed: 2026-09-24 … 2026-10-05

/*
 * guest_oom.c — ВАЖНОСТЬ ПРОЦЕССОВ ГОСТЯ ДЛЯ ЯДРА ТЕЛЕФОНА (регресс 24.09, Р-23).
 *
 * ★ Что было. Диспетчер активностей гостя ставит каждому процессу важность:
 * пишет число в /proc/<pid>/oom_adj — старый файл со шкалой −17…15 (строка
 * «/proc/%d/oom_adj» в libandroid_runtime.so прошивок 4.2 и 4.4). На живом
 * аппарате пишет system_server с правом CAP_SYS_RESOURCE, и ядро принимает
 * любое число. У нас пишет процесс приложения телефона без этого права, а ядро
 * через старый файл без права разрешает только ПОВЫШАТЬ число: понижение —
 * EACCES. Проверено на процессе гостя: старым файлом 10 → 9 — отказ, новым
 * 647 → 0 — можно, ниже нуля — отказ.
 *
 * Чем кончалось. Диспетчер №3 ответ проверяет: не смог опустить важность
 * поставщика медиатеки до нуля — «Failed setting oom adj», «Existing provider
 * … is crashing; detaching», и снимает поставщика сам, молча (ни падения, ни
 * строки о снятии). У №1 и №2 отказ глотается, но процесс, однажды
 * побывавший в кэше, телефон так и видит кэшем — и при нехватке памяти может
 * снять ПЕРЕДНЕЕ приложение гостя первым.
 *
 * ★ Что делаем. Запись в старый файл переводим в новый, /proc/<pid>/oom_score_adj,
 * по формуле самого ядра (15 → 1000, иначе adj·1000/17): через новый файл
 * понижать можно до предела, унаследованного от приложения стенда (у
 * переднего — ноль). Ниже предела ядро не пустит — тогда пишем ноль. Запись
 * прямо в новый файл — так же. Гостю отвечаем «записано», как ядро ответило
 * бы системному процессу; «процесса нет» — как ядро (ESRCH), по нему
 * диспетчер законно узнаёт о смерти. Чтение не трогаем: ядро само показывает
 * число в шкале открытого файла.
 *
 * ⚠️ Описатель мог смениться мимо нас (close_range, dup2 поверх, exec):
 * перед каждой записью сверяем узел с запомненным, иначе цифры, записанные в
 * чужой файл с тем же номером, пропали бы здесь.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"

#include <sys/stat.h>

#include "guest_oom.h"
#include "guest_proc.h"

#define OOM_FDS 1024

/* 0 — не наш; 1 — старый файл (−17…15); 2 — новый (−1000…1000). Таблица
 * копируется с fork вместе с описателями. */
static signed char oom_kind[OOM_FDS];
static int oom_pid[OOM_FDS];
static dev_t oom_dev[OOM_FDS];
static ino_t oom_ino[OOM_FDS];

void guest_oom_opened(const char *path, abi_long flags, abi_long fd)
{
    if (fd < 0 || fd >= OOM_FDS || !path) {
        return;
    }
    oom_kind[fd] = 0;
    if ((flags & 3) == 0 || strncmp(path, "/proc/", 6)) {
        return;                         /* только на запись и только /proc */
    }
    /*
     * ★ Р-116: «чей путь» — одно решение для всех подмен /proc (guest_proc.c):
     * /proc/<self|thread-self|pid>/[task/<tid>/]oom_adj — у ядра это файл процесса.
     */
    const char *p;
    long owner;
    if (!guest_proc_owner_path(path, &owner, &p)) {
        return;
    }
    int pid = (int)owner;
    int kind = !strcmp(p, "oom_adj") ? 1 : !strcmp(p, "oom_score_adj") ? 2 : 0;
    struct stat st;
    if (!kind || fstat((int)fd, &st)) {
        return;
    }
    oom_pid[fd] = pid;
    oom_dev[fd] = st.st_dev;
    oom_ino[fd] = st.st_ino;
    oom_kind[fd] = (signed char)kind;
}

/* Число в новый файл; 0 — записано, иначе −errno. */
static int put_score(int pid, long score)
{
    char path[48], b[16];
    snprintf(path, sizeof path, "/proc/%d/oom_score_adj", pid);
    int d = open(path, O_WRONLY | O_CLOEXEC);
    if (d < 0) {
        return -errno;
    }
    int k = snprintf(b, sizeof b, "%ld", score);
    int r = write(d, b, (size_t)k) == k ? 0 : -errno;
    close(d);
    return r;
}

int guest_oom_write(abi_long fd, const void *buf, abi_long len, abi_long *ret)
{
    if (fd < 0 || fd >= OOM_FDS || !oom_kind[fd] || len <= 0) {
        return 0;
    }
    struct stat st;
    if (fstat((int)fd, &st) || st.st_dev != oom_dev[fd] || st.st_ino != oom_ino[fd]) {
        oom_kind[fd] = 0;               /* номер уже чужой — пишет qemu */
        return 0;
    }
    char t[32];
    size_t n = (size_t)len < sizeof t - 1 ? (size_t)len : sizeof t - 1;
    memcpy(t, buf, n);
    t[n] = 0;
    char *e;
    long v = strtol(t, &e, 10);
    if (e == t) {
        return 0;                       /* не число — ответит ядро (EINVAL) */
    }
    long score;
    if (oom_kind[fd] == 1) {
        if (v < -17 || v > 15) {
            return 0;
        }
        score = v == 15 ? 1000 : v * 1000 / 17;   /* как oom_adj_write ядра */
    } else {
        if (v < -1000 || v > 1000) {
            return 0;
        }
        score = v;
    }
    int r = put_score(oom_pid[fd], score);
    if (r == -EACCES && score < 0) {
        r = put_score(oom_pid[fd], 0);  /* ниже предела не пустят — предел */
    }
    if (r == -ENOENT || r == -ESRCH) {
        errno = ESRCH;                  /* процесса нет — так ответит и ядро */
        *ret = get_errno(-1);
        return 1;
    }
    *ret = len;
    return 1;
}

void guest_oom_close(abi_long fd)
{
    if (fd >= 0 && fd < OOM_FDS) {
        oom_kind[fd] = 0;
    }
}
