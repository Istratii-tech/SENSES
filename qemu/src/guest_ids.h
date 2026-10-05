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
// Changed: 2026-08-29 … 2026-10-03

/* guest_ids.h — личность гостевых процессов: свой учёт прав, а не хозяйский. */
#ifndef GUEST_IDS_H
#define GUEST_IDS_H

#include <stdbool.h>
#include <sys/types.h>
#include <linux/capability.h>
/* PR_SET_KEEPCAPS и прочие — их обслуживает guest_ids_prctl. */
#include <sys/prctl.h>

/* Сколько дополнительных групп помним. Зигота 2.3 ставит их до десятка. */
#define GUEST_NGROUPS 64

/* Чтение личности. getuid отдаёт настоящий, geteuid — действующий. */
int guest_ids_getuid(void);
int guest_ids_geteuid(void);
int guest_ids_getsuid(void);
int guest_ids_getfsuid(void);
int guest_ids_getgid(void);
int guest_ids_getegid(void);
int guest_ids_getsgid(void);
int guest_ids_getfsgid(void);

/* Прежние имена — их использует патч 0008 в местах getuid32/getgid32. */
static inline int guest_guest_uid(void) { return guest_ids_geteuid(); }
static inline int guest_guest_gid(void) { return guest_ids_getegid(); }

/* Смена личности. Возвращают 0 или -errno (не -1: errno у нас свой). */
int guest_ids_setuid(uid_t uid);
int guest_ids_setgid(gid_t gid);
int guest_ids_setreuid(uid_t ruid, uid_t euid);
int guest_ids_setregid(gid_t rgid, gid_t egid);
int guest_ids_setresuid(uid_t ruid, uid_t euid, uid_t suid);
int guest_ids_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
/* Эти возвращают ПРЕЖНЕЕ значение и не могут отказать — как в ядре. */
int guest_ids_setfsuid(uid_t fsuid);
int guest_ids_setfsgid(gid_t fsgid);

/* Группы. getgroups отдаёт число групп или -errno. */
int guest_ids_getgroups(int size, gid_t *list);
int guest_ids_setgroups(int size, const gid_t *list);

/*
 * Личность СОСЕДНЕГО гостевого процесса по номеру, который отдал ядро в
 * SO_PEERCRED. Возвращает 1, если нашли (тогда *uid и *gid заполнены).
 */
int guest_ids_peercred(int pid, int *uid, int *gid);

/*
 * Смена владельца файла. Хозяин её нам не даст (мы не root), а гостю она
 * нужна: installd прошивки без неё СНОСИТ только что созданный каталог.
 * Возвращает 1, если отказ надо превратить в успех.
 */
int guest_ids_chown_forgive(int host_errno, const char *what);

/*
 * Личность для ребёнка при execve (режим «init прошивки», патч 0079): строки
 * окружения GUEST_UID, GUEST_EUID, GUEST_GID, GUEST_EGID, GUEST_GROUPS. Кладёт в
 * out по GUEST_IDS_ENV_LEN байт, возвращает число строк (GUEST_IDS_ENV_N).
 */
#define GUEST_IDS_ENV_N   5
#define GUEST_IDS_ENV_LEN 512
int guest_ids_child_env(char out[][GUEST_IDS_ENV_LEN], int max);
/* Строка окружения — одна из тех, что задаёт guest_ids_child_env. */
bool guest_ids_is_child_env(const char *e);

/* Права (capabilities). Возвращают 0 или -errno. */
int guest_ids_capget(struct __user_cap_header_struct *hdr,
                   struct __user_cap_data_struct *data);
int guest_ids_capset(struct __user_cap_header_struct *hdr,
                   const struct __user_cap_data_struct *data);

/*
 * prctl, относящийся к правам. Возвращает 1, если вызов НАШ (тогда ответ
 * гостю лежит в *out), и 0, если это не про личность — пусть идёт своим путём.
 */
int guest_ids_prctl(int option, unsigned long a2, unsigned long a3,
                  unsigned long a4, unsigned long a5, long *out);

#endif
