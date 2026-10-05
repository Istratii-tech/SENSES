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

/*
 * guest_selinux.h — SELinux «всё разрешено» для прошивок 5.0–7.0 в режиме
 * «init прошивки». Включается GUEST_FWINIT=1 И GUEST_SELINUX=1; без любой из
 * двух переменных ни одна функция здесь не меняет поведения. Подробности — в
 * guest_selinux.c и в шапках патчей 0084…
 */
#ifndef GUEST_SELINUX_H
#define GUEST_SELINUX_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/vfs.h>

/* Включён ли режим: GUEST_FWINIT=1 и GUEST_SELINUX=1 (читается один раз). */
bool guest_selinux(void);

/*
 * ---- selinuxfs (патч 0084) ----
 * Старт процесса транслятора: завести каталог selinuxfs в dev дерева, если его
 * ещё нет, и подключить заведение классов по первому обращению к пути.
 */
void guest_selinux_start(void);
/* statfs по гостевому пути: под /sys/fs/selinux f_type — SELINUX_MAGIC. */
bool guest_selinux_statfs(const char *guest_path, struct statfs *st);
/* fstatfs по описателю: то же для описателя файла selinuxfs. */
void guest_selinux_fstatfs(int fd, struct statfs *st);


/*
 * ---- места под транзакции и атрибуты процесса (патчи 0085, 0086) ----
 * Перехваты open, read, write, close для описателей, которые выдал транслятор:
 * запись и чтение у них исполняет код, а не файл. abi_long — гостевое «длинное»
 * (его определяет включающий файл, как у guest_oom.h).
 */
/* open по гостевому пути: true — путь наш, в *fd описатель, или −1 с errno. */
bool guest_selinux_try_open(const char *guest_path, int flags, int *fd);
/* read: true — чтение наше, в *ret ответ гостю (число байт или −ошибка гостя). */
bool guest_selinux_read(int fd, void *buf, size_t n, abi_long *ret);
/* write (buf может быть NULL при n = 0): true — запись наша, в *ret ответ гостю. */
bool guest_selinux_write(int fd, const void *buf, size_t n, abi_long *ret);
/* close: забыть описатель. */
void guest_selinux_close(int fd);

/*
 * ---- атрибуты процесса (патч 0086) ----
 * Для execve: переменная окружения потомка «GUEST_SECON=<контекст>» (в buf, cap
 * байт); 1 — её надо передать, 0 — не надо (контекст по умолчанию). Прежнее
 * GUEST_SECON из окружения потомку не досылается (guest_selinux_is_child_env).
 */
int guest_selinux_child_env(char *buf, size_t cap);
bool guest_selinux_is_child_env(const char *entry);

/*
 * ---- метки файлов: расширенные атрибуты (патч 0087) ----
 * Вызовы *xattr без libattr в сборке отвечали ENOSYS. op — какой вызов; аргументы
 * — гостевые, как пришли (см. guest_selinux.c). Результат — для гостя: число,
 * 0 или −гостевая ошибка. Имена user.* — у файла телефона во всех режимах, список —
 * их имена плюс security.selinux при метках (Р-112, guest_xattr.h). security.selinux и
 * security.restorecon_last — подражание при метках (GUEST_FWINIT=1 и GUEST_SELINUX=1
 * или GUEST_SELINUX_LABELS=1); без них и для прочих имён — ENOSYS, как прежде.
 */
enum {
    GX_GET, GX_LGET, GX_FGET, GX_SET, GX_LSET, GX_FSET,
    GX_LIST, GX_LLIST, GX_FLIST, GX_REMOVE, GX_LREMOVE, GX_FREMOVE,
};
abi_long guest_selinux_xattr(int op, abi_ulong a1, abi_ulong a2, abi_ulong a3,
                             abi_ulong a4, abi_ulong a5);

/*
 * ---- SO_PEERSEC (патч 0088) ----
 * getsockopt(SOL_SOCKET, SO_PEERSEC) на сокете sockfd: true — ответ наш. buf — уже
 * заблокированный гостевой буфер на *len байт; на выходе *len — длина контекста с
 * нулём (при ERANGE — нужная), *ret — 0 или −гостевая ошибка.
 */
bool guest_selinux_peersec(int sockfd, char *buf, socklen_t *len, abi_long *ret);

#endif
