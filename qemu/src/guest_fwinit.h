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
// Changed: 2026-10-03 … 2026-10-04

/*
 * guest_fwinit.h — «ядро для init»: транслятор изображает ядро настоящему
 * /init прошивки (режим «init прошивки»). Включается GUEST_FWINIT=1; без
 * переменной ни одна функция здесь не меняет поведения. Подробности — в
 * guest_fwinit.c и в шапках патчей 0075…0083.
 */
#ifndef GUEST_FWINIT_H
#define GUEST_FWINIT_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

/*
 * Включён ли режим: GUEST_FWINIT равно «1» (читается один раз). Первый вызов
 * заодно переписывает относительные пути файлов стенда в абсолютные.
 */
bool guest_fwinit(void);

/* ---- mknod (патч 0076) ---- */
/* Узел, который в этом режиме создаёт заглушка: символьный или блочный. */
bool guest_fwinit_node(mode_t mode);
/* mknod по хозяйскому пути: 0 или -1 с errno, как вызов. */
int guest_fwinit_mknod(const char *host, mode_t mode, dev_t dev);

/* ---- поддельные файлы /proc (вход guest_fs_try_open) ---- */
/*
 * Текст поддельного файла /proc для init или NULL. buf (cap байт) — буфер
 * вызывающего: в нём собирается строка /proc/cmdline; на прочие файлы — константы.
 */
const char *guest_fwinit_proc_text(const char *path, char *buf, size_t cap);

/*
 * /proc/emmc из файла стенда: GUEST_EMMC — абсолютный путь файла, его содержимое и
 * есть /proc/emmc. Файл готовит стенд (таблица разделов прошивки изготовителя —
 * имена разделов транслятор не выдумывает). true — *data (g_free) и *len заполнены.
 */
bool guest_fwinit_emmc(char **data, size_t *len);

/* ---- имя процесса (патч 0077) ---- */
/* Запомнить гостевой путь программы по хозяйскому пути до realpath. */
void guest_fwinit_program(const char *host_path);
/* Имя процесса — гостевая программа (PR_SET_NAME), только в этом режиме. */
void guest_fwinit_comm(void);

/* ---- журнал запусков (патч 0078) ---- */
/* GUEST_START_LOG: строка о старте гостевой программы. */
void guest_fwinit_start_log(const char *argv0);

/* ---- служба свойств (патч 0080) ---- */
/* Гостевой sun_path (до перевода под корень) — сокет службы свойств? */
bool guest_fwinit_prop_path(const void *sockaddr, socklen_t len);
/* Успешный bind такого сокета: запомнить слушающий описатель. */
void guest_fwinit_prop_listener(int fd);
/* accept/accept4 на описателе lfd вернули newfd (или ошибку < 0). */
void guest_fwinit_prop_accepted(int lfd, int newfd);
/* Прочитано n байт по описателю fd (read, recv, recvfrom) из буфера buf. */
void guest_fwinit_prop_data(int fd, const void *buf, size_t n);
/* То же для recvmsg: iov уже заполнен, всего принято total байт. */
void guest_fwinit_prop_iov(int fd, const struct iovec *iov, size_t cnt,
                           size_t total);
/* Описатель закрывается — снять отметку. */
void guest_fwinit_prop_closed(int fd);

/* ---- reboot (патч 0081) ---- */
/* GUEST_REBOOT_LOG: cmd — довод cmd; arg — гостевой адрес строки (RESTART2). */
void guest_fwinit_reboot(unsigned cmd, unsigned long arg);

/* ---- область свойств: unlink не удаляет имя (патч 0083) ---- */
/* Гостевой путь — ровно /dev/__properties__: unlink/unlinkat отвечают 0, файл остаётся. */
bool guest_fwinit_keep(const char *guest_path);

/* ---- запись в узел журнала ядра (патч 0082) ---- */
/* Гостевой путь — ссылка на файл GUEST_KMSG: открытие на запись — с O_APPEND. */
bool guest_fwinit_kmsg(const char *guest_path);

#endif
