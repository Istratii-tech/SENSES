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
// Changed: 2026-10-03

/* guest_script.h — что лежит в начале исполняемого файла гостя: ELF, сценарий
 * `#!` или ни то ни другое. Решение — как у ядра Linux (fs/binfmt_elf.c,
 * fs/binfmt_script.c), чтобы гостевой execve отвечал ровно то, что ответило бы
 * ядро (см. guest_script.c и патч 0071).
 *
 * ★ Файл не зависит от qemu: только libc POSIX. Поэтому его разбор гоняется
 * хостовым cc на Маке (native/test/test_script.c), а не только на телефоне. */
#ifndef GUEST_SCRIPT_H
#define GUEST_SCRIPT_H

#include <stddef.h>

/* Что лежит в начале файла — как решает ядро (fs/binfmt_elf.c, fs/binfmt_script.c). */
#define GUEST_SCRIPT_BUF   256   /* BINPRM_BUF_SIZE ядра */
/* Предел вложенности: сценарий, чей интерпретатор — сценарий… Ядра 3.x держат его в
 * search_binary_handler (BINPRM_MAX_RECURSION = 4, при большей глубине — -ELOOP); у ядер
 * 5.x и новее exec_binprm допускает глубину до 5. Мы держим 4 — как у ядер аппаратов
 * 2.3–6.0, — и пятый сценарий подряд отвечает ELOOP. */
#define GUEST_SCRIPT_DEPTH 4
enum { GUEST_EXEC_ELF = 0, GUEST_EXEC_SCRIPT = 1 };

/* Разбор первых len байт файла. Возврат: GUEST_EXEC_ELF, GUEST_EXEC_SCRIPT (interp и arg заполнены,
 * arg — пустая строка, если довода нет) или -ENOEXEC. Без системных вызовов. */
int guest_script_parse(const char *buf, size_t len, char *interp, size_t interp_sz, char *arg, size_t arg_sz);

/* Открыть host_path, прочесть до GUEST_SCRIPT_BUF байт, разобрать. Возврат как у parse или -errno
 * (open/read/fstat; каталог → -EACCES). Дескриптор закрывается всегда. */
int guest_script_probe(const char *host_path, char *interp, size_t interp_sz, char *arg, size_t arg_sz);

#endif
