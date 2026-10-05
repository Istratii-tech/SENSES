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
// Changed: 2026-09-15

/* guest_pagelog.h — слежка за правами исполняемых страниц гостя (см. .c). */
#ifndef GUEST_PAGELOG_H
#define GUEST_PAGELOG_H

/* Включена ли слежка (есть ли GUEST_PAGE_LOG). Проверять ПЕРЕД сбором доводов. */
int guest_plog_on(void);

/* Строка в журнал. Сама добавляет номер процесса и перевод строки. */
void guest_plog(const char *fmt, ...) G_GNUC_PRINTF(1, 2);

/* Права страницы тремя буквами в свой буфер (нужно 5 байт): "rwx", "rw-", … */
const char *guest_plog_prot(int flags, char *buf);

/*
 * ★★★ Кольцо последних исполненных блоков перевода — по потоку.
 *
 * Нужно, чтобы узнать, ОТКУДА пришёл прыжок в никуда: отчёт о падении знает
 * только сам негодный адрес, а команда перехода стоит в конце предыдущего
 * блока. Кольцо заполняется в cpu_tb_exec и читается отчётом о падении.
 *
 * ⚠️ Полным оно бывает ТОЛЬКО при выключенном сцеплении блоков (`cmd nochain`):
 * иначе переходы между сцепленными блоками идут мимо cpu_tb_exec и в кольцо
 * не попадают. Сцепление стоит около нуля по скорости (109 кадр/с против 110),
 * так что на время разбора его не жалко.
 */
void guest_trace_push(uint64_t pc, unsigned size);

/* Блок номер back от конца (0 — самый свежий). Ноль, когда записей больше нет. */
int guest_trace_get(int back, uint64_t *pc, unsigned *size);

/* Снимок кольца в журнал — звать В МИГ ОТКАЗА (разбор в .c). */
void guest_trace_dump(void);

/* Просмотр свежезаписанного кода на негодные переходы (разбор в .c). */
void guest_check_code(uint64_t start, uint64_t end, uint64_t lr, uint64_t pc);

/* Сверка наблюдаемых слов; зовётся с каждым входом в блок (разбор в .c). */
void guest_watch_tick(void);

/* Выключить оптимизатор переводов (GUEST_NO_TCGOPT). */
int guest_no_tcgopt(void);

/* Не ставить ловушку на запись в страницы кода (GUEST_NO_SMC). */
int guest_no_smc(void);

/* Нужны ли строки про защиту страниц от записи (GUEST_PAGE_LOG_SMC). */
int guest_plog_smc(void);

#endif /* GUEST_PAGELOG_H */
