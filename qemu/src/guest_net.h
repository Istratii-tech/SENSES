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
// Changed: 2026-08-29 … 2026-09-21

/* guest_net.h — подставной netlink для гостевых служб (netd, vold). */
#ifndef GUEST_NET_H
#define GUEST_NET_H

/*
 * Подмена сокета, если настоящий создать не дали. Возвращает 1, когда подмена
 * состоялась (номер в *fd), и 0, когда этот случай не наш.
 */
int guest_net_socket_fallback(int domain, int type, int protocol, int *fd);

/*
 * Подмена уже созданного сокета, если ПРИВЯЗАТЬ его не дали. Возвращает 1,
 * когда подмена состоялась: за тем же номером дескриптора теперь стоит
 * безвредный AF_UNIX. Ноль — случай не наш.
 */
int guest_net_bind_fallback(int sockfd);

/* Наш ли это дескриптор (то есть подставной). */
int guest_net_owns(int fd);

/* Забыть дескриптор при закрытии (и закрыть наш конец пары). */
void guest_net_close(int fd);

/*
 * Ответить на то, что гость послал в подставной netlink. Возвращает 1, когда
 * ответ отправлен. Отправка гостю ВСЕГДА считается удавшейся: настоящий
 * netlink здесь ответил бы успехом. См. guest_net.c — без этого браузер
 * прошивки не рисует ни одной страницы.
 */
int guest_net_answer(int fd, const void *msg, size_t len);

/*
 * Гость привязал наш подставной сокет: запомнить номер порта и группы, чтобы
 * отвечать ему так, как ответило бы ядро. См. guest_net.c.
 */
void guest_net_bound(int fd, const void *addr, socklen_t len);

/*
 * Ответ на getsockname для подставного сокета: AF_NETLINK, наш номер порта.
 * Без этого `ip` прошивки отказывается работать на «Wrong address family».
 * 1 — ответ подставлен (*len = sizeof(struct sockaddr_nl)).
 */
int guest_net_sockname(int fd, void *addr, socklen_t cap, socklen_t *len);

/*
 * Адрес отправителя для только что принятого ответа: ядро (nl_pid = 0).
 * Без этого потребитель выбрасывает наш ответ как «пришёл не от ядра».
 * 1 — адрес подставлен (*len = sizeof(struct sockaddr_nl)).
 */
int guest_net_from_kernel(int fd, void *addr, socklen_t cap, socklen_t *len);

/*
 * Гость пишет запрос netlink в НЕ наш дескриптор — забрать сокет себе.
 * 1 — дескриптор теперь наш. Хозяин разрешает netlink создать и
 * привязать, но не даёт послать, поэтому подмены при socket/bind мало.
 */
int guest_net_adopt(int fd, const void *msg, size_t len);


/* Увести гостевое соединение (80/443/53) посреднику приложения — см. guest_net.c. */
void guest_http_redirect(int fd, void *addr, socklen_t addrlen);

/*
 * Подставить обратно адрес того сервера имён, которого гость спрашивал: иначе
 * резолвер bionic выбрасывает наш ответ как «не от того сервера».
 */
void guest_dns_unredirect(int fd, void *addr, socklen_t len);

#endif
