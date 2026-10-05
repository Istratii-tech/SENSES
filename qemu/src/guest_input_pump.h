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

/* guest_input_pump.h — сеансы поддельного /dev/input/event0 и их переносчики (Р-119).
 *
 * Сеанс — одно открытие устройства гостем: пара сокетов (конец A — гостю, конец B —
 * переносчику) и поток-переносчик, который подключается к сокету стенда (GUEST_INPUT)
 * и перекладывает оттуда гостю целые события. Ответы на ioctl — в guest_input.c.
 *
 * ★★ Беда Р-119 (№16, 7.1.1). В одном процессе гостя (system_server) жили два сеанса,
 * стенд закрывал прежнее соединение того же ПРОЦЕССА на каждом подключении, и сеансы
 * гоняли друг друга по кругу — 743 переподключения за запуск; события, попавшие в
 * закрываемое соединение, пропадали (у EventHub — последняя порция жеста, палец
 * «залипал»). Отсюда три правила этого файла.
 *
 * 1. ★ Переносчик живёт, пока жив ГОСТЕВОЙ КОНЕЦ пары, — и узнаёт об этом сам, от ядра.
 *    Прежде он узнавал о закрытии только через перехват close() (флаг live) и по ошибке
 *    записи. Закрытие мимо перехвата — dup2/dup3 поверх номера, close_range, закрытие
 *    при exec у того, кто держал копию, — оставляло его жить вечно: он держал соединение
 *    со стендом и переподключался после каждого разрыва, а его номер числился за сеансом.
 *    Теперь переносчик опрашивает и свой конец B: последнее закрытие конца A (любым
 *    путём, в любом процессе-держателе) — это конец файла на B, и переносчик уходит сразу.
 *    Перехват close() только снимает номер с сеанса; копия описателя (dup) держит
 *    устройство, как у ядра. Что гость пишет в устройство (светодиоды EV_LED), переносчик
 *    вычитывает и выбрасывает — иначе такая запись упиралась бы в полный буфер.
 * 2. ★ Номер описателя — не имя. Гостевой номер, ушедший мимо перехвата, ядро тут же
 *    отдаёт другому файлу. Сеанс признаёт номер своим, только если за ним ТОТ ЖЕ файл
 *    (устройство и индекс сокета A, снятые при открытии). Свои описатели переносчик
 *    закрывает так же — только если номер всё ещё его (гость мог закрыть и их).
 * 3. ★ Сразу после connect переносчик шлёт стенду ПРИВЕТСТВИЕ — одну строку ASCII:
 *
 *        IN1 <процесс> <рождение> <сеанс> <подключение> <описатель> <поток>\n
 *
 *    знак сеанса = процесс (getpid хозяина — тот же, что SO_PEERCRED у стенда) +
 *    рождение (монотонные часы первого открытия в этом образе процесса, шестнадцатерично:
 *    exec сохраняет номер процесса, но не рождение) + сеанс (счётчик открытий в образе,
 *    не повторяется). Подключение — номер подключения сеанса (1, 2, …), описатель —
 *    гостевой номер при открытии, поток — имя потока гостя, открывшего устройство
 *    (по нему видно, КТО открыл второй сеанс), только [A-Za-z0-9._:-], прочее — «_».
 *    Стенд по знаку отличает переподключение сеанса от второго сеанса того же процесса
 *    (Input.kt, InputHub.kt). Приветствие идёт переносчик → стенд, события — обратно:
 *    гость его не видит. Старый стенд сокет на чтение не открывает — строка лежит в
 *    приёмном буфере, вреда нет.
 *
 * ★ Файл не зависит от qemu: только libc и pthread; включает его один guest_input.c,
 * а хостовый cc на Маке гоняет native/test/test_input.c с поддельным сервером стенда.
 * Прокладка Мака — GI_SOCK_CLOEXEC 0 (нет SOCK_CLOEXEC; ставим FD_CLOEXEC сами) и
 * GI_THREAD_NAME (нет PR_GET_NAME).
 */
#ifndef GUEST_INPUT_PUMP_H
#define GUEST_INPUT_PUMP_H

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef GI_SOCK_CLOEXEC
#define GI_SOCK_CLOEXEC SOCK_CLOEXEC
#endif
#ifndef GI_THREAD_NAME
#include <sys/prctl.h>
#define GI_THREAD_NAME(buf, n) prctl(PR_GET_NAME, (unsigned long)(buf), 0, 0, 0)
#endif

/* Сроки, мс. Опрос — заодно проверка «стенд не отвечает»; передышка после разрыва — против
 * пинг-понга со старым стендом (см. gi_drop); повтор — пока стенд не слушает. */
#ifndef GI_POLL_MS
#define GI_POLL_MS 500
#endif
#ifndef GI_DROP_MS
#define GI_DROP_MS 200
#endif
#ifndef GI_RETRY_MS
#define GI_RETRY_MS 500
#endif

#define GI_EVSZ 16                  /* struct input_event 32-битного гостя */
#define GI_MAXSESS 8
#define GI_HELLO_FMT "IN1 %d %llx %u %u %d %s\n"

struct gi_sess {
    int used;
    int fd_guest;                   /* номер у гостя; −1 — гость его закрыл (через перехват) */
    int fd_feed;                    /* конец B: читает и пишет переносчик */
    dev_t dev_guest, dev_feed;      /* кто такие концы: номер мог уйти другому файлу */
    ino_t ino_guest, ino_feed;
    unsigned serial;                /* номер сеанса в образе процесса, не повторяется */
    unsigned conns;                 /* сколько раз подключался к стенду */
    char who[16];                   /* поток гостя, открывший устройство (уже очищенный) */
};

static struct gi_sess g_gi_sess[GI_MAXSESS];
static int g_gi_used;               /* сколько занято — без замка: у большинства процессов ноль */
static pthread_mutex_t g_gi_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_gi_path[512];
static unsigned g_gi_serial;
static unsigned long long g_gi_birth;

static inline void gi_set_path(const char *p)
{
    snprintf(g_gi_path, sizeof g_gi_path, "%s", p ? p : "");
}

static inline void gi_cloexec(int fd)
{
    if (GI_SOCK_CLOEXEC == 0 && fd >= 0) {
        fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
}

/* Тот ли файл под номером: 1 — тот (номер наш), 0 — номер закрыт или ушёл другому. */
static inline int gi_same(int fd, dev_t dev, ino_t ino)
{
    struct stat st;

    return fd >= 0 && fstat(fd, &st) == 0 && st.st_dev == dev && st.st_ino == ino;
}

/* Закрыть свой описатель — только если номер ещё наш (гость мог закрыть его и отдать другому). */
static inline void gi_close_own(int fd, dev_t dev, ino_t ino)
{
    if (gi_same(fd, dev, ino)) {
        close(fd);
    }
}

/* Сеанс по гостевому номеру; под g_gi_lock. Номер, за которым уже другой файл, снимается. */
static inline struct gi_sess *gi_find_locked(int fd)
{
    if (fd < 0) {
        return NULL;
    }
    for (int i = 0; i < GI_MAXSESS; i++) {
        struct gi_sess *s = &g_gi_sess[i];

        if (s->used && s->fd_guest == fd) {
            if (gi_same(fd, s->dev_guest, s->ino_guest)) {
                return s;
            }
            s->fd_guest = -1;       /* закрыт мимо перехвата — номер больше не наш */
        }
    }
    return NULL;
}

/*
 * Есть ли у процесса сеансы вообще. ★ Перехват ioctl и close зовёт нас на КАЖДЫЙ вызов
 * любого описателя (binder — тысячи в секунду); у процессов без устройства ввода —
 * одно чтение без замка.
 */
static inline int gi_any(void)
{
    return __atomic_load_n(&g_gi_used, __ATOMIC_ACQUIRE) != 0;
}

static inline int gi_owns(int fd)
{
    if (!gi_any()) {
        return 0;
    }
    pthread_mutex_lock(&g_gi_lock);
    int r = gi_find_locked(fd) != NULL;
    pthread_mutex_unlock(&g_gi_lock);
    return r;
}

/* Сколько сеансов занято (переносчик ещё не ушёл). */
static inline int gi_count(void)
{
    int n = 0;

    pthread_mutex_lock(&g_gi_lock);
    for (int i = 0; i < GI_MAXSESS; i++) {
        n += g_gi_sess[i].used;
    }
    pthread_mutex_unlock(&g_gi_lock);
    return n;
}

/* Конец B сеанса по гостевому номеру (для проверки); −1 — не наш. */
static inline int gi_feed_of(int fd)
{
    pthread_mutex_lock(&g_gi_lock);
    struct gi_sess *s = gi_find_locked(fd);
    int r = s ? s->fd_feed : -1;
    pthread_mutex_unlock(&g_gi_lock);
    return r;
}

/* Имя потока для приветствия: только [A-Za-z0-9._:-], прочее — «_»; пустое — «-». */
static inline void gi_clean_name(char *dst, size_t cap, const char *src)
{
    size_t n = 0;

    for (; src && *src && n + 1 < cap; src++) {
        unsigned char c = (unsigned char)*src;
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 c == '.' || c == '_' || c == ':' || c == '-';
        dst[n++] = ok ? (char)c : '_';
    }
    if (n == 0 && cap > 1) {
        dst[n++] = '-';
    }
    dst[n] = 0;
}

/* Строка приветствия; длина или −1. */
static inline int gi_hello(char *buf, size_t cap, const struct gi_sess *s, int fd_guest, unsigned conn)
{
    int n = snprintf(buf, cap, GI_HELLO_FMT, (int)getpid(), g_gi_birth, s->serial, conn, fd_guest, s->who);

    return (n > 0 && (size_t)n < cap) ? n : -1;
}

/* Записать целиком: частичная запись сдвинула бы поток событий на неполное событие. */
static inline int gi_write_all(int fd, const void *p, size_t n)
{
    const uint8_t *b = p;

    while (n) {
        ssize_t w = write(fd, b, n);

        if (w <= 0) {
            if (w < 0 && errno == EINTR) {
                continue;
            }
            return -1;
        }
        b += w;
        n -= (size_t)w;
    }
    return 0;
}

/*
 * Конец B готов к чтению: либо гость что-то написал в устройство (выбрасываем), либо
 * гостевой конец закрыт ВЕЗДЕ (конец файла). 1 — закрыт.
 */
static inline int gi_feed_gone(int feed, short revents)
{
    uint8_t junk[512];

    if (revents & (POLLERR | POLLNVAL)) {
        return 1;
    }
    /* Не больше 64 порций за раз: гость, пишущий без остановки, не должен отнять у
     * переносчика стенд. Остальное вычитаем на следующем пробуждении. */
    for (int i = 0; i < 64; i++) {
        ssize_t n = recv(feed, junk, sizeof junk, MSG_DONTWAIT);

        if (n > 0) {
            continue;               /* EV_LED и прочее от гостя — устройству не нужно */
        }
        if (n == 0) {
            return 1;
        }
        if (errno == EINTR) {
            continue;
        }
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : 1;
    }
    return 0;
}

/* Подождать ms, следя за гостевым концом. 1 — гость закрыл устройство (или номер конца B
 * уже не наш: гость закрыл и его). */
static inline int gi_wait_feed(const struct gi_sess *s, int ms)
{
    struct pollfd p = { s->fd_feed, POLLIN, 0 };
    int r = poll(&p, 1, ms);

    if (!gi_same(s->fd_feed, s->dev_feed, s->ino_feed)) {
        return 1;
    }
    if (r > 0) {
        return gi_feed_gone(s->fd_feed, p.revents);
    }
    return 0;
}

/* Подключиться к стенду и поздороваться; описатель или −1. */
static inline int gi_connect(struct gi_sess *s, int fd_guest, ino_t *ino, dev_t *dev)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | GI_SOCK_CLOEXEC, 0);
    struct sockaddr_un a;
    struct stat st;
    char h[160];

    if (fd < 0) {
        return -1;
    }
    gi_cloexec(fd);
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", g_gi_path);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0 || fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    unsigned conn = __atomic_add_fetch(&s->conns, 1, __ATOMIC_SEQ_CST);
    int n = gi_hello(h, sizeof h, s, fd_guest, conn);
    if (n < 0 || gi_write_all(fd, h, (size_t)n) < 0) {
        close(fd);
        return -1;
    }
    *ino = st.st_ino;
    *dev = st.st_dev;
    return fd;
}

/*
 * Разрыв связи со стендом — с передышкой.
 *
 * ⚠️ Без паузы со СТАРЫМ стендом (правило «один процесс — одно соединение») получается
 * пинг-понг сотни раз в секунду. Передышку ждём на своём конце пары: гость, закрывший
 * устройство в это время, отпускает переносчик сразу. 1 — гость закрыл устройство.
 */
static inline int gi_drop(int *app, dev_t dev, ino_t ino, const struct gi_sess *s)
{
    if (*app >= 0) {
        gi_close_own(*app, dev, ino);
        *app = -1;
    }
    return gi_wait_feed(s, GI_DROP_MS);
}

/*
 * Переносчик: сокет стенда → гостю, целыми событиями; и сторож гостевого конца.
 *
 * ⚠️ Стенд ждём САМИ и повторяем попытку: EventHub открывает устройство один раз при
 * старте system_server, и если стенд в этот миг ещё не слушает, второй попытки у гостя
 * не будет.
 */
static inline void *gi_pump(void *arg)
{
    struct gi_sess *s = arg;
    uint8_t buf[GI_EVSZ * 64];
    size_t have = 0;
    int app = -1;
    dev_t app_dev = 0;
    ino_t app_ino = 0;
    int feed = s->fd_feed;
    int fd_guest = s->fd_guest;     /* номер при открытии — для приветствия */

    for (;;) {
        if (app < 0) {
            app = gi_connect(s, fd_guest, &app_ino, &app_dev);
            if (app < 0) {
                if (gi_wait_feed(s, GI_RETRY_MS)) {
                    break;
                }
                continue;
            }
            have = 0;
        }
        struct pollfd p[2] = { { app, POLLIN, 0 }, { feed, POLLIN, 0 } };
        int r = poll(p, 2, GI_POLL_MS);
        int perr = errno;
        /*
         * ⚠️ Оба номера — в общей таблице описателей гостя. Гость с ошибкой может закрыть и
         * наши (номер он считает своим) — и номер тут же уйдёт его же новому файлу: мы бы
         * читали его данные и писали в него события. Поэтому на каждом пробуждении —
         * проверка, что за номерами всё те же сокеты.
         */
        if (!gi_same(feed, s->dev_feed, s->ino_feed)) {
            break;
        }
        if (!gi_same(app, app_dev, app_ino)) {
            app = -1;               /* соединение у нас отняли — не закрываем чужое, подключаемся снова */
            continue;
        }
        if (r < 0) {
            if (perr != EINTR && gi_drop(&app, app_dev, app_ino, s)) {
                break;
            }
            continue;
        }
        if (r == 0) {
            continue;
        }
        if (p[1].revents && gi_feed_gone(feed, p[1].revents)) {
            break;                  /* гостевой конец закрыт — любым путём */
        }
        if (!p[0].revents) {
            continue;
        }
        ssize_t n = read(app, buf + have, sizeof buf - have);
        if (n <= 0) {
            if (n < 0 && (errno == EINTR || errno == EAGAIN)) {
                continue;
            }
            if (gi_drop(&app, app_dev, app_ino, s)) {
                break;
            }
            continue;
        }
        have += (size_t)n;
        size_t whole = have - have % GI_EVSZ;
        if (whole) {
            if (gi_write_all(feed, buf, whole) < 0) {
                break;              /* гость закрыл устройство */
            }
            memmove(buf, buf + whole, have - whole);
            have -= whole;
        }
    }
    if (app >= 0) {
        gi_close_own(app, app_dev, app_ino);
    }
    pthread_mutex_lock(&g_gi_lock);
    gi_close_own(s->fd_feed, s->dev_feed, s->ino_feed);
    s->fd_feed = -1;
    s->fd_guest = -1;
    s->used = 0;
    __atomic_sub_fetch(&g_gi_used, 1, __ATOMIC_RELEASE);
    pthread_mutex_unlock(&g_gi_lock);
    return NULL;
}

/*
 * Поток заводим с ЗАКРЫТЫМИ сигналами.
 *
 * ⚠️ Сигналы в qemu-user принадлежат гостю: их ловит его обработчик и доставляет
 * транслируемому коду. Хозяйский поток, которому такой сигнал достанется, полез бы в
 * состояние процессора гостя, которого у него нет. Так же поступает и сам qemu.
 */
static inline int gi_spawn(struct gi_sess *s)
{
    sigset_t all, old;
    pthread_t th;

    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, &old);
    int rc = pthread_create(&th, NULL, gi_pump, s);
    pthread_sigmask(SIG_SETMASK, &old, NULL);
    if (rc != 0) {
        return -1;
    }
    pthread_detach(th);
    return 0;
}

/* Открыть сеанс: 0 и гостевой конец в *fd, или −1 и errno. */
static inline int gi_open(int *fd)
{
    int sv[2];
    struct stat a, b;
    char name[32] = { 0 };

    *fd = -1;
    /* ⚠️ CLOEXEC: описатель поддельного экрана не должен переживать execve. */
    if (socketpair(AF_UNIX, SOCK_STREAM | GI_SOCK_CLOEXEC, 0, sv) < 0) {
        return -1;
    }
    gi_cloexec(sv[0]);
    gi_cloexec(sv[1]);
    if (fstat(sv[0], &a) < 0 || fstat(sv[1], &b) < 0) {
        int e = errno;
        close(sv[0]);
        close(sv[1]);
        errno = e;
        return -1;
    }
    GI_THREAD_NAME(name, sizeof name);
    name[sizeof name - 1] = 0;

    pthread_mutex_lock(&g_gi_lock);
    struct gi_sess *s = NULL;
    for (int i = 0; i < GI_MAXSESS; i++) {
        if (!g_gi_sess[i].used) {
            s = &g_gi_sess[i];
            break;
        }
    }
    if (s) {
        if (!g_gi_birth) {
            struct timespec t;

            clock_gettime(CLOCK_MONOTONIC, &t);
            g_gi_birth = (unsigned long long)t.tv_sec * 1000000000ULL + (unsigned long long)t.tv_nsec;
            if (!g_gi_birth) {
                g_gi_birth = 1;
            }
        }
        memset(s, 0, sizeof *s);
        s->used = 1;
        s->fd_guest = sv[0];
        s->fd_feed = sv[1];
        s->dev_guest = a.st_dev;
        s->ino_guest = a.st_ino;
        s->dev_feed = b.st_dev;
        s->ino_feed = b.st_ino;
        s->serial = ++g_gi_serial;
        gi_clean_name(s->who, sizeof s->who, name);
        __atomic_add_fetch(&g_gi_used, 1, __ATOMIC_RELEASE);
    }
    pthread_mutex_unlock(&g_gi_lock);
    if (!s) {
        close(sv[0]);
        close(sv[1]);
        errno = ENFILE;
        return -1;
    }
    if (gi_spawn(s) < 0) {
        pthread_mutex_lock(&g_gi_lock);
        s->used = 0;
        __atomic_sub_fetch(&g_gi_used, 1, __ATOMIC_RELEASE);
        pthread_mutex_unlock(&g_gi_lock);
        close(sv[0]);
        close(sv[1]);
        errno = EAGAIN;
        return -1;
    }
    *fd = sv[0];
    return 0;
}

/*
 * Перехват close(): номер больше не наш. Переносчика не трогаем — он уйдёт сам по концу
 * файла на своём конце, как только закроется ПОСЛЕДНЯЯ копия гостевого конца (её может
 * держать dup или потомок до exec).
 */
static inline void gi_close(int fd)
{
    if (!gi_any()) {
        return;
    }
    pthread_mutex_lock(&g_gi_lock);
    struct gi_sess *s = gi_find_locked(fd);

    if (s) {
        s->fd_guest = -1;
    }
    pthread_mutex_unlock(&g_gi_lock);
}

#endif /* GUEST_INPUT_PUMP_H */
