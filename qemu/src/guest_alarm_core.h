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

/* guest_alarm_core.h — устройство /dev/alarm гостя на таймерах хозяина (Р-120): сторона хозяина.
 * Разбор номеров ioctl, состояние устройства и его команды; память гостя, описатель устройства и
 * сигналы — у вызывающего (guest_alarm.c).
 *
 * ★★ Зачем. Служба будильников Android 2.3–6.0 ставит и ждёт будильники через /dev/alarm (7.x — тоже,
 * если он открывается; иначе она берёт timerfd на часах *_ALARM, которых приложению не дают — нет
 * CAP_WAKE_ALARM). Устройства у гостя не было, и служба уходила в запасной путь «для эмулятора без
 * драйвера» («Failed to open alarm driver. Falling back to a handler.»): он ставит ОДНО сообщение на срок
 * последнего заведённого будильника и в часах uptime. У будильника по настенным часам (RTC) срок —
 * миллисекунды эпохи, то есть годы вперёд, так что часы строки состояния стояли (`TIME_TICK` просрочен на
 * 14 мин, «Pending alarm batches: 9» в `dumpsys alarm`). Замер №1 (4.2) 23.09, №16 (7.1.1) 06.10.
 * Кроме будильников: 2.3–4.x читают через /dev/alarm и `SystemClock.elapsedRealtime()`
 * (ANDROID_ALARM_GET_TIME(ELAPSED_REALTIME), открытие O_RDONLY в каждом процессе); без устройства они
 * брали часы uptime без времени сна.
 *
 * ★ Ответы — как у ядра Android (drivers/staging/android/alarm-dev.c, include/uapi/linux/android_alarm.h),
 * для 32-битного гостя (`struct timespec` — два 32-битных слова, номера с размером 8):
 *   ANDROID_ALARM_CLEAR(t)          _IO('a', 0 | t<<4)        снять будильник типа t и его невыданное срабатывание
 *   ANDROID_ALARM_WAIT              _IO('a', 1)               ждать, пока сработает хоть один; вернуть МАСКУ
 *                                                              сработавших (бит t — тип t) и забыть её
 *   ANDROID_ALARM_SET(t)            _IOW('a', 2 | t<<4, ts)   завести срок (абсолютный, в часах типа t)
 *   ANDROID_ALARM_SET_AND_WAIT(t)   _IOW('a', 3 | t<<4, ts)   то и другое
 *   ANDROID_ALARM_GET_TIME(t)       _IOW('a', 4 | t<<4, ts)   время часов типа t (гостю — в довод)
 *   ANDROID_ALARM_SET_RTC           _IOW('a', 5, ts)          перевести часы — гость не может: EPERM
 * Типы: 0 RTC_WAKEUP, 1 RTC, 2 ELAPSED_REALTIME_WAKEUP, 3 ELAPSED_REALTIME, 4 SYSTEMTIME (часы —
 * CLOCK_REALTIME, CLOCK_REALTIME, CLOCK_BOOTTIME, CLOCK_BOOTTIME, CLOCK_MONOTONIC), 5 POWER_OFF_WAKEUP
 * (есть у части ядер изготовителей; принят как RTC_WAKEUP: настенные часы, бит 0, но свой срок — не делит
 * его с типом 0). Тип в номере — биты 4–7 поля nr; ядро сводит команду к базовой маской `~0xf0`, и тип
 * больше пяти — EINVAL при любой команде (проверяется раньше разбора команды). Мусорный номер — EINVAL
 * (`default:` ядра). Старые номера с секундами вместо timespec (SET_OLD / SET_AND_WAIT_OLD, 4 байта) — тип
 * RTC_WAKEUP, как у ядра.
 *
 * ★ Состояние — как у ядра: на каждое открытие СВОЁ (ядро держало одно на всё устройство и отвечало EBUSY
 * второму хозяину; служба будильников — один процесс, а читатели часов не ставят ничего). Срок срабатывает →
 * бит «выдать» (pend) этого типа, срок снят (armed = 0). WAIT отдаёт все такие биты разом и стирает их;
 * SET того же типа невыданное срабатывание НЕ стирает (так у ядра), CLEAR — стирает.
 *
 * ★ Хозяин — timerfd (CLOCK_REALTIME / CLOCK_BOOTTIME / CLOCK_MONOTONIC, абсолютный срок; *_ALARM
 * приложению не дают) и ppoll. Подводные камни timerfd, которые решение обходит:
 *  - срок {0, 0} timerfd понимает как СНЯТИЕ таймера, а у ядра будильников нуль — давно прошедший срок и
 *    срабатывает сразу: нулевой срок и срок до эпохи заменяются на 1 нс (ga_abs);
 *  - повторная установка timerfd СБРАСЫВАЕТ невычитанное срабатывание, а ядро будильников его хранит
 *    до WAIT. Поэтому SET смотрит на ответ самой установки (старое значение таймера: ненулевой остаток —
 *    был взведён и не сработал в миг обмена): таймер, который мы считали взведённым, а он уже нет, —
 *    сработал и стёрт установкой, срабатывание записывается в «выдать» (одно решение на оба случая:
 *    сработал давно или в миг установки);
 *  - таймеры заводятся при первом же SET / SET_AND_WAIT / WAIT, а не при открытии: каждый процесс
 *    2.3–4.x открывает /dev/alarm ради GET_TIME, и шесть лишних описателей на процесс — зря. Заведённый
 *    набор неизменен до закрытия, поэтому ждущий WAIT видит и будильник, который другой поток поставит
 *    потом (так служба будильников и работает: ждёт в одном потоке, ставит из других).
 *
 * ★ Ожидание WAIT — ppoll по всем таймерам, БЕЗ повтора по EINTR: -1 с errno как есть. Транслятор зовёт его
 * через safe_syscall (guest_alarm.c, GA_POLL): сигнал гостя прерывает ожидание (EINTR, либо
 * QEMU_ERESTARTSYS — вызов перезапустится после обработчика); прошивка сама повторяет WAIT по EINTR.
 *
 * ⚠️ Предел: смену настенных часов (бит TIME_CHANGE, 1 << 16) не сообщаем — хозяин часов не переводит.
 *
 * ★ Файл не зависит от qemu: только libc. Вызовы хозяина — через GA_* (по умолчанию Linux: timerfd, poll,
 * clock_gettime), поэтому решение гоняется хостовым cc на Маке с прокладкой (native/test/test_alarm.c).
 * Всё — static inline.
 */
#ifndef GUEST_ALARM_CORE_H
#define GUEST_ALARM_CORE_H

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* Типы будильников ядра Android; последний — POWER_OFF_WAKEUP. */
enum {
    GA_RTC_WAKEUP = 0,
    GA_RTC = 1,
    GA_ELAPSED_REALTIME_WAKEUP = 2,
    GA_ELAPSED_REALTIME = 3,
    GA_SYSTEMTIME = 4,
    GA_POWER_OFF_WAKEUP = 5,
    GA_TYPES = 6
};

/* Часы хозяина: настенные, «с загрузки» (со временем сна), монотонные. */
enum { GA_CLK_REAL = 0, GA_CLK_BOOT = 1, GA_CLK_MONO = 2 };

/*
 * Вызовы хозяина. Ошибка — -1 с errno.
 *   GA_TIMER_NEW(clk)        новый таймер (неблокирующий, close-on-exec) на часах clk → описатель
 *   GA_TIMER_ARM(fd, abs)    взвести на абсолютный срок abs (НЕ нулевой); сбрасывает невычитанное срабатывание;
 *                            1 — таймер был взведён и не сработал к моменту обмена, 0 — нет
 *   GA_TIMER_DISARM(fd)      снять; тот же ответ
 *   GA_TIMER_DRAIN(fd)       вычитать срабатывание без ожидания: 1 — было, 0 — нет
 *   GA_CLOSE(fd)             закрыть
 *   GA_NOW(clk, ts)          время часов clk
 *   GA_POLL(fds, n)          ждать без потолка, пока готов хоть один; -1 + errno (EINTR) — как у poll
 */
#ifndef GA_TIMER_NEW
#include <sys/timerfd.h>
#include <unistd.h>

static inline int ga_host_clock(int clk)
{
    return clk == GA_CLK_BOOT ? CLOCK_BOOTTIME : clk == GA_CLK_MONO ? CLOCK_MONOTONIC : CLOCK_REALTIME;
}

static inline int ga_host_timer_new(int clk)
{
    return timerfd_create(ga_host_clock(clk), TFD_NONBLOCK | TFD_CLOEXEC);
}

/* Обмен значения: abs == NULL — снять. Ответ — был ли таймер взведён (остаток старого значения не нуль). */
static inline int ga_host_timer_swap(int fd, const struct timespec *abs)
{
    struct itimerspec n, old;

    memset(&n, 0, sizeof n);
    memset(&old, 0, sizeof old);
    if (abs) {
        n.it_value = *abs;
    }
    if (timerfd_settime(fd, abs ? TFD_TIMER_ABSTIME : 0, &n, &old) < 0) {
        return -1;
    }
    return (old.it_value.tv_sec != 0 || old.it_value.tv_nsec != 0) ? 1 : 0;
}

static inline int ga_host_timer_drain(int fd)
{
    uint64_t ticks;
    ssize_t r = read(fd, &ticks, sizeof ticks);

    if (r == (ssize_t)sizeof ticks) {
        return 1;
    }
    if (r < 0 && errno == EAGAIN) {
        return 0;
    }
    if (r >= 0) {
        errno = EIO;
    }
    return -1;
}

#define GA_TIMER_NEW(clk)       ga_host_timer_new(clk)
#define GA_TIMER_ARM(fd, abs)   ga_host_timer_swap(fd, abs)
#define GA_TIMER_DISARM(fd)     ga_host_timer_swap(fd, NULL)
#define GA_TIMER_DRAIN(fd)      ga_host_timer_drain(fd)
#define GA_CLOSE(fd)            close(fd)
#define GA_NOW(clk, ts)         clock_gettime(ga_host_clock(clk), ts)
#endif

#ifndef GA_POLL
#define GA_POLL(fds, n)         poll((fds), (nfds_t)(n), -1)
#endif

/* Команды, которые устройство понимает после разбора номера. */
enum {
    GA_OP_NONE = 0,
    GA_OP_CLEAR,
    GA_OP_WAIT,
    GA_OP_SET,
    GA_OP_SET_WAIT,
    GA_OP_GET_TIME,
    GA_OP_SET_RTC,
    GA_OP_SET_OLD,            /* секунды вместо timespec: 4 байта, тип RTC_WAKEUP */
    GA_OP_SET_WAIT_OLD,
    GA_OP_CLOEXEC,            /* FIOCLEX — общий ioctl файла, делает вызывающий */
    GA_OP_NOCLOEXEC,          /* FIONCLEX */
    GA_OP_NOP                 /* FIONBIO, FIOASYNC — успех без действия */
};

typedef struct {
    int op;
    int type;
} GaCmd;

/* Номера Linux/ARM (<asm-generic/ioctl.h>): nr — биты 0–7, тип — 8–15, размер — 16–29, направление «запись» — 1 << 30. */
#define GA_IO(nr)           ((0x61u << 8) | (uint32_t)(nr))
#define GA_IOW(nr, size)    ((1u << 30) | ((uint32_t)(size) << 16) | (0x61u << 8) | (uint32_t)(nr))

/*
 * Разбор номера. 0 — разобран (*c); -1 + EINVAL — не наш или тип больше пяти.
 * Ядро: тип из nr >> 4 проверяется ДО команды; команда — по номеру с обнулёнными битами 4–7.
 */
static inline int ga_decode(uint32_t cmd, GaCmd *c)
{
    uint32_t base;
    unsigned type;

    c->op = GA_OP_NONE;
    c->type = 0;
    /* Общие ioctl файла (их ядро обрабатывает раньше драйвера). */
    if (cmd == 0x5451u) {
        c->op = GA_OP_CLOEXEC;
        return 0;
    }
    if (cmd == 0x5450u) {
        c->op = GA_OP_NOCLOEXEC;
        return 0;
    }
    if (cmd == 0x5421u || cmd == 0x5452u) {
        c->op = GA_OP_NOP;
        return 0;
    }
    type = (cmd & 0xffu) >> 4;
    if (type >= GA_TYPES) {
        errno = EINVAL;
        return -1;
    }
    /* Старые номера (секунды): без типа, как у ядра — тип RTC_WAKEUP. */
    if (cmd == GA_IOW(2, 4)) {
        c->op = GA_OP_SET_OLD;
        return 0;
    }
    if (cmd == GA_IOW(3, 4)) {
        c->op = GA_OP_SET_WAIT_OLD;
        return 0;
    }
    base = cmd & ~0xf0u;
    c->type = (int)type;
    if (base == GA_IO(0)) {
        c->op = GA_OP_CLEAR;
    } else if (base == GA_IO(1)) {
        c->op = GA_OP_WAIT;
    } else if (base == GA_IOW(2, 8)) {
        c->op = GA_OP_SET;
    } else if (base == GA_IOW(3, 8)) {
        c->op = GA_OP_SET_WAIT;
    } else if (base == GA_IOW(4, 8)) {
        c->op = GA_OP_GET_TIME;
    } else if (base == GA_IOW(5, 8)) {
        c->op = GA_OP_SET_RTC;
    } else {
        c->type = 0;
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/* Довод команды: сколько байт гостевой памяти, читать ли их у гостя, писать ли гостю. */
static inline int ga_arg_size(const GaCmd *c)
{
    switch (c->op) {
    case GA_OP_SET:
    case GA_OP_SET_WAIT:
    case GA_OP_GET_TIME:
    case GA_OP_SET_RTC:
        return 8;
    case GA_OP_SET_OLD:
    case GA_OP_SET_WAIT_OLD:
        return 4;
    default:
        return 0;
    }
}

static inline int ga_arg_in(const GaCmd *c)
{
    return c->op == GA_OP_SET || c->op == GA_OP_SET_WAIT || c->op == GA_OP_SET_RTC ||
           c->op == GA_OP_SET_OLD || c->op == GA_OP_SET_WAIT_OLD;
}

static inline int ga_arg_out(const GaCmd *c)
{
    return c->op == GA_OP_GET_TIME;
}

/* timespec 32-битного гостя ARM: два слова, младшим байтом вперёд. */
static inline int32_t ga_le32(const uint8_t *b)
{
    return (int32_t)((uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24));
}

static inline void ga_ts_load32(const uint8_t *b, struct timespec *ts)
{
    ts->tv_sec = (time_t)ga_le32(b);
    ts->tv_nsec = (long)ga_le32(b + 4);
}

static inline void ga_ts_store32(uint8_t *b, const struct timespec *ts)
{
    uint32_t s = (uint32_t)ts->tv_sec;
    uint32_t n = (uint32_t)ts->tv_nsec;

    for (int i = 0; i < 4; i++) {
        b[i] = (uint8_t)(s >> (8 * i));
        b[4 + i] = (uint8_t)(n >> (8 * i));
    }
}

/*
 * Срок гостя → срок для timerfd: наносекунды приведены к [0, 1e9); срок до эпохи и {0, 0} — 1 нс
 * («давно прошёл», срабатывает сразу). Нуль timerfd понимает как снятие таймера.
 */
static inline void ga_abs(const struct timespec *in, struct timespec *out)
{
    int64_t sec = (int64_t)in->tv_sec;
    int64_t nsec = (int64_t)in->tv_nsec;

    sec += nsec / 1000000000;
    nsec %= 1000000000;
    if (nsec < 0) {
        nsec += 1000000000;
        sec--;
    }
    if (sec < 0 || (sec == 0 && nsec == 0)) {
        sec = 0;
        nsec = 1;
    }
    out->tv_sec = (time_t)sec;
    out->tv_nsec = (long)nsec;
}

/* Часы типа и бит типа в маске WAIT (тип 5 — бит RTC_WAKEUP). */
static inline int ga_type_clock(int type)
{
    return (type == GA_ELAPSED_REALTIME_WAKEUP || type == GA_ELAPSED_REALTIME) ? GA_CLK_BOOT :
           type == GA_SYSTEMTIME ? GA_CLK_MONO : GA_CLK_REAL;
}

static inline unsigned ga_type_bit(int type)
{
    return 1u << (type == GA_POWER_OFF_WAKEUP ? GA_RTC_WAKEUP : type);
}

/* Одно открытие устройства. Статическое: замок заводится сразу, структуру не освобождают. */
typedef struct {
    pthread_mutex_t lock;
    int open;                       /* открыто и не закрыто */
    int started;                    /* таймеры заведены */
    unsigned gen;                   /* номер открытия: ждущий WAIT узнаёт, что устройство закрыли/открыли заново */
    int fd[GA_TYPES];               /* таймеры хозяина по типам */
    int armed[GA_TYPES];            /* срок заведён и не сработал (по нашему учёту) */
    int pend[GA_TYPES];             /* сработал, WAIT ещё не выдал */
} GaDev;

#define GA_DEV_INITIALIZER { PTHREAD_MUTEX_INITIALIZER, 0, 0, 0, { 0 }, { 0 }, { 0 } }

static inline int ga_dev_open(GaDev *d)
{
    pthread_mutex_lock(&d->lock);
    d->open = 1;
    d->started = 0;
    d->gen++;
    memset(d->fd, 0, sizeof d->fd);
    memset(d->armed, 0, sizeof d->armed);
    memset(d->pend, 0, sizeof d->pend);
    pthread_mutex_unlock(&d->lock);
    return 0;
}

static inline void ga_dev_close(GaDev *d)
{
    pthread_mutex_lock(&d->lock);
    if (d->open) {
        if (d->started) {
            for (int t = 0; t < GA_TYPES; t++) {
                GA_CLOSE(d->fd[t]);
            }
        }
        d->open = 0;
        d->started = 0;
        d->gen++;
    }
    pthread_mutex_unlock(&d->lock);
}

/* Завести таймеры, если ещё нет. Замок держит вызывающий. */
static inline int ga_start_locked(GaDev *d)
{
    if (d->started) {
        return 0;
    }
    for (int t = 0; t < GA_TYPES; t++) {
        d->fd[t] = GA_TIMER_NEW(ga_type_clock(t));
        if (d->fd[t] < 0) {
            int e = errno;

            while (--t >= 0) {
                GA_CLOSE(d->fd[t]);
            }
            errno = e;
            return -1;
        }
    }
    d->started = 1;
    return 0;
}

/* Вычитать сработавший таймер типа t в «выдать». Замок держит вызывающий. */
static inline void ga_drain_locked(GaDev *d, int t)
{
    if (GA_TIMER_DRAIN(d->fd[t]) > 0) {
        d->pend[t] = 1;
        d->armed[t] = 0;
    }
}

static inline int ga_dev_set(GaDev *d, int type, const struct timespec *ts)
{
    struct timespec abs;
    int was;

    ga_abs(ts, &abs);
    pthread_mutex_lock(&d->lock);
    if (!d->open) {
        pthread_mutex_unlock(&d->lock);
        errno = EBADF;
        return -1;
    }
    if (ga_start_locked(d) < 0) {
        int e = errno;

        pthread_mutex_unlock(&d->lock);
        errno = e;
        return -1;
    }
    was = GA_TIMER_ARM(d->fd[type], &abs);
    if (was < 0) {
        int e = errno;

        pthread_mutex_unlock(&d->lock);
        errno = e;
        return -1;
    }
    /* Считали «взведён, не сработал», а к обмену уже нет: срабатывание сброшено самой установкой — вернуть. */
    if (d->armed[type] && !was) {
        d->pend[type] = 1;
    }
    d->armed[type] = 1;
    pthread_mutex_unlock(&d->lock);
    return 0;
}

static inline int ga_dev_clear(GaDev *d, int type)
{
    pthread_mutex_lock(&d->lock);
    if (!d->open) {
        pthread_mutex_unlock(&d->lock);
        errno = EBADF;
        return -1;
    }
    if (d->started) {
        if (GA_TIMER_DISARM(d->fd[type]) < 0) {
            int e = errno;

            pthread_mutex_unlock(&d->lock);
            errno = e;
            return -1;
        }
        (void)GA_TIMER_DRAIN(d->fd[type]);
    }
    d->armed[type] = 0;
    d->pend[type] = 0;
    pthread_mutex_unlock(&d->lock);
    return 0;
}

/* Маска сработавших (≥ 1) или -1 + errno (EINTR / QEMU_ERESTARTSYS — сигнал гостя; EBADF — устройство закрыли). */
static inline long ga_dev_wait(GaDev *d)
{
    unsigned gen;

    pthread_mutex_lock(&d->lock);
    if (!d->open) {
        pthread_mutex_unlock(&d->lock);
        errno = EBADF;
        return -1;
    }
    if (ga_start_locked(d) < 0) {
        int e = errno;

        pthread_mutex_unlock(&d->lock);
        errno = e;
        return -1;
    }
    gen = d->gen;
    pthread_mutex_unlock(&d->lock);
    for (;;) {
        struct pollfd p[GA_TYPES];
        unsigned mask = 0;
        int r;

        pthread_mutex_lock(&d->lock);
        if (!d->open || d->gen != gen) {
            pthread_mutex_unlock(&d->lock);
            errno = EBADF;
            return -1;
        }
        for (int t = 0; t < GA_TYPES; t++) {
            ga_drain_locked(d, t);
            if (d->pend[t]) {
                mask |= ga_type_bit(t);
                d->pend[t] = 0;
            }
        }
        if (mask) {
            pthread_mutex_unlock(&d->lock);
            return (long)mask;
        }
        for (int t = 0; t < GA_TYPES; t++) {
            p[t].fd = d->fd[t];
            p[t].events = POLLIN;
            p[t].revents = 0;
        }
        pthread_mutex_unlock(&d->lock);
        r = GA_POLL(p, GA_TYPES);
        if (r < 0) {
            return -1;
        }
        for (int t = 0; t < GA_TYPES; t++) {
            if (p[t].revents & (POLLNVAL | POLLERR)) {
                errno = EBADF;
                return -1;
            }
        }
    }
}

static inline int ga_dev_time(int type, struct timespec *ts)
{
    if (type < 0 || type >= GA_TYPES) {
        errno = EINVAL;
        return -1;
    }
    return GA_NOW(ga_type_clock(type), ts);
}

/*
 * Выполнить разобранную команду. arg — host-буфер длины ga_arg_size(c): для команд «в хозяина»
 * (ga_arg_in) уже заполнен вызывающим, для GET_TIME заполняется здесь. Ответ: ≥ 0 или -1 + errno.
 * Общие ioctl файла (GA_OP_CLOEXEC и прочие) делает вызывающий, не мы.
 */
static inline long ga_exec(GaDev *d, const GaCmd *c, uint8_t *arg)
{
    struct timespec ts;

    switch (c->op) {
    case GA_OP_CLEAR:
        return ga_dev_clear(d, c->type) < 0 ? -1 : 0;
    case GA_OP_WAIT:
        return ga_dev_wait(d);
    case GA_OP_SET:
    case GA_OP_SET_WAIT:
        ga_ts_load32(arg, &ts);
        break;
    case GA_OP_SET_OLD:
    case GA_OP_SET_WAIT_OLD:
        ts.tv_sec = (time_t)ga_le32(arg);
        ts.tv_nsec = 0;
        break;
    case GA_OP_GET_TIME:
        if (ga_dev_time(c->type, &ts) < 0) {
            return -1;
        }
        ga_ts_store32(arg, &ts);
        return 0;
    case GA_OP_SET_RTC:
        errno = EPERM;                  /* часы телефона гость не переводит */
        return -1;
    default:
        errno = EINVAL;
        return -1;
    }
    if (ga_dev_set(d, c->type, &ts) < 0) {
        return -1;
    }
    if (c->op == GA_OP_SET_WAIT || c->op == GA_OP_SET_WAIT_OLD) {
        return ga_dev_wait(d);
    }
    return 0;
}

#endif
