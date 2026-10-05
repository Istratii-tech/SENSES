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

/* guest_xattr.h — расширенные атрибуты пространства user.* гостя — НАСТОЯЩИЕ, у файла
 * телефона (Р-112). Сторона хозяина: пути и описатели уже хозяйские, буферы — свои;
 * перевод пути, память гостя и номера ошибок гостя — у вызывающего (guest_selinux.c,
 * guest_selinux_xattr; обработчики — патч 0087).
 *
 * ★★ Зачем. installd 7.x (migrate_app_data) метит «основное» хранилище приложения
 * атрибутом user.default_crypto и на каждом подъёме сверяет его getxattr. Подделка
 * «запись — успех, чтение — всегда ENODATA» (Р-104) говорила ему, что отметка пропала,
 * и он на КАЖДОМ подъёме переносил каталоги приложения между /data/user/0 и
 * /data/user_de/0 — данные уезжали, базы не открывались:
 *
 *   W installd  Requested default storage /data/data/<пакет> is not active; migrating from /data/user_de/0/<пакет>
 *   E SQLiteLog (14) os_unix.c:…: (2) open(/data/user_de/0/…/databases/calllog_shadow.db)
 *
 * Атрибут обязан читаться тем, что записано. Хозяйская ФС телефона (ext4) даёт
 * приложению user.* на его собственных файлах — запись, чтение (в том числе пустое
 * значение), список, удаление; проверено ведущим программой на NDK под учёткой
 * приложения. Дерево гостя лежит в доме приложения — значит, храним там же.
 *
 * ★ Ответы — как у ядра Linux (fs/xattr.c):
 *  - ошибки хозяина — как есть (ENODATA, ERANGE, E2BIG, ENOTSUP, ENOENT, EPERM…);
 *  - значение больше XATTR_SIZE_MAX (64 КиБ) на запись — E2BIG до обращения к файлу;
 *  - чтение: буфер больше 64 КиБ ядро урезает до 64 КиБ, и если значению всё равно
 *    тесно (ERANGE) — E2BIG; размер 0 — только длина;
 *  - список: имена через ноль, каждое со своим нулём; размер 0 — только длина; мал
 *    буфер — ERANGE (у предела 64 КиБ — E2BIG).
 *
 * ★ Список гостю — ТОЛЬКО имена user.* хозяина и свои имена подражания (extra:
 * security.selinux при метках, guest_selinux.c). Прочее, что хозяин держит на файле
 * (security.selinux телефона с его контекстом, system.posix_acl_*), — сведения о
 * хозяине, гостю их не видно. Хозяйская ФС без атрибутов вовсе (ENOTSUP) при своих
 * именах — только свои: так ядро с модулем безопасности отвечает файлу ФС без
 * атрибутов (vfs_listxattr → security_inode_listsecurity).
 *
 * ★ Файл не зависит от qemu: только libc. Вызовы хозяина — через GX_* (по умолчанию
 * Linux: <sys/xattr.h>, без libattr), поэтому решение гоняется хостовым cc на Маке
 * с прокладкой под его API (native/test/test_xattr.c) на настоящем файле во
 * временном каталоге. Всё — static inline: включает один guest_selinux.c.
 */
#ifndef GUEST_XATTR_H
#define GUEST_XATTR_H

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef GX_GETXATTR
#include <sys/xattr.h>
#define GX_GETXATTR(p, n, v, s)       getxattr(p, n, v, s)
#define GX_LGETXATTR(p, n, v, s)      lgetxattr(p, n, v, s)
#define GX_FGETXATTR(f, n, v, s)      fgetxattr(f, n, v, s)
#define GX_SETXATTR(p, n, v, s, fl)   setxattr(p, n, v, s, fl)
#define GX_LSETXATTR(p, n, v, s, fl)  lsetxattr(p, n, v, s, fl)
#define GX_FSETXATTR(f, n, v, s, fl)  fsetxattr(f, n, v, s, fl)
#define GX_LISTXATTR(p, l, s)         listxattr(p, l, s)
#define GX_LLISTXATTR(p, l, s)        llistxattr(p, l, s)
#define GX_FLISTXATTR(f, l, s)        flistxattr(f, l, s)
#define GX_REMOVEXATTR(p, n)          removexattr(p, n)
#define GX_LREMOVEXATTR(p, n)         lremovexattr(p, n)
#define GX_FREMOVEXATTR(f, n)         fremovexattr(f, n)
#endif

/* Как указана цель: путь (за последней ссылкой), сама ссылка (l*), описатель (f*). */
enum { GX_BY_PATH = 0, GX_BY_LINK = 1, GX_BY_FD = 2 };

/* XATTR_SIZE_MAX и XATTR_LIST_MAX ядра Linux (include/uapi/linux/limits.h). */
#define GX_SIZE_MAX 65536

/* Имя из пространства user.* — его храним у файла телефона. */
static inline int gx_is_user(const char *name)
{
    return name != NULL && strncmp(name, "user.", 5) == 0;
}

/* ENOTSUP и EOPNOTSUPP: у Linux одно число, у Мака — два. */
static inline int gx_unsupported(long e)
{
#if ENOTSUP != EOPNOTSUPP
    return e == -ENOTSUP || e == -EOPNOTSUPP;
#else
    return e == -ENOTSUP;
#endif
}

/*
 * Значение атрибута хозяина. size — сколько просил гость (0 — только длина), buf —
 * не меньше MIN(size, GX_SIZE_MAX) байт. Длина значения или −errno.
 */
static inline long gx_get(int by, const char *path, int fd, const char *name,
                          void *buf, size_t size)
{
    size_t cap = size > GX_SIZE_MAX ? GX_SIZE_MAX : size;
    void *b = cap ? buf : NULL;
    ssize_t r;

    r = by == GX_BY_FD ? GX_FGETXATTR(fd, name, b, cap) :
        by == GX_BY_LINK ? GX_LGETXATTR(path, name, b, cap) :
        GX_GETXATTR(path, name, b, cap);
    if (r < 0) {
        return (errno == ERANGE && size >= GX_SIZE_MAX) ? -E2BIG : -errno;
    }
    return (long)r;
}

/* Записать len байт val (NULL при len 0 — пустое значение). flags — XATTR_CREATE/REPLACE как есть. 0 или −errno. */
static inline long gx_set(int by, const char *path, int fd, const char *name,
                          const void *val, size_t len, int flags)
{
    static const char empty[1];
    int r;

    if (len > GX_SIZE_MAX) {
        return -E2BIG;
    }
    if (val == NULL || len == 0) {
        val = empty;
    }
    r = by == GX_BY_FD ? GX_FSETXATTR(fd, name, val, len, flags) :
        by == GX_BY_LINK ? GX_LSETXATTR(path, name, val, len, flags) :
        GX_SETXATTR(path, name, val, len, flags);
    return r < 0 ? -errno : 0;
}

/* Удалить атрибут. 0 или −errno. */
static inline long gx_remove(int by, const char *path, int fd, const char *name)
{
    int r = by == GX_BY_FD ? GX_FREMOVEXATTR(fd, name) :
            by == GX_BY_LINK ? GX_LREMOVEXATTR(path, name) :
            GX_REMOVEXATTR(path, name);

    return r < 0 ? -errno : 0;
}

/*
 * Список гостю из списка хозяина (host, hlen байт): имена user.* в том же порядке, потом
 * extra (elen байт, имена со своими нулями). out — не меньше возвращённого или NULL (только
 * счёт). Длина списка. Имя без нуля в конце списка хозяина (ядро так не отдаёт) — с нулём.
 */
static inline size_t gx_list_compose(const char *host, size_t hlen, const char *extra,
                                     size_t elen, char *out)
{
    size_t i = 0, k, n = 0;

    while (i < hlen) {
        for (k = i; k < hlen && host[k] != '\0'; k++) {
        }
        if (k - i > 5 && memcmp(host + i, "user.", 5) == 0) {
            if (out) {
                memcpy(out + n, host + i, k - i);
                out[n + (k - i)] = '\0';
            }
            n += k - i + 1;
        }
        i = k + 1;
    }
    if (elen) {
        if (out) {
            memcpy(out + n, extra, elen);
        }
        n += elen;
    }
    return n;
}

/* Ответ ядра по размеру буфера гостя: 0 — длина; мал — ERANGE (у предела 64 КиБ — E2BIG). */
static inline long gx_fit(size_t need, size_t size)
{
    if (size != 0 && size < need) {
        return size >= GX_SIZE_MAX ? -E2BIG : -ERANGE;
    }
    return (long)need;
}

static inline ssize_t gx_host_list(int by, const char *path, int fd, char *l, size_t s)
{
    return by == GX_BY_FD ? GX_FLISTXATTR(fd, l, s) :
           by == GX_BY_LINK ? GX_LLISTXATTR(path, l, s) :
           GX_LISTXATTR(path, l, s);
}

/*
 * Список гостю: user.* хозяина + extra. *list — новый буфер (free) с готовым списком,
 * возврат — его длина; или −errno (тогда *list == NULL). Размер гостя здесь не
 * смотрится: см. gx_fit.
 */
static inline long gx_list(int by, const char *path, int fd, const char *extra,
                           size_t elen, char **list)
{
    char *h = NULL;
    long hn = -ERANGE;
    size_t n;
    int tries;

    *list = NULL;
    /* Список мог вырасти между запросом длины и чтением (ERANGE) — переспрашиваем. */
    for (tries = 0; tries < 8 && hn == -ERANGE; tries++) {
        ssize_t want = gx_host_list(by, path, fd, NULL, 0), got;

        if (want < 0) {
            hn = -errno;
            break;
        }
        free(h);
        h = malloc(want ? (size_t)want : 1);
        if (h == NULL) {
            return -ENOMEM;
        }
        if (want == 0) {
            hn = 0;
            break;
        }
        got = gx_host_list(by, path, fd, h, (size_t)want);
        hn = got < 0 ? -errno : (long)got;
    }
    if (hn < 0) {
        if (!(gx_unsupported(hn) && elen)) {
            free(h);
            return hn;
        }
        hn = 0;                         /* ФС без атрибутов: только свои имена */
    }
    n = gx_list_compose(h, (size_t)hn, extra, elen, NULL);
    *list = malloc(n ? n : 1);
    if (*list == NULL) {
        free(h);
        return -ENOMEM;
    }
    gx_list_compose(h, (size_t)hn, extra, elen, *list);
    free(h);
    return (long)n;
}

#endif /* GUEST_XATTR_H */
