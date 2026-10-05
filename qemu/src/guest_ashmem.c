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
// Changed: 2026-08-29 … 2026-10-05

/* guest_ashmem.c — /dev/ashmem для гостя, целиком внутри qemu.
 *
 * Зачем ВТОРАЯ реализация ashmem (первая — guest/ashmem_shim.c). Гостевой шим
 * подменяет пять функций libcutils через LD_PRELOAD, и для программ это
 * работает. Но линкер bionic 2.3 НЕ подставляет preload в библиотеки, которые
 * загружены через dlopen, а HAL-модули загружаются именно так. Поймано на живом
 * стеке: SurfaceFlinger поднял gralloc.default.so, и тот пошёл напрямую —
 *
 *   open("/dev/ashmem",O_RDWR|O_LARGEFILE) = -1 errno=2
 *
 * — после чего SF падал в mspace_malloc по нулевому указателю (si_addr=0x4).
 * Симптом на пустом месте: ashmem «работал» для Dalvik и не работал для HAL.
 *
 * Здесь перехват на уровне устройства, поэтому он покрывает ЛЮБОЙ путь: и
 * dlopen, и статические вызовы, и код, который открывает устройство сам.
 *
 * Регион = memfd: безымянная разделяемая память, ровно то, чем ashmem и был.
 * SET_SIZE становится ftruncate, PIN/UNPIN — заглушками (страницы у нас никогда
 * не отбираются), mmap гость делает сам и получает настоящую общую память.
 *
 * ⚠️ Номера ioctl сверены с libcutils.so ИЗ ПРОШИВКИ, а не с заголовками:
 * SET_NAME=0x41007701, SET_SIZE=0x40047703, SET_PROT_MASK=0x40047705,
 * PIN=0x40087707, UNPIN=0x40087708. Мелкие _IO-номера в файле литералами не
 * лежат (компилятор ставит их в movw), поэтому проверены по смыслу.
 *
 * ★★★★★ ОПИСАТЕЛЬ ПРИХОДИТ ИЗ ЧУЖОГО ПРОЦЕССА — ТАБЛИЦЫ МАЛО.
 *
 * Здесь была вторая ошибка, от которой браузер прошивки падал при запуске (14 сентября).
 * Область искалась ТОЛЬКО в таблице regs[], а таблица живёт в памяти одного
 * экземпляра qemu. Движок браузера же раздаёт общую память между своими процессами,
 * посылая описатель по сокету (SCM_RIGHTS). У получателя в таблице его нет —
 * значит guest_ashmem_ioctl отвечал «не моё», запрос уходил настоящему ioctl,
 * тот видел memfd, не знал ioctl'ов ashmem и отвечал −1. А движок браузера на этот
 * −1 намеренно ломает процесс. Снято с живого стенда:
 *
 *   Fatal signal 5 (SIGTRAP) at 0x7a6b6a52, thread 19590 (Browser_ChildIOT)
 *   R00=ffffffff R01=00007706        ← возврат −1, запрос ASHMEM_GET_PROT_MASK
 *   байты у PC: be00 de42            ← bkpt #0 — умышленный слом
 *   у LR: … bl ioctl; orr r0,r0,r0 asr #31; cmp r0,#0; blt → bkpt
 *
 * То же случилось бы при dup() описателя и при переполнении таблицы.
 *
 * Поэтому «наш ли описатель» теперь решается ПО САМОМУ ОПИСАТЕЛЮ: memfd видно
 * по имени в /proc/self/fd/N («memfd:guest-ashmem»), размер берётся из fstat, а
 * права — из печатей memfd (F_SEAL_FUTURE_WRITE). Ровно так ashmem поверх
 * memfd сделан и в самом Android, начиная с 11-й версии. Таблица осталась
 * только ради имени области: оно нужно лишь для отладки.
 */
#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"

#include <sys/mman.h>

#include "guest_ashmem.h"

#define ASHMEM_SET_NAME         0x41007701u
#define ASHMEM_GET_NAME         0x81007702u
#define ASHMEM_SET_SIZE         0x40047703u
#define ASHMEM_GET_SIZE         0x00007704u
#define ASHMEM_SET_PROT_MASK    0x40047705u
#define ASHMEM_GET_PROT_MASK    0x00007706u
#define ASHMEM_PIN              0x40087707u
#define ASHMEM_UNPIN            0x40087708u
#define ASHMEM_GET_PIN_STATUS   0x00007709u
#define ASHMEM_PURGE_ALL_CACHES 0x0000770au

#define ASHMEM_NAME_LEN 256
#define ASHMEM_IS_PINNED 1
#define ASHMEM_NOT_PURGED 0

/*
 * Имя memfd. По нему и только по нему мы узнаём свои области в чужом процессе,
 * поэтому оно должно быть приметным и не меняться.
 */
#define GUEST_ASHMEM_TAG "guest-ashmem"

/* musl этих имён не объявляет, а заголовков ядра в сборке нет. */
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002u
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_GET_SEALS
#define F_GET_SEALS 1034
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
/* Появилась в ядре 5.1; на телефоне ядро шестое, но проверку оставляем. */
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE 0x0010
#endif

#define MAXREG 256

static struct region {
    int used;
    int fd;
    uint32_t size;
    uint32_t prot;
    char name[ASHMEM_NAME_LEN];
} regs[MAXREG];

static struct region *by_fd(int fd)
{
    for (int i = 0; i < MAXREG; i++) {
        if (regs[i].used && regs[i].fd == fd) {
            return &regs[i];
        }
    }
    return NULL;
}

/*
 * Журнал шима. Включается GUEST_ASHMEM_LOG=<файл>; без него молчим совсем.
 * Нужен редко — когда надо увидеть, приходят ли описатели из чужих процессов.
 */
static FILE *g_alog;
static int alog_tried;

static void alog(const char *fmt, ...)
{
    va_list ap;

    if (!alog_tried) {
        const char *path = getenv("GUEST_ASHMEM_LOG");

        alog_tried = 1;
        if (path && *path) {
            g_alog = fopen(path, "ae");
        }
    }
    if (!g_alog) {
        return;
    }
    fprintf(g_alog, "[pid=%d] ", (int)getpid());
    va_start(ap, fmt);
    vfprintf(g_alog, fmt, ap);
    va_end(ap);
    fputc('\n', g_alog);
    fflush(g_alog);
}

/*
 * Похоже ли это на запрос к ashmem: у всех его ioctl семейство 0x77 ('w').
 *
 * ⚠️ Проверка стоит ПЕРВОЙ во всём разборе ioctl и потому обязана быть
 * дешёвой: сюда приходит каждый ioctl гостя, а их основная масса — горячие
 * вызовы binder. Раньше на каждом таком вызове пробегалась вся таблица из 256
 * записей; теперь для чужого номера всё кончается одним сравнением.
 */
static int ashmem_req(unsigned long req)
{
    return ((req >> 8) & 0xffu) == 0x77u;
}

/*
 * Наш ли это описатель — по нему самому, а не по таблице (разбор в шапке).
 * memfd виден в /proc/self/fd как «/memfd:<имя> (deleted)».
 */
static int is_ours(int fd)
{
    char link[48], target[128];
    ssize_t n;

    if (fd < 0) {
        return 0;
    }
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    n = readlink(link, target, sizeof target - 1);
    if (n <= 0) {
        return 0;
    }
    target[n] = '\0';
    return strstr(target, "memfd:" GUEST_ASHMEM_TAG) != NULL;
}

/*
 * Права области. У ядра ashmem это маска, которую можно только СУЖАТЬ, и
 * единственное сужение, которым пользуются на деле, — снять запись. У memfd
 * ровно это делает печать: F_SEAL_FUTURE_WRITE запрещает будущие отображения
 * на запись, не трогая уже сделанные. Печать живёт при описателе, поэтому
 * ответ одинаков во всех процессах, куда его переслали.
 */
static uint32_t prot_of(int fd)
{
    int seals = fcntl(fd, F_GET_SEALS);

    if (seals > 0 && (seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))) {
        return PROT_READ | PROT_EXEC;
    }
    return PROT_READ | PROT_WRITE | PROT_EXEC;
}

/* Сузить права до «только чтение». 0 — печать поставлена. */
static int seal_readonly(int fd)
{
    /*
     * ⚠️ Порядок важен. F_SEAL_WRITE отказывает (EBUSY), если у области уже
     * есть отображение на запись, — а именно так делает движок браузера: пишет в
     * свою копию и лишь потом объявляет область чужому процессу «только для
     * чтения». F_SEAL_FUTURE_WRITE такому отображению не мешает.
     */
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == 0) {
        return 0;
    }
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE) == 0) {
        return 0;
    }
    return -1;
}

int guest_ashmem_try_open(const char *path, int *fd)
{
    if (!path || strcmp(path, "/dev/ashmem") != 0) {
        return 0;
    }
    struct region *r = NULL;

    for (int i = 0; i < MAXREG; i++) {
        if (!regs[i].used) {
            r = &regs[i];
            break;
        }
    }

    /*
     * ⚠️ Без MFD_ALLOW_SEALING печати ставить нельзя, а без них права области
     * не переживут пересылку описателя в другой процесс (см. шапку).
     * ⚠️ MFD_CLOEXEC НЕ ставим нарочно: гость открывает /dev/ashmem без
     * O_CLOEXEC и вправе ждать, что описатель переживёт exec.
     */
    int mfd = memfd_create(GUEST_ASHMEM_TAG, MFD_ALLOW_SEALING);
    if (mfd < 0) {
        /* Старое ядро без печатей — лучше область без них, чем отказ. */
        mfd = memfd_create(GUEST_ASHMEM_TAG, 0);
    }
    if (mfd < 0) {
        *fd = -1;
        return 1;                      /* errno уже выставлен */
    }
    /*
     * Таблица нужна только ради имени области (оно чисто отладочное), поэтому
     * её нехватка больше не повод отказывать в открытии: размер и права
     * читаются из самого описателя.
     */
    if (r) {
        memset(r, 0, sizeof *r);
        r->used = 1;
        r->fd = mfd;
        snprintf(r->name, sizeof r->name, "unnamed");
        /* Права по умолчанию как у ядра: всё разрешено, дальше только сужают. */
        r->prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    } else {
        alog("таблица имён полна — область %d живёт без записи", mfd);
    }
    *fd = mfd;
    return 1;
}

int guest_ashmem_ioctl(int fd, unsigned long req, abi_ulong arg, abi_long *ret)
{
    struct region *r;

    /* Чужое семейство — уходим сразу, до всякого поиска. */
    if (!ashmem_req(req)) {
        return 0;
    }
    r = by_fd(fd);
    if (!r && !is_ours(fd)) {
        return 0;
    }
    if (!r) {
        /* Описатель из чужого процесса или dup — отвечаем по нему самому. */
        alog("описатель %d не в таблице (запрос 0x%lx) — отвечаем по memfd",
             fd, req);
    }

    switch (req) {
    case ASHMEM_SET_NAME:
        if (arg && r) {
            /* Имя нужно только для отладки: ядро им помечает область. */
            snprintf(r->name, sizeof r->name, "%.*s", ASHMEM_NAME_LEN - 1,
                     (const char *)g2h_untagged(arg));
        }
        *ret = 0;
        return 1;

    case ASHMEM_GET_NAME:
        if (arg) {
            char name[ASHMEM_NAME_LEN];

            snprintf(name, sizeof name, "%s",
                     r ? r->name : GUEST_ASHMEM_TAG);
            memcpy(g2h_untagged(arg), name, sizeof name);
        }
        *ret = 0;
        return 1;

    case ASHMEM_SET_SIZE:
        /*
         * ⚠️ Размер приходит ЗНАЧЕНИЕМ (size_t), а не указателем: у ashmem
         * этот ioctl объявлен _IOW(…, size_t), и ядро берёт arg как число.
         */
        if (ftruncate(fd, (off_t)(uint32_t)arg) < 0) {
            *ret = -1;
            return 1;
        }
        if (r) {
            r->size = (uint32_t)arg;
        }
        *ret = 0;
        return 1;

    case ASHMEM_GET_SIZE: {
        /* Из самого описателя: так ответ верен и в чужом процессе. */
        struct stat st;

        if (fstat(fd, &st) == 0) {
            *ret = (abi_long)st.st_size;
        } else if (r) {
            *ret = (abi_long)r->size;
        } else {
            *ret = -1;
        }
        return 1;
    }

    case ASHMEM_SET_PROT_MASK:
        if (!((uint32_t)arg & PROT_WRITE) && seal_readonly(fd) < 0) {
            alog("описатель %d: печать «только чтение» не встала (%s)",
                 fd, strerror(errno));
        }
        if (r) {
            r->prot = (uint32_t)arg;
        }
        /*
         * ⚠️ Отвечаем успехом даже если печать не встала. Отказ здесь для
         * движка браузера означает «общую память создать не удалось» — он бросит
         * всю затею; неточные права хуже, но не смертельны.
         */
        *ret = 0;
        return 1;

    case ASHMEM_GET_PROT_MASK:
        *ret = (abi_long)prot_of(fd);
        return 1;

    case ASHMEM_PIN:
        /* Страницы у нас не отбираются никогда — регион всегда «не выброшен». */
        *ret = ASHMEM_NOT_PURGED;
        return 1;

    case ASHMEM_UNPIN:
        *ret = 0;
        return 1;

    case ASHMEM_GET_PIN_STATUS:
        *ret = ASHMEM_IS_PINNED;
        return 1;

    case ASHMEM_PURGE_ALL_CACHES:
        *ret = 0;
        return 1;

    default:
        /* Наш описатель, но незнакомый запрос: честный отказ, а не молчание. */
        errno = EINVAL;
        *ret = -1;
        return 1;
    }
}

void guest_ashmem_close(int fd)
{
    struct region *r = by_fd(fd);

    if (r) {
        r->used = 0;
    }
}
