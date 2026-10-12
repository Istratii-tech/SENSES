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
// Changed: 2026-08-29 … 2026-10-11

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

#include <pthread.h>
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
    struct region *r = by_fd(fd);

    if (seals > 0 && (seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))) {
        return PROT_READ | PROT_EXEC;
    }
    /* Р-130: печать не встала (ядро хозяина < 5.1, а запись уже отображена) — права держит маска шима. */
    if (r && !(r->prot & PROT_WRITE)) {
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
    /*
     * ★ Р-130: GUEST_ASHMEM_NOFUTURE=1 — вести себя как ядро хозяина < 5.1 (F_SEAL_FUTURE_WRITE
     * не ставить): так путь «печать F_SEAL_WRITE или маска шима» проверяется и на новом ядре
     * (tests/qemu/ashmem.sh, tools/ashmem-relro-probe.sh). В работе переменной нет.
     */
    static int no_future = -1;

    if (no_future < 0) {
        const char *e = getenv("GUEST_ASHMEM_NOFUTURE");

        no_future = e && *e && *e != '0';
    }
    if (!no_future && fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == 0) {
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
        /*
         * ★ Р-130в: маску можно только СУЖАТЬ — как у настоящего ashmem (`(asma->prot_mask & prot) != prot` →
         * EINVAL). Раньше расширение молча возвращало запись, а теперь маска шима значима (отказ mmap на запись).
         */
        if (((uint32_t)arg & ~prot_of(fd)) != 0) {
            errno = EINVAL;
            *ret = -1;
            return 1;
        }
        if (!((uint32_t)arg & PROT_WRITE) && seal_readonly(fd) < 0) {
            alog("описатель %d: печать «только чтение» не встала (%s)",
                 fd, strerror(errno));
            /*
             * ★ Р-130: на ядре хозяина < 5.1 (F_SEAL_FUTURE_WRITE нет) печать F_SEAL_WRITE
             * не встаёт, пока у области есть отображение на запись (EBUSY) — а проверка
             * «можно ли делить RELRO» во встроенном браузере прошивки делает именно так:
             * отображает область на запись и сразу сужает права. Маска остаётся у шима
             * (r->prot ниже), и guest_ashmem_mmap_prep отказывает по ней новым
             * отображениям на запись, как отказал бы настоящий ashmem.
             */
            static int told;

            if (!told) {
                told = 1;
                alog("печать не встала, права держу маской шима: отображения этой области на запись "
                     "отказываю сам (EPERM); дальше об этом не пишу");
            }
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

/*
 * ★★★★★ Р-130: ОТОБРАЖЕНИЕ ОБЛАСТИ ASHMEM — КАК У НАСТОЯЩЕГО ASHMEM, А НЕ КАК У ЯДРА ХОЗЯИНА.
 *
 * Встроенный браузер прошивки проверяет, можно ли делить RELRO между процессами
 * (собственный загрузчик библиотек): область ashmem → отобразить на запись →
 * ASHMEM_SET_PROT_MASK(PROT_READ) → отобразить PROT_READ + MAP_SHARED (ДОЛЖНО
 * пройти) → отобразить на запись (ДОЛЖНО отказать). У нас область — memfd, а права
 * сужает печать на запись. На ядре хозяина < 5.1 (например 4.9) второй шаг падает:
 *
 *   E libc  mmap fail (… size 4096, flags 0x1, errno 1 (Operation not permitted))
 *   W cr.library_loader  This system cannot safely share RELRO sections
 *
 * — после чего собственный загрузчик движка не используется, `System.loadLibrary(<движок>)`
 * бросает UnsatisfiedLinkError (в пакете лежит только копия библиотеки для собственного загрузчика).
 * Причина: memfd ВСЕГДА открыт на чтение-запись, а `mmap(PROT_READ, MAP_SHARED)` по
 * описателю, открытому на запись, ядро считает потенциально записываемым общим
 * отображением (VM_SHARED остаётся) и на запечатанной области отказывает
 * (`mapping_map_writable`, EPERM). Ядро 5.1+ с F_SEAL_FUTURE_WRITE этого не делает.
 *
 * Лечение — как у самого Android (libcutils, ashmem поверх memfd): отображение «только
 * чтение» запечатанной области делаем по описателю, ПЕРЕОТКРЫТОМУ только на чтение
 * (`open("/proc/self/fd/N", O_RDONLY)`): у такого файла нет права записи, VM_SHARED
 * не ставится, страницы те же. Вызывается из do_mmap (патч 0097) перед настоящим
 * mmap; описатель для отображения возвращается в *rfd, закрыть его после mmap —
 * дело вызывающего.
 *
 * Отображение на запись запечатанной области остаётся отказом EPERM (его даёт ядро; так
 * требует и проверка движка браузера). Если печать не встала (запись уже отображена, а
 * F_SEAL_FUTURE_WRITE на этом ядре нет), отказ даёт шим по маске в таблице.
 *
 * ★★★★★ Р-130б: НА ХОЗЯИНЕ-Android ПЕРЕОТКРЫТЬ НЕЛЬЗЯ — SELinux. У untrusted_app на файлы
 * appdomain_tmpfs (memfd — они) нет права `open`: только read/write/map по уже открытому
 * описателю, и `open("/proc/self/fd/N")` отвечает EACCES («Permission denied») — замерено
 * на телефоне с ядром 4.9. Тогда запечатанную область отображаем на хозяине как
 * MAP_PRIVATE с теми же правами: печать F_SEAL_WRITE частному отображению не мешает
 * (private не делит запись с файлом и VM_SHARED не ставит), а содержимое то же — страницы
 * общие с файлом, пока в них не писали, а писать в запечатанную область уже нельзя.
 * Для «только чтение» этого достаточно целиком: байты видны те же (в том числе записанные
 * до сужения прав через первое отображение и после — через ещё живое отображение на
 * запись, пока их не разделила запись в частную копию, которой у «только чтение» нет).
 *
 * Отказ с EACCES/EPERM запоминается на процесс (g_reopen_denied): дальше сразу MAP_PRIVATE,
 * без новой попытки, — иначе каждое отображение стоило бы ещё и отказа SELinux в журнале
 * хозяина. Строка в журнал шима — одна на процесс. GUEST_ASHMEM_NOREOPEN=1 изображает такой
 * запрет на хозяине без SELinux (tests/qemu/ashmem.sh, tools/ashmem-relro-probe.sh).
 *
 * Что с mprotect(PROT_WRITE) гостя по такому отображению (Р-130в). Хозяин сам РАЗРЕШИЛ бы
 * (у private VM_MAYWRITE остаётся — копия при записи; запечатанное содержимое при этом не
 * меняется никогда), а настоящий ashmem и ядро с печатью отказывают EACCES: у отображения
 * снят VM_MAYWRITE. И от этого отказа зависит проверка движка браузера: третий её шаг —
 * («описатель только на чтение?») — после «только чтение» пробует
 * mprotect(PROT_READ|PROT_WRITE) и считает «делить RELRO нельзя», если mprotect прошёл. Поэтому
 * шим помнит гостевые диапазоны, отображённые подменой MAP_SHARED → MAP_PRIVATE (таблица
 * g_pr ниже, их ведут хуки syscall.c: mmap/munmap/mremap/mprotect, патч 0097), и
 * guest_ashmem_mprotect_denied отказывает EACCES любому mprotect, добавляющему запись к ЛЮБОЙ
 * части такого диапазона — без изменений в самом отображении. Описатель, переоткрытый только на
 * чтение (где это разрешено), отказывает EACCES сам, его в таблицу не вносим.
 *
 * Возврат: 0 — отображать как обычно; 1 — отображать по *rfd; 2 — отображать как
 * MAP_PRIVATE (вместо MAP_SHARED; do_mmap меняет тип отображения) и записать диапазон;
 * 3 — отображать как обычно, но записать диапазон (права держит маска шима — печати нет; Р-130в);
 * -1 — отказ (errno).
 * ⚠️ Дёшево для чужих: MAP_PRIVATE (файлы, библиотеки) уходит первой же проверкой, а
 * для MAP_SHARED «наш ли описатель» решает readlink /proc/self/fd, как в is_ours().
 */
/* Р-130б: переоткрытие уже отказало (SELinux) — больше не пробуем; для проверок хост-теста сбрасывается ими. */
static int g_reopen_denied;

static int reopen_forbidden_by_env(void)
{
    static int v = -1;

    if (v < 0) {
        const char *e = getenv("GUEST_ASHMEM_NOREOPEN");

        v = e && *e && *e != '0';
    }
    return v;
}

int guest_ashmem_mmap_prep(int fd, int prot, int host_flags, int *rfd)
{
    struct region *r;
    int seals, sealed, sealed_w;

    *rfd = -1;
    /* MAP_ANONYMOUS: описатель ядро игнорирует — это не отображение нашей области */
    if (fd < 0 || !(host_flags & MAP_SHARED) || (host_flags & MAP_ANONYMOUS) || !is_ours(fd)) {
        return 0;
    }
    r = by_fd(fd);
    seals = fcntl(fd, F_GET_SEALS);
    sealed = seals > 0 && (seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE));
    sealed_w = seals > 0 && (seals & F_SEAL_WRITE);
    if (prot & PROT_WRITE) {
        if (!sealed && r && !(r->prot & PROT_WRITE)) {
            alog("описатель %d: отображение на запись области «только чтение» — отказ (печати нет, маска шима)",
                 fd);
            errno = EPERM;
            return -1;
        }
        return 0;                      /* запечатанной откажет ядро, остальным можно */
    }
    /*
     * ★ Р-130в (проверка Р-130, Важное 4): переоткрывать и подменять — ТОЛЬКО при F_SEAL_WRITE. При
     * F_SEAL_FUTURE_WRITE (ядро 5.1+) ядро само пускает «только чтение» по описателю на запись и само снимает
     * VM_MAYWRITE (mprotect на запись — EACCES): там поведение побайтно прежнее, без лишних open и строк журнала.
     */
    if (!sealed_w) {
        /*
         * Печати нет вовсе, а права «только чтение» держит маска шима (ядро < 5.1: F_SEAL_WRITE не встал из-за EBUSY —
         * запись уже была отображена): отображение проходит как есть, но получившееся «только чтение» ядро оставило бы
         * записываемым через mprotect, а проверка движка браузера этого не прощает — диапазон записывается (ответ 3).
         */
        if (!sealed && r && !(r->prot & PROT_WRITE)) {
            return 3;
        }
        return 0;
    }
    {
        char link[48];
        int ro = -1;

        if (!g_reopen_denied) {
            if (reopen_forbidden_by_env()) {
                errno = EACCES;                    /* как SELinux хозяина-Android, без самого SELinux */
            } else {
                snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
                ro = open(link, O_RDONLY | O_CLOEXEC);
            }
        } else {
            errno = EACCES;
        }
        if (ro < 0) {
            static int told_private;
            int e = errno;

            if (e == EACCES || e == EPERM) {
                g_reopen_denied = 1;
            }
            if (!told_private) {
                told_private = 1;
                alog("описатель %d: переоткрыть только на чтение нельзя (%s) — запечатанную область "
                     "отображаю на хозяине как MAP_PRIVATE; дальше об этом не пишу", fd, strerror(e));
            }
            return 2;
        }
        *rfd = ro;
        alog("описатель %d: отображение «только чтение» запечатанной области — по описателю, "
             "переоткрытому только на чтение (%d)", fd, ro);
    }
    return 1;
}

/*
 * ★★★★★ Р-130в: ДИАПАЗОНЫ, ОТОБРАЖЁННЫЕ ПОДМЕНОЙ «MAP_SHARED → MAP_PRIVATE».
 *
 * Гостевые адреса [a, b), страницы по 4 КБ (ARM). Ведут их хуки в syscall.c (патч 0097):
 *   mmap    — после успешного отображения с ответом 2 (guest_ashmem_range_note); MAP_FIXED поверх чего-то
 *             вычитает перекрытие (guest_ashmem_range_forget) — старое отображение заменено;
 *   munmap  — вычитает перекрытие (запись режется: дыра посередине даёт два куска);
 *   mremap  — после успеха: старый диапазон вычитается, а если он был записан ЦЕЛИКОМ, новое место
 *             (его длина не больше прежней) записывается заново — перенесённое отображение остаётся под отказом;
 *   mprotect — guest_ashmem_mprotect_denied: запись к любой части диапазона → EACCES без изменений.
 * fork — таблица копируется вместе с памятью процесса (замок после fork пересоздаётся); execve — qemu
 * запускается заново, таблица пуста. Потоки одного процесса делят адресное пространство — и таблицу, под замком.
 * Таблица малая, с потолком PRMAX; переполнение — одна строка в журнал шима и прежнее поведение (для записи,
 * которая не поместилась, mprotect на запись проходит как раньше; при разрезании записи без места — вся запись
 * отбрасывается, чтобы устаревший кусок не запретил mprotect чужому отображению на том же адресе).
 * Быстрый путь: пока таблица пуста (а это почти всегда), хуки отвечают одной атомарной проверкой.
 */
#define PRMAX 64
#define PR_PAGE 0x1000u

static struct { uint64_t a, b; } g_pr[PRMAX];
static int g_npr;                        /* под g_prl */
static int g_pr_any;                     /* зеркало g_npr > 0 — для быстрого пути без замка */
static pthread_mutex_t g_prl = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_pr_once = PTHREAD_ONCE_INIT;
static int g_pr_told_full;

static void pr_atfork_child(void)
{
    pthread_mutex_init(&g_prl, NULL);    /* замок мог остаться взятым другим потоком родителя */
}

static void pr_init(void)
{
    pthread_atfork(NULL, NULL, pr_atfork_child);
}

static uint64_t pr_end(abi_ulong start, abi_ulong len)
{
    return (uint64_t)start + (((uint64_t)len + PR_PAGE - 1) & ~(uint64_t)(PR_PAGE - 1));
}

static void pr_full_note(const char *what)
{
    if (!g_pr_told_full) {
        g_pr_told_full = 1;
        alog("таблица диапазонов подмены MAP_PRIVATE полна (%d): %s; дальше об этом не пишу", PRMAX, what);
    }
}

/* Вычесть [a, b) из записей. Под g_prl. */
static void pr_sub_l(uint64_t a, uint64_t b)
{
    int i = 0;

    while (i < g_npr) {
        uint64_t ra = g_pr[i].a, rb = g_pr[i].b;

        if (rb <= a || ra >= b) {
            i++;
        } else if (ra < a && rb > b) {                 /* дыра посередине: два куска */
            if (g_npr < PRMAX) {
                g_pr[g_npr].a = b;
                g_pr[g_npr].b = rb;
                g_npr++;
                g_pr[i].b = a;
                i++;
            } else {
                pr_full_note("запись с дырой отброшена целиком");
                g_pr[i] = g_pr[--g_npr];
            }
        } else if (ra < a) {                           /* срезан хвост */
            g_pr[i].b = a;
            i++;
        } else if (rb > b) {                           /* срезано начало */
            g_pr[i].a = b;
            i++;
        } else {                                       /* перекрыта целиком */
            g_pr[i] = g_pr[--g_npr];
        }
    }
}

/* Добавить [a, b) (после вычитания перекрытия). Под g_prl. */
static void pr_add_l(uint64_t a, uint64_t b)
{
    pr_sub_l(a, b);
    if (b <= a) {
        return;
    }
    if (g_npr < PRMAX) {
        g_pr[g_npr].a = a;
        g_pr[g_npr].b = b;
        g_npr++;
    } else {
        pr_full_note("mprotect на запись по новому отображению отказывать не будем");
    }
}

static void pr_publish(void)
{
    __atomic_store_n(&g_pr_any, g_npr > 0, __ATOMIC_RELEASE);
}

/* Отображение гостя [start, start+len) сделано подменой MAP_PRIVATE вместо MAP_SHARED. */
void guest_ashmem_range_note(abi_ulong start, abi_ulong len)
{
    if (!len) {
        return;
    }
    pthread_once(&g_pr_once, pr_init);
    pthread_mutex_lock(&g_prl);
    pr_add_l(start, pr_end(start, len));
    pr_publish();
    pthread_mutex_unlock(&g_prl);
}

/* munmap или MAP_FIXED поверх: перекрытие больше не наше. */
void guest_ashmem_range_forget(abi_ulong start, abi_ulong len)
{
    if (!len || !__atomic_load_n(&g_pr_any, __ATOMIC_ACQUIRE)) {
        return;
    }
    pthread_mutex_lock(&g_prl);
    pr_sub_l(start, pr_end(start, len));
    pr_publish();
    pthread_mutex_unlock(&g_prl);
}

/* Целиком ли [start, start+len) лежит в записях (склеенных встык). */
int guest_ashmem_range_covers(abi_ulong start, abi_ulong len)
{
    uint64_t cur = start, end;
    int found = 1, r = 0;

    if (!len || !__atomic_load_n(&g_pr_any, __ATOMIC_ACQUIRE)) {
        return 0;
    }
    end = pr_end(start, len);
    pthread_mutex_lock(&g_prl);
    while (found && cur < end) {
        found = 0;
        for (int i = 0; i < g_npr; i++) {
            if (g_pr[i].a <= cur && cur < g_pr[i].b) {
                cur = g_pr[i].b;
                found = 1;
                break;
            }
        }
    }
    r = cur >= end;
    pthread_mutex_unlock(&g_prl);
    return r;
}

/* mremap удался: старый диапазон вычесть; если он был записан целиком (cov) — записать новое место (длина keeplen). */
void guest_ashmem_range_moved(abi_ulong old, abi_ulong oldlen, abi_ulong newaddr, abi_ulong keeplen, int cov)
{
    if (!oldlen || !__atomic_load_n(&g_pr_any, __ATOMIC_ACQUIRE)) {
        return;
    }
    pthread_mutex_lock(&g_prl);
    pr_sub_l(old, pr_end(old, oldlen));
    if (cov && keeplen) {
        pr_add_l(newaddr, pr_end(newaddr, keeplen));
    }
    pr_publish();
    pthread_mutex_unlock(&g_prl);
}

/*
 * mprotect гостя: 1 — отказать (EACCES, ничего не менять): запись добавляется к любой части диапазона,
 * который у нас отображён вместо запечатанного общего. Выровненный начальный адрес — как требует ядро (иначе у
 * qemu своя ошибка EINVAL).
 */
int guest_ashmem_mprotect_denied(abi_ulong start, abi_ulong len, int prot)
{
    uint64_t end;
    int denied = 0;
    static int told;

    if (!(prot & PROT_WRITE) || !len || (start & (PR_PAGE - 1)) ||
        !__atomic_load_n(&g_pr_any, __ATOMIC_ACQUIRE)) {
        return 0;
    }
    end = pr_end(start, len);
    pthread_mutex_lock(&g_prl);
    for (int i = 0; i < g_npr; i++) {
        if (g_pr[i].a < end && start < g_pr[i].b) {
            denied = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_prl);
    if (denied && !told) {
        told = 1;
        alog("mprotect на запись по отображению запечатанной области (MAP_PRIVATE вместо MAP_SHARED) — EACCES, "
             "как у ashmem; дальше об этом не пишу");
    }
    return denied;
}

void guest_ashmem_close(int fd)
{
    struct region *r = by_fd(fd);

    if (r) {
        r->used = 0;
    }
}
