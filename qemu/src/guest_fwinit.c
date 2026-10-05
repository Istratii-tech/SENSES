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
// Changed: 2026-10-03 … 2026-10-05

/*
 * guest_fwinit.c — «ядро для init»: транслятор изображает ядро настоящему
 * /init прошивки.
 *
 * ★ Что это. Режим «init прошивки» поднимает не свой автомат запуска, а
 * НАСТОЯЩИЙ /init из рамдиска прошивки: он сам читает сценарии, ведёт службу
 * свойств и порождает службы. Настоящему init нужно ядро: узлы устройств, строка
 * ядра, файловые системы, личность служб и журнал. Ядра у нас нет — его роль
 * играет транслятор, и всё, что для этого нужно, лежит здесь. Договор со
 * стендом (переменные и форматы журналов) задаёт приложение; в комплект он не входит.
 *
 * ★ ВСЁ ТОЛЬКО ПРИ GUEST_FWINIT=1. Без переменной ни одна функция не меняет
 * поведения: guest_fwinit() отвечает «нет», и вызовы идут как прежде. Код
 * читает переменные окружения сам (getenv): их кладёт стенд, а из окружения
 * гостя они вычеркнуты (патч 0060) и ему досылаются по execve.
 *
 * ⚠️ Журналы пишутся так же, как GUEST_EXIT_LOG (патч 0070): файл открывается на
 * КАЖДУЮ строку с дозаписью (процессы гостя — форки, общий описатель через fork
 * держать нельзя), строка короче PIPE_BUF и уходит одним write.
 *
 * ★ Пути файлов стенда — АБСОЛЮТНЫЕ (GUEST_KMSG, GUEST_START_LOG, GUEST_PROP_LOG,
 * GUEST_REBOOT_LOG). Относительный путь после гостевого chdir (а у init он сразу
 * chdir("/")) указал бы уже не туда, а ссылка mknod на относительный путь
 * считалась бы от каталога ссылки. Поэтому при старте процесса относительное
 * значение переписывается в абсолютное — от рабочего каталога ХОЗЯИНА, пока гость
 * ещё не сделал chdir (см. absolutize_paths); потомкам переменная уходит уже
 * такой (патч 0060 досылает GUEST_* из окружения процесса).
 */
#include "qemu/osdep.h"
#include <sys/sysmacros.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include "qemu/path.h"
#include "qemu.h"
#include "user-internals.h"

#include "guest_fwinit.h"
#include "guest_selinux.h"

/*
 * Пути файлов стенда из окружения → абсолютные (см. шапку файла). Относительное
 * значение дописывается к рабочему каталогу хозяина; не удалось узнать каталог —
 * значение остаётся как есть (потребители тогда пропускают относительный путь).
 *
 * ⚠️ Зовётся один раз из guest_fwinit() в начале процесса: setenv не терпит
 * гонки с getenv у соседних потоков, а гостевых потоков в этот миг ещё нет.
 */
static void absolutize_paths(void)
{
    static const char *const names[] = {
        "GUEST_KMSG", "GUEST_START_LOG", "GUEST_PROP_LOG", "GUEST_REBOOT_LOG",
        "GUEST_EMMC",
    };
    char cwd[PATH_MAX];
    size_t i;

    if (!getcwd(cwd, sizeof cwd)) {
        return;
    }
    for (i = 0; i < ARRAY_SIZE(names); i++) {
        const char *v = getenv(names[i]);
        char *full;

        if (!v || !*v || v[0] == '/') {
            continue;
        }
        full = g_strdup_printf("%s%s%s", cwd, strcmp(cwd, "/") ? "/" : "", v);
        setenv(names[i], full, 1);
        g_free(full);
    }
}

static int fwinit_on;
static pthread_once_t fwinit_once = PTHREAD_ONCE_INIT;

static void fwinit_setup(void)
{
    const char *e = getenv("GUEST_FWINIT");

    /* Ровно «1»: «0», «10», «1x» режим не включают. */
    fwinit_on = e && strcmp(e, "1") == 0;
    if (fwinit_on) {
        absolutize_paths();
    }
}

/*
 * ⚠️ То же условие читает util/path.c (fwinit_dev, патч 0075): код в util/ не
 * вправе зависеть от linux-user/, поэтому оно записано дважды. Менять — в обоих.
 */
bool guest_fwinit(void)
{
    pthread_once(&fwinit_once, fwinit_setup);
    return fwinit_on;
}

/* ------------------------------------------------------------------ mknod */

bool guest_fwinit_node(mode_t mode)
{
    return guest_fwinit() && (S_ISCHR(mode) || S_ISBLK(mode));
}

/*
 * ★ Настоящего узла приложению не создать (нет права CAP_MKNOD), а настоящему
 * init узлы нужны с первых строк: он делает mknod("/dev/__null__", 1:3) и без
 * него выходит с кодом 1.
 *
 * «Пустые» устройства без состояния — ссылка на хозяйский узел (его и так
 * видно гостю, см. util/path.c): 1:3 null, 1:5 zero, 1:7 full, 1:8 random,
 * 1:9 urandom. 1:11 — журнал ядра (init пишет в /dev/__kmsg__ свои строки): при
 * заданном GUEST_KMSG — ссылка на файл стенда, иначе обычный файл. Прочие
 * символьные и блочные — пустой обычный файл с правами из mode: узел «на
 * месте», ueventd и fs_mgr его находят.
 *
 * ⚠️ Узел создаётся только под корнем гостя: путь вне дерева (его гостю не
 * показывают) идёт настоящему mknod, и тот откажет, как обычно.
 * ⚠️ Файл стенда для 1:11 создаётся, если его ещё нет: init открывает узел на
 * запись без O_CREAT, а ссылка на несуществующий файл дала бы ему ENOENT.
 * Содержимое не трогаем (не усекаем): им распоряжается стенд.
 */
int guest_fwinit_mknod(const char *host, mode_t mode, dev_t dev)
{
    const char *to = NULL;
    const char *root = path_prefix();
    size_t rl = root ? strlen(root) : 0;
    int fd;

    if (!root || strncmp(host, root, rl) != 0 || (host[rl] != '/' && host[rl] != '\0')) {
        return mknod(host, mode, dev);
    }
    if (S_ISCHR(mode) && major(dev) == 1) {
        switch (minor(dev)) {
        case 3: to = "/dev/null"; break;
        case 5: to = "/dev/zero"; break;
        case 7: to = "/dev/full"; break;
        case 8: to = "/dev/random"; break;
        case 9: to = "/dev/urandom"; break;
        case 11: {
            const char *k = getenv("GUEST_KMSG");

            /* Цель ссылки — только абсолютный путь (см. absolutize_paths). */
            if (k && *k == '/') {
                to = k;
                fd = open(k, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
                if (fd >= 0) {
                    close(fd);
                }
            }
            break;
        }
        }
    }
    if (to) {
        return symlink(to, host);
    }
    fd = open(host, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, mode & 07777);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return 0;
}

/* ------------------------------------------------------------- /proc init */

/*
 * Поддельные файлы /proc для init (сверка по полному гостевому имени).
 *
 * /proc/cmdline — строка ядра гостя: GUEST_CMDLINE (стенд кладёт туда
 * androidboot.hardware и selinux=0); без неё — только selinux=0. Хозяйскую
 * строку гость не видит: в ней серийник и загрузчик телефона. ro.hardware init
 * берёт отсюда и по нему выбирает init.<аппарат>.rc.
 *
 * /proc/filesystems и …/mounts — без selinuxfs: libselinux решает «SELinux
 * включён» по ним, если точку /sys/fs/selinux не нашла (а её у гостя нет).
 * Хозяйский список у телефона selinuxfs содержит.
 */
static const char FS_TEXT[] =
    "nodev\tsysfs\nnodev\trootfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tdevpts\n"
    "nodev\tpipefs\nnodev\tsockfs\n\text4\n\tvfat\nnodev\tfuse\n";
/*
 * С GUEST_SELINUX=1 (патч 0084) в обоих списках есть selinuxfs: libselinux 5.0+
 * находит точку по statfs, а в этих файлах — запасной путь и признак «SELinux
 * включён» у всего, что смотрит /proc/filesystems.
 */
static const char FS_TEXT_SE[] =
    "nodev\tsysfs\nnodev\trootfs\nnodev\ttmpfs\nnodev\tproc\nnodev\tdevpts\n"
    "nodev\tpipefs\nnodev\tsockfs\n\text4\n\tvfat\nnodev\tfuse\nnodev\tselinuxfs\n";
static const char MOUNTS_TEXT[] =
    "rootfs / rootfs ro,relatime 0 0\n"
    "tmpfs /dev tmpfs rw,nosuid,relatime,mode=755 0 0\n"
    "devpts /dev/pts devpts rw,relatime,mode=600 0 0\n"
    "proc /proc proc rw,relatime 0 0\n"
    "sysfs /sys sysfs rw,relatime 0 0\n"
    "/dev/block/system /system ext4 ro,relatime 0 0\n"
    "/dev/block/userdata /data ext4 rw,nosuid,nodev,relatime 0 0\n"
    "/dev/block/cache /cache ext4 rw,nosuid,nodev,relatime 0 0\n";
static const char MOUNTS_TEXT_SE[] =
    "rootfs / rootfs ro,relatime 0 0\n"
    "tmpfs /dev tmpfs rw,nosuid,relatime,mode=755 0 0\n"
    "devpts /dev/pts devpts rw,relatime,mode=600 0 0\n"
    "proc /proc proc rw,relatime 0 0\n"
    "sysfs /sys sysfs rw,relatime 0 0\n"
    "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n"
    "/dev/block/system /system ext4 ro,relatime 0 0\n"
    "/dev/block/userdata /data ext4 rw,nosuid,nodev,relatime 0 0\n"
    "/dev/block/cache /cache ext4 rw,nosuid,nodev,relatime 0 0\n";

static bool all_digits(const char *s, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
    }
    return n > 0;
}

/* «/proc/mounts», «/proc/<self|thread-self|число>/mounts» и тот же вид у потока. */
static bool is_mounts_path(const char *path)
{
    const char *r = path + 6;           /* после «/proc/» */
    const char *s;
    size_t n;

    if (!strcmp(r, "mounts")) {
        return true;
    }
    s = strchr(r, '/');
    if (!s) {
        return false;
    }
    n = (size_t)(s - r);
    if (!(n == 4 && !strncmp(r, "self", 4)) &&
        !(n == 11 && !strncmp(r, "thread-self", 11)) && !all_digits(r, n)) {
        return false;
    }
    r = s + 1;
    if (!strcmp(r, "mounts")) {
        return true;
    }
    if (strncmp(r, "task/", 5) != 0) {
        return false;
    }
    r += 5;
    s = strchr(r, '/');
    return s && all_digits(r, (size_t)(s - r)) && !strcmp(s + 1, "mounts");
}

const char *guest_fwinit_proc_text(const char *path, char *buf, size_t cap)
{
    if (!guest_fwinit() || !path || strncmp(path, "/proc/", 6)) {
        return NULL;
    }
    if (!strcmp(path, "/proc/cmdline") && buf && cap > 1) {
        const char *c = getenv("GUEST_CMDLINE");
        size_t n;

        /* Строку собираем в буфере вызывающего: общего состояния нет, потоки не мешают. */
        snprintf(buf, cap, "%s", c && *c ? c : "selinux=0");
        n = strlen(buf);
        while (n > 0 && buf[n - 1] == '\n') {
            buf[--n] = '\0';
        }
        if (n + 1 < cap) {
            buf[n] = '\n';
            buf[n + 1] = '\0';
        }
        return buf;
    }
    if (!strcmp(path, "/proc/filesystems")) {
        return guest_selinux() ? FS_TEXT_SE : FS_TEXT;
    }
    if (is_mounts_path(path)) {
        return guest_selinux() ? MOUNTS_TEXT_SE : MOUNTS_TEXT;
    }
    return NULL;
}

/*
 * ★ /proc/emmc — таблица разделов накопителя у ядер изготовителя. Команда
 * изготовителя `devwait emmc@<имя>` в init читает её, ищет раздел по имени и ждёт
 * его узел; без файла она пишет «can't find emmc@<имя> in /proc/emmc» (после
 * ожидания) и init идёт дальше, но каждая такая строка — потерянные секунды
 * подъёма, а mount_all без разделов не монтирует ничего. Что в файле — решает
 * стенд: имена и размеры разделов у каждой прошивки свои, транслятор их не знает
 * и не выдумывает. Содержимое GUEST_EMMC отдаётся как /proc/emmc целиком; нет
 * переменной или файл не читается — в режиме ENOENT (хозяйскую таблицу разделов, если
 * она у хозяина есть, гость не видит; guest_fs.c), без режима — как прежде.
 */
bool guest_fwinit_emmc(char **data, size_t *len)
{
    const char *f;
    gsize n = 0;

    if (!guest_fwinit()) {
        return false;
    }
    f = getenv("GUEST_EMMC");
    if (!f || f[0] != '/') {                /* только абсолютный путь (см. absolutize_paths) */
        return false;
    }
    {
        struct stat st;

        /* Таблица разделов — единицы килобайт: огромный файл не читаем. */
        if (stat(f, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size > (1 << 20)) {
            return false;
        }
    }
    if (!g_file_get_contents(f, data, &n, NULL)) {
        return false;
    }
    *len = n;
    return true;
}

/* ---------------------------------------------------- программа гостя: имя процесса */

/* Гостевой путь программы этого процесса: как её запустили, без realpath. */
static char prog[PATH_MAX];

/*
 * ★ Гостевой путь программы берём ДО realpath (linux-user/main.c): ссылки дерева
 * прошивки (`/system/bin/ls` → `toolbox`) realpath раскрывает, а ядро и стенд
 * знают программу по имени, с которым её запустили.
 */
void guest_fwinit_program(const char *host_path)
{
    char *g;

    if (!guest_fwinit() || !host_path) {
        return;
    }
    g = path_to_guest(host_path);
    snprintf(prog, sizeof prog, "%s", g ? g : host_path);
    g_free(g);
}

/*
 * ★ Имя процесса — гостевая программа: последние до 15 знаков её имени
 * (PR_SET_NAME; так же Android сокращает имена своих процессов).
 *
 * Симптом. После гостевого execve (патч 0005) транслятор перезапускает САМ СЕБЯ
 * через /proc/self/exe, и ядро хозяина зовёт процесс «exe»: журнал выходов
 * (патч 0070) и ps не знают, какая служба умерла.
 */
void guest_fwinit_comm(void)
{
    const char *b;
    size_t n;

    if (!guest_fwinit() || !prog[0]) {
        return;
    }
    b = strrchr(prog, '/');
    b = b ? b + 1 : prog;
    n = strlen(b);
    if (n > 15) {
        b += n - 15;
    }
    prctl(PR_SET_NAME, (unsigned long)b, 0, 0, 0);
}

/* ----------------------------------------- журнал запусков и помощники журналов */

/* Время в миллисекундах — как у журнала выходов (патч 0070). */
static long long now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Управляющие знаки — в «?»: одна строка журнала должна остаться одной строкой. */
static void clean(char *s)
{
    for (; *s; s++) {
        if ((unsigned char)*s < 0x20 || *s == 0x7f) {
            *s = '?';
        }
    }
}

/* Дозапись одной строки в файл из переменной; нет переменной — молча. */
static void put_line(const char *envname, const char *line, size_t n)
{
    const char *path = getenv(envname);
    int fd;

    if (!path || !*path) {
        return;
    }
    fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
        return;
    }
    (void)!write(fd, line, n);
    close(fd);
}

/*
 * GUEST_START_LOG: «<время_мс> <pid> <ppid> <гостевой путь программы> <argv[0]>».
 * Пишет каждый процесс транслятора при старте гостевой программы — и первый
 * запуск, и каждый execve (после него транслятор стартует заново).
 *
 * ⚠️ У сценария `#!` программа — его интерпретатор: execve уже заменил сценарий
 * интерпретатором (патч 0071), и до этого места доходит он.
 */
void guest_fwinit_start_log(const char *argv0)
{
    char a[1024], p[1024];
    char line[2300];
    int n;

    if (!guest_fwinit()) {
        return;
    }
    snprintf(p, sizeof p, "%s", prog[0] ? prog : "?");
    snprintf(a, sizeof a, "%s", argv0 ? argv0 : "");
    clean(p);
    clean(a);
    n = snprintf(line, sizeof line, "%lld %d %d %s %s\n", now_ms(),
                 (int)getpid(), (int)getppid(), p, a);
    if (n > 0 && n < (int)sizeof line) {
        put_line("GUEST_START_LOG", line, (size_t)n);
    }
}

/* ------------------------------------------------------ служба свойств init */

/*
 * ★ Записи свойств, принятые службой свойств init.
 *
 * Служба свойств у init — сокет /dev/socket/property_service: клиент
 * (setprop, любая служба) соединяется и шлёт ОДНО сообщение PROP_MSG_SETPROP —
 * 128 байт: cmd (4 байта, 1), имя (32) и значение (92), хвосты — нули. init
 * принимает его (accept → recv) и сам кладёт в область свойств. Формат области
 * у каждого поколения свой, а сообщение — одно и то же; поэтому стенд видит записи
 * здесь, не зная устройства области.
 *
 * Как узнаём «наш» сокет. Процесс, который сделал bind на гостевой путь сокета
 * службы свойств, — это init: запоминаем слушающий описатель (отметка
 * «слушающий»). Описатели из accept/accept4 на нём — соединения («приём»);
 * на каждый read/recv/recvfrom/recvmsg по такому описателю разбираем принятые
 * байты. close снимает отметку. Чужие сокеты (и сокеты других процессов — таблица
 * у каждого процесса транслятора своя, после execve она пуста) не трогаем.
 *
 * ⚠️ Сообщение собираем из принятых байт, а не из одного вызова: поколения
 * читают его по-разному (одним recv на 128 байт или кусками cmd/имя/значение).
 * Принятое с первым словом не 1 (запись «по новому протоколу» с переменной
 * длиной и пр.) пропускаем: до этого шага такие сообщения не разбираем.
 * ⚠️ Отметку снимает ТОЛЬКО close. dup2/dup3 поверх отмеченного номера и
 * close_range отметку не снимают (отмеченный номер, ставший чужим сокетом, даст
 * лишнюю строку журнала, если первое слово чужих байт совпадёт с cmd 1) — init
 * 2.3–4.4 так не делает.
 * ⚠️ Таблица на PROP_FDS описателей; переполнение — запись не отмечается (молча).
 * ⚠️ Строка журнала пишется ВНЕ замка таблицы (prop_emit зовётся после unlock):
 * медленный файл не должен держать чужие read, а fork в момент, когда замок
 * занят другим потоком, не должен оставить его занятым у ребёнка.
 */
#define PROP_SOCKET   "/dev/socket/property_service"
#define PROP_MSG_SIZE 128
#define PROP_NAME_MAX 32
#define PROP_VALUE_MAX 92
#define PROP_CMD_SETPROP 1
#define PROP_FDS 16

enum { PK_FREE = 0, PK_LISTEN, PK_CONN, PK_SKIP };

typedef struct {
    int fd;
    int kind;
    unsigned fill;
    unsigned char buf[PROP_MSG_SIZE];
} PropFd;

static PropFd pf[PROP_FDS];
static pthread_mutex_t pf_lock = PTHREAD_MUTEX_INITIALIZER;
/* Сколько отмеченных: быстрая проверка без замка на каждый read гостя. */
static int pf_count;

bool guest_fwinit_prop_path(const void *sockaddr, socklen_t len)
{
    const struct sockaddr_un *un = sockaddr;
    size_t off = offsetof(struct sockaddr_un, sun_path);
    size_t n, want = strlen(PROP_SOCKET);

    if (!guest_fwinit() || !un || len <= off || un->sun_family != AF_UNIX) {
        return false;
    }
    n = len - off;
    if (n > sizeof un->sun_path) {
        n = sizeof un->sun_path;
    }
    return strnlen(un->sun_path, n) == want &&
           memcmp(un->sun_path, PROP_SOCKET, want) == 0;
}

static PropFd *pf_find(int fd)
{
    int i;

    for (i = 0; i < PROP_FDS; i++) {
        if (pf[i].kind != PK_FREE && pf[i].fd == fd) {
            return &pf[i];
        }
    }
    return NULL;
}

/* Занять строку таблицы под fd с отметкой kind (замок взят). */
static void pf_mark(int fd, int kind)
{
    PropFd *e = pf_find(fd);
    int i;

    if (!e) {
        for (i = 0; i < PROP_FDS; i++) {
            if (pf[i].kind == PK_FREE) {
                e = &pf[i];
                __atomic_add_fetch(&pf_count, 1, __ATOMIC_RELAXED);
                break;
            }
        }
    }
    if (!e) {
        return;
    }
    e->fd = fd;
    e->kind = kind;
    e->fill = 0;
}

void guest_fwinit_prop_listener(int fd)
{
    const char *log = getenv("GUEST_PROP_LOG");

    if (!guest_fwinit() || !log || !*log || fd < 0) {
        return;
    }
    pthread_mutex_lock(&pf_lock);
    pf_mark(fd, PK_LISTEN);
    pthread_mutex_unlock(&pf_lock);
}

void guest_fwinit_prop_accepted(int lfd, int newfd)
{
    PropFd *e;

    if (!__atomic_load_n(&pf_count, __ATOMIC_RELAXED) || newfd < 0) {
        return;
    }
    pthread_mutex_lock(&pf_lock);
    e = pf_find(lfd);
    if (e && e->kind == PK_LISTEN) {
        pf_mark(newfd, PK_CONN);
    }
    pthread_mutex_unlock(&pf_lock);
}

void guest_fwinit_prop_closed(int fd)
{
    PropFd *e;

    if (!__atomic_load_n(&pf_count, __ATOMIC_RELAXED)) {
        return;
    }
    pthread_mutex_lock(&pf_lock);
    e = pf_find(fd);
    if (e) {
        e->kind = PK_FREE;
        __atomic_sub_fetch(&pf_count, 1, __ATOMIC_RELAXED);
    }
    pthread_mutex_unlock(&pf_lock);
}

/* Целое сообщение собрано: «<время_мс> <pid init> <имя>=<значение>». Замок НЕ держать. */
static void prop_emit(const unsigned char *m)
{
    char name[PROP_NAME_MAX + 1], value[PROP_VALUE_MAX + 1];
    char line[256];
    int n;

    memcpy(name, m + 4, PROP_NAME_MAX);
    name[PROP_NAME_MAX] = '\0';
    memcpy(value, m + 4 + PROP_NAME_MAX, PROP_VALUE_MAX);
    value[PROP_VALUE_MAX] = '\0';
    clean(name);
    clean(value);
    n = snprintf(line, sizeof line, "%lld %d %s=%s\n", now_ms(), (int)getpid(),
                 name, value);
    if (n > 0 && n < (int)sizeof line) {
        put_line("GUEST_PROP_LOG", line, (size_t)n);
    }
}

void guest_fwinit_prop_data(int fd, const void *buf, size_t n)
{
    const unsigned char *b = buf;

    if (!__atomic_load_n(&pf_count, __ATOMIC_RELAXED) || !b || n == 0) {
        return;
    }
    /*
     * За один проход под замком собираем не больше ОДНОГО сообщения: готовое
     * копируем себе, замок отпускаем и только потом пишем строку. Остаток
     * (в одном read бывает больше одного сообщения) берём следующим проходом.
     */
    while (n > 0) {
        unsigned char msg[PROP_MSG_SIZE];
        bool done = false;
        PropFd *e;

        pthread_mutex_lock(&pf_lock);
        e = pf_find(fd);
        if (!e || e->kind != PK_CONN) {
            pthread_mutex_unlock(&pf_lock);
            return;
        }
        while (n > 0 && !done) {
            size_t take = MIN(n, PROP_MSG_SIZE - e->fill);

            memcpy(e->buf + e->fill, b, take);
            e->fill += take;
            b += take;
            n -= take;
            if (e->fill >= 4 &&
                (e->buf[0] | e->buf[1] << 8 | e->buf[2] << 16 |
                 (unsigned)e->buf[3] << 24) != PROP_CMD_SETPROP) {
                e->kind = PK_SKIP;
                n = 0;
                break;
            }
            if (e->fill == PROP_MSG_SIZE) {
                memcpy(msg, e->buf, sizeof msg);
                e->fill = 0;
                done = true;
            }
        }
        pthread_mutex_unlock(&pf_lock);
        if (done) {
            prop_emit(msg);
        }
    }
}

void guest_fwinit_prop_iov(int fd, const struct iovec *iov, size_t cnt,
                           size_t total)
{
    size_t i;

    if (!__atomic_load_n(&pf_count, __ATOMIC_RELAXED)) {
        return;
    }
    for (i = 0; i < cnt && total > 0; i++) {
        size_t take = MIN(iov[i].iov_len, total);

        guest_fwinit_prop_data(fd, iov[i].iov_base, take);
        total -= take;
    }
}

/* ----------------------------------------------------------------- reboot */

/*
 * GUEST_REBOOT_LOG: «<время_мс> <pid> <имя программы> <cmd в hex> <строка|->».
 * Строка — довод RESTART2 (причина: «recovery», «bootloader»…); у прочих команд
 * и при пустой строке «-». Что вызов отвечает гостю, не меняется (патч 0073).
 * cmd — число без «0x»: 1234567 (RESTART), 4321fedc (POWER_OFF), a1b2c3d4
 * (RESTART2).
 */
#define REBOOT_CMD_RESTART2 0xA1B2C3D4u

void guest_fwinit_reboot(unsigned cmd, unsigned long arg)
{
    char name[17] = "";
    char why[128] = "";
    char line[320];
    int n;

    if (!guest_fwinit()) {
        return;
    }
    if (cmd == REBOOT_CMD_RESTART2 && arg) {
        char *s = lock_user_string((abi_ulong)arg);

        if (s) {
            snprintf(why, sizeof why, "%s", s);
            unlock_user(s, (abi_ulong)arg, 0);
        }
    }
    clean(why);
    prctl(PR_GET_NAME, (unsigned long)name, 0, 0, 0);
    clean(name);
    n = snprintf(line, sizeof line, "%lld %d %s %x %s\n", now_ms(),
                 (int)getpid(), name[0] ? name : "-", cmd, why[0] ? why : "-");
    if (n > 0 && n < (int)sizeof line) {
        put_line("GUEST_REBOOT_LOG", line, (size_t)n);
    }
}

/* ------------------------------------------- область свойств: имя не удаляется */

/*
 * ★ init 4.2–4.3 создаёт область свойств файлом /dev/__properties__ и сразу
 * удаляет имя: файл живёт, пока открыт описатель. Нашим помощникам стенда эта
 * область нужна ПО ПУТИ (читать свойства, которые init пишет в неё сам), и
 * удалённое имя им не найти. Поэтому unlink и unlinkat РОВНО этого гостевого
 * пути отвечают 0 и файл не трогают (патч 0083).
 *
 * ⚠️ Сверка дословная: «/dev//__properties__» или «/dev/./__properties__» — уже
 * другие строки и удаляются как обычно. Относительный путь (unlinkat с dirfd)
 * не проверяется, init зовёт по абсолютному. unlinkat с AT_REMOVEDIR — не
 * unlink, его не касаемся. Отвечаем 0 и когда файла нет (вызов ничего не знает
 * о файле).
 */
bool guest_fwinit_keep(const char *guest_path)
{
    return guest_fwinit() && guest_path &&
           strcmp(guest_path, "/dev/__properties__") == 0;
}

/* ------------------------------------------ запись в узел журнала ядра */

/*
 * ★ Гостевой путь под /dev/ — наш узел журнала ядра, то есть ссылка на файл
 * GUEST_KMSG (узел 1:11, см. guest_fwinit_mknod)? Настоящий /dev/kmsg ядро пишет
 * с дозаписью, а init и службы открывают узел на запись без O_APPEND и пишут с
 * нуля: открытие такого пути получает O_APPEND (патч 0082). Сверяем по ссылке
 * под корнем гостя, поэтому имя узла (__kmsg__, kmsg) не важно.
 *
 * ⚠️ Только абсолютные пути под /dev/: относительные (openat с dirfd) не
 * проверяются — init открывает узел по абсолютному.
 */
bool guest_fwinit_kmsg(const char *guest_path)
{
    const char *k;
    char link[PATH_MAX];
    ssize_t n;

    if (!guest_fwinit() || !guest_path || strncmp(guest_path, "/dev/", 5) != 0) {
        return false;
    }
    k = getenv("GUEST_KMSG");
    if (!k || *k != '/') {
        return false;
    }
    n = readlink(path(guest_path), link, sizeof link - 1);
    if (n <= 0) {
        return false;
    }
    link[n] = '\0';
    return strcmp(link, k) == 0;
}
