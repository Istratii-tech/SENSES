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

/* guest_fs.c — гостю показываем ЕГО раздел, а не диск телефона.
 *
 * ★★★ Зачем. Гостевой /data — это каталог в песочнице приложения, и statfs по
 * нему отдаёт цифры ВСЕГО накопителя хозяина: 471 ГБ, из них свободно
 * 3,3 ГБ. По абсолютной величине места вдоволь, а по доле — 0,7 %, и вот что
 * из этого выходит в Android 2.3:
 *
 *   * DeviceStorageMonitorService считает порог как долю от общего размера
 *     (верхнего ограничения в 2.3 ещё нет) — 10 % от 471 ГБ это 47 ГБ. Свободные
 *     3,3 ГБ меньше порога, и в шторке навсегда повисает «Low on space»;
 *   * PackageManager по этому признаку зовёт installd освобождать кэш, а тот
 *     обходит все пакеты и на каждом жалуется:
 *       E installd  Couldn't openat cache: No such file or directory
 *     — за одну загрузку таких строк набирается полторы сотни;
 *   * DropBoxManagerService.trimToFit падает в system_process на StatFs;
 *   * приложения, поднятые ради широковещания, валятся в обработчике ошибки.
 *
 * Аппараты тех лет имели раздел данных примерно в полтора гигабайта, и все эти
 * расчёты писались под такой порядок. Столько и показываем: числа взяты с
 * потолка, но они
 * ЗАНИЖЕНЫ относительно настоящего свободного места на телефоне — значит гость
 * не сможет пообещать себе больше, чем есть на самом деле.
 *
 * ⚠️ Подменяем только ветви гостя (/data, /cache, /mnt, /system, /sdcard).
 * Остальное — как есть: пусть /proc и /dev отвечают правдой.
 */
#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"

#include <sys/vfs.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

#include "guest_fs.h"
#include "guest_fwinit.h"
#include "guest_proc.h"
#include "guest_selinux.h"

/* Правдоподобный раздел данных тех лет: 1,5 ГБ всего, 1 ГБ свободно, блок 4 КБ. */
#define FS_BSIZE   4096u
#define FS_BLOCKS  393216u      /* 1,5 ГБ */
#define FS_FREE    262144u      /* 1,0 ГБ */
#define FS_FILES   65536u
#define FS_FFREE   60000u

static int ours(const char *p)
{
    static const char *const pre[] = {
        "/data", "/cache", "/mnt", "/system", "/sdcard", "/tmp", NULL
    };

    if (!p || p[0] != '/') {
        return 0;
    }
    for (int i = 0; pre[i]; i++) {
        size_t n = strlen(pre[i]);

        if (!strncmp(p, pre[i], n) && (p[n] == 0 || p[n] == '/')) {
            return 1;
        }
    }
    return 0;
}

void guest_fs_fake(const char *path, struct statfs *st)
{
    /*
     * ★ SELinux «всё разрешено» (GUEST_FWINIT=1 и GUEST_SELINUX=1): точка
     * /sys/fs/selinux — selinuxfs, f_type SELINUX_MAGIC (патч 0084).
     */
    if (guest_selinux_statfs(path, st)) {
        return;
    }
    if (!st || !ours(path)) {
        return;
    }
    st->f_bsize = FS_BSIZE;
    st->f_frsize = FS_BSIZE;
    st->f_blocks = FS_BLOCKS;
    st->f_bfree = FS_FREE;
    st->f_bavail = FS_FREE;
    st->f_files = FS_FILES;
    st->f_ffree = FS_FFREE;
}

/*
 * ★ Группы планировщика: /proc/<tid>/cgroup гость должен видеть СВОЙ.
 *
 * libcutils 2.3 определяет группу потока чтением этого файла и понимает ровно
 * два вида строк — «/» и «/bg_non_interactive». Хозяйский Android 16 отдаёт ему
 * свои группы («top-app», «background» и прочие), и Dalvik на КАЖДОМ обращении
 * пишет в лог две строки:
 *
 *   W dalvikvm  Fail to determine scheduling group 'top-app'
 *   E dalvikvm  Cannot get policy, owner thread id=…
 *
 * За две минуты работы их набирается больше двух тысяч — четверть всего
 * гостевого лога, и каждая строка это ещё и лишнее чтение /proc.
 *
 * Отдаём безобидное «обычная группа»: поток считается интерактивным, что для
 * нас и верно — планировщиком гостя мы всё равно не управляем.
 */
static const char CGROUP_TEXT[] = "2:cpu:/\n";

/*
 * ★★★★★ СПИСОК СЕТЕВЫХ УСТРОЙСТВ — НАШ, А НЕ ХОЗЯЙСКИЙ.
 *
 * `/sys/class/net` гостю подменяет дерево (там лежит одна петля), а этот файл
 * он читал У ХОЗЯИНА — со всеми два десятками `rmnet*`, с `p2p0` и, главное,
 * с живым `wlan0` телефона вместе со счётчиками его трафика:
 *
 *     wlan0: 27300642 60570 0 0 … 17190396 60748 …
 *
 * Это не просто утечка сведений об аппарате. Прошивка ВИДИТ работающий Wi-Fi
 * там, где его быть не должно, и принимается им распоряжаться: настроить
 * адрес (чужой!), поднять супликант, перезалить прошивку адаптера — и так по
 * кругу, рассылая состояние всем подписчикам через диспетчер задач. Один
 * такой круг стоил стенду 1224 посылок за шесть минут и однажды — дедлока.
 *
 * Подменяем ИМЕННО этот путь. Дерево здесь не поможет: `/proc` гостю нужен
 * настоящий (свой `/proc/self`, свои `/proc/<pid>`), и оно его не уводит.
 *
 * ⚠️ Счётчики нули, и это честно: сеть гостя идёт хозяйскими сокетами, а не
 * через петлю. Чужой счётчик был бы враньём, свой — правдой про ноль.
 */
static const char NETDEV_TEXT[] =
    "Inter-|   Receive                                                "
    "|  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast"
    "|bytes    packets errs drop fifo colls carrier compressed\n"
    "    lo:       0       0    0    0    0     0          0         0"
    "        0       0    0    0    0     0       0          0\n";

/*
 * ★★★ ПАМЯТЬ — НАША, А НЕ ХОЗЯЙСКАЯ.
 *
 * `/proc/meminfo` гость читал у хозяина и видел его гигабайты. Две беды сразу:
 *
 *   * опознаватель телефона (объём памяти у моделей разный), а гость знать про
 *     аппарат не должен (V.5);
 *   * прошивка раскладывает по этим числам СВОИ пределы — размер кучи Dalvik,
 *     пороги прибирания процессов, кэш картинок. На телефоне с 12 ГБ она
 *     считает себя хозяйкой 12 ГБ, а получит столько, сколько мы ей дали.
 *
 * Числа — те же, что клал в дерево `tools/mktree.sh`: правдоподобный аппарат
 * тех лет, 1,8 ГБ. ⚠️ Здесь, а не в дереве: дерево на телефоне собирает
 * `Installer`, и `proc/` он не кладёт вовсе — подмена в дереве работала только
 * у деревьев, собранных на машине.
 *
 * ⚠️ Числа статические, и это осознанно: «свободно» у нас не меняется, зато
 * гость никогда не увидит ни тесноты чужого телефона, ни его простора.
 */
static const char MEMINFO_TEXT[] =
    "MemTotal:        1846588 kB\n"
    "MemFree:          742216 kB\n"
    "Buffers:           28152 kB\n"
    "Cached:           402384 kB\n"
    "SwapCached:            0 kB\n"
    "Active:           520316 kB\n"
    "Inactive:         281944 kB\n"
    "Active(anon):     372660 kB\n"
    "Inactive(anon):     2372 kB\n"
    "Active(file):     147656 kB\n"
    "Inactive(file):   279572 kB\n"
    "Unevictable:         256 kB\n"
    "Mlocked:               0 kB\n"
    "HighTotal:       1245184 kB\n"
    "HighFree:         381208 kB\n"
    "LowTotal:         601404 kB\n"
    "LowFree:          361008 kB\n"
    "SwapTotal:             0 kB\n"
    "SwapFree:              0 kB\n"
    "Dirty:                 0 kB\n"
    "Writeback:             0 kB\n"
    "AnonPages:        371992 kB\n"
    "Mapped:           182664 kB\n"
    "Shmem:              3080 kB\n"
    "Slab:              54620 kB\n"
    "SReclaimable:      24176 kB\n"
    "SUnreclaim:        30444 kB\n"
    "KernelStack:        9432 kB\n"
    "PageTables:        18256 kB\n"
    "NFS_Unstable:          0 kB\n"
    "Bounce:                0 kB\n"
    "WritebackTmp:          0 kB\n"
    "CommitLimit:      923292 kB\n"
    "Committed_AS:   16558312 kB\n"
    "VmallocTotal:     245760 kB\n"
    "VmallocUsed:       92416 kB\n"
    "VmallocChunk:      70652 kB\n";

/*
 * ★★★ ОСТАЛЬНОЙ `/proc/net` — ТОЖЕ НАШ.
 *
 * `/proc/net/dev` подменялся давно (выше), а соседние файлы гость читал у
 * хозяина и получал из них весь телефон целиком:
 *
 *   * `route` — домашняя сеть и шлюз по умолчанию;
 *   * `arp` — аппаратные адреса соседей по сети (опознаёт квартиру, не только
 *     телефон);
 *   * `if_inet6` — адреса хозяина, из них выводится аппаратный адрес;
 *   * `tcp`, `udp` (и `tcp6`, `udp6`) — ВСЕ соединения телефона вместе с
 *     чужими `uid`: с кем говорит владелец и какими программами;
 *   * `xt_qtaguid/stats` — счётчики трафика по приложениям хозяина; у него он
 *     обычно закрыт правами, и гость получал `Permission denied`, отчего
 *     служба статистики прошивки заваливала журнал
 *     `Failed to parse network stats`.
 *
 * Отвечаем тем же, что уже говорим в `/proc/net/dev` и `/sys/class/net`: у
 * гостя одна петля и ничего больше. Это не выдумка — сеть гостя идёт нашими
 * сокетами, а не его таблицей маршрутизации.
 *
 * ⚠️ Заголовок оставляем настоящий: разборщики прошивки читают файл строками и
 * первую пропускают. Пустой файл они считают ошибкой чтения.
 */
static const char ROUTE_TEXT[] =
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\t"
    "MTU\tWindow\tIRTT\n"
    "lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n";

static const char ARP_TEXT[] =
    "IP address       HW type     Flags       HW address            Mask"
    "     Device\n";

/* ⚠️ У этого файла заголовка нет вовсе — только строки. Наша одна: ::1 на lo. */
static const char IF_INET6_TEXT[] =
    "00000000000000000000000000000001 01 80 10 80       lo\n";

static const char TCP_TEXT[] =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode\n";

static const char UDP_TEXT[] =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode ref pointer drops\n";

static const char TCP6_TEXT[] =
    "  sl  local_address                         remote_address"
    "                        st tx_queue rx_queue tr tm->when retrnsmt   uid"
    "  timeout inode\n";

static const char UDP6_TEXT[] =
    "  sl  local_address                         remote_address"
    "                        st tx_queue rx_queue tr tm->when retrnsmt   uid"
    "  timeout inode ref pointer drops\n";

static const char QTAGUID_TEXT[] =
    "idx iface acct_tag_hex uid_tag_int cnt_set rx_bytes rx_packets tx_bytes"
    " tx_packets rx_tcp_bytes rx_tcp_packets rx_udp_bytes rx_udp_packets"
    " rx_other_bytes rx_other_packets tx_tcp_bytes tx_tcp_packets"
    " tx_udp_bytes tx_udp_packets tx_other_bytes tx_other_packets\n";

/*
 * ★ Итог по интерфейсам (регресс 24.09, Р-29). Служба статистики сети 4.2 и 4.4
 * (`NetworkStatsFactory`) читает не только `stats`, но и `iface_stat_fmt`
 * (сводка, первая строка — заголовок) и `iface_stat_all` (без заголовка). У
 * хозяина оба закрыты правами, как и `stats`: гость получал `EACCES`, и на
 * каждом опросе служба писала `Log.wtf` «problem reading network stats» — в
 * летописи №3 это тридцать записей «проверка не прошла [NetworkStats]».
 * Отвечаем как ядро без интерфейсов: заголовок и ни одной строки.
 */
static const char QTAGUID_IFACE_FMT_TEXT[] =
    "ifname total_skb_rx_bytes total_skb_rx_packets total_skb_tx_bytes"
    " total_skb_tx_packets\n";

/* Путь → готовый текст. Сверка ТОЧНАЯ, по полному имени. */
static const struct {
    const char *path;
    const char *text;
} SUBST[] = {
    { "/proc/net/dev",               NETDEV_TEXT  },
    { "/proc/meminfo",               MEMINFO_TEXT },
    { "/proc/net/route",             ROUTE_TEXT   },
    { "/proc/net/arp",               ARP_TEXT     },
    { "/proc/net/if_inet6",          IF_INET6_TEXT},
    { "/proc/net/tcp",               TCP_TEXT     },
    { "/proc/net/udp",               UDP_TEXT     },
    { "/proc/net/tcp6",              TCP6_TEXT    },
    { "/proc/net/udp6",              UDP6_TEXT    },
    { "/proc/net/xt_qtaguid/stats",  QTAGUID_TEXT },
    { "/proc/net/xt_qtaguid/iface_stat_fmt", QTAGUID_IFACE_FMT_TEXT },
    { "/proc/net/xt_qtaguid/iface_stat_all", "" },      /* у этого заголовка нет */
};

/*
 * Отдать гостю готовый текст вместо хозяйского файла.
 *
 * ★★★★★ ЗДЕСЬ БЫЛ `tmpfile()`, И ИЗ-ЗА НЕГО НИ ОДНА ПОДМЕНА НЕ РАБОТАЛА НА
 * ТЕЛЕФОНЕ — НИ РАЗУ, ЗА ВСЁ ВРЕМЯ.
 *
 * `tmpfile()` по стандарту заводит файл в `/tmp`. На машине с Linux он есть, и
 * проверка проходила; на Android каталога `/tmp` НЕТ ВОВСЕ, вызов отвечает
 * отказом, а мы на отказе возвращали 0 — «пусть читает хозяйский». То есть
 * подмена молча превращалась в свою противоположность ровно там, где она и
 * нужна.
 *
 * Снаружи это не выглядело никак: отказа нет, в журнале ни строки, файл
 * читается. Поймано только прямым замером с телефона 22.09:
 *
 *     qrun busybox cat /proc/net/dev    → lo, p2p0, sit0 и счётчики хозяина
 *     qrun busybox cat /proc/self/cgroup → cpuset, schedtune, cpuacct/uid_0/…
 *
 * — то есть ровно то, от чего подмена и защищала. В книге это стояло как
 * «закрыто и перепроверено» (см. 8.2: проверять надо саму работу, а не наличие
 * кода).
 *
 * ★ Теперь память, а не файловая система: `memfd_create` не зависит ни от
 * какого каталога и есть во всех ядрах с 3.17 — то есть у любого хозяина, на
 * который мы ставимся (Android 8 и новее). `tmpfile()` оставлен запасным: на
 * обычной машине с Linux он и так работал.
 */
static int give_text(const char *text, size_t len, int *fd)
{
    int d = -1;

#ifdef __NR_memfd_create
    d = (int)syscall(__NR_memfd_create, "guestfs", 0);
#endif
    if (d < 0) {
        FILE *f = tmpfile();

        if (!f) {
            return 0;                 /* не смогли — пусть читает хозяйский */
        }
        d = dup(fileno(f));
        fclose(f);
        if (d < 0) {
            return 0;
        }
    }
    for (size_t off = 0; off < len; ) {
        ssize_t w = write(d, text + off, len - off);

        if (w <= 0) {
            close(d);
            return 0;
        }
        off += (size_t)w;
    }
    lseek(d, 0, SEEK_SET);
    *fd = d;
    return 1;
}

int guest_fs_try_open(const char *path, int *fd)
{
    size_t n;

    if (!path || strncmp(path, "/proc/", 6)) {
        return 0;
    }
    {
        /*
         * ★ Режим «init прошивки» (GUEST_FWINIT=1): строка ядра гостя,
         * список файловых систем и точки монтирования — без selinuxfs и без
         * хозяйских данных. Без переменной guest_fwinit_proc_text отвечает
         * NULL, и всё идёт как прежде (см. guest_fwinit.c).
         */
        char tbuf[1024];                /* для /proc/cmdline: свой у каждого вызова */
        const char *t = guest_fwinit_proc_text(path, tbuf, sizeof tbuf);

        if (t) {
            return give_text(t, strlen(t), fd);
        }
    }
    /*
     * ★ Режим «init прошивки»: /proc/emmc — из файла стенда GUEST_EMMC (команда
     * изготовителя devwait ищет в нём разделы). Без переменной — ENOENT (в режиме).
     */
    if (!strcmp(path, "/proc/emmc")) {
        char *data;
        size_t len;

        if (guest_fwinit_emmc(&data, &len)) {
            int r = give_text(data, len, fd);

            g_free(data);
            return r;
        }
        /*
         * В режиме без GUEST_EMMC (или с нечитаемым файлом) хозяйской таблицы разделов
         * гость не видит, даже если у хозяина /proc/emmc есть: ENOENT. Без режима — как прежде.
         */
        if (guest_fwinit()) {
            *fd = -1;
            errno = ENOENT;
            return 1;
        }
        return 0;
    }
    /*
     * ★ `/proc/version` (регресс 24.09, Р-31). У хозяина он закрыт правами
     * (`EACCES`), и гость на каждой загрузке писал «BootReceiver: Can't log
     * boot events», отчёт об ошибках прошивки — то же, а «О телефоне» в
     * Настройках показывал вместо версии ядра «недоступно». Отвечаем строкой,
     * согласной с `uname` (0061): версия — из ключа `-r`, сборщик и узел —
     * «localhost». Дата постоянная — Настройки 4.x разбирают строку только с
     * датой, а по постоянной хозяина не узнать. Без `-r` не вмешиваемся (то же
     * правило, что у 0061).
     */
    if (!strcmp(path, "/proc/version") && qemu_uname_release && *qemu_uname_release) {
        char t[192];
        int k = snprintf(t, sizeof t, "Linux version %s (android-build@localhost) "
                         "(gcc version 4.8 (GCC) ) #1 SMP PREEMPT "
                         "Mon Jan 1 00:00:00 UTC 2018\n", qemu_uname_release);

        return k > 0 && k < (int)sizeof t ? give_text(t, (size_t)k, fd) : 0;
    }
    /*
     * ★ Р-116: /proc/net — у ядра ссылка на self/net, и то же отдают
     * /proc/<свой pid>/net/…, /proc/self/task/<tid>/net/…, /proc/thread-self/net/…
     * (чей путь — guest_proc.c). Иначе по ним гость читал сеть ХОЗЯИНА. Сверка с
     * таблицей — по имени /proc/net/…; прочие проверки ниже — по исходному пути.
     */
    const char *rest = strstr(path + 6, "/net/") ? guest_proc_mine_rest(path) : NULL;
    const char *look = path;
    char alias[128];

    if (rest && !strncmp(rest, "net/", 4) &&
        snprintf(alias, sizeof alias, "/proc/%s", rest) < (int)sizeof alias) {
        look = alias;
    }
    for (size_t i = 0; i < ARRAY_SIZE(SUBST); i++) {
        if (!strcmp(look, SUBST[i].path)) {
            return give_text(SUBST[i].text, strlen(SUBST[i].text), fd);
        }
    }
    n = strlen(path);
    if (n < 7 || strcmp(path + n - 7, "/cgroup")) {
        return 0;
    }
    return give_text(CGROUP_TEXT, sizeof CGROUP_TEXT - 1, fd);
}
