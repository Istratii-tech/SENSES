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

/* guest_net.c — подставной netlink для гостевых служб.
 *
 * Зачем. netd и vold прошивки первым делом заводят сокет событий ядра:
 *
 *   int NetlinkManager::start() {
 *       mSock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT);
 *       setsockopt(mSock, SOL_SOCKET, SO_RCVBUFFORCE, …);
 *       bind(mSock, …);
 *       mHandler->start();
 *   }
 *
 * Процессу приложения на Android этого не дают — политика SELinux не пускает
 * untrusted_app создавать netlink_kobject_uevent_socket:
 *
 *   I Netd  Netd 1.0 starting
 *   E Netd  Unable to create uevent socket: Permission denied
 *   E Netd  Unable to start NetlinkManager (Permission denied)
 *   · netd завершился, код 1
 *
 * И это не мелочь: без netd загрузка встаёт НАВСЕГДА.
 * NetworkManagementService.create ждёт его соединения на
 * mConnectedSignal.await(), а в логе видно лишь бесконечное
 * «NetdConnector: Communications error».
 *
 * Что делаем. Ровно то же, что с ashmem и binder: даём безвредную замену там,
 * где хозяйское ядро отказывает. Гость получает обычный AF_UNIX SOCK_DGRAM —
 * несвязанный и никому не известный. Читать из него можно, и чтение честно
 * блокируется навсегда: событий ядра у нас и не будет. Поток-слушатель внутри
 * netd спит на нём, а всё остальное — приём команд от system_server — работает.
 *
 * ★ Подменяем ТОЛЬКО когда настоящий вызов отказал по правам. Там, где netlink
 * доступен (например на обычном Linux), гость получит настоящий сокет и настоящие
 * события. Подмена не должна прятать работающую возможность.
 *
 * ⚠️ bind и setsockopt на подставном дескрипторе отвечают успехом, не делая
 * ничего: гость шлёт им sockaddr_nl и SO_RCVBUFFORCE, которые для AF_UNIX
 * бессмысленны, а отказ на любом из них netd считает смертельным.
 *
 * ★★★★★ 14 сентября: МОЛЧАНИЕ ПОДСТАВНОГО СОКЕТА ВЕШАЛО ВЕСЬ ВЕБ.
 *
 * «Читать можно, чтение блокируется навсегда» — для netd безобидно (его поток
 * событий и должен спать), а для браузера оказалось смертельно. Сетевая часть
 * Движок браузера прошивки (libbrowsercore → libbrowsernet) при создании
 * КАЖДОЙ страницы делает так:
 *
 *   BrowserFrame.nativeCreateFrame
 *     → net::NetworkChangeNotifier::Create()
 *       → NetworkChangeNotifierLinux()
 *         → base::Thread::StartWithOptions()   ← ЖДЁТ, пока поток отчитается
 *
 * а сам поток ПЕРЕД тем как отчитаться просит у ядра список адресов
 * (RTM_GETADDR, дамп) и читает ответ ПОДРЯД, пока не придёт NLMSG_DONE.
 * Ответа нет — поток не отчитывается — StartWithOptions стоит вечно —
 * nativeCreateFrame не возвращается — страница не рисуется НИКОГДА. Снято на
 * живом стенде: поток висит в recvfrom(fd, …, 4096), wchan =
 * __skb_wait_for_more_packets, а его создатель — в WaitableEvent::Wait.
 * Отсюда и «полоса встала на 35 %, содержимое белое» — даже для file://.
 *
 * Поэтому подставной сокет теперь не немой. Вместо одинокого AF_UNIX берём
 * ПАРУ: один конец отдаём гостю, второй держим у себя и отвечаем на запросы
 * дампов сами — одним интерфейсом (поднят, не петля) с адресом, и NLMSG_DONE.
 * Событий по-прежнему нет: ждущий их поток netd спит, как и спал.
 *
 * ⚠️ Почему «есть интерфейс», а не «пусто»: у движка браузера пустой список линков
 * означает CONNECTION_NONE, то есть «сети нет вовсе», и он начинает отказывать
 * запросам сам, не доходя до сокета. А сеть у гостя как раз ЕСТЬ — она идёт
 * через хозяйское ядро (см. guest_http_redirect ниже). Так что один поднятый
 * интерфейс — не выдумка, а самое близкое к правде, что можно сказать в
 * терминах netlink.
 */
#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "guest_net.h"

/* Подставных сокетов бывает единицы: netd и vold по одному. */
#define GUEST_NET_MAX 16

/*
 * ★ Наш конец пары (peers[i]) — тот, в который мы пишем ответы гостю. Гость о
 * нём не знает и видеть его не должен: для него это обычный сокет netlink.
 */
static int fds[GUEST_NET_MAX];
static int peers[GUEST_NET_MAX];
/*
 * ★★★★★ НОМЕР ПОРТА И ГРУППЫ — НЕ УКРАШЕНИЕ, А ПОЛОВИНА ОТВЕТА.
 *
 * У netlink нет «соединения»: и запрос, и ответ — датаграммы, и потребитель
 * отличает свои от чужих по ТРЁМ полям сразу. Вот проверка из libnetlink, по
 * которой живут все `ip …` прошивки (rtnl_dump_filter_l, rtnl_talk):
 *
 *     if (nladdr.nl_pid != 0 ||                  ← пришло НЕ от ядра
 *         h->nlmsg_pid != rth->local.nl_pid ||   ← адресовано НЕ НАМ
 *         h->nlmsg_seq != rth->dump)             ← не на наш запрос
 *             goto skip_it;                      ← молча выбросить и читать дальше
 *
 * Пока мы отвечали, копируя nlmsg_pid ИЗ ЗАПРОСА (а там ноль), второе условие
 * не сходилось никогда: наш ответ выбрасывался целиком, и следующее чтение
 * вставало навсегда. Снаружи это выглядело как повисший `ip rule flush`,
 * который держал netd, а с ним имена и конец загрузки (20 сентября).
 *
 * Поэтому помним, каким номером порта гость себя знает:
 *   * забрали настоящий netlink — берём номер С НЕГО (getsockname ДО подмены):
 *     потребитель уже спросил его у ядра и запомнил;
 *   * подменили с самого начала — берём тот, которым гость назвался в bind,
 *     а если он попросил «любой» (ноль), выдаём свой pid, как делает ядро.
 */
static uint32_t nlpid[GUEST_NET_MAX];
static uint32_t nlgrp[GUEST_NET_MAX];
static int nfds;

/*
 * Битовая карта наших дескрипторов — чтобы отвечать на «наш ли это?» без
 * замка (см. guest_net_owns). Номера дескрипторов у гостя невелики; всё, что
 * выше потолка, заведомо не наше.
 */
#define GUEST_NET_FDBITS 4096
static uint32_t owned[GUEST_NET_FDBITS / 32];

static void own_set(int fd, int on)
{
    if (fd < 0 || fd >= GUEST_NET_FDBITS) {
        return;
    }
    if (on) {
        qatomic_or(&owned[fd / 32], 1u << (fd % 32));
    } else {
        qatomic_and(&owned[fd / 32], ~(1u << (fd % 32)));
    }
}
static QemuMutex lock;
static bool inited;

/* Забыть цель запроса имён при закрытии дескриптора (тело ниже). */
static void dns_forget(int fd);

static void net_init(void)
{
    if (!inited) {
        qemu_mutex_init(&lock);
        inited = true;
    }
}

/*
 * Свой журнал, а не qemu_log_mask.
 *
 * ⚠️ qemu_log_mask из процесса, полученного FORK'ом (а все приложения гостя —
 * форки зиготы), до файла может и не дойти: блокировку журнала qemu берёт
 * через RCU, а её состояние форк не переносит. Поймано 14 сентября: подмена
 * netlink в браузере ТОЧНО случилась (сокет виден в /proc/net/unix), а строки
 * о ней в qemu-app_process.log не было. Поэтому здесь — обычный файл в режиме
 * дописывания, как у шима binder.
 */
static FILE *g_nlog;

static void nlog_init(void)
{
    static int done;
    const char *path;

    if (done) {
        return;
    }
    done = 1;
    path = getenv("GUEST_NET_LOG");
    if (!path || !*path) {
        return;
    }
    g_nlog = (path[0] == '-' && !path[1]) ? stderr : fopen(path, "ae");
}

static void nlog(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void nlog(const char *fmt, ...)
{
    va_list ap;

    nlog_init();
    if (!g_nlog) {
        return;
    }
    fprintf(g_nlog, "[pid=%d] ", getpid());
    va_start(ap, fmt);
    vfprintf(g_nlog, fmt, ap);
    va_end(ap);
    fputc('\n', g_nlog);
    fflush(g_nlog);
}

int guest_net_socket_fallback(int domain, int type, int protocol, int *fd)
{
    int s, i, sv[2];

    if (domain != PF_NETLINK) {
        return 0;
    }
    /*
     * Только отказ по правам. ENOSYS или EPROTONOSUPPORT — это другой разговор,
     * и прятать их подменой значило бы врать гостю о том, чего нет вовсе.
     */
    if (errno != EACCES && errno != EPERM) {
        return 0;
    }

    /* Флаги создания сохраняем: гость мог просить SOCK_CLOEXEC/SOCK_NONBLOCK. */
    if (socketpair(AF_UNIX, SOCK_DGRAM | (type & ~0xf /* SOCK_TYPE_MASK */),
                   0, sv) < 0) {
        return 0;
    }
    s = sv[0];

    net_init();
    qemu_mutex_lock(&lock);
    if (nfds >= GUEST_NET_MAX) {
        qemu_mutex_unlock(&lock);
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    for (i = 0; i < nfds; i++) {
        if (fds[i] == s) {          /* номер переиспользован после close */
            break;
        }
    }
    if (i == nfds) {
        nfds++;
    } else {
        close(peers[i]);            /* прежняя пара за тем же номером */
    }
    fds[i] = s;
    peers[i] = sv[1];
    nlpid[i] = 0;                   /* номер порта выдадим при первом спросе */
    nlgrp[i] = 0;
    own_set(s, 1);
    qemu_mutex_unlock(&lock);

    nlog("socket: netlink(%d) запрещён хозяином — подставлена пара AF_UNIX, "
         "дескриптор %d", protocol, s);
    *fd = s;
    return 1;
}

/*
 * ★ Второй заход той же беды: сокет создать дали, а ПРИВЯЗАТЬ не дали.
 *
 * На этом телефоне socket(PF_NETLINK, SOCK_DGRAM, NETLINK_KOBJECT_UEVENT)
 * проходит, и подмена выше не включается, — а следующий же bind отвечает
 * «Permission denied», и netd 4.1 умирает так же насмерть:
 *
 *   E Netd  Unable to bind netlink socket: Permission denied
 *   E Netd  Unable to start NetlinkManager (Permission denied)
 *
 * Лечение то же по смыслу: за тем же НОМЕРОМ дескриптора ставим безвредный
 * AF_UNIX (dup2), и дальше он ведёт себя как подставной — чтение из него
 * блокируется навсегда, потому что событий ядра у нас всё равно не будет.
 * Номер не меняется, поэтому гость ничего не замечает.
 */
/*
 * Забрать netlink себе: за тем же номером дескриптора ставим пару AF_UNIX и
 * записываем её в таблицу. Общее для двух случаев — «не дали привязать» и
 * «не дали послать» (см. guest_net_adopt).
 */
static int netlink_take_over(int sockfd, const char *why)
{
    int dom = 0, i, sv[2], fl, fdfl;
    socklen_t len = sizeof(dom);
    struct sockaddr_nl was;
    socklen_t waslen = sizeof(was);
    uint32_t keep_pid = 0, keep_grp = 0;

    if (sockfd < 0) {
        return 0;
    }
    /* Только netlink: чужие сокеты подменять не наше дело. */
    if (getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &dom, &len) < 0 ||
        dom != PF_NETLINK) {
        return 0;
    }

    /*
     * ★★★★★ НОМЕР ПОРТА СНИМАЕМ ДО ПОДМЕНЫ — ВТОРОГО СЛУЧАЯ НЕ БУДЕТ.
     *
     * Сюда мы приходим, когда хозяин дал сокет СОЗДАТЬ и ПРИВЯЗАТЬ, но не дал
     * послать. Значит потребитель уже сделал getsockname на настоящем netlink
     * и запомнил выданный ядром номер (`rth->local.nl_pid` у libnetlink). С
     * этой минуты он будет сверять с ним КАЖДЫЙ ответ — и наш выбросит, если
     * мы назовёмся иначе. После dup2 спросить будет уже не у кого: за этим
     * номером станет AF_UNIX.
     */
    memset(&was, 0, sizeof(was));
    if (getsockname(sockfd, (struct sockaddr *)&was, &waslen) == 0 &&
        waslen >= sizeof(was) && was.nl_family == AF_NETLINK) {
        keep_pid = was.nl_pid;
        keep_grp = was.nl_groups;
    }

    /*
     * ★★★★★ ФЛАГИ ДЕСКРИПТОРА СОХРАНЯЕМ. Это не мелочь, а ГЛАВНАЯ причина
     * того, что браузер прошивки не рисовал ни одной страницы (14 сентября).
     *
     * Гость ставит флаги ДО bind, и dup2 их сносит: новый дескриптор берёт
     * состояние нового файла, а не прежнего. Наблюдатель за сетью у движка браузера
     * (net::NetworkChangeNotifierLinux, старая ветка — в libbrowsernet она
     * без AddressTracker) делает ровно так:
     *
     *   sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
     *   fcntl(sock, F_SETFL, flags | O_NONBLOCK);      ← ставит НЕБЛОКИРУЮЩИЙ
     *   bind(sock, …);                                 ← ЗДЕСЬ наша подмена
     *   … ListenForNotifications(): recv(sock, buf, 4096, 0) до EAGAIN …
     *
     * Он ВЫЧЁРПЫВАЕТ накопившееся, ожидая отказа EAGAIN как признака «пусто», и
     * только потом отдаёт дескриптор своему циклу событий и отчитывается «поток
     * встал». Наш подставной сокет приезжал БЛОКИРУЮЩИМ — и первый же recv
     * вставал навсегда. А ждал его создатель:
     *
     *   BrowserFrame.nativeCreateFrame → NetworkChangeNotifier::Create()
     *     → base::Thread::StartWithOptions() → WaitableEvent::Wait()
     *
     * то есть создание КАЖДОЙ страницы. Отсюда «полоса встала на 35 %, лист
     * белый» — и для сетевых страниц, и для локального file://.
     *
     * ⚠️ F_GETFD тоже: dup2 сбрасывает FD_CLOEXEC на новом дескрипторе.
     */
    fl = fcntl(sockfd, F_GETFL, 0);
    fdfl = fcntl(sockfd, F_GETFD, 0);

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        return 0;
    }
    if (dup2(sv[0], sockfd) < 0) {
        close(sv[0]);
        close(sv[1]);
        return 0;
    }
    close(sv[0]);
    if (fl >= 0) {
        fcntl(sockfd, F_SETFL, fl);
    }
    if (fdfl >= 0) {
        fcntl(sockfd, F_SETFD, fdfl);
    }

    net_init();
    qemu_mutex_lock(&lock);
    for (i = 0; i < nfds; i++) {
        if (fds[i] == sockfd) {
            break;
        }
    }
    if (i == nfds) {
        if (nfds >= GUEST_NET_MAX) {
            qemu_mutex_unlock(&lock);
            close(sv[1]);
            return 0;
        }
        nfds++;
    } else {
        close(peers[i]);            /* прежняя пара за тем же номером */
    }
    fds[i] = sockfd;
    peers[i] = sv[1];
    nlpid[i] = keep_pid;
    nlgrp[i] = keep_grp;
    own_set(sockfd, 1);
    qemu_mutex_unlock(&lock);

    nlog("%s — за дескриптором %d теперь пара AF_UNIX "
         "(флаги файла 0x%x сохранены, номер порта %u, группы 0x%x)",
         why, sockfd, fl, keep_pid, keep_grp);
    return 1;
}

int guest_net_bind_fallback(int sockfd)
{
    /* Только отказ по правам — см. оговорку в guest_net_socket_fallback. */
    if (errno != EACCES && errno != EPERM) {
        return 0;
    }
    return netlink_take_over(sockfd, "bind: netlink запрещён хозяином");
}

/*
 * ★★★ БЕЗ ЗАМКА. Это не оптимизация, а исправление ошибки.
 *
 * guest_net_owns зовётся на КАЖДУЮ посылку в сокет — а весь binder стенда живёт
 * на сокетах (sendmsg к демону). Замок здесь означал бы, что все потоки всех
 * процессов выстраиваются в очередь на общий мьютекс ради проверки «а не наш
 * ли это дескриптор», и это на самом горячем пути системы.
 *
 * ⚠️ Хуже того, замок на этом пути опасен при fork: если в момент форка его
 * держал другой поток, ребёнку достаётся ЗАПЕРТЫЙ мьютекс, и первая же посылка
 * в нём встаёт навсегда. Гостевые процессы рождаются форком зиготы — то есть
 * под удар попадает любое приложение.
 *
 * Поэтому держим битовую карту и читаем её без замка. Запись по-прежнему под
 * замком; гонка чтения безобидна: дескриптор либо уже наш, либо ещё не наш, и
 * оба ответа верны для того мгновения, когда вопрос задан.
 */
int guest_net_owns(int fd)
{
    if (!inited || fd < 0 || fd >= GUEST_NET_FDBITS) {
        return 0;
    }
    return (qatomic_read(&owned[fd / 32]) >> (fd % 32)) & 1;
}

void guest_net_close(int fd)
{
    int i, peer = -1;

    if (!inited || fd < 0) {
        return;
    }
    qemu_mutex_lock(&lock);
    for (i = 0; i < nfds; i++) {
        if (fds[i] == fd) {
            peer = peers[i];
            own_set(fd, 0);
            --nfds;
            fds[i] = fds[nfds];
            peers[i] = peers[nfds];
            nlpid[i] = nlpid[nfds];
            nlgrp[i] = nlgrp[nfds];
            break;
        }
    }
    qemu_mutex_unlock(&lock);
    /* ⚠️ Закрываем ВНЕ замка: close может занять время, а таблица нужна другим. */
    if (peer >= 0) {
        close(peer);
    }
    dns_forget(fd);
}

/*
 * ★★★★★ Ответы на запросы дампа: почему подставной netlink обязан говорить.
 *
 * Разбор — в шапке файла. Коротко: потребитель шлёт запрос с NLM_F_DUMP и
 * читает ПОДРЯД, пока не увидит NLMSG_DONE. Молчание = вечная остановка.
 *
 * Отвечаем минимально и честно: один интерфейс, поднятый, не петля, с одним
 * адресом IPv4 — и NLMSG_DONE. Событий (без запроса) не шлём вовсе: их у нас
 * действительно нет.
 */

/* Номер, имя и адрес выдуманного интерфейса. */
#define GUEST_IFINDEX 1
#define GUEST_IFNAME  "guest0"
/*
 * 10.0.2.15 — адрес, который qemu раздаёт гостю в полносистемном режиме.
 * Взят ради узнаваемости: увидев его в отладке, сразу понятно, что он наш.
 * Значение в сетевом порядке байт.
 */
#define GUEST_IFADDR  0x0f02000au

/*
 * Флаги интерфейса. Записаны числами нарочно: <linux/if.h> и <net/if.h>
 * в musl конфликтуют определениями struct ifreq, а нам нужны только константы.
 *   0x00001 IFF_UP        0x00002 IFF_BROADCAST  0x00040 IFF_RUNNING
 *   0x01000 IFF_MULTICAST 0x10000 IFF_LOWER_UP
 * ⚠️ IFF_LOWER_UP и IFF_RUNNING обязательны: движок браузера считает линк рабочим
 * только при UP+RUNNING+LOWER_UP и НЕ петле.
 */
#define GUEST_IFF (0x00001u | 0x00002u | 0x00040u | 0x01000u | 0x10000u)

/* Наш конец пары для гостевого дескриптора, или −1. */
static int peer_of(int fd)
{
    int i, peer = -1;

    if (!inited || fd < 0) {
        return -1;
    }
    qemu_mutex_lock(&lock);
    for (i = 0; i < nfds; i++) {
        if (fds[i] == fd) {
            peer = peers[i];
            break;
        }
    }
    qemu_mutex_unlock(&lock);
    return peer;
}

/*
 * Номер порта этого дескриптора: чем гость себя знает. Ноль в таблице значит
 * «ещё не выдан» — выдаём, как ядро при самопривязке, свой pid.
 */
static uint32_t nl_port(int fd)
{
    int i;
    uint32_t port = 0;

    if (!inited || fd < 0) {
        return (uint32_t)getpid();
    }
    qemu_mutex_lock(&lock);
    for (i = 0; i < nfds; i++) {
        if (fds[i] == fd) {
            if (!nlpid[i]) {
                nlpid[i] = (uint32_t)getpid();
            }
            port = nlpid[i];
            break;
        }
    }
    qemu_mutex_unlock(&lock);
    return port ? port : (uint32_t)getpid();
}

/* Группы, на которые гость подписан (нужны только в ответе getsockname). */
static uint32_t nl_groups(int fd)
{
    int i;
    uint32_t g = 0;

    if (!inited || fd < 0) {
        return 0;
    }
    qemu_mutex_lock(&lock);
    for (i = 0; i < nfds; i++) {
        if (fds[i] == fd) {
            g = nlgrp[i];
            break;
        }
    }
    qemu_mutex_unlock(&lock);
    return g;
}

void guest_net_bound(int fd, const void *addr, socklen_t len)
{
    const struct sockaddr_nl *nl = addr;
    uint32_t port, grp;
    int i;

    if (!inited || fd < 0 || !addr || len < sizeof(*nl) ||
        nl->nl_family != AF_NETLINK) {
        return;
    }
    /*
     * Ноль в запросе значит «дай любой» — ядро в этом случае выдаёт pid
     * процесса (первому сокету; дальше случайные числа, но одинаковость нам
     * важнее правдоподобия: сверять его будет тот же процесс).
     */
    port = nl->nl_pid ? nl->nl_pid : (uint32_t)getpid();
    grp = nl->nl_groups;
    qemu_mutex_lock(&lock);
    for (i = 0; i < nfds; i++) {
        if (fds[i] == fd) {
            nlpid[i] = port;
            nlgrp[i] = grp;
            break;
        }
    }
    qemu_mutex_unlock(&lock);
    nlog("дескриптор %d привязан: номер порта %u, группы 0x%x", fd, port, grp);
}

/*
 * ★★★★ ПОДСТАВНОЙ СОКЕТ ОБЯЗАН НАЗЫВАТЬСЯ NETLINK'ОМ.
 *
 * Открытие `ip` (и всякого, кто живёт на libnetlink) кончается так:
 *
 *     bind(fd, &local, sizeof local);
 *     addr_len = sizeof(rth->local);
 *     getsockname(fd, &rth->local, &addr_len);
 *     if (addr_len != sizeof(rth->local))     → «Wrong address length»
 *     if (rth->local.nl_family != AF_NETLINK) → «Wrong address family 1»
 *
 * За нашим дескриптором стоит AF_UNIX, и без этой подмены ответ был бы
 * «семейство 1, длина 2» — то есть отказ ещё до первого запроса. Возвращаем
 * то, что вернуло бы ядро: AF_NETLINK, наш номер порта, наши группы, длина
 * ровно sizeof(struct sockaddr_nl).
 */
int guest_net_sockname(int fd, void *addr, socklen_t cap, socklen_t *len)
{
    struct sockaddr_nl nl;

    if (!guest_net_owns(fd) || !addr || !len) {
        return 0;
    }
    memset(&nl, 0, sizeof(nl));
    nl.nl_family = AF_NETLINK;
    nl.nl_pid = nl_port(fd);
    nl.nl_groups = nl_groups(fd);
    memcpy(addr, &nl, cap < sizeof(nl) ? (size_t)cap : sizeof(nl));
    /* Как ядро: настоящую длину говорим даже в тесный буфер. */
    *len = sizeof(nl);
    return 1;
}

/*
 * ★★★★ ОТВЕТ ПРИХОДИТ ОТ ЯДРА, А НЕ «НИ ОТ КОГО».
 *
 * Пара AF_UNIX связная, и recvmsg на ней отдаёт msg_namelen = 0, не тронув
 * буфер отправителя. У потребителя он лежит на стеке НЕИНИЦИАЛИЗИРОВАННЫМ:
 *
 *     struct sockaddr_nl nladdr;                  ← мусор со стека
 *     struct msghdr msg = { .msg_name = &nladdr, .msg_namelen = sizeof nladdr … };
 *     recvmsg(fd, &msg, 0);
 *     if (nladdr.nl_pid != 0) goto skip_it;       ← почти всегда правда
 *
 * То есть наш честный ответ выбрасывался ещё до разбора, и следующее чтение
 * вставало навсегда. Подставляем адрес ядра (nl_pid = 0) и длину 12.
 */
int guest_net_from_kernel(int fd, void *addr, socklen_t cap, socklen_t *len)
{
    struct sockaddr_nl nl;

    if (!guest_net_owns(fd) || !addr || !len) {
        return 0;
    }
    memset(&nl, 0, sizeof(nl));
    nl.nl_family = AF_NETLINK;      /* nl_pid = 0 и nl_groups = 0 — это ядро */
    memcpy(addr, &nl, cap < sizeof(nl) ? (size_t)cap : sizeof(nl));
    *len = sizeof(nl);
    return 1;
}

/*
 * Дописать атрибут в хвост сообщения, поправив его длину.
 *
 * ★★★★★ ДЛИНА СООБЩЕНИЯ ОБЯЗАНА ВКЛЮЧАТЬ ВЫРАВНИВАНИЕ ПОСЛЕДНЕГО АТРИБУТА.
 *
 * Здесь была ошибка, от которой браузер прошивки падал при запуске (14 сентября).
 * Длина росла на rta_len — БЕЗ добивки до четырёх байт:
 *
 *     h->nlmsg_len = NLMSG_ALIGN(h->nlmsg_len) + a->rta_len;   ← было
 *
 * Ядро так не делает. nla_put резервирует в буфере nla_total_size(), то есть
 * ВЫРОВНЕННЫЙ размер вместе с добивкой (и обнуляет её), а nlmsg_end пишет в
 * nlmsg_len расстояние до конца этого резерва. Для IFLA_IFNAME="guest0" ядро
 * скажет 44 (32 + 12), а мы говорили 41 (32 + 9).
 *
 * Разница в три байта ломает разбор у потребителя. Обход атрибутов устроен так:
 *
 *     size_t length = IFA_PAYLOAD(header);          // 49 − 24 = 25
 *     for (attr = IFA_RTA(msg); RTA_OK(attr, length); attr = RTA_NEXT(attr, length))
 *
 * RTA_NEXT вычитает из остатка ВЫРОВНЕННУЮ длину атрибута: 25 → 17 → 9 → −3.
 * Пока остаток знаковый, −3 просто обрывает цикл. Но у сетевой части движка браузера
 * (net/base/address_tracker_linux.cc) остаток объявлен size_t, и −3 становится
 * 0xFFFFFFFD: цикл идёт дальше по чужой памяти, пока не упрётся в незанятую
 * страницу. Снято с живого стенда, поток DnsConfigService:
 *
 *   Fatal signal 11 (SIGSEGV) at 0x7dbebc48, thread 19003 (DnsConfigServic)
 *   R00=7dbebc48 R01=fff2affd            ← R01 = тот самый остаток
 *   байты у PC: 8802 2a04 bf28 4291 d320 ← ldrh r2,[r0]; cmp r2,#4; cmp r1,r2
 *
 * то есть ровно RTA_OK: «rta_len ≥ 4 и rta_len ≤ остаток». Процесс браузера
 * умирал целиком, до того как успевал показать страницу.
 *
 * ⚠️ Добивку ОБНУЛЯЕМ здесь, а не полагаемся на memset буфера у вызывающего:
 * так сообщение верно само по себе, откуда бы его ни собирали.
 */
static void put_attr(struct nlmsghdr *h, int type, const void *val, size_t n)
{
    struct rtattr *a = (struct rtattr *)((char *)h + NLMSG_ALIGN(h->nlmsg_len));
    size_t pad;

    a->rta_type = type;
    a->rta_len = RTA_LENGTH(n);
    memcpy(RTA_DATA(a), val, n);
    pad = RTA_ALIGN(a->rta_len) - a->rta_len;
    if (pad) {
        memset((char *)RTA_DATA(a) + n, 0, pad);
    }
    h->nlmsg_len = NLMSG_ALIGN(h->nlmsg_len) + RTA_ALIGN(a->rta_len);
}

/*
 * ⚠️★★★ nlmsg_pid В ОТВЕТЕ — ЭТО АДРЕСАТ, А НЕ ОТПРАВИТЕЛЬ.
 *
 * Здесь стояло `h->nlmsg_pid = req->nlmsg_pid`, и это была главная поломка
 * подставного netlink. В запросе потребитель кладёт туда ноль (libnetlink так
 * и делает), а в ответе ждёт СВОЙ номер порта — тот, что ему выдало ядро при
 * привязке. Ноль не сходится, ответ выбрасывается, чтение не кончается
 * никогда. Поэтому берём номер из таблицы дескриптора (см. nl_port).
 */
static void put_head(struct nlmsghdr *h, int type, int flags,
                     const struct nlmsghdr *req, uint32_t port, size_t payload)
{
    h->nlmsg_len = NLMSG_LENGTH(payload);
    h->nlmsg_type = type;
    h->nlmsg_flags = flags;
    h->nlmsg_seq = req->nlmsg_seq;
    h->nlmsg_pid = port;
}

/* Одна запись дампа линков: наш интерфейс. */
static size_t make_link(char *buf, const struct nlmsghdr *req, uint32_t port)
{
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    struct ifinfomsg *ifi;

    put_head(h, RTM_NEWLINK, NLM_F_MULTI, req, port, sizeof(*ifi));
    ifi = (struct ifinfomsg *)NLMSG_DATA(h);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_type = 1;                  /* ARPHRD_ETHER */
    ifi->ifi_index = GUEST_IFINDEX;
    ifi->ifi_flags = GUEST_IFF;
    ifi->ifi_change = 0xffffffffu;
    put_attr(h, IFLA_IFNAME, GUEST_IFNAME, sizeof(GUEST_IFNAME));
    return NLMSG_ALIGN(h->nlmsg_len);
}

/* Одна запись дампа адресов: адрес на нашем интерфейсе. */
static size_t make_addr(char *buf, const struct nlmsghdr *req, uint32_t port)
{
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    struct ifaddrmsg *ifa;
    uint32_t ip = GUEST_IFADDR;

    put_head(h, RTM_NEWADDR, NLM_F_MULTI, req, port, sizeof(*ifa));
    ifa = (struct ifaddrmsg *)NLMSG_DATA(h);
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = 24;
    ifa->ifa_flags = 0x80;              /* IFA_F_PERMANENT */
    ifa->ifa_scope = 0;                 /* RT_SCOPE_UNIVERSE */
    ifa->ifa_index = GUEST_IFINDEX;
    put_attr(h, IFA_ADDRESS, &ip, sizeof(ip));
    put_attr(h, IFA_LOCAL, &ip, sizeof(ip));
    put_attr(h, IFA_LABEL, GUEST_IFNAME, sizeof(GUEST_IFNAME));
    return NLMSG_ALIGN(h->nlmsg_len);
}

/* «Дамп окончен» — то самое сообщение, которого ждал повисший поток. */
static size_t make_done(char *buf, const struct nlmsghdr *req, uint32_t port)
{
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    int zero = 0;

    put_head(h, NLMSG_DONE, NLM_F_MULTI, req, port, sizeof(zero));
    memcpy(NLMSG_DATA(h), &zero, sizeof(zero));
    return NLMSG_ALIGN(h->nlmsg_len);
}

/* Подтверждение без ошибки — на запросы с NLM_F_ACK. */
static size_t make_ack(char *buf, const struct nlmsghdr *req, uint32_t port)
{
    struct nlmsghdr *h = (struct nlmsghdr *)buf;
    struct nlmsgerr *e;

    put_head(h, NLMSG_ERROR, 0, req, port, sizeof(*e));
    e = (struct nlmsgerr *)NLMSG_DATA(h);
    e->error = 0;
    e->msg = *req;
    return NLMSG_ALIGN(h->nlmsg_len);
}

/*
 * ★★★★ ЗАБРАТЬ НАСТОЯЩИЙ NETLINK, КОГДА ГОСТЬ В НЕГО ПИШЕТ.
 *
 * Подменять сокет при создании или привязке мало. Хозяин (Android 14) на
 * телефоне разрешает приложению netlink СОЗДАТЬ и ПРИВЯЗАТЬ, но запрещает
 * послать в него запрос. Такой сокет остаётся настоящим, мимо нашей таблицы, и
 * гость получает отказ на ровном месте. Снято с живого стенда, браузер прошивки:
 *
 *   [ERROR:address_tracker_linux.cc(222)]
 *       Could not send NETLINK request: Permission denied (13)
 *
 * а в нашем журнале на том же месте стояло «★ дескриптор N НЕ наш, а посылка
 * похожа на netlink — ответить некому». Ровно этот случай теперь и лечим:
 * забираем сокет себе прямо здесь, перед посылкой, и дальше отвечаем сами.
 *
 * Подменять настоящий netlink не жалко и по существу: через него гость увидел
 * бы интерфейсы ХОЗЯИНА (Wi-Fi телефона, его адреса), а должен видеть свой
 * выдуманный guest0 — тот, про который мы ему рассказываем везде.
 *
 * ⚠️ Дёшево по стоимости: сюда приходит КАЖДАЯ гостевая посылка в сокет.
 * Сначала три сравнения в уже прочитанном заголовке, и только для похожего на
 * запрос netlink — один getsockopt. Пары нашего binder'а до него не доходят.
 *
 * 1 — дескриптор теперь наш (или был нашим), отвечать есть чем.
 */
int guest_net_adopt(int fd, const void *msg, size_t len)
{
    const struct nlmsghdr *h = msg;

    if (!msg || fd < 0 || len < sizeof(*h)) {
        return 0;
    }
    if (h->nlmsg_len < sizeof(*h) || h->nlmsg_len > len) {
        return 0;
    }
    if (!(h->nlmsg_flags & NLM_F_REQUEST)) {
        return 0;
    }
    if (guest_net_owns(fd)) {
        return 1;
    }
    nlog_init();
    if (!netlink_take_over(fd, "send: настоящий netlink забран себе")) {
        nlog("★ дескриптор %d НЕ наш, а посылка похожа на netlink "
             "(тип %u, флаги 0x%x) — забрать не вышло",
             fd, h->nlmsg_type, h->nlmsg_flags);
        return 0;
    }
    return 1;
}

int guest_net_answer(int fd, const void *msg, size_t len)
{
    const struct nlmsghdr *req = msg;
    char buf[512];
    size_t n = 0;
    uint32_t port;
    int peer = peer_of(fd);

    if (peer < 0) {
        nlog("дескриптор %d наш, а пары к нему нет — отвечать нечем", fd);
        return 0;
    }
    if (len < sizeof(*req)) {
        nlog("дескриптор %d: посылка %zu Б — не netlink, молчим", fd, len);
        return 0;
    }
    /* Похоже ли это вообще на netlink. Не похоже — молча принимаем и молчим. */
    if (req->nlmsg_len < sizeof(*req) || req->nlmsg_len > len) {
        nlog("дескриптор %d: длина %u при посылке %zu Б — не netlink, молчим",
             fd, req->nlmsg_len, len);
        return 0;
    }
    if (!(req->nlmsg_flags & NLM_F_REQUEST)) {
        nlog("дескриптор %d: тип %u без NLM_F_REQUEST — молчим",
             fd, req->nlmsg_type);
        return 0;
    }

    port = nl_port(fd);
    memset(buf, 0, sizeof(buf));
    if ((req->nlmsg_flags & NLM_F_DUMP) == NLM_F_DUMP) {
        if (req->nlmsg_type == RTM_GETLINK) {
            n += make_link(buf + n, req, port);
        } else if (req->nlmsg_type == RTM_GETADDR) {
            n += make_addr(buf + n, req, port);
        }
        /*
         * Прочие дампы (маршруты, правила, соседи) отдаём пустыми: врать про
         * них незачем, а NLMSG_DONE всё равно обязателен — иначе снова
         * зависание. Пустой список — это честный ответ: маршрутов и правил у
         * нас действительно нет, и `ip rule flush` на нём кончает работу
         * успехом, ничего не удаляя.
         */
        n += make_done(buf + n, req, port);
    } else if (req->nlmsg_flags & NLM_F_ACK) {
        n = make_ack(buf, req, port);
    } else {
        nlog("дескриптор %d: тип %u, флаги 0x%x — ни дамп, ни ack, молчим",
             fd, req->nlmsg_type, req->nlmsg_flags);
        return 0;
    }

    /*
     * ⚠️ MSG_DONTWAIT обязателен: если гость не читает, очередь пары рано или
     * поздно заполнится, и qemu встал бы на записи вместе с гостем.
     */
    if (send(peer, buf, n, MSG_DONTWAIT) < 0) {
        nlog("ответ на дескриптор %d НЕ УШЁЛ: %s", fd, strerror(errno));
        return 0;
    }
    nlog("дескриптор %d: запрос типа %u (флаги 0x%x, номер %u) — ответили %zu Б "
         "от ядра на порт %u", fd, req->nlmsg_type, req->nlmsg_flags,
         req->nlmsg_seq, n, port);
    return 1;
}

/*
 * ★★★ Перехват HTTP: гостевые соединения на порт 80 уводим посреднику.
 *
 * Зачем. libssl прошивки — OpenSSL 1.0.0a (июнь 2010), он умеет только TLS 1.0,
 * а нынешние сайты его не принимают: измерено — два публичных сайта по TLS 1.0
 * отказывают, по TLS 1.2 отвечают. Обновление корневых сертификатов не спасает
 * (дело не в доверии, а в версии протокола), а сделать гостю современный TLS
 * нельзя — в его libssl нет даже SNI.
 *
 * Поэтому наружу за страницей ходит ПРИЛОЖЕНИЕ, современным TLS телефона, а
 * гость получает её обычным HTTP (см. Http.kt). Чтобы гостю ничего не
 * настраивать — ни прокси в системных настройках, ни правок браузера, — соединения
 * на порт 80 подменяются здесь, на уровне вызова connect.
 *
 * ⚠️ Подменяем ТОЛЬКО AF_INET и ТОЛЬКО порт 80, и только если приложение дало
 * порт посредника (GUEST_HTTP80). Всё прочее — DNS, время, чужие порты — идёт
 * как шло: подмена не должна прятать работающую сеть.
 */
/*
 * ★★★★★ ОТВЕТ ДОЛЖЕН ПРИЙТИ ОТ ТОГО, КОГО СПРАШИВАЛИ.
 *
 * Увести запрос имени к своему ответчику мало. Резолвер bionic проверяет, от
 * КОГО пришёл ответ, и чужой молча выбрасывает:
 *
 *   res_send.c, send_dg():
 *     resplen = recvfrom(s, ans, anssiz, 0, (struct sockaddr *)&from, &fromlen);
 *     …
 *     if (!(statp->options & RES_INSECURE1) &&
 *         !res_ourserver_p(statp, (struct sockaddr *)&from))
 *             goto retry;          ← ответ выброшен, спрашиваем снова
 *
 * Гость спрашивает 8.8.8.8:53 (это мы прописали ему в net.dns1), мы уводим
 * запрос на 127.0.0.1:18053 — и ответ, честно приходящий оттуда же, «не от
 * того сервера». Снаружи это выглядит так, будто разрешения имён нет вовсе:
 *
 *   UnknownHostException: Unable to resolve host "dm.vendor.example":
 *   No address associated with hostname
 *
 * при том что в нашем журнале на то же имя стоят ДЕСЯТКИ ответов подряд — это
 * и есть цикл retry (снято 14 сентября).
 *
 * Поэтому запоминаем, куда гость целился, и при приёме подставляем этот адрес
 * обратно. Гость видит ровно ту картину, которую ждёт: спросил 8.8.8.8:53 —
 * ответил 8.8.8.8:53.
 *
 * ⚠️ Только для запросов имён (порт 53). У TCP-соединений на 80/443 источник
 * никто не сверяет, а лишняя подмена там только запутала бы отладку.
 */
#define GUEST_DNS_MAX 64

struct dns_aim {
    int fd;
    socklen_t len;
    struct sockaddr_storage sa;
};

static struct dns_aim dnsmap[GUEST_DNS_MAX];
static int ndnsmap;

/* Запомнить, куда гость целился этим дескриптором. */
static void dns_remember(int fd, const void *orig, socklen_t len)
{
    int i;

    if (fd < 0 || !orig || len == 0 || len > sizeof(((struct dns_aim *)0)->sa)) {
        return;
    }
    net_init();
    qemu_mutex_lock(&lock);
    for (i = 0; i < ndnsmap; i++) {
        if (dnsmap[i].fd == fd) {
            break;
        }
    }
    if (i == ndnsmap) {
        if (ndnsmap >= GUEST_DNS_MAX) {
            /* ⚠️ Кольцом, а не отказом: дескрипторы имён живут недолго. */
            i = 0;
            ndnsmap = 1;
        } else {
            ndnsmap++;
        }
    }
    dnsmap[i].fd = fd;
    dnsmap[i].len = len;
    memcpy(&dnsmap[i].sa, orig, len);
    qemu_mutex_unlock(&lock);
}

void guest_dns_unredirect(int fd, void *addr, socklen_t len)
{
    int i;

    if (!inited || fd < 0 || !addr || len == 0) {
        return;
    }
    qemu_mutex_lock(&lock);
    for (i = 0; i < ndnsmap; i++) {
        if (dnsmap[i].fd == fd) {
            memcpy(addr, &dnsmap[i].sa, MIN(len, dnsmap[i].len));
            break;
        }
    }
    qemu_mutex_unlock(&lock);
}

static void dns_forget(int fd)
{
    int i;

    if (!inited || fd < 0) {
        return;
    }
    qemu_mutex_lock(&lock);
    for (i = 0; i < ndnsmap; i++) {
        if (dnsmap[i].fd == fd) {
            dnsmap[i] = dnsmap[--ndnsmap];
            break;
        }
    }
    qemu_mutex_unlock(&lock);
}

void guest_http_redirect(int fd, void *addr, socklen_t addrlen)
{
    static int http = -1, https = -1, dns = -1;
    struct sockaddr_in *in = (struct sockaddr_in *)addr;
    int want, oport;

    if (http == -1) {
        const char *h = getenv("GUEST_HTTP80");
        const char *t = getenv("GUEST_HTTPS443");
        const char *d = getenv("GUEST_DNS53");

        http = h ? atoi(h) : 0;
        https = t ? atoi(t) : 0;
        dns = d ? atoi(d) : 0;
    }
    if (!addr) {
        return;
    }
    /*
     * ★★★ IPv6 тоже. Гость спрашивает у резолвера и адрес IPv6, и получив его,
     * соединяется семейством AF_INET6 — а подмена, знавшая только AF_INET,
     * молча пропускала такое соединение мимо. Снаружи это выглядело так, будто
     * перехват не работает вовсе: пробы на явном адресе IPv4 проходили, а
     * браузер — нет.
     *
     * Подставляем адрес IPv4 в виде ::ffff:127.0.0.1: соединение с ним уходит
     * обычным IPv4-пакетом и попадает на наш обычный слушающий сокет.
     */
    if (addrlen >= (socklen_t)sizeof(struct sockaddr_in6) &&
        ((struct sockaddr_in6 *)addr)->sin6_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
        int p6 = ntohs(in6->sin6_port);
        int want6 = 0;

        if (http == -1) {
            const char *h = getenv("GUEST_HTTP80");
            const char *t = getenv("GUEST_HTTPS443");
            const char *d = getenv("GUEST_DNS53");

            http = h ? atoi(h) : 0;
            https = t ? atoi(t) : 0;
            dns = d ? atoi(d) : 0;
        }
        if (p6 == 80) {
            want6 = http;
        } else if (p6 == 443) {
            want6 = https;
        } else if (p6 == 53) {
            want6 = dns;
        }
        if (want6 > 0) {
            static const uint8_t v4mapped[16] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1
            };
            const uint8_t *a6 = (const uint8_t *)&in6->sin6_addr;
            /*
             * ★★★★ Адрес вида ::ffff:127.1.x.y ОСТАВЛЯЕМ, как и в IPv4-ветке.
             *
             * Так ходит сетевая часть движка браузера: имя разрешается в наш 127.1.x.y
             * (запись A), а соединение делается сокетом AF_INET6 по адресу
             * ::ffff:127.1.x.y. Прежде мы затирали его на ::ffff:127.0.0.1 —
             * и приёмник TLS терял ИМЯ САЙТА, потому что узнаёт он его именно
             * по адресу. В журнале это выглядело так:
             *
             *   TLS: соединение на 127.0.0.1 -> localhost
             *
             * дальше приёмник отдавал сертификат на «localhost», браузер его не
             * принимал, и страница кончалась «Webpage not available» — при том
             * что имя разрешилось и соединение дошло. Так падали все https-сайты.
             *
             * Для открытого http (порт 80) имя не нужно — оно придёт в
             * заголовке Host, а посредник слушает только 127.0.0.1.
             */
            int keep = (p6 == 443 &&
                        !memcmp(a6, v4mapped, 12) && a6[12] == 127 &&
                        !(a6[13] == 0 && a6[14] == 0 && a6[15] == 1));

            if (p6 == 53) {
                dns_remember(fd, in6, addrlen);
            }
            if (!keep) {
                memcpy(&in6->sin6_addr, v4mapped, sizeof(v4mapped));
            }
            in6->sin6_port = htons(want6);
        }
        return;
    }
    if (addrlen < (socklen_t)sizeof(*in) || in->sin_family != AF_INET) {
        return;
    }
    oport = ntohs(in->sin_port);
    /*
     * ★★★ ПРОБА «ЕСТЬ ЛИ У АППАРАТА АДРЕС IPv4» — НА ПЕТЛЮ.
     *
     * Резолвер bionic перед КАЖДЫМ разбором имени с `AI_ADDRCONFIG` (а так
     * зовёт `getaddrinfo` вся система) проверяет, есть ли у аппарата адрес
     * семейства: заводит UDP-сокет и делает `connect` на 8.8.8.8 **порт 0**
     * (для IPv6 — на `2000::`). Порт нулевой, данных не будет: ответ даёт сам
     * `connect` — есть маршрут или нет.
     *
     * Беда в том, что маршрут этот — ХОЗЯЙСКИЙ. На телефоне без сети (режим
     * полёта, нет карты и Wi-Fi) проба отвечает «адреса IPv4 нет», резолвер
     * выбрасывает записи A ещё до запроса и отдаёт `NS_NOTFOUND` —
     * «No address associated with hostname», хотя наш ответчик имён лежит на
     * петле и разрешил бы что угодно. То есть интернет у гостя зависел бы от
     * того, есть ли интернет у телефона, — а он нам не нужен вовсе.
     *
     * Уводим пробу на петлю: маршрут туда есть всегда, `connect` отвечает
     * успехом, и разбор имён идёт одинаково на любом аппарате.
     *
     * ⚠️ Только когда наш ответчик включён (`GUEST_DNS53`). Без него гость
     * разбирает имена по-настоящему, и проба обязана говорить правду — прятать
     * работающую возможность подменой нельзя (то же правило, что в 0014, 0019).
     *
     * ⚠️ IPv6 не трогаем: записи AAAA наш ответчик и так отдаёт пустыми, а
     * лишний «есть IPv6» заставил бы гостя ходить за ними впустую.
     *
     * ★ Побочно это ещё и закрывает утечку: приём «соединиться и посмотреть
     * `getsockname`» — обычный способ узнать свой адрес в сети, и до правки
     * гость узнавал им адрес телефона в домашней сети.
     */
    if (oport == 0) {
        if (dns > 0 && (ntohl(in->sin_addr.s_addr) >> 24) != 127) {
            in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
        return;
    }
    switch (oport) {
    case 80:
        want = http;
        break;
    /*
     * ★ Порт 443. Гость умеет только TLS 1.0, и нынешние сайты его отвергают;
     * поэтому рукопожатие принимаем САМИ (см. Tls.kt), а наружу идём
     * современным TLS телефона. Без этого напечатанный `https://` не работает
     * вовсе — а именно так адреса и набирают.
     */
    case 443:
        want = https;
        break;
    /*
     * ★ Порт имён. Разрешение имён в прошивке не работает (проверено:
     * `busybox nslookup example.com 8.8.8.8` не отвечает, хотя сам телефон в
     * сети и TCP у гостя есть), причём на одних телефонах работает, на других
     * нет. Настоящий DNS гостю и не нужен: за страницей ходит приложение и
     * узел берёт из заголовка `Host`. Поэтому отвечаем сами — см. Dns.kt.
     */
    case 53:
        want = dns;
        break;
    default:
        return;
    }
    if (want <= 0) {
        return;
    }
    /*
     * ★ Запоминаем цель ДО подмены — ответ придётся выдать «от неё»
     * (см. guest_dns_unredirect выше).
     */
    if (oport == 53) {
        dns_remember(fd, in, addrlen);
    }
    in->sin_port = htons(want);
    /*
     * ★★★ Петлевой адрес ОСТАВЛЯЕМ как есть — но только для https.
     *
     * Имена в режиме перехвата разрешает наш же ответчик и выдаёт каждому имени
     * свой адрес из 127.1.x.y (см. Dns.kt). По нему приёмник TLS узнаёт, к
     * какому сайту идёт гость, ещё ДО рукопожатия — и берёт нужный сертификат.
     * Если адрес затереть на 127.0.0.1, имя теряется, и гость на каждом сайте
     * видит окно «сертификат не совпадает».
     *
     * Не петлевой адрес (ответчик выключен, имя разрешилось по-настоящему)
     * уводим на петлю, иначе соединение уйдёт к настоящему серверу.
     *
     * ⚠️★★ А вот ОТКРЫТОМУ http адрес надо ровнять на 127.0.0.1, и это не
     * мелочь. Посредник слушает именно 127.0.0.1 (а не все адреса — незачем
     * пускать к себе чужих из локальной сети), и соединение на 127.1.0.13:18080
     * он не примет вовсе. Снаружи это выглядело так: `https://example.com`
     * открывается, а `http://example.com` — «Webpage not available», при том
     * что имя разрешилось. Имя посреднику нужно и так есть: у открытого http
     * оно приходит в заголовке `Host` (см. Http.kt), сертификат не нужен.
     */
    if (oport == 80 || (ntohl(in->sin_addr.s_addr) >> 24) != 127) {
        in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
}
