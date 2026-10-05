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

// guest_binder.c — изображает драйвер /dev/binder для гостевой прошивки.
//
// ★ Форк файла glue_binder.c из более ранней нашей работы, где он уже
// поднимал полный стек Android 7. Взят целиком и намеренно: в нём
// закодированы выстраданные инварианты ПОРЯДКА команд, каждый с описанием того
// краха, который он лечит (BAD COMMAND 29190, SIGSEGV в RefBase::incStrong,
// Watchdog по заблокированному потоку). Переписывать это заново — значит
// повторить те же ошибки.
//
// ★★ Отличие от донора: там шим жил В ГОСТЕВОМ процессе (LD_PRELOAD, гость
// 64-битный), здесь он живёт ВНУТРИ qemu (гость 32-битный). Отсюда три вида
// правок, и только они:
//   1. гостевые адреса переводятся g2h/h2g — мы в том же адресном пространстве,
//      но гостевой указатель это abi_ulong, а не void*;
//   2. массив смещений объектов у 32-битного гостя 4-байтный, а протокол демона
//      несёт 8-байтные — пересчёт на обеих границах;
//   3. mmap делается через target_mmap: область обязана лечь в адресное
//      пространство ГОСТЯ и попасть в его учёт страниц.
//
// Устройство осталось прежним:
//   open("/dev/binder")  -> socketpair, гостю отдаётся конец A (на нём работает
//                           poll, потому что это настоящий сокет);
//   ioctl(BINDER_*)      -> сообщения демону binderd, ответы -> команды BR_* ;
//   mmap(fd)             -> анонимная область в памяти ГОСТЯ, куда МЫ кладём
//                           данные входящих транзакций;
//   close(fd)            -> демон разошлёт извещения о смерти.
//
// Соединение с демоном — на КАЖДЫЙ ПОТОК гостя: несколько потоков, читающих
// один сокет, растаскивали бы чужие сообщения.
//
// Путь к сокету демона берётся из GUEST_BINDER, лог — из GUEST_BINDER_LOG.

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "user-mmap.h"

#include <pthread.h>
#include <poll.h>
#include <sys/syscall.h>

#include "binder_proto.h"
#include "guest_binder.h"
#include "guest_fb.h"
#include "guest_ids.h"
#include "guest_ashmem.h"
#include "guest_input.h"
#include "guest_alarm.h"
#include "guest_fs.h"
#include "guest_trace.h"

// Свой номер потока: musl не всегда отдаёт gettid(), а нам он нужен только как
// метка в протоколе и в логе.
static pid_t guest_gettid(void) { return (pid_t)syscall(SYS_gettid); }
#define gettid guest_gettid

// Лог шима. Включается GUEST_BINDER_LOG=<файл> (или «-» — на stderr): без него
// молчим совсем, потому что на каждую транзакцию тут по несколько строк.
static int g_verbose;
static FILE *g_blog;

static void blog_init(void)
{
    static int done;
    if (done) {
        return;
    }
    done = 1;
    const char *path = getenv("GUEST_BINDER_LOG");
    if (!path || !*path) {
        return;
    }
    g_blog = (path[0] == '-' && !path[1]) ? stderr : fopen(path, "ae");
    /*
     * ★ Два уровня, а не один.
     *
     * Подробный лог — по несколько строк на КАЖДУЮ транзакцию: за две минуты
     * работы системы это сотни мегабайт, и на телефоне его просто некуда
     * писать. А тревожные сообщения (битое смещение, недоступная память
     * гостя, кончившийся приёмный пул) редки — и именно они говорят, что
     * посылка испорчена. Поэтому файл открываем всегда, когда задан
     * GUEST_BINDER_LOG, а подробность включает отдельная GUEST_BINDER_VERBOSE.
     */
    const char *v = getenv("GUEST_BINDER_VERBOSE");
    g_verbose = g_blog != NULL && v && *v && *v != '0';
}

/* Тревожное сообщение: пишется всегда, когда задан GUEST_BINDER_LOG. */
static void bwarn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void bwarn(const char *fmt, ...)
{
    if (!g_blog) {
        return;
    }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(g_blog, "[%3ld.%03ld pid=%d tid=%d] ", (long)ts.tv_sec % 1000,
            ts.tv_nsec / 1000000, getpid(), (int)guest_gettid());
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_blog, fmt, ap);
    va_end(ap);
    fputc('\n', g_blog);
    fflush(g_blog);
}

static void blog(const char *fmt, ...)
{
    if (!g_verbose) {
        return;
    }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(g_blog, "[%3ld.%03ld pid=%d tid=%d] ", (long)ts.tv_sec % 1000,
            ts.tv_nsec / 1000000, getpid(), (int)guest_gettid());
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_blog, fmt, ap);
    va_end(ap);
    fputc('\n', g_blog);
    fflush(g_blog);
}
#define glog blog

// Путь к сокету демона. У донора это жило в libglue.c; здесь берём из
// окружения при первом обращении.
static char g_binder[512];

static void binder_path_init(void)
{
    static int done;
    if (done) {
        return;
    }
    done = 1;
    const char *e = getenv("GUEST_BINDER");
    if (e && *e) {
        snprintf(g_binder, sizeof g_binder, "%s", e);
    }
}

static int connect_sock(const char *spec)
{
    // ⚠️ SOCK_CLOEXEC обязателен. Через этот сокет поток говорит с binderd, и
    // если он переживёт execve, демон будет считать УМЕРШИЙ процесс живым:
    // соединение не закроется, POLLHUP не придёт, и «похороны» процесса не
    // случатся. У донора это выглядело как зависание всей системы по Watchdog.
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un a;
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", spec);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    /*
     * ⚠️★★★ НЕ ЗАНИМАТЬ ДЕСКРИПТОРЫ 0, 1 и 2. Если у гостевого процесса они
     * свободны (а у запущенного не через init — свободны), сокет к демону
     * садится на место stdin. Дальше любая штатная уборка потоков ввода-вывода
     * в самой прошивке закрывает его или переоткрывает на /dev/null — и наша
     * связь пропадает молча. В отказе это видно прямо: `fd=0, Bad file
     * descriptor`, а поток, ждавший ответа, висит навсегда.
     *
     * Переносим повыше. Промах переноса не смертелен: работаем как есть.
     */
    if (fd < 3) {
        int hi = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (hi >= 0) { close(fd); fd = hi; }
    }
    return fd;
}

#define SB_MAXSESS 4
// Сколько потоков одной сессии помним для побудки на закрытии (Р-4): пул
// binder у libbinder — до 16 потоков, с запасом на тех, кто зовёт сам.
#define SB_MAXTHR  64
#define SB_PEND    (64 * 1024)
// Потолок на длину одного сообщения демона. Настоящий драйвер ограничен
// размером отображённой области процесса (у нас ~2 МБ), так что 4 МБ — это
// сторож от мусорной длины, а не рабочий предел.
#define SB_MAXMSG  (4 * 1024 * 1024)

// dsize/osize — разметка ПРИНЯТОЙ транзакции внутри блока: [данные][смещения].
// Нужны, чтобы при BC_FREE_BUFFER пройти по объектам посылки и снять ссылки,
// которые демон завёл при переводе. Для блоков, выделенных не под приём, нули.
struct blk { size_t off, size; int used; int cool; uint32_t dsize, osize; struct blk *next; };

struct sess {
    int used;
    int fd_guest;              // конец A: его видит гость
    int fd_wake;               // конец B: наш, для будильника
    uint8_t *map;
    size_t map_size;
    struct blk *blocks;
    pthread_mutex_t lock;
    pthread_t pump;            // поток-будильник
    int pump_fd;               // его соединение с демоном
    int pump_live;
    /*
     * ★★★ НИЧЕЙНАЯ ОТЛОЖЕННАЯ РАБОТА — общая на процесс.
     *
     * Отложенное лежит у ПОТОКА, а поток может уйти. Демон при этом считает
     * работу доставленной (он её отдал и забыл), гость её не видел — и она
     * исчезает бесследно. Поэтому при уходе потока непрочитанные ЧУЖИЕ
     * ТРАНЗАКЦИИ перекладываются сюда, а забирает их любой следующий поток
     * этого же процесса. Ответы так переносить нельзя: они адресованы именно
     * ушедшему потоку и ему одному.
     */
    struct qmsg *dq, **dq_tail;
    /*
     * ★★★★★ ЗАКРЫВАЕТ ЛИ ЭТОТ ПРОЦЕСС ИЗВЕЩЕНИЯ О СМЕРТИ.
     *
     * Ставится, когда от него впервые пришла команда BC_DEAD_BINDER_DONE.
     * Нужен затем, что признак «поток занят извещением» иначе ВРЁТ навсегда:
     * старый `servicemanager` — это не libbinder, а свой крошечный разборщик
     * на C, и он на BR_DEAD_BINDER просто зовёт обработчик, не отвечая
     * ничего. Его счётчик извещений растёт и не спадает никогда.
     *
     * ⚠️ Цена доверия к нему — СМЕРТЬ РЕЕСТРА СЛУЖБ. Измерено 21.09: страховка
     * приняла законно ждущий работу главный поток `servicemanager` за
     * застрявший и отдала ему BR_FAILED_REPLY. У `binder_parse` это не
     * «ошибка вызова», а конец разбора:
     *     case BR_FAILED_REPLY: r = -1;
     * `binder_loop` на этом ВЫХОДИТ:
     *     E Binder  binder_loop: io error -1 Success
     * Реестр служб умирает молча, всё уже найденное продолжает работать — и
     * беда всплывает через полчаса совсем в другом месте.
     */
    int closes_death;
    /*
     * ★★★ СОКЕТЫ ПОТОКОВ ЭТОЙ СЕССИИ — ЧТОБЫ РАЗБУДИТЬ ИХ НА ЗАКРЫТИИ
     * (регресс 24.09, Р-4).
     *
     * Гостевые программы на Dalvik (`am`, `pm`, наши пробы) не выходили сами:
     * после `main` главный поток ждёт в `DestroyJavaVM` поток `Binder_1`, а тот
     * спит в чтении СВОЕГО сокета к демону (`unix_stream_read_generic`).
     * `IPCThreadState::stopProcess` закрывает описатель binder, но закрытие
     * описателя сессии в другом потоке чужое чтение не будит — и процесс жил
     * до срока (`am start` установщика — 90 с, `run:` — 120 с).
     *
     * Теперь закрытие сессии делает `shutdown` сокетам её потоков, их чтение
     * возвращается, а ioctl отдаёт EBADF — ровно тот отказ, на котором
     * libbinder выходит из пула штатно (на любом другом он зовёт abort()).
     *
     * ⚠️ Только сокеты, заведённые ЭТИМ процессом (поле pid). Ребёнок после
     * fork наследует описатели сокетов всех потоков родителя, а `shutdown`
     * действует на сам сокет, не на описатель: закрой ребёнок binder — и
     * связь с демоном потерял бы родитель (зигота, system_server).
     */
    int closing;
    struct { int fd; pid_t pid; } tfd[SB_MAXTHR];
    int ntfd;
};

// Отложенное сообщение демона. Отложить приходится по двум причинам: оно не
// влезло в буфер чтения гостя, либо оно обгоняет наше BR_TRANSACTION_COMPLETE
// (порядок в буфере обязан быть [ссылки][подтверждение][чужая работа]).
//
// ⚠️ Именно очередь, а не один буфер. С одним слотом второе отложенное
// сообщение приходилось отдавать вперёд подтверждения — и libbinder рвал
// процесс на «*** BAD COMMAND 29190». Заодно ушли 64 КБ на каждый гостевой
// поток: теперь память берётся только под то, что реально отложено.
struct qmsg { struct qmsg *next; size_t n; uint8_t buf[]; };
struct thr;
static void dq_drop(struct thr *t);

struct thr {
    int fd;                    // соединение с демоном
    struct sess *s;
    struct qmsg *dq, **dq_tail;   // прочитано у демона, но ещё не отдано гостю
    int looper;
    int completes;             // сколько BR_TRANSACTION_COMPLETE мы должны гостю
    int failed;                // сколько BR_FAILED_REPLY мы должны гостю
    int acks;                  // сколько подтверждений обработки ждём от демона
    uint32_t iseq;             // номер последнего принятого сообщения от демона
    uint8_t *rx;               // растущий приёмный буфер: см. drecv
    uint32_t rxcap;
    // ★ Учёт ОДНОГО захода в ioctl: сколько посылок гость отдал нам сейчас и
    // что это было. Нужен для сторожа «приняли посылку, а подтверждения не
    // отдали» — см. binder_write_read.
    int sent;
    uint32_t last_code, last_flags, last_handle;
    /*
     * ★★★ Учёт ВСЕЙ ЖИЗНИ потока — для страховки от вечного ожидания.
     * Подробности у rescue_possible().
     */
    int in_txn;                // входящих транзакций в работе
    /*
     * ★★★★★ ИЗВЕЩЕНИЙ О СМЕРТИ В РАБОТЕ.
     *
     * Такой же признак «поток занят чужим делом», как in_txn, но для другой
     * команды. Поток пула, получивший BR_DEAD_BINDER, уходит в
     * `sendObituary()` — а это гостевой код, который может и позвать кого
     * угодно. Пока он там, BC_DEAD_BINDER_DONE ещё не послан, и ждать работу
     * поток НЕ МОЖЕТ ПО УСТРОЙСТВУ libbinder. Без этого счёта такой поток
     * неотличим от свободного — см. rescue_possible().
     *
     * ⚠️★★★★★ СЧЁТЧИК ЗАВЫШАЕТ, И ЭТО НЕ ЛЕЧИТСЯ. Извещение закрывают
     * командой BC_DEAD_BINDER_DONE, и так делает libbinder — но НЕ ВСЕ. Старый
     * `servicemanager` (свой крошечный разборщик на C, не libbinder) на
     * BR_DEAD_BINDER просто зовёт обработчик и НИЧЕГО не отвечает. Замерено
     * 21.09: когда умер system_server, у его главного потока счётчик дошёл до
     * 90 (по числу служб) и не спадал больше никогда.
     *
     * Поэтому решений по нему принимать НЕЛЬЗЯ — только разрешать ожиданию
     * быть с потолком. Разоружается при первом же холостом спасении, см.
     * binder_write_read.
     */
    int in_death;              // извещений о смерти, ещё не закрытых гостем
    /*
     * ★ Сколько посылок было у потока В МИГ выдачи последнего извещения.
     * Признак «занят извещением» сам по себе врёт (см. выше), а вот «получил
     * извещение И ПОСЛЕ ЭТОГО что-то послал» — не врёт: посылать из
     * `binderDied` можно только изнутри `waitForResponse`, а туда из пула не
     * попадают. Старый `servicemanager` не шлёт ничего — и под это правило не
     * подпадает, как и должен.
     */
    int tx_at_death;
    uint64_t inbuf[8];         // адреса их буферов (пока гость не вернул)
    uint32_t incode[8];        // ★ и коды: на что именно поток сейчас отвечает
    int pending_sync;          // свои ДВУСТОРОННИЕ посылки без ответа
    /*
     * ★ Трасса (guest_trace.c): открытые НАШИ отметки потока — «o» для своего
     * вызова с ответом, «i» для чужого, который поток исполняет. Конец ставим,
     * только если на вершине лежит отметка того же рода: иначе «E» закрыл бы
     * чужую отметку прошивки (трассу включили посреди вызова).
     */
    char tr_st[16];
    int tr_n;
    int tx_total;              // сколько посылок поток отправил за жизнь
    /*
     * ★ Сколько подтверждений мы гостю ВЫДАЛИ. Сравнение с tx_total в миг
     * спасения говорит, на чьей стороне потеря, без всякого разбора: выдали
     * меньше, чем приняли посылок, — потеряли мы; выдали ровно столько же —
     * потерял гость (libbinder разобрал подтверждение как чужое).
     */
    int cpl_given;
    int cpl_orphan;            // не начислено подтверждений «в никуда» (см. will_read)
    int will_read;             // в ЭТОМ заходе в ioctl гость забирает ответ
    /* ★ Сколько наших посылок демон не принял. Норма — ноль. */
    int lost;
    /*
     * ★★★★★ В прошлом заходе отдали гостю ОДНОСТОРОННЮЮ транзакцию. В начале
     * следующего ioctl скажем демону SB_ASYNC_DONE: к этому мигу гость уже
     * выполнил executeCommand, и демон может отдавать следующую к тому же узлу.
     */
    int async_pending;
};

static struct sess g_sess[SB_MAXSESS];
static pthread_key_t g_thrkey;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static int g_first_thread_done;

/*
 * ★ Сколько транзакций на процесс записывать в перепись. Печать на горячем
 * пути сдвигает время и прячет гонку — поэтому потолок, а не «всё подряд».
 * Всё интересное про службы случается в первые секунды жизни процесса.
 */
#define SB_TRACE_N 64

/*
 * ★★★ САМАЯ ДЛИННАЯ СТРОКА ПОСЫЛКИ.
 *
 * Зачем. Номер маркера — это адрес объекта, а адреса Dalvik переиспользует:
 * через полсекунды тот же 0xb4eeb0 уже другая служба. Из-за этого разбор
 * «какая транзакция чья» упирался в догадки по размерам и времени.
 *
 * А в посылке лежит имя открытым текстом: у scheduleCreateService — класс
 * службы из ServiceInfo, у scheduleBindService — компонент из Intent. Строки в
 * Parcel хранятся UTF-16, поэтому ищем самую длинную цепочку «печатный символ,
 * старший байт ноль» и её печатаем. Гадать больше не надо.
 */
static void txn_sniff(const void *data, unsigned long long dsize,
                      char *out, unsigned outn) {
    const unsigned char *d = (const unsigned char *)data;
    unsigned long long n = dsize / 2, best = 0, bestlen = 0, cur = 0;
    out[0] = 0;
    for (unsigned long long i = 0; i < n; i++) {
        unsigned char lo = d[i * 2], hi = d[i * 2 + 1];
        int ok = (hi == 0 && lo >= 0x20 && lo < 0x7f);
        if (ok) { cur++; if (cur > bestlen) { bestlen = cur; best = i + 1 - cur; } }
        else cur = 0;
    }
    if (bestlen < 6) return;
    /* Длинное имя обрезаем с НАЧАЛА: хвост («…systemui.ImageWallpaper») говорит
     * больше, чем голова («com.android…»). */
    unsigned keep = outn - 1;
    if (bestlen > keep) { best += bestlen - keep; bestlen = keep; }
    unsigned k = 0;
    for (unsigned long long i = 0; i < bestlen; i++) out[k++] = (char)d[(best + i) * 2];
    out[k] = 0;
}

/*
 * ★★★ ПЕРВЫЙ ОБЪЕКТ ПОСЫЛКИ — «маркер».
 *
 * Зачем. У службы маркер (token) — это объект ServiceRecord из system_server.
 * ActivityThread держит по нему карту `mServices`, а ключ там — САМ ОБЪЕКТ
 * BinderProxy, без equals. Если на «создать службу» и на «привязать» гость
 * получит РАЗНЫЕ номера ссылки, это будут два разных BinderProxy, и
 * `mServices.get(маркер)` вернёт null. Дальше handleBindService МОЛЧА не
 * делает ничего: ни publishService, ни подтверждения, ни строки в журнале —
 * ровно то, что мы видим как «requested=true received=false» и чёрные обои.
 *
 * Поэтому печатаем номер: две строки подряд с разными номерами — приговор.
 */
static void txn_obj0(const void *data, unsigned long long dsize,
                     const void *offs8, unsigned long long noff,
                     char *out, unsigned outn) {
    out[0] = 0;
    if (!noff || outn < 24) return;
    unsigned long long off;
    memcpy(&off, offs8, 8);
    if (off + 16 > dsize) return;
    const unsigned char *o = (const unsigned char *)data + off;
    unsigned int type, w2;
    memcpy(&type, o, 4);
    memcpy(&w2, o + 8, 4);
    snprintf(out, outn, " маркер=%s0x%x",
             type == 0x73622a85u ? "свой:"   : type == 0x73682a85u ? "ссылка:" :
             type == 0x77622a85u ? "свойсл:" : type == 0x77682a85u ? "ссылсл:" : "иное:",
             w2);
}

/*
 * ★★★★★ ИМЯ ИНТЕРФЕЙСА ПРЯМО ИЗ ПОСЫЛКИ.
 *
 * Зачем. Разбор потерянных транзакций упирался в один и тот же вопрос: «код 20
 * — это что?» Номера у IApplicationThread в прошивке изготовителя СДВИНУТЫ
 * против AOSP (bindApplication здесь 13, а не 12), и всякая догадка по таблице
 * AOSP врёт.
 *
 * А имя интерфейса лежит в самой посылке: любая java-транзакция начинается с
 * writeInterfaceToken — слово строгого режима, потом строка UTF-16. То же
 * делает и нативный Parcel. Берём хвост после последней точки, чтобы строка
 * журнала осталась короткой: «IApplicationThread», «IActivityManager».
 *
 * ⚠️ У PING (_PNG) и INTERFACE (_NTF) данных нет вовсе — вернём пусто.
 */
static void txn_iface(const void *data, unsigned long long dsize,
                      char *out, unsigned outn) {
    const unsigned char *d = (const unsigned char *)data;
    out[0] = 0;
    if (dsize < 8 || outn < 8) return;
    unsigned int len;
    memcpy(&len, d + 4, 4);
    if (len < 3 || len > 96 || 8ull + (unsigned long long)(len + 1) * 2 > dsize) return;
    unsigned start = 0;
    for (unsigned i = 0; i < len; i++) {
        unsigned short c;
        memcpy(&c, d + 8 + i * 2, 2);
        if (c == '.') start = i + 1;            // запоминаем последнюю точку
    }
    unsigned k = 0;
    for (unsigned i = start; i < len && k + 1 < outn; i++) {
        unsigned short c;
        memcpy(&c, d + 8 + i * 2, 2);
        out[k++] = (c >= 32 && c < 127) ? (char)c : '?';
    }
    out[k] = 0;
}

/* ★ Трасса: начало и конец своей отметки вызова binder (см. struct thr).
 * Начало кладётся на стек, только когда трасса идёт (tr_begin зовут при
 * включённой); конец снимает со стека всегда, а «E» пишет guest_trace_mark
 * лишь при включённой. */
static void tr_begin(struct thr *t, char kind, const char *ifn, uint32_t code)
{
    if (t->tr_n < (int)sizeof t->tr_st) t->tr_st[t->tr_n++] = kind;
    guest_trace_mark('B', "binder%c %s#%u", kind == 'o' ? '>' : '<',
                     ifn[0] ? ifn : "?", (unsigned)code);
}

static void tr_end(struct thr *t, char kind)
{
    if (t->tr_n > 0 && t->tr_st[t->tr_n - 1] == kind) {
        t->tr_n--;
        guest_trace_mark('E', " ");
    }
}

static void thr_free(void *p) {
    struct thr *t = (struct thr *)p;
    if (!t) return;
    /*
     * ★★★★★ ОТЛОЖЕННОЕ НЕ БРОСАЕМ — ПЕРЕКЛАДЫВАЕМ ПРОЦЕССУ.
     *
     * Здесь `t->dq` не трогали вовсе: поток уходил, а всё, что демон ему уже
     * отдал (не влезло в буфер чтения гостя или ждало очереди за
     * подтверждением), просто утекало вместе с ним. Демон при этом потерь не
     * видит — он свою работу отдал.
     *
     * Наружу это выходит службой, которая «привязана, но не подключилась»:
     * `requested=true received=false`, `executeNesting` висит навсегда, ANR не
     * срабатывает. Измерено 16 сентября: разом ЧЕТЫРЕ такие службы в четырёх
     * процессах — среди них `ImageWallpaper`, и это и есть «обои пропадают
     * через раз».
     *
     * Чужие транзакции достаются процессу: их возьмёт следующий его поток.
     * Ответы отдавать некому — о них говорим вслух.
     */
    if (t->dq) {
        struct sess *ss = t->s;
        int moved = 0, dropped = 0;
        if (ss) pthread_mutex_lock(&ss->lock);
        while (t->dq) {
            struct qmsg *q = t->dq;
            t->dq = q->next;
            q->next = NULL;
            struct sb_hdr *h = (struct sb_hdr *)q->buf;
            if (ss && q->n >= sizeof *h && h->type == SB_R_TRANSACTION) {
                if (!ss->dq_tail) ss->dq_tail = &ss->dq;
                *ss->dq_tail = q; ss->dq_tail = &q->next;
                moved++;
            } else { free(q); dropped++; }
        }
        t->dq_tail = &t->dq;
        if (ss) pthread_mutex_unlock(&ss->lock);
        if (moved || dropped)
            bwarn("binder: поток уходит с отложенным: %d чужих транзакций отдал "
                  "процессу, %d выбросил (адресованы ему одному)", moved, dropped);
    }
    if (t->fd >= 0) {
        struct sess *ss = t->s;
        if (ss) {
            // Снять с учёта побудки (Р-4): описатель сейчас закроется, и номер
            // достанется другому — будить его на закрытии сессии было бы чужое.
            pid_t me = getpid();
            pthread_mutex_lock(&ss->lock);
            for (int i = 0; i < ss->ntfd; i++) {
                if (ss->tfd[i].fd == t->fd && ss->tfd[i].pid == me) {
                    ss->tfd[i] = ss->tfd[--ss->ntfd];
                    break;
                }
            }
            pthread_mutex_unlock(&ss->lock);
        }
        struct sb_hdr h = { .len = sizeof h, .type = SB_BYE, .flags = SB_F_MAGIC };
        (void)!write(t->fd, &h, sizeof h);
        close(t->fd);
    }
    free(t->rx);
    free(t);
}

static void thrkey_init(void) { pthread_key_create(&g_thrkey, thr_free); }

// ------------------------------------------------------ распределитель буферов

// Приёмные буферы транзакций живут в области, которую гость получил через mmap:
// именно туда указывает data.ptr.buffer, и оттуда гость читает посылку, а потом
// возвращает буфер командой BC_FREE_BUFFER.
static void *buf_alloc(struct sess *s, size_t size) {
    size = (size + 7) & ~(size_t)7;
    if (!size) size = 8;
    pthread_mutex_lock(&s->lock);
    /*
     * ★★★ Карантин на только что освобождённые блоки.
     *
     * Гость освобождает приёмный буфер не одним действием: сначала
     * Parcel::closeFileDescriptors() проходит по массиву смещений объектов и
     * закрывает дескрипторы, и лишь потом уходит BC_FREE_BUFFER. Если между
     * этими двумя шагами мы отдадим тот же блок под новую транзакцию, гость
     * прочитает уже ЧУЖИЕ смещения — и падает прямо там:
     *
     *   GUESTFATAL sig=11 pc=… /system/lib/libbinder.so
     *   PC -> android::Parcel::closeFileDescriptors()+0x1e
     *   LR -> android::IPCThreadState::freeBuffer(...)+0xb
     *
     * а вместе с system_server умирает вся система. Поэтому освобождённый блок
     * пропускаем несколько ближайших выделений: за это время гость успевает
     * дочитать. Берём такой блок, только если других нет вовсе.
     */
    struct blk *best = NULL, *hot = NULL;
    for (struct blk *b = s->blocks; b; b = b->next) {
        if (b->used || b->size < size) continue;
        if (b->cool > 0) { if (!hot) hot = b; continue; }
        best = b;
        break;
    }
    if (!best) best = hot;
    if (!best) { pthread_mutex_unlock(&s->lock); return NULL; }
    /* Отсчёт карантина ведём по выделениям, а не по времени: так он не зависит
     * от того, насколько занят процесс. */
    for (struct blk *b = s->blocks; b; b = b->next)
        if (b->cool > 0) b->cool--;
    if (best->size > size + 64) {                       // отрезаем хвост
        struct blk *tail = (struct blk *)malloc(sizeof *tail);
        if (tail) {
            tail->off = best->off + size;
            tail->size = best->size - size;
            tail->used = 0;
            tail->cool = 0;
            tail->dsize = tail->osize = 0;
            tail->next = best->next;
            best->next = tail;
            best->size = size;
        }
    }
    best->used = 1;
    /*
     * ★★★ Проверка границы области — последняя преграда перед порчей чужой
     * памяти гостя.
     *
     * Блоки нарезаются делением (см. «отрезаем хвост» выше), и стоит учёту
     * разъехаться хоть на байт, как выданный блок вылезет ЗА пределы области,
     * которую гость получил через mmap. Дальше мы пишем тело транзакции прямо
     * туда — то есть в память гостя, которая нам не принадлежит. Наружу это
     * выглядит как смерть В ЧУЖОМ МЕСТЕ и без всякой связи с binder:
     *
     *   mediaserver:   Fatal signal 6 (SIGABRT) … stack corruption detected
     *   system_server: Fatal signal 11 (SIGSEGV) at 0x9805e00c
     *
     * и оба раза — в потоке Binder_1. Отладить такое по месту падения нельзя:
     * портится одно, а падает другое, позже и в другом процессе.
     *
     * Поэтому лучше честно отказать (гость получит BR_FAILED_REPLY и переживёт
     * это), чем молча испортить память. И громко сказать: если строка появится,
     * искать надо здесь, в учёте блоков, а не там, где упало.
     */
    if (best->off + size > s->map_size) {
        bwarn("binder: ★★★ блок вылез за область: смещение %zu + %zu > %zu — "
              "ОТКАЗЫВАЕМ (иначе испортили бы память гостя)",
              (size_t)best->off, size, (size_t)s->map_size);
        best->used = 0;
        pthread_mutex_unlock(&s->lock);
        return NULL;
    }
    void *p = s->map + best->off;
    pthread_mutex_unlock(&s->lock);
    return p;
}

// Записать разметку принятой посылки в блок, выданный buf_alloc.
static void buf_note(struct sess *s, void *addr, uint32_t dsize, uint32_t osize) {
    pthread_mutex_lock(&s->lock);
    size_t off = (size_t)((uint8_t *)addr - s->map);
    for (struct blk *b = s->blocks; b; b = b->next)
        if (b->off == off) { b->dsize = dsize; b->osize = osize; break; }
    pthread_mutex_unlock(&s->lock);
}

// Забрать разметку и тут же стереть: повторный BC_FREE_BUFFER по тому же
// адресу не должен снять ссылки второй раз.
static int buf_take(struct sess *s, uint64_t addr, uint32_t *dsize, uint32_t *osize) {
    int found = 0;
    pthread_mutex_lock(&s->lock);
    size_t off = (size_t)(addr - (uint64_t)(uintptr_t)s->map);
    for (struct blk *b = s->blocks; b; b = b->next)
        if (b->off == off) { *dsize = b->dsize; *osize = b->osize; b->dsize = b->osize = 0; found = 1; break; }
    pthread_mutex_unlock(&s->lock);
    return found;
}

static void buf_free(struct sess *s, uint64_t addr) {
    pthread_mutex_lock(&s->lock);
    size_t off = (size_t)(addr - (uint64_t)(uintptr_t)s->map);
    for (struct blk *b = s->blocks; b; b = b->next) {
        if (b->off != off) continue;
        b->used = 0;
        b->cool = 16;                 // ★ карантин, см. buf_alloc
        // Склеиваем соседние свободные, иначе область быстро дробится.
        for (struct blk *q = s->blocks; q; q = q->next)
            while (!q->used && q->next && !q->next->used) {
                struct blk *n = q->next;
                q->size += n->size;
                if (n->cool > q->cool) q->cool = n->cool;
                q->next = n->next;
                free(n);
            }
        break;
    }
    pthread_mutex_unlock(&s->lock);
}


// Дочитать ровно len байт. Нужно там, где длина известна заранее: на потоковом
// сокете и read, и recvmsg вправе отдать меньше, чем просили.
static int rd_all(int fd, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) { errno = EPIPE; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

// ------------------------------------------------- поток-будильник (pump)

// Главный поток гостя ждёт binder не в ioctl, а в poll/epoll на дескрипторе
// (так работают zygote и system_server через Looper). Демон умеет сообщить, что
// для процесса появилась работа, но принять это сообщение и разбудить poll
// некому — поэтому в каждом процессе живёт один служебный поток: он держит
// отдельное соединение с демоном и на каждое уведомление пишет байт в конец B
// сокетной пары. Гость видит POLLIN на своём конце и сам заходит в ioctl.

static void *pump_main(void *arg) {
    struct sess *s = (struct sess *)arg;
    int fd = connect_sock(g_binder);
    if (fd < 0) { glog("binder: будильник не подключился: %s", strerror(errno)); return NULL; }
    s->pump_fd = fd;
    struct { struct sb_hdr h; struct sb_hello b; } msg;
    memset(&msg, 0, sizeof msg);
    msg.h.len = sizeof msg;
    msg.h.type = SB_HELLO;
    msg.h.tid = (uint32_t)gettid();
    msg.h.flags = SB_F_MAGIC;             // без метки демон сочтёт это мусором
    msg.b.pid = (uint32_t)getpid();
    // ⚠️ Личность гостя, а не хозяина: по ней servicemanager решает, кому можно
    // объявлять службы (см. guest_ids.c).
    msg.b.uid = (uint32_t)guest_guest_uid();
    msg.b.gid = (uint32_t)guest_guest_gid();
    msg.b.first = 2;                       // 2 — «я будильник, не рабочий поток»
    if (write(fd, &msg, sizeof msg) != (ssize_t)sizeof msg) { close(fd); s->pump_fd = -1; return NULL; }
    s->pump_live = 1;
    glog("binder: будильник поднят");
    for (;;) {
        struct sb_hdr h;
        // ⚠️ Ровно то место, где раньше рвалась связь молча: обычный read на
        // потоковом сокете вправе отдать меньше, а прерванный сигналом —
        // вернуть EINTR. Выход из цикла тут = будильник умер, и гость, ждущий
        // в poll, больше никогда не проснётся.
        if (rd_all(fd, &h, sizeof h) < 0) break;
        if ((h.flags & SB_F_MAGIC_MASK) != SB_F_MAGIC) {
            glog("binder: ★ будильник поймал не наш заголовок (len=%u тип=%u)", h.len, h.type);
            break;
        }
        if (h.len > sizeof h) {            // тело нам не нужно, просто вычитываем
            char junk[512];
            uint32_t left = h.len - (uint32_t)sizeof h;
            while (left) {
                ssize_t k = read(fd, junk, left > sizeof junk ? sizeof junk : left);
                if (k <= 0) break;
                left -= (uint32_t)k;
            }
        }
        char one = 'w';
        ssize_t wr = write(s->fd_wake, &one, 1);   // гость увидит POLLIN и зайдёт в ioctl
        // Диагностика: сразу проверяем, стал ли гостевой конец читаемым.
        struct pollfd pf = { .fd = s->fd_guest, .events = POLLIN };
        int pr = poll(&pf, 1, 0);
        glog("binder: будильник -> байт в fd=%d (%zd); гостевой fd=%d готов? %d (0x%x)",
             s->fd_wake, wr, s->fd_guest, pr, pf.revents);
    }
    s->pump_live = 0;
    close(fd);
    s->pump_fd = -1;
    glog("binder: будильник ушёл");
    return NULL;
}

static void pump_start(struct sess *s) {
    if (s->pump_live || !g_binder[0]) return;
    s->pump_fd = -1;
    if (pthread_create(&s->pump, NULL, pump_main, s) != 0)
        glog("binder: не удалось создать будильник");
}

// После fork в ребёнке остаётся ровно один поток, а унаследованные соединения с
// демоном принадлежат родителю: писать в них нельзя, у ребёнка другой pid.
// Поэтому соединения закрываем, а будильник поднимаем заново. Без этого zygote,
// который только форками и живёт, работать не может.
static void binder_atfork_child(void) {
    for (int i = 0; i < SB_MAXSESS; i++) {
        struct sess *s = &g_sess[i];
        if (!s->used) continue;
        if (s->pump_fd >= 0) { close(s->pump_fd); s->pump_fd = -1; }
        s->pump_live = 0;
        // ⚠️ Ничейное отложенное — РОДИТЕЛЯ: он его и получит. Ребёнку чужую
        // работу отдавать нельзя, иначе она выполнится дважды.
        while (s->dq) { struct qmsg *q = s->dq; s->dq = q->next; free(q); }
        s->dq_tail = &s->dq;
        pthread_mutex_init(&s->lock, NULL);      // мьютекс мог остаться взятым
        // ⚠️ Сокеты потоков в учёте побудки — РОДИТЕЛЯ (Р-4): будить их
        // ребёнку нельзя, а свои его потоки заведут заново.
        s->ntfd = 0;
        s->closing = 0;
    }
    struct thr *t = (struct thr *)pthread_getspecific(g_thrkey);
    if (t && t->fd >= 0) { close(t->fd); t->fd = -1; dq_drop(t); }
    // ⚠️ Учёт родителя ребёнку не наследуется. Соединение мы только что
    // закрыли, значит ни подтверждений от демона, ни долгов перед гостем у
    // ребёнка нет: оставленные счётчики заставили бы его ждать ответа,
    // который придёт РОДИТЕЛЮ. Зигота живёт форками — тут это цена всего.
    if (t) { t->acks = 0; t->completes = 0; t->failed = 0; t->iseq = 0; t->sent = 0;
             t->in_txn = 0; t->in_death = 0; t->tx_at_death = 0;
             t->pending_sync = 0; t->tx_total = 0; t->cpl_given = 0; }
    g_first_thread_done = 0;
    for (int i = 0; i < SB_MAXSESS; i++)
        if (g_sess[i].used) pump_start(&g_sess[i]);
}

// ---------------------------------------------------------------- сессии

// Что сейчас в таблице сессий — для ловушки промаха перехвата.
static const char *binder_sess_dump(void) {
    static __thread char b[128];
    int n = snprintf(b, sizeof b, "сессии:");
    for (int i = 0; i < SB_MAXSESS && n > 0 && n < (int)sizeof b; i++)
        n += snprintf(b + n, sizeof b - (size_t)n, " [%d]%s fd=%d", i,
                      g_sess[i].used ? "занят" : "свободен", g_sess[i].fd_guest);
    return b;
}

static struct sess *sess_by_fd(int fd) {
    for (int i = 0; i < SB_MAXSESS; i++)
        if (g_sess[i].used && g_sess[i].fd_guest == fd) return &g_sess[i];
    return NULL;
}

// Открытие «устройства»: гостю отдаём конец сокетной пары. Это делает рабочим
// poll/epoll на дескрипторе binder — на него опирается главный поток гостя.
static int binder_open_fake(void) {
    struct sess *s = NULL;
    for (int i = 0; i < SB_MAXSESS; i++) if (!g_sess[i].used) { s = &g_sess[i]; break; }
    if (!s) { errno = ENFILE; return -1; }
    int sv[2];
    // ⚠️ SOCK_CLOEXEC: настоящий /dev/binder открывается с O_CLOEXEC, и после
    // execve процесс обязан открыть драйвер заново. Без этого наш описатель
    // уезжает в новый образ, где таблица сессий уже пустая, — и обращения к
    // binder на нём уходят в ядро ХОЗЯИНА («ioctl error -13»).
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0) return -1;
    memset(s, 0, sizeof *s);
    s->used = 1;
    s->fd_guest = sv[0];
    s->fd_wake = sv[1];
    pthread_mutex_init(&s->lock, NULL);
    s->pump_fd = -1;
    pthread_once(&g_once, thrkey_init);
    static int atfork_done;
    if (!atfork_done) { atfork_done = 1; pthread_atfork(NULL, NULL, binder_atfork_child); }
    pump_start(s);
    glog("binder: сессия открыта, fd=%d", s->fd_guest);
    return s->fd_guest;
}

static void binder_close_fake(struct sess *s) {
    glog("binder: сессия закрыта fd=%d", s->fd_guest);
    /*
     * ★★★ Разбудить потоки этой сессии (Р-4, см. sess.closing): их чтение
     * вернётся, ioctl отдаст EBADF, и libbinder выведет их из пула. Иначе
     * гостевая программа на Dalvik не завершается никогда.
     */
    s->closing = 1;
    {
        pid_t me = getpid();
        int woke = 0;
        pthread_mutex_lock(&s->lock);
        for (int i = 0; i < s->ntfd; i++) {
            if (s->tfd[i].pid == me) {
                shutdown(s->tfd[i].fd, SHUT_RDWR);
                woke++;
            }
        }
        pthread_mutex_unlock(&s->lock);
        if (woke) glog("binder: закрытие сессии — разбужено потоков %d", woke);
    }
    if (s->map) target_munmap(h2g(s->map), s->map_size);
    while (s->blocks) { struct blk *b = s->blocks; s->blocks = b->next; free(b); }
    close(s->fd_wake);
    s->used = 0;
}

// ------------------------------------------------------ связь с демоном

static struct thr *thr_get(struct sess *s) {
    pthread_once(&g_once, thrkey_init);
    struct thr *t = (struct thr *)pthread_getspecific(g_thrkey);
    if (t) return t;
    t = (struct thr *)calloc(1, sizeof *t);
    if (!t) return NULL;
    t->fd = -1;
    t->s = s;
    pthread_setspecific(g_thrkey, t);

    if (!g_binder[0]) { glog("binder: не задан GUEST_BINDER"); return t; }
    t->fd = connect_sock(g_binder);
    if (t->fd < 0) { glog("binder: демон недоступен (%s): %s", g_binder, strerror(errno)); return t; }
    struct { struct sb_hdr h; struct sb_hello b; } msg;
    memset(&msg, 0, sizeof msg);
    msg.h.len = sizeof msg;
    msg.h.type = SB_HELLO;
    msg.h.tid = (uint32_t)gettid();
    msg.h.flags = SB_F_MAGIC;             // без метки демон сочтёт это мусором
    msg.b.pid = (uint32_t)getpid();
    // ⚠️ Личность гостя, а не хозяина: по ней servicemanager решает, кому можно
    // объявлять службы (см. guest_ids.c).
    msg.b.uid = (uint32_t)guest_guest_uid();
    msg.b.gid = (uint32_t)guest_guest_gid();
    msg.b.first = g_first_thread_done ? 0 : 1;
    g_first_thread_done = 1;
    if (write(t->fd, &msg, sizeof msg) != (ssize_t)sizeof msg) {
        glog("binder: HELLO не ушёл"); close(t->fd); t->fd = -1; return t;
    }
    // Ждём подтверждения, иначе первые сообщения могут опередить регистрацию.
    struct sb_hdr ack;
    // ⚠️ Дочитывать обязательно. Частичное чтение здесь раньше проходило молча,
    // а недобранные байты оставались в сокете — дальше «заголовком» считалась
    // середина чужого сообщения, и поток навсегда уходил ждать мусорную длину.
    if (rd_all(t->fd, &ack, sizeof ack) < 0 ||
        (ack.flags & SB_F_MAGIC_MASK) != SB_F_MAGIC || ack.type != SB_R_OK) {
        glog("binder: демон не подтвердил HELLO — связь рвём, чтобы не поехал поток");
        close(t->fd); t->fd = -1; return t;
    }
    t->iseq = ack.tid;                     // дальше номера идут подряд
    // ★ Запомнить сокет в сессии — разбудить его на закрытии (Р-4).
    pthread_mutex_lock(&s->lock);
    if (s->ntfd < SB_MAXTHR) {
        s->tfd[s->ntfd].fd = t->fd;
        s->tfd[s->ntfd].pid = getpid();
        s->ntfd++;
    }
    pthread_mutex_unlock(&s->lock);
    return t;
}

// Записать всё до конца. На потоковом сокете write/sendmsg имеют право отдать
// меньше, чем просили, а прерванный сигналом вызов — вернуть EINTR. Без
// досылки поток сообщений рассинхронизируется, и другая сторона вечно ждёт
// тело сообщения (симптом ловили на getService: демон ответил, тело не дошло).
static int wr_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = (const uint8_t *)buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) { errno = EPIPE; return -1; }
        p += n; len -= (size_t)n;
    }
    return 0;
}

static int dsend(struct thr *t, uint16_t type, const void *body, uint32_t blen,
                 const int *fds, int nfds) {
    if (t->fd < 0) { errno = ENOTCONN; return -1; }
    struct sb_hdr h = { .len = (uint32_t)(sizeof h + blen), .type = type,
                         .nfds = (uint16_t)nfds, .tid = (uint32_t)gettid(),
                         .flags = SB_F_MAGIC };
    struct iovec iov[2] = { { &h, sizeof h }, { (void *)body, blen } };
    char cbuf[CMSG_SPACE(sizeof(int) * 8)];
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = iov;
    m.msg_iovlen = blen ? 2 : 1;
    if (nfds > 0) {
        memset(cbuf, 0, sizeof cbuf);
        m.msg_control = cbuf;
        m.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)nfds);
        struct cmsghdr *cm = CMSG_FIRSTHDR(&m);
        cm->cmsg_level = SOL_SOCKET;
        cm->cmsg_type = SCM_RIGHTS;
        cm->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)nfds);
        memcpy(CMSG_DATA(cm), fds, sizeof(int) * (size_t)nfds);
    }
    if (nfds > 0) {
        m.msg_iovlen = 1;                       // заголовок + описатели
        ssize_t n;
        do { n = sendmsg(t->fd, &m, MSG_NOSIGNAL); } while (n < 0 && errno == EINTR);
        if (n != (ssize_t)sizeof h) return -1;
        return blen ? wr_all(t->fd, body, blen) : 0;
    }
    if (wr_all(t->fd, &h, sizeof h) < 0) return -1;
    return blen ? wr_all(t->fd, body, blen) : 0;
}

// Читает ровно одно сообщение демона. Описатели, если были, кладёт в fds.
static int drecv(struct thr *t, uint8_t **bufp, size_t cap, int *fds, int *nfds) {
    *nfds = 0;
    struct sb_hdr h;
    char cbuf[CMSG_SPACE(sizeof(int) * 8)];
    struct iovec iov = { &h, sizeof h };
    struct msghdr m;
    memset(&m, 0, sizeof m);
    m.msg_iov = &iov; m.msg_iovlen = 1;
    m.msg_control = cbuf; m.msg_controllen = sizeof cbuf;
    // ★ EINTR — не разрыв. Гостевые процессы получают сигналы (у SF это
    // POSIX-таймеры), и прерванное чтение надо повторить, а не объявлять
    // потерей связи. Измерено на телефоне 2026-08-26: шим возвращал libbinder
    // ошибку, поток БРОСАЛ чтение и уходил в poll, а демон по-прежнему считал
    // его ждущим — и отдавал ему следующую транзакцию, которая там и висела.
    // Снаружи это выглядело так: bootanimation вечно ждёт ответа от
    // SurfaceFlinger, у которого все потоки спокойно спят.
    // ⚠️ MSG_WAITALL не спасает от сигнала. Если сигнал пришёл ПОСЛЕ первых
    // байт, recvmsg возвращает частичный счёт, а не EINTR, — и раньше здесь
    // терялось ползаголовка. Дальше «заголовком» становилась середина чужого
    // тела, шим уходил читать длину, взятую из мусора, и висел вечно, а демон
    // при этом спокойно спал без работы. Остаток дочитываем сами.
    ssize_t n;
    do { n = recvmsg(t->fd, &m, MSG_WAITALL); }
    while (n < 0 && errno == EINTR && (glog("binder: чтение прервано сигналом, повтор"), 1));
    if (n <= 0) return -1;
    if (n < (ssize_t)sizeof h) {
        glog("binder: заголовок пришёл кусками (%zd из %zu), дочитываем", n, sizeof h);
        if (rd_all(t->fd, (uint8_t *)&h + n, sizeof h - (size_t)n) < 0) return -1;
    }
    for (struct cmsghdr *cm = CMSG_FIRSTHDR(&m); cm; cm = CMSG_NXTHDR(&m, cm)) {
        if (cm->cmsg_level != SOL_SOCKET || cm->cmsg_type != SCM_RIGHTS) continue;
        int cnt = (int)((cm->cmsg_len - CMSG_LEN(0)) / sizeof(int));
        for (int i = 0; i < cnt && *nfds < 8; i++)
            memcpy(&fds[(*nfds)++], CMSG_DATA(cm) + i * sizeof(int), sizeof(int));
    }
    /*
     * ★★ СКОЛЬКО ОПИСАТЕЛЕЙ ОБЕЩАНО В ЗАГОЛОВКЕ — СТОЛЬКО И ДОЛЖНО ПРИЙТИ.
     *
     * Без этой сверки потеря описателя была НЕМОЙ: объекты оставались с
     * номерами по порядку, гость принимал ноль за описатель, и разбираться
     * приходилось с другого конца — по замершей картинке. Сверка стоит одного
     * сравнения на сообщение и сразу говорит, на чьей стороне потеря.
     */
    if ((int)h.nfds != *nfds) {
        static unsigned said;
        if (said < 8 || (said & 1023) == 0)
            glog("binder: ★ описателей пришло %d, а обещано %u (тип %u, №%u, случай %u)",
                 *nfds, (unsigned)h.nfds, (unsigned)h.type, (unsigned)h.tid, said + 1);
        said++;
    }

    // Метка и порядок: рассинхрон ловим ЗДЕСЬ, а не вечным чтением мусорной
    // длины. Любые 16 байт похожи на заголовок, отличить их можно только так.
    if ((h.flags & SB_F_MAGIC_MASK) != SB_F_MAGIC || h.len < sizeof h) {
        glog("binder: ★ РАССИНХРОН — заголовок не наш: len=%u тип=%u №%u флаги=%#x",
             h.len, h.type, h.tid, h.flags);
        errno = EPROTO;
        return -1;
    }
    if (t->iseq && h.tid != t->iseq + 1)
        glog("binder: ★ пропуск сообщений: ждали №%u, пришло №%u (тип %u)",
             t->iseq + 1, h.tid, h.type);
    t->iseq = h.tid;

    uint32_t blen = h.len - (uint32_t)sizeof h;
    uint8_t *buf = *bufp;
    if (blen > cap - sizeof h) {
        // ★★★ КРУПНОЕ СООБЩЕНИЕ — не повод рвать связь.
        //
        // Так приходит ParceledListSlice: ответ на
        // ApplicationPackageManager.getInstalledApplications() при 203 пакетах
        // — 67516 байт, а буфер на стеке был 64 КБ. Шим объявлял разрыв
        // (ENOTCONN), у гостя это выглядело как
        //   android.os.RemoteException: Unknown binder error code. 0xffffff95
        // (0xffffff95 = -107 = ENOTCONN), и рабочий стол прошивки падал по кругу,
        // не сумев поднять свой поставщик данных. Хвост сообщения при этом
        // оставался в сокете — отсюда же шли «★ РАССИНХРОН».
        //
        // Теперь берём растущий буфер потока. На стеке его держать нельзя:
        // у гостевых потоков стек скромный, а сообщение бывает под мегабайт.
        if (h.len > SB_MAXMSG) {
            glog("binder: ★ длина сообщения невозможна: %u (тип %u) — связь рвём",
                 h.len, h.type);
            errno = EPROTO;
            return -1;
        }
        if (t->rxcap < h.len) {
            uint8_t *p = (uint8_t *)realloc(t->rx, h.len);
            if (!p) { glog("binder: нет памяти под сообщение %u байт", h.len); errno = ENOMEM; return -1; }
            t->rx = p;
            t->rxcap = h.len;
            glog("binder: приёмный буфер потока вырос до %u байт (тип %u)", h.len, h.type);
        }
        buf = t->rx;
        *bufp = buf;
    }
    memcpy(buf, &h, sizeof h);
    size_t got = 0;
    while (got < blen) {
        // ★ Сторож. Тело демон пишет сразу за заголовком, ждать его дольше
        // секунд незачем. Раньше здесь был вечный read: если длина взята из
        // мусорного заголовка, поток гостя вставал навсегда, а демон при этом
        // спокойно спал без работы — снаружи это выглядело как «binder молчит»
        // и разбиралось часами. Теперь это громкая ошибка с приметами.
        struct pollfd pf = { .fd = t->fd, .events = POLLIN };
        int pr;
        do { pr = poll(&pf, 1, 10000); } while (pr < 0 && errno == EINTR);
        if (pr <= 0) {
            glog("binder: ★ тело не пришло: ждали %u байт, взяли %zu; "
                 "заголовок тип=%u len=%u №%u флаги=%#x",
                 blen, got, h.type, h.len, h.tid, h.flags);
            errno = EPROTO;
            return -1;
        }
        ssize_t k = read(t->fd, buf + sizeof h + got, blen - got);
        if (k < 0 && errno == EINTR) continue;      // тело сообщения — так же
        if (k <= 0) return -1;
        got += (size_t)k;
    }
    return (int)(sizeof h + blen);
}

// --------------------------------------- проверка смещений объектов посылки

// Объект обязан целиком лежать внутри данных и быть выровнен — так проверяет
// binder_transaction() в драйвере. Возвращает 1, если смещение годное.
// ★★★ Чтение памяти ГОСТЯ так, чтобы отказ приходил КОДОМ, а не сигналом.
//
// Настоящий драйвер копирует посылку через copy_from_user: если страница
// недоступна, он получает ошибку и отвечает отправителю BR_FAILED_REPLY. У нас
// же обычный memcpy по g2h — и недоступная страница убивает САМ qemu:
//
//   qemu-arm: QEMU internal SIGSEGV {code=ACCERR, addr=0x46981008}
//   D Zygote  Process 4274 terminated by signal (11)
//   I Zygote  Exit zygote because system server (4274) has terminated
//
// то есть через пару минут после загрузки умирает system_server, а с ним вся
// система. Место нашлось только по адресу сбоя: memcpy из bc_process.
//
// Проверки перед копированием (page_check_range через lock_user) НЕ хватает:
// она говорит о состоянии на момент проверки, а между ней и копированием
// память гостя успевает пропасть — соседний гостевой поток волен снять
// отображение. Проверено: с проверкой падение осталось, только сдвинулось.
//
// Поэтому читаем через /proc/self/mem: ядро копирует нашу же память, но по
// правилам чтения файла — недоступный кусок даёт короткое чтение или EIO,
// а не сигнал. Один системный вызов на посылку, для binder это ничто.
static int guest_mem_fd(void) {
    static int fd = -2;
    if (fd == -2) {
        fd = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
        if (fd < 0) glog("binder: нет /proc/self/mem (%s) — читаю напрямую",
                         strerror(errno));
    }
    return fd;
}

// 1 — прочитано целиком; 0 — гость дал недоступную память.
static int guest_read(void *dst, abi_ulong gaddr, size_t len) {
    if (len == 0) return 1;
    int fd = guest_mem_fd();
    if (fd < 0) {                         // отката нет — читаем как раньше
        memcpy(dst, g2h_untagged(gaddr), len);
        return 1;
    }
    // Смещение в /proc/self/mem — ХОЗЯЙСКИЙ адрес: файл индексируется по
    // адресному пространству процесса, а не по гостевому.
    off_t off = (off_t)(uintptr_t)g2h_untagged(gaddr);
    uint8_t *p = (uint8_t *)dst;
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, p + done, len - done, off + (off_t)done);
        if (n > 0) { done += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

static int obj_off_ok(uint64_t off, size_t dsize) {
    if (off & 3) return 0;
    if (off > dsize) return 0;
    return dsize - (size_t)off >= sizeof(struct flat_binder_object);
}

// Громкий отчёт о битом смещении: по нему видно, ОТКУДА взялось значение.
// Ключевой признак — лежит ли посылка гостя внутри нашего приёмного пула:
// если да, значит буфер переиспользовали под гостем (то есть виноваты мы).
static void bad_offsets(struct sess *s, const char *dir,
                        const struct binder_transaction_data *tr,
                        const uint8_t *b, size_t dsz, size_t osz, uint64_t i) {
    const uint8_t *pool = s ? s->map : NULL;
    size_t plen = s ? s->map_size : 0;
    const uint8_t *dbuf = (const uint8_t *)(uintptr_t)tr->data.ptr.buffer;
    const uint8_t *obuf = (const uint8_t *)(uintptr_t)tr->data.ptr.offsets;
    int d_in = pool && dbuf >= pool && dbuf < pool + plen;
    int o_in = pool && obuf >= pool && obuf < pool + plen;
    const uint64_t *offs = (const uint64_t *)(b + sizeof(struct sb_txn) + dsz);
    bwarn("binder: %s — БИТОЕ смещение объекта №%llu = 0x%llx "
         "(цель=%u код=%u флаги=0x%x данные=%zu смещений=%zu) "
         "буфер=%p%s объекты=%p%s пул=%p+%zu",
         dir, (unsigned long long)i, (unsigned long long)offs[i],
         (unsigned)tr->target.handle, (unsigned)tr->code, (unsigned)tr->flags,
         dsz, osz, (const void *)dbuf, d_in ? " (В ПУЛЕ)" : "",
         (const void *)obuf, o_in ? " (В ПУЛЕ)" : "", (const void *)pool, plen);
    char line[256]; size_t n = 0;
    for (uint64_t k = 0; k < osz / 8 && k < 8; k++)
        n += (size_t)snprintf(line + n, sizeof line - n, "%s0x%llx",
                              k ? " " : "", (unsigned long long)offs[k]);
    bwarn("binder:   смещения целиком: %s", line);
}

// ------------------------------------------- сборка команд BR_* для гостя

struct outbuf { uint8_t *p; size_t cap, len; };

static int out_put(struct outbuf *o, uint32_t cmd, const void *body, size_t blen) {
    if (o->len + 4 + blen > o->cap) return -1;         // не влезло — отдадим позже
    memcpy(o->p + o->len, &cmd, 4);
    o->len += 4;
    if (blen) { memcpy(o->p + o->len, body, blen); o->len += blen; }
    return 0;
}

// Превращает сообщение демона в команды BR_*. 0 — успех, -1 — не влезло.
static int msg_to_br(struct thr *t, struct sess *s, uint8_t *msg, int *fds, int nfds,
                     struct outbuf *o) {
    (void)t;
    struct sb_hdr *h = (struct sb_hdr *)msg;
    uint8_t *body = msg + sizeof *h;
    switch (h->type) {
    case SB_R_COMPLETE:      t->cpl_given++;
                              return out_put(o, BR_TRANSACTION_COMPLETE, NULL, 0);
    case SB_R_DEAD_REPLY:
    case SB_R_FAILED_REPLY:
        // ★★★ НЕУДАВШАЯСЯ ТРАНЗАКЦИЯ ПОДТВЕРЖДЕНИЯ НЕ ПОЛУЧАЕТ.
        //
        // Так делает драйвер: в binder_transaction() BR_TRANSACTION_COMPLETE
        // кладётся в очередь потока только на удачном пути, а каждый выход по
        // err_* освобождает tcomplete и отдаёт лишь BR_FAILED_REPLY/
        // BR_DEAD_REPLY.
        //
        // Чем это грозило. libbinder в waitForResponse на BR_FAILED_REPLY
        // делает `goto finish` НЕМЕДЛЕННО, и наше подтверждение оставалось
        // непрочитанным в mIn. Потом поток уходил в пул, и executeCommand
        // натыкался на команду, которой не знает:
        //   E IPCThreadState: *** BAD COMMAND 29190 received from Binder driver
        //   E IPCThreadState: getAndExecuteCommand(fd=4) returned unexpected
        //                     error -2147483648, aborting
        // (0x7206 = BR_TRANSACTION_COMPLETE, -2147483648 = UNKNOWN_ERROR)
        // — то есть abort() в system_server. Измерено на телефоне 2026-08-26:
        // так он умирал через 8 секунд после «Boot is finished», следом за
        // падением android.process.acore («FAILED BINDER TRANSACTION»).
        if (t->pending_sync > 0) {
            t->pending_sync--;     // ответа на этот вызов уже не будет
        }
        tr_end(t, 'o');
        if (t->completes > 0) {
            t->completes--;
            glog("binder: транзакция не прошла (%s) — подтверждение отменено",
                 h->type == SB_R_DEAD_REPLY ? "мёртвый адресат" : "отказ");
        }
        return out_put(o, h->type == SB_R_DEAD_REPLY ? BR_DEAD_REPLY : BR_FAILED_REPLY,
                       NULL, 0);
    case SB_R_SPAWN:         return out_put(o, BR_SPAWN_LOOPER, NULL, 0);
    case SB_R_OK:            return out_put(o, BR_NOOP, NULL, 0);
    // ★ Гость ждёт 4-байтный cookie, протокол несёт 8-байтный.
    case SB_R_DEAD_BINDER: {
        binder_uintptr_t c = (binder_uintptr_t)*(uint64_t *)body;
        int r = out_put(o, BR_DEAD_BINDER, &c, sizeof c);
        /*
         * ★ С этой минуты поток занят: libbinder уйдёт в sendObituary(), а
         * оттуда — в гостевой binderDied, и вернётся только послав
         * BC_DEAD_BINDER_DONE. Ждать работу он до тех пор не может.
         */
        if (r == 0) { t->in_death++; t->tx_at_death = t->tx_total; }
        return r;
    }
    case SB_R_CLEAR_DEATH_DONE: {
        binder_uintptr_t c = (binder_uintptr_t)*(uint64_t *)body;
        return out_put(o, BR_CLEAR_DEATH_NOTIFICATION_DONE, &c, sizeof c);
    }
    case SB_R_ERROR:         return out_put(o, BR_ERROR, body, 4);
    case SB_R_ACK:
        // Демон обработал нашу транзакцию/ответ. Гостю отдавать нечего.
        if (t->acks > 0) t->acks--;
        return 0;
    case SB_R_REF: {
        struct sb_ptr_cookie *pc = (struct sb_ptr_cookie *)body;
        struct binder_ptr_cookie b = { .ptr = pc->ptr, .cookie = pc->cookie };
        uint32_t cmd = pc->op == SB_REF_INCREFS ? BR_INCREFS :
                       pc->op == SB_REF_ACQUIRE ? BR_ACQUIRE :
                       pc->op == SB_REF_RELEASE ? BR_RELEASE : BR_DECREFS;
        return out_put(o, cmd, &b, sizeof b);
    }
    case SB_R_TRANSACTION:
    case SB_R_REPLY: {
        struct sb_txn *m = (struct sb_txn *)body;
        uint8_t *data = body + sizeof *m;
        // ★ Гостю кладём смещения 4-байтными: [данные][смещения по 4].
        size_t noff = (size_t)m->offsets_size / 8;
        size_t osz_g = noff * sizeof(binder_size_t);
        size_t total = (size_t)m->data_size + osz_g;
        void *buf = buf_alloc(s, total);
        if (!buf) {
            bwarn("binder: приёмный буфер кончился (%zu байт)", total);
            return out_put(o, BR_FAILED_REPLY, NULL, 0);
        }
        /*
         * ★★★ Порядок первых транзакций процесса.
         *
         * Приложения падают в ОБРАБОТЧИКЕ исключения: NPE приходит на
         * ActivityThread.handleReceiver:2008 и handleCreateService:2187, а по
         * разбору framework.jar прошивки это `mInstrumentation.onException(...)`
         * внутри catch. mInstrumentation заполняется в handleBindApplication —
         * значит процесс получил RECEIVER или CREATE_SERVICE РАНЬШЕ, чем
         * BIND_APPLICATION.
         *
         * Настоящий драйвер такого не допускает: односторонние транзакции
         * лежат в очереди ПРОЦЕССА и разбираются по порядку. Печатаем первые
         * десять кодов на процесс — если BIND_APPLICATION (в 2.3 это код 12 у
         * IApplicationThread) приходит не первым, причина найдена.
         */
        /*
         * ★★★ Сторож пустой посылки.
         *
         * Приложения падают одинаково — NullPointerException в
         * ActivityThread.handleReceiver и handleCreateService, то есть у них
         * Intent или ServiceInfo оказались null. А null там берётся ровно из
         * одного места: Parcel.readInt() за концом данных возвращает НОЛЬ, и
         * `if (readInt() != 0)` перед CREATOR решает, что объекта нет.
         *
         * Значит до получателя дошла посылка без данных (или с нулями), хотя
         * отправитель заполнял её как обычно. Ловим это здесь: у настоящей
         * транзакции первые четыре байта — метка строгого режима, дальше
         * дескриптор интерфейса, нулей там не бывает.
         */
        /* ⚠️ Пустой ОТВЕТ — норма (в нём один int «исключения не было»), а вот
         * пустая ВХОДЯЩАЯ транзакция означала бы потерю данных. */
        /*
         * ⚠️ PING_TRANSACTION ('_PNG', «ты жив?») и INTERFACE_TRANSACTION
         * ('_NTF', «как тебя зовут?») данных не несут ВООБЩЕ — пустыми они
         * бывают по своей природе, а не по потере. Сторож кричал на них
         * сотнями строк и 14 сентября сбил разбор зависшей установки на ложный
         * след. (То же самое уже было записано в отчёте от 7 сентября,
         * раздел 10: «пустые транзакции — ложная тревога, это коды _PNG и
         * _NTF». Второй раз на те же грабли.) Молчим про оба.
         */
        if (h->type == SB_R_TRANSACTION && m->data_size < 8 &&
            m->code != 0x5f504e47u /* _PNG */ &&
            m->code != 0x5f4e5446u /* _NTF */) {
            bwarn("binder: приём — ПУСТАЯ транзакция (данные=%llu код=%u "
                  "флаги=0x%x узел=0x%llx)",
                  (unsigned long long)m->data_size, (unsigned)m->code,
                  (unsigned)m->flags, (unsigned long long)m->node_ptr);
        }
        /*
         * ★ ВРЕМЕННО: перепись всего, что гость реально получает.
         *
         * Разбираем «служба привязана, но не подключилась»: демон уверен, что
         * отдал `scheduleCreateService`, гость её не выполнил. Единственный
         * способ узнать, дошла ли она до `ActivityThread`, — записать КАЖДУЮ
         * входящую транзакцию с её кодом здесь, на последнем рубеже перед
         * гостем. Сорока штук на процесс хватает: всё интересное случается в
         * первые секунды его жизни.
         */
        if (h->type == SB_R_TRANSACTION) {
            static int seen, seen_app;
            int want = seen < SB_TRACE_N;
            char ifn0[48]; ifn0[0] = 0;
            if ((m->flags & TF_ONE_WAY) || want)
                txn_iface(data, m->data_size, ifn0, sizeof ifn0);
            if (!want && (m->flags & TF_ONE_WAY) &&
                !strcmp(ifn0, "IApplicationThread") && seen_app < 4000) {
                want = 1; seen_app++;
            } else if (want) seen++;
            if (want) {
                char ifn[48], ob[40];
                memcpy(ifn, ifn0, sizeof ifn);
                if (!ifn[0]) txn_iface(data, m->data_size, ifn, sizeof ifn);
                char sn[42];
                txn_obj0(data, m->data_size, data + m->data_size, noff, ob, sizeof ob);
                txn_sniff(data, m->data_size, sn, sizeof sn);
                bwarn("binder: ГОСТЮ  %-22s код=%-4u %s данные=%llu%s %s",
                      ifn[0] ? ifn : "?", (unsigned)m->code,
                      (m->flags & TF_ONE_WAY) ? "одност" : "  ждёт",
                      (unsigned long long)m->data_size, ob, sn);
            }
        }
        // ★ Односторонняя пошла гостю — в начале следующего ioctl отчитаемся.
        if (m->flags & TF_ONE_WAY) t->async_pending = 1;
        memcpy(buf, data, (size_t)m->data_size);
        if (noff) {
            const uint64_t *wo = (const uint64_t *)(data + m->data_size);
            binder_size_t *go = (binder_size_t *)((uint8_t *)buf + m->data_size);
            for (size_t i = 0; i < noff; i++) go[i] = (binder_size_t)wo[i];
        }
        buf_note(s, buf, (uint32_t)m->data_size, (uint32_t)osz_g);
        /*
         * Описатели: демон записал в объекты их НОМЕРА в посылке, ставим свои.
         *
         * ★★★★★ ХОДИМ ПО ОБЪЕКТАМ ВСЕГДА, ДАЖЕ КОГДА ОПИСАТЕЛЕЙ НЕ ПРИШЛО.
         *
         * ⚠️ Раньше при `nfds == 0` весь обход пропускался — и в объекте
         * оставался НОМЕР ПО ПОРЯДКУ, то есть чаще всего ноль. Гость принимал
         * его за описатель, потому что «нет описателя» в Android — это −1, а
         * ноль совершенно законен. Дальше расходилось на две беды, и обе
         * выглядели как «система работает, картинка замерла»:
         *
         *   • буфер слоя: `eglCreateImageKHR` пытался отобразить fd 0, получал
         *     EBADF, отдавал ноль — и очередь буферов окна вставала навсегда
         *     («acquireBuffer: max acquired buffer count reached»);
         *   • заслонка кадра (Fence): `fence->isValid()` для нуля отвечает
         *     «да», `dup(0)` отдаёт EBADF, и `dequeueBuffer` ВОЗВРАЩАЕТ ОШИБКУ
         *     — приложению не из чего рисовать:
         *         E SurfaceTextureClient dequeueBuffer: error duping fence: 9
         *
         * Теперь несопоставленному объекту ставим −1. Это не уловка: −1 и
         * значит «описателя нет», и весь framework так его и разбирает —
         * заслонка становится «без заслонки», буфер честно не открывается.
         */
        if (noff) {
            binder_size_t *offs = (binder_size_t *)((uint8_t *)buf + m->data_size);
            for (uint64_t i = 0; i < noff; i++) {
                // Та же проверка, что и на отправке: без неё битое смещение
                // не только читает, но и ПИШЕТ мимо буфера (fo->handle).
                if (!obj_off_ok(offs[i], (size_t)m->data_size)) {
                    bwarn("binder: приём — смещение объекта №%llu = 0x%llx вне данных "
                         "(данные=%llu смещений=%llu код=%u)",
                         (unsigned long long)i, (unsigned long long)offs[i],
                         (unsigned long long)m->data_size,
                         (unsigned long long)m->offsets_size, (unsigned)m->code);
                    break;
                }
                struct flat_binder_object *fo =
                    (struct flat_binder_object *)((uint8_t *)buf + offs[i]);
                if (fo->type != BINDER_TYPE_FD) continue;
                /*
                 * ⚠️ Сравнение БЕЗ знака и с двух сторон. Прежняя проверка
                 * `(int)fo->handle < nfds` пропускала любое большое значение:
                 * приведённое к int, оно становится отрицательным, а
                 * отрицательное меньше nfds. Дальше `fds[отрицательный]` читает
                 * мимо массива на стеке — и гость получает мусорный описатель
                 * либо мы читаем чужую память.
                 */
                if (fo->handle < (uint32_t)nfds) fo->handle = (uint32_t)fds[fo->handle];
                else {
                    static unsigned lost;
                    if (lost < 8 || (lost & 1023) == 0)
                        bwarn("binder: приём — описатель №%u вне пришедших (%d) — ставлю −1 "
                              "(всего %u; тип сообщения %u, код %u)",
                              (unsigned)fo->handle, nfds, lost + 1,
                              (unsigned)h->type, (unsigned)m->code);
                    lost++;
                    fo->handle = (uint32_t)-1;
                }
            }
        }
        struct binder_transaction_data tr;
        memset(&tr, 0, sizeof tr);
        tr.target.ptr = (h->type == SB_R_TRANSACTION) ? m->node_ptr : 0;
        tr.cookie = (h->type == SB_R_TRANSACTION) ? m->node_cookie : 0;
        tr.code = m->code;
        tr.flags = m->flags;
        tr.sender_pid = (pid_t)m->sender_pid;
        tr.sender_euid = (uid_t)m->sender_euid;
        tr.data_size = (binder_size_t)m->data_size;
        tr.offsets_size = (binder_size_t)osz_g;
        // ★ Гостю отдаём ГОСТЕВЫЕ адреса.
        tr.data.ptr.buffer = h2g(buf);
        tr.data.ptr.offsets = h2g((uint8_t *)buf + m->data_size);
        uint32_t cmd = (h->type == SB_R_TRANSACTION) ? BR_TRANSACTION : BR_REPLY;
        if (out_put(o, cmd, &tr, sizeof tr) < 0) { buf_free(s, (uint64_t)(uintptr_t)buf); return -1; }
        /*
         * ★ Отмечаем, что поток ВОШЁЛ в чужую транзакцию: пока он её не
         * закончил (не вернул буфер через BC_FREE_BUFFER), он заведомо не
         * «свободный поток пула». Держим именно адреса буферов, а не счётчик:
         * транзакции вкладываются друг в друга, и закрываются они не в том
         * порядке, в каком пришли.
         */
        if (cmd == BR_TRANSACTION) {
            if (t->in_txn < (int)(sizeof t->inbuf / sizeof t->inbuf[0])) {
                t->incode[t->in_txn] = m->code;
                t->inbuf[t->in_txn++] = (uint64_t)(uintptr_t)buf;
            }
            if (guest_trace_on()) {
                char ifn[48];
                txn_iface(data, m->data_size, ifn, sizeof ifn);
                if (m->flags & TF_ONE_WAY)
                    guest_trace_mark('N', "binder< %s#%u 1", ifn[0] ? ifn : "?",
                                     (unsigned)m->code);
                else tr_begin(t, 'i', ifn, m->code);
            }
        } else {
            if (t->pending_sync > 0)
                t->pending_sync--;     // пришёл ответ на наш двусторонний вызов
            tr_end(t, 'o');
        }
        return 0;
    }
    default:
        bwarn("binder: непонятное сообщение демона %u", h->type);
        return 0;
    }
}

/*
 * Как drecv, но с потолком ожидания и с приметами в журнале.
 *
 * Зачем: ждать подтверждения демона МОЖНО только ограниченное время. Настоящий
 * драйвер отдаёт BR_TRANSACTION_COMPLETE, не выходя из ioctl, и отправитель не
 * зависит ни от кого. У нас же подтверждение идёт по сокету, и если оно
 * потеряется, гостевой поток встаёт в recvmsg НАВСЕГДА. Поймано на телефоне
 * 2026-09-04: system_server, поток Binder_3, односторонняя scheduleTrimMemory,
 * замок ActivityManagerService зажат — и вся система замерла на экране
 * ленты рабочего стола, при том что все 53 процесса живы.
 *
 * Возврат: -2 — время вышло и ничего не прочитано.
 */
static int drecv_to(struct thr *t, uint8_t **bufp, size_t cap, int *fds, int *nfds,
                    int total_ms, const char *what)
{
    int left = total_ms;
    while (left > 0) {
        struct pollfd pf = { .fd = t->fd, .events = POLLIN };
        int step = left > 5000 ? 5000 : left;
        int pr;
        do { pr = poll(&pf, 1, step); } while (pr < 0 && errno == EINTR);
        if (pr < 0) return -1;
        if (pr > 0) return drecv(t, bufp, cap, fds, nfds);
        left -= step;
        glog("binder: ★ %s — тишина от демона %d с (ждём подтверждений %d, "
             "долг гостю %d, отказов %d, последняя посылка код=%u флаги=0x%x цель=%u)",
             what, (total_ms - left) / 1000, t->acks, t->completes, t->failed,
             t->last_code, t->last_flags, t->last_handle);
    }
    return -2;
}

// ------------------------------------------- разбор команд BC_* от гостя

// Возвращает 0. Ошибки логируются: падать нельзя, гость от этого умрёт молча.
/*
 * ★★★★★ Возвращает, СКОЛЬКО БАЙТ командного буфера разобрано.
 *
 * Раньше возвращала void, а вызывающий безусловно писал
 * `bwr->write_consumed = bwr->write_size` — «разобрали всё». Любой ранний
 * выход отсюда (усечённая команда, незнакомый код BC) при этом означал, что
 * ОСТАТОК БУФЕРА ПРОПАДАЛ молча: libbinder по write_consumed чистит mOut
 * целиком и больше эти команды не пришлёт. Если в остатке была
 * BC_TRANSACTION, отправитель об этом не узнает НИКОГДА — для односторонней
 * посылки вызов «удался».
 */
static size_t bc_process(struct thr *t, struct sess *s, const uint8_t *w, size_t wlen) {
    size_t off = 0;
    while (off + 4 <= wlen) {
        uint32_t cmd;
        memcpy(&cmd, w + off, 4);
        off += 4;
        switch (cmd) {
        case BC_TRANSACTION:
        case BC_REPLY: {
            if (off + sizeof(struct binder_transaction_data) > wlen) return off - 4;
            const struct binder_transaction_data *tr =
                (const struct binder_transaction_data *)(w + off);
            off += sizeof *tr;
            size_t dsz = (size_t)tr->data_size;
            // ★ У 32-битного гостя элемент массива смещений 4 байта, а протокол
            // демона несёт 8-байтные: пересчитываем на границе.
            size_t noff = (size_t)tr->offsets_size / sizeof(binder_size_t);
            size_t osz = noff * 8;
            uint32_t blen = (uint32_t)(sizeof(struct sb_txn) + dsz + osz);
            uint8_t *b = (uint8_t *)malloc(blen);
            if (!b) return off - 4;
            struct sb_txn *m = (struct sb_txn *)b;
            memset(m, 0, sizeof *m);
            m->handle = tr->target.handle;
            m->code = tr->code;
            m->flags = tr->flags;
            m->data_size = dsz;
            m->offsets_size = osz;
            // ★★★ Гостевые диапазоны ПРОВЕРЯЕМ, а не разыменовываем на веру.
            //
            // Прежде здесь стоял memcpy прямо по g2h_untagged. Стоило гостю
            // прислать посылку с указателем на неотображённую страницу — и
            // падал не гость, а САМ qemu, в своём же коде:
            //
            //   qemu-arm: QEMU internal SIGSEGV {code=ACCERR, addr=0x46981008}
            //   D Zygote  Process 4274 terminated by signal (11)
            //   I Zygote  Exit zygote because system server (4274) has terminated
            //
            // — то есть через пару минут после загрузки умирал system_server, а
            // с ним вся система. Место нашлось только по адресу сбоя: memcpy,
            // вызванный из bc_process, источник 0x46885008 длиной 0x41bb4, у
            // страницы флаги 0 (не отображена).
            //
            // Настоящий драйвер так себя не ведёт: binder_transaction() делает
            // copy_from_user и на отказе идёт в err_copy_data_failed, отвечая
            // отправителю BR_FAILED_REPLY. Делаем ровно это.
            binder_size_t *rawoff = NULL;
            int ok = guest_read(b + sizeof *m, (abi_ulong)tr->data.ptr.buffer, dsz);
            if (ok && noff) {
                rawoff = (binder_size_t *)malloc(noff * sizeof(binder_size_t));
                ok = rawoff && guest_read(rawoff, (abi_ulong)tr->data.ptr.offsets,
                                          noff * sizeof(binder_size_t));
            }
            if (!ok) {
                const uint8_t *pool = s ? s->map : NULL;
                const uint8_t *dbuf = (const uint8_t *)g2h_untagged(tr->data.ptr.buffer);
                bwarn("binder: посылка с НЕДОСТУПНОЙ памятью гостя — отказ "
                     "(цель=%u код=%u данные=0x%llx+%zu смещений=%zu)%s",
                     (unsigned)tr->target.handle, (unsigned)tr->code,
                     (unsigned long long)tr->data.ptr.buffer, dsz, noff,
                     (pool && dbuf >= pool && dbuf < pool + s->map_size)
                         ? " ДАННЫЕ В НАШЕМ ПУЛЕ" : "");
                free(rawoff);
                free(b);
                // Подтверждения приёма НЕ выдаём: драйвер на этом пути
                // освобождает tcomplete и отдаёт только отказ.
                t->failed++;
                break;
            }
            if (noff) {
                uint64_t *wo = (uint64_t *)(b + sizeof *m + dsz);
                for (size_t i = 0; i < noff; i++) wo[i] = rawoff[i];
                free(rawoff);
            }
            /*
             * ★★★★★ ПРОБА «ОТВЕТ-УКАЗАТЕЛЬ» НА СТОРОНЕ ОТПРАВИТЕЛЯ.
             *
             * Зачем. Игра умирает на `Unknown exception code: N`, где N —
             * гостевой указатель: там, где writeNoException обязан положить
             * ноль, лежит чужое слово. Демон показал, что получает мусор уже
             * ГОТОВЫМ, — значит беда до него. Здесь развилка из двух:
             *   • адрес данных лежит В НАШЕМ ПУЛЕ — libbinder отдал в ответ
             *     буфер ВХОДЯЩЕЙ транзакции (или мы его переиспользовали);
             *   • адрес в куче гостя — libbinder отдал не тот Parcel либо
             *     Parcel уже освобождён (тогда первое слово — звено списка
             *     свободных блоков dlmalloc).
             * Различить можно только тут, у источника.
             */
            /* ⚠️ Только ЧЕТЫРЕ байта и без объектов: ответ с объектом (16 байт,
             * первое слово 0x73622a85 — метка вида) законен, и на нём потолок
             * печати выгорал бы впустую. Та же грабля, что у ловушки в демоне. */
            if (cmd == BC_REPLY && dsz == 4 && noff == 0) {
                uint32_t w0 = 0, w1 = 0;
                memcpy(&w0, b + sizeof *m, 4);
                if (dsz >= 8) memcpy(&w1, b + sizeof *m + 4, 4);
                static int said_rp;
                if (w0 >= 0x00010000u && w0 < 0xc0000000u && said_rp < 60) {
                    said_rp++;
                    const uint8_t *pool = s ? s->map : NULL;
                    const uint8_t *dbuf = (const uint8_t *)g2h_untagged(tr->data.ptr.buffer);
                    int in_pool = pool && dbuf >= pool && dbuf < pool + s->map_size;
                    /* Читаем те же байты ВТОРОЙ раз: если значение изменилось,
                     * память под нами переписывают прямо сейчас. */
                    uint32_t again = 0;
                    (void)guest_read(&again, (abi_ulong)tr->data.ptr.buffer, 4);
                    bwarn("binder: ★★★ ОТВЕЧАЕМ УКАЗАТЕЛЕМ 0x%08x (следом 0x%08x, "
                          "повторное чтение 0x%08x): данные=%zu флаги=0x%x "
                          "адрес=0x%llx%s | отвечаем на код=%u, входящих в работе %d, "
                          "своих вызовов без ответа %d, посылок за жизнь %d",
                          (unsigned)w0, (unsigned)w1, (unsigned)again, dsz,
                          (unsigned)tr->flags,
                          (unsigned long long)tr->data.ptr.buffer,
                          in_pool ? " ★В НАШЕМ ПУЛЕ★" : " (куча гостя)",
                          t->in_txn > 0 ? (unsigned)t->incode[t->in_txn - 1] : 0u,
                          t->in_txn, t->pending_sync, t->tx_total);
                }
            }
            // Описатели вынимаем из объектов и отправляем через SCM_RIGHTS.
            int fds[8]; int nfds = 0;
            if (osz) {
                uint64_t *offs = (uint64_t *)(b + sizeof *m + dsz);
                for (uint64_t i = 0; i < noff && nfds < 8; i++) {
                    // ⚠️ Смещение обязано быть проверено ДО разыменования.
                    // Настоящий драйвер делает ровно это в binder_transaction():
                    // объект целиком внутри данных и выровнен, иначе
                    // BR_FAILED_REPLY. Без проверки битое смещение убивало не
                    // «того, кто прислал», а САМ ГОСТЕВОЙ ПРОЦЕСС: SIGSEGV
                    // прямо здесь, в шиме. Измерено 2026-08-26: так умирал
                    // system_server через ~1,5 минуты после systemReady.
                    if (!obj_off_ok(offs[i], dsz)) {
                        bad_offsets(s, "отправка", tr, b, dsz, osz, i);
                        break;
                    }
                    struct flat_binder_object *fo =
                        (struct flat_binder_object *)(b + sizeof *m + offs[i]);
                    if (fo->type == BINDER_TYPE_FD) fds[nfds++] = (int)fo->handle;
                }
            }
            /*
             * ★ Вторая половина переписи: что гость ОТПРАВЛЯЕТ. Без неё нельзя
             * отличить «приложение не ответило» от «ответ потерялся по дороге»:
             * односторонний serviceDoneExecuting приложение → AMS ни следа в
             * журнале не оставляет ни при какой беде.
             */
            char ifn[48]; ifn[0] = 0;
            int oneway = (tr->flags & TF_ONE_WAY) != 0;
            int traced = guest_trace_on();
            if (cmd == BC_TRANSACTION) {
                static int seen_tx, seen_app;
                int want = seen_tx < SB_TRACE_N;
                /*
                 * ★ Дескриптор разбираем только у односторонних и у первых
                 * шестидесяти четырёх — на горячем пути system_server иначе
                 * заплатим за каждую из тысяч транзакций в секунду.
                 */
                if (oneway || want || traced) txn_iface(b + sizeof *m, dsz, ifn, sizeof ifn);
                /*
                 * ★★★ Односторонние к IApplicationThread пишем ВСЕГДА (до
                 * потолка): это и есть жизнь службы — scheduleCreateService,
                 * scheduleBindService, scheduleServiceArgs. У system_server
                 * общий потолок в 64 строки выгорает за первые миллисекунды,
                 * и ровно эти строки в трассу не попадали.
                 */
                if (!want && oneway && !strcmp(ifn, "IApplicationThread") &&
                    seen_app < 4000) { want = 1; seen_app++; }
                else if (want) seen_tx++;
                if (want) {
                    char ob[40], sn[42];
                    txn_obj0(b + sizeof *m, dsz, b + sizeof *m + dsz, noff, ob, sizeof ob);
                    txn_sniff(b + sizeof *m, dsz, sn, sizeof sn);
                    bwarn("binder: ОТ ГОСТЯ %-22s код=%-4u %s данные=%llu%s %s",
                          ifn[0] ? ifn : "?", (unsigned)tr->code,
                          oneway ? "одност" : "  ждёт",
                          (unsigned long long)dsz, ob, sn);
                }
            }
            /*
             * ★★★★★ ОТПРАВКУ ПРОВЕРЯЕМ.
             *
             * Здесь результат dsend не смотрели вовсе: гость получал наше
             * BR_TRANSACTION_COMPLETE и считал, что всё прошло. Для
             * ОДНОСТОРОННЕЙ транзакции это значит, что вызов «удался» при
             * полностью потерянной посылке — и никто, нигде, никогда об этом
             * не узнает. Наружу это выглядит как служба, которой
             * ActivityManagerService выставил requested=true, а приложение
             * привязку не получило: `received=false`, `executeNesting` висит
             * вечно, ANR не срабатывает, в журнале гостя ни строчки. Так
             * пропадают обои.
             */
            if (dsend(t, cmd == BC_TRANSACTION ? SB_TRANSACT : SB_REPLY,
                      b, blen, fds, nfds) < 0) {
                t->lost++;
                /*
                 * ⚠️★ ЖАЛУЕМСЯ НЕ КАЖДЫЙ РАЗ. Порванная связь рвётся не на одну
                 * посылку: гость шлёт дальше, и каждая попытка писала строку.
                 * Измерено на живой прошивке — 768 МБ в минуту, 2,8 гигабайта
                 * за четыре минуты. Журнал, который может съесть диск
                 * человека, — это уже не журнал.
                 */
                if (t->lost <= 8 || (t->lost % 4096) == 0)
                    bwarn("binder: ★★★ ПОСЫЛКА НЕ УШЛА К ДЕМОНУ: %s код=%u %s данные=%zu "
                          "(fd=%d, ошибка «%s»); потеряно посылок %u",
                          ifn[0] ? ifn : "?", (unsigned)tr->code,
                          oneway ? "односторонняя" : "ждёт ответа", dsz,
                          t->fd, strerror(errno), t->lost);
                /*
                 * ★★★★★ И ГОВОРИМ ОБ ЭТОМ ОТПРАВИТЕЛЮ.
                 *
                 * Здесь стояло «отправитель об этом НЕ УЗНАЕТ» — и это была не
                 * оговорка, а поведение: посылка терялась, а поток, ждущий
                 * ответа, оставался ждать ЕГО НАВСЕГДА. Снаружи это выглядит
                 * как замерший экран при живой системе: измерено на второй
                 * прошивке — композитор спит в `unix_stream_read_generic`,
                 * вывод прошивки идёт, кадров нет ни одного.
                 *
                 * Настоящий драйвер так себя не ведёт: недоставленная
                 * транзакция уходит в `err_*`, и отправитель получает
                 * BR_FAILED_REPLY. Делаем ровно это — тем же счётчиком, каким
                 * уже отвечаем на недоступную память гостя. Подтверждения
                 * приёма при этом НЕ выдаём: драйвер на пути отказа
                 * освобождает tcomplete и отдаёт только отказ.
                 *
                 * ⚠️ Односторонней посылке ответа не положено, и ждать его
                 * никто не будет, — но отказ ей и не повредит: libbinder
                 * читает его как FAILED_TRANSACTION и идёт дальше. Разделять
                 * два случая значило бы завести путь, который никто не
                 * проверит.
                 */
                free(b);
                t->failed++;
                break;
            }
            t->acks++;
            t->sent++;
            t->tx_total++;
            if (cmd == BC_TRANSACTION && !(tr->flags & TF_ONE_WAY)) t->pending_sync++;
            t->last_code = tr->code;
            t->last_flags = tr->flags;
            t->last_handle = tr->target.handle;
            free(b);
            /* ★ Трасса: свой вызов с ответом — отметка до ответа (закроет
             * BR_REPLY), односторонний — мгновение, ответ на чужой — конец.
             * ⚠️ Снимаем со стека ВСЕГДА, а пишем — только при включённой
             * трассе: иначе выключенная посреди вызова трасса оставила бы
             * отметку висеть, и следующий ответ закрыл бы ею чужую. */
            if (cmd == BC_REPLY) tr_end(t, 'i');
            else if (traced) {
                if (oneway) guest_trace_mark('N', "binder> %s#%u 1",
                                             ifn[0] ? ifn : "?", (unsigned)tr->code);
                else tr_begin(t, 'o', ifn, tr->code);
            }
            /*
             * Ядро отвечает BR_TRANSACTION_COMPLETE сразу на приём команды.
             * Выдаём его САМИ: если бы это делал демон, подтверждение обгоняло
             * бы наш SB_WAIT и ломало учёт «поток ждёт» на его стороне.
             *
             * ⚠️★★★★★ НО ТОЛЬКО ЕСЛИ ГОСТЬ В ЭТОМ ЖЕ ЗАХОДЕ ЧИТАЕТ.
             *
             * `IPCThreadState::transact` всегда посылает и читает одним
             * `ioctl` (`talkWithDriver(doReceive=true)`), и подтверждение
             * уходит тем же вызовом — как у настоящего драйвера. А вот
             * `flushCommands()` шлёт буфер команд БЕЗ чтения
             * (`talkWithDriver(false)`): такую посылку никто не ждёт, и
             * начисленное на неё подтверждение останется у нас на руках.
             * Оно уедет со следующим чтением — а это чтение уже из пул-цикла,
             * где `executeCommand` такой команды не знает:
             *
             *   *** BAD COMMAND 29190 received from Binder driver
             *   getAndExecuteCommand(fd=41) returned unexpected error
             *   -2147483648, aborting
             *
             * (0x7206 = BR_TRANSACTION_COMPLETE, −2147483648 = UNKNOWN_ERROR)
             * — то есть `abort()` и смерть процесса. 22.09 так умирала зигота
             * и с ней вся система через несколько минут работы.
             *
             * ⚠️ Гасить отставшие подтверждения ПОЗЖЕ нельзя: замер показал
             * 9373 отставших за одну загрузку — это норма (подтверждение
             * законно уезжает следующим чтением того же `waitForResponse`), и
             * гашение ломает картинку. Отличается только случай «послал и не
             * читает» — вот его и не начисляем.
             */
            if (t->will_read) t->completes++;
            else {
                t->cpl_orphan++;
                if (t->cpl_orphan <= 8 || (t->cpl_orphan % 100) == 0)
                    bwarn("binder: посылка БЕЗ чтения (код=%u флаги=0x%x цель=%u) — "
                          "подтверждение не начисляю, его никто не ждёт "
                          "(всего таких %d)",
                          tr->code, tr->flags, tr->target.handle, t->cpl_orphan);
            }
            break;
        }
        case BC_FREE_BUFFER: {
            // ★ Указатель гостя 4-байтный; дальше работаем ХОЗЯЙСКИМ адресом,
            // потому что распределитель буферов считает смещения от s->map.
            if (off + 4 > wlen) return off - 4;
            uint32_t gaddr;
            memcpy(&gaddr, w + off, 4);
            off += 4;
            uint64_t addr = (uint64_t)(uintptr_t)g2h_untagged(gaddr);
            // ★★★ Отдать ссылки, которые демон завёл на объекты этой посылки.
            //
            // Настоящий драйвер при освобождении буфера проходит по его
            // объектам и снимает ровно те ссылки, что добавил при переводе
            // (binder_transaction_buffer_release). У нас этого не было вовсе:
            // demon наращивал strong за каждый переведённый объект, а обратно
            // не снимал никогда — счётчик ссылки не доходил до нуля, и слот
            // жил до смерти процесса. Измерено 2026-08-27: у system_server
            // 1980 ссылок, из них 1306 на уже умершие узлы, и +340 ссылок в
            // минуту БЕЗ участия человека. Пул из 32768 кончался за полтора
            // часа, после чего ref_get отдавал NULL, ссылку на servicemanager
            // (handle 0) новому процессу выдать было нечем, и КАЖДОЕ
            // запускаемое приложение падало сразу:
            //   NPE: IActivityManager.attachApplication на null объекте
            //     at android.app.ActivityThread.attach(ActivityThread.java:6304)
            // а у system_server сыпались FAILED BINDER TRANSACTION.
            // ⚠️ Выключатель для проверки: GUEST_NO_FREEBUF=1 возвращает прежнее
            // поведение (ссылки от буферов не снимаются вовсе). Нужен, чтобы
            // отделять последствия этой правки от чужих поломок, не пересобирая
            // дерево туда-обратно.
            // ⚠️ Имя не «off»: в доноре эта статическая переменная затеняла
            // счётчик разбора команд с тем же именем — работало, но читалось
            // как ошибка.
            static int nofree = -1;
            if (nofree < 0) { const char *e = getenv("GUEST_NO_FREEBUF"); nofree = (e && *e == '1'); }
            uint32_t dsz = 0, osz = 0;
            if (!nofree && buf_take(s, addr, &dsz, &osz) && osz >= sizeof(binder_size_t)) {
                const uint8_t *base = (const uint8_t *)(uintptr_t)addr;
                // Смещения в гостевом буфере лежат 4-байтными: мы сами их такими
                // и положили при приёме.
                const binder_size_t *offs = (const binder_size_t *)(base + dsz);
                for (uint64_t i = 0; i < osz / sizeof(binder_size_t); i++) {
                    if (!obj_off_ok(offs[i], (size_t)dsz)) break;
                    const struct flat_binder_object *fo =
                        (const struct flat_binder_object *)(base + offs[i]);
                    if (fo->type != BINDER_TYPE_HANDLE && fo->type != BINDER_TYPE_WEAK_HANDLE)
                        continue;   // свой объект вернулся домой — ссылки не заводилось
                    struct sb_ref r = { .op = (fo->type == BINDER_TYPE_HANDLE)
                                                ? SB_REF_RELEASE_BUF : SB_REF_DECREFS_BUF,
                                         .handle = fo->handle };
                    dsend(t, SB_REF, &r, sizeof r, NULL, 0);
                }
            }
            /* ★ Чужая транзакция закончена — см. пометку в msg_to_br. */
            for (int k = 0; k < t->in_txn; k++) {
                if (t->inbuf[k] != addr) continue;
                for (int j = k + 1; j < t->in_txn; j++) {
                    t->inbuf[j - 1] = t->inbuf[j];
                    t->incode[j - 1] = t->incode[j];   /* ★ коды едут вместе с адресами */
                }
                t->in_txn--;
                break;
            }
            buf_free(s, addr);
            break;
        }
        case BC_INCREFS: case BC_ACQUIRE: case BC_RELEASE: case BC_DECREFS: {
            if (off + 4 > wlen) return off - 4;
            struct sb_ref r;
            memcpy(&r.handle, w + off, 4);
            off += 4;
            r.op = cmd == BC_INCREFS ? SB_REF_INCREFS : cmd == BC_ACQUIRE ? SB_REF_ACQUIRE :
                   cmd == BC_RELEASE ? SB_REF_RELEASE : SB_REF_DECREFS;
            dsend(t, SB_REF, &r, sizeof r, NULL, 0);
            break;
        }
        case BC_INCREFS_DONE: case BC_ACQUIRE_DONE: {
            if (off + sizeof(struct binder_ptr_cookie) > wlen) return off - 4;
            struct binder_ptr_cookie done;
            memcpy(&done, w + off, sizeof done);
            off += sizeof done;
            /*
             * ★★★ Р-71: подтверждение захвата ИДЁТ К ДЕМОНУ. Раньше его
             * выбрасывали («демону это не нужно») — и демон отпускал объект
             * владельцу (BR_RELEASE/BR_DECREFS), не дожидаясь, пока владелец
             * исполнит свой BR_ACQUIRE: пул-поток удалял объект раньше, чем
             * главный делал incStrong, и главный падал по освобождённой памяти.
             * У настоящего драйвера отпускание ждёт BC_ACQUIRE_DONE/
             * BC_INCREFS_DONE; ворота узла в демоне (binderd_refs.h) — то же.
             *
             * ptr расширяем нулями до 64 бит — так же, как демон получил
             * node->ptr из flat_binder_object (там 32-битное поле копируется в
             * uint64_t) и как SB_R_REF несёт его обратно: иначе узел по
             * подтверждению не найдётся и отложенное отпускание не уйдёт никогда.
             */
            struct sb_ptr_cookie pc = {
                .op = cmd == BC_INCREFS_DONE ? SB_REF_INCREFS : SB_REF_ACQUIRE,
                .ptr = (uint64_t)done.ptr,
                .cookie = (uint64_t)done.cookie,
            };
            dsend(t, SB_REF_DONE, &pc, sizeof pc, NULL, 0);
            break;
        }
        case BC_REGISTER_LOOPER: case BC_ENTER_LOOPER: case BC_EXIT_LOOPER: {
            uint32_t op = cmd == BC_REGISTER_LOOPER ? 0 : cmd == BC_ENTER_LOOPER ? 1 : 2;
            t->looper = (op != 2);
            dsend(t, SB_LOOPER, &op, sizeof op, NULL, 0);
            break;
        }
        case BC_REQUEST_DEATH_NOTIFICATION: case BC_CLEAR_DEATH_NOTIFICATION: {
            if (off + sizeof(struct binder_handle_cookie) > wlen) return off - 4;
            const struct binder_handle_cookie *hc =
                (const struct binder_handle_cookie *)(w + off);
            off += sizeof *hc;
            struct sb_death d = { .op = (cmd == BC_REQUEST_DEATH_NOTIFICATION) ? 0u : 1u,
                                   .handle = hc->handle, .cookie = hc->cookie };
            dsend(t, SB_DEATH, &d, sizeof d, NULL, 0);
            break;
        }
        case BC_DEAD_BINDER_DONE: {
            if (off + sizeof(binder_uintptr_t) > wlen) return off - 4;
            off += sizeof(binder_uintptr_t);
            /* Извещение отработано — поток снова волен ждать работу. */
            if (t->in_death > 0) t->in_death--;
            /* ★ И заодно: этот процесс извещения ЗАКРЫВАЕТ, значит счётчику
             * у него можно верить (см. поле closes_death). */
            if (s) s->closes_death = 1;
            break;
        }
        default:
            glog("binder: команда BC 0x%x не поддержана", cmd);
            return off - 4;
        }
    }
    return off;
}

// --------------------------------------------------------- сам ioctl

// Привести байт-будильник в соответствие с состоянием очереди у демона.
static void wake_sync(struct sess *s, int more) {
    // ⚠️ Слив ТОЛЬКО через MSG_DONTWAIT, без переключения O_NONBLOCK у самого
    // описателя.
    //
    // Раньше здесь было: снять флаги, добавить O_NONBLOCK, слить в цикле,
    // вернуть флаги обратно. Описатель s->fd_guest — ОДИН НА ВЕСЬ ПРОЦЕСС, и
    // в ioctl сюда заходят разные потоки. Стоило двум оказаться тут разом, как
    // второй возвращал блокирующий режим, пока первый ещё крутил цикл, — и
    // тот навсегда вис в read() на пустом сокете.
    //
    // Снаружи это выглядело как «binder молчит»: гостевой поток стоит в
    // read(fd, …, 64) (ровно sizeof junk), демон при этом спокойно спит без
    // работы, а транзакция, за которой поток приходил, давно отвечена. Ловилось
    // это неделями и списывалось то на vsync, то на потерянный ответ. Измерено
    // на телефоне 2026-08-26: так вис createDisplayEventConnection у
    // android.display, setMasterMute у AudioService и checkService у
    // EventThread — каждый раз в разном месте, потому что это гонка.
    //
    // MSG_DONTWAIT действует на один вызов и общего состояния не трогает.
    char junk[64];
    int had = 0;
    while (recv(s->fd_guest, junk, sizeof junk, MSG_DONTWAIT) > 0) had = 1;
    (void)had;
    if (more) { char one = 'w'; (void)!write(s->fd_wake, &one, 1); }
}

static int msg_to_br(struct thr *t, struct sess *s, uint8_t *msg, int *fds, int nfds,
                    struct outbuf *o);

static void dq_push(struct thr *t, const uint8_t *msg, size_t n) {
    struct qmsg *q = (struct qmsg *)malloc(sizeof *q + n);
    if (!q) { glog("binder: нет памяти под отложенное сообщение (%zu байт)", n); return; }
    q->next = NULL; q->n = n;
    memcpy(q->buf, msg, n);
    if (!t->dq_tail) t->dq_tail = &t->dq;
    *t->dq_tail = q;
    t->dq_tail = &q->next;
}

// Отдать отложенное гостю. Останавливаемся на первом, что не влезло в буфер, —
// порядок сообщений менять нельзя.
static void dq_flush(struct thr *t, struct sess *s, struct outbuf *o) {
    /*
     * ★ Сперва ничейное: его оставил ушедший поток, и ждёт оно дольше всех.
     * Порядок «кто раньше положен» для односторонних посылок важен — приложение
     * падает, если `scheduleReceiver` обгонит `bindApplication`.
     */
    if (s) {
        pthread_mutex_lock(&s->lock);
        while (s->dq) {
            struct qmsg *q = s->dq;
            int fds0[8], nfds0 = 0;
            if (msg_to_br(t, s, q->buf, fds0, nfds0, o) < 0) break;  // не влезло — в другой раз
            s->dq = q->next;
            if (!s->dq) s->dq_tail = &s->dq;
            free(q);
        }
        pthread_mutex_unlock(&s->lock);
    }
    while (t->dq) {
        struct qmsg *q = t->dq;
        int fds[8], nfds = 0;
        if (msg_to_br(t, s, q->buf, fds, nfds, o) < 0) return;   // не влезло — ждёт дальше
        t->dq = q->next;
        if (!t->dq) t->dq_tail = &t->dq;
        free(q);
    }
}

static void dq_drop(struct thr *t) {
    /*
     * ⚠️ Зовётся ТОЛЬКО после ветвления: у ребёнка это копия отложенного
     * родителя, и отдавать её некому — работа адресована родителю, он её и
     * получит. Потери здесь нет. Настоящая потеря была при уходе потока — она
     * закрыта перекладкой в очередь процесса, см. thr_free.
     */
    while (t->dq) { struct qmsg *q = t->dq; t->dq = q->next; free(q); }
    t->dq_tail = &t->dq;
}

/*
 * ★★★★★ МОЖЕТ ЛИ ЭТОТ ПОТОК ЗАКОННО ЖДАТЬ РАБОТУ.
 *
 * Зачем это вообще. В конце binder_write_read есть ожидание работы БЕЗ
 * ПОТОЛКА — и оно правильное: свободный поток пула обязан стоять в ioctl,
 * пока ему не дадут транзакцию, так делает и настоящий драйвер. Беда в том,
 * что ровно так же выглядит поток, застрявший ВНУТРИ transact(): libbinder в
 * waitForResponse ждёт BR_TRANSACTION_COMPLETE тем же самым чтением. Если
 * подтверждение где-то потерялось, поток стоит навсегда, и отличить его от
 * свободного по одному лишь буферу чтения невозможно.
 *
 * Чем это кончается. 15 сентября стенд встал чёрным экраном: system_server,
 * поток Binder_4, ОДНОСТОРОННЯЯ ApplicationThreadProxy.setProcessState из
 * applyOomAdjLocked — то есть с зажатым замком ActivityManagerService. Все 58
 * процессов живы, часы тикают, DNS ходит, а интерфейса нет вовсе: мост GPU
 * честно рисовал пустые кадры («ПРОВАЛ 60001 мс» подряд). Замер в момент
 * зависания: очереди всех сокетов пусты (`ss -x` — ни байта), демон считает
 * поток свободным («ждёт работу=1, своих вызовов без ответа=0»), то есть
 * подтверждения не ждёт НИКТО и не пришлёт его тоже никто.
 * Ровно та же беда 4 сентября (Binder_3, односторонняя scheduleTrimMemory) —
 * тогда закрыли только один её путь, потолком в 30 с на ожидание
 * подтверждения демона.
 *
 * ★★★ И ТРЕТИЙ РАЗ ТА ЖЕ БЕДА — 21 сентября, ЧЕРЕЗ ДЫРУ В ЭТОЙ САМОЙ
 * СТРАХОВКЕ. Прошивка загрузилась целиком и проработала восемь часов; человек
 * снял блокировку экрана — и система замерла при живых 27 процессах. Снимок по
 * SIGQUIT показал всё сразу:
 *
 *   "Binder_2" tid=45 NATIVE                     ← держит замок AMS
 *     at android.os.BinderProxy.transact(Native Method)
 *     at ApplicationThreadProxy.scheduleTrimMemory(…)   ← ОДНОСТОРОННЯЯ
 *     at ActivityManagerService.updateOomAdjLocked(…)
 *     at ActivityManagerService.appDiedLocked(…)
 *     at ActivityManagerService$AppDeathRecipient.binderDied(…)
 *     at android.os.BinderProxy.sendDeathNotice(…)      ← ★ ИЗВЕЩЕНИЕ О СМЕРТИ
 *   "main" tid=1 MONITOR … waiting to lock <0x42c7f7a8> held by tid=45
 *   ещё три потока system_server — там же, и четыре чужих процесса стоят в
 *   вызовах к нему (оболочка — в performTraversals, и потому не забирает
 *   касания: «touched window has not finished processing the input events»).
 *
 * Почему страховка промолчала: поток В ПУЛЕ (looper = 1) и НЕ внутри чужой
 * транзакции (in_txn = 0) — он внутри ИЗВЕЩЕНИЯ О СМЕРТИ. По прежним двум
 * правилам это «свободный поток», и его оставили ждать вечно. Отсюда третье
 * правило ниже.
 *
 * Как отличаем. Поток заведомо НЕ свободен, если:
 *   * он не в пуле (BC_ENTER_LOOPER/BC_REGISTER_LOOPER не присылал) — такие
 *     потоки заходят в ioctl только из transact(); либо
 *   * он внутри чужой транзакции (получил BR_TRANSACTION и ещё не вернул её
 *     буфер) — из executeCommand в ожидание работы не уходят; либо
 *   * он внутри извещения о смерти И ЧТО-ТО ПОСЛАЛ ПОСЛЕ НЕГО
 *     (см. in_death_work) — это тот же executeCommand, только другая команда.
 *     ⚠️ Одного «получил извещение» НЕДОСТАТОЧНО: закрывают его не все, и у
 *     старого servicemanager счётчик не спадает никогда.
 *
 * ⚠️★★★ А вот «мы должны ему подтверждение» (`cpl_given < tx_total`) признаком
 * НЕ ГОДИТСЯ, хотя и выглядит точным: счёт расходится навсегда на законном
 * пути — при отказе «адресат мёртв» долг подтверждения ОТМЕНЯЕТСЯ
 * (см. msg_to_br), и с этой минуты поток выглядел бы вечно ждущим
 * подтверждения. Пробовали 21.09 — system_server умер на первом же таком
 * потоке пула.
 * И при этом он не ждёт настоящего ответа на свой двусторонний вызов
 * (pending_sync == 0 — такое ожидание законно, ответ придёт как работа),
 * и хоть что-то за свою жизнь посылал.
 *
 * ⚠️ Осторожность здесь не лишняя: BR_TRANSACTION_COMPLETE, выданное потоку
 * пула, executeCommand не разбирает вовсе — «*** BAD COMMAND 29190 received
 * from Binder driver» и abort() всего процесса. Поэтому страхуем только те
 * потоки, где ожидание работы невозможно ПО УСТРОЙСТВУ libbinder.
 *
 * ⚠️ Выключатель GUEST_NO_BINDER_RESCUE=1 возвращает прежнее поведение (ждать
 * вечно). Нужен, чтобы отделить последствия этой страховки от чужих поломок.
 */
#define GUEST_STUCK_MS 8000          /* меньше минуты Watchdog'а гостя */

static int rescue_off(void) {
    static int v = -1;
    if (v < 0) { const char *e = getenv("GUEST_NO_BINDER_RESCUE"); v = e && *e && *e != '0'; }
    return v;
}

/*
 * ★★★★★ ПОТОК ЗАНЯТ ИЗВЕЩЕНИЕМ О СМЕРТИ — И ЭТО ВИДНО ПО ПОСЫЛКАМ.
 *
 * Одного `in_death` мало: закрывают извещение не все (разбор — у поля), и у
 * старого `servicemanager` счётчик доходит до числа служб и не спадает
 * никогда. Зато «получил извещение И ПОСЛЕ ЭТОГО что-то послал» — признак
 * точный: послать из `binderDied` можно только изнутри `waitForResponse`, а
 * поток пула, стоящий за работой, не посылает ничего.
 *
 * ⚠️ Цена ошибки здесь — смерть всего процесса. Что бы мы ни отдали потоку,
 * который на самом деле стоит в пуле, `executeCommand` этого не знает:
 *   E IPCThreadState getAndExecuteCommand(fd=41) returned unexpected error
 *                    -2147483648, aborting
 *   F libc           Fatal signal 6 (SIGABRT) … thread … (Binder_3)
 * и следом «Exit zygote because system server has terminated». Поймано
 * 21.09 дважды, на двух разных неверных признаках подряд.
 */
static int in_death_work(const struct thr *t) {
    /*
     * ⚠️★★★ ТРЕТЬЕ УСЛОВИЕ — И БЕЗ НЕГО ВСЁ ОСТАЛЬНОЕ БЕССМЫСЛЕННО.
     *
     * «Послал после извещения» казалось доказательством того, что поток внутри
     * `waitForResponse`. Оно им не является: в `tx_total` считаются И ОТВЕТЫ
     * (BC_REPLY), а реестр служб только и делает, что отвечает. Один раз
     * получив извещение о смерти (и не закрыв его — он этого не умеет), он
     * навсегда попадал под правило, и первый же его ОТВЕТ взводил признак.
     *
     * Поэтому верим счётчику извещений только у тех, кто их ЗАКРЫВАЕТ
     * (см. sess.closes_death). libbinder закрывает всегда; крошечный
     * разборщик `servicemanager` — никогда, и трогать его нельзя вовсе.
     */
    return t->s && t->s->closes_death &&
           t->in_death > 0 && t->tx_total > t->tx_at_death;
}

static int rescue_possible(const struct thr *t) {
    if (rescue_off()) return 0;
    if (t->pending_sync > 0) return 0;   // ждёт ответа на свой вызов — законно
    if (t->tx_total == 0) return 0;      // ничего не посылал — ждать ему нечего
    return !t->looper || t->in_txn > 0 || in_death_work(t);
}

/*
 * Какой отказ отдать гостю, когда связь с демоном оборвалась. Сессию закрыл
 * сам процесс (stopProcess, см. sess.closing) — EBADF: на нём libbinder выходит
 * из пула штатно. Иначе — ENOTCONN, как было.
 */
static int gone_errno(struct sess *s) { return (s && s->closing) ? EBADF : ENOTCONN; }

static int binder_write_read(struct thr *t, struct sess *s, struct binder_write_read *bwr) {
    if (g_verbose) glog("binder: WR вход tid=%d запись=%llu чтение=%llu", gettid(),
                        (unsigned long long)bwr->write_size, (unsigned long long)bwr->read_size);
    /*
     * ★★★★★ «Предыдущую одностороннюю разобрал». Шлём ПЕРВЫМ делом: между
     * прошлым ioctl и этим libbinder выполнил executeCommand целиком, значит
     * сообщение уже легло в очередь главного потока и порядок зафиксирован.
     * Пока демон этого не услышит, следующую одностороннюю к тому же узлу он
     * не выдаст — иначе scheduleBindService обгоняет scheduleCreateService.
     */
    if (t->async_pending && t->fd >= 0) {
        struct sb_hdr ah = { .len = sizeof ah, .type = SB_ASYNC_DONE,
                              .tid = (uint32_t)gettid(), .flags = SB_F_MAGIC };
        t->async_pending = 0;
        (void)!write(t->fd, &ah, sizeof ah);
    }
    t->sent = 0;
    t->will_read = bwr->read_size > 0;
    if (bwr->write_size) {
        size_t used = bc_process(t, s, (const uint8_t *)(uintptr_t)bwr->write_buffer,
                                 (size_t)bwr->write_size);
        /*
         * ★★★ СТОРОЖ НЕДОРАЗОБРАННОГО БУФЕРА.
         *
         * Гость кладёт в один буфер несколько команд подряд: BC_FREE_BUFFER,
         * BC_RELEASE и следом BC_TRANSACTION. Если разбор встал на середине, а
         * мы сказали «разобрали всё», libbinder выбросит остаток — и посылка
         * исчезнет без следа. Кричим об этом с первым непонятым словом.
         */
        if (used != (size_t)bwr->write_size) {
            uint32_t bad = 0;
            if (used + 4 <= (size_t)bwr->write_size)
                memcpy(&bad, (const uint8_t *)(uintptr_t)bwr->write_buffer + used, 4);
            bwarn("binder: ★★★ КОМАНДНЫЙ БУФЕР РАЗОБРАН НЕ ДО КОНЦА: %zu из %llu байт, "
                  "первое непонятое слово 0x%x — ОСТАТОК ПРОПАДЁТ",
                  used, (unsigned long long)bwr->write_size, (unsigned)bad);
        }
        bwr->write_consumed = bwr->write_size;
    }
    bwr->read_consumed = 0;
    if (!bwr->read_size) return 0;

    struct outbuf o = { .p = (uint8_t *)(uintptr_t)bwr->read_buffer,
                        .cap = (size_t)bwr->read_size, .len = 0 };
    int more = 0, from_daemon = 0, waited = 0;

    // ⚠️ Отложенное отдаём НЕ здесь, а после наших подтверждений: в буфере
    // чтения порядок обязан быть [ссылки][BR_TRANSACTION_COMPLETE][работа].

    // ★★★ ПОРЯДОК КОМАНД. Сначала — то, что демон прислал по только что
    // отправленной транзакции (BR_INCREFS/BR_ACQUIRE на объекты, которые гость
    // сам же и отдал), и только ПОТОМ наше BR_TRANSACTION_COMPLETE.
    //
    // Так делает настоящий драйвер: в binder_transaction() перевод объектов
    // (binder_translate_binder -> binder_inc_ref_for_node) кладёт BR_INCREFS и
    // BR_ACQUIRE в очередь ЭТОГО потока, а BR_TRANSACTION_COMPLETE
    // добавляется последним.
    //
    // Почему это важно. libbinder разбирает буфер в waitForResponse и на
    // BR_TRANSACTION_COMPLETE делает `goto finish` — то есть ВЫХОДИТ, оставив
    // остальное в mIn. Сразу после выхода разрушается Parcel ответа, и
    // последняя ссылка на только что отданный объект (например Client у
    // SurfaceFlinger) исчезает — объект удаляется. Пришедший следом
    // BR_ACQUIRE попадает в мёртвую память: SIGSEGV в RefBase::incStrong,
    // mRefs == NULL, обращение к 0x4. Измерено на телефоне 2026-08-26: с
    // подтверждением впереди SurfaceFlinger падал на каждом создании
    // соединения, с правильным порядком — живёт.
    while (t->acks > 0) {
        struct sb_hdr wh = { .len = sizeof wh, .type = SB_WAIT,
                              .tid = (uint32_t)gettid(), .flags = SB_F_MAGIC };
        waited = 1;
        if (t->fd < 0 || write(t->fd, &wh, sizeof wh) != (ssize_t)sizeof wh) { errno = gone_errno(s); return -1; }
        uint8_t stackmsg[SB_PEND], *msg = stackmsg;
        int fds[8], nfds = 0;
        int n = drecv_to(t, &msg, sizeof stackmsg, fds, &nfds, 30000, "жду подтверждение посылки");
        if (n == -2) {
            // Подтверждения нет полминуты. Считаем посылку принятой: гостю
            // отдадим BR_TRANSACTION_COMPLETE и он пойдёт дальше. Опоздавшее
            // подтверждение потом просто пропадёт (см. SB_R_ACK).
            bwarn("binder: ★★ ПОДТВЕРЖДЕНИЯ НЕТ 30 с — отпускаю гостя "
                 "(ждали %d, долг %d, посылка код=%u флаги=0x%x цель=%u)",
                 t->acks, t->completes, t->last_code, t->last_flags, t->last_handle);
            t->acks = 0;
            break;
        }
        if (n < 0) { glog("binder: WR разрыв связи с демоном (ждали подтверждение)"); errno = gone_errno(s); return -1; }
        more = (((struct sb_hdr *)msg)->flags & SB_F_MORE) != 0;
        from_daemon = 1;
        // ★★ ЧУЖАЯ РАБОТА НЕ ЛЕЗЕТ ВПЕРЁД НАШЕГО ПОДТВЕРЖДЕНИЯ.
        //
        // Порядок в буфере обязан быть: [ссылки][BR_TRANSACTION_COMPLETE][работа].
        // Настоящий драйвер кладёт подтверждение в очередь ЭТОГО потока сразу
        // за ссылками, а входящая работа приходит уже следующим чтением.
        //
        // Если пустить входящую транзакцию вперёд, libbinder разберёт её
        // первой, ответит (sendReply -> waitForResponse), и в mIn у него
        // останется НАШ BR_TRANSACTION_COMPLETE — он съест его как
        // подтверждение своего ответа, а настоящее подтверждение станет лишним
        // уже в пул-цикле. Там executeCommand такой команды не знает и рвёт
        // процесс: «*** BAD COMMAND 29190 received from Binder driver»
        // (0x7206 = BR_TRANSACTION_COMPLETE), а следом system_server и zygote.
        // Измерено на телефоне 2026-08-26, сразу после «System now ready».
        uint16_t ty = ((struct sb_hdr *)msg)->type;
        if ((ty == SB_R_TRANSACTION || ty == SB_R_REPLY) && t->completes > 0) {
            if (nfds == 0) { dq_push(t, msg, (size_t)n); continue; }
            // С описателями отложить нельзя (они уже у нас на руках и в
            // очередь не переносятся) — тогда сначала выдаём подтверждения,
            // и только потом работу: порядок важнее экономии.
            while (t->completes > 0 && out_put(&o, BR_TRANSACTION_COMPLETE, NULL, 0) == 0)
                { t->completes--; t->cpl_given++; }
        }
        if (msg_to_br(t, s, msg, fds, nfds, &o) < 0) { dq_push(t, msg, (size_t)n); break; }
    }

    // Отказы по недоступной памяти гостя — прежде подтверждений: так же
    // поступает драйвер, у него err_copy_data_failed освобождает tcomplete.
    while (t->failed > 0 && out_put(&o, BR_FAILED_REPLY, NULL, 0) == 0) t->failed--;

    // Теперь — наши собственные подтверждения на принятые команды.
    while (t->completes > 0 && out_put(&o, BR_TRANSACTION_COMPLETE, NULL, 0) == 0)
        { t->completes--; t->cpl_given++; }

    // И только теперь — отложенная чужая работа.
    if (!t->completes) dq_flush(t, s, &o);

    // ★★★ ИНВАРИАНТ ДРАЙВЕРА: на каждую принятую BC_TRANSACTION/BC_REPLY гость
    // обязан получить BR_TRANSACTION_COMPLETE в ЭТОМ ЖЕ заходе в ioctl.
    // libbinder в waitForResponse ждёт именно его и без него уходит в чтение
    // навсегда — с зажатым замком, если это поток system_server. Если учёт
    // где-то потерялся, лучше отдать подтверждение и громко сказать об этом,
    // чем заморозить систему.
    if (t->sent > 0 && o.len == 0) {
        bwarn("binder: ★★ УЧЁТ ПОТЕРЯН — приняли посылок %d (код=%u флаги=0x%x цель=%u), "
             "а отдать гостю нечего (ждём подтверждений %d, долг %d, отказов %d, "
             "отложено %s) — выдаю подтверждения сам",
             t->sent, t->last_code, t->last_flags, t->last_handle,
             t->acks, t->completes, t->failed, t->dq ? "есть" : "нет");
        while (t->sent > 0 && out_put(&o, BR_TRANSACTION_COMPLETE, NULL, 0) == 0)
            { t->sent--; t->cpl_given++; }
    }

    // ★★★ Никогда не уходить в ожидание, если у нас уже лежит отложенное.
    //
    // Иначе получается вечная блокировка: ответ на транзакцию отложен в
    // очередь (не влез в буфер чтения гостя или обгонял наше подтверждение),
    // отдать его в этом заходе не вышло, а мы посылаем демону SB_WAIT и
    // засыпаем в recvmsg. Новой работы демон не пришлёт — она уже у нас.
    // Поток гостя стоит навсегда; если это поток system_server с замком
    // ActivityManagerService, через минуту Watchdog убивает систему:
    //   WATCHDOG KILLING SYSTEM PROCESS: Blocked in monitor
    //     ActivityManagerService on foreground thread (android.fg)
    // Поймано трижды подряд — на scheduleUnbindService, onBindMethod и
    // scheduleReceiver. Вместо ожидания возвращаем гостю пустое чтение: он
    // тут же зайдёт снова, и на следующем заходе очередь уйдёт ему.
    if (o.len == 0 && t->dq) {
        // Сначала пробуем отдать очередь, не дожидаясь, пока разойдутся
        // подтверждения: порядок команд важен, но вечная блокировка хуже.
        dq_flush(t, s, &o);
        if (o.len == 0) {
            bwarn("binder: ★ отложенное есть, а отдать не вышло (подтверждений %d) — "
                 "не ухожу в ожидание", t->completes);
            if (from_daemon) wake_sync(s, more);
            bwr->read_consumed = 0;
            return 0;
        }
    }

    // Если гостю всё ещё нечего отдать — ждём работу.
    // ★ Для потока, который ждать работу не может (см. rescue_possible), это
    // ожидание с потолком: иначе он встанет навсегда, а с ним и вся система.
    const int rescue = rescue_possible(t);
    while (o.len == 0) {
        struct sb_hdr wh = { .len = sizeof wh, .type = SB_WAIT,
                              .tid = (uint32_t)gettid(), .flags = SB_F_MAGIC };
        waited = 1;
        if (t->fd < 0 || write(t->fd, &wh, sizeof wh) != (ssize_t)sizeof wh) {
            errno = gone_errno(s);
            return -1;
        }
        uint8_t stackmsg[SB_PEND], *msg = stackmsg;
        int fds[8], nfds = 0;
        int n;
        if (rescue) {
            n = drecv_to(t, &msg, sizeof stackmsg, fds, &nfds, GUEST_STUCK_MS, "жду работу");
            if (n == -2) {
                /*
                 * ★★★★★ ПОДТВЕРЖДЕНИЕ ВЫДАЁМ, ТОЛЬКО ЕСЛИ САМИ ЕГО ДОЛЖНЫ.
                 *
                 * Прежде спасение выдавало BR_TRANSACTION_COMPLETE всегда — и
                 * этим убивало то, что спасало. libbinder ждёт подтверждение
                 * ровно после своей посылки; поток пула, стоящий в ожидании
                 * работы, его не разбирает вовсе:
                 *
                 *   *** BAD COMMAND 29190 received from Binder driver
                 *   getAndExecuteCommand(fd=…) returned unexpected error …
                 *   -> abort()  прямо в IPCThreadState::joinThreadPool
                 *
                 * Измерено 17.09: под игрой это срабатывало 48 раз за
                 * запуск, гостевые процессы гибли, стенд сваливался с 44
                 * процессов до 25 — и любой замер графики после этого был про
                 * недогруженный стенд, а не про мост.
                 *
                 * Различаем по учёту: выдали подтверждений МЕНЬШЕ, чем приняли
                 * посылок, — долг наш, выдаём. Выдали столько же — ждать
                 * подтверждения потоку неоткуда и незачем; выходим ПУСТЫМИ.
                 * Пустой возврат для libbinder безвреден: `getAndExecuteCommand`
                 * при пустом mIn просто возвращает успех и заходит снова.
                 */
                int ours = t->cpl_given < t->tx_total;
                /*
                 * ★★★★★ ОТКАЗ ВМЕСТО ПУСТОТЫ, КОГДА ПОТОК ВНУТРИ ЧУЖОЙ
                 * ТРАНЗАКЦИИ.
                 *
                 * Пустой возврат безвреден, но и бесполезен: libbinder заходит
                 * снова и ждёт снова, и так вечно. Пока он так ходит, поток
                 * ДЕРЖИТ СВОИ ЗАМКИ — а если это Binder_1 диспетчера задач, то
                 * замок `ActivityManagerService`, и вся система встаёт намертво
                 * при свободном процессоре: измерено 20.09, дедлок на доставке
                 * широковещания (`scheduleRegisteredReceiver` внутри
                 * `finishReceiver`), 144 круга спасения подряд.
                 *
                 * Настоящий драйвер на недоставленной транзакции отдаёт
                 * BR_FAILED_REPLY: `waitForResponse` разбирает его как
                 * FAILED_TRANSACTION, вызов возвращает ошибку, вызывающий
                 * ОТПУСКАЕТ ЗАМКИ и идёт дальше. Потеря одной посылки стоит
                 * одного пропущенного широковещания; потеря замка стоит всей
                 * системы.
                 *
                 * ⚠️ Отказ выдаём ТОЛЬКО потоку, который обрабатывает чужую
                 * транзакцию (`in_txn > 0`). Поток пула, стоящий за работой,
                 * никакой ответ не разбирает — ему по-прежнему пустота (см.
                 * разбор выше про BAD COMMAND и abort).
                 *
                 * ⚠️ Выключатель GUEST_BINDER_NO_FAIL=1 возвращает прежнюю
                 * пустоту: нужен, чтобы отделить последствия этой страховки от
                 * чужих поломок.
                 */
                static int nofail = -1;
                if (nofail < 0) {
                    const char *e = getenv("GUEST_BINDER_NO_FAIL");
                    nofail = e && *e && *e != '0';
                }
                /*
                 * ⚠️★★★ ОТКАЗ — ТОЛЬКО ВНУТРИ ЧУЖОЙ ТРАНЗАКЦИИ, как и было.
                 *
                 * Соблазн добавить сюда `in_death` был, и он стоил дорого:
                 * 21.09 счётчик извещений оказался завышенным (старый
                 * `servicemanager` их не закрывает, см. поле in_death), и
                 * BR_FAILED_REPLY уехал потоку, который ЗАКОННО ждал работу.
                 * Его крошечный разборщик такой команды не знает —
                 * «parse: OOPS» — и процесс ушёл, а с ним вся система.
                 */
                int fail = !ours && !nofail && (t->in_txn > 0 || in_death_work(t));
                bwarn("binder: ★★★ ВЕЧНОЕ ОЖИДАНИЕ РАЗОРВАНО — потоку нечего ждать "
                      "(в пуле %d, внутри чужих транзакций %d, внутри извещений о "
                      "смерти %d, свои двусторонние без "
                      "ответа %d, посылок за жизнь %d, подтверждений выдано %d, "
                      "принято в этом заходе %d, подтверждений в очереди %d, не принял "
                      "демон %d, односторонняя не разобрана %d, последняя посылка "
                      "код=%u флаги=0x%x цель=%u) — потеря %s, %s",
                      t->looper, t->in_txn, t->in_death, t->pending_sync, t->tx_total,
                      t->cpl_given,
                      t->sent, t->completes, t->lost, t->async_pending,
                      t->last_code, t->last_flags, t->last_handle,
                      ours ? "НАША" : "у гостя",
                      ours ? "выдаю подтверждение"
                           : fail ? "отдаю ОТКАЗ — иначе поток держит свои замки вечно"
                                  : "выхожу ПУСТЫМ (подтверждение здесь убивает процесс)");
                if (ours) out_put(&o, BR_TRANSACTION_COMPLETE, NULL, 0);
                else if (fail) out_put(&o, BR_FAILED_REPLY, NULL, 0);
                break;
            }
        } else {
            n = drecv(t, &msg, sizeof stackmsg, fds, &nfds);
        }
        if (n < 0) { glog("binder: WR разрыв связи с демоном"); errno = gone_errno(s); return -1; }
        more = (((struct sb_hdr *)msg)->flags & SB_F_MORE) != 0;
        from_daemon = 1;
        if (g_verbose) glog("binder: WR получено сообщение тип=%u (%d байт, ещё=%d)",
                            ((struct sb_hdr *)msg)->type, n, more);
        if (msg_to_br(t, s, msg, fds, nfds, &o) < 0) {
            dq_push(t, msg, (size_t)n);               // отдадим следующим вызовом
            break;
        }
    }
    // ★ Точный учёт будильника. Байт в сокетной паре означает «может быть
    // работа», а демон в каждом сообщении говорит, осталась ли она.
    //
    // ⚠️ Трогать сокет можно ТОЛЬКО если в этом вызове мы действительно
    // говорили с демоном. Иначе выходит так: гость проснулся, зашёл в ioctl, а
    // мы отдали ему своё собственное BR_TRANSACTION_COMPLETE из счётчика, ни о
    // чём демона не спросив, — и заодно вычистили байт, которым он звал за
    // настоящей транзакцией. Гость уходил в poll навсегда, а транзакция висела
    // в очереди демона. Один в один тот случай, который ловился полдня.
    if (from_daemon) wake_sync(s, more);

    // Мы выходим из ioctl — значит больше не ждём. Демон снимает признак сам
    // на каждом отправленном сообщении, но так инвариант держится и на путях,
    // где сообщения не было (например, чтение прервали).
    if (waited && t->fd >= 0) {
        struct sb_hdr uh = { .len = sizeof uh, .type = SB_UNWAIT,
                              .tid = (uint32_t)gettid(), .flags = SB_F_MAGIC };
        (void)!write(t->fd, &uh, sizeof uh);
    }

    if (g_verbose) glog("binder: WR выход, отдано %zu байт (ещё работа: %d)", o.len, more);
    bwr->read_consumed = o.len;
    return 0;
}

// Возвращает 1, если ioctl относится к нашему binder и уже обработан.
static int binder_ioctl(int fd, unsigned long req, void *arg, int *ret) {
    struct sess *s = sess_by_fd(fd);
    if (!s) return 0;
    struct thr *t = thr_get(s);
    *ret = 0;
    switch (req) {
    case BINDER_VERSION:
        if (arg) ((struct binder_version *)arg)->protocol_version = BINDER_CURRENT_PROTOCOL_VERSION;
        return 1;
    case BINDER_SET_MAX_THREADS:
        if (arg) dsend(t, SB_SET_MAX_THREADS, arg, 4, NULL, 0);
        return 1;
    case BINDER_SET_CONTEXT_MGR: {
        dsend(t, SB_SET_CTX_MGR, NULL, 0, NULL, 0);
        uint8_t stackmsg[256], *msg = stackmsg; int fds[8], nfds = 0;
        int n = drecv(t, &msg, sizeof stackmsg, fds, &nfds);
        struct sb_hdr *h = (struct sb_hdr *)msg;
        if (n < 0 || h->type != SB_R_OK) { *ret = -1; errno = EBUSY; }
        else glog("binder: стали диспетчером контекста");
        return 1;
    }
    case BINDER_THREAD_EXIT:
        if (t->fd >= 0) {
            struct sb_hdr h = { .len = sizeof h, .type = SB_BYE,
                                 .tid = (uint32_t)gettid(), .flags = SB_F_MAGIC };
            (void)!write(t->fd, &h, sizeof h);
            close(t->fd);
            t->fd = -1;
        }
        return 1;
    case BINDER_WRITE_READ:
        if (!arg) { *ret = -1; errno = EINVAL; return 1; }
        *ret = binder_write_read(t, s, (struct binder_write_read *)arg);
        return 1;
    case BINDER_SET_IDLE_TIMEOUT:
    case BINDER_SET_IDLE_PRIORITY:
        return 1;
    default:
        glog("binder: ioctl 0x%lx не поддержан", req);
        *ret = -1;
        errno = EINVAL;
        return 1;
    }
}

// mmap на нашем дескрипторе: обычная анонимная область. Гость просит PROT_READ,
// но писать в неё должны мы — поэтому берём чтение и запись.
static int binder_mmap(int fd, size_t len, abi_ulong *out) {
    struct sess *s = sess_by_fd(fd);
    if (!s) return 0;
    if (s->map) { *out = h2g(s->map); return 1; }
    // ★ target_mmap, а не mmap: область обязана лечь в адресное пространство
    // ГОСТЯ и попасть в его учёт страниц, иначе гость её не увидит, а qemu
    // сможет выдать те же адреса кому-то ещё. Гость просит PROT_READ, но писать
    // туда должны мы — берём чтение и запись.
    abi_long g = target_mmap(0, len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g == -1) { *out = (abi_ulong)-1; return 1; }
    void *p = g2h_untagged((abi_ulong)g);
    s->map = (uint8_t *)p;
    s->map_size = len;
    struct blk *b = (struct blk *)malloc(sizeof *b);
    b->off = 0; b->size = len; b->used = 0; b->cool = 0;
    b->dsize = b->osize = 0; b->next = NULL;
    s->blocks = b;
    glog("binder: mmap %zu байт -> гость 0x%llx (хозяин %p)", len,
         (unsigned long long)g, p);
    *out = (abi_ulong)g;
    return 1;
}

// ---------------------------------------------------- точки входа из qemu
//
// Вызываются из linux-user/syscall.c (патч 0006). Всё, что относится к
// /dev/binder, обрабатывается здесь; остальное qemu делает как обычно.

/* Открытие: 1 — это наш путь, в *fd лежит результат. */
int guest_binder_try_open(const char *path, int *fd)
{
    // Отметки atrace прошивки — в нашу трассу (см. guest_trace.c).
    if (guest_trace_try_open(path, fd)) {
        return 1;
    }
    // ashmem — тоже наше устройство (см. guest_ashmem.c): перехват на уровне
    // устройства покрывает и HAL-модули, куда preload не попадает.
    if (guest_ashmem_try_open(path, fd)) {
        return 1;
    }
    // Поддельный сенсорный экран (см. guest_input.c). Все наши устройства
    // перехватываются одной точкой: в syscall.c про них знает только эта.
    if (guest_input_try_open(path, fd)) {
        return 1;
    }
    // Будильники гостя: /dev/alarm на таймерах хозяина (см. guest_alarm.c, Р-120).
    if (guest_alarm_try_open(path, fd)) {
        return 1;
    }
    // Группы планировщика: гость должен читать свой /proc/<tid>/cgroup, а не
    // хозяйский (см. guest_fs.c) — иначе Dalvik заваливает лог жалобами.
    if (guest_fs_try_open(path, fd)) {
        return 1;
    }
    if (!path || strcmp(path, "/dev/binder") != 0) {
        return 0;
    }
    blog_init();
    binder_path_init();
    if (!g_binder[0]) {
        // Демон не задан — пусть гость получит честный отказ, а не чужой
        // драйвер хозяина (у него /dev/binder есть, и это опасно).
        blog("binder: GUEST_BINDER не задан — открытие отклонено");
        errno = ENOENT;
        *fd = -1;
        return 1;
    }
    *fd = binder_open_fake();
    return 1;
}

/* Наш ли это описатель (нужно перед mmap и close). */
int guest_binder_owns(int fd)
{
    return sess_by_fd(fd) != NULL;
}

/* ioctl. 1 — обработано; arg — ГОСТЕВОЙ адрес. */
int guest_binder_ioctl(int fd, unsigned long req, abi_ulong arg, abi_long *ret)
{
    // Кадровый буфер: за ним обычный файл, а gralloc и SurfaceFlinger
    // спрашивают у него геометрию через ioctl. Отвечает guest_fb.c.
    if (guest_fb_ioctl(fd, req, arg, ret)) {
        return 1;
    }
    if (guest_ashmem_ioctl(fd, req, arg, ret)) {
        return 1;
    }
    // Опросы поддельного экрана: версия, имя, набор осей (см. guest_input.c).
    if (guest_input_ioctl(fd, req, arg, ret)) {
        return 1;
    }
    // Будильники: SET / CLEAR / WAIT / GET_TIME по номерам android_alarm.h (см. guest_alarm.c).
    if (guest_alarm_ioctl(fd, req, arg, ret)) {
        return 1;
    }
    if (!sess_by_fd(fd)) {
        return 0;
    }
    int r = 0;
    void *host = arg ? g2h_untagged(arg) : NULL;
    int handled = binder_ioctl(fd, req, host, &r);
    if (handled) {
        // Отдаём -1 и оставляем errno: перевод в гостевой номер ошибки делает
        // сам qemu (host_to_target_errno — статическая функция syscall.c и
        // отсюда не видна).
        *ret = (r < 0) ? -1 : 0;
    }
    return handled;
}

/* mmap. 1 — обработано; *addr — ГОСТЕВОЙ адрес области или (abi_ulong)-1. */
int guest_binder_mmap(int fd, abi_ulong len, abi_ulong *addr)
{
    return binder_mmap(fd, (size_t)len, addr);
}

void guest_binder_close(int fd)
{
    guest_fb_forget(fd);
    guest_ashmem_close(fd);
    guest_input_close(fd);
    guest_alarm_close(fd);
    struct sess *s = sess_by_fd(fd);
    if (s) {
        binder_close_fake(s);
    }
}
