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

// binder_proto.h — определения драйвера binder и протокол «шим ↔ binderd».
//
// ★ Происхождение. Это форк файла из более ранней нашей работы, где
// тот же демон уже поднимал полный стек Android 7 — SurfaceFlinger,
// зиготу и system_server. Протокол «шим ↔ binderd» перенесён без смысловых
// правок; переименованы только метки: на проводе теперь «sb00» и «SB», в
// именах — префикс SB_ / sb_. Правки по-прежнему могут ходить между проектами
// в обе стороны, а лечить одну и ту же гонку дважды не приходится.
//
// ★ Объявления UAPI. The kernel-interface declarations in the section
// "UAPI binder" below follow include/uapi/linux/android/binder.h of the Linux
// kernel (GPL-2.0 WITH Linux-syscall-note); the rest of this file, and the
// "shim <-> binderd" protocol, are ours.
//
// ★ Единственное расхождение — РАЗРЯДНОСТЬ ГОСТЯ. Там гость 64-битный (Android
// 7, версия протокола binder 8), здесь 32-битный (Android 2.3, версия 7).
// Отличаются только ядерные структуры UAPI ниже; сам проводной протокол несёт
// 64-битные ptr/cookie и явные размеры, поэтому демону разрядность безразлична.
//
// Числа сверены с ПРОШИВКОЙ, а не с заголовками AOSP: в libbinder.so из ROM'а
// найдены ровно BINDER_WRITE_READ=0xc0186201 (значит sizeof=24),
// SET_MAX_THREADS=0x40046205, SET_CONTEXT_MGR=0x40046207,
// THREAD_EXIT=0x40046208, VERSION=0xc0046209.
//
// Зачем свой binder. Ядерного домена binder гостю не достать: диспетчеры
// контекста заняты хозяином, а binderfs требует прав. Но гостю binder нужен
// ТОЛЬКО внутри себя — с хозяйским он не разговаривает никогда, значит
// достаточно подделать драйвер для своих же процессов.
//
// Раскладка проверяется static_assert'ами: расхождение падает на сборке, а не
// портит память молча.

#ifndef GUEST_BINDER_PROTO_H
#define GUEST_BINDER_PROTO_H

#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>

// ------------------------------------------------------------- UAPI binder

// ⚠️ 32 бита: гость — Android 2.3 armeabi. Отсюда и sizeof(binder_write_read)=24,
// и flat_binder_object на 16 байт, и массив смещений из 4-байтных элементов.
typedef uint32_t binder_size_t;
typedef uint32_t binder_uintptr_t;

struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_version { int32_t protocol_version; };

#define BINDER_CURRENT_PROTOCOL_VERSION 7      // 7 — 32-битный вариант

#define BINDER_WRITE_READ        _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_IDLE_TIMEOUT  _IOW('b', 3, int64_t)
#define BINDER_SET_MAX_THREADS   _IOW('b', 5, uint32_t)
#define BINDER_SET_IDLE_PRIORITY _IOW('b', 6, int32_t)
#define BINDER_SET_CONTEXT_MGR   _IOW('b', 7, int32_t)
#define BINDER_THREAD_EXIT       _IOW('b', 8, int32_t)
#define BINDER_VERSION           _IOWR('b', 9, struct binder_version)

struct binder_transaction_data {
    union { uint32_t handle; binder_uintptr_t ptr; } target;
    binder_uintptr_t cookie;
    uint32_t code;
    uint32_t flags;
    pid_t sender_pid;
    uid_t sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union {
        struct { binder_uintptr_t buffer; binder_uintptr_t offsets; } ptr;
        uint8_t buf[8];
    } data;
};

struct binder_ptr_cookie { binder_uintptr_t ptr; binder_uintptr_t cookie; };

struct binder_handle_cookie {
    uint32_t handle;
    binder_uintptr_t cookie;
} __attribute__((packed));

// Флаги транзакции
#define TF_ONE_WAY     0x01
#define TF_ROOT_OBJECT 0x04
#define TF_STATUS_CODE 0x08
#define TF_ACCEPT_FDS  0x10

// Команды от процесса к драйверу
enum binder_driver_command_protocol {
    BC_TRANSACTION = _IOW('c', 0, struct binder_transaction_data),
    BC_REPLY = _IOW('c', 1, struct binder_transaction_data),
    BC_ACQUIRE_RESULT = _IOW('c', 2, int32_t),
    BC_FREE_BUFFER = _IOW('c', 3, binder_uintptr_t),
    BC_INCREFS = _IOW('c', 4, uint32_t),
    BC_ACQUIRE = _IOW('c', 5, uint32_t),
    BC_RELEASE = _IOW('c', 6, uint32_t),
    BC_DECREFS = _IOW('c', 7, uint32_t),
    BC_INCREFS_DONE = _IOW('c', 8, struct binder_ptr_cookie),
    BC_ACQUIRE_DONE = _IOW('c', 9, struct binder_ptr_cookie),
    BC_ATTEMPT_ACQUIRE = _IOW('c', 10, struct binder_ptr_cookie),
    BC_REGISTER_LOOPER = _IO('c', 11),
    BC_ENTER_LOOPER = _IO('c', 12),
    BC_EXIT_LOOPER = _IO('c', 13),
    BC_REQUEST_DEATH_NOTIFICATION = _IOW('c', 14, struct binder_handle_cookie),
    BC_CLEAR_DEATH_NOTIFICATION = _IOW('c', 15, struct binder_handle_cookie),
    BC_DEAD_BINDER_DONE = _IOW('c', 16, binder_uintptr_t),
};

// Ответы драйвера процессу
enum binder_driver_return_protocol {
    BR_ERROR = _IOR('r', 0, int32_t),
    BR_OK = _IO('r', 1),
    BR_TRANSACTION = _IOR('r', 2, struct binder_transaction_data),
    BR_REPLY = _IOR('r', 3, struct binder_transaction_data),
    BR_ACQUIRE_RESULT = _IOR('r', 4, int32_t),
    BR_DEAD_REPLY = _IO('r', 5),
    BR_TRANSACTION_COMPLETE = _IO('r', 6),
    BR_INCREFS = _IOR('r', 7, struct binder_ptr_cookie),
    BR_ACQUIRE = _IOR('r', 8, struct binder_ptr_cookie),
    BR_RELEASE = _IOR('r', 9, struct binder_ptr_cookie),
    BR_DECREFS = _IOR('r', 10, struct binder_ptr_cookie),
    BR_ATTEMPT_ACQUIRE = _IOR('r', 11, struct binder_ptr_cookie),
    BR_NOOP = _IO('r', 12),
    BR_SPAWN_LOOPER = _IO('r', 13),
    BR_FINISHED = _IO('r', 14),
    BR_DEAD_BINDER = _IOR('r', 15, binder_uintptr_t),
    BR_CLEAR_DEATH_NOTIFICATION_DONE = _IOR('r', 16, binder_uintptr_t),
    BR_FAILED_REPLY = _IO('r', 17),
};

#define B_PACK_CHARS(c1, c2, c3, c4) \
    ((((uint32_t)(c1)) << 24) | (((uint32_t)(c2)) << 16) | (((uint32_t)(c3)) << 8) | ((uint32_t)(c4)))
#define B_TYPE_LARGE 0x85

enum {
    BINDER_TYPE_BINDER = B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE),
    BINDER_TYPE_WEAK_BINDER = B_PACK_CHARS('w', 'b', '*', B_TYPE_LARGE),
    BINDER_TYPE_HANDLE = B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE),
    BINDER_TYPE_WEAK_HANDLE = B_PACK_CHARS('w', 'h', '*', B_TYPE_LARGE),
    BINDER_TYPE_FD = B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE),
    BINDER_TYPE_FDA = B_PACK_CHARS('f', 'd', 'a', B_TYPE_LARGE),
    BINDER_TYPE_PTR = B_PACK_CHARS('p', 't', '*', B_TYPE_LARGE),
};

#define FLAT_BINDER_FLAG_PRIORITY_MASK 0xff
#define FLAT_BINDER_FLAG_ACCEPTS_FDS   0x100

struct flat_binder_object {
    uint32_t type;
    uint32_t flags;
    union { binder_uintptr_t binder; uint32_t handle; };
    binder_uintptr_t cookie;
};

// Раскладка обязана совпасть с ядерной: гостевой libbinder читает эти поля по
// смещениям, вкомпилированным в него в 2017 году.
// Раскладка ГОСТЕВЫХ структур: 32-битный Android 2.3.
_Static_assert(sizeof(struct binder_write_read) == 24, "binder_write_read");
_Static_assert(sizeof(struct binder_transaction_data) == 40, "binder_transaction_data");
_Static_assert(sizeof(struct flat_binder_object) == 16, "flat_binder_object");
_Static_assert(sizeof(struct binder_ptr_cookie) == 8, "binder_ptr_cookie");
_Static_assert(sizeof(struct binder_handle_cookie) == 8, "binder_handle_cookie");

// --------------------------------------------- наш протокол «шим ↔ binderd»
//
// Одно соединение на ПОТОК гостя: иначе несколько потоков, читающих один
// сокет, растаскивали бы чужие сообщения. Демон группирует соединения по pid.
//
// Транзакции ходят с уже переведёнными объектами: перевод делает демон, потому
// что только у него есть таблицы узлов и ссылок. Файловые описатели идут
// отдельно, через SCM_RIGHTS, в порядке появления в массиве смещений.

#define SB_MAGIC 0x73623030u   /* "sb00" */

enum sb_type {
    // шим -> демон
    SB_HELLO = 1,          // struct sb_hello
    SB_SET_CTX_MGR,        // без тела
    SB_SET_MAX_THREADS,    // uint32
    SB_TRANSACT,           // struct sb_txn + данные + смещения
    SB_REPLY,              // struct sb_txn + данные + смещения
    SB_REF,                // struct sb_ref (increfs/acquire/release/decrefs)
    SB_REF_DONE,           // struct sb_ptr_cookie
    SB_LOOPER,             // uint32: 0 register, 1 enter, 2 exit
    SB_DEATH,              // struct sb_death (0 request, 1 clear)
    SB_DEAD_DONE,          // uint64 cookie
    SB_WAIT,               // «жду работу» — блокирующее чтение
    SB_UNWAIT,             // «больше не жду» — поток вышел из ioctl
    SB_BYE,                // поток уходит
    /*
     * ★★★★★ «Одностороннюю разобрал» — шим шлёт в НАЧАЛЕ следующего ioctl,
     * если в прошлом заходе отдал гостю одностороннюю транзакцию.
     *
     * Зачем отдельное сообщение. Демон держит односторонние к одному узлу по
     * одной (как node->async_todo в настоящем драйвере) и должен знать, когда
     * получатель ДЕЙСТВИТЕЛЬНО её выполнил. SB_UNWAIT для этого не годится:
     * его шлют на ВЫХОДЕ из того же ioctl, то есть ДО того, как гость вообще
     * увидел работу. С таким признаком сериализация не делает ничего.
     *
     * А между двумя ioctl одного потока libbinder успевает выполнить
     * executeCommand целиком: и в пуле (joinThreadPool), и на главном потоке
     * (handlePolledCommands -> flushCommands) следом всегда идёт новый ioctl.
     */
    SB_ASYNC_DONE,

    // демон -> шим
    SB_R_OK = 64,
    SB_R_ERROR,            // int32
    SB_R_TRANSACTION,      // struct sb_txn + данные + смещения
    SB_R_REPLY,
    SB_R_COMPLETE,         // BR_TRANSACTION_COMPLETE
    SB_R_DEAD_REPLY,
    SB_R_FAILED_REPLY,
    SB_R_REF,              // struct sb_ptr_cookie + op -> BR_INCREFS/ACQUIRE/...
    SB_R_SPAWN,            // BR_SPAWN_LOOPER
    SB_R_DEAD_BINDER,      // uint64 cookie
    SB_R_CLEAR_DEATH_DONE, // uint64 cookie
    // ★ Подтверждение: демон обработал присланную транзакцию или ответ. Шим
    // не выходит из ioctl, пока его не получит, — так гость видит все
    // BR_INCREFS/BR_ACQUIRE на только что отданные объекты ещё ДО того, как
    // разрушит Parcel. Настоящий драйвер делает это синхронно внутри ioctl.
    SB_R_ACK,
};

// Флаг SB_F_MORE — «у демона для этого процесса ещё есть работа». Без него
// шим не может согласовать байт-будильник с состоянием очереди: слив байтов
// «на всякий случай» съедал уведомление, и гость, ждущий в poll, засыпал
// навсегда при непустой очереди.
#define SB_F_MORE 1u

// ★ Метка и порядковый номер — против рассинхрона потока сообщений.
//
// Сокет между шимом и демоном ПОТОКОВЫЙ: стоит один раз прочитать не столько
// байт, сколько надо, и дальше заголовком считается середина чужого тела.
// Внешне это выглядит как вечное ожидание: гостевой поток стоит в read() на
// длину, взятую из мусора, а демон при этом спокойно спит без работы.
// Поймать такое без метки нельзя — любые 16 байт «похожи» на заголовок.
//
// Поэтому в старших битах flags едет метка, а в поле tid сообщений
// «демон -> шим» (там оно всё равно не использовалось) — номер по порядку.
// Шим сверяет и то и другое и при расхождении громко ругается, вместо того
// чтобы зависнуть.
#define SB_F_MAGIC      0x53420000u   // «SB»
#define SB_F_MAGIC_MASK 0xffff0000u

struct sb_hdr {
    uint32_t len;      // полная длина, включая заголовок
    uint16_t type;
    uint16_t nfds;     // сколько описателей идёт через SCM_RIGHTS
    uint32_t tid;
    uint32_t flags;    // SB_F_*
};

struct sb_hello {
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
    uint32_t first;    // 1 — это первый поток процесса
};

// Транзакция. Для SB_TRANSACT значим handle, для ответов — node_ptr/cookie.
struct sb_txn {
    uint32_t handle;        // цель (для запроса)
    uint32_t code;
    uint32_t flags;
    uint32_t sender_pid;
    uint32_t sender_euid;
    uint32_t pad;
    uint64_t node_ptr;      // заполняет демон для получателя
    uint64_t node_cookie;
    uint64_t data_size;
    uint64_t offsets_size;
    // далее: data_size байт данных, затем offsets_size байт смещений
};

struct sb_ref {
    uint32_t op;            // 0 increfs, 1 acquire, 2 release, 3 decrefs
    uint32_t handle;
};

struct sb_ptr_cookie {
    uint32_t op;            // 0 increfs, 1 acquire, 2 release, 3 decrefs
    uint32_t pad;
    uint64_t ptr;
    uint64_t cookie;
};

struct sb_death {
    uint32_t op;            // 0 request, 1 clear
    uint32_t handle;
    uint64_t cookie;
};

#define SB_REF_INCREFS 0
#define SB_REF_ACQUIRE 1
#define SB_REF_RELEASE 2
#define SB_REF_DECREFS 3
// ★ «Буферные» снятия: их шлёт шим, когда гость вернул буфер транзакции
// (BC_FREE_BUFFER). Считаются ТОЛЬКО на самой ссылке и НЕ трогают счётчик
// узла — владелец объекта о них знать не должен, иначе он начинает удалять
// ещё нужные объекты (проверено: SurfaceFlinger падал в GraphicBuffer::flatten
// по освобождённой памяти, а загрузка — на BatteryService.isPoweredLocked).
#define SB_REF_RELEASE_BUF 4
#define SB_REF_DECREFS_BUF 5

// ------------------------------------------- общая область свойств гостя
//
// Свойства обязаны быть общими для всех процессов гостя: system_server пишет
// sys.boot_completed, init читает ctl.start, лончер читает ro.*. Настоящий
// property-сервис живёт в init и общается через /dev/socket/property_service,
// но нам проще и надёжнее общий отображаемый файл: читатели работают вообще без
// системных вызовов, писатели берут flock. Записи редки, чтения частые.
//
// Файл создаёт init прежней работы, читают и пишут все гостевые процессы через libglue
// (путь передаётся в SB_PROPS).

#define SB_PROP_MAGIC 0x73627072u   /* "sbpr" */
#define SB_PROP_MAXREC 1024

struct sb_prop_hdr {
    uint32_t magic;
    uint32_t count;     // сколько записей занято
    uint32_t serial;    // растёт на каждую запись — по нему видно изменения
    uint32_t max;       // сколько записей вмещается
};

struct sb_prop_rec {
    char k[64];
    char v[92];
};

#endif  // SB_BINDER_PROTO_H
