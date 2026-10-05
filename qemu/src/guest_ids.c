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

/* guest_ids.c — личность гостевых процессов: СВОЙ учёт прав, а не хозяйский.
 *
 * Зачем это вообще. Прошивка — целая система, а не приложение. Её службы
 * объявляются в binder, а servicemanager пускает туда только root и AID_SYSTEM
 * (svc_can_register в его binder.c). Наши гостевые процессы наследуют uid
 * приложения (на телефоне это что-то вроде 10661), и SurfaceFlinger получал
 * отказ на регистрацию — снаружи это выглядело как «bootanimation ждёт службу
 * SurfaceFlinger», хотя SF работал и объявился. Поэтому гостю показываем root.
 *
 * ★ Почему учёт свой, а не хозяйские вызовы. Система не только СМОТРИТ на свои
 * права — она их МЕНЯЕТ. Зигота 2.3, порождая system_server, делает
 * prctl(PR_SET_KEEPCAPS), setgroups, setgid(1000), setuid(1000), capset. Ни
 * один из этих вызовов у процесса приложения на живом Android пройти не может:
 *
 *   E dalvikvm  cannot PR_SET_KEEPCAPS: Operation not permitted
 *   E dalvikvm  VM aborting
 *   D Zygote    Process 14623 terminated by signal (11)
 *
 * (PR_SET_KEEPCAPS отдаёт EPERM, потому что зигота САМОГО Android запирает
 * securebits у процессов приложений битом SECURE_KEEP_CAPS_LOCKED; qemu 8.2.2
 * пропускает этот prctl прямо в ядро, см. do_prctl.)
 *
 * Пускать эти вызовы к хозяину и не надо: понижение прав внутри гостя — его
 * внутреннее дело, ровно такое же, как номер его uid. Поэтому здесь заведена
 * модель учётных данных: гость их ставит и читает, а хозяйский процесс
 * остаётся тем, чем был. Права ХОЗЯИНА не меняются ни на байт: запрещённое
 * песочнице остаётся запрещённым, гость лишь видит согласованную картину.
 *
 * ⚠️ Модель ОДНА на процесс qemu и общая для всех гостевых потоков — так же,
 * как в ядре: учётные данные принадлежат процессу, а не потоку. При fork
 * копируется вместе с процессом qemu, что тоже верно. А вот execve через
 * патч 0005 перезапускает qemu заново, и модель начинается с GUEST_UID/GUEST_GID:
 * для нас это безвредно (execve делает только Dalvik ради dexopt, до всякой
 * смены личности), но знать об этом надо.
 *
 * Начальные значения — GUEST_UID/GUEST_GID, по умолчанию 0 (root).
 *
 * ★ Режим «init прошивки» (GUEST_FWINIT=1, патч 0079) выставляет личность СЛУЖБАМ
 * через execve: init делает setgid, setgroups, setuid и сразу execve службы. Как
 * ядро, личность должна пережить execve: guest_ids_child_env() отдаёт ТЕКУЩУЮ
 * модель строками окружения для ребёнка — GUEST_UID (настоящий), GUEST_EUID
 * (действующий), GUEST_GID, GUEST_EGID и GUEST_GROUPS (дополнительные группы
 * через запятую, «1004,1007»), а модель ребёнка читает их при старте. Без
 * GUEST_EUID/GUEST_EGID/GUEST_GROUPS всё как прежде; а без GUEST_FWINIT=1 модель
 * их не читает вовсе (задай их кто угодно — действующие номера равны настоящим,
 * групп нет).
 */
#include "qemu/osdep.h"
#include "qemu.h"
#include "guest_fwinit.h"
#include "user-internals.h"

#include "guest_ids.h"

typedef struct {
    uid_t ruid, euid, suid, fsuid;
    gid_t rgid, egid, sgid, fsgid;
    int ngroups;
    gid_t groups[GUEST_NGROUPS];
    /* Права: три набора по два слова (версия 3 UAPI). */
    uint32_t eff[2], perm[2], inh[2];
    int keepcaps;
    uint32_t securebits;
} GuestCreds;

static GuestCreds C;
static QemuMutex lock;
static bool inited;

/* Выкладывает личность соседям; определена ниже, зовётся уже из ids_init. */
static void creds_publish_locked(void);

static int env_id(const char *name, int def)
{
    const char *e = getenv(name);

    if (!e || !*e) {
        return def;
    }
    return atoi(e);
}

/* GUEST_GROUPS=«1004,1007» — дополнительные группы; нет или пусто — ни одной. */
static int env_groups(gid_t *out, int max)
{
    const char *e = getenv("GUEST_GROUPS");
    int n = 0;

    while (e && *e && n < max) {
        char *end;
        long v = strtol(e, &end, 10);

        if (end == e) {
            break;
        }
        out[n++] = (gid_t)v;
        e = *end == ',' ? end + 1 : end;
    }
    return n;
}

static void ids_init(void)
{
    if (inited) {
        return;
    }
    qemu_mutex_init(&lock);
    C.ruid = env_id("GUEST_UID", 0);
    C.rgid = env_id("GUEST_GID", 0);
    /*
     * ★ После execve ядро хранит настоящий и действующий номера как были, а
     * сохранённый и файловый делает равными действующему (файл без setuid).
     * Без GUEST_EUID/GUEST_EGID действующий равен настоящему — как прежде.
     * ⚠️ GUEST_EUID, GUEST_EGID и GUEST_GROUPS читаются ТОЛЬКО в режиме «init
     * прошивки» (GUEST_FWINIT=1, патч 0079): без него «как прежде» строго.
     */
    if (guest_fwinit()) {
        C.euid = C.suid = C.fsuid = env_id("GUEST_EUID", C.ruid);
        C.egid = C.sgid = C.fsgid = env_id("GUEST_EGID", C.rgid);
        C.ngroups = env_groups(C.groups, GUEST_NGROUPS);
    } else {
        C.euid = C.suid = C.fsuid = C.ruid;
        C.egid = C.sgid = C.fsgid = C.rgid;
        C.ngroups = 0;
    }
    /*
     * У root полный набор прав. Иначе capget вернул бы нули, и проверка
     * «а есть ли у меня CAP_*» внутри гостя дала бы ложный отрицательный
     * ответ там, где на живом устройстве ответ положительный.
     */
    if (C.euid == 0) {
        C.eff[0] = C.eff[1] = 0xffffffffu;
        C.perm[0] = C.perm[1] = 0xffffffffu;
    }
    C.inh[0] = C.inh[1] = 0;
    C.keepcaps = 0;
    C.securebits = 0;
    inited = true;
    creds_publish_locked();
}

/*
 * ★ Личность видна и СОСЕДНИМ гостевым процессам.
 *
 * Зигота решает, что вправе делать проситель, по SO_PEERCRED — то есть по
 * НАСТОЯЩИМ правам соединившегося процесса, как их видит ядро хозяина. У нас
 * это uid приложения, а не 1000, и первый же запуск приложения обрывается:
 *
 *   E Zygote   Zygote security policy prevents request:
 *   E Zygote   ZygoteSecurityException: App UIDs may not specify uid's or gid's
 *                 at ZygoteConnection.applyUidSecurityPolicy(ZygoteConnection.java:552)
 *   E Process  Starting VM process through Zygote failed
 *   E ActivityManager  Failure starting process com.android.systemui
 *
 * Врать «всегда root» нельзя: это молча выключило бы ВСЕ проверки прав
 * просителя внутри гостя, а такие тихие подмены потом стоят часов. Поэтому
 * каждый процесс qemu выкладывает свою личность в файл, названный его
 * ХОЗЯЙСКИМ номером процесса, — а номер в SO_PEERCRED ядро отдаёт настоящий,
 * и он указывает ровно на тот же процесс qemu. Получается точный ответ без
 * всякого общего состояния и без рукопожатий в потоке данных.
 *
 * Каталог задаётся переменной GUEST_CREDS. Нет её — возможность выключена и
 * SO_PEERCRED идёт как есть.
 */
static void creds_publish_locked(void)
{
    const char *dir = getenv("GUEST_CREDS");
    char path[PATH_MAX];
    char buf[64];
    int fd, n;

    if (!dir || !*dir) {
        return;
    }
    if (snprintf(path, sizeof path, "%s/%d", dir, (int)getpid()) >= (int)sizeof path) {
        return;
    }
    /*
     * ⚠️ Пишем целиком и с нуля: файл читают другие процессы в любой момент,
     * а запись короче прежней оставила бы хвост от старой личности.
     */
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return;
    }
    n = snprintf(buf, sizeof buf, "%d %d\n", (int)C.euid, (int)C.egid);
    if (write(fd, buf, n) != n) {
        /* Молча: это вспомогательные сведения, а не работа гостя. */
    }
    close(fd);
}

int guest_ids_peercred(int pid, int *uid, int *gid)
{
    const char *dir = getenv("GUEST_CREDS");
    char path[PATH_MAX];
    char buf[64];
    int fd, n, u = -1, g = -1;

    if (!dir || !*dir || pid <= 0) {
        return 0;
    }
    if (snprintf(path, sizeof path, "%s/%d", dir, pid) >= (int)sizeof path) {
        return 0;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) {
        return 0;
    }
    buf[n] = 0;
    if (sscanf(buf, "%d %d", &u, &g) != 2 || u < 0 || g < 0) {
        return 0;
    }
    *uid = u;
    *gid = g;
    return 1;
}

/*
 * ⚠️ Захват без ветвления на «уже готово»: ids_init вызывается из каждой точки
 * входа, а первый вызов приходит из однопоточного пролога (getuid в линкере),
 * задолго до появления гостевых потоков.
 */
#define ENTER() do { ids_init(); qemu_mutex_lock(&lock); } while (0)
/* ⚠️ Выкладываем ПОД замком: иначе сосед прочтёт полуправку. */
#define LEAVE() do { creds_publish_locked(); qemu_mutex_unlock(&lock); } while (0)

/*
 * ★ Личность для ДОЧЕРНЕГО процесса при execve (режим «init прошивки», патч 0079).
 * Строки окружения кладутся в out (по GUEST_IDS_ENV_LEN байт каждая); возвращает
 * их число. Права ребёнок выводит сам: у root полный набор, у прочих пусто —
 * как после execve обычного файла.
 */
int guest_ids_child_env(char out[][GUEST_IDS_ENV_LEN], int max)
{
    char groups[GUEST_IDS_ENV_LEN - 14];
    size_t off = 0;
    int i, n = 0;

    if (max < GUEST_IDS_ENV_N) {
        return 0;
    }
    /*
     * ⚠️ Только чтение модели: ENTER()/LEAVE() здесь не годятся — LEAVE()
     * переписывает файл личности (O_TRUNC + write) на каждый execve, и сосед,
     * читающий его в этот миг, увидел бы пустой файл. Берём замок без публикации.
     */
    ids_init();
    qemu_mutex_lock(&lock);
    groups[0] = '\0';
    for (i = 0; i < C.ngroups; i++) {
        int w = snprintf(groups + off, sizeof groups - off, "%s%u",
                         i ? "," : "", (unsigned)C.groups[i]);

        if (w < 0 || (size_t)w >= sizeof groups - off) {
            groups[off] = '\0';     /* не влезло — берём сколько влезло */
            break;
        }
        off += (size_t)w;
    }
    snprintf(out[n++], GUEST_IDS_ENV_LEN, "GUEST_UID=%u", (unsigned)C.ruid);
    snprintf(out[n++], GUEST_IDS_ENV_LEN, "GUEST_EUID=%u", (unsigned)C.euid);
    snprintf(out[n++], GUEST_IDS_ENV_LEN, "GUEST_GID=%u", (unsigned)C.rgid);
    snprintf(out[n++], GUEST_IDS_ENV_LEN, "GUEST_EGID=%u", (unsigned)C.egid);
    snprintf(out[n++], GUEST_IDS_ENV_LEN, "GUEST_GROUPS=%s", groups);
    qemu_mutex_unlock(&lock);
    return n;
}

/* Эта строка окружения — из тех, что задаёт guest_ids_child_env? */
bool guest_ids_is_child_env(const char *e)
{
    static const char *const names[] = {
        "GUEST_UID=", "GUEST_EUID=", "GUEST_GID=", "GUEST_EGID=",
        "GUEST_GROUPS=",
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(names); i++) {
        if (strncmp(e, names[i], strlen(names[i])) == 0) {
            return true;
        }
    }
    return false;
}

int guest_ids_getuid(void)  { ids_init(); return C.ruid; }
int guest_ids_geteuid(void) { ids_init(); return C.euid; }
int guest_ids_getsuid(void) { ids_init(); return C.suid; }
int guest_ids_getfsuid(void){ ids_init(); return C.fsuid; }
int guest_ids_getgid(void)  { ids_init(); return C.rgid; }
int guest_ids_getegid(void) { ids_init(); return C.egid; }
int guest_ids_getsgid(void) { ids_init(); return C.sgid; }
int guest_ids_getfsgid(void){ ids_init(); return C.fsgid; }

/* Всемогущ ли гость сейчас. Проверяется до правки, как и в ядре. */
static bool privileged(void)
{
    return C.euid == 0;
}

/*
 * ★★★★★ ПРАВА, А НЕ ТОЛЬКО НУЛЕВОЙ UID.
 *
 * ⚠️ Из-за этого В СТЕНДЕ НЕ УСТАНАВЛИВАЛОСЬ НИ ОДНО ПРИЛОЖЕНИЕ, и выглядело
 * это как беда установщика, а не наша. В журнале было ровно одно внятное слово:
 *
 *     I PackageManager  Running dexopt on: com.vendor.game
 *     E installd        setgid(50190) failed in installd during dexopt
 *     W installd        DexInv: --- END '/data/app/….apk' --- status=0x4000
 *
 * Разгадка в том, как устроен сам installd. Он стартует под root, но сразу
 * ПОНИЖАЕТ себе личность до AID_INSTALL (1012) — и делает это аккуратно:
 * `prctl(PR_SET_KEEPCAPS, 1)`, `setgid(1012)`, `setuid(1012)`, а следом
 * `capset`, которым оставляет себе ровно пять прав: CAP_DAC_OVERRIDE,
 * CAP_CHOWN, CAP_FOWNER, CAP_SETUID и CAP_SETGID. Двумя последними он потом и
 * работает: перед dexopt ветвится и в потомке зовёт setgid/setuid на личность
 * приложения. В ядре это проходит по праву, а не по нулевому uid.
 *
 * Наша модель смотрела только `euid == 0`. Пока процесс был root, всё
 * сходилось; как только installd честно понизился — любая смена личности
 * стала отвечать отказом, dexopt выходил с кодом 64, и установка обрывалась.
 *
 * Теперь спрашиваем ДЕЙСТВУЮЩИЙ набор прав, как ядро. Права модель и так
 * ведёт (capget/capset), не хватало только этой проверки.
 */
#define GUEST_CAP_SETGID 6
#define GUEST_CAP_SETUID 7

static bool has_cap(int cap)
{
    return (C.eff[cap >> 5] & (1u << (cap & 31))) != 0;
}

static bool may_setuid(void) { return privileged() || has_cap(GUEST_CAP_SETUID); }
static bool may_setgid(void) { return privileged() || has_cap(GUEST_CAP_SETGID); }

int guest_ids_setuid(uid_t uid)
{
    int r = 0;

    ENTER();
    if (may_setuid()) {
        /*
         * ★ Ровно та тонкость, ради которой зигота и зовёт PR_SET_KEEPCAPS:
         * при setuid из root ядро сбрасывает права, ЕСЛИ keepcaps не выставлен.
         * Воспроизводим это, иначе система, положившаяся на сохранение прав,
         * увидит у себя не то, что ожидала.
         */
        /*
         * ⚠️ Права сбрасываются при ПЕРЕХОДЕ ИЗ ROOT, а не при любой смене
         * личности. Раньше здесь стояло просто «uid != 0», и это было
         * безобидно только потому, что менять личность мог один лишь root.
         * Теперь это может и обладатель CAP_SETUID (тот же installd под
         * AID_INSTALL), и для него сброс был бы неверен: в ядре процесс,
         * который уже не root, своих прав такой сменой не теряет.
         */
        int was_root = (C.euid == 0);

        C.ruid = C.euid = C.suid = C.fsuid = uid;
        if (was_root && uid != 0) {
            if (!C.keepcaps) {
                C.perm[0] = C.perm[1] = 0;
            }
            C.eff[0] = C.eff[1] = 0;
        }
    } else if (uid == C.ruid || uid == C.suid) {
        C.euid = C.fsuid = uid;
    } else {
        r = -EPERM;
    }
    LEAVE();
    return r;
}

int guest_ids_setgid(gid_t gid)
{
    int r = 0;

    ENTER();
    if (may_setgid()) {
        C.rgid = C.egid = C.sgid = C.fsgid = gid;
    } else if (gid == C.rgid || gid == C.sgid) {
        C.egid = C.fsgid = gid;
    } else {
        r = -EPERM;
    }
    LEAVE();
    return r;
}

int guest_ids_setreuid(uid_t ruid, uid_t euid)
{
    int r = 0;

    ENTER();
    if (!may_setuid() &&
        ((ruid != (uid_t)-1 && ruid != C.ruid && ruid != C.euid) ||
         (euid != (uid_t)-1 && euid != C.ruid && euid != C.euid &&
          euid != C.suid))) {
        r = -EPERM;
    } else {
        if (ruid != (uid_t)-1) {
            C.ruid = ruid;
        }
        if (euid != (uid_t)-1) {
            C.euid = C.fsuid = euid;
        }
        if (ruid != (uid_t)-1 || (euid != (uid_t)-1 && euid != C.ruid)) {
            C.suid = C.euid;
        }
    }
    LEAVE();
    return r;
}

int guest_ids_setregid(gid_t rgid, gid_t egid)
{
    int r = 0;

    ENTER();
    if (!may_setgid() &&
        ((rgid != (gid_t)-1 && rgid != C.rgid && rgid != C.egid) ||
         (egid != (gid_t)-1 && egid != C.rgid && egid != C.egid &&
          egid != C.sgid))) {
        r = -EPERM;
    } else {
        if (rgid != (gid_t)-1) {
            C.rgid = rgid;
        }
        if (egid != (gid_t)-1) {
            C.egid = C.fsgid = egid;
        }
        if (rgid != (gid_t)-1 || (egid != (gid_t)-1 && egid != C.rgid)) {
            C.sgid = C.egid;
        }
    }
    LEAVE();
    return r;
}

int guest_ids_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    int r = 0;

    ENTER();
    if (!may_setuid()) {
        uid_t want[3] = { ruid, euid, suid };
        int i;

        for (i = 0; i < 3; i++) {
            if (want[i] != (uid_t)-1 && want[i] != C.ruid &&
                want[i] != C.euid && want[i] != C.suid) {
                r = -EPERM;
                break;
            }
        }
    }
    if (r == 0) {
        if (ruid != (uid_t)-1) {
            C.ruid = ruid;
        }
        if (euid != (uid_t)-1) {
            C.euid = C.fsuid = euid;
        }
        if (suid != (uid_t)-1) {
            C.suid = suid;
        }
    }
    LEAVE();
    return r;
}

int guest_ids_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
    int r = 0;

    ENTER();
    if (!may_setgid()) {
        gid_t want[3] = { rgid, egid, sgid };
        int i;

        for (i = 0; i < 3; i++) {
            if (want[i] != (gid_t)-1 && want[i] != C.rgid &&
                want[i] != C.egid && want[i] != C.sgid) {
                r = -EPERM;
                break;
            }
        }
    }
    if (r == 0) {
        if (rgid != (gid_t)-1) {
            C.rgid = rgid;
        }
        if (egid != (gid_t)-1) {
            C.egid = C.fsgid = egid;
        }
        if (sgid != (gid_t)-1) {
            C.sgid = sgid;
        }
    }
    LEAVE();
    return r;
}

int guest_ids_setfsuid(uid_t fsuid)
{
    int old;

    ENTER();
    old = C.fsuid;
    if (may_setuid() || fsuid == C.ruid || fsuid == C.euid ||
        fsuid == C.suid || fsuid == C.fsuid) {
        C.fsuid = fsuid;
    }
    LEAVE();
    return old;               /* ядро всегда отдаёт прежнее, отказа нет */
}

int guest_ids_setfsgid(gid_t fsgid)
{
    int old;

    ENTER();
    old = C.fsgid;
    if (may_setgid() || fsgid == C.rgid || fsgid == C.egid ||
        fsgid == C.sgid || fsgid == C.fsgid) {
        C.fsgid = fsgid;
    }
    LEAVE();
    return old;
}

int guest_ids_getgroups(int size, gid_t *list)
{
    int n;

    ENTER();
    n = C.ngroups;
    if (size == 0) {
        LEAVE();
        return n;             /* «сколько их» — размер буфера не нужен */
    }
    if (size < n) {
        LEAVE();
        return -EINVAL;
    }
    memcpy(list, C.groups, (size_t)n * sizeof(gid_t));
    LEAVE();
    return n;
}

int guest_ids_setgroups(int size, const gid_t *list)
{
    ENTER();
    if (size < 0 || size > GUEST_NGROUPS) {
        LEAVE();
        return -EINVAL;
    }
    if (!may_setgid()) {
        LEAVE();
        return -EPERM;
    }
    if (size > 0) {
        memcpy(C.groups, list, (size_t)size * sizeof(gid_t));
    }
    C.ngroups = size;
    LEAVE();
    return 0;
}

/*
 * Смена владельца файла: хозяин отказывает, гость обязан считать, что вышло.
 *
 * installd прошивки заводит каталог пакета так:
 *
 *   mkdir(pkgdir, 0751); chmod(pkgdir, 0751); chown(pkgdir, uid, gid);
 *
 * и на отказе ЛЮБОГО шага делает unlink(pkgdir) и возвращает ошибку. Мы не
 * root, chown отдаёт EPERM — и каталоги данных всех пакетов прошивки исчезали
 * сразу после создания:
 *
 *   E installd        cannot chown dir '/data/data/com.android.settings': Operation not permitted
 *   W PackageManager  Unable to create data directory: /data/data/com.vendor.app
 *   E ActivityThread  Failed to find provider info for settings
 *
 * а без провайдера настроек system_server умирает в PowerManagerService.
 *
 * ⚠️ Настоящий владелец у файлов остаётся хозяйский (uid приложения). Гостю мы
 * пока не показываем то, что он «поставил»: stat отдаёт правду. Там, где
 * система СВЕРЯЕТ владельца (PackageManagerService сверяет владельца каталога
 * данных с uid пакета), это будет видно — и лечиться отдельно.
 */
int guest_ids_chown_forgive(int host_errno, const char *what)
{
    static bool told;

    if (host_errno != EPERM && host_errno != EACCES) {
        return 0;
    }
    if (!told) {
        told = true;
        qemu_log_mask(LOG_UNIMP,
                      "guest_ids: смену владельца хозяин не даёт (%s) — "
                      "гостю отвечаем успехом\n", what ? what : "?");
    }
    return 1;
}

/* Сколько слоёв прав в наборе: версия 1 — один, версии 2 и 3 — два. */
static int cap_items(uint32_t version)
{
    return version == _LINUX_CAPABILITY_VERSION_1 ? 1 : 2;
}

int guest_ids_capget(struct __user_cap_header_struct *hdr,
                   struct __user_cap_data_struct *data)
{
    int i, n;

    ENTER();
    /*
     * ⚠️ Ядро на неизвестной версии ПЕРЕЗАПИСЫВАЕТ поле version той, что
     * поддерживает, и возвращает EINVAL. Гость на это рассчитывает: bionic
     * пробует версию, читает ответ и повторяет. Ведём себя так же.
     */
    if (hdr->version != _LINUX_CAPABILITY_VERSION_1 &&
        hdr->version != _LINUX_CAPABILITY_VERSION_2 &&
        hdr->version != _LINUX_CAPABILITY_VERSION_3) {
        hdr->version = _LINUX_CAPABILITY_VERSION_3;
        LEAVE();
        return -EINVAL;
    }
    if (hdr->pid != 0 && hdr->pid != (int)getpid()) {
        LEAVE();
        return -ESRCH;        /* чужие процессы у нас не заведены */
    }
    if (data) {
        n = cap_items(hdr->version);
        for (i = 0; i < n; i++) {
            data[i].effective = C.eff[i];
            data[i].permitted = C.perm[i];
            data[i].inheritable = C.inh[i];
        }
    }
    LEAVE();
    return 0;
}

int guest_ids_capset(struct __user_cap_header_struct *hdr,
                   const struct __user_cap_data_struct *data)
{
    int i, n;

    ENTER();
    if (hdr->version != _LINUX_CAPABILITY_VERSION_1 &&
        hdr->version != _LINUX_CAPABILITY_VERSION_2 &&
        hdr->version != _LINUX_CAPABILITY_VERSION_3) {
        hdr->version = _LINUX_CAPABILITY_VERSION_3;
        LEAVE();
        return -EINVAL;
    }
    if (hdr->pid != 0 && hdr->pid != (int)getpid()) {
        LEAVE();
        return -EPERM;        /* менять права чужому нельзя и в ядре */
    }
    if (!data) {
        LEAVE();
        return -EFAULT;
    }
    n = cap_items(hdr->version);
    for (i = 0; i < n; i++) {
        /*
         * Ядро требует, чтобы новый набор не выходил за прежний permitted.
         * Проверку повторяем: система на неё опирается — zygote ставит
         * system_server'у урезанный набор и ждёт, что он именно урежется.
         */
        if ((data[i].permitted & ~C.perm[i]) ||
            (data[i].effective & ~data[i].permitted)) {
            LEAVE();
            return -EPERM;
        }
    }
    for (i = 0; i < n; i++) {
        C.eff[i] = data[i].effective;
        C.perm[i] = data[i].permitted;
        C.inh[i] = data[i].inheritable;
    }
    if (n == 1) {
        C.eff[1] = C.perm[1] = C.inh[1] = 0;
    }
    LEAVE();
    return 0;
}

int guest_ids_prctl(int option, unsigned long a2, unsigned long a3,
                  unsigned long a4, unsigned long a5, long *out)
{
    (void)a3; (void)a4; (void)a5;

    switch (option) {
    case PR_SET_KEEPCAPS:
        /*
         * ★ Тот самый вызов, на котором умирал system_server. У хозяина он
         * отдаёт EPERM: зигота Android запирает securebits процессам
         * приложений. Здесь он просто взводит флаг в НАШЕЙ модели.
         */
        ENTER();
        if (a2 != 0 && a2 != 1) {
            LEAVE();
            *out = -EINVAL;
            return 1;
        }
        C.keepcaps = (int)a2;
        LEAVE();
        *out = 0;
        return 1;

    case PR_GET_KEEPCAPS:
        ENTER();
        *out = C.keepcaps;
        LEAVE();
        return 1;

    case PR_SET_SECUREBITS:
        ENTER();
        if (!privileged()) {
            LEAVE();
            *out = -EPERM;
            return 1;
        }
        C.securebits = (uint32_t)a2;
        LEAVE();
        *out = 0;
        return 1;

    case PR_GET_SECUREBITS:
        ENTER();
        *out = C.securebits;
        LEAVE();
        return 1;

    case PR_CAPBSET_READ:
        /* Ограничивающий набор у нас полный: гость волен ронять что хочет. */
        *out = (a2 <= 63) ? 1 : -EINVAL;
        return 1;

    case PR_CAPBSET_DROP:
        ENTER();
        *out = privileged() ? 0 : -EPERM;
        LEAVE();
        return 1;

    default:
        return 0;             /* не про личность — пусть идёт своим путём */
    }
}
