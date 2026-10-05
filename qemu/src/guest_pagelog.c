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
// Changed: 2026-09-15 … 2026-10-05

/* guest_pagelog.c — слежка за правами ИСПОЛНЯЕМЫХ страниц гостя.
 *
 * Зачем. Браузер прошивки с включённым JavaScript падает прыжком в память,
 * которой гостю уже не выдавали:
 *
 *   Fatal signal 11 (SIGSEGV) at 0x3a0cf960, thread (WebViewCoreThre)
 *   PC=0x3a0cf960 [гость: страница не выдавалась] в 33a19000-3c000000 ---p
 *   LR=0x3c78d1b1 [гость: rw-]                    в 3c700000-3c800000 rw-p
 *   след по стеку: libjs.so ×5, дальше libbrowsercore.so ×7
 *
 * Права в квадратных скобках — это ПАМЯТЬ ГЛАЗАМИ ТРАНСЛЯТОРА (page_get_flags).
 * Транслятор НЕ переводит код со страницы без PAGE_EXEC — значит страница
 * когда-то была исполняемой и права потеряла. Вопрос ровно один: каким вызовом
 * движок её отобрал и сбросил ли транслятор при этом свои переводы.
 *
 * Ответ должен быть один из трёх, и журнал их различает:
 *
 *   1. Строка про эту страницу есть, «переводы=сброшены» — дыра не здесь,
 *      смотреть дальше (кто прыгнул).
 *   2. Строка есть, «переводы=ОСТАЛИСЬ» — вот она, дыра.
 *   3. Строк про эту страницу нет вовсе — движок отбирает её путём, который
 *      мимо page_set_flags, и надо смотреть madvise (он тут тоже есть).
 *
 * ⚠️ Почему слежка именно в page_set_flags: это ЕДИНСТВЕННАЯ воронка, через
 * которую в qemu проходят и mmap, и munmap, и mprotect, и mremap. Ловить
 * каждый вызов по отдельности незачем, а различить их можно по виду записи:
 * «заново=да» — это mmap (PAGE_RESET), пустые новые права — munmap, всё
 * остальное — mprotect.
 *
 * ⚠️ Почему только страницы с PAGE_EXEC: иначе сюда попадёт КАЖДЫЙ mmap гостя,
 * а их за загрузку сотни тысяч. Исполняемых же — единицы на библиотеку.
 *
 * Включается переменной GUEST_PAGE_LOG (путь к файлу), как GUEST_NET_LOG и
 * GUEST_ASHMEM_LOG. Без неё ни одной лишней команды на горячем пути нет:
 * guest_plog_on() проверяет указатель.
 */
#include "qemu/osdep.h"
#include "qemu.h"
/* ★ page_protect и замок mmap — см. взведение сторожа в guest_check_code. */
#include "exec/exec-all.h"

#include "guest_pagelog.h"

static FILE *g_plog;
static int plog_tried;

int guest_plog_on(void)
{
    if (!plog_tried) {
        const char *path = getenv("GUEST_PAGE_LOG");

        plog_tried = 1;
        if (path && *path) {
            g_plog = fopen(path, "ae");
        }
    }
    return g_plog != NULL;
}

void guest_plog(const char *fmt, ...)
{
    va_list ap;

    if (!guest_plog_on()) {
        return;
    }
    /*
     * ⚠️ Номер процесса обязателен: журнал ОДИН на все полсотни гостевых
     * процессов, они пишут в него одновременно. Дозапись (O_APPEND) + сброс
     * после каждой строки держат строки целыми.
     */
    fprintf(g_plog, "[pid=%d] ", (int)getpid());
    va_start(ap, fmt);
    vfprintf(g_plog, fmt, ap);
    va_end(ap);
    fputc('\n', g_plog);
    fflush(g_plog);
}

const char *guest_plog_prot(int flags, char *buf)
{
    if (!(flags & PAGE_VALID)) {
        return "нет";
    }
    buf[0] = (flags & PAGE_READ)  ? 'r' : '-';
    buf[1] = (flags & PAGE_WRITE) ? 'w' : '-';
    buf[2] = (flags & PAGE_EXEC)  ? 'x' : '-';
    /*
     * Четвёртая буква — «сквозная» (PAGE_PASSTHROUGH). Она решает судьбу
     * madvise(MADV_DONTNEED): без неё qemu МОЛЧА НИЧЕГО НЕ ДЕЛАЕТ и отвечает
     * гостю успехом (его собственное решение, см. комментарий в target_madvise).
     */
    buf[3] = (flags & PAGE_PASSTHROUGH) ? 'p' : '.';
    buf[4] = 0;
    return buf;
}

/* Столько блоков помним. Степень двойки — чтобы обойтись маской. */
#define GUEST_TRACE_N 32

static __thread uint64_t trace_pc[GUEST_TRACE_N];
static __thread unsigned trace_sz[GUEST_TRACE_N];
static __thread unsigned trace_i;

void guest_trace_push(uint64_t pc, unsigned size)
{
    unsigned i = trace_i++ & (GUEST_TRACE_N - 1);

    trace_pc[i] = pc;
    trace_sz[i] = size;
    /* ★ Сторож изменений — сверка раз в 2048 входов, см. guest_watch_tick. */
    guest_watch_tick();
}

int guest_trace_get(int back, uint64_t *pc, unsigned *size)
{
    unsigned i;

    if (back < 0 || back >= GUEST_TRACE_N || (unsigned)back >= trace_i) {
        return 0;
    }
    i = (trace_i - 1 - back) & (GUEST_TRACE_N - 1);
    *pc = trace_pc[i];
    *size = trace_sz[i];
    return 1;
}

int guest_plog_smc(void)
{
    static int smc = -1;

    if (smc < 0) {
        const char *v = getenv("GUEST_PAGE_LOG_SMC");

        smc = (v && *v && *v != '0') ? 1 : 0;
    }
    return smc && guest_plog_on();
}

/*
 * ★★★ Снимок кольца — В МИГ ОТКАЗА, а не в отчёте о падении.
 *
 * ⚠️ Почему не в отчёте. Первая попытка печатала кольцо из dump_core_and_abort,
 * и толку не было совсем: между негодным прыжком и смертью процесса успевает
 * отработать СОБСТВЕННЫЙ обработчик падения прошивки (тот самый, что пишет
 * «Fatal signal 11 … thread … (WebViewCoreThre)»), а он затаптывает всё
 * кольцо. Выглядело это так:
 *
 *   блок-0 (4 б)=0x4081f488   ← 2777 df00 27ad df00 = movs r7,#119/#173; svc 0
 *   блок-1..11                  /system/bin/linker
 *
 * то есть последнее, что видно, — возврат из обработчика сигнала.
 *
 * Здесь же снимок берётся там, где транслятор отказался выбирать команду, —
 * до всякого обработчика.
 *
 * Отображение ищем в /proc/self/maps: гостевая память лежит в адресном
 * пространстве самого qemu, поэтому имя файла и смещение в нём берутся оттуда
 * прямо (тот же приём, что в отчёте о падении).
 */
static void plog_where(const char *tag, uint64_t a, unsigned size)
{
    FILE *m = fopen("/proc/self/maps", "r");
    char line[512], pb[8];

    if (!m) {
        guest_plog("%s=0x%08lx (%u б) [%s]", tag, (unsigned long)a, size,
                 guest_plog_prot(page_get_flags(a), pb));
        return;
    }
    while (fgets(line, sizeof line, m)) {
        unsigned long lo, hi;
        char *nl;

        if (sscanf(line, "%lx-%lx", &lo, &hi) != 2 || a < lo || a >= hi) {
            continue;
        }
        nl = strchr(line, '\n');
        if (nl) {
            *nl = 0;
        }
        guest_plog("%s=0x%08lx (%u б, +0x%lx) [%s] в %s", tag, (unsigned long)a,
                 size, (unsigned long)(a - lo),
                 guest_plog_prot(page_get_flags(a), pb), line);
        fclose(m);
        return;
    }
    fclose(m);
    guest_plog("%s=0x%08lx (%u б) [%s] — вне отображений", tag, (unsigned long)a,
             size, guest_plog_prot(page_get_flags(a), pb));
}

/*
 * ★★★ Снимок СТРАНИЦЫ КОДА, из которой ушёл негодный переход.
 *
 * Зачем целая страница, а не десяток байт: по одной команде не отличить
 * «движок породил негодный код» от «память испортилась». На целой странице это
 * видно сразу — соседние переходы либо все осмысленные (тогда испорчена одна
 * команда), либо мусор (тогда испорчен кусок памяти).
 *
 * Пишется ОДИН раз на процесс, рядом с журналом, файлом `<журнал>.dump`, и
 * разбирается на Маке обычным дизассемблером:
 *   llvm-objdump -D -b binary -m arm --adjust-vma=0x<основание>
 */
static void dump_code_page(uint64_t pc)
{
    static int done;
    const char *path = getenv("GUEST_PAGE_LOG");
    uint64_t base = pc & ~0xfffULL;
    char name[512];
    FILE *f;

    if (done || !path || !*path) {
        return;
    }
    done = 1;
    if (!(page_get_flags(base) & PAGE_READ)) {
        guest_plog("   страницу 0x%08lx снять нельзя: читать её не дают",
                 (unsigned long)base);
        return;
    }
    snprintf(name, sizeof name, "%s.dump", path);
    f = fopen(name, "we");
    if (!f) {
        return;
    }
    fwrite(g2h_untagged((abi_ulong)base), 1, 4096, f);
    fclose(f);
    guest_plog("   ★ страница кода 0x%08lx снята в %s (4096 б)",
             (unsigned long)base, name);
}

/* Последняя просмотренная область и счёт просмотров — для отчёта о падении. */
static uint64_t seen_lo, seen_hi;
static unsigned long seen_n;
static int watch_n;            /* сторож изменений, определения ниже */
static int watch_old(uint64_t addr, uint32_t *val);
static int watch_old(uint64_t addr, uint32_t *val);

/*
 * ★★★ Снимок ОБЪЕКТА КОДА целиком — по промежутку, который назвал сам гость.
 *
 * Промежуток из `cacheflush` — это в точности область команд объекта Code,
 * который движок JavaScript только что записал (CPU::FlushICache(instruction_start,
 * instruction_size)). Берём его с запасом с обеих сторон: перед началом лежит
 * заголовок объекта, после конца — таблицы (безопасных точек, обратных дуг),
 * а по ним видно, что это за код.
 *
 * Разбирать на Маке:
 *   llvm-mc --disassemble --triple=armv7-none-linux-androideabi
 * или своим разбором слов (см. tools/), зная основание из журнала.
 */
static void dump_code_range(uint64_t from, uint64_t to)
{
    static int done;
    const char *path = getenv("GUEST_PAGE_LOG");
    char name[512];
    FILE *f;
    uint64_t a, lo, hi;

    if (done || !path || !*path) {
        return;
    }
    done = 1;
    lo = (from > 0x400 ? from - 0x400 : 0) & ~3ULL;
    hi = (to + 0x800) & ~3ULL;
    snprintf(name, sizeof name, "%s.obj", path);
    f = fopen(name, "we");
    if (!f) {
        return;
    }
    for (a = lo; a < hi; a += 4) {
        uint32_t w = 0;

        if (page_get_flags(a) & PAGE_READ) {
            w = *(const uint32_t *)g2h_untagged((abi_ulong)a);
        }
        fwrite(&w, 4, 1, f);
    }
    fclose(f);
    guest_plog("   ★ объект кода 0x%08lx-0x%08lx снят в %s (%lu б)",
             (unsigned long)lo, (unsigned long)hi, name,
             (unsigned long)(hi - lo));
}

void guest_trace_dump(void)
{
    uint64_t pc;
    unsigned size;
    int k;

    if (!guest_plog_on()) {
        return;
    }
    /*
     * ★ Смотрели ли мы вообще ту область, где стоит поломка. Без этой строки
     * «сканер ничего не нашёл» ничего не значит: он мог туда не заглядывать.
     */
    if (guest_trace_get(0, &pc, &size)) {
        guest_plog("   просмотров кода: %lu, последняя область 0x%08lx-0x%08lx, "
                 "наблюдаемых слов %d; блок-0 %s этой области",
                 seen_n, (unsigned long)seen_lo, (unsigned long)seen_hi,
                 watch_n,
                 (pc >= seen_lo && pc < seen_hi) ? "ВНУТРИ" : "СНАРУЖИ");
    }
    /*
     * ★★★★★ ЧЕМ СЛОВО БЫЛО ДО ПОРЧИ.
     *
     * Сверка по кругу (guest_watch_tick) не успевает: слово пишется и
     * исполняется за считаные блоки, раньше очередного круга. Зато СПИСОК
     * наблюдаемых значений свежий — он обновляется при каждом чистом
     * просмотре области. Достаём прежнее значение прямо здесь, в миг отказа.
     */
    if (guest_trace_get(0, &pc, &size) && size >= 4) {
        uint64_t w = pc + size - 4;
        uint32_t was;

        if (watch_old(w, &was)) {
            uint32_t now = (page_get_flags(w) & PAGE_READ)
                ? *(const uint32_t *)g2h_untagged((abi_ulong)w) : 0;

            guest_plog("   ★★★★★ слово 0x%08lx: БЫЛО %08x, СТАЛО %08x",
                     (unsigned long)w, was, now);
        } else {
            guest_plog("   слова 0x%08lx среди наблюдаемых нет (в списке %d)",
                     (unsigned long)w, watch_n);
        }
    }
    for (k = 0; k < 12 && guest_trace_get(k, &pc, &size); k++) {
        char tag[32];

        snprintf(tag, sizeof tag, "   блок-%d", k);
        plog_where(tag, pc, size);
    }
    /*
     * Байты ХВОСТА самого свежего блока: там и стоит команда, отдавшая
     * управление. Читаем прямо из памяти гостя — она наша.
     */
    if (guest_trace_get(0, &pc, &size) && size && (page_get_flags(pc) & PAGE_READ)) {
        uint64_t from = (pc + size) & ~1ULL;
        char buf[128];
        int n = 0;
        uint64_t i;

        if (from >= 16) {
            from -= 16;
        }
        for (i = from; i <= (uint64_t)((pc + size) & ~1ULL) && n < 110; i += 2) {
            n += snprintf(buf + n, sizeof buf - n, " %04x",
                          *(const uint16_t *)g2h_untagged((abi_ulong)i));
        }
        guest_plog("   байты хвоста блока-0 (0x%08lx-0x%08lx):%s",
                 (unsigned long)from, (unsigned long)((pc + size) & ~1ULL), buf);
        dump_code_page(pc);
    }
}

/*
 * Пределы libdvm.so — один раз на процесс.
 *
 * ⚠️ Зачем отсекать Dalvik. Первый заход просматривал промежуток любого
 * cacheflush и дал 3156 «негодных переходов», все до одного из libdvm.so:
 * в кэше кода Dalvik между командами лежат ДАННЫЕ (ячейки сцепления,
 * литералы), и слепой просмотр принимает их за переходы. У движка JavaScript объект кода
 * сплошной, поэтому там ложных срабатываний нет.
 */
static int dvm_known;
static unsigned long dvm_lo, dvm_hi;

static int from_dalvik(uint64_t lr)
{
    if (!dvm_known) {
        FILE *m = fopen("/proc/self/maps", "r");
        char line[512];

        dvm_known = 1;
        if (m) {
            while (fgets(line, sizeof line, m)) {
                unsigned long lo, hi;

                if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 &&
                    strstr(line, "libdvm.so")) {
                    if (!dvm_lo || lo < dvm_lo) {
                        dvm_lo = lo;
                    }
                    if (hi > dvm_hi) {
                        dvm_hi = hi;
                    }
                }
            }
            fclose(m);
        }
    }
    return dvm_lo && lr >= dvm_lo && lr < dvm_hi;
}

/*
 * Один негодный переход в промежутке. Возвращает адрес или 0.
 *
 * ⚠️⚠️ ПОДПИСЬ ОБЯЗАТЕЛЬНА. Первый заход искал «любое слово, похожее на переход
 * в неотображённую память», и утонул в ложных: 3156 срабатываний в кэше кода
 * Dalvik и ещё 333 в пулах констант самого движка JavaScript — там между командами лежат
 * данные (теговые указатели вида 0x7a016f6d), а разряды 27..25 у них те же.
 *
 * Поэтому берём ровно нашу подпись: слово стоит СРАЗУ ПОСЛЕ `blx ip`
 * (e12fff3c). Это метка «готово» барьера записи движка JavaScript — место заведомо
 * исполняемое, данных там не бывает.
 */
static uint64_t bad_branch_in(uint64_t from, uint64_t to, uint32_t *word,
                              uint32_t *target)
{
    uint64_t a;

    for (a = (from & ~3ULL) + 4; a + 4 <= to; a += 4) {
        uint32_t w, tgt;
        int32_t imm;

        if (!(page_get_flags(a) & PAGE_READ)) {
            a = (a | 0xfff) - 3;
            continue;
        }
        /*
         * Подпись: перед словом — blx ip.
         *
         * ⚠️ Читаемость ПРЕДЫДУЩЕГО слова проверять обязательно. Без этой
         * проверки сканер, перешагнув нечитаемую страницу, лез за её конец и
         * ронял сам qemu — а с ним и гостевой процесс. Поймано на живом
         * стенде: система поднималась на 17 процессов вместо полусотни.
         */
        if (!(page_get_flags(a - 4) & PAGE_READ) ||
            *(const uint32_t *)g2h_untagged((abi_ulong)(a - 4)) != 0xe12fff3cu) {
            continue;
        }
        w = *(const uint32_t *)g2h_untagged((abi_ulong)a);
        if (((w >> 25) & 7) != 5) {      /* b/bl: разряды 27..25 = 101 */
            continue;
        }
        imm = (int32_t)(w << 8) >> 6;    /* знаковое imm24, умноженное на 4 */
        tgt = (uint32_t)(a + 8 + imm);
        /*
         * ⚠️⚠️★ ПРОВЕРЯТЬ НАДО ИСПОЛНЯЕМОСТЬ, А НЕ «ОТОБРАЖЕНА ЛИ ПАМЯТЬ».
         *
         * Здесь стояло `PAGE_VALID`, и это СБИЛО ВЕСЬ РАЗБОР на полдня: цель
         * негодного перехода попадает в отображённый файл шрифта (права r--),
         * память там есть, и сканер считал такой переход нормальным. Отсюда
         * вывод «в миг сброса кэша код ещё цел» — и ложная версия о порче
         * слова. На деле слово такое С САМОГО НАЧАЛА: сторож изменений потом
         * прямо сказал «БЫЛО ea800240, СТАЛО ea800240».
         */
        if (page_get_flags(tgt) & PAGE_EXEC) {
            continue;
        }
        *word = w;
        *target = tgt;
        return a;
    }
    return 0;
}

/* ★ Сторож изменений — определения ниже по файлу (см. разбор там же). */
static void watch_fill(uint64_t lo, uint64_t hi);
static int watch_said;
static unsigned long watch_fills;

/*
 * ★★★ ПРОВЕРКА КОДА В МИГ, КОГДА ГОСТЬ ПРОСИТ СБРОСИТЬ КЭШ КОМАНД.
 *
 * Зачем. Снимок страницы показал: в сгенерированном коде движка JavaScript ровно ОДНО слово
 * негодное — безусловный переход на 32 МБ вниз, в память, которой у процесса
 * нет и не было:
 *
 *   +0x0ac: 0a000001   beq  →  +0x0b8      ⎫ проверка страничных признаков
 *   +0x0b0: e59fc244   ldr  ip,[pc,#0x244] ⎬ барьер записи движка (RecordWrite:
 *   +0x0b4: e12fff3c   blx  ip             ⎭ CheckPageFlag ×2 + CallStub)
 *   +0x0b8: ea800240   b    −32 МБ         ← сюда сходятся ТРИ перехода
 *
 * Остальные 31 переход страницы — внутри объекта. Значит это не протухший
 * перевод (транслятор исполнил ровно то, что лежит в памяти) и не сдвиг всего
 * объекта, а испорченное одно слово.
 *
 * ⚠️ Просматривать ТОЛЬКО названный промежуток оказалось мало: слово в нём не
 * появлялось ни разу, то есть портится оно не в тот сброс, которым его
 * записали. Поэтому у сбросов НЕ ИЗ DALVIK просматривается вся область кода
 * целиком — так первый же сброс после порчи её и покажет, а вместе с ней
 * адрес возврата в libjs.so.
 */
void guest_check_code(uint64_t start, uint64_t end, uint64_t lr, uint64_t pc)
{
    /* Больше четверти мегабайта за раз не смотрим: это уже не правка кода. */
    const uint64_t kMax = 256 * 1024;
    static uint64_t prev_lr, prev_start, prev_end;
    static unsigned long prev_n;
    static int said;
    uint64_t a, lo, hi;
    uint32_t w = 0, tgt = 0;

    if (!guest_plog_on()) {
        return;
    }
    /*
     * ★ Пропуски тоже записываем. Иначе «сброса на этот адрес не было»
     * ничего не значит: он мог быть и отсеяться здесь.
     */
    if (end <= start || end - start > kMax) {
        guest_plog("сброс ПРОПУЩЕН (величина) 0x%08lx-0x%08lx, возврат 0x%08lx",
                 (unsigned long)start, (unsigned long)end, (unsigned long)lr);
        return;
    }
    if (from_dalvik(lr)) {
        return;
    }

    /*
     * Границы области кода — расширяем от названного промежутка по правам,
     * пока страницы исполняемые. Потолок — два мегабайта: у движка JavaScript кусок кода
     * ровно один мегабайт.
     */
    lo = start & ~0xfffULL;
    hi = (end + 0xfff) & ~0xfffULL;
    while (lo > 0x1000 && hi - lo < 2 * 1024 * 1024 &&
           (page_get_flags(lo - 0x1000) & PAGE_EXEC)) {
        lo -= 0x1000;
    }
    while (hi - lo < 2 * 1024 * 1024 && (page_get_flags(hi) & PAGE_EXEC)) {
        hi += 0x1000;
    }

    a = bad_branch_in(lo, hi, &w, &tgt);
    if (!a) {
        /*
         * Код цел. Запоминаем этот сброс: когда порча всё-таки появится,
         * она произошла МЕЖДУ ним и следующим, и виновата та работа движка JavaScript,
         * что шла в промежутке.
         */
        prev_lr = lr;
        prev_start = start;
        prev_end = end;
        prev_n++;
        seen_lo = lo;
        seen_hi = hi;
        seen_n++;
        /*
         * ★ Пишем КАЖДЫЙ сброс кэша не из Dalvik. Их за всю работу около
         * тысячи — журнал не заплывёт, зато видно, попадал ли под сброс тот
         * объект кода, который потом падает. Сейчас похоже, что НЕТ: слова из
         * него не оказалось среди наблюдаемых, хотя область просматривалась.
         */
        guest_plog("сброс кэша 0x%08lx-0x%08lx (область 0x%08lx-0x%08lx), "
                 "возврат 0x%08lx",
                 (unsigned long)start, (unsigned long)end,
                 (unsigned long)lo, (unsigned long)hi, (unsigned long)lr);
        /*
         * ★ Наполнить список наблюдаемых слов (сторож изменений ниже по
         * файлу). Область берём только большую — это кусок кода движка JavaScript, а не
         * мелкая правка; список обновляем изредка, он недёшев.
         */
        if (!watch_said && hi - lo >= 256 * 1024) {
            /*
             * Обновляем при КАЖДОМ чистом просмотре: так снимок всегда свежий,
             * и любое изменение между просмотром и сверкой будет поймано.
             */
            watch_fills++;
            watch_fill(lo, hi);
        }
        /*
         * ⚠️⚠️ ЗДЕСЬ СТОЯЛО ВЗВЕДЕНИЕ СТОРОЖА — И ЭТО НЕГОДНО.
         *
         * Замысел был закрыть дыру в стороже записи (патч 0052): он ловит
         * только записи, пришедшие отказом доступа, а отказ стоит лишь на
         * страницах, с которых уже переводили. Свежий код ещё не исполнялся,
         * защиты на нём нет, и запись проходит молча — при шести падениях
         * сторож не поймал ни одной.
         *
         * Пробовали снимать право записи со всех только что записанных
         * страниц прямо здесь (page_protect в цикле). ⛔ СТЕНД ПОСЛЕ ЭТОГО НЕ
         * ПОДНИМАЕТСЯ: 18 процессов вместо полусотни, интерфейса нет. Причина
         * простая — на страницы, в которые гость пишет ПОСТОЯННО, ставится
         * ловушка, и каждая запись уходит через сигнал; это не «медленнее», а
         * нежизнеспособно.
         *
         * Если возвращаться к этому, взводить надо ТОЧЕЧНО: только на ту
         * страницу, где уже видели подпись `blx ip` + осмысленный переход, и
         * только один раз.
         */
        return;
    }
    if (said) {
        return;         /* уже сказали; дальше только шум */
    }
    said = 1;
    guest_plog("   предыдущий ЧИСТЫЙ сброс был №%lu: 0x%08lx-0x%08lx, "
             "возврат 0x%08lx", prev_n, (unsigned long)prev_start,
             (unsigned long)prev_end, (unsigned long)prev_lr);
    plog_where("   предыдущий возврат", prev_lr, 0);
    guest_plog("★★ НЕГОДНЫЙ ПЕРЕХОД В КОДЕ: 0x%08lx = %08x -> 0x%08lx "
             "(память не отображена); область 0x%08lx-0x%08lx, "
             "сброс кэша 0x%08lx-0x%08lx",
             (unsigned long)a, w, (unsigned long)tgt,
             (unsigned long)lo, (unsigned long)hi,
             (unsigned long)start, (unsigned long)end);
    guest_plog("   негодное слово на +0x%lx от начала сброса "
             "(сброс 0x%08lx-0x%08lx, длина 0x%lx)",
             (unsigned long)(a - start), (unsigned long)start,
             (unsigned long)end, (unsigned long)(end - start));
    plog_where("   вернуться", lr, 0);
    plog_where("   исполнялось", pc, 0);
    dump_code_range(start, end);
}

/*
 * ★★★ Не ставить ловушку на запись в страницы кода (GUEST_NO_SMC).
 *
 * Разбор — у места применения, в accel/tcg/user-exec.c (page_protect) и в
 * linux-user/arm/cpu_loop.c (ARM_NR_cacheflush). Коротко: обычный путь
 * слежки за самоправкой кода повторяет гостевую запись повторным исполнением
 * команды, и это единственное место, где запись может пропасть. С этим ключом
 * ловушки нет, а переводы сбрасываются по явной просьбе гостя.
 */
int guest_no_smc(void)
{
    static int v = -1;

    if (v < 0) {
        const char *s = getenv("GUEST_NO_SMC");

        v = (s && *s && *s != '0') ? 1 : 0;
    }
    return v;
}

/*
 * ★★★★★ СТОРОЖ ИЗМЕНЕНИЙ: поймать миг, когда слово становится негодным.
 *
 * Зачем именно так. Три более простых подхода уже провалились, и каждый по
 * своей причине:
 *   • просмотр промежутка из cacheflush (0050) — в миг просьбы код ещё цел;
 *   • сторож записи через отказ доступа (0052) — свежий код ещё не под
 *     защитой, запись в него проходит молча;
 *   • ставить защиту на весь свежий код — стенд не поднимается (см. граблю).
 *
 * Здесь без всяких ловушек: запоминаем ЗНАЧЕНИЯ слов, стоящих сразу после
 * `blx ip` (их в области кода единицы тысяч), и время от времени сверяем.
 * Как только слово изменилось на переход в неотображённую память — печатаем
 * кольцо последних блоков перевода, а в нём и виден тот код, который писал.
 *
 * ⚠️ Кольцо полно только при выключенном сцеплении блоков (`cmd nochain`).
 */
/*
 * ⚠️ Потолок был 4096 — и этого НЕ ХВАТИЛО: список упирался в него, а нужное
 * слово лежит примерно на 80 % длины области и в список не попадало. Видно это
 * стало только по строке «наблюдаемых слов 4096» в отчёте о падении.
 */
#define WATCH_MAX 65536

static struct { uint32_t addr; uint32_t val; } watch[WATCH_MAX];
static unsigned long watch_tick;

static void watch_fill(uint64_t lo, uint64_t hi)
{
    uint64_t a;

    watch_n = 0;
    for (a = lo + 4; a + 4 <= hi && watch_n < WATCH_MAX; a += 4) {
        if (!(page_get_flags(a) & PAGE_READ) ||
            !(page_get_flags(a - 4) & PAGE_READ)) {
            a = (a | 0xfff) - 3;
            continue;
        }
        if (*(const uint32_t *)g2h_untagged((abi_ulong)(a - 4)) != 0xe12fff3cu) {
            continue;
        }
        watch[watch_n].addr = (uint32_t)a;
        watch[watch_n].val = *(const uint32_t *)g2h_untagged((abi_ulong)a);
        watch_n++;
    }
}

/* Прежнее значение наблюдаемого слова по адресу. */
static int watch_old(uint64_t addr, uint32_t *val)
{
    int i;

    for (i = 0; i < watch_n; i++) {
        if (watch[i].addr == (uint32_t)addr) {
            *val = watch[i].val;
            return 1;
        }
    }
    return 0;
}

/* Зовётся с каждым входом в блок перевода; сверка — раз в 8192 входов. */
void guest_watch_tick(void)
{
    int i;

    if (watch_said || watch_n == 0 || (++watch_tick & 0x1fff) != 0) {
        return;
    }
    for (i = 0; i < watch_n; i++) {
        uint32_t v, tgt;
        int32_t imm;

        if (!(page_get_flags(watch[i].addr) & PAGE_READ)) {
            continue;
        }
        v = *(const uint32_t *)g2h_untagged((abi_ulong)watch[i].addr);
        if (v == watch[i].val) {
            continue;
        }
        if (((v >> 25) & 7) != 5) {         /* стало не переходом — ладно */
            watch[i].val = v;
            continue;
        }
        imm = (int32_t)(v << 8) >> 6;
        tgt = watch[i].addr + 8 + imm;
        if (page_get_flags(tgt) & PAGE_EXEC) {   /* ★ не PAGE_VALID, см. выше */
            watch[i].val = v;
            continue;
        }
        watch_said = 1;
        guest_plog("★★★★★ ВОТ ОНА: слово 0x%08lx БЫЛО %08x, СТАЛО %08x "
                 "(переход в 0x%08lx — памяти нет)",
                 (unsigned long)watch[i].addr, watch[i].val, v,
                 (unsigned long)tgt);
        {
            /* Соседи — чтобы видеть, одно слово поменялось или кусок. */
            uint64_t a0 = (uint64_t)watch[i].addr - 16;
            char buf[160];
            int n = 0;
            uint64_t a;

            for (a = a0; a <= (uint64_t)watch[i].addr + 16; a += 4) {
                if (!(page_get_flags(a) & PAGE_READ)) {
                    break;
                }
                n += snprintf(buf + n, sizeof buf - n, " %08x",
                              *(const uint32_t *)g2h_untagged((abi_ulong)a));
            }
            guest_plog("   соседи 0x%08lx..:%s", (unsigned long)a0, buf);
        }
        guest_trace_dump();
        return;
    }
}

/*
 * ★★★ Выключить оптимизатор переводов целиком (GUEST_NO_TCGOPT).
 *
 * Опыт по разбору падения движка JavaScript; разбор — у места применения, в tcg/tcg.c.
 * Коротко: движок порождает переход со смещением, у которого лишним оказался
 * ровно один разряд, — это похоже на неверно вычисленное число. Одну такую
 * ошибку оптимизатора мы уже закрыли переходом на 8.2.4; этот ключ проверяет
 * весь оптимизатор разом.
 */
int guest_no_tcgopt(void)
{
    static int v = -1;

    if (v < 0) {
        const char *s = getenv("GUEST_NO_TCGOPT");

        v = (s && *s && *s != '0') ? 1 : 0;
    }
    return v;
}
