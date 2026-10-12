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

/* guest_fb.c — ioctl кадрового буфера для гостя.
 *
 * Зачем. За гостевым /dev/graphics/fb0 у нас стоит обычный файл: гость и
 * приложение отображают его вместе, и путь до экрана телефона на этом уже
 * проверен (см. guest/fbpaint.c, GuestView.kt). Но обычный файл не отвечает на
 * ioctl — а gralloc.default и SurfaceFlinger первым делом спрашивают у драйвера
 * геометрию: FBIOGET_VSCREENINFO и FBIOGET_FSCREENINFO. Без ответов SF не
 * поднимается вовсе.
 *
 * Отвечаем сами: умолчание 480x800, **16 бит RGB565**. Настоящие числа задаёт
 * профиль прошивки — на её родном разрешении и формате её ресурсы встают без
 * сдвигов.
 *
 * ★★ Почему именно 565, а не 8888. gralloc.default в 2.3 объявляет формат
 * кадрового буфера ЖЁСТКО: `dev->device.format = HAL_PIXEL_FORMAT_RGB_565`,
 * что бы ни ответил драйвер (в 4.x это стало условным). Мы сначала отвечали
 * 32 бита — и получили в буфере загрузочный экран изготовителя, нарисованный ДВАЖДЫ
 * рядом и в половину высоты: гость писал по 2 байта на точку в наши 4. Ровно
 * та картинка, по которой формат и опознаётся.
 *
 * ★ Одна страница на весь экран, БЕЗ двойной буферизации: `yres_virtual =
 * yres`. Тогда gralloc.default не делает переключения страниц вовсе (fb_post
 * просто копирует кадр в отображённую область), и приложению не нужно знать,
 * какая половина буфера сейчас показывается. Ценой возможного разрыва картинки
 * — зато без рассинхрона, который иначе пришлось бы отлаживать на живом экране.
 *
 * ★★ Р-144: ДВЕ СТРАНИЦЫ — только по просьбе стенда, переменной GUEST_FB_FLIP.
 * Её стенд ставит, когда композитор гостя рисует программно ПРЯМО в fb0 и
 * кадр показывает вид гостя (путь «кадровый буфер», у 1.x: загрузчик EGL до
 * моста не доходит). Композитор 1.x просит `yres_virtual = 2·yres` и, получив
 * отказ, пишет «page flipping not supported» и рисует в запасной буфер, а на
 * каждом кадре копирует его в fb0 целиком (300 КБ при 320x480) — копия под
 * трансляцией и разрыв, если вид гостя читает посреди копии. С переменной:
 *   * FBIOGET/FBIOPUT_VSCREENINFO отвечают `yres_virtual = 2·yres`, yoffset —
 *     показываемая страница; smem_len — обе страницы (файл стенд и так заводит
 *     на два кадра, Vm.FB_BYTES);
 *   * FBIOPUT_VSCREENINFO и FBIOPAN_DISPLAY с yoffset 0 или yres переключают
 *     показываемую страницу (1.x листает именно FBIOPUT_VSCREENINFO с
 *     FB_ACTIVATE_VBL, gralloc 2.3+ — FBIOPAN_DISPLAY);
 *   * какая страница показана, транслятор пишет в файл листания стенда — путь
 *     в самой переменной (хозяйский, вне дерева гостя): 16 байт, четыре слова
 *     little-endian {знак FB_FLIP_MAGIC, страница, номер листания, страниц}.
 *     Номер листания растёт на каждое переключение — по нему вид гостя
 *     (GuestView.kt) берёт новый кадр без сверки отпечатка, из той половины,
 *     которую гость велел показать. Файл общий для всех процессов гостя:
 *     номер читается из него (pread) и пишется назад, а описатель на миг —
 *     открыл, прочёл, записал, закрыл: гость наших описателей не видит.
 * Без переменной (мост, 2.3+) всё как было: одна страница, `yres_virtual =
 * yres`, FBIOPAN_DISPLAY ничего не делает.
 *
 * ⚠️ Вертикальной развёртки нет: FB_ACTIVATE_VBL здесь не ждёт её, а
 * переключает сразу. Окно разрыва остаётся — вид гостя копирует показанную
 * страницу (доли миллисекунды), а композитор как раз начинает рисовать в неё
 * следующий кадр, — но оно на порядки уже копии целого кадра в одну страницу.
 *
 * ⚠️ Формат задаётся ЗДЕСЬ, и приложение обязано показывать буфер тем же
 * форматом (Bitmap.Config.RGB_565). Разойдётся — картинка сдвоится или цвета
 * перевернутся.
 */
#include "qemu/osdep.h"
#include <stdlib.h>
#include "qemu.h"
#include "user-internals.h"

#include <linux/fb.h>

#include "guest_fb.h"

/*
 * ⚠️ Своё определение: в linux/fb.h FBIO_WAITFORVSYNC объявлен через __u32, а
 * этого типа в нашем окружении нет — сборка падала на «expected expression
 * before __u32». Свой _IOW тоже не годится: макрос проверки типа в этом
 * окружении не разворачивается в константу. Пишем число, с выводом рядом.
 */
/* 0x40044620 = _IOC_WRITE<<30 | 4<<16 | 'F'<<8 | 0x20. */
#define GUEST_FBIO_WAITFORVSYNC 0x40044620u

/*
 * ★★★ Раскладка ГОСТЯ, а не хозяина.
 *
 * В struct fb_fix_screeninfo поля smem_start и mmio_start объявлены как
 * `unsigned long`: у 32-битного гостя это 4 байта, у нашего 64-битного хозяина —
 * 8. Заполнив структуру хозяйской раскладкой, мы сдвигаем гостю ВСЁ, что идёт
 * после первого такого поля.
 *
 * Как это выглядело: gralloc.default читал smem_len = 0 и возвращал
 * `return -errno` — а errno там СТАРЫЙ, от последнего неудачного access() при
 * поиске HAL. Наружу выходило «couldn't open framebuffer HAL (No such file or
 * directory)», то есть жалоба на отсутствующий файл там, где файл открыт и
 * прочитан. Следом SurfaceFlinger падал по нулевому указателю на устройство.
 *
 * ⚠️ У fb_var_screeninfo все поля __u32, поэтому его раскладка совпадает и он
 * работал сразу — из-за этого расхождение и выглядело загадочным: половина
 * ioctl отвечала правильно.
 */
struct target_fb_fix_screeninfo {
    char id[16];
    uint32_t smem_start;
    uint32_t smem_len;
    uint32_t type;
    uint32_t type_aux;
    uint32_t visual;
    uint16_t xpanstep;
    uint16_t ypanstep;
    uint16_t ywrapstep;
    uint32_t line_length;
    uint32_t mmio_start;
    uint32_t mmio_len;
    uint32_t accel;
    uint16_t reserved[3];
};
/* 68 байт — ровно столько занимает эта структура у 32-битного ядра. */
QEMU_BUILD_BUG_ON(sizeof(struct target_fb_fix_screeninfo) != 68);

/*
 * Геометрия. Умолчание — 480x800, но один и тот же двоичный файл qemu
 * обслуживает любую прошивку, а экраны у них разные. Поэтому
 * числа берутся из окружения:
 *
 *   GUEST_FB_W, GUEST_FB_H     — точки; GUEST_FB_MM_W, GUEST_FB_MM_H — миллиметры.
 *
 * ⚠️ Приложение (Vm.FB_*) и сборщик дерева (размер файла dev/graphics/fb0)
 * обязаны знать ТЕ ЖЕ числа: буфер меньше, чем xres*yres*bpp/8, гость затрёт
 * за концом отображения.
 *
 * Разбор один раз: FBIOPAN_DISPLAY приходит на каждый кадр, и getenv на
 * каждый вызов был бы расточительством.
 */
#define FB_BPP    16
static int fb_geom_done;
static int fb_w = 480, fb_h = 800, fb_mm_w = 56, fb_mm_h = 94;

/*
 * ★ Р-144: листание страниц (см. шапку). fb_flip — путь файла листания из
 * GUEST_FB_FLIP (NULL — одна страница, как прежде); fb_pages — 1 или 2;
 * fb_page — показываемая страница по мнению ЭТОГО процесса (FBIOGET отвечает
 * ею; общий номер листания живёт в файле).
 */
#define FB_FLIP_MAGIC 0x50494c46u      /* «FLIP» little-endian */
static const char *fb_flip;
static int fb_pages = 1;
static int fb_page;

static int env_int(const char *name, int dflt)
{
    const char *s = getenv(name);
    if (!s || !*s) {
        return dflt;
    }
    int v = atoi(s);
    return v > 0 ? v : dflt;
}

static void fb_geom_init(void)
{
    if (fb_geom_done) {
        return;
    }
    fb_geom_done = 1;
    fb_w    = env_int("GUEST_FB_W", fb_w);
    fb_h    = env_int("GUEST_FB_H", fb_h);
    /* Физический размер: умолчание снято с экрана 4,3 дюйма при 217 точках на
     * дюйм — плотность тех лет. Если задан
     * только размер в точках, пересчитываем миллиметры по той же плотности,
     * иначе гость посчитал бы себе неверные dpi. */
    fb_mm_w = env_int("GUEST_FB_MM_W", fb_w * 254 / 2170);
    fb_mm_h = env_int("GUEST_FB_MM_H", fb_h * 254 / 2170);
    const char *flip = getenv("GUEST_FB_FLIP");
    if (flip && flip[0] == '/') {
        fb_flip = flip;
        fb_pages = 2;
    }
}

/*
 * ★ Р-144: показать страницу [page] — запомнить и записать в файл листания
 * {знак, страница, номер листания + 1, страниц}. Номер — из файла: гостевых
 * процессов, листающих один fb0, может быть несколько (перезапуск
 * композитора), и счёт обязан расти, а не начинаться с нуля. Сбой открытия
 * или записи — молча: вид гостя тогда покажет страницу 0 по отпечатку, как
 * при одной странице (хуже, но не черно).
 */
static void fb_show_page(int page)
{
    uint32_t w[4] = { 0, 0, 0, 0 };

    fb_page = page;
    if (!fb_flip) {
        return;
    }
    int f = open(fb_flip, O_RDWR | O_CLOEXEC);
    if (f < 0) {
        return;
    }
    if (pread(f, w, sizeof w, 0) != (ssize_t)sizeof w || w[0] != FB_FLIP_MAGIC) {
        w[2] = 0;                      /* файл свежий (нули от стенда) — счёт с нуля */
    }
    w[0] = FB_FLIP_MAGIC;
    w[1] = (uint32_t)page;
    w[2] += 1;
    w[3] = (uint32_t)fb_pages;
    if (pwrite(f, w, sizeof w, 0) != (ssize_t)sizeof w) {
        /* не записалось — вид гостя останется на отпечатке страницы 0 */
    }
    close(f);
}

/*
 * ★ Р-144: yoffset из гостевой fb_var_screeninfo (все поля __u32, раскладка
 * гостя совпадает с хозяйской: xres, yres, xres_virtual, yres_virtual,
 * xoffset, yoffset — шестое слово). Только 0 и yres — страницы; прочее
 * (у композитора таких нет) не трогает показ: -1.
 */
static int fb_page_of(abi_ulong arg)
{
    struct fb_var_screeninfo v;

    memcpy(&v, g2h_untagged(arg), sizeof v);
    if (v.yoffset == 0) {
        return 0;
    }
    if (fb_pages == 2 && v.yoffset == (uint32_t)fb_h) {
        return 1;
    }
    return -1;
}

#define FB_W      fb_w
#define FB_H      fb_h
#define FB_MM_W   fb_mm_w
#define FB_MM_H   fb_mm_h

/*
 * Какие описатели — наши. Узнаём по имени файла через /proc/self/fd и
 * запоминаем: FBIOPAN_DISPLAY может приходить на каждый кадр, и readlink на
 * каждый вызов был бы расточительством.
 */
#define FB_MAXFD 8
static int fb_yes[FB_MAXFD], fb_no[FB_MAXFD];

static int fd_in(const int *tbl, int fd)
{
    for (int i = 0; i < FB_MAXFD; i++) {
        if (tbl[i] == fd + 1) {
            return 1;
        }
    }
    return 0;
}

static void fd_add(int *tbl, int fd)
{
    for (int i = 0; i < FB_MAXFD; i++) {
        if (!tbl[i]) {
            tbl[i] = fd + 1;
            return;
        }
    }
}

static int is_fb_fd(int fd)
{
    char link[64], target[PATH_MAX];

    if (fd < 0) {
        return 0;
    }
    if (fd_in(fb_yes, fd)) {
        return 1;
    }
    if (fd_in(fb_no, fd)) {
        return 0;
    }
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, target, sizeof target - 1);
    if (n <= 0) {
        return 0;                      /* не запоминаем: описатель мог закрыться */
    }
    target[n] = 0;
    /*
     * ⚠️ Сравнение по ХВОСТУ пути: слева стоит корень прошивки, а он у
     * приложения на телефоне и на обычном Linux разный.
     */
    size_t tlen = strlen(target);
    static const char tail[] = "dev/graphics/fb0";
    int ours = tlen >= sizeof tail - 1 &&
        !strcmp(target + tlen - (sizeof tail - 1), tail);
    fd_add(ours ? fb_yes : fb_no, fd);
    return ours;
}

void guest_fb_forget(int fd)
{
    for (int i = 0; i < FB_MAXFD; i++) {
        if (fb_yes[i] == fd + 1) {
            fb_yes[i] = 0;
        }
        if (fb_no[i] == fd + 1) {
            fb_no[i] = 0;
        }
    }
}

static void fill_var(struct fb_var_screeninfo *v)
{
    fb_geom_init();
    memset(v, 0, sizeof *v);
    v->xres = FB_W;
    v->yres = FB_H;
    v->xres_virtual = FB_W;
    /* Одна страница — без двойной буферизации; две — только по GUEST_FB_FLIP (Р-144, см. шапку). */
    v->yres_virtual = FB_H * fb_pages;
    v->yoffset = (uint32_t)(fb_page * FB_H);
    v->bits_per_pixel = FB_BPP;
    /* RGB565: синий в младших битах, красный в старших — как на живом экране. */
    v->red.offset = 11; v->red.length = 5;
    v->green.offset = 5; v->green.length = 6;
    v->blue.offset = 0; v->blue.length = 5;
    v->transp.offset = 0; v->transp.length = 0;
    v->activate = FB_ACTIVATE_NOW;
    v->width = FB_MM_W;
    v->height = FB_MM_H;
    v->vmode = FB_VMODE_NONINTERLACED;
    /*
     * ★★★ Тайминги задают ЧАСТОТУ РАЗВЁРТКИ, а по ней SurfaceFlinger решает,
     * как часто складывать кадр. Считает он так (HWComposer 4.4):
     *   Гц = 1e12 / (полная_высота * полная_ширина * pixclock_пс)
     * Полная высота 8+960+8+8 = 984, полная ширина 8+540+8+8 = 564.
     *
     * ★★★★★ УМОЛЧАНИЕ 60 Гц. Это ровно то число, которое видит человек.
     *
     * ⚠️ Здесь дважды стоял неверный вывод, и оба раза он звучал убедительно.
     *
     * Заход 1 (старый конвейер): 60 Гц дали ТРИ кадра в секунду → «гость не
     * вывозит композицию». Неверно: тот стенд платил за кадр 29 кругов
     * ожидания в мосте и терял две трети готовых кадров на показе.
     *
     * Заход 2 (после починок моста, телефон с ядром 4.9): 43 Гц дали 40,1 и 45,9
     * кадр/с, 60 Гц — 37,6 и 46,2 → «разницы нет, упираемся в поток гостя
     * (86-92 % ядра)». Тоже неверно, и по двум причинам сразу: числа снимались
     * листанием вручную, вразнобой, а сама система в тот момент КРУГОМ
     * ПОДНИМАЛА ПАДАЮЩИЙ mediaserver (патч 0039) — вот откуда взялись
     * «86-92 % ядра» у гостя.
     *
     * Заход 3 (повторяемая мерка `cmd scroll:15`, mediaserver жив):
     *
     *     частота   кадр/с   процессор     лаунчер   кадры окна моста
     *      43 Гц     42,4    1,2 ядра        49 %    218 из 240 в 20-30 мс
     *      60 Гц     60,0    3,4 ядра        96 %    ВСЕ 240 быстрее 20 мс
     *     120 Гц    113,5    3,7 ядра       105 %    232 из 240 быстрее 20 мс
     *
     * Совпадение 42,4 с 43 не случайно: программная развёртка SurfaceFlinger
     * (VSyncThread у HWComposer, настоящего hwcomposer у нас нет) выдаёт такт
     * ровно этой частоты, и быстрее назначенного гость рисовать не станет,
     * сколько бы у него ни было запаса. Мы сами назначили себе 43 кадра.
     *
     * Умолчание 120 Гц: переход с 60 на 120 стоит почти ничего (3,4 → 3,7
     * ядра из восьми), а плавность растёт вдвое — подтверждено и мерками, и
     * глазами на живом телефоне. Показания моста сходятся с меркой: окна во
     * время листания дают 112, 117, 118, 91, 93 кадр/с.
     *
     * ⚠️ ЧТО ЗДЕСЬ СЧИТАЕТСЯ. И мерка, и «ЭКРАН … кадр/с» — это кадры ПОКАЗА,
     * то есть композиции SurfaceFlinger. Сколько раз перерисовался сам
     * лаунчер, они не говорят. Что 120 действительно плавнее, а не просто
     * чаще пересобирает то же самое, проверено глазами.
     *
     * ⚠️ На медленном хозяине частоту стоит понизить: `cmd hz:N` (GUEST_FB_HZ),
     * действует со следующего подъёма стека. На том телефоне умолчание 120 НЕ
     * проверялось.
     */
    /*
     * ★ Частоту можно задать снаружи: GUEST_FB_HZ=<герцы>. Так проверка «а если
     * быстрее» не требует пересборки трансляции — при прежнем устройстве
     * каждый заход стоил сборки и загрузки, и поэтому проверялся один раз.
     * Умолчание — 120 Гц (см. разбор выше).
     */
    {
        int hz = 0;
        const char *e = getenv("GUEST_FB_HZ");
        if (e) hz = atoi(e);
        if (hz < 10 || hz > 120) hz = 120;
        /*
         * ⚠️ Гц = 1e12 / (полная_высота * полная_ширина * pixclock_пс).
         * В шапке выше стояло 1e15 — опечатка, и она стоила захода: с ней
         * частота выходит в тысячу раз ниже (0,04 Гц), SurfaceFlinger считает
         * экран почти неподвижным, и кадров становится вдвое меньше. Сверка:
         * 554976 точек * 41667 пс = 23,1 мс = 43,2 Гц.
         */
        unsigned long total = (unsigned long)(FB_H + 24) * (unsigned long)(FB_W + 24);
        v->pixclock = (unsigned)(1000000000000ULL / (total * (unsigned long)hz));
    }
    v->left_margin = 8;
    v->right_margin = 8;
    v->upper_margin = 8;
    v->lower_margin = 8;
    v->hsync_len = 8;
    v->vsync_len = 8;
}

static void fill_fix(struct target_fb_fix_screeninfo *f)
{
    fb_geom_init();
    memset(f, 0, sizeof *f);
    snprintf(f->id, sizeof f->id, "guestfb");
    f->smem_start = 0;                 /* физического адреса у нас нет */
    f->smem_len = FB_W * FB_H * (FB_BPP / 8) * fb_pages;
    f->ypanstep = fb_pages > 1 ? 1 : 0;   /* Р-144: листать можно только при двух страницах */
    f->type = FB_TYPE_PACKED_PIXELS;
    f->visual = FB_VISUAL_TRUECOLOR;
    f->line_length = FB_W * (FB_BPP / 8);
    f->accel = FB_ACCEL_NONE;
}

int guest_fb_ioctl(int fd, unsigned long req, abi_ulong arg, abi_long *ret)
{
    switch (req) {
    case FBIOGET_VSCREENINFO:
    case FBIOPUT_VSCREENINFO:
    case FBIOGET_FSCREENINFO:
    case FBIOPAN_DISPLAY:
    case GUEST_FBIO_WAITFORVSYNC:
    case FBIOBLANK:
        break;
    default:
        return 0;                      /* не наш запрос */
    }
    if (!is_fb_fd(fd)) {
        return 0;                      /* не наш описатель */
    }

    *ret = 0;
    switch (req) {
    case FBIOGET_VSCREENINFO: {
        struct fb_var_screeninfo v;
        fill_var(&v);
        memcpy(g2h_untagged(arg), &v, sizeof v);
        return 1;
    }
    case FBIOGET_FSCREENINFO: {
        struct target_fb_fix_screeninfo f;
        fill_fix(&f);
        memcpy(g2h_untagged(arg), &f, sizeof f);
        return 1;
    }
    case FBIOPUT_VSCREENINFO: {
        /*
         * Гость сообщает, чего хочет. Мы ничего не меняем, но обязаны вернуть
         * ему ту геометрию, которая ДЕЙСТВИТЕЛЬНО есть: gralloc.default читает
         * структуру обратно и по ней считает line_length и смещение страницы.
         * Промолчать нельзя — он поверит своим числам и уедет за буфер.
         *
         * ★ Р-144: при двух страницах yoffset просьбы — страница к показу
         * (композитор 1.x листает именно этим вызовом, FB_ACTIVATE_VBL).
         */
        fb_geom_init();
        if (fb_pages == 2) {
            int page = fb_page_of(arg);
            if (page >= 0) {
                fb_show_page(page);
            }
        }
        struct fb_var_screeninfo v;
        fill_var(&v);
        memcpy(g2h_untagged(arg), &v, sizeof v);
        return 1;
    }
    case FBIOPAN_DISPLAY:
        /* Одна страница — переключать нечего. ★ Р-144: две — показать yoffset. */
        fb_geom_init();
        if (fb_pages == 2) {
            int page = fb_page_of(arg);
            if (page < 0) {
                errno = EINVAL;        /* соглашение шима: *ret = -1 и errno хозяина (патч 0006) */
                *ret = -1;
                return 1;
            }
            fb_show_page(page);
        }
        return 1;
    case GUEST_FBIO_WAITFORVSYNC:
        /*
         * Ждать нечего: настоящей развёртки нет. Возвращаемся сразу — гость
         * сам ограничит частоту, а мы не хотим спать в его потоке.
         */
        return 1;
    case FBIOBLANK:
        return 1;
    }
    return 0;
}
