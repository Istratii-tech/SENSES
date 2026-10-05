#!/bin/bash
# Сборка qemu-arm ДЛЯ АНДРОИДА: статический бинарь на musl.
#
# ЧТО НУЖНО: хозяин aarch64 Linux и права root. Скрипт монтирует /proc и /dev,
# разворачивает chroot и собирает в нём. На macOS запускать внутри любой
# Linux-виртуалки — важно только, чтобы архитектура была aarch64.
#
#   sudo ./qemu/build-android.sh
#
# ПОЧЕМУ СТАТИЧЕСКИЙ. Динамический бинарь на телефоне не запустится вовсе: там
# bionic, и хозяйский линкер гостевой /lib/ld-linux не найдёт. Полностью
# статический ELF Android исполняет без вопросов — ему нужен только ABI ядра, а
# он общий.
#
# ПОЧЕМУ ЧЕРЕЗ ALPINE, а не musl-gcc поверх Debian или Ubuntu: qemu обязательно
# требует glib, а статической libglib-2.0.a те не дают вовсе. У Alpine есть
# glib-static, собранный тем же musl. Контейнеров не используем — Alpine
# поднимается chroot'ом из minirootfs, чтобы не тянуть в зависимости ещё и
# среду исполнения контейнеров.
set -euo pipefail
# ★★ 8.2.4, а не 8.2.2. В 8.2.2 есть ошибка правильности самого транслятора:
# «tcg/optimize: Fix sign_mask for logical right-shift» (2911e9b95f3b, ломает
# 93a967fbb57, заявка qemu #2248) — значение, заведомо равное 0 или −1, после
# логического сдвига вправо на переменное число считается по-прежнему
# знакорасширенным, и следующее расширение знака выбрасывается; гость получает
# неверное число. Вышло исправление только в 8.2.3.
# ⚠️ Все наши патчи (число — в NOTICE и в BUILD-MANIFEST.txt) ложатся на 8.2.4 без правки.
VER="${VER:-8.2.4}"
# ★★★ СБОРКА ПРИБИТА: вход, у которого нет суммы, не принимается.
#
# Раньше архив QEMU качался без проверки, а корень Alpine брался «последний из
# latest-releases.yaml»: завтра по тому же комплекту собрался бы другой двоичный
# файл, и «полный исходный текст» (GPLv2 §3) перестал бы быть тем, из чего
# собрано то, что мы раздаём. Теперь:
#   * архив QEMU — по сумме sha256 (для VER=8.2.4 она записана здесь);
#   * корень Alpine — файл с точным именем и по сумме sha256 (для BR=v3.20);
#   * в конце сборки пишется qemu/build/BUILD-MANIFEST.txt: что именно было
#     взято и что получилось (версии пакетов Alpine на день сборки, компилятор,
#     патчи с суммами, сумма результата).
# Другая версия QEMU или другой корень требуют задать СВОЮ сумму:
#   VER=… QEMU_SHA256=…   BR=… ALPINE_ROOTFS=… ALPINE_SHA256=…
QEMU_SHA256_PIN=""
[ "$VER" = 8.2.4 ] && QEMU_SHA256_PIN=ecf5537feab92641b99d7482f551f2195d3a5bd34acef9d52bfbff353a607397
QEMU_SHA256="${QEMU_SHA256:-$QEMU_SHA256_PIN}"
[ -n "$QEMU_SHA256" ] || { echo "для VER=$VER не задана QEMU_SHA256: архив без суммы не принимаю"; exit 1; }
# ⚠️ Ветка Alpine прибита. На latest-stable (3.24) приезжает Python 3.14, а
# mkvenv у qemu 8.2.2 на нём падает: «found no usable distlib». 3.20 несёт
# Python 3.12 и meson 1.4 — та пара, на которой qemu 8.2 собирался всегда.
BR="${BR:-v3.20}"
ALPINE_ROOTFS_PIN=""; ALPINE_SHA256_PIN=""
if [ "$BR" = v3.20 ]; then
  ALPINE_ROOTFS_PIN=alpine-minirootfs-3.20.10-aarch64.tar.gz
  ALPINE_SHA256_PIN=61ac877fdbcee6914731bc22a4ed5668ea3470f201f97a7078931c48b71bbeec
fi
ALPINE_ROOTFS="${ALPINE_ROOTFS:-$ALPINE_ROOTFS_PIN}"
ALPINE_SHA256="${ALPINE_SHA256:-$ALPINE_SHA256_PIN}"
[ -n "$ALPINE_ROOTFS" ] && [ -n "$ALPINE_SHA256" ] || {
  echo "для BR=$BR не заданы ALPINE_ROOTFS и ALPINE_SHA256: корень без суммы не принимаю"; exit 1; }
# Сумма файла: sha256sum (Linux), иначе shasum (на случай запуска не на Linux — только для проверки скрипта).
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
# ⚠️★★★ Chroot СВОЙ у каждого каталога сборки, и это не педантизм.
#
# Пока путь к chroot был общим для двух рабочих копий, накопленное в нём
# переезжало из одной в другую и ломало сборку МОЛЧА: патчи предыдущей работы
# оставались лежать и накладывались вместе с нашими. Отказ при этом на причину
# не указывал совсем — «undefined reference» на функцию, которой у нас нет,
# потому что звал её чужой патч. Номера патчей у разных копий вдобавок
# сталкиваются, и лишний патч встаёт в неожиданное место очереди.
#
# Теперь имя chroot берётся из имени каталога проекта. Цена — своя копия Alpine
# на копию (сотня мегабайт), и она того стоит.
ALP="${ALP:-/var/tmp/alp-$(basename "$PROJ" | tr "[:upper:]" "[:lower:]")-$BR}"
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

echo "== 1/5 minirootfs Alpine (aarch64), прибит: $ALPINE_ROOTFS"
# ★ Отметка рядом с chroot хранит сумму архива, из которого он развёрнут. Без неё
# нельзя сказать, из чего собран корень, и сборка отказывает: тихо принять
# прежний chroot («latest» из старого запуска) значило бы снять пин.
# ⚠️ Удалять чужой chroot сами не будем: в нём примонтированы /proc и /dev, и
# `rm -rf` прошёл бы сквозь /dev хозяина. Размонтировать и стереть — руками,
# либо взять другой каталог: ALP=/var/tmp/alp-новый sudo ./qemu/build-android.sh
if [ -x "$ALP/bin/busybox" ]; then
  if [ "$(cat "$ALP/.pinned-rootfs-sha256" 2>/dev/null)" != "$ALPINE_SHA256" ]; then
    echo "chroot $ALP развёрнут НЕ из прибитого архива ($ALPINE_ROOTFS, $ALPINE_SHA256)."
    echo "Размонтируйте $ALP/proc и $ALP/dev и удалите каталог, либо задайте другой ALP=…"
    exit 1
  fi
else
  BASE="https://dl-cdn.alpinelinux.org/alpine/$BR/releases/aarch64"
  curl -fsSL "$BASE/$ALPINE_ROOTFS" -o /var/tmp/alp.tar.gz
  GOT=$(sha256_of /var/tmp/alp.tar.gz)
  if [ "$GOT" != "$ALPINE_SHA256" ]; then
    rm -f /var/tmp/alp.tar.gz
    echo "сумма $ALPINE_ROOTFS не сошлась: ждали $ALPINE_SHA256, получили $GOT"; exit 1
  fi
  echo "   сумма сошлась: $GOT"
  sudo mkdir -p "$ALP"
  sudo tar xzf /var/tmp/alp.tar.gz -C "$ALP"
  echo "$ALPINE_SHA256" | sudo tee "$ALP/.pinned-rootfs-sha256" >/dev/null
  rm -f /var/tmp/alp.tar.gz
fi
sudo cp -f /etc/resolv.conf "$ALP/etc/resolv.conf"
# proc нужен и apk (для случайных чисел), и meson (nproc, /proc/self)
mountpoint -q "$ALP/proc" || sudo mount -t proc proc "$ALP/proc"
mountpoint -q "$ALP/dev"  || sudo mount --bind /dev "$ALP/dev"

echo "== 2/5 патчи и наши исходники внутрь chroot"
# ⚠️★★★ Каталог патчей ОЧИЩАЕМ, а не дополняем.
#
# Пока здесь стояло только `cp -f`, ранее положенные патчи оставались лежать, и
# сборка молча брала их вместе с нашими. Отказ вида
#   undefined reference to `guest_http_redirect'  (do_connect, do_sendto)
# на причину не указывал совсем: функцию звал патч, которого в нашем наборе
# нет. Хуже того, номера патчей сталкиваются, и лишний встаёт в неожиданное
# место очереди — то есть меняет и порядок наложения остальных.
sudo rm -rf "$ALP/root/patches"
sudo mkdir -p "$ALP/root/patches"
for p in "$PROJ"/qemu/patches/*.patch; do
  [ -e "$p" ] && sudo cp -f "$p" "$ALP/root/patches/"
done
# ★ Наши исходники для linux-user (шим binder и протокол). Внутрь патча их
# кладать нельзя: файл на 1300 строк правился бы мучительно, а diff распухал бы
# при каждой правке. Патч только вешает вызовы, код живёт здесь.
sudo mkdir -p "$ALP/root/src"
sudo cp -f "$PROJ"/qemu/src/* "$ALP/root/src/"

echo "== 3/5 скрипт сборки внутрь chroot"
sudo tee "$ALP/root/build.sh" >/dev/null <<INNER
#!/bin/sh
set -eu
VER=$VER
FRESH=${FRESH:-0}
# ★ Диапазон дат наших изменений — для пометок по GPLv2 §2a (см. ниже).
CHANGED_DATES='2026-08-29 … 2026-10-05'
QEMU_SHA256=$QEMU_SHA256
ALPINE_ROOTFS=$ALPINE_ROOTFS
ALPINE_SHA256=$ALPINE_SHA256
BR=$BR
INNER
sudo tee -a "$ALP/root/build.sh" >/dev/null <<'INNER'
apk update -q
# ⚠️ ninja берём из samurai: пакет ninja-build кладёт бинарь в
# /usr/lib/ninja-build/bin и в PATH его нет — configure его не находит.
# py3-* — для mkvenv, он создаёт venv и без distlib отказывается работать.
apk add -q build-base meson samurai pkgconf python3 py3-pip py3-setuptools \
    py3-distlib bison flex linux-headers glib-dev glib-static zlib-static \
    curl tar xz
cd /root
# ⚠️ Архив НЕ удаляем: изменившийся набор патчей требует чистого дерева, и
# перекачивать 120 МБ ради этого незачем.
#
# ⚠️★ Имя архива — С НОМЕРОМ ВЕРСИИ. Раньше он звался просто `q.tar.xz`, и
# сборка с другим VER брала СТАРЫЙ архив: проверка «файл есть» проходила, и
# распаковывалась прежняя версия. Снаружи это выглядело как «обновление не
# помогло», хотя обновления и не было.
[ -f "q-$VER.tar.xz" ] || curl -fsSL "https://download.qemu.org/qemu-$VER.tar.xz" -o "q-$VER.tar.xz"
# ★★ Сумма архива сверяется при КАЖДОМ запуске, а не только после скачивания:
# файл мог остаться от прежнего запуска или от другого источника. Расхождение —
# отказ; битый файл стираем, чтобы следующий запуск скачал заново.
QSUM=$(sha256sum "q-$VER.tar.xz" | cut -d" " -f1)
if [ "$QSUM" != "$QEMU_SHA256" ]; then
  rm -f "q-$VER.tar.xz"
  echo "!! сумма архива QEMU $VER не сошлась: ждали $QEMU_SHA256, получили $QSUM"
  exit 1
fi
echo "   архив QEMU $VER: сумма сошлась"

# ★ Состояние дерева определяется ОТПЕЧАТКОМ всего набора патчей, а не попыткой
# применить каждый по отдельности.
#
# Прежняя проверка («уже наложен» = патч применяется обратно) неверна в принципе:
# патчи трогают одни и те же места, и следующий ломает контекст предыдущему.
# 0008 добавил строку вплотную к строке из 0006 — после чего 0006 перестал
# применяться и прямо, и обратно, и ЛЮБАЯ пересборка без FRESH падала на нём:
#
#   !! патч не лёг и не наложен: 0006-guest-binder.patch — соберите с FRESH=1
#
# Теперь набор либо тот же самый (дерево не трогаем), либо изменился — и тогда
# дерево пересоздаётся само, без ручного FRESH. Это единственный способ быть
# уверенным, что собран именно тот код, который лежит в patches/.
STAMP=/root/patches.stamp
SUM=$(cat /root/patches/*.patch | md5sum | cut -d" " -f1)
if [ "${FRESH:-0}" = 1 ] || [ ! -d "qemu-$VER" ] || \
   [ "$(cat $STAMP 2>/dev/null)" != "$SUM" ]; then
  echo "   набор патчей другой (или FRESH) — дерево заново"
  rm -rf "qemu-$VER" "$STAMP"
  tar xf "q-$VER.tar.xz"
  cd "qemu-$VER"
  for p in /root/patches/*.patch; do
    [ -e "$p" ] || continue
    patch -p1 -N < "$p" >/dev/null || { echo "!! патч не лёг: $(basename $p)"; exit 1; }
    echo "   наложен $(basename $p)"
  done

  # ★★★★★ GPLv2 §2a: ИЗМЕНЁННЫЙ ФАЙЛ ОБЯЗАН НЕСТИ ПОМЕТКУ.
  #
  # «You must cause the modified files to carry prominent notices stating that
  # you changed the files and the date of any change.» Мы распространяем
  # libqemu.so внутри APK, значит это требование на нас распространяется.
  #
  # ⚠️ Почему ЗДЕСЬ, а не в самих патчах: пометка в патче сдвинула бы начало
  # файла, и у следующего патча разъехался бы контекст. После наложения всего
  # набора — единственное безопасное место.
  #
  # ⚠️ Список берём из самих патчей: что они правят, то и помечаем. Руками
  # список вести нельзя — разойдётся с действительностью на первом же патче.
  echo "   ставлю пометки об изменении (GPLv2 §2a)"
  grep -h '^--- a/' /root/patches/*.patch | sed 's|^--- a/||' | awk '{print $1}' \
    | sort -u | while read -r f; do
      [ -f "$f" ] || continue
      grep -q 'ISTRATII_TECH SENSES' "$f" && continue
      case "$f" in
        *.build|*.mak|Makefile*) o='' ; pre='# ' ; c='' ;;
        *)                       o='/*' ; pre=' * ' ; c=' */' ;;
      esac
      { [ -n "$o" ] && echo "$o"
        echo "${pre}MODIFIED by the ISTRATII_TECH SENSES project: running an"
        echo "${pre}Android system under ARM32-to-ARM64 user-mode translation."
        echo "${pre}Dates of change: ${CHANGED_DATES}."
        echo "${pre}For what was changed and where to get the sources, see NOTICE."
        [ -n "$c" ] && echo "$c"
        cat "$f"
      } > "$f.noticetmp" && mv "$f.noticetmp" "$f"
    done
  echo "   помечено файлов: $(grep -hl 'ISTRATII_TECH SENSES' $(grep -h '^--- a/' /root/patches/*.patch | sed 's|^--- a/||' | awk '{print $1}' | sort -u) 2>/dev/null | wc -l | tr -d ' ')"

  cd /root
  echo "$SUM" > "$STAMP"
else
  echo "   набор патчей тот же — дерево не трогаем"
fi
cd "/root/qemu-$VER"
# Наши файлы — в дерево qemu, перед сборкой (после патчей: meson.build уже
# знает про guest_binder.c).
cp -f /root/src/* linux-user/

mkdir -p build-static && cd build-static
# --without-default-features: для linux-user не нужно ничего, кроме glib и zlib.
# Всё прочее (pixman, sdl, capstone, fdt) статически тянуло бы полдистрибутива.
#
# ★★★ Оптимизация выше умолчания. qemu собирается с -O2; здесь -O3 и сборка со
# сквозной оптимизацией (LTO). Смысл ровно один: главный поток гостевого
# приложения при листании занят ТРАНСЛЯЦИЕЙ на 94 % пользовательского времени
# (замерено на живом телефоне), и единственный рычаг для него — скорость самого
# транслятора. Ожидание — проценты, не разы.
#
# ⚠️ Ключи задаются переменными OPT и LTO, чтобы вернуться к прежней сборке
# можно было одной командой: OPT=-O2 LTO=0 ./qemu/build-android.sh
#
# ⚠️ Каталог сборки пересоздаётся, КОГДА КЛЮЧИ ПОМЕНЯЛИСЬ. Прежняя проверка
# «есть build.ninja — значит настроено» пропускала configure совсем, и новые
# ключи молча не применялись бы: бинарь получился бы прежним, а замер — ложным.
# ★ Страница 16 КБ — то же требование, что и в native/build.sh: на аппаратах
# Android 15+ со страницей 16 КБ ядро не отобразит сегменты, выровненные на 4.
# Сегодня статический бинарь и так выходит с выравниванием 64 КБ, но полагаться
# на умолчание компоновщика нельзя — оно менялось от версии к версии.
CFG="--static --target-list=arm-linux-user --disable-system --disable-tools \
     --disable-docs --disable-guest-agent --disable-werror \
     --without-default-features --extra-cflags=${OPT:--O3} \
     --extra-ldflags=-Wl,-z,max-page-size=16384"
[ "${LTO:-1}" = 1 ] && CFG="$CFG --enable-lto"
CSUM=$(echo "$CFG" | md5sum | cut -d" " -f1)
if [ "$(cat .cfgstamp 2>/dev/null)" != "$CSUM" ]; then
  echo "   ключи сборки другие — настраиваю заново"
  rm -rf ./* .cfgstamp 2>/dev/null || true
  ../configure $CFG
  echo "$CSUM" > .cfgstamp
fi
ninja qemu-arm
mkdir -p /root/out
cp -f qemu-arm /root/out/qemu-arm
# ★ Копия С СИМВОЛАМИ. Нужна, когда qemu падает в СВОЁМ коде («QEMU internal
# SIGSEGV»): адрес сбоя переводится в имя функции только по ней.
cp -f qemu-arm /root/out/qemu-arm-dbg
strip /root/out/qemu-arm
ls -l /root/out/qemu-arm
file /root/out/qemu-arm 2>/dev/null || readelf -h /root/out/qemu-arm | head -12

# ★★★ BUILD-MANIFEST.txt — что именно взято и что получилось.
#
# Это ответ на вопрос «из чего собран этот двоичный файл», который GPLv2 §3
# задаёт получателю: версии пакетов Alpine на день сборки не прибиты (ветка
# движется), поэтому они ЗАПИСЫВАЮТСЯ. Лежит рядом с двоичным файлом и уезжает
# с ним в выпуск. Текст — по-английски: файл читают получатели комплекта.
#
# ⚠️ Версии библиотек, названные в NOTICE (раздел 1.3), сверяются с фактическими:
# разошлись — это сказано и здесь, и в выводе сборки (NOTICE надо поправить).
EXPECT="glib-2.80.5-r0 gettext-0.22.5-r0 musl-1.2.5-r3 zlib-1.3.2-r0 libgcc-13.2.1_git20240309-r1"
APKV=$(apk info -v | sort)
LIBS=""
for e in $EXPECT; do
  echo "$APKV" | grep -qx "$e" || LIBS="$LIBS $e"
done
{
  echo "BUILD-MANIFEST for qemu-arm-android (libqemu.so)"
  echo "built (UTC):  $(date -u '+%Y-%m-%d %H:%M:%S')"
  echo
  echo "QEMU version:   $VER"
  echo "QEMU archive:   qemu-$VER.tar.xz  sha256 $QEMU_SHA256"
  echo "Alpine branch:  $BR"
  echo "Alpine root:    $ALPINE_ROOTFS  sha256 $ALPINE_SHA256"
  echo "configure:      $CFG"
  echo "                OPT=${OPT:--O3} LTO=${LTO:-1}"
  echo
  echo "compiler:       $(gcc --version | head -1)"
  echo
  if [ -z "$LIBS" ]; then
    echo "libraries named in NOTICE 1.3: all present in the versions given there"
  else
    echo "!! libraries named in NOTICE 1.3 NOT found in the versions given there:$LIBS"
    echo "!! (the Alpine branch has moved on; NOTICE 1.3 must be corrected)"
    echo "!! libraries named in NOTICE 1.3 NOT found in the versions given there:$LIBS" >&2
  fi
  echo
  echo "== apk info -v (build chroot)"
  echo "$APKV"
  echo
  NP=$(ls /root/patches/*.patch | wc -l | tr -d ' ')
  echo "== patches: $NP (applied in this order), sha256"
  (cd /root/patches && sha256sum *.patch)
  echo
  echo "== our source files copied into linux-user/: $(ls /root/src | wc -l | tr -d ' '), sha256"
  (cd /root/src && sha256sum *)
  echo
  echo "== result, sha256"
  (cd /root/out && sha256sum qemu-arm qemu-arm-dbg)
} > /root/out/BUILD-MANIFEST.txt
echo "   BUILD-MANIFEST.txt: патчей $NP, результат $(sha256sum /root/out/qemu-arm | cut -d' ' -f1)"
INNER
sudo chmod +x "$ALP/root/build.sh"

echo "== 4/5 сборка в chroot"
sudo chroot "$ALP" /usr/bin/env FRESH="${FRESH:-0}" OPT="${OPT:--O3}" LTO="${LTO:-1}" /bin/sh /root/build.sh

echo "== 5/5 бинарь наружу"
mkdir -p "$PROJ/qemu/build"
# ⚠️ Всё через sudo: наружу отдаёт root из chroot, и файл на virtiofs остаётся
# root-овым — обычный chmod по нему получает «Operation not permitted», и
# сборка падала на последнем шаге, уже сделав дело.
sudo cp -f "$ALP/root/out/qemu-arm" "$PROJ/qemu/build/qemu-arm-android"
sudo cp -f "$ALP/root/out/qemu-arm-dbg" "$PROJ/qemu/build/qemu-arm-android-dbg"
sudo cp -f "$ALP/root/out/BUILD-MANIFEST.txt" "$PROJ/qemu/build/BUILD-MANIFEST.txt"
sudo chmod 644 "$PROJ/qemu/build/BUILD-MANIFEST.txt"
sudo chmod 755 "$PROJ/qemu/build/qemu-arm-android" "$PROJ/qemu/build/qemu-arm-android-dbg"
ls -l "$PROJ/qemu/build/qemu-arm-android"
"$PROJ/qemu/build/qemu-arm-android" --version | head -1
echo "== готово: qemu/build/qemu-arm-android, qemu/build/BUILD-MANIFEST.txt (хранить и раздавать вместе)"
