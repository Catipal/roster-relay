#!/usr/bin/env bash
# Copyright (c) 2026 The Bitcoin PoS Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# BPS Companion for Android, from source: Qt 6.12, ZXing-C++ and QtKeychain
# built here, then one unsigned APK per ABI. What CI runs, and what F-Droid
# can run.
#
#   tools/android.sh [abi...]      default: arm64-v8a armeabi-v7a x86_64
#
# from the app's repository, or mobile/tools/android.sh in the BPS tree.
#
# Needs: a JDK 21, CMake 3.21+, Ninja, a C++ compiler for the host Qt, and an
# Android SDK at $ANDROID_SDK_ROOT with build-tools;37.0.0, platforms;android-37.0
# (Qt 6.12 compiles against it; the app targets 36) and ndk;$NDK_VERSION.
# Everything else is fetched and checked against the checksums below, except
# Gradle, which Qt's Gradle wrapper fetches itself. Work goes to $WORK (default ~/bps-mobile); finished
# packages to $WORK/out. Steps already done are skipped on a second run.
#
# The packages come out unsigned. Sign them with your own key; never with a
# key made for testing.
set -euo pipefail

QT_VERSION=6.12.0
NDK_VERSION=${NDK_VERSION:-28.2.13676358}
WORK=${WORK:-$HOME/bps-mobile}
ABIS=("$@")
[ ${#ABIS[@]} -gt 0 ] || ABIS=(arm64-v8a armeabi-v7a x86_64)

HERE=$(cd "$(dirname "$0")" && pwd)
# The app's own repository has app/ beside tools/; the BPS tree, mobile/app.
if [ -d "$HERE/../app" ]; then APP_SRC=$(cd "$HERE/../app" && pwd); else APP_SRC=$(cd "$HERE/../../mobile/app" && pwd); fi
: "${ANDROID_SDK_ROOT:?set ANDROID_SDK_ROOT to the Android SDK}"
NDK=$ANDROID_SDK_ROOT/ndk/$NDK_VERSION
[ -d "$NDK" ] || { echo "NDK $NDK_VERSION is not installed in $ANDROID_SDK_ROOT" >&2; exit 1; }

DL=$WORK/dl SRC=$WORK/src BLD=$WORK/build LOG=$WORK/logs OUT=$WORK/out
HOST=$WORK/qt-$QT_VERSION-host
mkdir -p "$DL" "$SRC" "$BLD" "$LOG" "$OUT"
say() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { say "FAILED: $1 (log: $2)"; tail -40 "$2" >&2; exit 1; }

# Qt's own modules, checked against the sha256 Qt publishes beside each.
QT_MODULES=(qtbase qtshadertools qtdeclarative qtsvg qtmultimedia)
QT_URL=https://download.qt.io/official_releases/qt/${QT_VERSION%.*}/$QT_VERSION/submodules

ZXING_URL=https://github.com/zxing-cpp/zxing-cpp/archive/refs/tags/v3.1.1.tar.gz
ZXING_SHA=7286b1e6ade66fe82b7c8208b4595deeb55d6486b410834fdc65702f46650542
KEYCHAIN_URL=https://github.com/frankosterfeld/qtkeychain/archive/refs/tags/0.17.0.tar.gz
KEYCHAIN_SHA=3b85c3929034b0a99da777130c34d99f006fcd3a9d56564159399a33fee0e504

fetch() { # url file sha256
    if [ ! -s "$DL/$2" ]; then
        say "fetch $2"
        curl -fL --retry 3 -o "$DL/$2.part" "$1"
        mv "$DL/$2.part" "$DL/$2"
    fi
    echo "$3  $DL/$2" | sha256sum -c --quiet - || { rm -f "$DL/$2"; echo "checksum mismatch: $2" >&2; exit 1; }
}

unpack() { # file dir
    [ -d "$SRC/$2" ] || tar -C "$SRC" -xf "$DL/$1"
}

for m in "${QT_MODULES[@]}"; do
    f=$m-everywhere-src-$QT_VERSION.tar.xz
    [ -s "$DL/$f.sha256" ] || curl -fsL --retry 3 -o "$DL/$f.sha256" "$QT_URL/$f.sha256"
    fetch "$QT_URL/$f" "$f" "$(awk '{print $1}' "$DL/$f.sha256")"
    unpack "$f" "$m-everywhere-src-$QT_VERSION"
done
fetch "$ZXING_URL" zxing-cpp-3.1.1.tar.gz "$ZXING_SHA"
unpack zxing-cpp-3.1.1.tar.gz zxing-cpp-3.1.1
fetch "$KEYCHAIN_URL" qtkeychain-0.17.0.tar.gz "$KEYCHAIN_SHA"
unpack qtkeychain-0.17.0.tar.gz qtkeychain-0.17.0

# Builds one Qt module into a prefix: qt_module <name> <build dir> <prefix> <configure args...>
qt_module() {
    local m=$1 dir=$2 prefix=$3; shift 3
    [ -e "$dir/.done-$m" ] && return 0
    say "$(basename "$dir") $m"
    rm -rf "${dir:?}/$m" && mkdir -p "$dir/$m"
    local log=$LOG/$(basename "$dir")-$m.log
    if [ "$m" = qtbase ]; then
        (cd "$dir/$m" && "$SRC/qtbase-everywhere-src-$QT_VERSION/configure" -prefix "$prefix" "$@") > "$log" 2>&1 || fail "$m configure" "$log"
    else
        (cd "$dir/$m" && "$prefix/bin/qt-configure-module" "$SRC/$m-everywhere-src-$QT_VERSION") > "$log" 2>&1 || fail "$m configure" "$log"
    fi
    (cd "$dir/$m" && cmake --build . --parallel && cmake --install .) >> "$log" 2>&1 || fail "$m build" "$log"
    touch "$dir/.done-$m"
}

# The host Qt: only its tools are used, to cross-build the Android one.
for m in qtbase qtshadertools qtdeclarative; do
    qt_module "$m" "$BLD/host" "$HOST" -release -nomake examples -nomake tests -- -G Ninja
done

for abi in "${ABIS[@]}"; do
    QT=$WORK/qt-$QT_VERSION-android-$abi
    DEPS=$WORK/deps-android-$abi
    for m in "${QT_MODULES[@]}"; do
        qt_module "$m" "$BLD/android-$abi" "$QT" -release -nomake examples -nomake tests \
            -platform android-clang -android-ndk "$NDK" -android-sdk "$ANDROID_SDK_ROOT" \
            -android-abis "$abi" -qt-host-path "$HOST" -- -G Ninja -DQT_ALLOW_DOWNLOAD=ON
    done

    if [ ! -e "$DEPS/.done" ]; then
        say "android-$abi zxing, qtkeychain"
        log=$LOG/deps-android-$abi.log
        { "$QT/bin/qt-cmake" -S "$SRC/zxing-cpp-3.1.1" -B "$BLD/android-$abi/zxing" -G Ninja \
              -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$DEPS" -DBUILD_SHARED_LIBS=OFF \
              -DZXING_READERS=ON -DZXING_WRITERS=OLD -DZXING_EXAMPLES=OFF -DZXING_BLACKBOX_TESTS=OFF \
              -DZXING_UNIT_TESTS=OFF -DZXING_PYTHON_MODULE=OFF -DZXING_C_API=OFF \
              -DCMAKE_DISABLE_FIND_PACKAGE_Doxygen=ON &&
          cmake --build "$BLD/android-$abi/zxing" --target install &&
          "$QT/bin/qt-cmake" -S "$SRC/qtkeychain-0.17.0" -B "$BLD/android-$abi/qtkeychain" -G Ninja \
              -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$DEPS" -DBUILD_WITH_QT6=ON \
              -DBUILD_SHARED_LIBS=OFF -DBUILD_TRANSLATIONS=OFF -DBUILD_TEST_APPLICATION=OFF &&
          cmake --build "$BLD/android-$abi/qtkeychain" --target install; } > "$log" 2>&1 || fail "deps $abi" "$log"
        touch "$DEPS/.done"
    fi

    say "android-$abi app"
    APP=$BLD/android-$abi/app
    log=$LOG/app-android-$abi.log
    # Deployment only ever adds libraries to the package folder; a stale one would ship.
    rm -rf "$APP/android-build/libs" "$APP/android-build/assets"
    { "$QT/bin/qt-cmake" -S "$APP_SRC" -B "$APP" -G Ninja -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_FIND_ROOT_PATH="$DEPS" -DQT_ANDROID_BUILD_ALL_ABIS=OFF &&
      cmake --build "$APP" --target apk; } > "$log" 2>&1 || fail "app $abi" "$log"
    cp "$APP/android-build/build/outputs/apk/release/android-build-release-unsigned.apk" \
       "$OUT/bps-companion-$abi-unsigned.apk"
done

say "done"
(cd "$OUT" && ls -l && sha256sum ./*.apk)
