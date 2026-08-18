#!/usr/bin/env bash
set -euo pipefail

# ────────────────────────────────────────────────────────────
# Root My Pixel — Build All
# Compiles native helper, exploit payloads for all supported Pixel.
# targets, and the APK in one shot.
#
# Requirements:
#   - Android NDK (set ANDROID_NDK_HOME or auto-detected from $ANDROID_HOME)
#   - Gradle wrapper (./gradlew)
#   - macOS arm64 or Linux x86_64 host
# ────────────────────────────────────────────────────────────

ROOT="$(cd "$(dirname "$0")" && pwd)"
PAYLOADS="$ROOT/Root-My-Pixel-Payloads"
APP="$ROOT/app"
JNILIBS="$APP/src/main/jniLibs/arm64-v8a"
ASSETS="$APP/src/main/assets/exploits"

# ── NDK detection ───────────────────────────────────────────
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  if [ -n "${ANDROID_HOME:-}" ]; then
    ndk_ver=$(ls -1 "$ANDROID_HOME/ndk" 2>/dev/null | sort -V | tail -1)
    if [ -n "$ndk_ver" ]; then
      ANDROID_NDK_HOME="$ANDROID_HOME/ndk/$ndk_ver"
    fi
  fi
  if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "ERROR: ANDROID_NDK_HOME not set and NDK not found in ANDROID_HOME/ndk/"
    echo "Set ANDROID_NDK_HOME=/path/to/android-ndk and retry."
    exit 1
  fi
fi
echo "[*] Using NDK: $ANDROID_NDK_HOME"

# ── NDK compiler path (macOS host) ───────────────────────────
if [[ "$(uname -s)" == "Darwin" ]]; then
  HOST_PLATFORM="darwin-x86_64"
else
  HOST_PLATFORM="linux-x86_64"
fi
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$HOST_PLATFORM/bin/aarch64-linux-android35-clang"

# ── Supported devices targets ─────────────────────────────────
TARGETS=(
  "rango-CP2A.260705.006"     # Pixel 10 Pro Fold
  "blazer-CP2A.260705.006"    # Pixel 10 Pro
  "frankel-CP2A.260705.006"   # Pixel 10
  "mustang-CP2A.260705.006"   # Pixel 10 Pro XL
  "comet-CP2A.260705.006"     # Pixel 9 Pro Fold
  "caiman-CP2A.260705.006"    # Pixel 9 Pro
  "tegu-CP2A.260705.006"      # Pixel 9a
  "husky-CP2A.260705.006"     # Pixel 8 Pro
  "shiba-CP2A.260705.006"     # Pixel 8
  "akita-CP2A.260805.005"     # Pixel 8a
  "lynx-CP2A.260705.006"      # Pixel 7a
  "cheetah-CP2A.260705.006"   # Pixel 7 Pro
  "panther-CP2A.260705.006"   # Pixel 7
  "bluejay-CP2A.260705.006"   # Pixel 6a (Android 17)
  "bluejay-CP1A.260405.005"   # Pixel 6a (Android 16)
  "oriole-CP2A.260705.006"    # Pixel 6
)

echo ""
echo "═══ Step 1/3: Build native helper (libcve43499root.so) ═══"
echo ""
mkdir -p "$JNILIBS"
$CC -fPIE -pie -O2 -g0 -Wall -Wextra \
  "$PAYLOADS/src/su_daemon.c" \
  -ldl -o "$JNILIBS/libcve43499root.so"
ls -la "$JNILIBS/libcve43499root.so"
strings "$JNILIBS/libcve43499root.so" | grep -q "run-payload" && \
  echo "  ✓ --run-payload supported" || echo "  ✗ --run-payload MISSING"

echo ""
echo "═══ Step 2/3: Build exploit payloads ═══"
echo ""
for TARGET in "${TARGETS[@]}"; do
  echo "--- $TARGET ---"
  make -C "$PAYLOADS" TARGET="$TARGET" ANDROID_NDK_HOME="$ANDROID_NDK_HOME" release
  SRC="$PAYLOADS/build/$TARGET/cve-2026-43499-app.release.so"
  if [ -f "$SRC" ]; then
    cp "$SRC" "$ASSETS/$TARGET.so"
    echo "  OK: $ASSETS/$TARGET.so ($(stat -f%z "$SRC" 2>/dev/null || stat -c%s "$SRC") bytes)"
  else
    echo "  FAILED: $TARGET (missing $SRC)"
    exit 1
  fi
done

echo ""
echo "═══ Step 3/3: Build APK ═══"
echo ""
cd "$ROOT"
./gradlew assembleDebug

APK="$APP/build/outputs/apk/debug/app-debug.apk"
echo ""
echo "═══ BUILD COMPLETE ═══"
echo "APK: $APK ($(stat -f%z "$APK" 2>/dev/null || stat -c%s "$APK") bytes)"
echo ""
echo "Install: adb install -r $APK"
