#!/usr/bin/env bash
# guix shell -FCNm manifest.scm
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
# All variables can be overridden from the environment before calling this script.

# Where Android SDK components will be installed by sdkmanager.
ANDROID_HOME="${ANDROID_HOME:-${HOME}/android-sdk}"

# Gradle local cache (wrapper distribution + downloaded dependencies).
GRADLE_USER_HOME="${GRADLE_USER_HOME:-${HOME}/.gradle}"

# Build variant: <flavor><BuildType>
#   flavors    : dev | ref | abn | abnstore | prod
#   build types: Debug | Release
# Example overrides:
#   VARIANT=prodRelease ./build.sh
FLAVOR="${FLAVOR:-dev}"
BUILD_TYPE="${BUILD_TYPE:-Debug}"

# SDK components required by this project:
#   compileSdk = 36  →  platforms;android-36
#   AGP 8.13.2       →  build-tools;35.0.0
SDK_PACKAGES=(
  "platforms;android-36"
  "build-tools;35.0.0"
  "platform-tools"
)

# ── Derived values ─────────────────────────────────────────────────────────────
VARIANT="${FLAVOR}${BUILD_TYPE}"
GRADLE_TASK="assemble${FLAVOR^}${BUILD_TYPE}"

# ── Environment ───────────────────────────────────────────────────────────────
export ANDROID_HOME
export ANDROID_SDK_ROOT="${ANDROID_HOME}" # legacy alias still read by AGP

# JAVA_HOME: derive from javac in PATH (set by Guix via openjdk@21:jdk).
if [ -z "${JAVA_HOME:-}" ]; then
  JAVAC_PATH="$(readlink -f "$(which javac)")"
  export JAVA_HOME
  JAVA_HOME="$(dirname "$(dirname "${JAVAC_PATH}")")"
fi

export PATH="${ANDROID_HOME}/platform-tools:${ANDROID_HOME}/cmdline-tools/latest/bin:${PATH}"
export GRADLE_USER_HOME

echo "==> JAVA_HOME   : ${JAVA_HOME}"
echo "==> ANDROID_HOME: ${ANDROID_HOME}"
echo "==> Variant     : ${VARIANT}"

# ── Android SDK setup ─────────────────────────────────────────────────────────
echo ""
echo "==> Accepting Android SDK licences..."
# 'yes' pipes 'y' for every licence prompt; the command exits non-zero when
# there are no new licences to accept, hence the '|| true'.
yes | sdkmanager --sdk_root="${ANDROID_HOME}" --licenses >/dev/null 2>&1 || true

echo "==> Installing SDK components: ${SDK_PACKAGES[*]}"
sdkmanager --sdk_root="${ANDROID_HOME}" "${SDK_PACKAGES[@]}"

# ── Gradle build ──────────────────────────────────────────────────────────────
echo ""
echo "==> Running: ./gradlew ${GRADLE_TASK}"
./gradlew "${GRADLE_TASK}" \
  --no-daemon \
  --stacktrace \
  -Dorg.gradle.jvmargs="-Xmx4096m -Dfile.encoding=UTF-8"

# ── Output ────────────────────────────────────────────────────────────────────
echo ""
echo "==> Build complete. APK(s):"
find app/build/outputs/apk -name "*.apk" | sort | while read -r apk; do
  echo "    ${apk}"
done
