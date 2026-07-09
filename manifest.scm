;;; Guix manifest for building the eidch-android-wallet.
;;;
;;; Usage:
;;;   guix shell -m manifest.scm
;;;
;;; The Android SDK itself (build-tools, platform SDK) is NOT packaged in Guix
;;; and must be installed separately via sdkmanager:
;;;
;;;   1. Download Android command-line tools from:
;;;        https://developer.android.com/studio#command-tools
;;;   2. Unzip to $ANDROID_HOME/cmdline-tools/latest/
;;;   3. Install required SDK components:
;;;        sdkmanager "platforms;android-36"
;;;        sdkmanager "build-tools;35.0.0"
;;;        sdkmanager "platform-tools"
;;;   4. Accept licences:
;;;        sdkmanager --licenses
;;;
;;; Environment variables required before running ./gradlew:
;;;   export ANDROID_HOME=$HOME/android-sdk
;;;   export ANDROID_SDK_ROOT=$ANDROID_HOME   # legacy alias still used by AGP
;;;   export PATH=$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH

(specifications->manifest
  (list
    ;; ── Java ─────────────────────────────────────────────────────────────────
    ;; jvmToolchain(21) in android-application.gradle.kts requires JDK 21.
    ;; AGP 8.13.2 requires JDK 17+.
    "openjdk@21" "openjdk@21:jdk"

    ;; ── Shell & POSIX utilities ───────────────────────────────────────────────
    ;; Required by gradlew and various Gradle plugins.
    "bash"
    "coreutils"
    "findutils"
    "which"
    "sed"
    "grep"
    "gawk"
    "diffutils"
    "procps"       ; provides 'ps', used by Gradle daemon detection

    ;; ── Archive tools ─────────────────────────────────────────────────────────
    ;; Gradle wrapper downloads and extracts its own distribution (zip).
    ;; sdkmanager also downloads zip archives.
    "unzip"
    "zip"

    ;; ── Network tools ─────────────────────────────────────────────────────────
    ;; Used by the Gradle wrapper to download gradle-8.14.2-bin.zip on first run,
    ;; and by sdkmanager to download SDK components.
    "curl"
    "wget"
    "nss-certs"

    ;; ── Build essentials ──────────────────────────────────────────────────────
    ;; make + gcc are pulled in transitively by some native Android build-tools
    ;; (zxing-cpp, sqlcipher, JNA AAR).
    "gcc-toolchain"
    "make"

    ;; ── Git ───────────────────────────────────────────────────────────────────
    ;; Required by the aboutlibraries Gradle plugin to read VCS metadata,
    ;; and by KSP incremental compilation.
    "git"

    ;; ── Android platform tools ────────────────────────────────────────────────
    ;; Provides adb and fastboot (needed for instrumentation test deployment).
    ;; The full SDK build-tools and platform-36 must be installed via sdkmanager.
    "adb" "fastboot" "sdkmanager"
  ))
