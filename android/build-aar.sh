#!/usr/bin/env bash
# Builds the Go agent (android/mobile) into app/libs/mobile.aar.
# Requires the Android SDK + NDK (ANDROID_HOME, ANDROID_NDK_HOME). gomobile and
# gobind are pinned in go.mod and installed into a local bin dir.
set -euo pipefail

cd "$(dirname "$0")"
bin="$(pwd)/build/bin"
mkdir -p "$bin" app/libs
GOBIN="$bin" go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
export PATH="$bin:$PATH"

# max-page-size makes the native library loadable on devices with 16 KB pages.
gomobile bind \
  -ldflags="-extldflags=-Wl,-z,max-page-size=16384" \
  -target=android/arm64,android/arm \
  -androidapi 26 \
  -o app/libs/mobile.aar \
  ./mobile
