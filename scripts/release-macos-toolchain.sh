#!/usr/bin/env bash
# Sourced by release-build.sh, including its preflight-only mode. These pins
# belong to the release commit, never the operator's current checkout.
MACOS_XCODE_VERSION=27.1
MACOS_XCODE_BUILD=27A9275
MACOS_SDK_VERSION=27.0
MACOS_CLANG_VERSION='Apple clang version 21.0.0 (clang-2100.3.34.2)'

macos_toolchain_die() {
  printf 'macOS toolchain preflight: %s\n' "$*" >&2
  printf 'Install Xcode %s (build %s), SDK %s, %s. Select it with:\n  sudo xcode-select -s /Applications/Xcode_%s.app\nCheck DEVELOPER_DIR, SDKROOT and TOOLCHAINS overrides; see docs/ops/RELEASE_POLICY.md. Refusing before rebuild.\n' \
    "$MACOS_XCODE_VERSION" "$MACOS_XCODE_BUILD" "$MACOS_SDK_VERSION" "$MACOS_CLANG_VERSION" "$MACOS_XCODE_VERSION" >&2
  exit 1
}

macos_toolchain_prepare() {
  local xcode sdk clang_line tool suffix variable target_key
  for tool in xcodebuild xcrun; do
    command -v "$tool" >/dev/null || macos_toolchain_die "$tool not found"
  done
  xcode=$(xcodebuild -version) || macos_toolchain_die 'cannot read selected Xcode'
  [ "$xcode" = "$(printf 'Xcode %s\nBuild version %s' "$MACOS_XCODE_VERSION" "$MACOS_XCODE_BUILD")" ] ||
    macos_toolchain_die "Xcode mismatch: found [$xcode]"
  sdk=$(xcrun --sdk macosx --show-sdk-version) || macos_toolchain_die 'cannot read macOS SDK'
  [ "$sdk" = "$MACOS_SDK_VERSION" ] || macos_toolchain_die "SDK mismatch: found [$sdk]"
  MACOS_SDK_PATH=$(xcrun --sdk macosx --show-sdk-path) || macos_toolchain_die 'cannot locate macOS SDK'
  [ -n "$MACOS_SDK_PATH" ] || macos_toolchain_die 'empty macOS SDK path'
  if [ -n "${SDKROOT:-}" ] && [ "$SDKROOT" != "$MACOS_SDK_PATH" ]; then
    macos_toolchain_die "SDKROOT overrides selected SDK: [$SDKROOT]"
  fi
  CC=$(xcrun --sdk macosx --find clang) || macos_toolchain_die 'cannot locate Apple clang'
  MACOS_CLANG_OUTPUT=$("$CC" --version) || macos_toolchain_die 'cannot read Apple clang version'
  clang_line=${MACOS_CLANG_OUTPUT%%$'\n'*}
  [ "$clang_line" = "$MACOS_CLANG_VERSION" ] || macos_toolchain_die "clang mismatch: found [$clang_line]"
  CXX=$(xcrun --sdk macosx --find clang++) || macos_toolchain_die 'cannot locate Apple clang++'
  AR=$(xcrun --sdk macosx --find ar) || macos_toolchain_die 'cannot locate Apple ar'
  # cc-rs gives target-specific variables priority over CC/CXX/AR/CFLAGS.
  # Reject these rather than validating one compiler and building with another.
  for tool in CC CXX AR CFLAGS CXXFLAGS ARFLAGS; do
    for suffix in "$TARGET" "${TARGET//-/_}"; do
      variable="${tool}_$suffix"
      if printenv "$variable" >/dev/null; then
        macos_toolchain_die "remove native tool override $variable"
      fi
    done
    for variable in "TARGET_$tool" "HOST_$tool"; do
      if printenv "$variable" >/dev/null; then
        macos_toolchain_die "remove native tool override $variable"
      fi
    done
  done
  SDKROOT=$MACOS_SDK_PATH
  export CC CXX AR SDKROOT
  target_key=$(printf '%s' "$TARGET" | tr '[:lower:]-' '[:upper:]_')
  export "CARGO_TARGET_${target_key}_LINKER=$CC"
}

macos_toolchain_evidence() {
  printf 'target=%s\nxcode_version=%s\nxcode_build=%s\nsdk_version=%s\nsdk_path=%s\n' \
    "$TARGET" "$MACOS_XCODE_VERSION" "$MACOS_XCODE_BUILD" "$MACOS_SDK_VERSION" "$MACOS_SDK_PATH"
  printf 'runner_image=%s\nrunner_image_version=%s\nclang --version:\n%s\n' \
    "${ImageOS:-local}" "${ImageVersion:-local}" "$MACOS_CLANG_OUTPUT"
}
