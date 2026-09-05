#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$ROOT_DIR/JailbreakDetector"
BUILD_DIR="$HOME/projects/jailbreak-detector-build"
OUTPUT_DIR="$SOURCE_DIR/output"
export THEOS="${THEOS:-$HOME/theos}"

if [[ ! -f "$THEOS/makefiles/common.mk" ]]; then
  echo "找不到 Theos: $THEOS" >&2
  exit 1
fi

echo "使用 Theos: $THEOS"
echo "开始编译独立 SwiftUI RootHide Detector（不会编译 Dopamine）..."

for command_name in rsync make zip; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "缺少命令：$command_name" >&2; exit 1; }
done

if command -v ldconfig >/dev/null 2>&1 && ! ldconfig -p 2>/dev/null | grep -q 'libxml2\.so\.2'; then
  cat >&2 <<'EOF'
缺少 Swift 工具链依赖 libxml2.so.2。
请在 WSL 执行：sudo apt update && sudo apt install -y libxml2
然后重新运行本脚本。
EOF
  exit 1
fi

# 在 Linux 文件系统中编译，避免 /mnt/c 的权限、时间戳和 ldid 问题。
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"
rsync -a --delete --exclude='.theos/' --exclude='packages/' --exclude='output/' "$SOURCE_DIR/" "$BUILD_DIR/"
# Build first, then embed the framework before packaging so both the IPA and
# the resulting DEB contain IOSSecuritySuite.framework.
make -C "$BUILD_DIR" clean all FINALPACKAGE=1

# `make all` places the app in .theos/obj; the package target later stages it
# under .theos/_/Applications. Embed before packaging, so use the build copy.
APP_DIR="$BUILD_DIR/.theos/obj/JailbreakDetector.app"
if [[ ! -d "$APP_DIR" ]]; then
  APP_DIR=$(find "$BUILD_DIR/.theos" -type d -name 'JailbreakDetector.app' | head -n 1 || true)
fi
[[ -d "$APP_DIR" ]] || { echo "未找到构建后的 App：$BUILD_DIR/.theos" >&2; exit 1; }

# Theos does not consistently copy nested Frameworks directories from
# RESOURCE_DIRS. Explicitly embed the dynamic framework in the final app.
FRAMEWORK_SRC="$SOURCE_DIR/Resources/Frameworks/IOSSecuritySuite.framework"
if [[ -d "$FRAMEWORK_SRC" ]]; then
  mkdir -p "$APP_DIR/Frameworks"
  rm -rf "$APP_DIR/Frameworks/IOSSecuritySuite.framework"
  cp -a "$FRAMEWORK_SRC" "$APP_DIR/Frameworks/"
  echo "已嵌入框架：$APP_DIR/Frameworks/IOSSecuritySuite.framework"
else
  echo "未找到 IOSSecuritySuite.framework" >&2
  exit 1
fi

make -C "$BUILD_DIR" package FINALPACKAGE=1

IPA_WORK="$BUILD_DIR/ipa-build"
rm -rf "$IPA_WORK"
mkdir -p "$IPA_WORK/Payload"
cp -a "$APP_DIR" "$IPA_WORK/Payload/"
(cd "$IPA_WORK" && zip -qry "$BUILD_DIR/JailbreakDetector.ipa" Payload)

rm -f "$OUTPUT_DIR/JailbreakDetector.ipa" "$OUTPUT_DIR"/*.deb
cp "$BUILD_DIR/JailbreakDetector.ipa" "$OUTPUT_DIR/"
cp "$BUILD_DIR"/packages/*.deb "$OUTPUT_DIR/"

echo "构建完成：$OUTPUT_DIR/JailbreakDetector.ipa"
