#!/usr/bin/env bash

set -euo pipefail

die() {
    printf 'package-osx.sh: %s\n' "$1" >&2
    exit 1
}

if [[ "$#" -ne 3 ]]; then
    die "usage: $0 <macos-64|macos-arm64> <publish-output> <version>"
fi

Arch="$1"
OutputPath="$2"
Version="$3"

ScriptDir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=macos-assets.sh
source "$ScriptDir/macos-assets.sh"

CoreRef="$PATTN_MACOS_CORE_REF"
XrayReleaseTag="$PATTN_MACOS_XRAY_RELEASE_TAG"

case "$Arch" in
    macos-64)
        XrayAsset="Xray-macos-64.zip"
        ExpectedArchitecture="x86_64"
        CoreSha256="$PATTN_MACOS_CORE_SHA256_X64"
        XraySha256="$PATTN_MACOS_XRAY_SHA256_X64"
        ;;
    macos-arm64)
        XrayAsset="Xray-macos-arm64-v8a.zip"
        ExpectedArchitecture="arm64"
        CoreSha256="$PATTN_MACOS_CORE_SHA256_ARM64"
        XraySha256="$PATTN_MACOS_XRAY_SHA256_ARM64"
        ;;
    *)
        die "unsupported macOS architecture: $Arch"
        ;;
esac

[[ -n "$Version" ]] || die "version must not be empty"
[[ "$Version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-P[0-9]+)?$ ]] || die "invalid version: $Version"
[[ -d "$OutputPath" ]] || die "publish output does not exist: $OutputPath"

for command_name in curl create-dmg find hdiutil lipo otool plutil shasum; do
    command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
done

SevenZip=""
if command -v 7z >/dev/null 2>&1; then
    SevenZip="$(command -v 7z)"
elif command -v 7zz >/dev/null 2>&1; then
    SevenZip="$(command -v 7zz)"
else
    die "required command not found: 7z or 7zz"
fi

assert_architecture() {
    local binary="$1"
    local expected="$2"
    local actual

    actual="$(lipo -archs "$binary")"
    [[ "$actual" == "$expected" ]] || die "unexpected architecture for $binary: expected $expected, got $actual"
}

assert_portable_dependencies() {
    local binary="$1"
    local dependency
    local rpath

    dependency="$(otool -L "$binary" | awk '
        NR > 1 && $1 ~ /^\// &&
        $1 !~ /^\/System\/Library\// &&
        $1 !~ /^\/usr\/lib\// { print $1; exit }
    ')"
    [[ -z "$dependency" ]] || die "non-system absolute dependency in $binary: $dependency"

    rpath="$(otool -l "$binary" | awk '
        $1 == "path" && $2 ~ /^\// &&
        $2 !~ /^\/System\/Library\// &&
        $2 !~ /^\/usr\/lib\// { print $2; exit }
    ')"
    [[ -z "$rpath" ]] || die "non-system absolute rpath in $binary: $rpath"
}

assert_safe_tree() {
    local root="$1"
    local unsafe_entry

    [[ -d "$root" && ! -L "$root" ]] || die "expected a real directory: $root"
    unsafe_entry="$(find "$root" -mindepth 1 ! -type f ! -type d -print -quit)"
    [[ -z "$unsafe_entry" ]] || die "unsupported special file in staged tree: $unsafe_entry"
}

assert_safe_archive() {
    local archive="$1"
    local listing
    local line
    local path
    local first_path=1

    listing="$("$SevenZip" l -slt "$archive")" || die "could not inspect archive: $archive"
    while IFS= read -r line; do
        case "$line" in
            'Path = '*)
                path="${line#Path = }"
                if (( first_path )); then
                    first_path=0
                    continue
                fi
                [[ -n "$path" && "$path" != /* && ! "$path" =~ ^[A-Za-z]: ]] ||
                    die "unsafe archive path in $archive: $path"
                case "/$path/" in
                    */../*|*/./*)
                        die "unsafe archive path in $archive: $path"
                        ;;
                esac
                ;;
        esac
    done <<< "$listing"
}

assert_extracted_tree() {
    local root="$1"

    assert_safe_tree "$root"
}

validate_base_output() {
    local output="$1"
    local main_executable="$output/PattN"
    local amaz_tool="$output/AmazTool"

    assert_safe_tree "$output"
    [[ -f "$main_executable" && ! -L "$main_executable" && -x "$main_executable" ]] ||
        die "publish output is missing executable: $main_executable"
    [[ -f "$amaz_tool" && ! -L "$amaz_tool" && -x "$amaz_tool" ]] ||
        die "publish output is missing executable: $amaz_tool"
    [[ -f "$output/v2rayN.icns" && ! -L "$output/v2rayN.icns" ]] ||
        die "publish output is missing macOS icon: $output/v2rayN.icns"
    [[ -f "$output/v2rayN.png" && ! -L "$output/v2rayN.png" ]] ||
        die "publish output is missing macOS image: $output/v2rayN.png"

    assert_architecture "$main_executable" "$ExpectedArchitecture"
    assert_architecture "$amaz_tool" "$ExpectedArchitecture"
    assert_portable_dependencies "$main_executable"
    assert_portable_dependencies "$amaz_tool"
}

validate_staged_output() {
    local output="$1"
    local xray="$output/bin/xray/xray"

    validate_base_output "$output"
    [[ -f "$xray" && ! -L "$xray" && -x "$xray" ]] ||
        die "staged output is missing Xray: $xray"
    assert_architecture "$xray" "$ExpectedArchitecture"
    assert_portable_dependencies "$xray"
}

verify_sha256() {
    local file="$1"
    local expected="$2"
    local actual

    [[ "$expected" =~ ^[[:xdigit:]]{64}$ ]] || die "invalid expected SHA-256 for $file"
    actual="$(shasum -a 256 "$file" | awk '{ print $1 }')"
    [[ "$actual" == "$expected" ]] ||
        die "SHA-256 mismatch for $file: expected $expected, got $actual"
}

download_asset() {
    local url="$1"
    local output="$2"
    local expected_sha256="$3"

    curl --fail --location --retry 3 --retry-delay 2 \
        --connect-timeout 30 --max-time 900 \
        --proto '=https' --proto-redir '=https' \
        --silent --show-error --output "$output" "$url"
    verify_sha256 "$output" "$expected_sha256"
}

validate_base_output "$OutputPath"

CoreArchiveName="v2rayN-${Arch}.zip"
CoreUrl="https://github.com/2dust/v2rayN-core-bin/raw/${CoreRef}/${CoreArchiveName}"
XrayUrl="https://github.com/patterniha/Xray-core/releases/download/${XrayReleaseTag}/${XrayAsset}"
DmgPath="$PWD/PattN-${Arch}.dmg"
MountActive=false
MountedDevice=""
MountPoint=""
WorkDir="$(mktemp -d "${TMPDIR:-/tmp}/PattN-macos-package.XXXXXX")"
DmgBuildPath="$WorkDir/PattN-${Arch}.dmg"

detach_mount() {
    local target

    [[ "$MountActive" == true ]] || return 0
    target="$MountedDevice"
    [[ -n "$target" ]] || target="$MountPoint"
    if hdiutil detach "$target" >/dev/null 2>&1 || hdiutil detach -force "$target" >/dev/null 2>&1; then
        MountActive=false
        MountedDevice=""
        return 0
    fi
    return 1
}

cleanup() {
    if [[ "$MountActive" == true ]] && ! detach_mount; then
        printf 'package-osx.sh: could not detach validation mount; leaving temporary files at %s\n' \
            "$WorkDir" >&2
        return
    fi
    rm -rf "$WorkDir"
}
trap cleanup EXIT

CoreArchive="$WorkDir/$CoreArchiveName"
download_asset "$CoreUrl" "$CoreArchive" "$CoreSha256"
assert_safe_archive "$CoreArchive"
mkdir -p "$WorkDir/core"
"$SevenZip" x -y "-o$WorkDir/core" "$CoreArchive" >/dev/null

CoreRoot="$WorkDir/core/v2rayN-${Arch}"
assert_extracted_tree "$CoreRoot"

StagePath="$WorkDir/stage"
mkdir -p "$StagePath"
cp -R "$OutputPath"/. "$StagePath"/
cp -R "$CoreRoot"/. "$StagePath"/
validate_base_output "$StagePath"

XrayArchive="$WorkDir/xray-core.zip"
download_asset "$XrayUrl" "$XrayArchive" "$XraySha256"
assert_safe_archive "$XrayArchive"
mkdir -p "$WorkDir/xray"
"$SevenZip" x -y "-o$WorkDir/xray" "$XrayArchive" >/dev/null
assert_extracted_tree "$WorkDir/xray"

XrayBinary="$WorkDir/xray/xray"
[[ -f "$XrayBinary" && ! -L "$XrayBinary" && -x "$XrayBinary" ]] ||
    die "Xray archive has no executable at its expected root: $XrayBinary"
assert_architecture "$XrayBinary" "$ExpectedArchitecture"
assert_portable_dependencies "$XrayBinary"

XrayOutputPath="$StagePath/bin/xray"
mkdir -p "$XrayOutputPath"
cp -f "$XrayBinary" "$XrayOutputPath/xray"
chmod +x "$XrayOutputPath/xray"
validate_staged_output "$StagePath"

PackagePath="$WorkDir/PattN.app"
MacOSPath="$PackagePath/Contents/MacOS"
ResourcesPath="$PackagePath/Contents/Resources"
mkdir -p "$MacOSPath" "$ResourcesPath"
cp -R "$StagePath"/. "$MacOSPath"/

printf '%s\n' 'When this file exists, app will not store configs under this folder' \
    > "$MacOSPath/NotStoreConfigHere.txt"
chmod +x "$MacOSPath/PattN" "$MacOSPath/bin/xray/xray"
cp -f "$MacOSPath/v2rayN.icns" "$ResourcesPath/AppIcon.icns"

cat > "$PackagePath/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key>
  <string>en</string>
  <key>CFBundleLocalizations</key>
  <array>
    <string>zh-Hans</string>
    <string>zh-Hant</string>
    <string>en</string>
    <string>fa</string>
    <string>fr</string>
    <string>ru</string>
    <string>hu</string>
  </array>
  <key>CFBundleDisplayName</key>
  <string>PattN</string>
  <key>CFBundleExecutable</key>
  <string>PattN</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleIconName</key>
  <string>AppIcon</string>
  <key>CFBundleIdentifier</key>
  <string>patterniha.PattN</string>
  <key>CFBundleName</key>
  <string>PattN</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${Version}</string>
  <key>CSResourcesFileMapped</key>
  <true/>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>LSMinimumSystemVersion</key>
  <string>13.6</string>
</dict>
</plist>
EOF

validate_bundle() {
    local bundle_path="$1"
    local bundle_macos="$bundle_path/Contents/MacOS"
    local bundle_plist="$bundle_path/Contents/Info.plist"

    [[ -d "$bundle_path" && ! -L "$bundle_path" ]] || die "missing app bundle: $bundle_path"
    [[ -f "$bundle_plist" && ! -L "$bundle_plist" ]] || die "app bundle is missing Info.plist"
    validate_staged_output "$bundle_macos"
    [[ -f "$bundle_path/Contents/Resources/AppIcon.icns" && ! -L "$bundle_path/Contents/Resources/AppIcon.icns" ]] ||
        die "app bundle is missing AppIcon.icns"
    [[ -f "$bundle_macos/NotStoreConfigHere.txt" && ! -L "$bundle_macos/NotStoreConfigHere.txt" ]] ||
        die "app bundle is missing NotStoreConfigHere.txt"

    plutil -lint "$bundle_plist" >/dev/null
    [[ "$(plutil -extract CFBundleExecutable raw -o - "$bundle_plist")" == "PattN" ]] || die "invalid CFBundleExecutable"
    [[ "$(plutil -extract CFBundleIdentifier raw -o - "$bundle_plist")" == "patterniha.PattN" ]] || die "invalid CFBundleIdentifier"
    [[ "$(plutil -extract CFBundleShortVersionString raw -o - "$bundle_plist")" == "$Version" ]] || die "invalid CFBundleShortVersionString"
}

validate_bundle "$PackagePath"

create-dmg \
    --volname "PattN Installer" \
    --window-size 700 420 \
    --icon-size 100 \
    --icon "PattN.app" 160 185 \
    --hide-extension "PattN.app" \
    --app-drop-link 500 185 \
    "$DmgBuildPath" \
    "$PackagePath"

[[ -f "$DmgBuildPath" && ! -L "$DmgBuildPath" ]] || die "create-dmg did not produce: $DmgBuildPath"
hdiutil verify "$DmgBuildPath" >/dev/null

MountPoint="$WorkDir/mount"
mkdir -p "$MountPoint"
MountActive=true
if ! AttachOutput="$(hdiutil attach -nobrowse -readonly -mountpoint "$MountPoint" "$DmgBuildPath")"; then
    detach_mount || MountActive=false
    die "could not attach validation DMG"
fi
MountedDevice="$(printf '%s\n' "$AttachOutput" | awk '/^\/dev\// { print $1; exit }')"
validate_bundle "$MountPoint/PattN.app"
detach_mount || die "could not detach validation mount"

mv -f "$DmgBuildPath" "$DmgPath"
[[ -f "$DmgPath" && ! -L "$DmgPath" ]] || die "could not publish DMG: $DmgPath"
hdiutil verify "$DmgPath" >/dev/null
printf 'Created and validated %s\n' "$DmgPath"
