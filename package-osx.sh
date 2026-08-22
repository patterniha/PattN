#!/bin/bash

Arch="$1"
OutputPath="$2"
Version="$3"

FileName="v2rayN-${Arch}.zip"
wget -nv -O $FileName "https://github.com/2dust/v2rayN-core-bin/raw/refs/heads/master/$FileName"
7z x $FileName
cp -rf v2rayN-${Arch}/* $OutputPath

# PattN: bundle patterniha/Xray-core instead of the upstream core shipped in v2rayN-core-bin
case "$Arch" in
  macos-64)    XrayAsset="Xray-macos-64.zip" ;;
  macos-arm64) XrayAsset="Xray-macos-arm64-v8a.zip" ;;
esac
wget -nv -O xray-core.zip "https://github.com/patterniha/Xray-core/releases/latest/download/$XrayAsset"
7z x -y -oxray-core xray-core.zip
mkdir -p "$OutputPath/bin/xray"
cp -f xray-core/xray "$OutputPath/bin/xray/xray"
chmod +x "$OutputPath/bin/xray/xray"

PackagePath="v2rayN-Package-${Arch}"
mkdir -p "$PackagePath/PattN.app/Contents/Resources"
cp -rf "$OutputPath" "$PackagePath/PattN.app/Contents/MacOS"
cp -f "$PackagePath/PattN.app/Contents/MacOS/v2rayN.icns" "$PackagePath/PattN.app/Contents/Resources/AppIcon.icns"
echo "When this file exists, app will not store configs under this folder" > "$PackagePath/PattN.app/Contents/MacOS/NotStoreConfigHere.txt"
chmod +x "$PackagePath/PattN.app/Contents/MacOS/PattN"

cat >"$PackagePath/PattN.app/Contents/Info.plist" <<-EOF
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
  <string>2dust.v2rayN</string>
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

create-dmg \
    --volname "PattN Installer" \
    --window-size 700 420 \
    --icon-size 100 \
    --icon "PattN.app" 160 185 \
    --hide-extension "PattN.app" \
    --app-drop-link 500 185 \
    "PattN-${Arch}.dmg" \
    "$PackagePath/PattN.app"
