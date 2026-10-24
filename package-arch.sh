#!/usr/bin/env bash
# PattN: builds a pacman package (.pkg.tar.zst) for Arch Linux and its derivatives (x86_64 only).
#
# It follows package-debian.sh step by step: publish the self-contained desktop build, stage the cores (the
# patterniha/Xray-core fork, sing-box), the geo rules and the Aether core in bin/ (package-aether.sh), and install the
# result under /opt/v2rayN with the same launcher, desktop entry and icon as the .deb. Only the last step differs:
# a throw-away PKGBUILD wraps the staged tree and makepkg builds the package.
#
# Usage: ./package-arch.sh [version] [--buildfrom 1|2|3] [--netcore] [--with-core xray|sing-box|both]
#                          [--xray-ver X] [--singbox-ver X] [--arch x64]
# Output: ~/archbuild/v2rayn-<pkgver>-1-x86_64.pkg.tar.zst   (pkgver is the version with "-" turned into ".")
#
# Needs an Arch-family system (pacman, makepkg). Run as a normal user with sudo, or as root (CI container): makepkg
# refuses to run as root, so the packaging step then runs as a temporary user.
set -euo pipefail

VERSION_ARG=""
WITH_CORE="both"
FORCE_NETCORE=0
ARCH_OVERRIDE=""
BUILD_FROM=""
XRAY_VER="${XRAY_VER:-}"
SING_VER="${SING_VER:-}"

PKGNAME="v2rayn"
PROJECT_HINT="v2rayN.Desktop/v2rayN.Desktop.csproj"
OUTPUT_DIR="${HOME}/archbuild"
RID="linux-x64"

OS_ID=""
OS_NAME=""
HOST_ARCH=""
SCRIPT_DIR=""
PROJECT=""
VERSION=""

declare -a BUILT_PKGS=()

die() {
  echo "$*" >&2
  exit 1
}

as_root() {
  if [[ "$EUID" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

parse_args() {
  local first_arg="${1:-}"

  if [[ -n "$first_arg" && "$first_arg" != --* ]]; then
    VERSION_ARG="$first_arg"
    shift || true
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --with-core)   WITH_CORE="${2:-both}"; shift 2 ;;
      --xray-ver)    XRAY_VER="${2:-}"; shift 2 ;;
      --singbox-ver) SING_VER="${2:-}"; shift 2 ;;
      --netcore)     FORCE_NETCORE=1; shift ;;
      --arch)        ARCH_OVERRIDE="${2:-}"; shift 2 ;;
      --buildfrom)   BUILD_FROM="${2:-}"; shift 2 ;;
      *)
        [[ -n "${VERSION_ARG:-}" ]] || VERSION_ARG="$1"
        shift
        ;;
    esac
  done

  if [[ -n "${VERSION_ARG:-}" && -n "${BUILD_FROM:-}" ]]; then
    die "You cannot specify both an explicit version and --buildfrom at the same time.
        Provide either a version (e.g. 7.14.0) OR --buildfrom 1|2|3."
  fi

  case "${ARCH_OVERRIDE:-}" in
    ""|x64|x86_64|amd64) ;;
    *) die "Unknown --arch '${ARCH_OVERRIDE}'. Arch Linux packages are built for x64 only." ;;
  esac
}

detect_environment() {
  . /etc/os-release

  OS_ID="${ID:-}"
  OS_NAME="${NAME:-$OS_ID}"
  HOST_ARCH="$(uname -m)"

  case " ${OS_ID} ${ID_LIKE:-} " in
    *" arch "*)
      echo "Detected supported system: ${OS_NAME:-$OS_ID}"
      ;;
    *)
      die "Unsupported system: ${OS_NAME:-unknown} (${OS_ID:-unknown}).
This script only supports: Arch Linux and Arch-based distributions."
      ;;
  esac

  [[ "$HOST_ARCH" == "x86_64" ]] || die "Only supports x86_64"
}

install_dependencies() {
  mkdir -p "$OUTPUT_DIR"

  command -v pacman >/dev/null 2>&1 || die "pacman not found"

  as_root pacman -Syu --noconfirm --needed \
    base-devel git curl unzip tar jq rsync ca-certificates fakeroot file \
    desktop-file-utils xdg-utils wget python openssl dotnet-sdk-10.0

  if ! dotnet --info >/dev/null 2>&1; then
    echo "Could not set up the .NET SDK. Make sure these are available:"
    echo "dotnet-sdk 10.x, curl, unzip, tar, rsync, git, makepkg (base-devel), desktop-file-utils, xdg-utils"
    exit 1
  fi
}

prepare_workspace() {
  SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  cd "$SCRIPT_DIR"

  if [[ -f .gitmodules ]]; then
    git submodule sync --recursive || true
    git submodule update --init --recursive || true
  fi

  PROJECT="$PROJECT_HINT"
  [[ -f "$PROJECT" ]] || PROJECT="$(find . -maxdepth 3 -name 'v2rayN.Desktop.csproj' | head -n1 || true)"
  [[ -f "$PROJECT" ]] || die "v2rayN.Desktop.csproj not found"
}

choose_channel() {
  local ch="latest"
  local sel=""

  if [[ -n "${BUILD_FROM:-}" ]]; then
    case "$BUILD_FROM" in
      1) echo "latest"; return 0 ;;
      2) echo "prerelease"; return 0 ;;
      3) echo "keep"; return 0 ;;
      *) die "[ERROR] Invalid --buildfrom value: ${BUILD_FROM}. Use 1|2|3." ;;
    esac
  fi

  if [[ -t 0 ]]; then
    echo "[?] Choose v2rayN release channel:" >&2
    echo "    1) Latest (stable)  [default]" >&2
    echo "    2) Pre-release (preview)" >&2
    echo "    3) Keep current (do nothing)" >&2
    printf "Enter 1, 2 or 3 [default 1]: " >&2

    if read -r sel </dev/tty; then
      case "${sel:-}" in
        2) ch="prerelease" ;;
        3) ch="keep" ;;
      esac
    fi
  fi

  echo "$ch"
}

get_latest_tag_latest() {
  curl -fsSL "https://api.github.com/repos/2dust/v2rayN/releases/latest" \
    | jq -re '.tag_name' \
    | sed 's/^v//'
}

get_latest_tag_prerelease() {
  curl -fsSL "https://api.github.com/repos/2dust/v2rayN/releases?per_page=20" \
    | jq -re 'first(.[] | select(.prerelease == true) | .tag_name)' \
    | sed 's/^v//'
}

sync_submodules() {
  if [[ -f .gitmodules ]]; then
    git submodule sync --recursive || true
    git submodule update --init --recursive || true
  fi
}

git_try_checkout() {
  local want="$1"
  local ref=""

  if git rev-parse --git-dir >/dev/null 2>&1; then
    git fetch --tags --force --prune --depth=1 || true
    git rev-parse "refs/tags/${want}" >/dev/null 2>&1 && ref="$want"

    if [[ -n "$ref" ]]; then
      echo "[OK] Found ref '${ref}', checking out..."
      git checkout -f "$ref"
      sync_submodules
      return 0
    fi
  fi

  return 1
}

apply_channel_or_keep() {
  local ch="$1"
  local tag=""

  if [[ "$ch" == "keep" ]]; then
    echo "[*] Keep current repository state (no checkout)."
    VERSION="$(git describe --tags --abbrev=0 2>/dev/null || echo '0.0.0+git')"
    VERSION="${VERSION#v}"
    return 0
  fi

  echo "[*] Resolving ${ch} tag from GitHub releases..."

  case "$ch" in
    latest)     tag="$(get_latest_tag_latest || true)" ;;
    prerelease) tag="$(get_latest_tag_prerelease || true)" ;;
    *)          die "Failed to resolve latest tag for channel '${ch}'." ;;
  esac

  [[ -n "$tag" ]] || die "Failed to resolve latest tag for channel '${ch}'."

  echo "[*] Latest tag for '${ch}': ${tag}"
  git_try_checkout "$tag" || die "Failed to checkout '${tag}'."
  VERSION="${tag#v}"
}

resolve_version() {
  if git rev-parse --git-dir >/dev/null 2>&1; then
    if [[ -n "${VERSION_ARG:-}" ]]; then
      local clean_ver="${VERSION_ARG#v}"

      if git_try_checkout "$clean_ver"; then
        VERSION="$clean_ver"
      else
        echo "[WARN] Tag '${VERSION_ARG}' not found."
        apply_channel_or_keep "$(choose_channel)"
      fi
    else
      apply_channel_or_keep "$(choose_channel)"
    fi
  else
    echo "Current directory is not a git repo; proceeding on current tree."
    VERSION="${VERSION_ARG:-0.0.0}"
  fi

  VERSION="${VERSION#v}"
  echo "[*] GUI version resolved as: ${VERSION}"
}

download_xray() {
  local outdir="$1"
  local ver="${XRAY_VER:-}"
  local url=""
  local tmp=""

  mkdir -p "$outdir"

  if [[ -z "$ver" ]]; then
    # PattN: resolve the latest tag from the release redirect (the anonymous GitHub API is rate-limited on CI runners)
    ver="$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/patterniha/Xray-core/releases/latest | sed -E 's#.*/releases/tag/v##')" || true
    [[ "$ver" =~ ^[0-9] ]] || ver=""
  fi

  [[ -n "$ver" ]] || { echo "[xray] Failed to get version"; return 1; }
  url="https://github.com/patterniha/Xray-core/releases/download/v${ver}/Xray-linux-64.zip"

  echo "[+] Download xray: $url"

  tmp="$(mktemp -d)"
  curl -fL "$url" -o "$tmp/xray.zip" || { rm -rf "$tmp"; return 1; }
  unzip -q "$tmp/xray.zip" -d "$tmp" || { rm -rf "$tmp"; return 1; }
  install -m 755 "$tmp/xray" "$outdir/xray" || { rm -rf "$tmp"; return 1; }
  rm -rf "$tmp"
}

download_singbox() {
  local outdir="$1"
  local ver="${SING_VER:-}"
  local url=""
  local tmp=""
  local bin=""
  local cronet=""

  mkdir -p "$outdir"

  if [[ -z "$ver" ]]; then
    ver="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest \
      | grep -Eo '"tag_name":\s*"v[^"]+"' \
      | sed -E 's/.*"v([^"]+)".*/\1/' \
      | head -n1)" || true
  fi

  [[ -n "$ver" ]] || { echo "[sing-box] Failed to get version"; return 1; }
  url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-amd64.tar.gz"

  echo "[+] Download sing-box: $url"

  tmp="$(mktemp -d)"
  curl -fL "$url" -o "$tmp/singbox.tar.gz" || { rm -rf "$tmp"; return 1; }
  tar -C "$tmp" -xzf "$tmp/singbox.tar.gz" || { rm -rf "$tmp"; return 1; }

  bin="$(find "$tmp" -type f -name 'sing-box' | head -n1 || true)"
  [[ -n "$bin" ]] || { echo "[!] sing-box unpack failed"; rm -rf "$tmp"; return 1; }

  install -m 755 "$bin" "$outdir/sing-box" || { rm -rf "$tmp"; return 1; }

  cronet="$(find "$tmp" -type f -name 'libcronet*.so*' | head -n1 || true)"
  [[ -n "$cronet" ]] && install -m 644 "$cronet" "$outdir/libcronet.so" || true

  rm -rf "$tmp"
}

unify_geo_layout() {
  local outroot="$1"
  local n
  local names=(
    geosite.dat
    geoip.dat
    geoip-only-cn-private.dat
    Country.mmdb
    geoip.metadb
  )

  mkdir -p "$outroot/bin"

  for n in "${names[@]}"; do
    if [[ -f "$outroot/bin/xray/$n" ]]; then
      mv -f "$outroot/bin/xray/$n" "$outroot/bin/$n"
    fi
  done
}

download_geo_assets() {
  local outroot="$1"
  local bin_dir="$outroot/bin"
  local srss_dir="$bin_dir/srss"
  local f=""

  mkdir -p "$bin_dir" "$srss_dir"

  echo "[+] Download Xray Geo to ${bin_dir}"
  curl -fsSL -o "$bin_dir/geosite.dat" "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geosite.dat"
  curl -fsSL -o "$bin_dir/geoip.dat" "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/geoip.dat"
  curl -fsSL -o "$bin_dir/geoip-only-cn-private.dat" "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip-only-cn-private.dat"
  curl -fsSL -o "$bin_dir/Country.mmdb" "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"

  echo "[+] Download sing-box rule DB & rule-sets"
  curl -fsSL -o "$bin_dir/geoip.metadb" "https://github.com/MetaCubeX/meta-rules-dat/releases/latest/download/geoip.metadb"

  for f in geoip-private.srs geoip-cn.srs geoip-facebook.srs geoip-fastly.srs geoip-google.srs geoip-netflix.srs geoip-telegram.srs geoip-twitter.srs; do
    curl -fsSL -o "$srss_dir/$f" "https://raw.githubusercontent.com/2dust/sing-box-rules/refs/heads/rule-set-geoip/$f"
  done

  for f in geosite-cn.srs geosite-gfw.srs geosite-google.srs geosite-greatfire.srs geosite-geolocation-cn.srs geosite-category-ads-all.srs geosite-private.srs; do
    curl -fsSL -o "$srss_dir/$f" "https://raw.githubusercontent.com/2dust/sing-box-rules/refs/heads/rule-set-geosite/$f"
  done

  for f in geosite-category-ir.srs geoip-ir.srs; do
    curl -fsSL -o "$srss_dir/$f" "https://raw.githubusercontent.com/chocolate4u/Iran-sing-box-rules/rule-set/$f"
  done

  unify_geo_layout "$outroot"
}

populate_assets_zip_mode() {
  local outroot="$1"
  local url=""
  local tmp=""
  local nested_dir=""

  url="https://raw.githubusercontent.com/2dust/v2rayN-core-bin/refs/heads/master/v2rayN-linux-64.zip"

  echo "[+] Try v2rayN bundle archive: $url"

  tmp="$(mktemp -d)"
  curl -fL "$url" -o "$tmp/v2rayn.zip" || { echo "[!] Bundle download failed"; rm -rf "$tmp"; return 1; }
  unzip -q "$tmp/v2rayn.zip" -d "$tmp" || { echo "[!] Bundle unzip failed"; rm -rf "$tmp"; return 1; }

  if [[ -d "$tmp/bin" ]]; then
    mkdir -p "$outroot/bin"
    rsync -a "$tmp/bin/" "$outroot/bin/"
  else
    rsync -a "$tmp/" "$outroot/"
  fi

  rm -f "$outroot/v2rayn.zip" 2>/dev/null || true
  find "$outroot" -type d -name "mihomo" -prune -exec rm -rf {} + 2>/dev/null || true

  nested_dir="$(find "$outroot" -maxdepth 1 -type d -name 'v2rayN-linux-*' | head -n1 || true)"
  if [[ -n "$nested_dir" && -d "$nested_dir/bin" ]]; then
    mkdir -p "$outroot/bin"
    rsync -a "$nested_dir/bin/" "$outroot/bin/"
    rm -rf "$nested_dir"
  fi

  unify_geo_layout "$outroot"
  rm -rf "$tmp"

  echo "[+] Bundle extracted to $outroot"
}

populate_assets_netcore_mode() {
  local outroot="$1"

  mkdir -p "$outroot/bin/xray" "$outroot/bin/sing_box"

  if [[ "$WITH_CORE" == "xray" || "$WITH_CORE" == "both" ]]; then
    download_xray "$outroot/bin/xray" || echo "[!] xray download failed (skipped)"
  fi

  if [[ "$WITH_CORE" == "sing-box" || "$WITH_CORE" == "both" ]]; then
    download_singbox "$outroot/bin/sing_box" || echo "[!] sing-box download failed (skipped)"
  fi

  download_geo_assets "$outroot" || echo "[!] Geo rules download failed (skipped)"
}

stage_runtime_assets() {
  local outroot="$1"

  mkdir -p "$outroot/bin/xray" "$outroot/bin/sing_box"

  if [[ "$FORCE_NETCORE" -eq 0 ]]; then
    if populate_assets_zip_mode "$outroot"; then
      # PattN: the core-bin bundle ships upstream Xray; replace it with patterniha/Xray-core
      download_xray "$outroot/bin/xray" || { echo "[!] PattN: failed to fetch patterniha/Xray-core, aborting"; return 1; }
      # PattN: replace bundled geo files with Chocolate4U + Iran rule-sets
      download_geo_assets "$outroot" || echo "[!] Geo rules download failed (kept bundle defaults)"
      echo "[*] Using v2rayN bundle bin assets."
    else
      echo "[*] Bundle failed, fallback to separate core + rules."
      populate_assets_netcore_mode "$outroot"
    fi
  else
    echo "[*] --netcore specified: use separate core + rules."
    populate_assets_netcore_mode "$outroot"
  fi

  # PattN: the Aether core in bin/aether and Psiphon's server list in bin (package-aether.sh); a failed checksum or
  # signature check fails the package, so a broken or foreign download never ships
  bash "$SCRIPT_DIR/package-aether.sh" "linux-64" "$outroot/bin" || { echo "[!] PattN: failed to bundle patterniha/Aether and Psiphon's server list, aborting"; return 1; }
}

publish_binary() {
  dotnet clean "$PROJECT" -c Release
  rm -rf "$(dirname "$PROJECT")/bin/Release/net10.0" || true
  dotnet restore "$PROJECT"
  dotnet publish "$PROJECT" -c Release -r "$RID" -p:PublishSingleFile=false -p:SelfContained=true ${VERSION_ARG:+-p:Version=${VERSION_ARG#v}}
}

write_launcher_file() {
  local stage="$1"

  install -m 755 /dev/stdin "$stage/usr/bin/v2rayn" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DIR="/opt/v2rayN"
cd "$DIR"

if [[ -x "$DIR/PattN" ]]; then
  exec "$DIR/PattN" "$@"
fi

for dll in PattN.dll; do
  if [[ -f "$DIR/$dll" ]]; then
    exec /usr/bin/dotnet "$DIR/$dll" "$@"
  fi
done

echo "PattN launcher: no executable found in $DIR" >&2
ls -l "$DIR" >&2 || true
exit 1
EOF
}

write_desktop_file() {
  local stage="$1"

  install -m 644 /dev/stdin "$stage/usr/share/applications/v2rayn.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=PattN
Comment=PattN for Arch Linux
Exec=v2rayn
Icon=v2rayn
StartupWMClass=PattN
Terminal=false
Categories=Network;
EOF
}

# Writes the PKGBUILD that wraps the staged tree: $1 = build dir, $2 = staged tree, $3 = pkgver.
# The tree is copied as it is: no source download, no build() step, and no stripping, which the self-contained .NET
# runtime and the bundled cores must not go through.
write_pkgbuild() {
  local build_dir="$1"
  local stage="$2"
  local pkgver="$3"

  {
    printf 'pkgname=%s\n' "$PKGNAME"
    printf 'pkgver=%s\n' "$pkgver"
    printf '_stage=%q\n' "$stage"
  } > "$build_dir/PKGBUILD"

  cat >> "$build_dir/PKGBUILD" <<'EOF'
pkgrel=1
pkgdesc="PattN (Avalonia) GUI client for Linux, with the patterniha Xray-core fork, sing-box and Aether cores"
arch=('x86_64')
url="https://github.com/patterniha/PattN"
license=('GPL-3.0-only')
# the same runtime needs as the .deb and .rpm (fontconfig, freetype, ICU, OpenSSL, cairo, pango, GL), plus the X11
# client libraries Avalonia loads at start-up
depends=('bash' 'coreutils' 'desktop-file-utils' 'xdg-utils'
         'glibc' 'fontconfig' 'freetype2' 'icu' 'openssl' 'cairo' 'pango' 'mesa'
         'libx11' 'libice' 'libsm')
options=('!strip' '!debug' '!emptydirs')

package() {
    cp -a --no-preserve=ownership "${_stage}/." "${pkgdir}/"
}
EOF
}

# makepkg refuses to run as root: in a root container the packaging step runs as a temporary user.
run_makepkg() {
  local build_dir="$1"

  mkdir -p "$build_dir/out"

  if [[ "$EUID" -eq 0 ]]; then
    id -u pattnbuild >/dev/null 2>&1 || useradd -m -s /bin/bash pattnbuild
    chown -R pattnbuild "$build_dir"
    su pattnbuild -s /bin/bash -c "cd '$build_dir' && PKGDEST='$build_dir/out' makepkg -d -f --noconfirm"
  else
    ( cd "$build_dir" && PKGDEST="$build_dir/out" makepkg -d -f --noconfirm )
  fi
}

package_binary() {
  local pubdir=""
  local workdir=""
  local stage=""
  local build_dir=""
  local pkgver=""
  local project_dir=""
  local icon_candidate=""
  local core=""
  local built=""

  pubdir="$(dirname "$PROJECT")/bin/Release/net10.0/${RID}/publish"
  [[ -d "$pubdir" ]] || { echo "Publish directory not found: $pubdir"; return 1; }

  workdir="$(mktemp -d)"
  trap '[[ -n "${workdir:-}" ]] && rm -rf "$workdir"' RETURN
  # the temporary makepkg user (root containers) must be able to reach the staged tree
  chmod 0755 "$workdir"

  stage="$workdir/stage"
  build_dir="$workdir/build"

  mkdir -p "$stage/opt/v2rayN" "$stage/usr/bin" "$stage/usr/share/applications" "$stage/usr/share/icons/hicolor/256x256/apps" "$build_dir"
  cp -a "$pubdir/." "$stage/opt/v2rayN/"

  project_dir="$(cd "$(dirname "$PROJECT")" && pwd)"
  icon_candidate="$project_dir/v2rayN.png"
  [[ -f "$icon_candidate" ]] && cp "$icon_candidate" "$stage/usr/share/icons/hicolor/256x256/apps/v2rayn.png" || true

  stage_runtime_assets "$stage/opt/v2rayN"
  write_launcher_file "$stage"
  write_desktop_file "$stage"

  find "$stage/opt/v2rayN" -type d -exec chmod 0755 {} +
  find "$stage/opt/v2rayN" -type f -exec chmod 0644 {} +
  [[ -f "$stage/opt/v2rayN/PattN" ]] && chmod 0755 "$stage/opt/v2rayN/PattN" || true

  # Core binaries must be executable before installation: ordinary users cannot
  # chmod the root-owned files installed by pacman.
  for core in xray/xray sing_box/sing-box mihomo/mihomo; do
    if [[ -f "$stage/opt/v2rayN/bin/$core" ]]; then
      chmod 0755 "$stage/opt/v2rayN/bin/$core"
    fi
  done
  # PattN: and so must the Aether core and the two programs it runs
  for core in aether/aether aether/lyrebird aether/psiphon-tunnel-core; do
    if [[ -f "$stage/opt/v2rayN/bin/$core" ]]; then
      chmod 0755 "$stage/opt/v2rayN/bin/$core"
    fi
  done

  # pkgver may not contain a hyphen (7.25.6-P37 -> 7.25.6.P37) or anything outside [A-Za-z0-9._+]
  pkgver="$(printf '%s' "${VERSION//-/.}" | tr -c 'A-Za-z0-9._+' '_')"

  write_pkgbuild "$build_dir" "$stage" "$pkgver"
  run_makepkg "$build_dir"

  built="$(find "$build_dir/out" -maxdepth 1 -name "${PKGNAME}-*.pkg.tar.*" ! -name '*.sig' | head -n1 || true)"
  [[ -n "$built" ]] || { echo "makepkg produced no package"; return 1; }

  cp -f "$built" "$OUTPUT_DIR/"
  echo "Build done. Package at:"
  echo "  $OUTPUT_DIR/$(basename "$built")"
  BUILT_PKGS+=("$OUTPUT_DIR/$(basename "$built")")
}

print_summary() {
  local pkg=""

  echo ""
  echo "================ Build Summary ================="
  if [[ "${#BUILT_PKGS[@]}" -gt 0 ]]; then
    echo "Output directory: $OUTPUT_DIR"
    for pkg in "${BUILT_PKGS[@]}"; do
      echo "$pkg"
    done
  else
    echo "No packages detected in summary (check build logs above)."
  fi
  echo "==============================================="
}

main() {
  parse_args "$@"
  detect_environment
  install_dependencies
  prepare_workspace
  resolve_version

  echo "[*] Building for target: x64  (RID=$RID, pacman arch=x86_64)"
  publish_binary
  package_binary

  print_summary
}

main "$@"
