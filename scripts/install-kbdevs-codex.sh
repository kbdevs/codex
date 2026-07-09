#!/usr/bin/env sh
set -eu

repo="kbdevs/codex"
bin_dir="${CODEX_INSTALL_DIR:-${HOME}/.local/bin}"
bin_path="${bin_dir}/codex"
codex_home="${CODEX_HOME:-${HOME}/.codex}"
standalone_root="${codex_home}/packages/standalone"
releases_dir="${standalone_root}/releases"
current_link="${standalone_root}/current"
tmp_dir="$(mktemp -d)"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

os="$(uname -s)"
arch="$(uname -m)"

case "$os:$arch" in
  Darwin:arm64) target="aarch64-apple-darwin" ;;
  Darwin:x86_64) target="x86_64-apple-darwin" ;;
  Linux:x86_64) target="x86_64-unknown-linux-musl" ;;
  Linux:aarch64|Linux:arm64) target="aarch64-unknown-linux-musl" ;;
  *)
    echo "Unsupported platform: $os $arch" >&2
    exit 1
    ;;
esac

asset="codex-${target}.tar.gz"
url="https://github.com/${repo}/releases/latest/download/${asset}"
release_dir="${releases_dir}/kbdevs-latest-${target}"

mkdir -p "$tmp_dir/download" "$tmp_dir/release" "$releases_dir" "$bin_dir"
curl -fsSL "$url" -o "$tmp_dir/$asset"
tar -xzf "$tmp_dir/$asset" -C "$tmp_dir/download"
install -m 755 "$tmp_dir/download/codex" "$tmp_dir/release/codex"
install -m 755 "$tmp_dir/download/codex-code-mode-host" "$tmp_dir/release/codex-code-mode-host"

rm -rf "$release_dir"
mv "$tmp_dir/release" "$release_dir"

if [ -L "$current_link" ]; then
  rm -f "$current_link"
elif [ -e "$current_link" ]; then
  backup="${current_link}.backup.$(date +%s)"
  mv "$current_link" "$backup"
fi
ln -s "$release_dir" "$current_link"

if [ -L "$bin_path" ] || [ -e "$bin_path" ]; then
  rm -f "$bin_path"
fi
ln -s "$current_link/codex" "$bin_path"

if [ "${CODEX_NON_INTERACTIVE:-}" != "1" ]; then
  echo "Installed kbdevs Codex to $bin_path"
  case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) echo "Add $bin_dir to PATH before other Codex installs." ;;
  esac
fi
