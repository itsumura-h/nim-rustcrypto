#!/usr/bin/env sh
set -eu

package_root=${1:?package root is required}
target_id="linux-x86_64"
archive_name="librust_crypto_ffi.a"

version=$(awk -F'"' '/^version[[:space:]]*=/{print $2; exit}' "$package_root/rustcrypto.nimble")
module_root="$package_root/src/rustcrypto"
if [ ! -d "$module_root" ]; then
  module_root="$package_root/rustcrypto"
fi

module_destination_archive="$module_root/vendor/rustcrypto-ffi/$target_id/$archive_name"
module_destination_dir=$(dirname "$module_destination_archive")
cache_root="${XDG_CACHE_HOME:-$HOME/.cache}/rustcrypto/ffi/v$version"
cache_destination_archive="$cache_root/$target_id/$archive_name"
cache_destination_dir=$(dirname "$cache_destination_archive")

if [ -f "$module_destination_archive" ]; then
  printf '%s\n' "$module_destination_archive"
  exit 0
fi

if [ -f "$cache_destination_archive" ]; then
  mkdir -p "$module_destination_dir"
  cp "$cache_destination_archive" "$module_destination_archive"
  printf '%s\n' "$module_destination_archive"
  exit 0
fi

repo_slug="${RUSTCRYPTO_GITHUB_REPOSITORY:-}"
if [ -z "$repo_slug" ] && command -v git >/dev/null 2>&1; then
  repo_url=$(git -C "$package_root" remote get-url origin 2>/dev/null || true)
  case "$repo_url" in
    git@github.com:*)
      repo_slug=${repo_url#git@github.com:}
      repo_slug=${repo_slug%.git}
      ;;
    *github.com/*)
      repo_slug=${repo_url##*github.com/}
      repo_slug=${repo_slug%.git}
      ;;
  esac
fi

if [ -z "$repo_slug" ]; then
  repo_slug="itsumura-h/nim-rustcrypto"
fi

base_url="https://github.com/$repo_slug/releases/download/v$version"
archive_file_name="rustcrypto-ffi-v$version-$target_id.tar.gz"
checksum_file_name="$archive_file_name.sha256"

temp_root=$(mktemp -d "${TMPDIR:-/tmp}/rustcrypto-ffi.XXXXXX")
cleanup() {
  rm -rf "$temp_root"
}
trap cleanup EXIT INT TERM

archive_path="$temp_root/$archive_file_name"
checksum_path="$temp_root/$checksum_file_name"

download() {
  curl -fsSL -o "$1" "$2"
}

download "$archive_path" "$base_url/$archive_file_name"
download "$checksum_path" "$base_url/$checksum_file_name"
(cd "$temp_root" && sha256sum -c "$checksum_file_name")

mkdir -p "$module_destination_dir"
(cd "$module_root/vendor/rustcrypto-ffi" && tar -xzf "$archive_path" --strip-components=1)

if [ -f "$module_destination_archive" ]; then
  mkdir -p "$cache_destination_dir"
  cp "$module_destination_archive" "$cache_destination_archive"
  printf '%s\n' "$module_destination_archive"
  exit 0
fi

source_clone_dir="$temp_root/source"
source_repo_url="https://github.com/$repo_slug.git"
git clone --depth 1 "$source_repo_url" "$source_clone_dir"
cd "$source_clone_dir/src/rustcrypto-ffi"
cargo build --release --lib
built_archive="$source_clone_dir/src/rustcrypto-ffi/target/release/$archive_name"
if [ ! -f "$built_archive" ]; then
  printf '%s\n' "rustcrypto FFI archive was not built at $built_archive" >&2
  exit 1
fi

mkdir -p "$module_destination_dir" "$cache_destination_dir"
cp "$built_archive" "$module_destination_archive"
cp "$built_archive" "$cache_destination_archive"
printf '%s\n' "$module_destination_archive"
