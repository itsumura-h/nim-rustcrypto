use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("missing manifest dir"));
    let profile = env::var("PROFILE").unwrap_or_else(|_| "release".to_string());
    if profile != "release" {
        return;
    }

    let source_archive = manifest_dir
        .join("target")
        .join(&profile)
        .join("librust_crypto_ffi.a");
    let destination_archive = manifest_dir
        .join("../nim-rustcrypto")
        .join("vendor")
        .join("rustcrypto-ffi")
        .join("linux-x86_64")
        .join("librust_crypto_ffi.a");
    let module_destination_archive = manifest_dir
        .join("../nim-rustcrypto")
        .join("src")
        .join("rustcrypto")
        .join("vendor")
        .join("rustcrypto-ffi")
        .join("linux-x86_64")
        .join("librust_crypto_ffi.a");

    if source_archive.exists() {
        if let Some(parent) = destination_archive.parent() {
            std::fs::create_dir_all(parent).expect("failed to create destination directory");
        }
        std::fs::copy(&source_archive, &destination_archive).expect("failed to copy archive");
        if let Some(parent) = module_destination_archive.parent() {
            std::fs::create_dir_all(parent).expect("failed to create module destination directory");
        }
        std::fs::copy(&source_archive, &module_destination_archive)
            .expect("failed to copy module archive");
        return;
    }

    let script = format!(
        r#"set -eu
src="{src}"
dst="{dst}"
module_dst="{module_dst}"
while [ ! -f "$src" ]; do
  sleep 0.2
done
mkdir -p "$(dirname "$dst")"
cp "$src" "$dst"
mkdir -p "$(dirname "$module_dst")"
cp "$src" "$module_dst"
"#,
        src = source_archive.display(),
        dst = destination_archive.display(),
        module_dst = module_destination_archive.display(),
    );

    Command::new("sh")
        .arg("-c")
        .arg(script)
        .spawn()
        .expect("failed to spawn archive sync helper");
}
