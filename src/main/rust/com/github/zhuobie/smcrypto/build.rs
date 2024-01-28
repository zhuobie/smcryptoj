use std::env;
use std::path::PathBuf;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR env var is not defined");
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_dir = PathBuf::from(format!("target/{}", profile));
    let config = cbindgen::Config::from_file("cbindgen.toml").expect("Unable to find cbindgen.toml configuration file");
    cbindgen::generate_with_config(&crate_dir, config).unwrap().write_to_file(target_dir.join("smcrypto.h"));
}