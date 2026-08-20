use std::env;

const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn main() {
    println!("cargo:rerun-if-env-changed=STEIN_CORE_EXECUTABLE_SHA256");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let profile = env::var("PROFILE").expect("Cargo must set PROFILE");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo must set target OS");
    let development = env::var_os("CARGO_FEATURE_DEVELOPMENT_PACKAGE").is_some();

    if development && profile == "release" {
        panic!("a development package identity cannot be compiled as a release binary");
    }

    let digest = match env::var("STEIN_CORE_EXECUTABLE_SHA256") {
        Ok(value) => validate_digest(value),
        Err(_) if target_os == "windows" && profile == "release" => {
            panic!("STEIN_CORE_EXECUTABLE_SHA256 is required for a Windows release build")
        }
        Err(_) => ZERO_DIGEST.to_owned(),
    };

    println!("cargo:rustc-env=STEIN_PINNED_CORE_SHA256={digest}");
}

fn validate_digest(value: String) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64
        || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit())
        || normalized == ZERO_DIGEST
    {
        panic!("STEIN_CORE_EXECUTABLE_SHA256 must be a non-zero SHA-256 hex digest");
    }
    normalized
}
