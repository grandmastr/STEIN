use std::env;

const EXTENSION_ID_ENV: &str = "STEIN_EDGE_EXTENSION_ID";
const EDGE_PUBLISHER_ENV: &str = "STEIN_EDGE_PUBLISHER_SHA256";
const HOST_PUBLISHER_ENV: &str = "STEIN_EDGE_HOST_PUBLISHER_SHA256";
const CORE_EXECUTABLE_ENV: &str = "STEIN_CORE_EXECUTABLE_SHA256";
const EXTENSION_VERSION_ENV: &str = "STEIN_EDGE_EXTENSION_VERSION";

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PRODUCTION_EDGE_HOST");
    for name in [
        EXTENSION_ID_ENV,
        EXTENSION_VERSION_ENV,
        EDGE_PUBLISHER_ENV,
        HOST_PUBLISHER_ENV,
        CORE_EXECUTABLE_ENV,
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os("CARGO_FEATURE_PRODUCTION_EDGE_HOST").is_none() {
        return;
    }

    let extension_id = required(EXTENSION_ID_ENV);
    if extension_id.len() != 32
        || !extension_id
            .bytes()
            .all(|byte| (b'a'..=b'p').contains(&byte))
    {
        panic!("the production Edge extension identity is invalid");
    }
    let edge_publisher = exact_sha256(EDGE_PUBLISHER_ENV);
    let host_publisher = exact_sha256(HOST_PUBLISHER_ENV);
    let core_executable = exact_sha256(CORE_EXECUTABLE_ENV);
    let extension_version = required(EXTENSION_VERSION_ENV);
    if !valid_version(&extension_version) {
        panic!("the production Edge extension version is invalid");
    }
    println!("cargo:rustc-env=STEIN_EMBEDDED_EDGE_EXTENSION_ID={extension_id}");
    println!("cargo:rustc-env=STEIN_EMBEDDED_EDGE_EXTENSION_VERSION={extension_version}");
    println!("cargo:rustc-env=STEIN_EMBEDDED_EDGE_PUBLISHER_SHA256={edge_publisher}");
    println!("cargo:rustc-env=STEIN_EMBEDDED_EDGE_HOST_PUBLISHER_SHA256={host_publisher}");
    println!("cargo:rustc-env=STEIN_EMBEDDED_CORE_EXECUTABLE_SHA256={core_executable}");
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && (1..=4).contains(&value.split('.').count())
        && value.split('.').all(|component| {
            !component.is_empty()
                && component.len() <= 9
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component == "0" || !component.starts_with('0'))
        })
}

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("the production Edge host identity is unavailable"))
}

fn exact_sha256(name: &str) -> String {
    let value = required(name);
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || value.bytes().all(|byte| byte == b'0')
    {
        panic!("the production Edge host publisher identity is invalid");
    }
    value
}
