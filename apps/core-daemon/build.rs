use std::env;

const PACKAGE_NAME: &str = "STEIN.PersonalIntelligence";
const DESKTOP_APPLICATION_ID: &str = "Desktop";
const BROKER_APPLICATION_ID: &str = "PrivateBroker";
const BROWSER_APPLICATION_ID: &str = "BrowserObservationProducer";
const PACKAGE_FAMILY_ENV: &str = "STEIN_PRODUCTION_PACKAGE_FAMILY_NAME";
const BROKER_AUMID_ENV: &str = "STEIN_PRODUCTION_BROKER_AUMID";
const EDGE_EXTENSION_ID_ENV: &str = "STEIN_EDGE_EXTENSION_ID";
const EDGE_EXTENSION_VERSION_ENV: &str = "STEIN_EDGE_EXTENSION_VERSION";

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PRODUCTION_PRIVATE_ENDPOINT");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_PRODUCTION_EDGE_PRODUCER");
    println!("cargo:rerun-if-env-changed={PACKAGE_FAMILY_ENV}");
    println!("cargo:rerun-if-env-changed={BROKER_AUMID_ENV}");
    println!("cargo:rerun-if-env-changed={EDGE_EXTENSION_ID_ENV}");
    println!("cargo:rerun-if-env-changed={EDGE_EXTENSION_VERSION_ENV}");

    if env::var_os("CARGO_FEATURE_PRODUCTION_PRIVATE_ENDPOINT").is_none() {
        return;
    }

    let package_family_name = required(PACKAGE_FAMILY_ENV);
    let broker_aumid = required(BROKER_AUMID_ENV);
    validate_identity(&package_family_name, &broker_aumid);

    println!("cargo:rustc-env=STEIN_EMBEDDED_PACKAGE_FAMILY_NAME={package_family_name}");
    println!(
        "cargo:rustc-env=STEIN_EMBEDDED_DESKTOP_AUMID={package_family_name}!{DESKTOP_APPLICATION_ID}"
    );
    println!("cargo:rustc-env=STEIN_EMBEDDED_BROKER_AUMID={broker_aumid}");

    if env::var_os("CARGO_FEATURE_PRODUCTION_EDGE_PRODUCER").is_some() {
        let extension_id = required(EDGE_EXTENSION_ID_ENV);
        let extension_version = required(EDGE_EXTENSION_VERSION_ENV);
        if extension_id.len() != 32
            || !extension_id
                .bytes()
                .all(|byte| (b'a'..=b'p').contains(&byte))
            || !valid_version(&extension_version)
        {
            panic!("production Edge producer identity is invalid");
        }
        println!(
            "cargo:rustc-env=STEIN_EMBEDDED_BROWSER_PRODUCER_AUMID={package_family_name}!{BROWSER_APPLICATION_ID}"
        );
        println!("cargo:rustc-env=STEIN_EMBEDDED_EDGE_EXTENSION_ID={extension_id}");
        println!("cargo:rustc-env=STEIN_EMBEDDED_EDGE_EXTENSION_VERSION={extension_version}");
    }
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
    env::var(name).unwrap_or_else(|_| {
        panic!("production private endpoint requires trusted build identity environment")
    })
}

fn validate_identity(package_family_name: &str, broker_aumid: &str) {
    let publisher_id = package_family_name
        .strip_prefix(PACKAGE_NAME)
        .and_then(|suffix| suffix.strip_prefix('_'))
        .unwrap_or_else(|| panic!("production private endpoint identity is invalid"));
    let valid_publisher_id = publisher_id.len() == 13
        && publisher_id.bytes().all(|byte| {
            byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'a'..=b'h' | b'j'..=b'k' | b'm'..=b'n' | b'p'..=b't' | b'v'..=b'z'
                )
        });
    let expected_aumid = format!("{package_family_name}!{BROKER_APPLICATION_ID}");
    if !valid_publisher_id || broker_aumid != expected_aumid {
        panic!("production private endpoint identity is invalid");
    }
}
