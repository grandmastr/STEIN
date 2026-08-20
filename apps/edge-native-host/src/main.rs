#[cfg(all(windows, feature = "production-edge-host"))]
#[tokio::main]
async fn main() -> std::process::ExitCode {
    use std::io;

    use stein_edge_native_host::{connect_os_authenticated_core_ingress, run_producer_bridge};
    use stein_platform_windows::{
        EdgeNativeHostLaunchPolicy, verify_current_edge_native_host_launch,
    };

    let Some(edge_publisher) = decode_sha256(env!("STEIN_EMBEDDED_EDGE_PUBLISHER_SHA256")) else {
        return std::process::ExitCode::FAILURE;
    };
    let Some(host_publisher) = decode_sha256(env!("STEIN_EMBEDDED_EDGE_HOST_PUBLISHER_SHA256"))
    else {
        return std::process::ExitCode::FAILURE;
    };
    let Ok(policy) = EdgeNativeHostLaunchPolicy::new(
        env!("STEIN_EMBEDDED_EDGE_EXTENSION_ID"),
        edge_publisher,
        host_publisher,
    ) else {
        return std::process::ExitCode::FAILURE;
    };
    let Ok(_launch_evidence) = verify_current_edge_native_host_launch(&policy) else {
        return std::process::ExitCode::FAILURE;
    };

    let Some(core_executable) = decode_sha256(env!("STEIN_EMBEDDED_CORE_EXECUTABLE_SHA256")) else {
        return std::process::ExitCode::FAILURE;
    };
    // Launch evidence is supporting provenance only. The fixed producer pipe
    // additionally verifies the exact signed CORE server before stdin is read.
    let Ok(mut connection) = connect_os_authenticated_core_ingress(core_executable).await else {
        return std::process::ExitCode::FAILURE;
    };
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    match run_producer_bridge(
        &mut connection,
        &mut input,
        &mut output,
        env!("STEIN_EMBEDDED_EDGE_EXTENSION_ID"),
        env!("STEIN_EMBEDDED_EDGE_EXTENSION_VERSION"),
    )
    .await
    {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}

#[cfg(not(all(windows, feature = "production-edge-host")))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}

#[cfg(all(windows, feature = "production-edge-host"))]
fn decode_sha256(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = decode_nibble(pair[0])?.checked_mul(16)? + decode_nibble(pair[1])?;
    }
    (!decoded.iter().all(|byte| *byte == 0)).then_some(decoded)
}

#[cfg(all(windows, feature = "production-edge-host"))]
fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}
