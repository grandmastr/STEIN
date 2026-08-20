use std::process::ExitCode;

#[cfg(windows)]
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match stein_private_broker::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Broker failures are deliberately content-free. In particular,
            // never add OS error text, paths, package identifiers, frame bytes,
            // or request metadata here.
            eprintln!("STEIN private broker stopped: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() -> ExitCode {
    eprintln!("STEIN private broker is unavailable on this platform");
    ExitCode::FAILURE
}
