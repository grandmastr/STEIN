use windows::ApplicationModel::{AppInfo, PackageSignatureKind};
use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
use windows::core::HSTRING;

const PACKAGE_NAME: &str = "STEIN.PersonalIntelligence";
const DESKTOP_APPLICATION_ID: &str = "Desktop";

#[derive(Clone, Debug, Eq, PartialEq)]
struct RegistrationEvidence {
    app_id: String,
    app_user_model_id: String,
    package_family_name: String,
    package_name: String,
    package_family_name_from_id: String,
    package_status_ok: bool,
    signed_package: bool,
}

pub fn exact_desktop_registration_is_healthy(
    expected_package_family_name: &str,
    expected_aumid: &str,
) -> bool {
    let expected_package_family_name = expected_package_family_name.to_owned();
    let expected_aumid = expected_aumid.to_owned();
    let queried_aumid = expected_aumid.clone();
    std::thread::Builder::new()
        .name("stein-toast-registration-check".to_owned())
        .spawn(move || registration_evidence(&queried_aumid))
        .ok()
        .and_then(|thread| thread.join().ok())
        .flatten()
        .is_some_and(|evidence| {
            evidence_is_exact(&evidence, &expected_package_family_name, &expected_aumid)
        })
}

fn registration_evidence(aumid: &str) -> Option<RegistrationEvidence> {
    // Run the Windows Runtime query on a dedicated MTA thread so the daemon's
    // Tokio worker/apartment state cannot weaken or accidentally satisfy it.
    // SAFETY: this dedicated thread has not initialized COM/WinRT yet, and the
    // matching RoUninitialize guard remains on the same thread.
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.ok()?;
    struct RuntimeGuard;
    impl Drop for RuntimeGuard {
        fn drop(&mut self) {
            // SAFETY: this runs on the same thread as the successful
            // RoInitialize call and balances it exactly once.
            unsafe { RoUninitialize() };
        }
    }
    let _runtime = RuntimeGuard;

    let app = AppInfo::GetFromAppUserModelId(&HSTRING::from(aumid)).ok()?;
    let package = app.Package().ok()?;
    let package_id = package.Id().ok()?;
    Some(RegistrationEvidence {
        app_id: app.Id().ok()?.to_string(),
        app_user_model_id: app.AppUserModelId().ok()?.to_string(),
        package_family_name: app.PackageFamilyName().ok()?.to_string(),
        package_name: package_id.Name().ok()?.to_string(),
        package_family_name_from_id: package_id.FamilyName().ok()?.to_string(),
        package_status_ok: package.Status().ok()?.VerifyIsOK().ok()?,
        signed_package: package.SignatureKind().ok()? != PackageSignatureKind::None,
    })
}

fn evidence_is_exact(
    evidence: &RegistrationEvidence,
    expected_package_family_name: &str,
    expected_aumid: &str,
) -> bool {
    evidence.app_id == DESKTOP_APPLICATION_ID
        && evidence.app_user_model_id == expected_aumid
        && evidence.package_family_name == expected_package_family_name
        && evidence.package_name == PACKAGE_NAME
        && evidence.package_family_name_from_id == expected_package_family_name
        && evidence.package_status_ok
        && evidence.signed_package
        && expected_aumid == format!("{expected_package_family_name}!{DESKTOP_APPLICATION_ID}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> RegistrationEvidence {
        RegistrationEvidence {
            app_id: "Desktop".to_owned(),
            app_user_model_id: "STEIN.PersonalIntelligence_qrfd6g9swygw6!Desktop".to_owned(),
            package_family_name: "STEIN.PersonalIntelligence_qrfd6g9swygw6".to_owned(),
            package_name: "STEIN.PersonalIntelligence".to_owned(),
            package_family_name_from_id: "STEIN.PersonalIntelligence_qrfd6g9swygw6".to_owned(),
            package_status_ok: true,
            signed_package: true,
        }
    }

    #[test]
    fn only_exact_signed_healthy_os_registration_is_accepted() {
        let expected_pfn = "STEIN.PersonalIntelligence_qrfd6g9swygw6";
        let expected_aumid = "STEIN.PersonalIntelligence_qrfd6g9swygw6!Desktop";
        assert!(evidence_is_exact(&evidence(), expected_pfn, expected_aumid));

        let mut unsigned = evidence();
        unsigned.signed_package = false;
        assert!(!evidence_is_exact(&unsigned, expected_pfn, expected_aumid));

        let mut wrong_application = evidence();
        wrong_application.app_id = "PrivateBroker".to_owned();
        assert!(!evidence_is_exact(
            &wrong_application,
            expected_pfn,
            expected_aumid
        ));

        let mut unhealthy = evidence();
        unhealthy.package_status_ok = false;
        assert!(!evidence_is_exact(&unhealthy, expected_pfn, expected_aumid));
    }
}
