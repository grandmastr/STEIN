mod bridge;
mod native_credential_prompt;
#[cfg(windows)]
mod private_broker;
mod stein_adapter;
#[cfg(windows)]
mod toast_activation;
mod view;

use bridge::CoreBridge;
use tauri::{AppHandle, State};
use view::{
    AbandonGoalInput, ApproveModelRouteInput, CreateGoalInput, DashboardSnapshot,
    EffectivePolicyView, EndFocusSessionInput, ExplainInterventionInput, FocusSessionView,
    GoalDeletionView, GoalRevisionInput, GoalView, GrantPermissionInput,
    InterventionExplanationView, InterventionFeedbackInput, InterventionHistoryInput,
    InterventionHistoryView, InterventionView, LatestModelRequestReceiptInput,
    ModelRequestReceiptView, ModelRouteView, PublicErrorView, RegisterSelectedResourceInput,
    RemoveSelectedResourceInput, ResourceView, RevokePermissionInput, SelectedResourceDeletionView,
    SessionGrantView, SetMutedInput, StartFocusSessionInput, SteinIdentityView, UpdateGoalInput,
    UpdateUserPreferencesInput, UserPreferencesUpdateView, UserPreferencesView,
};

#[tauri::command]
async fn desktop_bootstrap(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
) -> Result<DashboardSnapshot, PublicErrorView> {
    bridge.inner().bootstrap(&app).await
}

#[tauri::command]
async fn desktop_refresh(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
) -> Result<DashboardSnapshot, PublicErrorView> {
    bridge.inner().refresh(&app).await
}

#[tauri::command]
async fn desktop_reconnect(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
) -> Result<DashboardSnapshot, PublicErrorView> {
    bridge.inner().reconnect(&app).await
}

#[tauri::command]
async fn desktop_create_goal(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: CreateGoalInput,
) -> Result<GoalView, PublicErrorView> {
    bridge.inner().create_goal(&app, input).await
}

#[tauri::command]
async fn desktop_update_goal(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: UpdateGoalInput,
) -> Result<GoalView, PublicErrorView> {
    bridge.inner().update_goal(&app, input).await
}

#[tauri::command]
async fn desktop_complete_goal(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: GoalRevisionInput,
) -> Result<GoalView, PublicErrorView> {
    bridge.inner().complete_goal(&app, input).await
}

#[tauri::command]
async fn desktop_abandon_goal(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: AbandonGoalInput,
) -> Result<GoalView, PublicErrorView> {
    bridge.inner().abandon_goal(&app, input).await
}

#[tauri::command]
async fn desktop_delete_goal(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: GoalRevisionInput,
) -> Result<GoalDeletionView, PublicErrorView> {
    bridge.inner().delete_goal(&app, input).await
}

/// The renderer supplies only reviewed route metadata. Rust validates and
/// builds the approval before opening CredUI, retains the credential only in
/// zeroizing native memory, approves through the private protocol, and writes
/// Credential Manager last under the returned approval identity. There is no
/// standalone renderer secret-write API.
#[tauri::command]
async fn desktop_setup_model_route(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: ApproveModelRouteInput,
) -> Result<ModelRouteView, PublicErrorView> {
    bridge
        .inner()
        .setup_model_route(&app, input, main_window_handle(&app)?)
        .await
}

#[cfg(windows)]
fn main_window_handle(app: &AppHandle) -> Result<isize, PublicErrorView> {
    use tauri::Manager;

    let window = app.get_webview_window("main").ok_or_else(|| {
        PublicErrorView::unavailable(
            "credential_prompt_parent_unavailable",
            "The desktop window is unavailable for the native credential prompt.",
        )
    })?;
    window.hwnd().map(|handle| handle.0 as isize).map_err(|_| {
        PublicErrorView::unavailable(
            "credential_prompt_parent_unavailable",
            "Windows could not identify the desktop window for the credential prompt.",
        )
    })
}

#[cfg(not(windows))]
fn main_window_handle(_app: &AppHandle) -> Result<isize, PublicErrorView> {
    Ok(0)
}

#[tauri::command]
async fn desktop_grant_permission(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: GrantPermissionInput,
) -> Result<SessionGrantView, PublicErrorView> {
    bridge.inner().grant_permission(&app, input).await
}

#[tauri::command]
async fn desktop_revoke_permission(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: RevokePermissionInput,
) -> Result<(), PublicErrorView> {
    bridge.inner().revoke_permission(&app, input).await
}

#[tauri::command]
async fn desktop_start_focus_session(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: StartFocusSessionInput,
) -> Result<FocusSessionView, PublicErrorView> {
    bridge.inner().start_focus_session(&app, input).await
}

#[tauri::command]
async fn desktop_register_selected_resource(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: RegisterSelectedResourceInput,
) -> Result<ResourceView, PublicErrorView> {
    bridge.inner().register_selected_resource(&app, input).await
}

#[tauri::command]
async fn desktop_remove_selected_resource(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: RemoveSelectedResourceInput,
) -> Result<SelectedResourceDeletionView, PublicErrorView> {
    bridge.inner().remove_selected_resource(&app, input).await
}

#[tauri::command]
async fn desktop_update_user_preferences(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: UpdateUserPreferencesInput,
) -> Result<UserPreferencesUpdateView, PublicErrorView> {
    bridge.inner().update_user_preferences(&app, input).await
}

#[tauri::command]
async fn desktop_get_stein_identity(
    bridge: State<'_, CoreBridge>,
) -> Result<SteinIdentityView, PublicErrorView> {
    bridge.inner().get_stein_identity().await
}

#[tauri::command]
async fn desktop_get_user_preferences(
    bridge: State<'_, CoreBridge>,
) -> Result<UserPreferencesView, PublicErrorView> {
    bridge.inner().get_user_preferences().await
}

#[tauri::command]
async fn desktop_get_effective_policy(
    bridge: State<'_, CoreBridge>,
) -> Result<EffectivePolicyView, PublicErrorView> {
    bridge.inner().get_effective_policy().await
}

#[tauri::command]
async fn desktop_get_selected_resources(
    bridge: State<'_, CoreBridge>,
) -> Result<Vec<ResourceView>, PublicErrorView> {
    bridge.inner().get_selected_resources().await
}

#[tauri::command]
async fn desktop_set_interventions_muted(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: SetMutedInput,
) -> Result<FocusSessionView, PublicErrorView> {
    bridge.inner().set_muted(&app, input).await
}

#[tauri::command]
async fn desktop_end_focus_session(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: EndFocusSessionInput,
) -> Result<FocusSessionView, PublicErrorView> {
    bridge.inner().end_focus_session(&app, input).await
}

#[tauri::command]
async fn desktop_record_intervention_feedback(
    app: AppHandle,
    bridge: State<'_, CoreBridge>,
    input: InterventionFeedbackInput,
) -> Result<InterventionView, PublicErrorView> {
    bridge.inner().record_feedback(&app, input).await
}

#[tauri::command]
async fn desktop_explain_intervention(
    bridge: State<'_, CoreBridge>,
    input: ExplainInterventionInput,
) -> Result<InterventionExplanationView, PublicErrorView> {
    bridge.inner().explain_intervention(input).await
}

#[tauri::command]
async fn desktop_get_intervention_history(
    bridge: State<'_, CoreBridge>,
    input: InterventionHistoryInput,
) -> Result<InterventionHistoryView, PublicErrorView> {
    bridge.inner().get_intervention_history(input).await
}

/// Read-only evidence for the daemon-owned scheduler path. This query cannot
/// start, retry, or otherwise authorize a model request.
#[tauri::command]
async fn desktop_get_latest_model_request_receipt(
    bridge: State<'_, CoreBridge>,
    input: LatestModelRequestReceiptInput,
) -> Result<Option<ModelRequestReceiptView>, PublicErrorView> {
    bridge.inner().get_latest_model_request_receipt(input).await
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(windows)]
    let mut toast_activation_registration = match toast_activation::initialize(std::env::args()) {
        toast_activation::ToastActivationStartup::Registered(registration) => Some(registration),
        toast_activation::ToastActivationStartup::NotPackaged => None,
        // A packaged process with the wrong identity, a forged direct
        // activation marker, or a failed COM registration cannot become a
        // notification activation surface.
        toast_activation::ToastActivationStartup::Rejected => return,
    };

    #[cfg(windows)]
    let toast_activation_receiver = toast_activation_registration
        .as_mut()
        .and_then(toast_activation::ToastActivationRegistration::take_receiver);

    let builder = tauri::Builder::default()
        .manage(CoreBridge::default())
        .invoke_handler(tauri::generate_handler![
            desktop_bootstrap,
            desktop_refresh,
            desktop_reconnect,
            desktop_create_goal,
            desktop_update_goal,
            desktop_complete_goal,
            desktop_abandon_goal,
            desktop_delete_goal,
            desktop_setup_model_route,
            desktop_grant_permission,
            desktop_revoke_permission,
            desktop_start_focus_session,
            desktop_register_selected_resource,
            desktop_remove_selected_resource,
            desktop_update_user_preferences,
            desktop_get_stein_identity,
            desktop_get_user_preferences,
            desktop_get_effective_policy,
            desktop_get_selected_resources,
            desktop_set_interventions_muted,
            desktop_end_focus_session,
            desktop_record_intervention_feedback,
            desktop_explain_intervention,
            desktop_get_intervention_history,
            desktop_get_latest_model_request_receipt,
        ]);

    #[cfg(windows)]
    let builder = builder.setup(move |app| {
        if let Some(receiver) = toast_activation_receiver {
            toast_activation::spawn(app.handle().clone(), receiver);
        }
        Ok(())
    });

    builder
        .run(tauri::generate_context!())
        .expect("failed to run STEIN desktop presentation");
}
