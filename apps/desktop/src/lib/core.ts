import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AbandonGoalInput,
  ApproveModelRouteInput,
  CreateGoalInput,
  DashboardSnapshot,
  DesktopBridgeEvent,
  EffectivePolicyView,
  EndFocusSessionInput,
  ExplainInterventionInput,
  FocusSessionView,
  GoalDeletionView,
  GoalRevisionInput,
  GoalView,
  GrantPermissionInput,
  InterventionExplanationView,
  InterventionFeedbackInput,
  InterventionHistoryInput,
  InterventionHistoryView,
  InterventionView,
  ModelRouteView,
  RegisterSelectedResourceInput,
  RemoveSelectedResourceInput,
  ResourceView,
  RevokePermissionInput,
  SecretMutationView,
  SelectedResourceDeletionView,
  SessionGrantView,
  SetMutedInput,
  StartFocusSessionInput,
  SteinIdentityView,
  StoreModelSecretInput,
  UpdateGoalInput,
  UpdateUserPreferencesInput,
  UserPreferencesUpdateView,
  UserPreferencesView,
} from "../protocol";

export const DESKTOP_BRIDGE_EVENT = "stein://desktop-bridge";

/** The renderer's complete, closed API to CORE and the native secret write. */
export const core = {
  bootstrap: (): Promise<DashboardSnapshot> =>
    invoke<DashboardSnapshot>("desktop_bootstrap"),
  refresh: (): Promise<DashboardSnapshot> =>
    invoke<DashboardSnapshot>("desktop_refresh"),
  reconnect: (): Promise<DashboardSnapshot> =>
    invoke<DashboardSnapshot>("desktop_reconnect"),
  createGoal: (input: CreateGoalInput): Promise<GoalView> =>
    invoke<GoalView>("desktop_create_goal", { input }),
  updateGoal: (input: UpdateGoalInput): Promise<GoalView> =>
    invoke<GoalView>("desktop_update_goal", { input }),
  completeGoal: (input: GoalRevisionInput): Promise<GoalView> =>
    invoke<GoalView>("desktop_complete_goal", { input }),
  abandonGoal: (input: AbandonGoalInput): Promise<GoalView> =>
    invoke<GoalView>("desktop_abandon_goal", { input }),
  deleteGoal: (input: GoalRevisionInput): Promise<GoalDeletionView> =>
    invoke<GoalDeletionView>("desktop_delete_goal", { input }),
  storeModelSecret: ({ routeId }: StoreModelSecretInput): Promise<SecretMutationView> =>
    invoke<SecretMutationView>("desktop_store_model_secret", { input: { routeId } }),
  approveModelRoute: (input: ApproveModelRouteInput): Promise<ModelRouteView> =>
    invoke<ModelRouteView>("desktop_approve_model_route", { input }),
  grantPermission: (input: GrantPermissionInput): Promise<SessionGrantView> =>
    invoke<SessionGrantView>("desktop_grant_permission", { input }),
  revokePermission: (input: RevokePermissionInput): Promise<void> =>
    invoke<void>("desktop_revoke_permission", { input }),
  startFocusSession: (input: StartFocusSessionInput): Promise<FocusSessionView> =>
    invoke<FocusSessionView>("desktop_start_focus_session", { input }),
  registerSelectedResource: (input: RegisterSelectedResourceInput): Promise<ResourceView> =>
    invoke<ResourceView>("desktop_register_selected_resource", { input }),
  removeSelectedResource: (
    input: RemoveSelectedResourceInput,
  ): Promise<SelectedResourceDeletionView> =>
    invoke<SelectedResourceDeletionView>("desktop_remove_selected_resource", { input }),
  updateUserPreferences: (
    input: UpdateUserPreferencesInput,
  ): Promise<UserPreferencesUpdateView> =>
    invoke<UserPreferencesUpdateView>("desktop_update_user_preferences", { input }),
  getSteinIdentity: (): Promise<SteinIdentityView> =>
    invoke<SteinIdentityView>("desktop_get_stein_identity"),
  getUserPreferences: (): Promise<UserPreferencesView> =>
    invoke<UserPreferencesView>("desktop_get_user_preferences"),
  getEffectivePolicy: (): Promise<EffectivePolicyView> =>
    invoke<EffectivePolicyView>("desktop_get_effective_policy"),
  getSelectedResources: (): Promise<ResourceView[]> =>
    invoke<ResourceView[]>("desktop_get_selected_resources"),
  setInterventionsMuted: (input: SetMutedInput): Promise<FocusSessionView> =>
    invoke<FocusSessionView>("desktop_set_interventions_muted", { input }),
  endFocusSession: (input: EndFocusSessionInput): Promise<FocusSessionView> =>
    invoke<FocusSessionView>("desktop_end_focus_session", { input }),
  recordInterventionFeedback: (
    input: InterventionFeedbackInput,
  ): Promise<InterventionView> =>
    invoke<InterventionView>("desktop_record_intervention_feedback", { input }),
  explainIntervention: (
    input: ExplainInterventionInput,
  ): Promise<InterventionExplanationView> =>
    invoke<InterventionExplanationView>("desktop_explain_intervention", { input }),
  getInterventionHistory: (
    input: InterventionHistoryInput,
  ): Promise<InterventionHistoryView> =>
    invoke<InterventionHistoryView>("desktop_get_intervention_history", { input }),
  subscribe: (onEvent: (event: DesktopBridgeEvent) => void): Promise<UnlistenFn> =>
    listen<DesktopBridgeEvent>(DESKTOP_BRIDGE_EVENT, ({ payload }) => onEvent(payload)),
};

export type CoreRendererClient = typeof core;
