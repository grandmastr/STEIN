import { useCallback, useEffect, useRef, useState } from "react";
import type {
  AbandonGoalInput,
  ApproveModelRouteInput,
  CreateGoalInput,
  DashboardSnapshot,
  DesktopBridgeEvent,
  EndFocusSessionInput,
  ExplainInterventionInput,
  GoalRevisionInput,
  GrantPermissionInput,
  InterventionFeedbackInput,
  InterventionHistoryInput,
  PublicErrorView,
  RegisterSelectedResourceInput,
  RemoveSelectedResourceInput,
  RevokePermissionInput,
  SetMutedInput,
  StartFocusSessionInput,
  StoreModelSecretInput,
  UpdateGoalInput,
  UpdateUserPreferencesInput,
} from "../protocol";
import { publicErrorFromUnknown } from "../protocol";
import { core, type CoreRendererClient } from "./core";

const EVENT_LIMIT = 30;

interface DashboardState {
  snapshot: DashboardSnapshot | null;
  error: PublicErrorView | null;
  loading: boolean;
  refreshing: boolean;
  commandPending: boolean;
}

function throwablePublicError(publicError: PublicErrorView): Error & PublicErrorView {
  return Object.assign(new Error(publicError.summary), publicError);
}

function applyBridgeEvent(
  snapshot: DashboardSnapshot | null,
  event: DesktopBridgeEvent,
): DashboardSnapshot | null {
  switch (event.type) {
    case "snapshotChanged":
      return event.snapshot;
    case "connectionChanged":
      // A reconnect or transport loss invalidates the entire presentation
      // cache. Do not keep rendering an earlier private projection while a new
      // broker assurance and authoritative snapshot are still unknown.
      return event.connection.phase === "connected" && snapshot
        ? { ...snapshot, connection: event.connection }
        : null;
    case "viewEvent":
      return snapshot
        ? {
            ...snapshot,
            cursor: event.event.cursor,
            recentEvents: [
              event.event,
              ...snapshot.recentEvents.filter(
                (item) => item.messageId !== event.event.messageId,
              ),
            ].slice(0, EVENT_LIMIT),
          }
        : snapshot;
  }
}

function applyBridgeEventToState(
  current: DashboardState,
  event: DesktopBridgeEvent,
): DashboardState {
  return {
    ...current,
    snapshot: applyBridgeEvent(current.snapshot, event),
    error:
      event.type === "connectionChanged" && event.connection.error
        ? event.connection.error
        : current.error,
  };
}

export function useCoreDashboard(client: CoreRendererClient = core) {
  const [state, setState] = useState<DashboardState>({
    snapshot: null,
    error: null,
    loading: true,
    refreshing: false,
    commandPending: false,
  });
  const mounted = useRef(true);

  const handleBridgeEvent = useCallback((event: DesktopBridgeEvent) => {
    setState((current) => applyBridgeEventToState(current, event));
  }, []);

  useEffect(() => {
    mounted.current = true;
    let unlisten: (() => void) | undefined;
    let bootstrapSettled = false;
    const pendingEvents: DesktopBridgeEvent[] = [];

    const receiveDuringBootstrap = (event: DesktopBridgeEvent) => {
      if (bootstrapSettled) handleBridgeEvent(event);
      else pendingEvents.push(event);
    };

    void (async () => {
      try {
        const stopListening = await client.subscribe(receiveDuringBootstrap);
        if (!mounted.current) {
          stopListening();
          return;
        }
        unlisten = stopListening;

        const snapshot = await client.bootstrap();
        if (!mounted.current) return;
        let initial: DashboardState = {
          snapshot,
          error: null,
          loading: false,
          refreshing: false,
          commandPending: false,
        };
        for (const event of pendingEvents) initial = applyBridgeEventToState(initial, event);
        pendingEvents.length = 0;
        bootstrapSettled = true;
        setState(initial);
      } catch (error: unknown) {
        if (!mounted.current) return;
        bootstrapSettled = true;
        setState({
          snapshot: null,
          error: publicErrorFromUnknown(error),
          loading: false,
          refreshing: false,
          commandPending: false,
        });
      }
    })();

    return () => {
      mounted.current = false;
      unlisten?.();
    };
  }, [client, handleBridgeEvent]);

  const runSnapshotAction = useCallback(
    async (action: () => Promise<DashboardSnapshot>) => {
      setState((current) => ({ ...current, refreshing: true, error: null }));
      try {
        const snapshot = await action();
        if (mounted.current) {
          setState((current) => ({
            ...current,
            snapshot,
            error: null,
            loading: false,
            refreshing: false,
          }));
        }
        return snapshot;
      } catch (error) {
        const publicError = publicErrorFromUnknown(error);
        if (mounted.current) {
          setState((current) => ({
            ...current,
            error: publicError,
            loading: false,
            refreshing: false,
          }));
        }
        throw throwablePublicError(publicError);
      }
    },
    [],
  );

  const runCommand = useCallback(async <T,>(action: () => Promise<T>): Promise<T> => {
    setState((current) => ({ ...current, commandPending: true, error: null }));
    try {
      const result = await action();
      if (mounted.current) {
        setState((current) => ({ ...current, commandPending: false, error: null }));
      }
      return result;
    } catch (error) {
      const publicError = publicErrorFromUnknown(error);
      if (mounted.current) {
        setState((current) => ({ ...current, commandPending: false, error: publicError }));
      }
      throw throwablePublicError(publicError);
    }
  }, []);

  return {
    ...state,
    refresh: useCallback(
      () => runSnapshotAction(client.refresh),
      [client.refresh, runSnapshotAction],
    ),
    reconnect: useCallback(
      () => runSnapshotAction(client.reconnect),
      [client.reconnect, runSnapshotAction],
    ),
    createGoal: useCallback(
      (input: CreateGoalInput) => runCommand(() => client.createGoal(input)),
      [client, runCommand],
    ),
    updateGoal: useCallback(
      (input: UpdateGoalInput) => runCommand(() => client.updateGoal(input)),
      [client, runCommand],
    ),
    completeGoal: useCallback(
      (input: GoalRevisionInput) => runCommand(() => client.completeGoal(input)),
      [client, runCommand],
    ),
    abandonGoal: useCallback(
      (input: AbandonGoalInput) => runCommand(() => client.abandonGoal(input)),
      [client, runCommand],
    ),
    deleteGoal: useCallback(
      (input: GoalRevisionInput) => runCommand(() => client.deleteGoal(input)),
      [client, runCommand],
    ),
    storeModelSecret: useCallback(
      (input: StoreModelSecretInput) => runCommand(() => client.storeModelSecret(input)),
      [client, runCommand],
    ),
    approveModelRoute: useCallback(
      (input: ApproveModelRouteInput) => runCommand(() => client.approveModelRoute(input)),
      [client, runCommand],
    ),
    grantPermission: useCallback(
      (input: GrantPermissionInput) => runCommand(() => client.grantPermission(input)),
      [client, runCommand],
    ),
    revokePermission: useCallback(
      (input: RevokePermissionInput) => runCommand(() => client.revokePermission(input)),
      [client, runCommand],
    ),
    startFocusSession: useCallback(
      (input: StartFocusSessionInput) => runCommand(() => client.startFocusSession(input)),
      [client, runCommand],
    ),
    registerSelectedResource: useCallback(
      (input: RegisterSelectedResourceInput) =>
        runCommand(() => client.registerSelectedResource(input)),
      [client, runCommand],
    ),
    removeSelectedResource: useCallback(
      (input: RemoveSelectedResourceInput) =>
        runCommand(() => client.removeSelectedResource(input)),
      [client, runCommand],
    ),
    updateUserPreferences: useCallback(
      (input: UpdateUserPreferencesInput) =>
        runCommand(() => client.updateUserPreferences(input)),
      [client, runCommand],
    ),
    getSteinIdentity: useCallback(
      () => runCommand(client.getSteinIdentity),
      [client.getSteinIdentity, runCommand],
    ),
    getUserPreferences: useCallback(
      () => runCommand(client.getUserPreferences),
      [client.getUserPreferences, runCommand],
    ),
    getEffectivePolicy: useCallback(
      () => runCommand(client.getEffectivePolicy),
      [client.getEffectivePolicy, runCommand],
    ),
    getSelectedResources: useCallback(
      () => runCommand(client.getSelectedResources),
      [client.getSelectedResources, runCommand],
    ),
    setInterventionsMuted: useCallback(
      (input: SetMutedInput) => runCommand(() => client.setInterventionsMuted(input)),
      [client, runCommand],
    ),
    endFocusSession: useCallback(
      (input: EndFocusSessionInput) => runCommand(() => client.endFocusSession(input)),
      [client, runCommand],
    ),
    recordInterventionFeedback: useCallback(
      (input: InterventionFeedbackInput) =>
        runCommand(() => client.recordInterventionFeedback(input)),
      [client, runCommand],
    ),
    explainIntervention: useCallback(
      (input: ExplainInterventionInput) =>
        runCommand(() => client.explainIntervention(input)),
      [client, runCommand],
    ),
    getInterventionHistory: useCallback(
      (input: InterventionHistoryInput) =>
        runCommand(() => client.getInterventionHistory(input)),
      [client, runCommand],
    ),
    clearError: useCallback(() => {
      setState((current) => ({ ...current, error: null }));
    }, []),
  };
}
