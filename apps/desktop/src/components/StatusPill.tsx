import type {
  ConnectionPhase,
  GoalState,
  HealthState,
  RuntimePhase,
} from "../protocol";

type Status = ConnectionPhase | RuntimePhase | HealthState | GoalState;

const healthyStatuses = new Set<Status>(["connected", "ready", "healthy", "active"]);
const warningStatuses = new Set<Status>(["connecting", "starting", "degraded", "draft"]);
const mutedStatuses = new Set<Status>(["completed", "abandoned", "stopping"]);

function labelForStatus(status: Status) {
  return status.replaceAll("_", " ");
}

export function StatusPill({ status, label }: { status: Status; label?: string }) {
  const tone = healthyStatuses.has(status)
    ? "positive"
    : warningStatuses.has(status)
      ? "warning"
      : mutedStatuses.has(status)
        ? "neutral"
        : "negative";

  return (
    <span className={`status-pill status-pill--${tone}`}>
      <span className="status-pill__dot" />
      {label ?? labelForStatus(status)}
    </span>
  );
}
