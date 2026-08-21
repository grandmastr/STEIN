//! SQLite persistence adapter for STEIN's Phase 2 durable owners.
//!
//! A single worker thread owns the only connection. Domain code sees only the
//! typed repository interface from `stein-core`; SQLite values and migrations
//! never cross that boundary.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;
use std::sync::mpsc::{self, SyncSender};
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Params, Transaction, TransactionBehavior, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use stein_core::{
    ActorId, AuditKind, AuditRecord, DeletionSummary, DeviceId, DeviceRegistration,
    DurableRepository, ExplicitPreferences, FocusSession, FocusSessionLifecycleWrite, Goal,
    GoalCreateReceipt, GoalDeletionResult, GoalDeletionTombstone, GoalId, IdempotencyKey,
    Intervention, InterventionDecisionWrite, InterventionTransitionWrite, ModelRouteApproval,
    NativeResourceCleanup, OperationKind, OperationReceipt, OutboxState, OwnerStateSnapshot,
    PendingDeliveryTransition, PendingInterventionDelivery, PermissionGrant,
    PermissionGrantRevocationWrite, PolicyDecision, PortFuture, RecordProvenance,
    RecordProvenanceSource, RepositoryError, RepositoryErrorKind, ResourceBinding, ResourceId,
    SecretDeletionCleanup, SelectedResourceDeletionResult, SelectedResourceDeletionTombstone,
    SteinIdentity, USER_PREFERENCES_SCHEMA_V1,
};
use time::OffsetDateTime;
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 6;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const BUSY_TIMEOUT_MILLISECONDS: i64 = 5_000;
const OUTBOX_CAPACITY_PER_OWNER: i64 = 20;
const OUTBOX_CAPACITY_PER_SESSION: i64 = 5;
const MAX_OUTBOX_TEXT_SCALARS: usize = 512;

const MIGRATION_CATALOG_SQL: &str = "
CREATE TABLE schema_migrations (
    owner TEXT NOT NULL,
    migration_id TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    PRIMARY KEY(owner, migration_id)
);";

const GOALS_V1_SQL: &str = "
CREATE TABLE goals_records (
    id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    payload TEXT NOT NULL
);
CREATE INDEX goals_owner_idx ON goals_records(owner);
CREATE TABLE goals_create_receipts (
    actor BLOB NOT NULL,
    idempotency_key BLOB NOT NULL,
    goal_id BLOB NOT NULL REFERENCES goals_records(id) ON DELETE CASCADE,
    payload TEXT NOT NULL,
    PRIMARY KEY(actor, idempotency_key)
);";

const IDENTITY_PERMISSIONS_V1_SQL: &str = "
CREATE TABLE identity_records (
    owner BLOB PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    payload TEXT NOT NULL
);
CREATE TABLE preference_records (
    owner BLOB PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    payload TEXT NOT NULL
);
CREATE TABLE resource_records (
    id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    payload TEXT NOT NULL
);
CREATE INDEX resources_owner_idx ON resource_records(owner);
CREATE TABLE permission_records (
    id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    session_id BLOB,
    payload TEXT NOT NULL
);
CREATE INDEX permissions_owner_idx ON permission_records(owner);
CREATE TABLE route_records (
    id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    payload TEXT NOT NULL
);
CREATE INDEX routes_owner_idx ON route_records(owner);";

const FOCUS_V1_SQL: &str = "
CREATE TABLE focus_records (
    id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    goal_id BLOB NOT NULL REFERENCES goals_records(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    payload TEXT NOT NULL
);
CREATE INDEX focus_owner_idx ON focus_records(owner);";

const INTERVENTION_V1_SQL: &str = "
CREATE TABLE intervention_records (
    id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    goal_id BLOB NOT NULL REFERENCES goals_records(id) ON DELETE CASCADE,
    session_id BLOB NOT NULL REFERENCES focus_records(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL CHECK(revision > 0),
    payload TEXT NOT NULL
);
CREATE INDEX interventions_owner_idx ON intervention_records(owner);
CREATE TABLE policy_records (
    id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX policy_owner_idx ON policy_records(owner);
CREATE TABLE outbox_records (
    id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    intervention_id BLOB NOT NULL REFERENCES intervention_records(id) ON DELETE CASCADE,
    deduplication_key BLOB NOT NULL UNIQUE,
    state TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX outbox_owner_state_idx ON outbox_records(owner, state);";

const AUDIT_V1_SQL: &str = "
CREATE TABLE audit_records (
    id BLOB PRIMARY KEY NOT NULL,
    owner BLOB NOT NULL,
    subject_id BLOB NOT NULL,
    occurred_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX audit_owner_time_idx ON audit_records(owner, occurred_at);";

const IDENTITY_PERMISSIONS_V2_CREATE_SQL: &str = "
CREATE TABLE permission_records_next (
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    goal_id BLOB NOT NULL REFERENCES goals_records(id) ON DELETE CASCADE CHECK(length(goal_id) = 16),
    revision INTEGER NOT NULL CHECK(revision > 0),
    session_id BLOB REFERENCES focus_records(id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
        CHECK(session_id IS NULL OR length(session_id) = 16),
    resource_id BLOB REFERENCES resource_records(id) ON DELETE SET NULL
        CHECK(resource_id IS NULL OR length(resource_id) = 16),
    payload TEXT NOT NULL
);";

const IDENTITY_PERMISSIONS_V2_FINISH_SQL: &str = "
DROP TABLE permission_records;
ALTER TABLE permission_records_next RENAME TO permission_records;
CREATE INDEX permissions_owner_idx ON permission_records(owner);
CREATE INDEX permissions_goal_idx ON permission_records(owner, goal_id);
CREATE INDEX permissions_session_idx ON permission_records(session_id);
CREATE INDEX permissions_resource_idx ON permission_records(resource_id);";

const INTERVENTION_V2_CREATE_SQL: &str = "
CREATE TABLE policy_records_next (
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    session_id BLOB NOT NULL REFERENCES focus_records(id) ON DELETE CASCADE CHECK(length(session_id) = 16),
    payload TEXT NOT NULL
);
CREATE TABLE outbox_records_next (
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 16),
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    intervention_id BLOB NOT NULL REFERENCES intervention_records(id) ON DELETE CASCADE CHECK(length(intervention_id) = 16),
    session_id BLOB NOT NULL REFERENCES focus_records(id) ON DELETE CASCADE CHECK(length(session_id) = 16),
    deduplication_key BLOB NOT NULL UNIQUE CHECK(length(deduplication_key) = 16),
    state TEXT NOT NULL CHECK(state IN (
        'queued', 'delivering', 'accepted_by_channel', 'delivery_unknown',
        'delivery_failed', 'expired', 'cancelled'
    )),
    expires_at TEXT NOT NULL,
    payload TEXT NOT NULL
);";

const INTERVENTION_V2_FINISH_SQL: &str = "
DROP TABLE outbox_records;
DROP TABLE policy_records;
ALTER TABLE policy_records_next RENAME TO policy_records;
ALTER TABLE outbox_records_next RENAME TO outbox_records;
CREATE INDEX policy_owner_idx ON policy_records(owner);
CREATE INDEX policy_session_idx ON policy_records(session_id);
CREATE INDEX outbox_owner_state_idx ON outbox_records(owner, state);
CREATE INDEX outbox_session_state_idx ON outbox_records(session_id, state);";

const PAYLOAD_RELATIONAL_LINKS_V2: &str =
    "decode typed v1 JSON; validate relational identity; copy goal/session/resource links; v1";

const OPERATION_RECEIPTS_V3_SQL: &str = "
CREATE TABLE operation_receipts (
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    operation_kind TEXT NOT NULL CHECK(operation_kind IN (
        'approve_model_route', 'grant_session_permission', 'start_focus_session'
    )),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) = 16),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    result_id BLOB NOT NULL CHECK(length(result_id) = 16),
    payload TEXT NOT NULL,
    PRIMARY KEY(owner, operation_kind, idempotency_key)
);
CREATE INDEX operation_receipts_result_idx
    ON operation_receipts(owner, operation_kind, result_id);";

const PREFERENCES_V4_CREATE_SQL: &str = "
CREATE TABLE preference_records_next (
    owner BLOB PRIMARY KEY NOT NULL CHECK(length(owner) = 16),
    revision INTEGER NOT NULL CHECK(revision > 0),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    payload TEXT NOT NULL
);";

const PREFERENCES_V4_FINISH_SQL: &str = "
DROP TABLE preference_records;
ALTER TABLE preference_records_next RENAME TO preference_records;";

const PREFERENCES_V4_CANONICALIZATION: &str = "decode legacy JSON; apply ADR0017 ExplicitPreferences defaults; validate owner, revision, and schema_version=1; canonical JSON re-encode; v1";

const IDENTITY_PREFERENCES_DEVICE_DELETIONS_V5_CREATE_SQL: &str = "
CREATE TABLE identity_records_next (
    owner BLOB PRIMARY KEY NOT NULL CHECK(length(owner) = 16),
    revision INTEGER NOT NULL CHECK(revision > 0),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    payload TEXT NOT NULL
);
CREATE TABLE preference_records_v5_next (
    owner BLOB PRIMARY KEY NOT NULL CHECK(length(owner) = 16),
    revision INTEGER NOT NULL CHECK(revision > 0),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    payload TEXT NOT NULL
);
CREATE TABLE device_records (
    owner BLOB PRIMARY KEY NOT NULL CHECK(length(owner) = 16),
    device_id BLOB NOT NULL UNIQUE CHECK(length(device_id) = 16),
    issued_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE goal_deletion_tombstones (
    goal_id BLOB PRIMARY KEY NOT NULL CHECK(length(goal_id) = 16),
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    deleted_revision INTEGER NOT NULL CHECK(deleted_revision > 0),
    deleted_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX goal_deletion_owner_idx ON goal_deletion_tombstones(owner);
CREATE TABLE resource_deletion_tombstones (
    resource_id BLOB PRIMARY KEY NOT NULL CHECK(length(resource_id) = 16),
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    deleted_revision INTEGER NOT NULL CHECK(deleted_revision > 0),
    deleted_at TEXT NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX resource_deletion_owner_idx ON resource_deletion_tombstones(owner);
CREATE TABLE native_resource_cleanup_records (
    resource_id BLOB PRIMARY KEY NOT NULL CHECK(length(resource_id) = 16),
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL CHECK(length(payload) <= 2048)
);
CREATE INDEX native_resource_cleanup_owner_idx
    ON native_resource_cleanup_records(owner);
CREATE TABLE operation_receipts_v5_next (
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    operation_kind TEXT NOT NULL CHECK(operation_kind IN (
        'approve_model_route', 'grant_session_permission', 'start_focus_session',
        'register_selected_resource'
    )),
    idempotency_key BLOB NOT NULL CHECK(length(idempotency_key) = 16),
    request_digest BLOB NOT NULL CHECK(length(request_digest) = 32),
    result_id BLOB NOT NULL CHECK(length(result_id) = 16),
    payload TEXT NOT NULL,
    PRIMARY KEY(owner, operation_kind, idempotency_key)
);";

const IDENTITY_PREFERENCES_DEVICE_DELETIONS_V5_FINISH_SQL: &str = "
DROP TABLE identity_records;
ALTER TABLE identity_records_next RENAME TO identity_records;
DROP TABLE preference_records;
ALTER TABLE preference_records_v5_next RENAME TO preference_records;
INSERT INTO operation_receipts_v5_next(
    owner,operation_kind,idempotency_key,request_digest,result_id,payload
)
SELECT owner,operation_kind,idempotency_key,request_digest,result_id,payload
FROM operation_receipts;
DROP TABLE operation_receipts;
ALTER TABLE operation_receipts_v5_next RENAME TO operation_receipts;
CREATE INDEX operation_receipts_result_idx
    ON operation_receipts(owner, operation_kind, result_id);";

const IDENTITY_PREFERENCES_V5_CANONICALIZATION: &str = "decode typed v4 JSON; replace identity with shipped SteinIdentityV1 invariants and product-migration provenance; disable ambient proactive enablement, remote processing, and restart continuity while preserving explicit global mute and bounded presentation preferences; canonical JSON re-encode; v2";

const SECRET_DELETION_CLEANUP_V6_SQL: &str = "
CREATE TABLE secret_deletion_cleanup_records (
    route_id BLOB PRIMARY KEY NOT NULL CHECK(length(route_id) = 16),
    owner BLOB NOT NULL CHECK(length(owner) = 16),
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL CHECK(length(payload) <= 1024)
);
CREATE INDEX secret_deletion_cleanup_owner_idx
    ON secret_deletion_cleanup_records(owner);";

struct MigrationDefinition {
    schema_version: i64,
    owner: &'static str,
    migration_id: &'static str,
    checksum_material: &'static [&'static str],
}

const MIGRATIONS: &[MigrationDefinition] = &[
    MigrationDefinition {
        schema_version: 1,
        owner: "goals",
        migration_id: "goals-v1",
        checksum_material: &[GOALS_V1_SQL],
    },
    MigrationDefinition {
        schema_version: 1,
        owner: "identity_permissions",
        migration_id: "identity-permissions-v1",
        checksum_material: &[IDENTITY_PERMISSIONS_V1_SQL],
    },
    MigrationDefinition {
        schema_version: 1,
        owner: "focus",
        migration_id: "focus-v1",
        checksum_material: &[FOCUS_V1_SQL],
    },
    MigrationDefinition {
        schema_version: 1,
        owner: "intervention",
        migration_id: "intervention-v1",
        checksum_material: &[INTERVENTION_V1_SQL],
    },
    MigrationDefinition {
        schema_version: 1,
        owner: "audit",
        migration_id: "audit-v1",
        checksum_material: &[AUDIT_V1_SQL],
    },
    MigrationDefinition {
        schema_version: 2,
        owner: "identity_permissions",
        migration_id: "identity-permissions-v2-goal-links",
        checksum_material: &[
            IDENTITY_PERMISSIONS_V2_CREATE_SQL,
            PAYLOAD_RELATIONAL_LINKS_V2,
            IDENTITY_PERMISSIONS_V2_FINISH_SQL,
        ],
    },
    MigrationDefinition {
        schema_version: 2,
        owner: "intervention",
        migration_id: "intervention-v2-workflow-links",
        checksum_material: &[
            INTERVENTION_V2_CREATE_SQL,
            PAYLOAD_RELATIONAL_LINKS_V2,
            INTERVENTION_V2_FINISH_SQL,
        ],
    },
    MigrationDefinition {
        schema_version: 3,
        owner: "application",
        migration_id: "application-v3-operation-receipts",
        checksum_material: &[OPERATION_RECEIPTS_V3_SQL],
    },
    MigrationDefinition {
        schema_version: 4,
        owner: "identity_permissions",
        migration_id: "identity-permissions-v4-explicit-preferences-v1",
        checksum_material: &[
            PREFERENCES_V4_CREATE_SQL,
            PREFERENCES_V4_CANONICALIZATION,
            PREFERENCES_V4_FINISH_SQL,
        ],
    },
    MigrationDefinition {
        schema_version: 5,
        owner: "identity_permissions",
        migration_id: "identity-permissions-v5-private-product-contracts",
        checksum_material: &[
            IDENTITY_PREFERENCES_DEVICE_DELETIONS_V5_CREATE_SQL,
            IDENTITY_PREFERENCES_V5_CANONICALIZATION,
            IDENTITY_PREFERENCES_DEVICE_DELETIONS_V5_FINISH_SQL,
        ],
    },
    MigrationDefinition {
        schema_version: 6,
        owner: "identity_permissions",
        migration_id: "identity-permissions-v6-secret-deletion-cleanup",
        checksum_material: &[SECRET_DELETION_CLEANUP_V6_SQL],
    },
];

type Job = Box<dyn FnOnce(&mut Connection) + Send + 'static>;
type OperationReceiptRow = (String, Vec<u8>, Vec<u8>, Vec<u8>, String);

#[derive(Clone)]
pub struct SqliteRepository {
    worker: std::sync::Arc<Worker>,
}

struct Worker {
    sender: Mutex<Option<SyncSender<Job>>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.sender
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(thread) = self
            .thread
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            let _ = thread.join();
        }
    }
}

impl std::fmt::Debug for SqliteRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteRepository")
            .finish_non_exhaustive()
    }
}

impl SqliteRepository {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RepositoryError> {
        let path = path.as_ref().to_path_buf();
        let (sender, receiver) = mpsc::sync_channel::<Job>(128);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let worker_path = path.clone();
        let thread = std::thread::Builder::new()
            .name("stein-sqlite-repository".to_owned())
            .spawn(move || {
                let opened =
                    Connection::open(&worker_path)
                        .map_err(sql_error)
                        .and_then(|mut connection| {
                            initialize(&mut connection)?;
                            Ok(connection)
                        });
                match opened {
                    Ok(mut connection) => {
                        let _ = ready_sender.send(Ok(()));
                        while let Ok(job) = receiver.recv() {
                            job(&mut connection);
                        }
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error));
                    }
                }
            })
            .map_err(|_| RepositoryError {
                kind: RepositoryErrorKind::Unavailable,
                summary: "The SQLite repository worker could not start.",
            })?;
        ready_receiver.recv().map_err(|_| RepositoryError {
            kind: RepositoryErrorKind::Unavailable,
            summary: "The SQLite repository worker stopped during startup.",
        })??;
        Ok(Self {
            worker: std::sync::Arc::new(Worker {
                sender: Mutex::new(Some(sender)),
                thread: Mutex::new(Some(thread)),
            }),
        })
    }

    pub fn schema_version(&self) -> Result<i64, RepositoryError> {
        self.call(|connection| {
            connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .map_err(sql_error)
        })
    }

    pub fn integrity_check(&self) -> Result<(), RepositoryError> {
        self.call(|connection| verify_database_integrity(connection))
    }

    pub fn create_recovery_copy(
        &self,
        destination: impl AsRef<Path>,
    ) -> Result<(), RepositoryError> {
        let destination = destination.as_ref().to_path_buf();
        self.call(move |connection| {
            let mut destination = Connection::open(destination).map_err(sql_error)?;
            let backup =
                rusqlite::backup::Backup::new(connection, &mut destination).map_err(sql_error)?;
            backup
                .run_to_completion(64, Duration::from_millis(10), None)
                .map_err(sql_error)?;
            drop(backup);
            if schema_version(&destination)? != SCHEMA_VERSION {
                return Err(RepositoryError {
                    kind: RepositoryErrorKind::Corrupt,
                    summary: "The SQLite recovery copy has an unexpected schema version.",
                });
            }
            verify_migration_catalog(&destination, SCHEMA_VERSION)?;
            verify_database_integrity(&destination)?;
            verify_logical_integrity(&destination)
        })
    }

    fn call<T, F>(&self, operation: F) -> Result<T, RepositoryError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, RepositoryError> + Send + 'static,
    {
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        let sender = self
            .worker
            .sender
            .lock()
            .map_err(|_| RepositoryError {
                kind: RepositoryErrorKind::Internal,
                summary: "The SQLite repository worker state is unavailable.",
            })?
            .as_ref()
            .cloned()
            .ok_or(RepositoryError {
                kind: RepositoryErrorKind::Unavailable,
                summary: "The SQLite repository worker has stopped.",
            })?;
        sender
            .send(Box::new(move |connection| {
                let _ = result_sender.send(operation(connection));
            }))
            .map_err(|_| RepositoryError {
                kind: RepositoryErrorKind::Unavailable,
                summary: "The SQLite repository worker is unavailable.",
            })?;
        result_receiver.recv().map_err(|_| RepositoryError {
            kind: RepositoryErrorKind::Unavailable,
            summary: "The SQLite repository operation was interrupted.",
        })?
    }
}

fn initialize(connection: &mut Connection) -> Result<(), RepositoryError> {
    connection.busy_timeout(BUSY_TIMEOUT).map_err(sql_error)?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE;
             PRAGMA synchronous=EXTRA;
             PRAGMA foreign_keys=ON;
             PRAGMA secure_delete=ON;
             PRAGMA temp_store=MEMORY;",
        )
        .map_err(sql_error)?;
    verify_pragma_text(connection, "journal_mode", "delete")?;
    verify_pragma_i64(connection, "synchronous", 3)?;
    verify_pragma_i64(connection, "foreign_keys", 1)?;
    verify_pragma_i64(connection, "secure_delete", 1)?;
    verify_pragma_i64(connection, "temp_store", 2)?;
    verify_pragma_i64(connection, "busy_timeout", BUSY_TIMEOUT_MILLISECONDS)?;

    verify_database_integrity(connection)?;
    let version = schema_version(connection)?;
    match version {
        0 => {
            migrate_v1(connection)?;
            migrate_v2(connection)?;
            migrate_v3(connection)?;
            migrate_v4(connection)?;
            migrate_v5(connection)?;
            migrate_v6(connection)?;
        }
        1 => {
            verify_migration_catalog(connection, 1)?;
            migrate_v2(connection)?;
            migrate_v3(connection)?;
            migrate_v4(connection)?;
            migrate_v5(connection)?;
            migrate_v6(connection)?;
        }
        2 => {
            verify_migration_catalog(connection, 2)?;
            migrate_v3(connection)?;
            migrate_v4(connection)?;
            migrate_v5(connection)?;
            migrate_v6(connection)?;
        }
        3 => {
            verify_migration_catalog(connection, 3)?;
            migrate_v4(connection)?;
            migrate_v5(connection)?;
            migrate_v6(connection)?;
        }
        4 => {
            verify_migration_catalog(connection, 4)?;
            migrate_v5(connection)?;
            migrate_v6(connection)?;
        }
        5 => {
            verify_migration_catalog(connection, 5)?;
            migrate_v6(connection)?;
        }
        SCHEMA_VERSION => verify_migration_catalog(connection, SCHEMA_VERSION)?,
        _ => {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Unavailable,
                summary: "The SQLite schema version is not supported by this binary.",
            });
        }
    }
    if schema_version(connection)? != SCHEMA_VERSION {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "The SQLite migration did not reach the expected schema version.",
        });
    }
    verify_migration_catalog(connection, SCHEMA_VERSION)?;
    verify_database_integrity(connection)?;
    scrub_terminal_outbox_content(connection)?;
    verify_database_integrity(connection)?;
    verify_logical_integrity(connection)?;
    Ok(())
}

fn migrate_v1(connection: &mut Connection) -> Result<(), RepositoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(sql_error)?;
    transaction
        .execute_batch(MIGRATION_CATALOG_SQL)
        .map_err(sql_error)?;
    for migration_sql in [
        GOALS_V1_SQL,
        IDENTITY_PERMISSIONS_V1_SQL,
        FOCUS_V1_SQL,
        INTERVENTION_V1_SQL,
        AUDIT_V1_SQL,
    ] {
        transaction
            .execute_batch(migration_sql)
            .map_err(sql_error)?;
    }
    record_migrations(&transaction, 1)?;
    transaction
        .pragma_update(None, "user_version", 1_i64)
        .map_err(sql_error)?;
    transaction.commit().map_err(sql_error)
}

fn migrate_v2(connection: &mut Connection) -> Result<(), RepositoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(sql_error)?;
    transaction
        .execute_batch(IDENTITY_PERMISSIONS_V2_CREATE_SQL)
        .map_err(sql_error)?;
    copy_permissions_to_v2(&transaction)?;
    transaction
        .execute_batch(IDENTITY_PERMISSIONS_V2_FINISH_SQL)
        .map_err(sql_error)?;

    transaction
        .execute_batch(INTERVENTION_V2_CREATE_SQL)
        .map_err(sql_error)?;
    copy_policy_and_outbox_to_v2(&transaction)?;
    transaction
        .execute_batch(INTERVENTION_V2_FINISH_SQL)
        .map_err(sql_error)?;
    record_migrations(&transaction, 2)?;
    transaction
        .pragma_update(None, "user_version", 2_i64)
        .map_err(sql_error)?;
    transaction.commit().map_err(sql_error)
}

fn migrate_v3(connection: &mut Connection) -> Result<(), RepositoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(sql_error)?;
    transaction
        .execute_batch(OPERATION_RECEIPTS_V3_SQL)
        .map_err(sql_error)?;
    record_migrations(&transaction, 3)?;
    transaction
        .pragma_update(None, "user_version", 3_i64)
        .map_err(sql_error)?;
    transaction.commit().map_err(sql_error)
}

fn migrate_v4(connection: &mut Connection) -> Result<(), RepositoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(sql_error)?;
    transaction
        .execute_batch(PREFERENCES_V4_CREATE_SQL)
        .map_err(sql_error)?;
    copy_preferences_to_v4(&transaction)?;
    transaction
        .execute_batch(PREFERENCES_V4_FINISH_SQL)
        .map_err(sql_error)?;
    record_migrations(&transaction, 4)?;
    transaction
        .pragma_update(None, "user_version", 4_i64)
        .map_err(sql_error)?;
    transaction.commit().map_err(sql_error)
}

fn migrate_v5(connection: &mut Connection) -> Result<(), RepositoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(sql_error)?;
    transaction
        .execute_batch(IDENTITY_PREFERENCES_DEVICE_DELETIONS_V5_CREATE_SQL)
        .map_err(sql_error)?;
    copy_identity_and_preferences_to_v5(&transaction)?;
    transaction
        .execute_batch(IDENTITY_PREFERENCES_DEVICE_DELETIONS_V5_FINISH_SQL)
        .map_err(sql_error)?;
    record_migrations(&transaction, 5)?;
    transaction
        .pragma_update(None, "user_version", 5_i64)
        .map_err(sql_error)?;
    transaction.commit().map_err(sql_error)
}

fn migrate_v6(connection: &mut Connection) -> Result<(), RepositoryError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(sql_error)?;
    transaction
        .execute_batch(SECRET_DELETION_CLEANUP_V6_SQL)
        .map_err(sql_error)?;
    record_migrations(&transaction, 6)?;
    transaction
        .pragma_update(None, "user_version", 6_i64)
        .map_err(sql_error)?;
    transaction.commit().map_err(sql_error)
}

fn copy_identity_and_preferences_to_v5(
    transaction: &Transaction<'_>,
) -> Result<(), RepositoryError> {
    let mut identity_statement = transaction
        .prepare("SELECT owner,revision,payload FROM identity_records")
        .map_err(sql_error)?;
    let identity_rows = identity_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sql_error)?;
    let identities: Result<Vec<_>, RepositoryError> = identity_rows
        .map(|row| {
            let (owner_blob, revision, payload) = row.map_err(sql_error)?;
            let owner = actor_from_blob(&owner_blob)?;
            let legacy: SteinIdentity = decode_owned(payload, owner)?;
            if revision != sql_u64(legacy.revision)? {
                return Err(relational_payload_mismatch());
            }
            let canonical = if legacy.has_shipped_v1_invariants() {
                legacy
            } else {
                let mut canonical = SteinIdentity::shipped_v1(owner, legacy.updated_at);
                canonical.revision = legacy.revision.saturating_add(1);
                canonical.updated_at = legacy.updated_at;
                canonical.provenance.recorded_at = legacy.updated_at;
                canonical
            };
            Ok((owner_blob, canonical))
        })
        .collect();
    drop(identity_statement);
    for (owner_blob, value) in identities? {
        transaction
            .execute(
                "INSERT INTO identity_records_next(owner,revision,schema_version,payload)
                 VALUES(?1,?2,?3,?4)",
                params![
                    owner_blob,
                    sql_u64(value.revision)?,
                    i64::from(value.schema_version),
                    encode(&value)?,
                ],
            )
            .map_err(sql_error)?;
    }

    let mut preferences_statement = transaction
        .prepare("SELECT owner,revision,schema_version,payload FROM preference_records")
        .map_err(sql_error)?;
    let preference_rows = preferences_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql_error)?;
    let preferences: Result<Vec<_>, RepositoryError> = preference_rows
        .map(|row| {
            let (owner_blob, revision, schema_version, payload) = row.map_err(sql_error)?;
            let owner = actor_from_blob(&owner_blob)?;
            let mut value: ExplicitPreferences = decode_owned(payload, owner)?;
            if revision != sql_u64(value.revision)?
                || schema_version != i64::from(value.schema_version)
                || value.schema_version != USER_PREFERENCES_SCHEMA_V1
            {
                return Err(relational_payload_mismatch());
            }
            let safe_intervention_cap = value.maximum_interventions_per_session.min(3);
            let safe_model_cap = value.maximum_model_requests_per_hour.min(12);
            let safe_cooldown = value.minimum_intervention_cooldown_seconds.max(15 * 60);
            let safety_changed = value.maximum_interventions_per_session != safe_intervention_cap
                || value.maximum_model_requests_per_hour != safe_model_cap
                || value.minimum_intervention_cooldown_seconds != safe_cooldown
                || value.proactive_interventions_enabled
                || value.remote_processing_enabled
                || value.restart_continuity_default;
            value.maximum_interventions_per_session = safe_intervention_cap;
            value.maximum_model_requests_per_hour = safe_model_cap;
            value.minimum_intervention_cooldown_seconds = safe_cooldown;
            value.proactive_interventions_enabled = false;
            value.remote_processing_enabled = false;
            value.restart_continuity_default = false;
            if safety_changed {
                value.revision = value.revision.saturating_add(1);
                value.provenance = RecordProvenance {
                    source: RecordProvenanceSource::ProductMigration,
                    version: "preferences-v5-safe-defaults".to_owned(),
                    recorded_at: value.updated_at,
                };
            }
            Ok((owner_blob, value))
        })
        .collect();
    drop(preferences_statement);
    for (owner_blob, value) in preferences? {
        transaction
            .execute(
                "INSERT INTO preference_records_v5_next(owner,revision,schema_version,payload)
                 VALUES(?1,?2,?3,?4)",
                params![
                    owner_blob,
                    sql_u64(value.revision)?,
                    i64::from(value.schema_version),
                    encode(&value)?,
                ],
            )
            .map_err(sql_error)?;
    }
    Ok(())
}

fn copy_preferences_to_v4(transaction: &Transaction<'_>) -> Result<(), RepositoryError> {
    let mut statement = transaction
        .prepare("SELECT owner,revision,payload FROM preference_records")
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sql_error)?;
    let preferences: Result<Vec<_>, RepositoryError> = rows
        .map(|row| {
            let (owner_blob, revision, payload) = row.map_err(sql_error)?;
            let owner = actor_from_blob(&owner_blob)?;
            let value: ExplicitPreferences = decode_owned(payload, owner)?;
            if revision != sql_u64(value.revision)?
                || value.schema_version != USER_PREFERENCES_SCHEMA_V1
            {
                return Err(relational_payload_mismatch());
            }
            Ok((value, owner_blob))
        })
        .collect();
    drop(statement);

    for (value, owner_blob) in preferences? {
        transaction
            .execute(
                "INSERT INTO preference_records_next(owner,revision,schema_version,payload)
                 VALUES(?1,?2,?3,?4)",
                params![
                    owner_blob,
                    sql_u64(value.revision)?,
                    i64::from(value.schema_version),
                    encode(&value)?,
                ],
            )
            .map_err(sql_error)?;
    }
    Ok(())
}

fn copy_permissions_to_v2(transaction: &Transaction<'_>) -> Result<(), RepositoryError> {
    let mut statement = transaction
        .prepare("SELECT id,owner,revision,session_id,payload FROM permission_records")
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(sql_error)?;
    let records: Result<Vec<_>, RepositoryError> = rows
        .map(|row| {
            let (record_id, owner, revision, session_id, payload) = row.map_err(sql_error)?;
            let value: PermissionGrant = decode(payload.clone())?;
            if record_id != id(value.id.as_uuid())
                || owner != id(value.owner.as_uuid())
                || revision != sql_u64(value.revision)?
                || session_id != value.focus_session_id.map(|session| id(session.as_uuid()))
            {
                return Err(relational_payload_mismatch());
            }
            Ok((value, payload))
        })
        .collect();
    drop(statement);

    for (value, payload) in records? {
        transaction
            .execute(
                "INSERT INTO permission_records_next(
                     id,owner,goal_id,revision,session_id,resource_id,payload
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    id(value.id.as_uuid()),
                    id(value.owner.as_uuid()),
                    id(value.goal_id.as_uuid()),
                    sql_u64(value.revision)?,
                    value.focus_session_id.map(|session| id(session.as_uuid())),
                    value
                        .selected_resource_id
                        .map(|resource| id(resource.as_uuid())),
                    payload,
                ],
            )
            .map_err(sql_error)?;
    }
    Ok(())
}

fn copy_policy_and_outbox_to_v2(transaction: &Transaction<'_>) -> Result<(), RepositoryError> {
    let mut policy_statement = transaction
        .prepare("SELECT id,owner,payload FROM policy_records")
        .map_err(sql_error)?;
    let policy_rows = policy_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sql_error)?;
    let policies: Result<Vec<_>, RepositoryError> = policy_rows
        .map(|row| {
            let (record_id, owner, payload) = row.map_err(sql_error)?;
            let value: PolicyDecision = decode(payload.clone())?;
            if record_id != id(value.id.as_uuid()) || owner != id(value.owner.as_uuid()) {
                return Err(relational_payload_mismatch());
            }
            Ok((value, payload))
        })
        .collect();
    drop(policy_statement);
    for (value, payload) in policies? {
        transaction
            .execute(
                "INSERT INTO policy_records_next(id,owner,session_id,payload)
                 VALUES(?1,?2,?3,?4)",
                params![
                    id(value.id.as_uuid()),
                    id(value.owner.as_uuid()),
                    id(value.focus_session_id.as_uuid()),
                    payload,
                ],
            )
            .map_err(sql_error)?;
    }

    let mut outbox_statement = transaction
        .prepare(
            "SELECT o.id,o.owner,o.intervention_id,o.deduplication_key,o.state,o.expires_at,
                    o.payload,i.session_id
             FROM outbox_records o
             JOIN intervention_records i ON i.id=o.intervention_id",
        )
        .map_err(sql_error)?;
    let outbox_rows = outbox_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        })
        .map_err(sql_error)?;
    let deliveries: Result<Vec<_>, RepositoryError> = outbox_rows
        .map(|row| {
            let (
                record_id,
                owner,
                intervention_id,
                deduplication_key,
                state,
                expires_at,
                payload,
                session_id,
            ) = row.map_err(sql_error)?;
            let mut value: PendingInterventionDelivery = decode(payload)?;
            if record_id != id(value.id.as_uuid())
                || owner != id(value.owner.as_uuid())
                || intervention_id != id(value.intervention_id.as_uuid())
                || deduplication_key != id(value.deduplication_key)
                || (state != outbox_state_wire(value.state)
                    && state != legacy_outbox_state_wire(value.state))
                || expires_at != value.expires_at.to_string()
            {
                return Err(relational_payload_mismatch());
            }
            if !outbox_state_retains_private_text(value.state) {
                value.user_visible_text.clear();
            }
            Ok((value, session_id))
        })
        .collect();
    drop(outbox_statement);
    for (value, session_id) in deliveries? {
        transaction
            .execute(
                "INSERT INTO outbox_records_next(
                     id,owner,intervention_id,session_id,deduplication_key,state,expires_at,payload
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    id(value.id.as_uuid()),
                    id(value.owner.as_uuid()),
                    id(value.intervention_id.as_uuid()),
                    session_id,
                    id(value.deduplication_key),
                    outbox_state_wire(value.state),
                    value.expires_at.to_string(),
                    encode(&value)?,
                ],
            )
            .map_err(sql_error)?;
    }
    Ok(())
}

fn migration_checksum(definition: &MigrationDefinition) -> String {
    let mut digest = Sha256::new();
    for part in std::iter::once(definition.owner)
        .chain(std::iter::once(definition.migration_id))
        .chain(definition.checksum_material.iter().copied())
    {
        let canonical = part.replace("\r\n", "\n");
        digest.update(
            u64::try_from(canonical.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        digest.update(canonical.as_bytes());
    }
    format!("sha256:{:x}", digest.finalize())
}

fn record_migrations(
    transaction: &Transaction<'_>,
    schema_version: i64,
) -> Result<(), RepositoryError> {
    for definition in MIGRATIONS
        .iter()
        .filter(|migration| migration.schema_version == schema_version)
    {
        transaction
            .execute(
                "INSERT INTO schema_migrations(owner,migration_id,checksum,applied_at)
                 VALUES(?1,?2,?3,strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                params![
                    definition.owner,
                    definition.migration_id,
                    migration_checksum(definition),
                ],
            )
            .map_err(sql_error)?;
    }
    Ok(())
}

fn verify_migration_catalog(
    connection: &Connection,
    schema_version: i64,
) -> Result<(), RepositoryError> {
    let mut expected: Vec<_> = MIGRATIONS
        .iter()
        .filter(|migration| migration.schema_version <= schema_version)
        .map(|migration| {
            (
                migration.owner.to_owned(),
                migration.migration_id.to_owned(),
                migration_checksum(migration),
            )
        })
        .collect();
    expected.sort();

    let mut statement = connection
        .prepare(
            "SELECT owner,migration_id,checksum,applied_at
             FROM schema_migrations ORDER BY owner,migration_id",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql_error)?;
    let mut actual = Vec::new();
    for row in rows {
        let (owner, migration_id, checksum, applied_at) = row.map_err(sql_error)?;
        if applied_at.is_empty() {
            return Err(migration_catalog_error());
        }
        actual.push((owner, migration_id, checksum));
    }
    if actual == expected {
        Ok(())
    } else {
        Err(migration_catalog_error())
    }
}

fn schema_version(connection: &Connection) -> Result<i64, RepositoryError> {
    connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(sql_error)
}

fn verify_database_integrity(connection: &Connection) -> Result<(), RepositoryError> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(sql_error)?;
    if integrity != "ok" {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "SQLite integrity verification failed.",
        });
    }
    let foreign_key_errors: i64 = connection
        .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(sql_error)?;
    if foreign_key_errors == 0 {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "SQLite foreign-key verification failed.",
        })
    }
}

fn verify_logical_integrity(connection: &Connection) -> Result<(), RepositoryError> {
    verify_owned_record_table::<Goal>(connection, "goals_records")?;
    verify_identity(connection)?;
    verify_preferences(connection)?;
    verify_devices(connection)?;
    verify_goal_deletion_tombstones(connection)?;
    verify_resource_deletion_tombstones(connection)?;
    verify_owned_record_table::<ResourceBinding>(connection, "resource_records")?;
    verify_resource_binding_privacy(connection)?;
    verify_native_resource_cleanups(connection)?;
    verify_secret_deletion_cleanups(connection)?;
    verify_owned_record_table::<PermissionGrant>(connection, "permission_records")?;
    verify_owned_record_table::<ModelRouteApproval>(connection, "route_records")?;
    verify_owned_record_table::<FocusSession>(connection, "focus_records")?;
    verify_owned_record_table::<Intervention>(connection, "intervention_records")?;
    verify_owned_record_table::<PolicyDecision>(connection, "policy_records")?;
    verify_owned_record_table::<AuditRecord>(connection, "audit_records")?;
    verify_owned_record_table::<PendingInterventionDelivery>(connection, "outbox_records")?;
    verify_outbox_privacy(connection)?;
    verify_goal_receipts(connection)?;
    verify_operation_receipts(connection)
}

fn validate_opaque_resource_reference(value: &str) -> Result<(), RepositoryError> {
    let lower = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 512
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
        || lower.contains("://")
        || lower.starts_with("file:")
    {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "A native resource reference is not an opaque bounded token.",
        });
    }
    Ok(())
}

fn verify_resource_binding_privacy(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare("SELECT owner,payload FROM resource_records")
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (owner_blob, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let value: ResourceBinding = decode_owned(payload, owner)?;
        validate_opaque_resource_reference(&value.opaque_reference)?;
    }
    Ok(())
}

fn verify_native_resource_cleanups(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare(
            "SELECT resource_id,owner,created_at,payload
             FROM native_resource_cleanup_records",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (resource_blob, owner_blob, created_at, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let value: NativeResourceCleanup = decode_owned(payload, owner)?;
        if id(value.resource_id.as_uuid()) != resource_blob
            || value.created_at.to_string() != created_at
        {
            return Err(relational_payload_mismatch());
        }
        validate_opaque_resource_reference(&value.opaque_reference)?;
    }
    Ok(())
}

fn validate_secret_reference(value: &str) -> Result<(), RepositoryError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "A secret cleanup reference is not a bounded opaque token.",
        });
    }
    Ok(())
}

fn verify_secret_deletion_cleanups(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare(
            "SELECT route_id,owner,created_at,payload
             FROM secret_deletion_cleanup_records",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (route_blob, owner_blob, created_at, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let value: SecretDeletionCleanup = decode_owned(payload, owner)?;
        if id(value.model_route_approval_id.as_uuid()) != route_blob
            || value.created_at.to_string() != created_at
        {
            return Err(relational_payload_mismatch());
        }
        validate_secret_reference(value.secret_ref.as_str())?;
        let route_payload: Option<String> = connection
            .query_row(
                "SELECT payload FROM route_records WHERE id=?1 AND owner=?2",
                params![
                    id(value.model_route_approval_id.as_uuid()),
                    id(owner.as_uuid())
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(sql_error)?;
        let Some(route_payload) = route_payload else {
            return Err(relational_payload_mismatch());
        };
        let route: ModelRouteApproval = decode_owned(route_payload, owner)?;
        if route.revoked_at.is_none() || route.secret_ref != value.secret_ref {
            return Err(relational_payload_mismatch());
        }
    }
    Ok(())
}

fn verify_identity(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare("SELECT owner,revision,schema_version,payload FROM identity_records")
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (owner_blob, revision, schema_version, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let value: SteinIdentity = decode_owned(payload, owner)?;
        if revision != sql_u64(value.revision)?
            || schema_version != i64::from(value.schema_version)
            || !value.has_shipped_v1_invariants()
        {
            return Err(relational_payload_mismatch());
        }
    }
    Ok(())
}

fn verify_devices(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare("SELECT owner,device_id,issued_at,payload FROM device_records")
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (owner_blob, device_blob, issued_at, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let value: DeviceRegistration = decode_owned(payload, owner)?;
        if id(value.device_id.as_uuid()) != device_blob || value.issued_at.to_string() != issued_at
        {
            return Err(relational_payload_mismatch());
        }
    }
    Ok(())
}

fn verify_goal_deletion_tombstones(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare(
            "SELECT goal_id,owner,deleted_revision,deleted_at,payload
             FROM goal_deletion_tombstones",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (goal_blob, owner_blob, revision, deleted_at, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let value: GoalDeletionTombstone = decode_owned(payload, owner)?;
        if id(value.goal_id.as_uuid()) != goal_blob
            || sql_u64(value.deleted_revision)? != revision
            || value.deleted_at.to_string() != deleted_at
        {
            return Err(relational_payload_mismatch());
        }
    }
    Ok(())
}

fn verify_resource_deletion_tombstones(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare(
            "SELECT resource_id,owner,deleted_revision,deleted_at,payload
             FROM resource_deletion_tombstones",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (resource_blob, owner_blob, revision, deleted_at, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let value: SelectedResourceDeletionTombstone = decode_owned(payload, owner)?;
        if id(value.resource_id.as_uuid()) != resource_blob
            || sql_u64(value.deleted_revision)? != revision
            || value.deleted_at.to_string() != deleted_at
        {
            return Err(relational_payload_mismatch());
        }
    }
    Ok(())
}

fn verify_preferences(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare("SELECT owner,revision,schema_version,payload FROM preference_records")
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (owner_blob, revision, schema_version, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let value: ExplicitPreferences = decode_owned(payload, owner)?;
        if revision != sql_u64(value.revision)?
            || schema_version != i64::from(value.schema_version)
            || value.schema_version != USER_PREFERENCES_SCHEMA_V1
        {
            return Err(relational_payload_mismatch());
        }
    }
    Ok(())
}

fn verify_outbox_privacy(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare("SELECT payload FROM outbox_records")
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(sql_error)?;
    for row in rows {
        let delivery: PendingInterventionDelivery = decode(row.map_err(sql_error)?)?;
        if (!outbox_state_retains_private_text(delivery.state)
            && !delivery.user_visible_text.is_empty())
            || delivery.user_visible_text.chars().count() > MAX_OUTBOX_TEXT_SCALARS
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A pending-delivery record violates its privacy bound.",
            });
        }
    }
    Ok(())
}

fn verify_owned_record_table<T>(
    connection: &Connection,
    table: &'static str,
) -> Result<(), RepositoryError>
where
    T: DeserializeOwned + OwnedDurableRecord,
{
    let mut statement = connection
        .prepare(&format!("SELECT id,owner,payload FROM {table}"))
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (record_id, owner_blob, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let value: T = decode_owned(payload, owner)?;
        if value.durable_owner() != owner || value.durable_id() != uuid_from_blob(&record_id)? {
            return Err(relational_payload_mismatch());
        }
    }
    Ok(())
}

fn verify_goal_receipts(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare("SELECT actor,idempotency_key,goal_id,payload FROM goals_create_receipts")
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (actor, key, goal_id, payload) = row.map_err(sql_error)?;
        let receipt: GoalCreateReceipt = decode(payload)?;
        if receipt.actor != actor_from_blob(&actor)?
            || receipt.idempotency_key.as_uuid() != uuid_from_blob(&key)?
            || receipt.goal_id.as_uuid() != uuid_from_blob(&goal_id)?
        {
            return Err(relational_payload_mismatch());
        }
    }
    Ok(())
}

fn verify_operation_receipts(connection: &Connection) -> Result<(), RepositoryError> {
    let mut statement = connection
        .prepare(
            "SELECT owner,operation_kind,idempotency_key,request_digest,result_id,payload
             FROM operation_receipts",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(sql_error)?;
    for row in rows {
        let (owner_blob, kind, key, digest, result_id, payload) = row.map_err(sql_error)?;
        let owner = actor_from_blob(&owner_blob)?;
        let receipt: OperationReceipt = decode_owned(payload, owner)?;
        if OperationKind::from_wire_name(&kind) != Some(receipt.kind)
            || receipt.idempotency_key.as_uuid() != uuid_from_blob(&key)?
            || digest.as_slice() != receipt.request_digest
            || receipt.result_id != uuid_from_blob(&result_id)?
        {
            return Err(relational_payload_mismatch());
        }
    }
    Ok(())
}

fn scrub_terminal_outbox_content(connection: &mut Connection) -> Result<(), RepositoryError> {
    let transaction = connection.transaction().map_err(sql_error)?;
    let mut statement = transaction
        .prepare(
            "SELECT id,state,payload FROM outbox_records
             WHERE state NOT IN ('queued','delivering')",
        )
        .map_err(sql_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sql_error)?;
    let deliveries: Result<Vec<_>, RepositoryError> = rows
        .map(|row| {
            let (record_id, state, payload) = row.map_err(sql_error)?;
            let mut delivery: PendingInterventionDelivery = decode(payload)?;
            if record_id != id(delivery.id.as_uuid())
                || state != outbox_state_wire(delivery.state)
                || outbox_state_retains_private_text(delivery.state)
            {
                return Err(relational_payload_mismatch());
            }
            delivery.user_visible_text.clear();
            Ok(delivery)
        })
        .collect();
    drop(statement);
    for delivery in deliveries? {
        transaction
            .execute(
                "UPDATE outbox_records SET payload=?1 WHERE id=?2 AND owner=?3",
                params![
                    encode(&delivery)?,
                    id(delivery.id.as_uuid()),
                    id(delivery.owner.as_uuid()),
                ],
            )
            .map_err(sql_error)?;
    }
    transaction.commit().map_err(sql_error)
}

fn migration_catalog_error() -> RepositoryError {
    RepositoryError {
        kind: RepositoryErrorKind::Corrupt,
        summary: "The SQLite migration catalog does not match this binary.",
    }
}

fn relational_payload_mismatch() -> RepositoryError {
    RepositoryError {
        kind: RepositoryErrorKind::Corrupt,
        summary: "A durable record does not match its relational identity.",
    }
}

fn verify_pragma_text(
    connection: &Connection,
    name: &'static str,
    expected: &str,
) -> Result<(), RepositoryError> {
    let value: String = connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(sql_error)?;
    if value.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Unavailable,
            summary: "SQLite did not accept a required storage pragma.",
        })
    }
}

fn verify_pragma_i64(
    connection: &Connection,
    name: &'static str,
    expected: i64,
) -> Result<(), RepositoryError> {
    let value: i64 = connection
        .query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
        .map_err(sql_error)?;
    if value == expected {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Unavailable,
            summary: "SQLite did not accept a required storage pragma.",
        })
    }
}

fn sql_error(error: rusqlite::Error) -> RepositoryError {
    let kind = match &error {
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                rusqlite::ErrorCode::ConstraintViolation
                    | rusqlite::ErrorCode::DatabaseBusy
                    | rusqlite::ErrorCode::DatabaseLocked
            ) =>
        {
            RepositoryErrorKind::Conflict
        }
        rusqlite::Error::QueryReturnedNoRows => RepositoryErrorKind::NotFound,
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                rusqlite::ErrorCode::DatabaseCorrupt
                    | rusqlite::ErrorCode::NotADatabase
                    | rusqlite::ErrorCode::SchemaChanged
            ) =>
        {
            RepositoryErrorKind::Corrupt
        }
        rusqlite::Error::SqliteFailure(code, _)
            if matches!(
                code.code,
                rusqlite::ErrorCode::CannotOpen
                    | rusqlite::ErrorCode::DiskFull
                    | rusqlite::ErrorCode::ReadOnly
            ) =>
        {
            RepositoryErrorKind::Unavailable
        }
        _ => RepositoryErrorKind::Internal,
    };
    RepositoryError {
        kind,
        summary: "The durable repository operation failed.",
    }
}

fn encode<T: Serialize>(value: &T) -> Result<String, RepositoryError> {
    let json = serde_json::to_value(value).map_err(|_| RepositoryError {
        kind: RepositoryErrorKind::Internal,
        summary: "A durable record could not be encoded.",
    })?;
    validate_durable_json(&json)?;
    serde_json::to_string(value).map_err(|_| RepositoryError {
        kind: RepositoryErrorKind::Internal,
        summary: "A durable record could not be encoded.",
    })
}

fn decode<T: DeserializeOwned>(value: String) -> Result<T, RepositoryError> {
    serde_json::from_str(&value).map_err(|_| RepositoryError {
        kind: RepositoryErrorKind::Corrupt,
        summary: "A durable record could not be decoded.",
    })
}

fn decode_owned<T: DeserializeOwned>(value: String, owner: ActorId) -> Result<T, RepositoryError> {
    let json: JsonValue = serde_json::from_str(&value).map_err(|_| RepositoryError {
        kind: RepositoryErrorKind::Corrupt,
        summary: "A durable record could not be decoded.",
    })?;
    if json.get("owner") != Some(&JsonValue::String(owner.as_uuid().to_string())) {
        return Err(relational_payload_mismatch());
    }
    serde_json::from_value(json).map_err(|_| RepositoryError {
        kind: RepositoryErrorKind::Corrupt,
        summary: "A durable record could not be decoded.",
    })
}

fn id(value: Uuid) -> Vec<u8> {
    value.as_bytes().to_vec()
}

fn actor_from_blob(value: &[u8]) -> Result<ActorId, RepositoryError> {
    uuid_from_blob(value).map(ActorId::from_uuid)
}

fn uuid_from_blob(value: &[u8]) -> Result<Uuid, RepositoryError> {
    Uuid::from_slice(value).map_err(|_| relational_payload_mismatch())
}

trait OwnedDurableRecord {
    fn durable_owner(&self) -> ActorId;
    fn durable_id(&self) -> Uuid;
}

macro_rules! impl_owned_durable_record {
    ($record:ty, $id_field:ident) => {
        impl OwnedDurableRecord for $record {
            fn durable_owner(&self) -> ActorId {
                self.owner
            }

            fn durable_id(&self) -> Uuid {
                self.$id_field.as_uuid()
            }
        }
    };
}

impl_owned_durable_record!(Goal, id);
impl_owned_durable_record!(ResourceBinding, id);
impl_owned_durable_record!(PermissionGrant, id);
impl_owned_durable_record!(ModelRouteApproval, id);
impl_owned_durable_record!(FocusSession, id);
impl_owned_durable_record!(Intervention, id);
impl_owned_durable_record!(PolicyDecision, id);
impl_owned_durable_record!(AuditRecord, id);
impl_owned_durable_record!(PendingInterventionDelivery, id);

fn validate_durable_json(value: &JsonValue) -> Result<(), RepositoryError> {
    match value {
        JsonValue::Array(values) => {
            for value in values {
                validate_durable_json(value)?;
            }
        }
        JsonValue::Object(fields) => {
            for (name, value) in fields {
                if matches!(
                    name.as_str(),
                    "observation"
                        | "observation_payload"
                        | "raw_observation"
                        | "raw_source_artifact"
                        | "working_context"
                        | "model_prompt"
                        | "model_request"
                        | "model_response"
                        | "provider_response"
                        | "chain_of_thought"
                        | "credential"
                        | "credential_value"
                        | "broker_capability"
                        | "screenshot"
                        | "screen_frame"
                        | "ui_tree"
                ) {
                    return Err(RepositoryError {
                        kind: RepositoryErrorKind::Internal,
                        summary: "A prohibited private field reached durable storage.",
                    });
                }
                validate_durable_json(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

const fn outbox_state_wire(state: OutboxState) -> &'static str {
    match state {
        OutboxState::Queued => "queued",
        OutboxState::Delivering => "delivering",
        OutboxState::AcceptedByChannel => "accepted_by_channel",
        OutboxState::DeliveryUnknown => "delivery_unknown",
        OutboxState::DeliveryFailed => "delivery_failed",
        OutboxState::Expired => "expired",
        OutboxState::Cancelled => "cancelled",
    }
}

const fn legacy_outbox_state_wire(state: OutboxState) -> &'static str {
    match state {
        OutboxState::Queued => "queued",
        OutboxState::Delivering => "delivering",
        OutboxState::AcceptedByChannel => "acceptedbychannel",
        OutboxState::DeliveryUnknown => "deliveryunknown",
        OutboxState::DeliveryFailed => "deliveryfailed",
        OutboxState::Expired => "expired",
        OutboxState::Cancelled => "cancelled",
    }
}

fn validate_delivery_update(
    current: &PendingInterventionDelivery,
    next: &PendingInterventionDelivery,
) -> Result<(), RepositoryError> {
    let transition_allowed = current.state == next.state
        || matches!(
            (current.state, next.state),
            (OutboxState::Queued, OutboxState::Delivering)
                | (OutboxState::Queued, OutboxState::Expired)
                | (OutboxState::Queued, OutboxState::Cancelled)
                | (
                    OutboxState::Delivering,
                    OutboxState::AcceptedByChannel
                        | OutboxState::DeliveryUnknown
                        | OutboxState::DeliveryFailed
                        | OutboxState::Cancelled
                )
        );
    let attempt_metadata_valid =
        if current.state == OutboxState::Queued && next.state == OutboxState::Delivering {
            next.attempt_count == current.attempt_count.saturating_add(1)
                && next.last_attempt_at.is_some()
        } else {
            next.attempt_count == current.attempt_count
                && next.last_attempt_at == current.last_attempt_at
        };
    let terminal_text_valid = if outbox_state_retains_private_text(next.state) {
        next.user_visible_text == current.user_visible_text
    } else {
        next.user_visible_text.is_empty()
    };

    let mut expected = current.clone();
    expected.state = next.state;
    expected.attempt_count = next.attempt_count;
    expected.last_attempt_at = next.last_attempt_at;
    expected
        .user_visible_text
        .clone_from(&next.user_visible_text);
    // Only the atomic queued -> delivering attempt marker may adopt the
    // freshly revalidated decision. Cancellation and expiry preserve the
    // decision that originally authorized the queued content.
    if current.state == OutboxState::Queued && next.state == OutboxState::Delivering {
        expected.policy_decision_id = next.policy_decision_id;
    }
    if transition_allowed && attempt_metadata_valid && terminal_text_valid && expected == *next {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Conflict,
            summary: "The pending delivery state transition is invalid.",
        })
    }
}

const fn outbox_state_retains_private_text(state: OutboxState) -> bool {
    matches!(state, OutboxState::Queued | OutboxState::Delivering)
}

fn sql_u64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError {
        kind: RepositoryErrorKind::Corrupt,
        summary: "A durable integer exceeds SQLite's supported range.",
    })
}

fn count_to_u64(value: usize) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| durable_count_overflow())
}

fn count_i64_to_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| durable_count_overflow())
}

fn durable_count_overflow() -> RepositoryError {
    RepositoryError {
        kind: RepositoryErrorKind::Corrupt,
        summary: "A durable record count exceeds the supported range.",
    }
}

fn load_blob_column(
    connection: &Connection,
    sql: &str,
    parameters: impl Params,
) -> Result<Vec<Vec<u8>>, RepositoryError> {
    let mut statement = connection.prepare(sql).map_err(sql_error)?;
    let rows = statement
        .query_map(parameters, |row| row.get::<_, Vec<u8>>(0))
        .map_err(sql_error)?;
    rows.map(|row| row.map_err(sql_error)).collect()
}

fn load_owner_records<T: DeserializeOwned>(
    connection: &Connection,
    table: &'static str,
    owner: ActorId,
) -> Result<Vec<T>, RepositoryError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT payload FROM {table} WHERE owner=?1 ORDER BY id"
        ))
        .map_err(sql_error)?;
    let rows = statement
        .query_map([id(owner.as_uuid())], |row| row.get::<_, String>(0))
        .map_err(sql_error)?;
    rows.map(|row| {
        row.map_err(sql_error)
            .and_then(|payload| decode_owned(payload, owner))
    })
    .collect()
}

fn load_optional_owner_record<T: DeserializeOwned>(
    connection: &Connection,
    table: &'static str,
    owner: ActorId,
) -> Result<Option<T>, RepositoryError> {
    connection
        .query_row(
            &format!("SELECT payload FROM {table} WHERE owner=?1"),
            [id(owner.as_uuid())],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_error)?
        .map(|payload| decode_owned(payload, owner))
        .transpose()
}

fn load_preferences_record(
    connection: &Connection,
    owner: ActorId,
) -> Result<Option<ExplicitPreferences>, RepositoryError> {
    let row: Option<(i64, i64, String)> = connection
        .query_row(
            "SELECT revision,schema_version,payload FROM preference_records WHERE owner=?1",
            [id(owner.as_uuid())],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sql_error)?;
    let Some((revision, schema_version, payload)) = row else {
        return Ok(None);
    };
    let value: ExplicitPreferences = decode_owned(payload, owner)?;
    if revision != sql_u64(value.revision)?
        || schema_version != i64::from(value.schema_version)
        || value.schema_version != USER_PREFERENCES_SCHEMA_V1
    {
        return Err(relational_payload_mismatch());
    }
    Ok(Some(value))
}

fn validate_owner_snapshot(
    owner: ActorId,
    snapshot: &OwnerStateSnapshot,
) -> Result<(), RepositoryError> {
    let wrong_owner = snapshot.goals.iter().any(|value| value.owner != owner)
        || snapshot
            .identity
            .as_ref()
            .is_some_and(|value| value.owner != owner)
        || snapshot
            .preferences
            .as_ref()
            .is_some_and(|value| value.owner != owner)
        || snapshot.resources.iter().any(|value| value.owner != owner)
        || snapshot.grants.iter().any(|value| value.owner != owner)
        || snapshot
            .model_routes
            .iter()
            .any(|value| value.owner != owner)
        || snapshot
            .focus_sessions
            .iter()
            .any(|value| value.owner != owner)
        || snapshot
            .interventions
            .iter()
            .any(|value| value.owner != owner)
        || snapshot
            .policy_decisions
            .iter()
            .any(|value| value.owner != owner)
        || snapshot
            .pending_deliveries
            .iter()
            .any(|value| value.owner != owner);
    if wrong_owner {
        Err(relational_payload_mismatch())
    } else {
        Ok(())
    }
}

fn check_expected_revision(
    transaction: &Transaction<'_>,
    table: &'static str,
    id_column: &'static str,
    record_id: Vec<u8>,
    expected: Option<u64>,
) -> Result<(), RepositoryError> {
    let current: Option<i64> = transaction
        .query_row(
            &format!("SELECT revision FROM {table} WHERE {id_column}=?1"),
            [record_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_error)?;
    match (current, expected) {
        (None, None) => Ok(()),
        (Some(current), Some(expected)) if current == sql_u64(expected)? => Ok(()),
        _ => Err(RepositoryError {
            kind: RepositoryErrorKind::Conflict,
            summary: "The durable record revision changed.",
        }),
    }
}

fn ensure_one_row_changed(changed: usize, summary: &'static str) -> Result<(), RepositoryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Conflict,
            summary,
        })
    }
}

fn require_owned_reference(
    connection: &Connection,
    table: &'static str,
    record_id: Vec<u8>,
    owner: ActorId,
) -> Result<(), RepositoryError> {
    let exists: bool = connection
        .query_row(
            &format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id=?1 AND owner=?2)"),
            params![record_id, id(owner.as_uuid())],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if exists {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::NotFound,
            summary: "A referenced durable record was not found for this owner.",
        })
    }
}

fn validate_operation_receipt(
    receipt: &OperationReceipt,
    expected_kind: OperationKind,
    expected_owner: ActorId,
    expected_result_id: Uuid,
) -> Result<(), RepositoryError> {
    if receipt.kind == expected_kind
        && receipt.owner == expected_owner
        && receipt.result_id == expected_result_id
    {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "An operation receipt does not match its aggregate.",
        })
    }
}

fn validate_creation_audit(
    audit: &AuditRecord,
    expected_owner: ActorId,
    expected_subject_id: Uuid,
) -> Result<(), RepositoryError> {
    if audit.owner == expected_owner && audit.subject_id == expected_subject_id {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "A creation audit record does not match its aggregate.",
        })
    }
}

fn insert_operation_receipt(
    connection: &Connection,
    receipt: &OperationReceipt,
) -> Result<(), RepositoryError> {
    connection
        .execute(
            "INSERT INTO operation_receipts(
                 owner,operation_kind,idempotency_key,request_digest,result_id,payload
             ) VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                id(receipt.owner.as_uuid()),
                receipt.kind.wire_name(),
                id(receipt.idempotency_key.as_uuid()),
                receipt.request_digest.as_slice(),
                id(receipt.result_id),
                encode(receipt)?,
            ],
        )
        .map_err(sql_error)?;
    Ok(())
}

fn insert_native_resource_cleanup(
    connection: &Connection,
    cleanup: &NativeResourceCleanup,
) -> Result<(), RepositoryError> {
    validate_opaque_resource_reference(&cleanup.opaque_reference)?;
    connection
        .execute(
            "INSERT INTO native_resource_cleanup_records(
                 resource_id,owner,created_at,payload
             ) VALUES(?1,?2,?3,?4)
             ON CONFLICT(resource_id) DO NOTHING",
            params![
                id(cleanup.resource_id.as_uuid()),
                id(cleanup.owner.as_uuid()),
                cleanup.created_at.to_string(),
                encode(cleanup)?,
            ],
        )
        .map_err(sql_error)?;
    Ok(())
}

fn insert_secret_deletion_cleanup(
    connection: &Connection,
    cleanup: &SecretDeletionCleanup,
) -> Result<(), RepositoryError> {
    validate_secret_reference(cleanup.secret_ref.as_str())?;
    let changed = connection
        .execute(
            "INSERT INTO secret_deletion_cleanup_records(
                 route_id,owner,created_at,payload
             ) VALUES(?1,?2,?3,?4)
             ON CONFLICT(route_id) DO NOTHING",
            params![
                id(cleanup.model_route_approval_id.as_uuid()),
                id(cleanup.owner.as_uuid()),
                cleanup.created_at.to_string(),
                encode(cleanup)?,
            ],
        )
        .map_err(sql_error)?;
    if changed == 0 {
        let payload: String = connection
            .query_row(
                "SELECT payload FROM secret_deletion_cleanup_records
                 WHERE route_id=?1 AND owner=?2",
                params![
                    id(cleanup.model_route_approval_id.as_uuid()),
                    id(cleanup.owner.as_uuid()),
                ],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        let existing: SecretDeletionCleanup = decode_owned(payload, cleanup.owner)?;
        if existing != *cleanup {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A secret-deletion cleanup obligation changed unexpectedly.",
            });
        }
    }
    Ok(())
}

fn validate_model_route_secret_reference(
    route: &ModelRouteApproval,
) -> Result<(), RepositoryError> {
    if route.has_approval_scoped_secret_ref() {
        Ok(())
    } else {
        Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "A model-route secret reference is not scoped to its approval.",
        })
    }
}

fn insert_audit(connection: &Connection, value: &AuditRecord) -> Result<(), RepositoryError> {
    if matches!(
        value.kind,
        AuditKind::SignificanceDecision | AuditKind::InterventionDecision
    ) && !value
        .policy_trace
        .as_ref()
        .is_some_and(stein_core::PolicyTrace::is_complete)
    {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Corrupt,
            summary: "A policy audit has incomplete trace provenance.",
        });
    }
    connection
        .execute(
            "INSERT INTO audit_records(
                 id,owner,subject_id,occurred_at,expires_at,payload
             ) VALUES(?1,?2,?3,?4,?5,?6)",
            params![
                id(value.id.as_uuid()),
                id(value.owner.as_uuid()),
                id(value.subject_id),
                value.occurred_at.to_string(),
                value.expires_at.to_string(),
                encode(value)?
            ],
        )
        .map_err(sql_error)?;
    Ok(())
}

fn insert_pending_delivery(
    connection: &Connection,
    value: &PendingInterventionDelivery,
) -> Result<(), RepositoryError> {
    if value.state != OutboxState::Queued
        || value.attempt_count != 0
        || value.last_attempt_at.is_some()
        || value.user_visible_text.chars().count() > MAX_OUTBOX_TEXT_SCALARS
        || value.created_at > value.not_before
        || value.not_before >= value.expires_at
    {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Conflict,
            summary: "The pending delivery does not satisfy the bounded queue contract.",
        });
    }
    let session_id: Vec<u8> = connection
        .query_row(
            "SELECT session_id FROM intervention_records
             WHERE id=?1 AND owner=?2",
            params![
                id(value.intervention_id.as_uuid()),
                id(value.owner.as_uuid())
            ],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    let policy_matches: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM policy_records
                 WHERE id=?1 AND owner=?2 AND session_id=?3
             )",
            params![
                id(value.policy_decision_id.as_uuid()),
                id(value.owner.as_uuid()),
                session_id.clone(),
            ],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if !policy_matches {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::NotFound,
            summary: "The pending delivery policy decision was not found.",
        });
    }
    let total_queued: i64 = connection
        .query_row(
            "SELECT count(*) FROM outbox_records WHERE owner=?1 AND state='queued'",
            [id(value.owner.as_uuid())],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    let session_queued: i64 = connection
        .query_row(
            "SELECT count(*) FROM outbox_records
             WHERE session_id=?1 AND state='queued'",
            [session_id.clone()],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if total_queued >= OUTBOX_CAPACITY_PER_OWNER || session_queued >= OUTBOX_CAPACITY_PER_SESSION {
        return Err(RepositoryError {
            kind: RepositoryErrorKind::Conflict,
            summary: "The bounded pending-delivery queue is full.",
        });
    }
    connection
        .execute(
            "INSERT INTO outbox_records(
                 id,owner,intervention_id,session_id,deduplication_key,state,expires_at,payload
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                id(value.id.as_uuid()),
                id(value.owner.as_uuid()),
                id(value.intervention_id.as_uuid()),
                session_id,
                id(value.deduplication_key),
                outbox_state_wire(value.state),
                value.expires_at.to_string(),
                encode(value)?
            ],
        )
        .map_err(sql_error)?;
    Ok(())
}

fn update_pending_delivery(
    connection: &Connection,
    value: &PendingInterventionDelivery,
) -> Result<(), RepositoryError> {
    let mut value = value.clone();
    if !outbox_state_retains_private_text(value.state) {
        value.user_visible_text.clear();
    }
    let current_payload: String = connection
        .query_row(
            "SELECT payload FROM outbox_records WHERE id=?1 AND owner=?2",
            params![id(value.id.as_uuid()), id(value.owner.as_uuid())],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_error)?
        .ok_or(RepositoryError {
            kind: RepositoryErrorKind::NotFound,
            summary: "The pending delivery was not found.",
        })?;
    let current: PendingInterventionDelivery = decode(current_payload)?;
    validate_delivery_update(&current, &value)?;
    let changed = connection
        .execute(
            "UPDATE outbox_records SET state=?1,payload=?2 WHERE id=?3 AND owner=?4",
            params![
                outbox_state_wire(value.state),
                encode(&value)?,
                id(value.id.as_uuid()),
                id(value.owner.as_uuid())
            ],
        )
        .map_err(sql_error)?;
    ensure_one_row_changed(changed, "The pending delivery changed concurrently.")
}

impl DurableRepository for SqliteRepository {
    fn health(&self) -> Result<(), RepositoryError> {
        self.call(|connection| {
            verify_pragma_text(connection, "journal_mode", "delete")?;
            verify_pragma_i64(connection, "synchronous", 3)?;
            verify_pragma_i64(connection, "foreign_keys", 1)?;
            verify_pragma_i64(connection, "secure_delete", 1)?;
            verify_pragma_i64(connection, "temp_store", 2)?;
            verify_pragma_i64(connection, "busy_timeout", BUSY_TIMEOUT_MILLISECONDS)?;
            if schema_version(connection)? != SCHEMA_VERSION {
                return Err(RepositoryError {
                    kind: RepositoryErrorKind::Unavailable,
                    summary: "The SQLite schema version changed while CORE was running.",
                });
            }
            verify_migration_catalog(connection, SCHEMA_VERSION)?;
            verify_database_integrity(connection)?;
            verify_logical_integrity(connection)
        })
    }

    fn load_owner_state(&self, owner: ActorId) -> Result<OwnerStateSnapshot, RepositoryError> {
        self.call(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(sql_error)?;
            let mut snapshot = OwnerStateSnapshot {
                current_device: transaction
                    .query_row(
                        "SELECT payload FROM device_records WHERE owner=?1",
                        [id(owner.as_uuid())],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_error)?
                    .map(|payload| decode_owned(payload, owner))
                    .transpose()?,
                goals: load_owner_records(&transaction, "goals_records", owner)?,
                identity: load_optional_owner_record(&transaction, "identity_records", owner)?,
                preferences: load_preferences_record(&transaction, owner)?,
                resources: load_owner_records(&transaction, "resource_records", owner)?,
                grants: load_owner_records(&transaction, "permission_records", owner)?,
                model_routes: load_owner_records(&transaction, "route_records", owner)?,
                focus_sessions: load_owner_records(&transaction, "focus_records", owner)?,
                interventions: load_owner_records(&transaction, "intervention_records", owner)?,
                policy_decisions: load_owner_records(&transaction, "policy_records", owner)?,
                pending_deliveries: load_owner_records(&transaction, "outbox_records", owner)?,
            };
            validate_owner_snapshot(owner, &snapshot)?;
            snapshot.goals.sort_by_key(|value| value.id);
            snapshot.resources.sort_by_key(|value| value.id);
            snapshot.grants.sort_by_key(|value| value.id);
            snapshot.model_routes.sort_by_key(|value| value.id);
            snapshot.focus_sessions.sort_by_key(|value| value.id);
            snapshot.interventions.sort_by_key(|value| value.id);
            snapshot.policy_decisions.sort_by_key(|value| value.id);
            snapshot.pending_deliveries.sort_by_key(|value| value.id);
            transaction.commit().map_err(sql_error)?;
            Ok(snapshot)
        })
    }

    fn load_or_issue_device(
        &self,
        owner: ActorId,
        candidate: DeviceId,
        issued_at: OffsetDateTime,
    ) -> Result<DeviceRegistration, RepositoryError> {
        self.call(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let existing: Option<String> = transaction
                .query_row(
                    "SELECT payload FROM device_records WHERE owner=?1",
                    [id(owner.as_uuid())],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            let value = if let Some(payload) = existing {
                decode_owned(payload, owner)?
            } else {
                let value = DeviceRegistration {
                    owner,
                    device_id: candidate,
                    issued_at,
                };
                transaction
                    .execute(
                        "INSERT INTO device_records(owner,device_id,issued_at,payload)
                         VALUES(?1,?2,?3,?4)",
                        params![
                            id(owner.as_uuid()),
                            id(candidate.as_uuid()),
                            issued_at.to_string(),
                            encode(&value)?,
                        ],
                    )
                    .map_err(sql_error)?;
                value
            };
            transaction.commit().map_err(sql_error)?;
            Ok(value)
        })
    }

    fn load_goals(&self, owner: ActorId) -> Result<Vec<Goal>, RepositoryError> {
        self.call(move |connection| load_owner_records(connection, "goals_records", owner))
    }

    fn find_goal_create(
        &self,
        owner: ActorId,
        key: IdempotencyKey,
    ) -> Result<Option<(GoalCreateReceipt, Goal)>, RepositoryError> {
        self.call(move |connection| {
            let row: Option<(String, Vec<u8>)> = connection
                .query_row(
                    "SELECT payload, goal_id FROM goals_create_receipts
                     WHERE actor=?1 AND idempotency_key=?2",
                    params![id(owner.as_uuid()), id(key.as_uuid())],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sql_error)?;
            let Some((receipt, goal_id)) = row else {
                return Ok(None);
            };
            let goal: String = connection
                .query_row(
                    "SELECT payload FROM goals_records WHERE id=?1",
                    [goal_id],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;
            Ok(Some((decode(receipt)?, decode(goal)?)))
        })
    }

    fn create_goal(&self, goal: &Goal, receipt: &GoalCreateReceipt) -> Result<(), RepositoryError> {
        if receipt.actor != goal.owner
            || receipt.goal_id != goal.id
            || receipt.title != goal.title
            || receipt.success_statement != goal.success_statement
            || receipt.deadline != goal.deadline
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The goal idempotency receipt does not match the durable goal.",
            });
        }
        let goal = goal.clone();
        let receipt = receipt.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            transaction
                .execute(
                    "INSERT INTO goals_records(id, owner, revision, payload) VALUES(?1,?2,?3,?4)",
                    params![
                        id(goal.id.as_uuid()),
                        id(goal.owner.as_uuid()),
                        sql_u64(goal.revision.get())?,
                        encode(&goal)?
                    ],
                )
                .map_err(sql_error)?;
            transaction
                .execute(
                    "INSERT INTO goals_create_receipts(actor,idempotency_key,goal_id,payload)
                     VALUES(?1,?2,?3,?4)",
                    params![
                        id(receipt.actor.as_uuid()),
                        id(receipt.idempotency_key.as_uuid()),
                        id(receipt.goal_id.as_uuid()),
                        encode(&receipt)?
                    ],
                )
                .map_err(sql_error)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn find_operation_receipt(
        &self,
        owner: ActorId,
        kind: OperationKind,
        key: IdempotencyKey,
    ) -> Result<Option<OperationReceipt>, RepositoryError> {
        self.call(move |connection| {
            let row: Option<OperationReceiptRow> = connection
                .query_row(
                    "SELECT operation_kind,idempotency_key,request_digest,result_id,payload
                     FROM operation_receipts
                     WHERE owner=?1 AND operation_kind=?2 AND idempotency_key=?3",
                    params![id(owner.as_uuid()), kind.wire_name(), id(key.as_uuid()),],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()
                .map_err(sql_error)?;
            let Some((stored_kind, stored_key, stored_digest, stored_result, payload)) = row else {
                return Ok(None);
            };
            let receipt: OperationReceipt = decode_owned(payload, owner)?;
            if OperationKind::from_wire_name(&stored_kind) != Some(kind)
                || stored_key != id(key.as_uuid())
                || stored_digest.as_slice() != receipt.request_digest
                || stored_result != id(receipt.result_id)
                || receipt.kind != kind
                || receipt.idempotency_key != key
            {
                return Err(relational_payload_mismatch());
            }
            Ok(Some(receipt))
        })
    }

    fn update_goal(&self, goal: &Goal, expected_revision: u64) -> Result<(), RepositoryError> {
        let goal = goal.clone();
        self.call(move |connection| {
            let changed = connection
                .execute(
                    "UPDATE goals_records SET revision=?1,payload=?2
                     WHERE id=?3 AND owner=?4 AND revision=?5",
                    params![
                        sql_u64(goal.revision.get())?,
                        encode(&goal)?,
                        id(goal.id.as_uuid()),
                        id(goal.owner.as_uuid()),
                        sql_u64(expected_revision)?
                    ],
                )
                .map_err(sql_error)?;
            if changed == 1 {
                Ok(())
            } else {
                Err(RepositoryError {
                    kind: RepositoryErrorKind::Conflict,
                    summary: "The durable goal revision changed.",
                })
            }
        })
    }

    fn delete_goal_cascade(
        &self,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
    ) -> Result<DeletionSummary, RepositoryError> {
        self.delete_goal_with_tombstone(
            owner,
            goal_id,
            expected_revision,
            OffsetDateTime::now_utc(),
        )
        .map(|result| result.tombstone.summary)
    }

    fn delete_goal_with_tombstone(
        &self,
        owner: ActorId,
        goal_id: GoalId,
        expected_revision: u64,
        deleted_at: OffsetDateTime,
    ) -> Result<GoalDeletionResult, RepositoryError> {
        self.call(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let goal_blob = id(goal_id.as_uuid());
            let owner_blob = id(owner.as_uuid());
            let existing_tombstone: Option<String> = transaction
                .query_row(
                    "SELECT payload FROM goal_deletion_tombstones
                     WHERE goal_id=?1 AND owner=?2",
                    params![goal_blob.clone(), owner_blob.clone()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            if let Some(payload) = existing_tombstone {
                let tombstone: GoalDeletionTombstone = decode_owned(payload, owner)?;
                if tombstone.deleted_revision != expected_revision {
                    return Err(RepositoryError {
                        kind: RepositoryErrorKind::Conflict,
                        summary: "The deleted goal revision does not match this retry.",
                    });
                }
                transaction.commit().map_err(sql_error)?;
                return Ok(GoalDeletionResult {
                    tombstone,
                    already_deleted: true,
                });
            }
            let current: Option<i64> = transaction
                .query_row(
                    "SELECT revision FROM goals_records WHERE id=?1 AND owner=?2",
                    params![goal_blob.clone(), owner_blob.clone()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            if current != Some(sql_u64(expected_revision)?) {
                return Err(RepositoryError {
                    kind: RepositoryErrorKind::Conflict,
                    summary: "The durable goal revision changed.",
                });
            }
            let session_ids = load_blob_column(
                &transaction,
                "SELECT id FROM focus_records WHERE owner=?1 AND goal_id=?2",
                params![owner_blob.clone(), goal_blob.clone()],
            )?;
            let intervention_ids = load_blob_column(
                &transaction,
                "SELECT id FROM intervention_records WHERE owner=?1 AND goal_id=?2",
                params![owner_blob.clone(), goal_blob.clone()],
            )?;
            let grant_ids = load_blob_column(
                &transaction,
                "SELECT id FROM permission_records WHERE owner=?1 AND goal_id=?2",
                params![owner_blob.clone(), goal_blob.clone()],
            )?;
            let policy_ids = load_blob_column(
                &transaction,
                "SELECT p.id FROM policy_records p
                 JOIN focus_records f ON f.id=p.session_id
                 WHERE f.owner=?1 AND f.goal_id=?2",
                params![owner_blob.clone(), goal_blob.clone()],
            )?;
            let policy_candidate_ids = {
                let mut statement = transaction
                    .prepare(
                        "SELECT p.payload FROM policy_records p
                         JOIN focus_records f ON f.id=p.session_id
                         WHERE f.owner=?1 AND f.goal_id=?2",
                    )
                    .map_err(sql_error)?;
                let rows = statement
                    .query_map(params![owner_blob.clone(), goal_blob.clone()], |row| {
                        row.get::<_, String>(0)
                    })
                    .map_err(sql_error)?;
                let mut candidate_ids = BTreeSet::new();
                for payload in rows {
                    let decision: PolicyDecision =
                        decode_owned(payload.map_err(sql_error)?, owner)?;
                    candidate_ids.insert(id(decision.candidate_id.as_uuid()));
                }
                candidate_ids
            };
            let outbox_entries: i64 = transaction
                .query_row(
                    "SELECT count(*) FROM outbox_records o
                     JOIN intervention_records i ON i.id=o.intervention_id
                     WHERE i.owner=?1 AND i.goal_id=?2",
                    params![owner_blob.clone(), goal_blob.clone()],
                    |row| row.get(0),
                )
                .map_err(sql_error)?;

            let mut resource_ids: BTreeSet<Vec<u8>> = load_blob_column(
                &transaction,
                "SELECT DISTINCT resource_id FROM permission_records
                 WHERE owner=?1 AND goal_id=?2 AND resource_id IS NOT NULL",
                params![owner_blob.clone(), goal_blob.clone()],
            )?
            .into_iter()
            .collect();
            let mut session_statement = transaction
                .prepare("SELECT payload FROM focus_records WHERE owner=?1 AND goal_id=?2")
                .map_err(sql_error)?;
            let session_rows = session_statement
                .query_map(params![owner_blob.clone(), goal_blob.clone()], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(sql_error)?;
            for payload in session_rows {
                let session: FocusSession = decode(payload.map_err(sql_error)?)?;
                if session.owner != owner || session.goal_id != goal_id {
                    return Err(relational_payload_mismatch());
                }
                resource_ids.extend(
                    session
                        .selected_resource_ids
                        .iter()
                        .map(|resource| id(resource.as_uuid())),
                );
            }
            drop(session_statement);

            let deleted_goal = transaction
                .execute(
                    "DELETE FROM goals_records WHERE id=?1 AND owner=?2",
                    params![goal_blob.clone(), owner_blob.clone()],
                )
                .map_err(sql_error)?;
            if deleted_goal != 1 {
                return Err(relational_payload_mismatch());
            }

            let mut deleted_resources = 0_u64;
            let mut deleted_resource_ids = BTreeSet::new();
            for resource_id in &resource_ids {
                let changed = transaction
                    .execute(
                        "DELETE FROM resource_records
                         WHERE id=?1 AND owner=?2
                           AND NOT EXISTS(
                               SELECT 1 FROM permission_records WHERE resource_id=?1
                           )",
                        params![resource_id, owner_blob.clone()],
                    )
                    .map_err(sql_error)?;
                deleted_resources = deleted_resources
                    .checked_add(count_to_u64(changed)?)
                    .ok_or_else(durable_count_overflow)?;
                if changed == 1 {
                    deleted_resource_ids.insert(resource_id.clone());
                }
            }

            let mut audit_subjects = BTreeSet::from([goal_blob.clone()]);
            audit_subjects.extend(session_ids.iter().cloned());
            audit_subjects.extend(intervention_ids.iter().cloned());
            audit_subjects.extend(grant_ids.iter().cloned());
            audit_subjects.extend(policy_ids);
            audit_subjects.extend(policy_candidate_ids);
            audit_subjects.extend(deleted_resource_ids);
            let mut deleted_audit = 0_u64;
            for subject_id in audit_subjects {
                let changed = transaction
                    .execute(
                        "DELETE FROM audit_records WHERE owner=?1 AND subject_id=?2",
                        params![owner_blob.clone(), subject_id],
                    )
                    .map_err(sql_error)?;
                deleted_audit = deleted_audit
                    .checked_add(count_to_u64(changed)?)
                    .ok_or_else(durable_count_overflow)?;
            }
            for result_id in session_ids.iter().chain(&grant_ids) {
                transaction
                    .execute(
                        "DELETE FROM operation_receipts WHERE owner=?1 AND result_id=?2",
                        params![owner_blob.clone(), result_id],
                    )
                    .map_err(sql_error)?;
            }
            let summary = DeletionSummary {
                goals: 1,
                focus_sessions: count_to_u64(session_ids.len())?,
                grants: count_to_u64(grant_ids.len())?,
                interventions: count_to_u64(intervention_ids.len())?,
                outbox_entries: count_i64_to_u64(outbox_entries)?,
                audit_records: deleted_audit,
                resource_bindings: deleted_resources,
            };
            let tombstone = GoalDeletionTombstone {
                owner,
                goal_id,
                deleted_revision: expected_revision,
                deleted_at,
                summary,
            };
            transaction
                .execute(
                    "INSERT INTO goal_deletion_tombstones(
                         goal_id,owner,deleted_revision,deleted_at,payload
                     ) VALUES(?1,?2,?3,?4,?5)",
                    params![
                        goal_blob,
                        owner_blob,
                        sql_u64(expected_revision)?,
                        deleted_at.to_string(),
                        encode(&tombstone)?,
                    ],
                )
                .map_err(sql_error)?;
            transaction.commit().map_err(sql_error)?;
            Ok(GoalDeletionResult {
                tombstone,
                already_deleted: false,
            })
        })
    }

    fn load_identity(&self, owner: ActorId) -> Result<Option<SteinIdentity>, RepositoryError> {
        self.call(move |connection| {
            connection
                .query_row(
                    "SELECT payload FROM identity_records WHERE owner=?1",
                    [id(owner.as_uuid())],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(sql_error)?
                .map(|payload| decode_owned(payload, owner))
                .transpose()
        })
    }

    fn save_identity(
        &self,
        value: &SteinIdentity,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        if !value.has_shipped_v1_invariants() {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "Only the shipped STEIN identity may be persisted.",
            });
        }
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            check_expected_revision(
                &transaction,
                "identity_records",
                "owner",
                id(value.owner.as_uuid()),
                expected_revision,
            )?;
            transaction
                .execute(
                    "INSERT INTO identity_records(owner,revision,schema_version,payload)
                     VALUES(?1,?2,?3,?4)
                     ON CONFLICT(owner) DO UPDATE SET
                         revision=excluded.revision,
                         schema_version=excluded.schema_version,
                         payload=excluded.payload",
                    params![
                        id(value.owner.as_uuid()),
                        sql_u64(value.revision)?,
                        i64::from(value.schema_version),
                        encode(&value)?
                    ],
                )
                .map_err(sql_error)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn load_preferences(
        &self,
        owner: ActorId,
    ) -> Result<Option<ExplicitPreferences>, RepositoryError> {
        self.call(move |connection| load_preferences_record(connection, owner))
    }

    fn save_preferences(
        &self,
        value: &ExplicitPreferences,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        if value.schema_version != USER_PREFERENCES_SCHEMA_V1 {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The explicit-preferences schema version is not supported.",
            });
        }
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            check_expected_revision(
                &transaction,
                "preference_records",
                "owner",
                id(value.owner.as_uuid()),
                expected_revision,
            )?;
            transaction
                .execute(
                    "INSERT INTO preference_records(owner,revision,schema_version,payload)
                     VALUES(?1,?2,?3,?4)
                     ON CONFLICT(owner) DO UPDATE SET
                         revision=excluded.revision,
                         schema_version=excluded.schema_version,
                         payload=excluded.payload",
                    params![
                        id(value.owner.as_uuid()),
                        sql_u64(value.revision)?,
                        i64::from(value.schema_version),
                        encode(&value)?
                    ],
                )
                .map_err(sql_error)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn load_resources(&self, owner: ActorId) -> Result<Vec<ResourceBinding>, RepositoryError> {
        self.call(move |connection| load_owner_records(connection, "resource_records", owner))
    }

    fn save_resource(&self, value: &ResourceBinding) -> Result<(), RepositoryError> {
        let value = value.clone();
        self.call(move |connection| {
            connection
                .execute(
                    "INSERT INTO resource_records(id,owner,revision,payload) VALUES(?1,?2,?3,?4)",
                    params![
                        id(value.id.as_uuid()),
                        id(value.owner.as_uuid()),
                        sql_u64(value.revision)?,
                        encode(&value)?
                    ],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    fn remove_resource(
        &self,
        owner: ActorId,
        resource_id: ResourceId,
        expected_revision: u64,
        deleted_at: OffsetDateTime,
    ) -> Result<SelectedResourceDeletionResult, RepositoryError> {
        self.call(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let resource_blob = id(resource_id.as_uuid());
            let owner_blob = id(owner.as_uuid());
            let existing_tombstone: Option<String> = transaction
                .query_row(
                    "SELECT payload FROM resource_deletion_tombstones
                     WHERE resource_id=?1 AND owner=?2",
                    params![resource_blob.clone(), owner_blob.clone()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            if let Some(payload) = existing_tombstone {
                let tombstone: SelectedResourceDeletionTombstone = decode_owned(payload, owner)?;
                if tombstone.deleted_revision != expected_revision {
                    return Err(RepositoryError {
                        kind: RepositoryErrorKind::Conflict,
                        summary: "The selected-resource revision changed.",
                    });
                }
                transaction.commit().map_err(sql_error)?;
                return Ok(SelectedResourceDeletionResult {
                    tombstone,
                    already_removed: true,
                });
            }
            let payload: Option<String> = transaction
                .query_row(
                    "SELECT payload FROM resource_records WHERE id=?1 AND owner=?2",
                    params![resource_blob.clone(), owner_blob.clone()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            let Some(payload) = payload else {
                return Err(RepositoryError {
                    kind: RepositoryErrorKind::NotFound,
                    summary: "The selected resource was not found.",
                });
            };
            let resource: ResourceBinding = decode_owned(payload, owner)?;
            if resource.revision != expected_revision {
                return Err(RepositoryError {
                    kind: RepositoryErrorKind::Conflict,
                    summary: "The selected-resource revision changed.",
                });
            }
            let grants: Vec<PermissionGrant> =
                load_owner_records(&transaction, "permission_records", owner)?;
            let sessions: Vec<FocusSession> =
                load_owner_records(&transaction, "focus_records", owner)?;
            if grants.iter().any(|grant| {
                grant.selected_resource_id == Some(resource_id)
                    && grant.state == stein_core::GrantState::Active
            }) || sessions.iter().any(|session| {
                session.selected_resource_ids.contains(&resource_id) && session.is_working()
            }) {
                return Err(RepositoryError {
                    kind: RepositoryErrorKind::Conflict,
                    summary: "The selected resource is still used by active authority.",
                });
            }
            let tombstone = SelectedResourceDeletionTombstone {
                owner,
                resource_id,
                deleted_revision: expected_revision,
                deleted_at,
            };
            let cleanup = NativeResourceCleanup {
                owner,
                resource_id,
                opaque_reference: resource.opaque_reference,
                created_at: deleted_at,
            };
            transaction
                .execute(
                    "DELETE FROM resource_records WHERE id=?1 AND owner=?2",
                    params![resource_blob.clone(), owner_blob.clone()],
                )
                .map_err(sql_error)?;
            transaction
                .execute(
                    "INSERT INTO resource_deletion_tombstones(
                         resource_id,owner,deleted_revision,deleted_at,payload
                     ) VALUES(?1,?2,?3,?4,?5)",
                    params![
                        resource_blob,
                        owner_blob,
                        sql_u64(expected_revision)?,
                        deleted_at.to_string(),
                        encode(&tombstone)?,
                    ],
                )
                .map_err(sql_error)?;
            insert_native_resource_cleanup(&transaction, &cleanup)?;
            transaction.commit().map_err(sql_error)?;
            Ok(SelectedResourceDeletionResult {
                tombstone,
                already_removed: false,
            })
        })
    }

    fn find_resource_deletion(
        &self,
        owner: ActorId,
        resource_id: ResourceId,
    ) -> Result<Option<SelectedResourceDeletionTombstone>, RepositoryError> {
        self.call(move |connection| {
            connection
                .query_row(
                    "SELECT payload FROM resource_deletion_tombstones
                     WHERE resource_id=?1 AND owner=?2",
                    params![id(resource_id.as_uuid()), id(owner.as_uuid())],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(sql_error)?
                .map(|payload| decode_owned(payload, owner))
                .transpose()
        })
    }

    fn save_native_resource_cleanup(
        &self,
        cleanup: &NativeResourceCleanup,
    ) -> Result<(), RepositoryError> {
        let cleanup = cleanup.clone();
        self.call(move |connection| insert_native_resource_cleanup(connection, &cleanup))
    }

    fn load_native_resource_cleanups(
        &self,
        owner: ActorId,
    ) -> Result<Vec<NativeResourceCleanup>, RepositoryError> {
        self.call(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT payload FROM native_resource_cleanup_records
                     WHERE owner=?1 ORDER BY resource_id",
                )
                .map_err(sql_error)?;
            let rows = statement
                .query_map([id(owner.as_uuid())], |row| row.get::<_, String>(0))
                .map_err(sql_error)?;
            rows.map(|row| {
                row.map_err(sql_error)
                    .and_then(|payload| decode_owned(payload, owner))
            })
            .collect()
        })
    }

    fn complete_native_resource_cleanup(
        &self,
        owner: ActorId,
        resource_id: ResourceId,
    ) -> Result<(), RepositoryError> {
        self.call(move |connection| {
            connection
                .execute(
                    "DELETE FROM native_resource_cleanup_records
                     WHERE resource_id=?1 AND owner=?2",
                    params![id(resource_id.as_uuid()), id(owner.as_uuid())],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    fn save_revoked_model_route_with_cleanup(
        &self,
        value: &ModelRouteApproval,
        expected_revision: u64,
        cleanup: &SecretDeletionCleanup,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError> {
        validate_model_route_secret_reference(value)?;
        if value.revoked_at.is_none()
            || value.owner != cleanup.owner
            || value.id != cleanup.model_route_approval_id
            || value.secret_ref != cleanup.secret_ref
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A secret-deletion cleanup obligation does not match its revoked route.",
            });
        }
        if audit.owner != value.owner
            || audit.kind != AuditKind::ModelRouteRevoked
            || audit.subject_id != value.id.as_uuid()
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A model-route revocation audit does not match its aggregate.",
            });
        }
        let value = value.clone();
        let cleanup = cleanup.clone();
        let audit = audit.clone();
        self.call(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            check_expected_revision(
                &transaction,
                "route_records",
                "id",
                id(value.id.as_uuid()),
                Some(expected_revision),
            )?;
            let changed = transaction
                .execute(
                    "UPDATE route_records SET revision=?1,payload=?2
                     WHERE id=?3 AND owner=?4",
                    params![
                        sql_u64(value.revision)?,
                        encode(&value)?,
                        id(value.id.as_uuid()),
                        id(value.owner.as_uuid()),
                    ],
                )
                .map_err(sql_error)?;
            ensure_one_row_changed(changed, "The model route belongs to another owner.")?;
            insert_secret_deletion_cleanup(&transaction, &cleanup)?;
            insert_audit(&transaction, &audit)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn load_secret_deletion_cleanups(
        &self,
        owner: ActorId,
    ) -> Result<Vec<SecretDeletionCleanup>, RepositoryError> {
        self.call(move |connection| {
            let mut statement = connection
                .prepare(
                    "SELECT payload FROM secret_deletion_cleanup_records
                     WHERE owner=?1 ORDER BY route_id",
                )
                .map_err(sql_error)?;
            let rows = statement
                .query_map([id(owner.as_uuid())], |row| row.get::<_, String>(0))
                .map_err(sql_error)?;
            rows.map(|row| {
                row.map_err(sql_error)
                    .and_then(|payload| decode_owned(payload, owner))
            })
            .collect()
        })
    }

    fn complete_secret_deletion_cleanup(
        &self,
        owner: ActorId,
        model_route_approval_id: stein_core::ModelRouteApprovalId,
    ) -> Result<(), RepositoryError> {
        self.call(move |connection| {
            connection
                .execute(
                    "DELETE FROM secret_deletion_cleanup_records
                     WHERE route_id=?1 AND owner=?2",
                    params![id(model_route_approval_id.as_uuid()), id(owner.as_uuid())],
                )
                .map_err(sql_error)?;
            Ok(())
        })
    }

    fn load_grants(&self, owner: ActorId) -> Result<Vec<PermissionGrant>, RepositoryError> {
        self.call(move |connection| load_owner_records(connection, "permission_records", owner))
    }

    fn save_grant(
        &self,
        value: &PermissionGrant,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            require_owned_reference(
                &transaction,
                "goals_records",
                id(value.goal_id.as_uuid()),
                value.owner,
            )?;
            if let Some(resource_id) = value.selected_resource_id {
                require_owned_reference(
                    &transaction,
                    "resource_records",
                    id(resource_id.as_uuid()),
                    value.owner,
                )?;
            }
            if let Some(session_id) = value.focus_session_id {
                require_owned_reference(
                    &transaction,
                    "focus_records",
                    id(session_id.as_uuid()),
                    value.owner,
                )?;
            }
            check_expected_revision(
                &transaction,
                "permission_records",
                "id",
                id(value.id.as_uuid()),
                expected_revision,
            )?;
            let changed = transaction
                .execute(
                    "INSERT INTO permission_records(
                     id,owner,goal_id,revision,session_id,resource_id,payload
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(id) DO UPDATE SET
                     goal_id=excluded.goal_id,
                     revision=excluded.revision,
                     session_id=excluded.session_id,
                     resource_id=excluded.resource_id,
                     payload=excluded.payload
                 WHERE permission_records.owner=excluded.owner",
                    params![
                        id(value.id.as_uuid()),
                        id(value.owner.as_uuid()),
                        id(value.goal_id.as_uuid()),
                        sql_u64(value.revision)?,
                        value
                            .focus_session_id
                            .map(|id_value| id(id_value.as_uuid())),
                        value
                            .selected_resource_id
                            .map(|id_value| id(id_value.as_uuid())),
                        encode(&value)?
                    ],
                )
                .map_err(sql_error)?;
            ensure_one_row_changed(changed, "The permission grant belongs to another owner.")?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn save_permission_grant_revocation(
        &self,
        value: &PermissionGrantRevocationWrite,
    ) -> Result<(), RepositoryError> {
        value.validate()?;
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let current_payload: Option<String> = transaction
                .query_row(
                    "SELECT payload FROM permission_records WHERE id=?1 AND owner=?2",
                    params![
                        id(value.grant.id.as_uuid()),
                        id(value.grant.owner.as_uuid())
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            let current_payload = current_payload.ok_or(RepositoryError {
                kind: RepositoryErrorKind::NotFound,
                summary: "The durable permission grant was not found.",
            })?;
            let current: PermissionGrant = decode_owned(current_payload, value.grant.owner)?;
            value.validate_against(&current)?;
            let changed = transaction
                .execute(
                    "UPDATE permission_records SET revision=?1,payload=?2
                     WHERE id=?3 AND owner=?4 AND revision=?5",
                    params![
                        sql_u64(value.grant.revision)?,
                        encode(&value.grant)?,
                        id(value.grant.id.as_uuid()),
                        id(value.grant.owner.as_uuid()),
                        sql_u64(value.expected_revision)?
                    ],
                )
                .map_err(sql_error)?;
            ensure_one_row_changed(changed, "The permission-grant revision changed.")?;
            insert_audit(&transaction, &value.audit)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn create_grant(
        &self,
        value: &PermissionGrant,
        receipt: &OperationReceipt,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError> {
        validate_operation_receipt(
            receipt,
            OperationKind::GrantSessionPermission,
            value.owner,
            value.id.as_uuid(),
        )?;
        validate_creation_audit(audit, value.owner, value.id.as_uuid())?;
        let value = value.clone();
        let receipt = receipt.clone();
        let audit = audit.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            require_owned_reference(
                &transaction,
                "goals_records",
                id(value.goal_id.as_uuid()),
                value.owner,
            )?;
            if let Some(resource_id) = value.selected_resource_id {
                require_owned_reference(
                    &transaction,
                    "resource_records",
                    id(resource_id.as_uuid()),
                    value.owner,
                )?;
            }
            if let Some(session_id) = value.focus_session_id {
                require_owned_reference(
                    &transaction,
                    "focus_records",
                    id(session_id.as_uuid()),
                    value.owner,
                )?;
            }
            transaction
                .execute(
                    "INSERT INTO permission_records(
                         id,owner,goal_id,revision,session_id,resource_id,payload
                     ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        id(value.id.as_uuid()),
                        id(value.owner.as_uuid()),
                        id(value.goal_id.as_uuid()),
                        sql_u64(value.revision)?,
                        value
                            .focus_session_id
                            .map(|id_value| id(id_value.as_uuid())),
                        value
                            .selected_resource_id
                            .map(|id_value| id(id_value.as_uuid())),
                        encode(&value)?,
                    ],
                )
                .map_err(sql_error)?;
            insert_operation_receipt(&transaction, &receipt)?;
            insert_audit(&transaction, &audit)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn load_model_routes(
        &self,
        owner: ActorId,
    ) -> Result<Vec<ModelRouteApproval>, RepositoryError> {
        self.call(move |connection| load_owner_records(connection, "route_records", owner))
    }

    fn save_model_route(
        &self,
        value: &ModelRouteApproval,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        validate_model_route_secret_reference(value)?;
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            check_expected_revision(
                &transaction,
                "route_records",
                "id",
                id(value.id.as_uuid()),
                expected_revision,
            )?;
            let changed = transaction
                .execute(
                    "INSERT INTO route_records(id,owner,revision,payload) VALUES(?1,?2,?3,?4)
                 ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,payload=excluded.payload
                 WHERE route_records.owner=excluded.owner",
                    params![
                        id(value.id.as_uuid()),
                        id(value.owner.as_uuid()),
                        sql_u64(value.revision)?,
                        encode(&value)?
                    ],
                )
                .map_err(sql_error)?;
            ensure_one_row_changed(changed, "The model route belongs to another owner.")?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn create_model_route(
        &self,
        value: &ModelRouteApproval,
        receipt: &OperationReceipt,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError> {
        validate_model_route_secret_reference(value)?;
        validate_operation_receipt(
            receipt,
            OperationKind::ApproveModelRoute,
            value.owner,
            value.id.as_uuid(),
        )?;
        validate_creation_audit(audit, value.owner, value.id.as_uuid())?;
        let value = value.clone();
        let receipt = receipt.clone();
        let audit = audit.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            transaction
                .execute(
                    "INSERT INTO route_records(id,owner,revision,payload)
                     VALUES(?1,?2,?3,?4)",
                    params![
                        id(value.id.as_uuid()),
                        id(value.owner.as_uuid()),
                        sql_u64(value.revision)?,
                        encode(&value)?,
                    ],
                )
                .map_err(sql_error)?;
            insert_operation_receipt(&transaction, &receipt)?;
            insert_audit(&transaction, &audit)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn load_focus_sessions(&self, owner: ActorId) -> Result<Vec<FocusSession>, RepositoryError> {
        self.call(move |connection| load_owner_records(connection, "focus_records", owner))
    }

    fn find_focus_session(
        &self,
        session_id: stein_core::FocusSessionId,
    ) -> Result<Option<FocusSession>, RepositoryError> {
        self.call(move |connection| {
            let row: Option<(String, Vec<u8>)> = connection
                .query_row(
                    "SELECT payload,owner FROM focus_records WHERE id=?1",
                    [id(session_id.as_uuid())],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sql_error)?;
            let Some((payload, owner)) = row else {
                return Ok(None);
            };
            let value: FocusSession = decode_owned(payload, actor_from_blob(&owner)?)?;
            if value.id != session_id {
                return Err(relational_payload_mismatch());
            }
            Ok(Some(value))
        })
    }

    fn bind_grants_and_create_focus_session(
        &self,
        session: &FocusSession,
        grants: &[(PermissionGrant, u64)],
        receipt: &OperationReceipt,
        audit: &AuditRecord,
    ) -> Result<(), RepositoryError> {
        validate_operation_receipt(
            receipt,
            OperationKind::StartFocusSession,
            session.owner,
            session.id.as_uuid(),
        )?;
        validate_creation_audit(audit, session.owner, session.id.as_uuid())?;
        let grant_ids: BTreeSet<_> = grants.iter().map(|(grant, _)| grant.id).collect();
        let resource_ids: BTreeSet<_> = grants
            .iter()
            .filter_map(|(grant, _)| grant.selected_resource_id)
            .collect();
        if session.permission_grant_ids != grant_ids
            || session.selected_resource_ids != resource_ids
            || grants.iter().any(|(grant, expected_revision)| {
                grant.owner != session.owner
                    || grant.goal_id != session.goal_id
                    || grant.focus_session_id != Some(session.id)
                    || grant.revision != expected_revision.saturating_add(1)
            })
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Conflict,
                summary: "The focus session does not match its bound grants.",
            });
        }
        let session = session.clone();
        let grants = grants.to_vec();
        let receipt = receipt.clone();
        let audit = audit.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            require_owned_reference(
                &transaction,
                "goals_records",
                id(session.goal_id.as_uuid()),
                session.owner,
            )?;
            for (grant, expected_revision) in &grants {
                if let Some(resource_id) = grant.selected_resource_id {
                    require_owned_reference(
                        &transaction,
                        "resource_records",
                        id(resource_id.as_uuid()),
                        session.owner,
                    )?;
                }
                check_expected_revision(
                    &transaction,
                    "permission_records",
                    "id",
                    id(grant.id.as_uuid()),
                    Some(*expected_revision),
                )?;
                let changed = transaction
                    .execute(
                        "UPDATE permission_records
                         SET goal_id=?1,revision=?2,session_id=?3,resource_id=?4,payload=?5
                         WHERE id=?6 AND owner=?7 AND revision=?8",
                        params![
                            id(grant.goal_id.as_uuid()),
                            sql_u64(grant.revision)?,
                            grant.focus_session_id.map(|value| id(value.as_uuid())),
                            grant.selected_resource_id.map(|value| id(value.as_uuid())),
                            encode(grant)?,
                            id(grant.id.as_uuid()),
                            id(session.owner.as_uuid()),
                            sql_u64(*expected_revision)?
                        ],
                    )
                    .map_err(sql_error)?;
                if changed != 1 {
                    return Err(RepositoryError {
                        kind: RepositoryErrorKind::Conflict,
                        summary: "A focus-session permission revision changed.",
                    });
                }
            }
            transaction
                .execute(
                    "INSERT INTO focus_records(id,owner,goal_id,revision,payload)
                     VALUES(?1,?2,?3,?4,?5)",
                    params![
                        id(session.id.as_uuid()),
                        id(session.owner.as_uuid()),
                        id(session.goal_id.as_uuid()),
                        sql_u64(session.revision)?,
                        encode(&session)?
                    ],
                )
                .map_err(sql_error)?;
            insert_operation_receipt(&transaction, &receipt)?;
            insert_audit(&transaction, &audit)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn save_focus_session(
        &self,
        value: &FocusSession,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            require_owned_reference(
                &transaction,
                "goals_records",
                id(value.goal_id.as_uuid()),
                value.owner,
            )?;
            check_expected_revision(&transaction,"focus_records","id",id(value.id.as_uuid()),expected_revision)?;
            let changed = transaction.execute(
                "INSERT INTO focus_records(id,owner,goal_id,revision,payload) VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(id) DO UPDATE SET
                     goal_id=excluded.goal_id,revision=excluded.revision,payload=excluded.payload
                 WHERE focus_records.owner=excluded.owner",
                params![id(value.id.as_uuid()),id(value.owner.as_uuid()),id(value.goal_id.as_uuid()),sql_u64(value.revision)?,encode(&value)?],
            ).map_err(sql_error)?;
            ensure_one_row_changed(changed, "The focus session belongs to another owner.")?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn save_focus_session_transition(
        &self,
        value: &FocusSessionLifecycleWrite,
    ) -> Result<(), RepositoryError> {
        value.validate()?;
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let current_payload: Option<String> = transaction
                .query_row(
                    "SELECT payload FROM focus_records WHERE id=?1 AND owner=?2",
                    params![
                        id(value.session.id.as_uuid()),
                        id(value.session.owner.as_uuid())
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            let current_payload = current_payload.ok_or(RepositoryError {
                kind: RepositoryErrorKind::NotFound,
                summary: "The durable focus session was not found.",
            })?;
            let current: FocusSession = decode_owned(current_payload, value.session.owner)?;
            value.validate_against(&current)?;
            require_owned_reference(
                &transaction,
                "goals_records",
                id(value.session.goal_id.as_uuid()),
                value.session.owner,
            )?;
            let changed = transaction
                .execute(
                    "UPDATE focus_records
                     SET goal_id=?1,revision=?2,payload=?3
                     WHERE id=?4 AND owner=?5 AND revision=?6",
                    params![
                        id(value.session.goal_id.as_uuid()),
                        sql_u64(value.session.revision)?,
                        encode(&value.session)?,
                        id(value.session.id.as_uuid()),
                        id(value.session.owner.as_uuid()),
                        sql_u64(value.expected_revision)?
                    ],
                )
                .map_err(sql_error)?;
            ensure_one_row_changed(changed, "The focus-session revision changed.")?;
            insert_audit(&transaction, &value.audit)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn load_interventions(&self, owner: ActorId) -> Result<Vec<Intervention>, RepositoryError> {
        self.call(move |connection| load_owner_records(connection, "intervention_records", owner))
    }

    fn save_intervention(
        &self,
        value: &Intervention,
        expected_revision: Option<u64>,
    ) -> Result<(), RepositoryError> {
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            require_owned_reference(
                &transaction,
                "goals_records",
                id(value.goal_id.as_uuid()),
                value.owner,
            )?;
            require_owned_reference(
                &transaction,
                "focus_records",
                id(value.focus_session_id.as_uuid()),
                value.owner,
            )?;
            check_expected_revision(&transaction,"intervention_records","id",id(value.id.as_uuid()),expected_revision)?;
            let changed = transaction.execute(
                "INSERT INTO intervention_records(id,owner,goal_id,session_id,revision,payload) VALUES(?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(id) DO UPDATE SET
                     goal_id=excluded.goal_id,
                     session_id=excluded.session_id,
                     revision=excluded.revision,
                     payload=excluded.payload
                 WHERE intervention_records.owner=excluded.owner",
                params![id(value.id.as_uuid()),id(value.owner.as_uuid()),id(value.goal_id.as_uuid()),id(value.focus_session_id.as_uuid()),sql_u64(value.revision)?,encode(&value)?],
            ).map_err(sql_error)?;
            ensure_one_row_changed(changed, "The intervention belongs to another owner.")?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn save_intervention_transition(
        &self,
        value: &InterventionTransitionWrite,
    ) -> Result<(), RepositoryError> {
        value.validate()?;
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(sql_error)?;
            let current_payload: Option<String> = transaction
                .query_row(
                    "SELECT payload FROM intervention_records WHERE id=?1 AND owner=?2",
                    params![
                        id(value.intervention.id.as_uuid()),
                        id(value.intervention.owner.as_uuid())
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            let current_payload = current_payload.ok_or(RepositoryError {
                kind: RepositoryErrorKind::NotFound,
                summary: "The durable intervention was not found.",
            })?;
            let current: Intervention = decode_owned(current_payload, value.intervention.owner)?;
            value.validate_against(&current)?;
            let policy_payload: Option<String> = transaction
                .query_row(
                    "SELECT payload FROM policy_records WHERE id=?1 AND owner=?2",
                    params![
                        id(value.intervention.policy_decision_id.as_uuid()),
                        id(value.intervention.owner.as_uuid())
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(sql_error)?;
            let policy = policy_payload.map(decode::<PolicyDecision>).transpose()?;
            value.validate_policy_against(policy.as_ref())?;
            require_owned_reference(
                &transaction,
                "goals_records",
                id(value.intervention.goal_id.as_uuid()),
                value.intervention.owner,
            )?;
            require_owned_reference(
                &transaction,
                "focus_records",
                id(value.intervention.focus_session_id.as_uuid()),
                value.intervention.owner,
            )?;
            if let Some(delivery_transition) = &value.delivery {
                let delivery = delivery_transition.delivery();
                let current_delivery = transaction
                    .query_row(
                        "SELECT payload FROM outbox_records WHERE id=?1 AND owner=?2",
                        params![id(delivery.id.as_uuid()), id(delivery.owner.as_uuid())],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .map_err(sql_error)?
                    .map(decode)
                    .transpose()?;
                delivery_transition.validate_against(current_delivery.as_ref())?;
                match delivery_transition {
                    PendingDeliveryTransition::Enqueue(delivery) => {
                        insert_pending_delivery(&transaction, delivery)?;
                    }
                    PendingDeliveryTransition::Update { delivery, .. }
                    | PendingDeliveryTransition::ReconcileLegacy { delivery, .. } => {
                        update_pending_delivery(&transaction, delivery)?;
                    }
                }
            }
            let changed = transaction
                .execute(
                    "UPDATE intervention_records
                     SET goal_id=?1,session_id=?2,revision=?3,payload=?4
                     WHERE id=?5 AND owner=?6 AND revision=?7",
                    params![
                        id(value.intervention.goal_id.as_uuid()),
                        id(value.intervention.focus_session_id.as_uuid()),
                        sql_u64(value.intervention.revision)?,
                        encode(&value.intervention)?,
                        id(value.intervention.id.as_uuid()),
                        id(value.intervention.owner.as_uuid()),
                        sql_u64(value.expected_revision)?
                    ],
                )
                .map_err(sql_error)?;
            ensure_one_row_changed(changed, "The intervention revision changed.")?;
            insert_audit(&transaction, &value.audit)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn save_policy_decision(&self, value: &PolicyDecision) -> Result<(), RepositoryError> {
        if !value.policy_trace.is_complete()
            || value.policy_version != value.policy_trace.policy_profile_id
        {
            return Err(RepositoryError {
                kind: RepositoryErrorKind::Corrupt,
                summary: "A policy decision has incomplete trace provenance.",
            });
        }
        let value = value.clone();
        self.call(move |connection| {
            require_owned_reference(
                connection,
                "focus_records",
                id(value.focus_session_id.as_uuid()),
                value.owner,
            )?;
            let changed = connection
                .execute(
                    "INSERT INTO policy_records(id,owner,session_id,payload) VALUES(?1,?2,?3,?4)",
                    params![
                        id(value.id.as_uuid()),
                        id(value.owner.as_uuid()),
                        id(value.focus_session_id.as_uuid()),
                        encode(&value)?
                    ],
                )
                .map_err(sql_error)?;
            ensure_one_row_changed(changed, "The policy decision could not be persisted.")
        })
    }

    fn commit_intervention_decision<'a>(
        &'a self,
        value: &'a InterventionDecisionWrite,
    ) -> PortFuture<'a, Result<(), RepositoryError>> {
        Box::pin(async move {
            value.validate()?;
            let value = value.clone();
            self.call(move |connection| {
                let transaction = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(sql_error)?;
                require_owned_reference(
                    &transaction,
                    "focus_records",
                    id(value.decision.focus_session_id.as_uuid()),
                    value.decision.owner,
                )?;

                if let Some(intervention) = &value.intervention {
                    require_owned_reference(
                        &transaction,
                        "goals_records",
                        id(intervention.goal_id.as_uuid()),
                        intervention.owner,
                    )?;
                }

                transaction
                    .execute(
                        "INSERT INTO policy_records(id,owner,session_id,payload)
                         VALUES(?1,?2,?3,?4)",
                        params![
                            id(value.decision.id.as_uuid()),
                            id(value.decision.owner.as_uuid()),
                            id(value.decision.focus_session_id.as_uuid()),
                            encode(&value.decision)?
                        ],
                    )
                    .map_err(sql_error)?;
                insert_audit(&transaction, &value.audit)?;

                if let Some(intervention) = &value.intervention {
                    let current_payload: Option<String> = transaction
                        .query_row(
                            "SELECT payload FROM intervention_records WHERE id=?1",
                            [id(intervention.id.as_uuid())],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(sql_error)?;
                    let current = current_payload.map(decode::<Intervention>).transpose()?;
                    value.validate_against(current.as_ref())?;
                    check_expected_revision(
                        &transaction,
                        "intervention_records",
                        "id",
                        id(intervention.id.as_uuid()),
                        value.expected_intervention_revision,
                    )?;
                    let changed = transaction
                        .execute(
                            "INSERT INTO intervention_records(
                                 id,owner,goal_id,session_id,revision,payload
                             ) VALUES(?1,?2,?3,?4,?5,?6)
                             ON CONFLICT(id) DO UPDATE SET
                                 goal_id=excluded.goal_id,
                                 session_id=excluded.session_id,
                                 revision=excluded.revision,
                                 payload=excluded.payload
                             WHERE intervention_records.owner=excluded.owner",
                            params![
                                id(intervention.id.as_uuid()),
                                id(intervention.owner.as_uuid()),
                                id(intervention.goal_id.as_uuid()),
                                id(intervention.focus_session_id.as_uuid()),
                                sql_u64(intervention.revision)?,
                                encode(intervention)?
                            ],
                        )
                        .map_err(sql_error)?;
                    ensure_one_row_changed(changed, "The intervention belongs to another owner.")?;
                }

                transaction.commit().map_err(sql_error)
            })
        })
    }

    fn find_policy_decision(
        &self,
        decision_id: stein_core::PolicyDecisionId,
    ) -> Result<Option<PolicyDecision>, RepositoryError> {
        self.call(move |connection| {
            let row: Option<(String, Vec<u8>)> = connection
                .query_row(
                    "SELECT payload,owner FROM policy_records WHERE id=?1",
                    [id(decision_id.as_uuid())],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(sql_error)?;
            let Some((payload, owner)) = row else {
                return Ok(None);
            };
            let value: PolicyDecision = decode_owned(payload, actor_from_blob(&owner)?)?;
            if value.id != decision_id {
                return Err(relational_payload_mismatch());
            }
            Ok(Some(value))
        })
    }

    fn append_audit(&self, value: &AuditRecord) -> Result<(), RepositoryError> {
        let value = value.clone();
        self.call(move |connection| insert_audit(connection, &value))
    }

    fn load_audit(
        &self,
        owner: ActorId,
        since: OffsetDateTime,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, RepositoryError> {
        self.call(move |connection| {
            let mut values: Vec<AuditRecord> =
                load_owner_records(connection, "audit_records", owner)?;
            values.retain(|value| value.occurred_at >= since);
            values.sort_by_key(|value| value.occurred_at);
            values.truncate(limit);
            Ok(values)
        })
    }

    fn purge_expired_audit(&self, now: OffsetDateTime) -> Result<u64, RepositoryError> {
        self.call(move |connection| {
            let mut statement = connection
                .prepare("SELECT id,payload FROM audit_records")
                .map_err(sql_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(sql_error)?;
            let expired: Result<Vec<_>, RepositoryError> = rows
                .map(|row| {
                    let (id_value, payload) = row.map_err(sql_error)?;
                    let record: AuditRecord = decode(payload)?;
                    Ok((id_value, record.expires_at <= now))
                })
                .collect();
            drop(statement);
            let mut count = 0_u64;
            for (id_value, is_expired) in expired? {
                if is_expired {
                    let changed = connection
                        .execute("DELETE FROM audit_records WHERE id=?1", [id_value])
                        .map_err(sql_error)?;
                    count = count
                        .checked_add(count_to_u64(changed)?)
                        .ok_or_else(durable_count_overflow)?;
                }
            }
            Ok(count)
        })
    }

    fn enqueue_delivery(&self, value: &PendingInterventionDelivery) -> Result<(), RepositoryError> {
        let value = value.clone();
        self.call(move |connection| {
            let transaction = connection.transaction().map_err(sql_error)?;
            insert_pending_delivery(&transaction, &value)?;
            transaction.commit().map_err(sql_error)
        })
    }

    fn save_delivery(&self, value: &PendingInterventionDelivery) -> Result<(), RepositoryError> {
        let value = value.clone();
        self.call(move |connection| update_pending_delivery(connection, &value))
    }

    fn load_pending_deliveries(
        &self,
        owner: ActorId,
    ) -> Result<Vec<PendingInterventionDelivery>, RepositoryError> {
        self.call(move |connection| load_owner_records(connection, "outbox_records", owner))
    }
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::{RepositoryErrorKind, encode};

    #[derive(Serialize)]
    struct ProhibitedDurableShape {
        model_prompt: String,
    }

    #[test]
    fn prohibited_private_field_names_never_encode() {
        let error = encode(&ProhibitedDurableShape {
            model_prompt: "synthetic-private-sentinel".to_owned(),
        })
        .unwrap_err();
        assert_eq!(error.kind, RepositoryErrorKind::Internal);
        assert_eq!(
            error.summary,
            "A prohibited private field reached durable storage."
        );
    }
}
