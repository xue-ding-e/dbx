//! Cancellation-safe completion for already admitted local profile mutations.
//!
//! Only the LocalBackend CRUD storage boundary uses this scope. Tool-policy
//! checks and all SQL work remain cancellable. Completion tasks recheck before
//! they start, and Storage checks the same guard again immediately before commit.
//! A rejected pre-commit guard rolls back the SQLite transaction; after successful
//! commit admission, required runtime cleanup survives loss of the HTTP reply.
//! Cancellation is not a rollback guarantee: inspect saved state before retrying.

use std::{future::Future, sync::Arc};

use tokio_util::sync::CancellationToken;

use crate::{http_auth::HttpRequestDeadline, http_principals::PrincipalLease};

tokio::task_local! {
    static HTTP_MUTATION_CONTEXT: RequestMutationContext;
}

#[derive(Clone)]
pub(crate) struct RequestMutationContext {
    request: HttpRequestDeadline,
    principal: Arc<PrincipalLease>,
    request_cancellation: CancellationToken,
    admission_closed: CancellationToken,
}

struct CloseAdmissionOnDrop(CancellationToken);

impl Drop for CloseAdmissionOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl RequestMutationContext {
    pub(crate) fn new(
        request: HttpRequestDeadline,
        principal: Arc<PrincipalLease>,
        request_cancellation: CancellationToken,
    ) -> Self {
        Self { request, principal, request_cancellation, admission_closed: CancellationToken::new() }
    }

    pub(crate) async fn scope<F: Future>(self, future: F) -> F::Output {
        // Dropping the HTTP dispatch future also closes admission, even if the
        // transport has not yet signalled its own cancellation token.
        let _close_admission = CloseAdmissionOnDrop(self.admission_closed.clone());
        HTTP_MUTATION_CONTEXT.scope(self, future).await
    }

    fn ensure_active(&self) -> Result<(), String> {
        if self.request.deadline <= tokio::time::Instant::now()
            || self.request.policy_cancellation.is_cancelled()
            || self.request_cancellation.is_cancelled()
            || self.principal.cancellation.is_cancelled()
            || self.admission_closed.is_cancelled()
        {
            return Err("MCP_REQUEST_CANCELLED: local mutation was not admitted".into());
        }
        Ok(())
    }
}

/// Capture at the backend boundary, before entering the owned completion task.
/// Storage invokes this in its blocking transaction before commit. Keeping the
/// original context also keeps the exact request/principal lifetime and permit.
pub(crate) fn current_commit_guard() -> Option<dbx_core::persistence::storage::McpConnectionCommitGuard> {
    HTTP_MUTATION_CONTEXT
        .try_with(|context| {
            let context = context.clone();
            let guard: dbx_core::persistence::storage::McpConnectionCommitGuard =
                Arc::new(move || context.ensure_active());
            guard
        })
        .ok()
}

fn spawn_completion<T, F>(
    context: RequestMutationContext,
    mutation: F,
) -> Result<tokio::task::JoinHandle<Result<T, String>>, String>
where
    T: Send + 'static,
    F: Future<Output = Result<T, String>> + Send + 'static,
{
    context.ensure_active()?;
    // Spawn does not inherit task locals. In embedded Web hosts, write-unlock
    // cleanup must keep the caller's credential owner instead of using desktop.
    let credential_owner = dbx_core::session_credentials::current_credential_owner();
    Ok(tokio::spawn(async move {
        // Recheck when the task actually starts, not just when it was queued.
        // Storage checks again before commit, including after blocking-pool or
        // SQLite-lock waits. This first poll is not a promise to commit.
        context.ensure_active()?;
        let result = dbx_core::session_credentials::with_credential_owner(credential_owner, mutation).await;
        // This is a tracked completion, not unbounded fire-and-forget work:
        // request capacity and the principal lease remain held until ALL cache
        // cleanup finishes. Principal shutdown waits for this lease to drain.
        drop(context);
        result
    }))
}

pub(crate) async fn complete_local_mutation<T, F>(mutation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: Future<Output = Result<T, String>> + Send + 'static,
{
    match HTTP_MUTATION_CONTEXT.try_with(Clone::clone) {
        Ok(context) => spawn_completion(context, mutation)?.await.map_err(|_| {
            "MCP_MUTATION_FAILED: mutation outcome is unknown; reload saved state before retrying".to_string()
        })?,
        // Local stdio/CLI callers have no HTTP principal. Preserve their
        // existing execution and cancellation semantics without spawning.
        Err(_) => mutation.await,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use tokio::sync::Semaphore;

    use super::*;
    use crate::{
        http_principals::PrincipalStates, server::PluginToolsMode, DbxMcpServer, McpScope, UnavailableBackend,
    };

    fn principals() -> Arc<PrincipalStates> {
        PrincipalStates::new(DbxMcpServer::with_plugin_tools_mode(
            Arc::new(UnavailableBackend::new("lifecycle-only fixture")),
            McpScope::default(),
            true,
            PluginToolsMode::Flat,
        ))
    }

    async fn context(states: &Arc<PrincipalStates>, budget: &Arc<Semaphore>) -> RequestMutationContext {
        RequestMutationContext::new(
            HttpRequestDeadline {
                principal: "owner".into(),
                deadline: tokio::time::Instant::now() + Duration::from_secs(30),
                _permit: Arc::new(budget.clone().acquire_owned().await.unwrap()),
                policy_cancellation: CancellationToken::new(),
            },
            Arc::new(states.acquire("owner").unwrap()),
            CancellationToken::new(),
        )
    }

    #[tokio::test]
    async fn non_http_mutations_keep_inline_cancellation_semantics() {
        let entered = Arc::new(Semaphore::new(0));
        let finish = Arc::new(Semaphore::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let request = tokio::spawn(complete_local_mutation({
            let entered = entered.clone();
            let finish = finish.clone();
            let completed = completed.clone();
            async move {
                entered.add_permits(1);
                finish.acquire().await.unwrap().forget();
                completed.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }));
        tokio::time::timeout(Duration::from_secs(5), entered.acquire()).await.unwrap().unwrap().forget();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        finish.add_permits(1);
        tokio::task::yield_now().await;
        assert_eq!(completed.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn expired_rotated_disconnected_and_closed_requests_never_start_mutations() {
        let states = principals();
        let budget = Arc::new(Semaphore::new(1));
        let started = Arc::new(AtomicUsize::new(0));
        for reason in 0..5 {
            let mut context = context(&states, &budget).await;
            match reason {
                0 => context.request.deadline = tokio::time::Instant::now(),
                1 => context.request.policy_cancellation.cancel(),
                2 => context.request_cancellation.cancel(),
                3 => context.admission_closed.cancel(),
                _ => context.principal.cancellation.cancel(),
            }
            let result = context
                .scope(complete_local_mutation({
                    let started = started.clone();
                    async move {
                        started.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                }))
                .await;
            assert!(result.unwrap_err().contains("MCP_REQUEST_CANCELLED"));
            assert_eq!(started.load(Ordering::SeqCst), 0);
            assert_eq!(budget.available_permits(), 1);
        }
        states.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn policy_rotation_or_dispatch_drop_before_first_poll_cannot_start_a_queued_write() {
        let states = principals();
        let budget = Arc::new(Semaphore::new(1));
        let started = Arc::new(AtomicUsize::new(0));
        for close_dispatch in [false, true] {
            let context = context(&states, &budget).await;
            let policy = context.request.policy_cancellation.clone();
            let task = context
                .clone()
                .scope(async {
                    let task = spawn_completion(context, {
                        let started = started.clone();
                        async move {
                            started.fetch_add(1, Ordering::SeqCst);
                            Ok(())
                        }
                    })
                    .unwrap();
                    if !close_dispatch {
                        policy.cancel();
                    }
                    // No yield: the new task cannot poll until this scope closes.
                    task
                })
                .await;
            assert!(task.await.unwrap().unwrap_err().contains("MCP_REQUEST_CANCELLED"));
            assert_eq!(started.load(Ordering::SeqCst), 0);
            assert_eq!(budget.available_permits(), 1);
        }
        states.shutdown().await;
    }

    #[tokio::test]
    async fn committed_mutation_cleanup_finishes_after_expiry_rotation_and_response_drop() {
        let states = principals();
        let budget = Arc::new(Semaphore::new(1));
        let mut context = context(&states, &budget).await;
        context.request.deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let deadline = context.request.deadline;
        let policy = context.request.policy_cancellation.clone();
        let entered = Arc::new(Semaphore::new(0));
        let finish = Arc::new(Semaphore::new(0));
        let cleaned = Arc::new(AtomicUsize::new(0));
        let request = tokio::spawn(context.scope(complete_local_mutation({
            let entered = entered.clone();
            let finish = finish.clone();
            let cleaned = cleaned.clone();
            async move {
                entered.add_permits(1); // synthetic committed-storage boundary
                finish.acquire().await.unwrap().forget();
                cleaned.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })));
        tokio::time::timeout(Duration::from_secs(5), entered.acquire()).await.unwrap().unwrap().forget();
        tokio::time::sleep_until(deadline).await;
        policy.cancel();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        assert_eq!(cleaned.load(Ordering::SeqCst), 0);
        assert_eq!(budget.available_permits(), 0);
        finish.add_permits(1);
        tokio::time::timeout(Duration::from_secs(5), states.shutdown()).await.unwrap();
        assert_eq!(cleaned.load(Ordering::SeqCst), 1);
        assert_eq!(budget.available_permits(), 1);
    }

    #[tokio::test]
    async fn live_request_guard_rejects_revocation_at_the_storage_commit_boundary() {
        use dbx_core::{
            persistence::{storage::McpConnectionCommitGuard, test_storage},
            storage::McpGlobalPolicy,
        };
        use serde_json::json;

        for reason in ["policy", "request", "principal", "dispatch"] {
            let directory = tempfile::tempdir().unwrap();
            let storage = test_storage::open(&directory.path().join("dbx.db")).await.unwrap();
            storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
            let config = serde_json::from_value(json!({
                "id": "fixture", "name": "Before", "db_type": "sqlite", "host": ":memory:",
                "port": 0, "username": "", "password": "", "read_only": true
            }))
            .unwrap();
            storage.add_connection_for_mcp(config).await.unwrap();
            let states = principals();
            let budget = Arc::new(Semaphore::new(1));
            let context = context(&states, &budget).await;
            let cancellation = match reason {
                "policy" => context.request.policy_cancellation.clone(),
                "request" => context.request_cancellation.clone(),
                "principal" => context.principal.cancellation.clone(),
                _ => context.admission_closed.clone(),
            };
            let checks = Arc::new(AtomicUsize::new(0));
            let result = context
                .scope({
                    let storage = storage.clone();
                    let checks = checks.clone();
                    async move {
                        let actual_guard = current_commit_guard().unwrap();
                        let commit_guard: McpConnectionCommitGuard = Arc::new(move || {
                            // Production's exact guard observes revocation after SQL
                            // changes have been staged but before commit is admitted.
                            if checks.fetch_add(1, Ordering::SeqCst) == 2 {
                                cancellation.cancel();
                            }
                            actual_guard()
                        });
                        complete_local_mutation(async move {
                            storage
                                .update_connection_for_mcp_with_commit_guard(
                                    "fixture",
                                    json!({"name": "Must roll back"}),
                                    Some(commit_guard),
                                )
                                .await
                        })
                        .await
                    }
                })
                .await;
            assert!(result.unwrap_err().contains("MCP_REQUEST_CANCELLED"), "{reason}");
            assert_eq!(checks.load(Ordering::SeqCst), 3, "{reason}");
            assert_eq!(storage.load_connections().await.unwrap()[0].name, "Before", "{reason}");
            assert_eq!(budget.available_permits(), 1, "{reason}");
            tokio::time::timeout(Duration::from_secs(5), states.shutdown()).await.unwrap();
        }
    }

    #[tokio::test]
    async fn panicking_completion_releases_capacity_and_does_not_block_shutdown() {
        let states = principals();
        let budget = Arc::new(Semaphore::new(1));
        let context = context(&states, &budget).await;
        let result = context
            .scope(complete_local_mutation::<(), _>(async {
                panic!("synthetic mutation panic; no database involved");
            }))
            .await;
        assert!(result.unwrap_err().contains("outcome is unknown"));
        assert_eq!(budget.available_permits(), 1);
        tokio::time::timeout(Duration::from_secs(5), states.shutdown()).await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_responses_retain_all_request_capacity_and_shutdown_waits_for_completion() {
        let states = principals();
        let budget = Arc::new(Semaphore::new(32));
        let entered = Arc::new(Semaphore::new(0));
        let finish = Arc::new(Semaphore::new(0));
        let cleaned = Arc::new(AtomicUsize::new(0));
        for _ in 0..32 {
            let context = context(&states, &budget).await;
            let request = tokio::spawn(context.scope(complete_local_mutation({
                let entered = entered.clone();
                let finish = finish.clone();
                let cleaned = cleaned.clone();
                async move {
                    entered.add_permits(1);
                    finish.acquire().await.unwrap().forget();
                    cleaned.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })));
            tokio::time::timeout(Duration::from_secs(5), entered.acquire()).await.unwrap().unwrap().forget();
            request.abort();
            assert!(request.await.unwrap_err().is_cancelled());
        }
        assert_eq!(budget.available_permits(), 0);
        assert!(budget.clone().try_acquire_owned().is_err());
        let shutdown = states.shutdown();
        tokio::pin!(shutdown);
        assert!(tokio::time::timeout(Duration::from_millis(20), &mut shutdown).await.is_err());
        assert!(states.acquire("new-owner").is_err());
        assert_eq!(cleaned.load(Ordering::SeqCst), 0);
        finish.add_permits(32);
        tokio::time::timeout(Duration::from_secs(5), shutdown).await.unwrap();
        assert_eq!(cleaned.load(Ordering::SeqCst), 32);
        assert_eq!(budget.available_permits(), 32);
    }
}
