//! Focused connection-management integration tests using real isolated SQLite storage.
use dbx_core::{
    models::connection::ConnectionConfig,
    persistence::{connection_management::*, test_storage},
    storage::{McpGlobalPolicy, Storage},
};
use serde_json::json;

fn config(id: &str, name: &str) -> ConnectionConfig {
    serde_json::from_value(json!({
        "id": id, "name": name, "db_type": "sqlite", "host": ":memory:", "port": 0,
        "username": "", "password": "fixture-password", "database": "fixture",
        "connection_string": "fixture-dsn", "url_params": "token=fixture-url",
        "connection_secrets": {"token": "fixture-plugin"},
        "init_script": "fixture-init-script",
        "transport_layers": [{"type":"ssh", "id":"bastion", "name":"Bastion", "enabled":true,
            "host":"bastion.invalid", "port":22, "user":"deploy", "password":"fixture-ssh",
            "key_path":"/synthetic/key", "key_passphrase":"fixture-passphrase", "auth_method":"key+password"}],
        "read_only": true, "note": "kept note"
    }))
    .unwrap()
}

async fn secret_rows(storage: &Storage) -> Vec<(String, String, Option<String>)> {
    let conn = rusqlite::Connection::open(storage.data_dir().join("dbx.db")).unwrap();
    let mut statement = conn
        .prepare("SELECT key, secret, secret_enc FROM connection_secrets WHERE connection_id = 'first' ORDER BY key")
        .unwrap();
    let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).unwrap();
    rows.collect::<Result<Vec<_>, _>>().unwrap()
}

#[tokio::test]
async fn connection_crud_preserves_omitted_secrets_and_desktop_settings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dbx.db");
    let storage = test_storage::open(&path).await.unwrap();
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    storage.add_connection_for_mcp(config("first", "First")).await.unwrap();
    storage.add_connection_for_mcp(config("second", "Second")).await.unwrap();
    let before = secret_rows(&storage).await;
    assert!(!before.is_empty());
    assert!(before
        .iter()
        .all(|(_, plaintext, encrypted)| plaintext.is_empty() && encrypted.as_ref().is_some_and(|v| !v.is_empty())));
    let changed = storage
        .update_connection_for_mcp("first", json!({"name": "Renamed", "read_only": false, "database": null}))
        .await
        .unwrap();
    assert_eq!(changed.name, "Renamed");
    assert!(!changed.read_only);
    assert_eq!(changed.database, None);
    assert_eq!(changed.note, "kept note");
    assert_eq!(changed.password, "fixture-password");
    assert_eq!(changed.transport_layers, config("first", "First").transport_layers);
    assert_eq!(changed.init_script.as_deref(), Some("fixture-init-script"));
    assert_eq!(changed.connection_string.as_deref(), Some("fixture-dsn"));
    assert_eq!(changed.connection_secrets.get("token").map(String::as_str), Some("fixture-plugin"));
    // The shared loader rewraps plugin secrets during hydration. Compare decrypted values,
    // not random AEAD nonces; every omitted credential must survive with no plaintext rows.
    let after = secret_rows(&storage).await;
    assert_eq!(before.len(), after.len());
    let codec = dbx_core::persistence::secret_codec::SecretCodec::resolve(
        dbx_core::persistence::secret_codec::SecretKeyPolicy::TestDataDir,
        directory.path(),
        false,
    )
    .unwrap()
    .codec;
    for ((key, _, encrypted_before), (key_after, plaintext, encrypted_after)) in before.iter().zip(&after) {
        assert_eq!(key, key_after);
        assert!(plaintext.is_empty());
        assert_eq!(
            codec.decrypt("first", key, encrypted_before.as_deref().unwrap()).unwrap(),
            codec.decrypt("first", key_after, encrypted_after.as_deref().unwrap()).unwrap()
        );
    }
    let other = storage.load_connections().await.unwrap().into_iter().find(|c| c.id == "second").unwrap();
    assert_eq!(other, config("second", "Second"));
    let reopened = test_storage::open(&path).await.unwrap();
    let saved = reopened.load_connections().await.unwrap().into_iter().find(|c| c.id == "first").unwrap();
    assert_eq!(saved, changed, "desktop storage must read the same persisted config");
    let replaced = storage.update_connection_for_mcp("first", json!({"password": "replacement-secret"})).await.unwrap();
    assert_eq!(replaced.password, "replacement-secret");
    let cleared = storage.update_connection_for_mcp("first", json!({"password": ""})).await.unwrap();
    assert_eq!(cleared.password, "");
    assert_eq!(cleared.connection_secrets, changed.connection_secrets);
    storage.update_connection_for_mcp("first", json!({"password": "temporary", "save_password": false})).await.unwrap();
    let no_password = storage.update_connection_for_mcp("first", json!({"save_password": true})).await.unwrap();
    assert!(no_password.password.is_empty());
    assert!(storage.remove_connection_for_mcp("first").await.unwrap());
    assert!(secret_rows(&storage).await.is_empty());
    assert!(!storage.remove_connection_for_mcp("first").await.unwrap());
    assert_eq!(storage.load_connections().await.unwrap().len(), 1);
}

#[tokio::test]
async fn connection_crud_rejects_invalid_duplicate_missing_and_blocked_changes() {
    let directory = tempfile::tempdir().unwrap();
    let storage = test_storage::open(&directory.path().join("dbx.db")).await.unwrap();
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    storage.add_connection_for_mcp(config("first", "First")).await.unwrap();
    storage.add_connection_for_mcp(config("second", "Second")).await.unwrap();
    assert!(storage
        .add_connection_for_mcp(config("third", " FIRST "))
        .await
        .unwrap_err()
        .starts_with("CONNECTION_ALREADY_EXISTS:"));
    assert!(storage
        .update_connection_for_mcp("first", json!({"name": "SECOND"}))
        .await
        .unwrap_err()
        .starts_with("CONNECTION_ALREADY_EXISTS:"));
    assert!(storage
        .update_connection_for_mcp("missing", json!({"name": "Third"}))
        .await
        .unwrap_err()
        .starts_with("CONNECTION_NOT_FOUND:"));
    for patch in [
        json!({"password": null}),
        json!({"port": 65536}),
        json!({"name":""}),
        json!({"id":"other"}),
        json!({"db_type":"postgres"}),
    ] {
        assert!(storage
            .update_connection_for_mcp("first", patch)
            .await
            .unwrap_err()
            .starts_with("INVALID_CONNECTION:"));
    }
    storage
        .save_mcp_global_policy(&McpGlobalPolicy {
            read_only: false,
            allowed_connection_ids: Some(vec!["second".into()]),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(storage
        .update_connection_for_mcp("first", json!({"read_only": false}))
        .await
        .unwrap_err()
        .starts_with("CONNECTION_OUT_OF_SCOPE:"));
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: true, ..Default::default() }).await.unwrap();
    assert!(storage
        .update_connection_for_mcp("first", json!({"read_only": false}))
        .await
        .unwrap_err()
        .starts_with("MCP_READ_ONLY:"));
    assert!(storage.remove_connection_for_mcp("first").await.unwrap_err().starts_with("MCP_READ_ONLY:"));
    assert!(storage.add_connection_for_mcp(config("third", "Third")).await.unwrap_err().starts_with("MCP_READ_ONLY:"));
    assert_eq!(
        storage.load_connections().await.unwrap().into_iter().find(|c| c.id == "first").unwrap(),
        config("first", "First")
    );
}

#[tokio::test]
async fn connection_crud_rejects_corrupt_stored_json_without_panicking() {
    let directory = tempfile::tempdir().unwrap();
    let storage = test_storage::open(&directory.path().join("dbx.db")).await.unwrap();
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    storage.add_connection_for_mcp(config("first", "First")).await.unwrap();
    let conn = rusqlite::Connection::open(storage.data_dir().join("dbx.db")).unwrap();
    conn.execute("UPDATE connections SET config_json = '[]' WHERE id = 'first'", []).unwrap();
    drop(conn);
    let error = storage.update_connection_for_mcp("first", json!({"read_only": false})).await.unwrap_err();
    assert!(error.starts_with("CONNECTION_LOAD_ERROR:"));
}

#[tokio::test]
async fn connection_crud_concurrent_partial_updates_do_not_overwrite_each_other() {
    let directory = tempfile::tempdir().unwrap();
    let storage = test_storage::open(&directory.path().join("dbx.db")).await.unwrap();
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    storage.add_connection_for_mcp(config("first", "First")).await.unwrap();
    let (first, second) = tokio::join!(
        storage.update_connection_for_mcp("first", json!({"name": "Changed"})),
        storage.update_connection_for_mcp("first", json!({"read_only": false}))
    );
    first.unwrap();
    second.unwrap();
    let saved = storage.load_connections().await.unwrap().pop().unwrap();
    assert_eq!(saved.name, "Changed");
    assert!(!saved.read_only);
    assert_eq!(saved.password, "fixture-password");
}

#[test]
fn backend_errors_never_echo_submitted_credentials() {
    for error in [
        r#"HTTP 500: {"password":"echoed-secret","token":"echoed-token"}"#,
        "unlabelled-secret",
        "INVALID_CONNECTION: echoed-secret",
        "Error [MCP_READ_ONLY]: echoed-secret",
    ] {
        let safe = safe_connection_error(error);
        assert!(!safe.contains("echoed"));
        assert!(!safe.contains("unlabelled-secret"));
    }
    assert!(safe_connection_error("Error [MCP_READ_ONLY]: detail").starts_with("MCP_READ_ONLY:"));
}

#[test]
fn patch_validation_has_explicit_clear_semantics() {
    for patch in [json!({"read_only": false}), json!({"password": ""}), json!({"database": null}), json!({"port": 0})] {
        assert!(validate_connection_patch(&patch).is_ok());
    }
    for patch in [
        json!({}),
        json!([]),
        json!({"password": null}),
        json!({"read_only": null}),
        json!({"port": 65536}),
        json!({"port": -1}),
        json!({"name": "  "}),
        json!({"id": "new"}),
        json!({"secret-token-key": "anything"}),
    ] {
        assert!(validate_connection_patch(&patch).is_err());
    }
    assert!(!validate_connection_patch(&json!({"secret-token-key": "anything"}))
        .unwrap_err()
        .contains("secret-token-key"));
}

#[test]
fn management_text_redacts_dsn_and_credential_assignment_variants() {
    for value in [
        "postgres://user:secret@host/db",
        "host; Password = secret",
        "TOKEN = secret",
        "uid=user;pwd=secret",
        "user:secret@host",
    ] {
        assert_eq!(safe_connection_text(value), "[REDACTED]");
    }
    assert_eq!(safe_connection_text("127.0.0.1"), "127.0.0.1");
    assert_eq!(safe_connection_text("[::1]"), "[::1]");
    assert_eq!(safe_connection_text("name\u{1b}[0m"), "name[0m");
}

#[test]
fn details_do_not_expose_secrets_or_urls() {
    let config: ConnectionConfig = serde_json::from_value(json!({
        "id": "c", "name": "test", "db_type": "postgres", "host": "postgres://user:host-secret@localhost/db",
        "port": 5432, "username": "user", "password": "password-secret", "database": "db",
        "connection_string": "dsn-secret", "url_params": "token=url-secret", "init_script": "script-secret",
        "connection_secrets": {"token": "plugin-secret"}, "external_config": {"token": "external-secret"}
    }))
    .unwrap();
    let detail = connection_details(&config);
    assert_eq!(detail["host"], "[REDACTED]");
    let output = detail.to_string();
    for secret in [
        "host-secret",
        "password-secret",
        "dsn-secret",
        "url-secret",
        "script-secret",
        "plugin-secret",
        "external-secret",
    ] {
        assert!(!output.contains(secret));
    }
}

#[tokio::test]
async fn rejected_commit_admission_rolls_back_every_connection_mutation_and_its_secret_rows() {
    use dbx_core::persistence::storage::McpConnectionCommitGuard;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn snapshot(storage: &Storage) -> serde_json::Value {
        let conn = rusqlite::Connection::open(storage.data_dir().join("dbx.db")).unwrap();
        let mut configs = conn.prepare("SELECT id, config_json FROM connections ORDER BY id").unwrap();
        let configs = configs
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut secrets = conn
            .prepare(
                "SELECT connection_id, key, secret, secret_enc FROM connection_secrets ORDER BY connection_id, key",
            )
            .unwrap();
        let secrets = secrets
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut state = conn.prepare("SELECT key, value_json FROM app_state ORDER BY key").unwrap();
        let state = state
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        json!({"connections": configs, "secrets": secrets, "app_state": state})
    }

    let directory = tempfile::tempdir().unwrap();
    let storage = test_storage::open(&directory.path().join("dbx.db")).await.unwrap();
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    storage.add_connection_for_mcp(config("first", "First")).await.unwrap();
    let before = snapshot(&storage);
    for operation in ["add", "update", "duplicate", "remove"] {
        let checks = Arc::new(AtomicUsize::new(0));
        let guard: McpConnectionCommitGuard = Arc::new({
            let checks = checks.clone();
            move || {
                // Existing isolated key: preparation and blocking-task entry
                // pass; cancellation is observed at the actual pre-commit gate.
                if checks.fetch_add(1, Ordering::SeqCst) == 2 {
                    Err("MCP_REQUEST_CANCELLED: synthetic pre-commit cancellation".into())
                } else {
                    Ok(())
                }
            }
        });
        let error = match operation {
            "add" => storage
                .add_connection_for_mcp_with_commit_guard(config("second", "Second"), Some(guard))
                .await
                .unwrap_err(),
            "update" => storage
                .update_connection_for_mcp_with_commit_guard(
                    "first",
                    json!({"name": "Changed", "password": "replacement-fixture"}),
                    Some(guard),
                )
                .await
                .unwrap_err(),
            "duplicate" => storage
                .duplicate_connection_for_mcp_with_commit_guard("first", "copy", "Copy", Some(guard))
                .await
                .unwrap_err(),
            _ => storage.remove_connection_for_mcp_with_commit_guard("first", Some(guard)).await.unwrap_err(),
        };
        assert!(error.contains("MCP_REQUEST_CANCELLED"), "{operation}: {error}");
        assert_eq!(checks.load(Ordering::SeqCst), 3, "{operation}: commit gate must run");
        assert_eq!(snapshot(&storage), before, "{operation}: no row or ciphertext change may survive rollback");
    }
}

#[tokio::test]
async fn postcommit_hydration_failure_reports_persistence_without_claiming_rollback() {
    use dbx_core::persistence::storage::MCP_CONNECTION_COMMITTED_RELOAD_FAILED;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dbx.db");
    let storage = test_storage::open(&path).await.unwrap();
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    storage.add_connection_for_mcp(config("first", "First")).await.unwrap();
    storage.add_connection_for_mcp(config("other", "Other")).await.unwrap();
    // Corrupt only an unrelated synthetic ciphertext. The target transaction
    // can commit, while the subsequent all-profile hydration must fail.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("UPDATE connection_secrets SET secret_enc = 'invalid-fixture-envelope' WHERE connection_id = 'other' AND key = 'password'", []).unwrap();
    let error = storage.update_connection_for_mcp("first", json!({"name": "Committed"})).await.unwrap_err();
    assert_eq!(error, MCP_CONNECTION_COMMITTED_RELOAD_FAILED);
    let saved: String =
        conn.query_row("SELECT config_json FROM connections WHERE id = 'first'", [], |row| row.get(0)).unwrap();
    assert_eq!(serde_json::from_str::<serde_json::Value>(&saved).unwrap()["name"], "Committed");
    let error = storage.duplicate_connection_for_mcp("first", "copy", "Copy").await.unwrap_err();
    assert_eq!(error, MCP_CONNECTION_COMMITTED_RELOAD_FAILED);
    let copied: i64 =
        conn.query_row("SELECT COUNT(*) FROM connections WHERE id = 'copy'", [], |row| row.get(0)).unwrap();
    assert_eq!(copied, 1);
}
