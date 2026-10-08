//! Exercise the narrow importer through real, isolated encrypted storage.
#![cfg(target_os = "linux")]

use dbx_core::{
    models::connection::{ConnectionConfig, TransportLayerConfig},
    persistence::{
        meatshell_import::{parse_request, ImportRequest},
        secret_codec::{managed_key_path, SecretKeyPolicy},
        test_storage,
    },
    storage::{McpGlobalPolicy, Storage},
};
use rusqlite::OptionalExtension;
use serde_json::{json, Value};
use std::{os::unix::fs::PermissionsExt, path::Path};

const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
const DATABASE_PASSWORD: &str = "SYNTHETIC_SELECTED_DATABASE";
const KEY_PASSPHRASE: &str = "SYNTHETIC_SELECTED_PASSPHRASE";
const TARGET_PASSWORD: &str = "SYNTHETIC_TARGET_PASSWORD";

fn request(include_password: bool) -> ImportRequest {
    let metadata = json!({
        "schema_version": 1,
        "target_session_id": "44444444-4444-4444-8444-444444444444",
        "route": [
            {"session_id": "33333333-3333-4333-8333-333333333333", "host": "192.0.2.10", "port": 22, "user": "fixture", "auth": "key"},
            {"session_id": "44444444-4444-4444-8444-444444444444", "host": "198.51.100.20", "port": 22, "user": "fixture", "auth": "password"}
        ]
    });
    let plan = json!({
        "format": "dbx-meatshell-import-plan", "version": 1,
        "source_connection_id": SOURCE,
        "new_connection_id": "22222222-2222-4222-8222-222222222222",
        "new_connection_name": "Synthetic independent connection",
        "host": "database.example.invalid", "port": 5432, "database": "synthetic_copy",
        "username": "fixture", "is_production": true, "ssl": false,
        "expected_export": metadata
    });
    let mut export = metadata;
    if include_password {
        export["route"][1]["password"] = json!(TARGET_PASSWORD);
    }
    parse_request(&serde_json::to_vec(&plan).unwrap(), &serde_json::to_vec(&export).unwrap()).unwrap()
}

async fn fixture() -> (tempfile::TempDir, Storage) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let storage = test_storage::open(&directory.path().join("dbx.db")).await.unwrap();
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    let config: ConnectionConfig = serde_json::from_value(json!({
        "id": SOURCE, "name": "Synthetic original", "db_type": "postgres",
        "host": "database.example.invalid", "port": 5432, "database": "synthetic_original",
        "username": "fixture", "password": DATABASE_PASSWORD, "save_password": true,
        "transport_layers": [{
            "type": "ssh", "id": "first-layer", "name": "Synthetic first", "enabled": true,
            "host": "192.0.2.10", "port": 22, "user": "fixture", "auth_method": "key",
            "key_path": "/synthetic/key-never-opened", "key_passphrase": KEY_PASSPHRASE,
            "password": "", "connect_timeout_secs": 7
        }]
    }))
    .unwrap();
    storage.add_connection_for_mcp(config).await.unwrap();
    (directory, storage)
}

fn snapshot(path: &Path) -> Value {
    let connection = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut statement = connection.prepare("SELECT id, config_json FROM connections ORDER BY id").unwrap();
    let connections: Vec<(String, String)> =
        statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap().collect::<Result<_, _>>().unwrap();
    let mut statement = connection
        .prepare("SELECT connection_id, key, secret, secret_enc FROM connection_secrets ORDER BY connection_id, key")
        .unwrap();
    let secrets: Vec<(String, String, String, Option<String>)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let layout: Option<String> = connection
        .query_row("SELECT layout_json FROM sidebar_layout WHERE id=1", [], |row| row.get(0))
        .optional()
        .unwrap();
    let settings: Option<String> = connection
        .query_row("SELECT settings_json FROM app_settings WHERE id=1", [], |row| row.get(0))
        .optional()
        .unwrap();
    json!({"connections": connections, "secrets": secrets, "layout": layout, "settings": settings})
}

#[tokio::test]
async fn importer_repeated_key_failures_are_nonmutating_and_recover_after_key_restoration() {
    for failure in ["missing", "invalid", "wrong"] {
        let (directory, _storage) = fixture().await;
        let path = directory.path().join("dbx.db");
        let key_path = managed_key_path(directory.path());
        let original_key = std::fs::read(&key_path).unwrap();
        let before = snapshot(&path);
        match failure {
            "missing" => std::fs::remove_file(&key_path).unwrap(),
            "invalid" => std::fs::write(&key_path, b"\n").unwrap(),
            _ => {
                let mut wrong_key = original_key.clone();
                wrong_key[0] = if wrong_key[0] == b'0' { b'1' } else { b'0' };
                std::fs::write(&key_path, wrong_key).unwrap();
            }
        }
        let failed_key = std::fs::read(&key_path).ok();
        let fresh = Storage::open_for_meatshell_import(&path)
            .await
            .unwrap()
            .with_secret_key_policy(SecretKeyPolicy::TestDataDir);

        // Use the production read-only status probe to populate the same error
        // cache as startup; do not inject a test-only cache implementation.
        let status = fresh.inspect_data_migration().await.unwrap();
        assert!(!status.key_provider_available, "{failure}");
        assert!(!status.key_creation_allowed, "{failure}");
        let expected_code = match failure {
            "missing" => "ENCRYPTED_DATA_KEY_MISSING",
            "invalid" => "SECRET_KEY_INVALID",
            _ => "SECRET_KEY_MISMATCH",
        };
        assert_eq!(status.error_code.as_deref(), Some(expected_code));
        for _ in 0..2 {
            assert!(fresh.import_meatshell(request(false), true).await.unwrap().dry_run);
            let error = fresh.import_meatshell(request(true), false).await.unwrap_err();
            assert_eq!(error, "MEATSHELL_SECRET_UNAVAILABLE: Required selected credentials cannot be resolved safely.");
            assert_eq!(snapshot(&path), before, "{failure}");
            assert_eq!(std::fs::read(&key_path).ok(), failed_key, "{failure}");
        }

        // The original encrypted rows and key are synthetic fixture data. The
        // same Storage instance must notice restored material without restart.
        std::fs::write(&key_path, &original_key).unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let report = fresh.import_meatshell(request(true), false).await.unwrap();
        assert_eq!(report.imported_count, 1);
        assert!(!report.database_connection_attempted);
        let imported_id = report.connection_id.unwrap();
        assert_eq!(fresh.get_secret(&imported_id, "password").await.unwrap().as_deref(), Some(DATABASE_PASSWORD));
        assert_eq!(std::fs::read(&key_path).unwrap(), original_key);
        let after = snapshot(&path);
        for row in before["connections"].as_array().unwrap() {
            assert!(after["connections"].as_array().unwrap().contains(row));
        }
        for row in before["secrets"].as_array().unwrap() {
            assert!(after["secrets"].as_array().unwrap().contains(row));
        }
        assert_eq!(after["settings"], before["settings"]);
        let imported = fresh
            .load_connections()
            .await
            .unwrap()
            .into_iter()
            .find(|connection| connection.id == imported_id)
            .unwrap();
        let TransportLayerConfig::Ssh(first) = &imported.transport_layers[0] else {
            panic!("expected synthetic first SSH hop");
        };
        let TransportLayerConfig::Ssh(target) = &imported.transport_layers[1] else {
            panic!("expected synthetic target SSH hop");
        };
        assert_eq!(first.key_passphrase, KEY_PASSPHRASE);
        assert_eq!(target.password, TARGET_PASSWORD);
    }
}
