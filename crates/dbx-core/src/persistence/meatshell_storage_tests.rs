use super::*;
use crate::persistence::{meatshell_import::parse_request, secret_codec::managed_key_path, test_storage};
use serde_json::{json, Value as Json};

const SOURCE: &str = "11111111-1111-4111-8111-111111111111";
const CANDIDATE: &str = "22222222-2222-4222-8222-222222222222";
const OUTER: &str = "33333333-3333-4333-8333-333333333333";
const TARGET: &str = "44444444-4444-4444-8444-444444444444";
const DB_PASSWORD: &str = "SYNTHETIC_SELECTED_DATABASE";
const KEY_PASSPHRASE: &str = "SYNTHETIC_SELECTED_PASSPHRASE";
const TARGET_PASSWORD: &str = "SYNTHETIC_TARGET_\\\"中🔐";
const UNRELATED: &str = "SYNTHETIC_UNRELATED_SECRET";

fn metadata() -> Json {
    json!({"schema_version":1,"target_session_id":TARGET,"route":[
        {"session_id":OUTER,"host":"192.0.2.10","port":22,"user":"fixture","auth":"key"},
        {"session_id":TARGET,"host":"198.51.100.20","port":22,"user":"fixture","auth":"password"}
    ]})
}
fn plan() -> Json {
    json!({"format":"dbx-meatshell-import-plan","version":1,"source_connection_id":SOURCE,
        "new_connection_id":CANDIDATE,"new_connection_name":"Synthetic independent production",
        "host":"database.example.invalid","port":5432,"database":"synthetic_release",
        "username":"fixture","is_production":true,"ssl":false,"expected_export":metadata()})
}
fn request(include_secret: bool) -> ImportRequest {
    let mut export = metadata();
    if include_secret {
        export["route"][1]["password"] = json!(TARGET_PASSWORD);
    }
    parse_request(&serde_json::to_vec(&plan()).unwrap(), &serde_json::to_vec(&export).unwrap()).unwrap()
}
fn source() -> ConnectionConfig {
    serde_json::from_value(json!({"id":SOURCE,"name":"Synthetic original","db_type":"postgres",
    "host":"database.example.invalid","port":5432,"database":"synthetic_original","username":"fixture",
    "password":DB_PASSWORD,"read_only":true,"save_password":true,"is_production":false,"ssl":true,
    "note":"do not copy this","init_script":UNRELATED,"connection_string":UNRELATED,
    "transport_layers":[
        {"type":"ssh","id":"first-layer","name":"Synthetic first","enabled":true,
         "host":"192.0.2.10","port":22,"user":"fixture","auth_method":"key","password":"",
         "key_path":"/synthetic/key-never-opened","key_passphrase":KEY_PASSPHRASE,"connect_timeout_secs":7,
         "expose_lan":false,"use_ssh_agent":false},
        {"type":"ssh","id":"old-wrong-hop","enabled":true,"host":"203.0.113.99","port":22,
         "user":"fixture","auth_method":"password","password":UNRELATED}
    ]}))
    .unwrap()
}
async fn fixture() -> (tempfile::TempDir, Storage) {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // tempfile uses platform-default directory permissions. This test
        // explicitly provisions the private profile required by the bridge.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let storage = test_storage::open(&dir.path().join("dbx.db")).await.unwrap();
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    storage.add_connection_for_mcp(source()).await.unwrap();
    let mut unrelated = source();
    unrelated.id = "unrelated-native-fixture".into();
    unrelated.name = "Synthetic unrelated".into();
    unrelated.password = UNRELATED.into();
    storage.add_connection_for_mcp(unrelated).await.unwrap();
    (dir, storage)
}
async fn snapshot(
    storage: &Storage,
) -> (Vec<(String, String)>, Vec<(String, String, String, Option<String>)>, Option<String>, String) {
    storage
        .with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT id,config_json FROM connections ORDER BY id").unwrap();
            let connections = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let mut stmt = conn
                .prepare(
                    "SELECT connection_id,key,secret,secret_enc FROM connection_secrets ORDER BY connection_id,key",
                )
                .unwrap();
            let secrets = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let layout = conn
                .query_row("SELECT layout_json FROM sidebar_layout WHERE id=1", [], |row| row.get(0))
                .optional()
                .unwrap();
            let policy =
                serde_json::to_string(&load_mcp_global_policy_in_tx(&conn.unchecked_transaction().unwrap()).unwrap())
                    .unwrap();
            Ok((connections, secrets, layout, policy))
        })
        .await
        .unwrap()
}
async fn corrupt(storage: &Storage, id: &str, key: &str) {
    let id = id.to_owned();
    let key = key.to_owned();
    storage.with_conn(move |conn| {
        conn.execute("UPDATE connection_secrets SET secret_enc='SYNTHETIC_INVALID_ENVELOPE' WHERE connection_id=?1 AND key=?2",params![id,key]).unwrap();
        Ok(())
    }).await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn bridge_preview_reads_no_source_secret_and_never_provisions_missing_key() {
    let (dir, storage) = fixture().await;
    corrupt(&storage, SOURCE, "password").await;
    let before = snapshot(&storage).await;
    let key = managed_key_path(dir.path());
    std::fs::remove_file(&key).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let db_path = dir.path().join("dbx.db");
        let db = db_path.symlink_metadata().unwrap();
        let directory = dir.path().symlink_metadata().unwrap();
        assert_eq!(db.uid(), unsafe { libc::geteuid() }, "fixture DB owner");
        assert_eq!(directory.uid(), unsafe { libc::geteuid() }, "fixture directory owner");
        assert_eq!(db.mode() & 0o077, 0, "fixture DB is private");
        assert_eq!(directory.mode() & 0o077, 0, "fixture directory is private");
        for ancestor in db_path.ancestors() {
            assert!(!ancestor.symlink_metadata().unwrap().file_type().is_symlink(), "fixture ancestor is not symlink");
        }
        crate::db::sqlite::connect_path(db_path.to_str().unwrap()).await.expect("native existing fixture opens");
    }
    let fresh = Storage::open_for_meatshell_import(&dir.path().join("dbx.db"))
        .await
        .unwrap()
        .with_secret_key_policy(SecretKeyPolicy::TestDataDir);
    assert!(fresh.import_meatshell(request(true), true).await.unwrap_err().starts_with("INVALID_MEATSHELL_IMPORT:"));
    let report = fresh.import_meatshell(request(false), true).await.unwrap();
    assert!(report.dry_run);
    assert_eq!(report.imported_count, 0);
    assert_eq!(report.planned_count, 1);
    assert!(!report.source_credentials_resolved);
    assert!(report.connection_id.is_none());
    assert_eq!(snapshot(&fresh).await, before);
    assert!(!key.exists());
    assert!(fresh
        .import_meatshell(request(true), false)
        .await
        .unwrap_err()
        .starts_with("MEATSHELL_SECRET_UNAVAILABLE:"));
    assert_eq!(snapshot(&fresh).await, before);
    assert!(!key.exists());
}

#[tokio::test]
async fn bridge_apply_rewraps_exact_selected_credentials_and_preserves_every_existing_row() {
    let (dir, storage) = fixture().await;
    // Broken unrelated ciphertext makes a broad hydrator fail, proving the
    // bridge never decrypts unrelated DSNs, source old hops, or other records.
    corrupt(&storage, "unrelated-native-fixture", "password").await;
    corrupt(&storage, "unrelated-native-fixture", "connection_string").await;
    corrupt(&storage, SOURCE, "connection_string").await;
    corrupt(&storage, SOURCE, "transport_layers.old-wrong-hop.ssh_password").await;
    let before = snapshot(&storage).await;
    let key_before = std::fs::read(managed_key_path(dir.path())).unwrap();
    let report = storage.import_meatshell(request(true), false).await.unwrap();
    assert_eq!(report.imported_count, 1);
    assert!(report.source_credentials_resolved);
    let id = report.connection_id.unwrap();
    assert_ne!(id, SOURCE);
    assert_ne!(id, CANDIDATE);
    let after = snapshot(&storage).await;
    assert_eq!(after.0.len(), before.0.len() + 1);
    for row in &before.0 {
        assert!(after.0.contains(row));
    }
    for row in &before.1 {
        assert!(after.1.contains(row));
    }
    assert_eq!(after.3, before.3);
    assert_eq!(std::fs::read(managed_key_path(dir.path())).unwrap(), key_before);
    let config: ConnectionConfig =
        serde_json::from_str(&after.0.iter().find(|(key, _)| key == &id).unwrap().1).unwrap();
    assert!(config.is_production);
    assert!(config.read_only);
    assert!(!config.ssl);
    assert_eq!(config.database.as_deref(), Some("synthetic_release"));
    assert_eq!(config.password, "");
    assert_eq!(config.transport_layers.len(), 2);
    assert!(config.note.is_empty());
    assert!(config.init_script.is_none());
    assert!(config.connection_string.is_none());
    let TransportLayerConfig::Ssh(first) = &config.transport_layers[0] else {
        panic!("expected SSH");
    };
    let TransportLayerConfig::Ssh(target) = &config.transport_layers[1] else {
        panic!("expected SSH");
    };
    assert_eq!(first.host, "192.0.2.10");
    assert_eq!(first.key_path, "/synthetic/key-never-opened");
    assert_eq!(first.auth_method, "key");
    assert_eq!(first.connect_timeout_secs, 7);
    assert_eq!(target.host, "198.51.100.20");
    assert_eq!(target.auth_method, "password");
    assert!(first.password.is_empty() && first.key_passphrase.is_empty() && target.password.is_empty());
    assert!(!first.expose_lan && !target.expose_lan && !first.use_ssh_agent && !target.use_ssh_agent);
    assert_eq!(storage.get_secret(&id, "password").await.unwrap().as_deref(), Some(DB_PASSWORD));
    assert_eq!(
        storage
            .get_secret(&id, &transport_layer_ssh_key_passphrase_key(0, &config.transport_layers[0]))
            .await
            .unwrap()
            .as_deref(),
        Some(KEY_PASSPHRASE)
    );
    assert_eq!(
        storage
            .get_secret(&id, &transport_layer_ssh_password_key(1, &config.transport_layers[1]))
            .await
            .unwrap()
            .as_deref(),
        Some(TARGET_PASSWORD)
    );
    let new_secrets: Vec<_> = after.1.iter().filter(|row| row.0 == id).collect();
    assert_eq!(new_secrets.len(), 3);
    assert!(new_secrets.iter().all(|row| row.2.is_empty() && row.3.as_deref().is_some_and(|s| !s.is_empty())));
    let saved = snapshot(&storage).await;
    assert!(storage
        .import_meatshell(request(true), false)
        .await
        .unwrap_err()
        .starts_with("CONNECTION_ALREADY_EXISTS:"));
    assert_eq!(snapshot(&storage).await, saved);
}

#[tokio::test]
async fn bridge_rejects_bad_source_credentials_without_changes() {
    for key in ["password", "transport_layers.first-layer.ssh_key_passphrase"] {
        let (_dir, storage) = fixture().await;
        corrupt(&storage, SOURCE, key).await;
        let before = snapshot(&storage).await;
        let error = storage.import_meatshell(request(true), false).await.unwrap_err();
        assert!(error.starts_with("MEATSHELL_SECRET_UNAVAILABLE:"));
        assert_eq!(snapshot(&storage).await, before);
    }
}

#[tokio::test]
async fn bridge_rejects_selected_legacy_plaintext_instead_of_migrating_it() {
    let (_dir, storage) = fixture().await;
    storage
        .with_conn(|conn| {
            conn.execute(
                "UPDATE connection_secrets SET secret=?1,secret_enc=NULL WHERE connection_id=?2 AND key='password'",
                params![DB_PASSWORD, SOURCE],
            )
            .unwrap();
            Ok(())
        })
        .await
        .unwrap();
    let before = snapshot(&storage).await;
    assert!(storage
        .import_meatshell(request(true), false)
        .await
        .unwrap_err()
        .starts_with("MEATSHELL_SECRET_UNAVAILABLE:"));
    assert_eq!(snapshot(&storage).await, before);
}

#[tokio::test]
async fn bridge_rolls_back_after_config_and_secret_inserts_when_layout_fails() {
    let (_dir, storage) = fixture().await;
    storage.with_conn(|conn| {
        conn.execute_batch("CREATE TRIGGER reject_new_fixture_layout BEFORE INSERT ON sidebar_layout BEGIN SELECT RAISE(ABORT,'SYNTHETIC_TRIGGER_DETAIL'); END;").unwrap(); Ok(())
    }).await.unwrap();
    let before = snapshot(&storage).await;
    let error = storage.import_meatshell(request(true), false).await.unwrap_err();
    assert_eq!(error, meatshell_import::store_error());
    assert!(!error.contains("SYNTHETIC_TRIGGER_DETAIL"));
    assert_eq!(snapshot(&storage).await, before);
}

#[tokio::test]
async fn bridge_enforces_native_policy_before_secrets_and_preserves_read_only_preview() {
    for (policy, code, preview_allowed) in [
        (McpGlobalPolicy { read_only: true, ..Default::default() }, "MCP_READ_ONLY:", true),
        (
            McpGlobalPolicy {
                read_only: false,
                allowed_tool_names: Some(vec!["dbx_list_connections".into()]),
                ..Default::default()
            },
            "TOOL_OUT_OF_SCOPE:",
            false,
        ),
        (
            McpGlobalPolicy {
                read_only: false,
                allowed_connection_ids: Some(vec![SOURCE.into()]),
                ..Default::default()
            },
            "CONNECTION_OUT_OF_SCOPE:",
            false,
        ),
    ] {
        let (_dir, storage) = fixture().await;
        storage.save_mcp_global_policy(&policy).await.unwrap();
        corrupt(&storage, SOURCE, "password").await;
        let before = snapshot(&storage).await;
        let preview = storage.import_meatshell(request(false), true).await;
        assert_eq!(preview.is_ok(), preview_allowed);
        assert!(storage.import_meatshell(request(true), false).await.unwrap_err().starts_with(code));
        assert_eq!(snapshot(&storage).await, before);
    }
}

#[tokio::test]
async fn bridge_rejects_source_route_account_and_candidate_collisions() {
    for mutation in 0..7 {
        let (_dir, storage) = fixture().await;
        let mut plan = plan();
        match mutation {
            0 => plan["source_connection_id"] = json!("missing-source"),
            1 => plan["host"] = json!("wrong.example.invalid"),
            2 => plan["username"] = json!("wrong_user"),
            3 => plan["port"] = json!(5433),
            4 => plan["new_connection_id"] = json!("unrelated-native-fixture"),
            5 => plan["new_connection_name"] = json!("Synthetic unrelated"),
            _ => {
                storage.with_conn(|conn| { conn.execute("UPDATE connections SET config_json=json_set(config_json,'$.transport_layers[0].profile_id','shared') WHERE id=?1",[SOURCE]).unwrap(); Ok(()) }).await.unwrap();
            }
        }
        let mut export = metadata();
        export["route"][1]["password"] = json!(TARGET_PASSWORD);
        let request =
            parse_request(&serde_json::to_vec(&plan).unwrap(), &serde_json::to_vec(&export).unwrap()).unwrap();
        let before = snapshot(&storage).await;
        assert!(storage.import_meatshell(request, false).await.is_err());
        assert_eq!(snapshot(&storage).await, before);
    }
}

#[test]
fn bridge_strict_contract_rejects_secrets_in_plan_unknown_fields_and_route_changes() {
    for mutation in 0..7 {
        let mut plan = plan();
        let mut export = metadata();
        match mutation {
            0 => plan["password"] = json!(TARGET_PASSWORD),
            1 => plan["expected_export"]["route"][1]["password"] = json!(TARGET_PASSWORD),
            2 => plan["is_production"] = json!(false),
            3 => plan["ssl"] = json!(true),
            4 => export["route"][0]["password"] = json!(UNRELATED),
            5 => export["route"][1]["host"] = json!("wrong.example.invalid"),
            _ => export["note"] = json!(UNRELATED),
        }
        assert!(parse_request(&serde_json::to_vec(&plan).unwrap(), &serde_json::to_vec(&export).unwrap()).is_err());
    }
    assert_eq!(request(true).target_password().unwrap().as_str(), TARGET_PASSWORD);
    assert!(request(false).target_password().is_err());
}

#[tokio::test]
async fn bridge_rejects_boolean_ports_instead_of_coercing_them_to_one() {
    for source_port in [true, false] {
        let (_dir, storage) = fixture().await;
        let mut plan = plan();
        let mut export = metadata();
        if source_port {
            plan["port"] = json!(1);
        } else {
            plan["expected_export"]["route"][0]["port"] = json!(1);
            export["route"][0]["port"] = json!(1);
        }
        storage
            .with_conn(move |conn| {
                let path = if source_port { "$.port" } else { "$.transport_layers[0].port" };
                conn.execute(
                    "UPDATE connections SET config_json=json_set(config_json,?1,json('true')) WHERE id=?2",
                    params![path, SOURCE],
                )
                .unwrap();
                Ok(())
            })
            .await
            .unwrap();
        let request =
            parse_request(&serde_json::to_vec(&plan).unwrap(), &serde_json::to_vec(&export).unwrap()).unwrap();
        let before = snapshot(&storage).await;
        assert!(storage.import_meatshell(request, true).await.unwrap_err().starts_with("MEATSHELL_SOURCE_MISMATCH:"));
        assert_eq!(snapshot(&storage).await, before);
    }
}
