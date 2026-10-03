use super::*;
use crate::persistence::{route_update::parse_request, secret_codec::managed_key_path, test_storage};
use serde_json::{json, Value};

const ID: &str = "route-fixture";
const KEY: &str = "transport_layers.second.ssh_password";
const PASSWORD: &str = "SYNTHETIC_TARGET_\\\"中🔐";

fn export() -> Value {
    json!({"schema_version":1,"target_session_id":"selected-target","route":[
        {"session_id":"selected-outer","host":"192.0.2.10","port":22,"user":"fixture","auth":"key"},
        {"session_id":"selected-target","host":"198.51.100.20","port":22,"user":"fixture","auth":"password"}
    ]})
}
fn plan() -> Value {
    json!({"format":"dbx-route-update-plan","version":1,"connection_id":ID,
        "expected":{"host":"old-db.invalid","port":5432,"database":"old-db","ssl":true,"username":"fixture",
            "transport_layers":[
                {"id":"first","host":"192.0.2.10","port":22,"user":"fixture","auth_method":"key"},
                {"id":"second","host":"203.0.113.99","port":22,"user":"fixture","auth_method":"password"}]},
        "changes":{"host":"internal-db.invalid","database":"synthetic_release","ssl":false,"second_hop_name":"New target"},
        "expected_export":export()})
}
fn request(plan: &Value, password: Option<Value>) -> RouteUpdateRequest {
    let mut export = plan["expected_export"].clone();
    if let Some(password) = password {
        export["route"][1]["password"] = password;
    }
    parse_request(&serde_json::to_vec(plan).unwrap(), &serde_json::to_vec(&export).unwrap()).unwrap()
}
async fn fixture() -> (tempfile::TempDir, Storage) {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let storage = test_storage::open(&dir.path().join("dbx.db")).await.unwrap();
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    let config: ConnectionConfig =
        serde_json::from_value(json!({"id":ID,"name":"Synthetic original","db_type":"postgres",
        "host":"old-db.invalid","port":5432,"database":"old-db","username":"fixture","ssl":true,
        "password":"SYNTHETIC_DB_PASSWORD","url_params":"secret=SYNTHETIC_URL","save_password":true,
        "transport_layers":[
            {"type":"ssh","id":"first","host":"192.0.2.10","port":22,"user":"fixture","auth_method":"key",
             "key_path":"/synthetic/key-never-opened","key_passphrase":"SYNTHETIC_PASSPHRASE"},
            {"type":"ssh","id":"second","name":"Old target","host":"203.0.113.99","port":22,
             "user":"fixture","auth_method":"password","password":"SYNTHETIC_OLD"}]}))
        .unwrap();
    storage.save_connections(std::slice::from_ref(&config)).await.unwrap();
    let mut other = config;
    other.id = "other".into();
    storage.save_connections(&[other]).await.unwrap();
    storage.with_conn(|conn| {
        // Unknown, future settings and an unreadable other profile must survive.
        conn.execute("UPDATE connections SET config_json=json_set(config_json,'$.future',json('{\"opaque\":true}'),'$.transport_layers[0].future',42) WHERE id=?1",[ID]).unwrap();
        conn.execute("INSERT INTO connections(id,config_json) VALUES('future-driver','{\"future\":42}')",[]).unwrap();
        conn.execute("INSERT INTO tunnel_profiles(id,config_json) VALUES('untouched','{}')",[]).unwrap();
        Ok(())
    }).await.unwrap();
    (dir, storage)
}

type Snapshot = (Vec<(String, String)>, Vec<(String, String, String, Option<String>)>, Vec<(String, String)>, String);
async fn snapshot(storage: &Storage) -> Snapshot {
    storage
        .with_conn(|conn| {
            let mut stmt = conn.prepare("SELECT id,config_json FROM connections ORDER BY id").unwrap();
            let configs = stmt
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
            let mut stmt = conn.prepare("SELECT id,config_json FROM tunnel_profiles ORDER BY id").unwrap();
            let profiles = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let settings =
                conn.query_row("SELECT settings_json FROM app_settings WHERE id=1", [], |row| row.get(0)).unwrap();
            Ok((configs, secrets, profiles, settings))
        })
        .await
        .unwrap()
}
fn config(snapshot: &Snapshot) -> Value {
    serde_json::from_str(&snapshot.0.iter().find(|(id, _)| id == ID).unwrap().1).unwrap()
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn route_preview_is_nonmutating_without_a_key_or_credential_reads() {
    let (dir, storage) = fixture().await;
    let before = snapshot(&storage).await;
    let key = managed_key_path(dir.path());
    std::fs::remove_file(&key).unwrap();
    let reopened = Storage::open_for_meatshell_import(&dir.path().join("dbx.db"))
        .await
        .unwrap()
        .with_secret_key_policy(SecretKeyPolicy::TestDataDir);
    let report = reopened.update_route(request(&plan(), None), true).await.unwrap();
    assert!(report.dry_run && !report.updated && !report.target_password_changed);
    assert_eq!(snapshot(&reopened).await, before);
    assert!(!key.exists());
    let error = reopened.update_route(request(&plan(), Some(json!(PASSWORD))), false).await.unwrap_err();
    assert!(error.starts_with("ROUTE_SECRET_UNAVAILABLE:"));
    assert_eq!(snapshot(&reopened).await, before);
    assert!(!key.exists());
}

#[tokio::test]
async fn route_apply_preserves_original_id_unknown_fields_and_unselected_ciphertext() {
    let (dir, storage) = fixture().await;
    // Unrelated/corrupt ciphertext must not be loaded, decrypted or rewritten.
    storage.with_conn(|conn| {conn.execute("UPDATE connection_secrets SET secret_enc='SYNTHETIC_INVALID' WHERE connection_id='other' OR key='url_params'",[]).unwrap();Ok(())}).await.unwrap();
    let before = snapshot(&storage).await;
    let key = std::fs::read(managed_key_path(dir.path())).unwrap();
    let report = storage.update_route(request(&plan(), Some(json!(PASSWORD))), false).await.unwrap();
    assert!(report.updated && report.target_password_changed && !report.database_connection_attempted);
    let output = serde_json::to_string(&report).unwrap();
    assert!(!output.contains(PASSWORD) && !output.contains("key-never-opened"));
    let after = snapshot(&storage).await;
    let mut expected = config(&before);
    expected["host"] = json!("internal-db.invalid");
    expected["database"] = json!("synthetic_release");
    expected["ssl"] = json!(false);
    expected["transport_layers"][1]["host"] = json!("198.51.100.20");
    expected["transport_layers"][1]["name"] = json!("New target");
    assert_eq!(config(&after), expected);
    assert_eq!(before.0.len(), after.0.len());
    for row in &before.0 {
        if row.0 != ID {
            assert!(after.0.contains(row));
        }
    }
    for row in &before.1 {
        if row.0 != ID || row.1 != KEY {
            assert!(after.1.contains(row));
        }
    }
    assert_eq!(before.1.len(), after.1.len());
    assert_eq!(before.2, after.2);
    assert_eq!(before.3, after.3);
    assert_eq!(std::fs::read(managed_key_path(dir.path())).unwrap(), key);
    assert_eq!(storage.get_secret(ID, KEY).await.unwrap().as_deref(), Some(PASSWORD));
    // The approved old route is an optimistic concurrency guard, not a reusable overwrite.
    assert!(storage
        .update_route(request(&plan(), Some(json!(PASSWORD))), false)
        .await
        .unwrap_err()
        .starts_with("ROUTE_SOURCE_MISMATCH:"));
    assert_eq!(snapshot(&storage).await, after);
}

#[tokio::test]
async fn route_omitted_database_and_password_stay_untouched_but_explicit_empty_clears() {
    let (_dir, storage) = fixture().await;
    let mut plan = plan();
    plan["changes"] = json!({});
    plan["expected_export"]["route"][1]["host"] = json!("203.0.113.99");
    let before = snapshot(&storage).await;
    storage.update_route(request(&plan, None), false).await.unwrap();
    let after = snapshot(&storage).await;
    assert_eq!(config(&after), config(&before));
    assert_eq!(after.1, before.1);
    storage.with_conn(|conn| {
        conn.execute("INSERT INTO connection_secrets(connection_id,key,secret,secret_enc) VALUES(?1,'ssh_tunnels.second.password','SYNTHETIC_LEGACY',NULL)",[ID]).unwrap();Ok(())
    }).await.unwrap();
    plan["changes"] = json!({"database":null,"second_hop_name":""});
    storage.update_route(request(&plan, Some(json!(""))), false).await.unwrap();
    let after = snapshot(&storage).await;
    assert!(config(&after)["database"].is_null());
    assert_eq!(config(&after)["transport_layers"][1]["name"], "");
    assert!(!after.1.iter().any(|row| row.0 == ID && (row.1 == KEY || row.1 == "ssh_tunnels.second.password")));
    plan["expected"]["database"] = Value::Null;
    storage.update_route(request(&plan, Some(json!(""))), false).await.unwrap();
    assert_eq!(snapshot(&storage).await, after);
}

#[tokio::test]
async fn route_wrong_existing_key_fails_without_creating_a_mixed_key_profile() {
    let (dir, storage) = fixture().await;
    let (other_dir, _other) = fixture().await;
    let before = snapshot(&storage).await;
    let path = managed_key_path(dir.path());
    let original = std::fs::read(&path).unwrap();
    std::fs::write(&path, std::fs::read(managed_key_path(other_dir.path())).unwrap()).unwrap();
    let error = storage.update_route(request(&plan(), Some(json!(PASSWORD))), false).await.unwrap_err();
    assert_eq!(error, route_update::secret_error());
    assert_eq!(snapshot(&storage).await, before);
    std::fs::write(path, original).unwrap();
    assert_eq!(storage.get_secret(ID, KEY).await.unwrap().as_deref(), Some("SYNTHETIC_OLD"));
}

#[tokio::test]
async fn route_failure_after_config_write_rolls_back_config_and_secrets_without_echo() {
    let (_dir, storage) = fixture().await;
    storage.with_conn(|conn| {
        conn.execute_batch("CREATE TRIGGER reject_route_secret BEFORE INSERT ON connection_secrets BEGIN SELECT RAISE(ABORT,'SYNTHETIC_SENSITIVE_FAILURE'); END;").unwrap();Ok(())
    }).await.unwrap();
    let before = snapshot(&storage).await;
    let error = storage.update_route(request(&plan(), Some(json!(PASSWORD))), false).await.unwrap_err();
    assert_eq!(error, route_update::store_error());
    assert!(!error.contains(PASSWORD) && !error.contains("SENSITIVE"));
    assert_eq!(snapshot(&storage).await, before);
}

#[tokio::test]
async fn route_rejects_null_or_missing_replacement_password_bad_metadata_and_shared_profiles() {
    let (_dir, storage) = fixture().await;
    let before = snapshot(&storage).await;
    for password in [None, Some(Value::Null), Some(json!(42)), Some(json!("enc:synthetic"))] {
        assert!(storage.update_route(request(&plan(), password), false).await.is_err());
        assert_eq!(snapshot(&storage).await, before);
    }
    assert!(storage.update_route(request(&plan(), Some(json!(PASSWORD))), true).await.is_err());
    let mut stale = plan();
    stale["expected"]["transport_layers"][1]["id"] = json!("wrong-id");
    assert!(storage.update_route(request(&stale, Some(json!(PASSWORD))), false).await.is_err());
    assert_eq!(snapshot(&storage).await, before);
    storage.with_conn(|conn| {conn.execute("UPDATE connections SET config_json=json_set(config_json,'$.transport_layers[1].profile_id','shared') WHERE id=?1",[ID]).unwrap();Ok(())}).await.unwrap();
    let before = snapshot(&storage).await;
    assert!(storage.update_route(request(&plan(), Some(json!(PASSWORD))), false).await.is_err());
    assert_eq!(snapshot(&storage).await, before);
}

#[tokio::test]
async fn route_rejects_null_or_wrong_type_fields_in_the_saved_route() {
    for (path, value) in [
        ("$.transport_layers[0].key_path", json!(42)),
        ("$.transport_layers[0].enabled", Value::Null),
        ("$.transport_layers[1].enabled", json!(1)),
        ("$.transport_layers[1].profile_id", Value::Null),
        ("$.transport_layers[0].password", Value::Null),
    ] {
        let (_dir, storage) = fixture().await;
        storage
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE connections SET config_json=json_set(config_json,?1,json(?2)) WHERE id=?3",
                    params![path, value.to_string(), ID],
                )
                .unwrap();
                Ok(())
            })
            .await
            .unwrap();
        let before = snapshot(&storage).await;
        assert!(storage
            .update_route(request(&plan(), None), true)
            .await
            .unwrap_err()
            .starts_with("ROUTE_SOURCE_MISMATCH:"));
        assert_eq!(snapshot(&storage).await, before);
    }
}

#[tokio::test]
async fn route_rejects_boolean_ports_instead_of_coercing_them_to_one() {
    for (index, path) in ["$.port", "$.transport_layers[0].port", "$.transport_layers[1].port"].into_iter().enumerate()
    {
        let (_dir, storage) = fixture().await;
        let mut plan = plan();
        match index {
            0 => plan["expected"]["port"] = json!(1),
            1 => {
                plan["expected"]["transport_layers"][0]["port"] = json!(1);
                plan["expected_export"]["route"][0]["port"] = json!(1);
            }
            _ => plan["expected"]["transport_layers"][1]["port"] = json!(1),
        }
        storage
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE connections SET config_json=json_set(config_json,?1,json('true')) WHERE id=?2",
                    params![path, ID],
                )
                .unwrap();
                Ok(())
            })
            .await
            .unwrap();
        let before = snapshot(&storage).await;
        for dry_run in [true, false] {
            let password = (!dry_run).then(|| json!(PASSWORD));
            assert!(storage
                .update_route(request(&plan, password), dry_run)
                .await
                .unwrap_err()
                .starts_with("ROUTE_SOURCE_MISMATCH:"));
            assert_eq!(snapshot(&storage).await, before);
        }
    }
}

#[test]
fn route_contract_rejects_unknown_fields_secret_plan_and_invalid_empty_values() {
    for changes in [
        json!({"password":"SYNTHETIC_SECRET"}),
        json!({"host":""}),
        json!({"ssl":null}),
        json!({"port":0}),
        json!({"transport_layers":[]}),
    ] {
        let mut plan = plan();
        plan["changes"] = changes;
        let error =
            parse_request(&serde_json::to_vec(&plan).unwrap(), &serde_json::to_vec(&export()).unwrap()).err().unwrap();
        assert_eq!(error, route_update::invalid());
        assert!(!error.contains("SYNTHETIC_SECRET"));
    }
    let mut export = export();
    export["route"][0]["password"] = Value::Null;
    assert!(parse_request(&serde_json::to_vec(&plan()).unwrap(), &serde_json::to_vec(&export).unwrap()).is_err());
}

#[tokio::test]
async fn route_global_id_allowlist_permits_listed_target_without_changing_policy() {
    for allowed_tool_names in [None, Some(vec!["dbx_update_connection".into()])] {
        let (_dir, storage) = fixture().await;
        let policy = McpGlobalPolicy {
            read_only: false,
            allowed_connection_ids: Some(vec![ID.into(), "permitted-peer".into()]),
            allowed_tool_names,
            query_timeout_secs: Some(45),
            ..Default::default()
        };
        storage.save_mcp_global_policy(&policy).await.unwrap();
        let before = snapshot(&storage).await;
        let preview = storage.update_route(request(&plan(), None), true).await.unwrap();
        assert!(preview.dry_run && !preview.updated && !preview.database_connection_attempted);
        assert_eq!(snapshot(&storage).await, before);

        let report = storage.update_route(request(&plan(), Some(json!(PASSWORD))), false).await.unwrap();
        assert!(report.updated && report.target_password_changed && !report.database_connection_attempted);
        assert_eq!(report.connection_id, ID);
        let after = snapshot(&storage).await;
        assert_eq!(config(&after)["database"], "synthetic_release");
        assert_eq!(storage.load_mcp_global_policy().await.unwrap().policy(), policy.normalized());
        assert_eq!(before.3, after.3);
        assert_eq!(before.2, after.2);
        assert_eq!(before.0.len(), after.0.len());
        assert_eq!(before.1.len(), after.1.len());
        for row in &before.0 {
            if row.0 != ID {
                assert!(after.0.contains(row));
            }
        }
        for row in &before.1 {
            if row.0 != ID || row.1 != KEY {
                assert!(after.1.contains(row));
            }
        }
        assert_eq!(storage.get_secret(ID, KEY).await.unwrap().as_deref(), Some(PASSWORD));
    }
}

#[tokio::test]
async fn route_preview_and_apply_reject_excluded_ids_empty_allowlists_groups_and_forbidden_tools() {
    let (_dir, storage) = fixture().await;
    for (policy, expected) in [
        (
            McpGlobalPolicy { allowed_connection_ids: Some(vec!["other".into()]), ..Default::default() },
            "CONNECTION_OUT_OF_SCOPE:",
        ),
        (McpGlobalPolicy { allowed_connection_ids: Some(vec![]), ..Default::default() }, "CONNECTION_OUT_OF_SCOPE:"),
        (
            McpGlobalPolicy {
                allowed_connection_ids: Some(vec![ID.into()]),
                allowed_group_ids: vec!["synthetic-group".into()],
                ..Default::default()
            },
            "CONNECTION_OUT_OF_SCOPE:",
        ),
        (
            McpGlobalPolicy {
                allowed_connection_ids: Some(vec![ID.into()]),
                allowed_tool_names: Some(vec!["dbx_list_connections".into()]),
                ..Default::default()
            },
            "TOOL_OUT_OF_SCOPE:",
        ),
        (
            McpGlobalPolicy {
                allowed_connection_ids: Some(vec![ID.into()]),
                allowed_tool_names: Some(vec![]),
                ..Default::default()
            },
            "TOOL_OUT_OF_SCOPE:",
        ),
    ] {
        storage.save_mcp_global_policy(&policy).await.unwrap();
        let before = snapshot(&storage).await;
        for dry_run in [true, false] {
            let password = (!dry_run).then(|| json!(PASSWORD));
            let error = storage.update_route(request(&plan(), password), dry_run).await.unwrap_err();
            assert!(error.starts_with(expected), "{error}");
            assert_eq!(snapshot(&storage).await, before);
        }
    }
}

#[tokio::test]
async fn route_apply_enforces_global_read_only_even_for_listed_target_without_mutation() {
    let (_dir, storage) = fixture().await;
    for allowed_connection_ids in [None, Some(vec![ID.into()])] {
        let policy = McpGlobalPolicy { read_only: true, allowed_connection_ids, ..Default::default() };
        storage.save_mcp_global_policy(&policy).await.unwrap();
        let before = snapshot(&storage).await;
        // Read-only mode permits metadata preview, but never route mutation.
        assert!(storage.update_route(request(&plan(), None), true).await.unwrap().dry_run);
        let error = storage.update_route(request(&plan(), Some(json!(PASSWORD))), false).await.unwrap_err();
        assert!(error.starts_with("MCP_READ_ONLY:"), "{error}");
        assert_eq!(snapshot(&storage).await, before);
    }
}
