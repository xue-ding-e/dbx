//! Real CLI process boundaries against synthetic private profiles only.
use dbx_core::{
    models::connection::ConnectionConfig,
    persistence::{secret_codec::managed_key_path, test_storage},
    storage::McpGlobalPolicy,
};
use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

fn command(directory: &std::path::Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dbx"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", directory)
        .env("XDG_CONFIG_HOME", directory)
        .env("XDG_DATA_HOME", directory)
        .env("DBX_DATA_DIR", directory)
        .env("DBX_SECRET_KEY_FILE", managed_key_path(directory))
        .args(["connections", "update-route", "--plan"])
        .arg(directory.join("plan.json"))
        .args(["--file", "-", "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}
fn invoke(mut command: Command, input: &Value) -> Output {
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(&serde_json::to_vec(input).unwrap()).unwrap();
    child.wait_with_output().unwrap()
}
fn code(output: &Output) -> String {
    assert!(!output.status.success());
    serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"]["code"].as_str().unwrap().into()
}

#[test]
fn route_cli_rejects_remote_scope_and_run_write_prohibition_before_opening_profile() {
    for (name, value, expected) in [
        ("DBX_WEB_URL", "http://127.0.0.1:1", "ROUTE_UPDATE_UNSUPPORTED"),
        ("DBX_MCP_SCOPE_CONNECTION_ID", "synthetic", "CONNECTION_OUT_OF_SCOPE"),
        ("DBX_MCP_SCOPE_CONNECTION_IDS", "synthetic,other", "CONNECTION_OUT_OF_SCOPE"),
        ("DBX_MCP_SCOPE_CONNECTION_NAME", "synthetic", "CONNECTION_OUT_OF_SCOPE"),
        ("DBX_MCP_SCOPE_DATABASE", "synthetic", "CONNECTION_OUT_OF_SCOPE"),
        ("DBX_MCP_SCOPE_SCHEMA", "synthetic", "CONNECTION_OUT_OF_SCOPE"),
        ("DBX_MCP_ALLOW_WRITES", "false", "MCP_READ_ONLY"),
    ] {
        for apply in [false, true] {
            if name == "DBX_MCP_ALLOW_WRITES" && !apply {
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let mut cmd = command(dir.path());
            cmd.env(name, value);
            if apply {
                cmd.arg("--yes");
            }
            let output = invoke(cmd, &json!({}));
            assert_eq!(code(&output), expected, "{name}, apply={apply}");
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn route_cli_defaults_to_preview_then_updates_original_id_with_no_secret_output() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let storage = test_storage::open(&dir.path().join("dbx.db")).await.unwrap();
    let allowed_ids = std::iter::once("fixture".to_string())
        .chain((1..=26).map(|index| format!("peer-{index:02}")))
        .collect::<Vec<_>>();
    let policy = McpGlobalPolicy { read_only: false, allowed_connection_ids: Some(allowed_ids), ..Default::default() };
    storage.save_mcp_global_policy(&policy).await.unwrap();
    let config:ConnectionConfig=serde_json::from_value(json!({"id":"fixture","name":"Synthetic","db_type":"postgres",
        "host":"db.invalid","port":5432,"database":"before","username":"fixture","password":"SYNTHETIC_DB","url_params":"sslmode=verify-full",
        "transport_layers":[
            {"id":"first","type":"ssh","host":"192.0.2.1","port":22,"user":"fixture","auth_method":"key","key_path":"/synthetic/key","key_passphrase":"SYNTHETIC_PASSPHRASE"},
            {"id":"second","type":"ssh","host":"192.0.2.2","port":22,"user":"fixture","auth_method":"password","password":"SYNTHETIC_OLD"}]})).unwrap();
    // Mirror a 31-connection profile with 27 explicitly allowed IDs. The four
    // excluded peers and every unselected credential must remain unchanged.
    let mut configs = vec![config.clone()];
    for index in 1..=30 {
        let mut peer = config.clone();
        peer.id = format!("peer-{index:02}");
        configs.push(peer);
    }
    storage.save_connections(&configs).await.unwrap();
    let before = storage.load_connections().await.unwrap();
    let mut export = json!({"schema_version":1,"target_session_id":"target","route":[
        {"session_id":"outer","host":"192.0.2.1","port":22,"user":"fixture","auth":"key"},
        {"session_id":"target","host":"192.0.2.3","port":22,"user":"fixture","auth":"password"}]});
    let plan = json!({"format":"dbx-route-update-plan","version":1,"connection_id":"fixture",
        "expected":{"host":"db.invalid","port":5432,"database":"before","ssl":false,"username":"fixture","transport_layers":[
            {"id":"first","host":"192.0.2.1","port":22,"user":"fixture","auth_method":"key"},
            {"id":"second","host":"192.0.2.2","port":22,"user":"fixture","auth_method":"password"}]},
        "changes":{"database":"after"},"expected_export":export});
    let plan_path = dir.path().join("plan.json");
    std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&plan_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let output = invoke(command(dir.path()), &export);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["updated"], false);
    assert_eq!(storage.load_connections().await.unwrap(), before);
    assert_eq!(storage.load_mcp_global_policy().await.unwrap().policy(), policy);
    // A run-scoped invocation is rejected even if its target is globally allowed.
    for apply in [false, true] {
        let mut scoped = command(dir.path());
        scoped.env("DBX_MCP_SCOPE_CONNECTION_ID", "fixture");
        if apply {
            scoped.arg("--yes");
        }
        assert_eq!(code(&invoke(scoped, &export)), "CONNECTION_OUT_OF_SCOPE");
        assert_eq!(storage.load_connections().await.unwrap(), before);
        assert_eq!(storage.load_mcp_global_policy().await.unwrap().policy(), policy);
    }
    export["route"][1]["password"] = json!("SYNTHETIC_NEW_SECRET");
    let wrong = tempfile::tempdir().unwrap();
    let _wrong_storage = test_storage::open(&wrong.path().join("dbx.db")).await.unwrap();
    let mut wrong_cmd = command(dir.path());
    wrong_cmd.arg("--yes").env("DBX_SECRET_KEY_FILE", managed_key_path(wrong.path()));
    let wrong_output = invoke(wrong_cmd, &export);
    assert_eq!(code(&wrong_output), "ROUTE_SECRET_UNAVAILABLE");
    assert_eq!(storage.load_connections().await.unwrap(), before);
    let mut cmd = command(dir.path());
    cmd.arg("--yes");
    let output = invoke(cmd, &export);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["connection_id"], "fixture");
    assert_eq!(report["updated"], true);
    assert!(report.get("postgres_sslmode_changed").is_none());
    for stream in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains("SYNTHETIC_"));
    }
    let loaded = storage.load_connections().await.unwrap();
    assert_eq!(loaded.len(), 31);
    let updated = loaded.iter().find(|connection| connection.id == "fixture").unwrap();
    assert_eq!(updated.database.as_deref(), Some("after"));
    assert_eq!(updated.password, "SYNTHETIC_DB");
    for peer in before.iter().filter(|connection| connection.id != "fixture") {
        assert!(loaded.contains(peer));
    }
    assert_eq!(storage.load_mcp_global_policy().await.unwrap().policy(), policy);
    assert_eq!(
        storage.get_secret("fixture", "transport_layers.second.ssh_password").await.unwrap().as_deref(),
        Some("SYNTHETIC_NEW_SECRET")
    );

    // The opt-in TLS correction uses only nonsecret route metadata; it does not
    // replace any SSH/DB password or touch the four excluded connections.
    let mut tls_plan = plan.clone();
    tls_plan["expected"]["database"] = json!("after");
    tls_plan["expected"]["transport_layers"][1]["host"] = json!("192.0.2.3");
    tls_plan["changes"] = json!({"ssl":false});
    tls_plan["postgres_sslmode_cas"] = json!({"expected":"verify-full","replacement":"disable"});
    export["route"][1].as_object_mut().unwrap().remove("password");
    std::fs::write(&plan_path, serde_json::to_vec(&tls_plan).unwrap()).unwrap();
    let output = invoke(command(dir.path()), &export);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["postgres_sslmode_changed"], false);
    assert_eq!(report["target_password_changed"], false);
    assert_eq!(storage.load_connections().await.unwrap(), loaded);
    for apply in [false, true] {
        let mut wrong_cmd = command(dir.path());
        wrong_cmd.env("DBX_SECRET_KEY_FILE", managed_key_path(wrong.path()));
        if apply {
            wrong_cmd.arg("--yes");
        }
        assert_eq!(code(&invoke(wrong_cmd, &export)), "ROUTE_SECRET_UNAVAILABLE");
        assert_eq!(storage.load_connections().await.unwrap(), loaded);
        let mut scoped = command(dir.path());
        scoped.env("DBX_MCP_SCOPE_CONNECTION_ID", "fixture");
        if apply {
            scoped.arg("--yes");
        }
        assert_eq!(code(&invoke(scoped, &export)), "CONNECTION_OUT_OF_SCOPE");
        assert_eq!(storage.load_connections().await.unwrap(), loaded);
    }
    let mut cmd = command(dir.path());
    cmd.arg("--yes");
    let output = invoke(cmd, &export);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["postgres_sslmode_changed"], true);
    assert_eq!(report["target_password_changed"], false);
    assert_eq!(report["database_connection_attempted"], false);
    let mut expected = loaded.clone();
    expected.iter_mut().find(|connection| connection.id == "fixture").unwrap().url_params =
        Some("sslmode=disable".into());
    assert_eq!(storage.load_connections().await.unwrap(), expected);
    assert_eq!(storage.load_mcp_global_policy().await.unwrap().policy(), policy);
}
