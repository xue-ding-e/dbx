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
        ("DBX_MCP_ALLOW_WRITES", "false", "MCP_READ_ONLY"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = command(dir.path());
        cmd.env(name, value).arg("--yes");
        let output = invoke(cmd, &json!({}));
        assert_eq!(code(&output), expected);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
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
    storage.save_mcp_global_policy(&McpGlobalPolicy { read_only: false, ..Default::default() }).await.unwrap();
    let config:ConnectionConfig=serde_json::from_value(json!({"id":"fixture","name":"Synthetic","db_type":"postgres",
        "host":"db.invalid","port":5432,"database":"before","username":"fixture","password":"SYNTHETIC_DB",
        "transport_layers":[
            {"id":"first","type":"ssh","host":"192.0.2.1","port":22,"user":"fixture","auth_method":"key","key_path":"/synthetic/key","key_passphrase":"SYNTHETIC_PASSPHRASE"},
            {"id":"second","type":"ssh","host":"192.0.2.2","port":22,"user":"fixture","auth_method":"password","password":"SYNTHETIC_OLD"}]})).unwrap();
    storage.save_connections(std::slice::from_ref(&config)).await.unwrap();
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
        std::fs::set_permissions(plan_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let output = invoke(command(dir.path()), &export);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["updated"], false);
    assert_eq!(storage.load_connections().await.unwrap(), vec![config]);
    export["route"][1]["password"] = json!("SYNTHETIC_NEW_SECRET");
    let wrong = tempfile::tempdir().unwrap();
    let _wrong_storage = test_storage::open(&wrong.path().join("dbx.db")).await.unwrap();
    let mut wrong_cmd = command(dir.path());
    wrong_cmd.arg("--yes").env("DBX_SECRET_KEY_FILE", managed_key_path(wrong.path()));
    let wrong_output = invoke(wrong_cmd, &export);
    assert_eq!(code(&wrong_output), "ROUTE_SECRET_UNAVAILABLE");
    assert_eq!(storage.load_connections().await.unwrap()[0].database.as_deref(), Some("before"));
    let mut cmd = command(dir.path());
    cmd.arg("--yes");
    let output = invoke(cmd, &export);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["connection_id"], "fixture");
    assert_eq!(report["updated"], true);
    for stream in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains("SYNTHETIC_"));
    }
    let loaded = storage.load_connections().await.unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].database.as_deref(), Some("after"));
    assert_eq!(loaded[0].password, "SYNTHETIC_DB");
    assert_eq!(
        storage.get_secret("fixture", "transport_layers.second.ssh_password").await.unwrap().as_deref(),
        Some("SYNTHETIC_NEW_SECRET")
    );
}
