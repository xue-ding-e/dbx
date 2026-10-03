//! Fail-closed process boundaries; no real profiles or network endpoints are used.
use std::process::{Command, Output, Stdio};

fn invoke(extra: &[&str], environment: &[(&str, &str)]) -> (tempfile::TempDir, Output) {
    let directory = tempfile::tempdir().unwrap();
    let plan = directory.path().join("missing-plan.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_dbx"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", directory.path())
        .env("XDG_DATA_HOME", directory.path())
        .env("DBX_DATA_DIR", directory.path())
        .args(["connections", "import-meatshell", "--file", "-", "--plan"])
        .arg(plan)
        .arg("--json")
        .args(extra)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    let result = command.output().unwrap();
    (directory, result)
}
fn error_code(output: &Output) -> String {
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    report["error"]["code"].as_str().or_else(|| report["code"].as_str()).unwrap().to_owned()
}

#[test]
fn bridge_honors_explicit_false_write_environment_before_opening_any_input() {
    for value in ["0", "false", " FALSE "] {
        let (dir, output) = invoke(&["--yes"], &[("DBX_MCP_ALLOW_WRITES", value)]);
        assert_eq!(error_code(&output), "MCP_READ_ONLY");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[test]
fn bridge_rejects_remote_backend_and_scoped_sessions_without_opening_profile() {
    for (name, value, code) in [
        ("DBX_WEB_URL", "http://127.0.0.1:1", "CONNECTION_IMPORT_UNSUPPORTED"),
        ("DBX_MCP_SCOPE_CONNECTION_ID", "synthetic-scope", "CONNECTION_OUT_OF_SCOPE"),
        ("DBX_MCP_SCOPE_DATABASE", "synthetic-db", "CONNECTION_OUT_OF_SCOPE"),
    ] {
        let (dir, output) = invoke(&["--yes"], &[(name, value)]);
        assert_eq!(error_code(&output), code);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}

#[test]
fn bridge_never_initializes_a_missing_profile_or_accepts_null_stdin() {
    let (dir, output) = invoke(&[], &[]);
    assert_eq!(error_code(&output), "INVALID_MEATSHELL_IMPORT");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    let (dir, output) = invoke(&["--initialize"], &[]);
    assert_eq!(error_code(&output), "INVALID_OPTION");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
