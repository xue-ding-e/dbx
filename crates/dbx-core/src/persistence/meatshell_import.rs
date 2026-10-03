//! Local-only, bounded MeatShell bridge input and metadata conversion.
//! No profiles, keys, databases, or network endpoints are opened by this module.
use crate::models::connection::ConnectionConfig;
use serde::{Deserialize, Serialize};
use serde_json::{json, value::RawValue, Value};
use std::{io::Read, net::IpAddr, path::Path};
use zeroize::{Zeroize, Zeroizing};

const MAX_PLAN_BYTES: u64 = 65_536;
const MAX_EXPORT_BYTES: u64 = 1_048_576;

pub(crate) fn invalid() -> String {
    "INVALID_MEATSHELL_IMPORT: Invalid or unsupported selected import.".into()
}
pub(crate) fn source_mismatch() -> String {
    "MEATSHELL_SOURCE_MISMATCH: Source identity or route does not match the approved plan.".into()
}
pub(crate) fn store_error() -> String {
    "MEATSHELL_STORE_ERROR: Native connection storage is unavailable or incompatible.".into()
}
pub(crate) fn secret_error() -> String {
    "MEATSHELL_SECRET_UNAVAILABLE: Required selected credentials cannot be resolved safely.".into()
}

pub struct ImportRequest {
    pub(crate) plan: ImportPlan,
    pub(crate) export: SelectedExport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportPlan {
    format: String,
    version: u32,
    pub(crate) source_connection_id: String,
    pub(crate) new_connection_id: String,
    pub(crate) new_connection_name: String,
    host: String,
    port: u16,
    database: String,
    username: String,
    is_production: bool,
    ssl: bool,
    expected_export: ExpectedExport,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedExport {
    schema_version: u32,
    target_session_id: String,
    route: Vec<HopMetadata>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HopMetadata {
    session_id: String,
    host: String,
    port: u16,
    user: String,
    auth: String,
}

pub(crate) struct SelectedExport {
    schema_version: u32,
    target_session_id: String,
    route: Vec<ExportHop>,
}

struct ExportHop {
    session_id: String,
    host: String,
    port: u16,
    user: String,
    auth: String,
    password: Option<SecretText>,
}

/// No Debug, Serialize, or Clone: accidental diagnostics cannot expose it.
struct SecretText(Zeroizing<String>);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExport<'a> {
    schema_version: u32,
    target_session_id: String,
    #[serde(borrow)]
    route: Vec<RawHop<'a>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHop<'a> {
    session_id: String,
    host: String,
    port: u16,
    user: String,
    auth: String,
    #[serde(default, borrow)]
    password: Option<&'a RawValue>,
}

/// The result never contains passwords, key paths, passphrases, or remote errors.
#[derive(Debug, Serialize)]
pub struct ImportReport {
    pub dry_run: bool,
    pub input_count: usize,
    pub planned_count: usize,
    pub imported_count: usize,
    pub source_connection_id: String,
    pub candidate_connection_id: String,
    pub connection_id: Option<String>,
    pub source_credentials_resolved: bool,
    pub database_connection_attempted: bool,
}

/// Parse exact bounded wire contracts. All parser details are suppressed.
/// Caller-owned byte slices remain the caller's responsibility.
pub fn parse_request(plan: &[u8], export: &[u8]) -> Result<ImportRequest, String> {
    if plan.len() > MAX_PLAN_BYTES as usize || export.len() > MAX_EXPORT_BYTES as usize {
        return Err(invalid());
    }
    let raw: RawExport<'_> = serde_json::from_slice(export).map_err(|_| invalid())?;
    if raw.route.len() != 2 || raw.route[0].password.is_some() {
        return Err(invalid());
    }
    let password = raw.route[1].password;
    let mut request = ImportRequest {
        plan: serde_json::from_slice(plan).map_err(|_| invalid())?,
        export: SelectedExport {
            schema_version: raw.schema_version,
            target_session_id: raw.target_session_id,
            route: raw
                .route
                .into_iter()
                .map(|hop| ExportHop {
                    session_id: hop.session_id,
                    host: hop.host,
                    port: hop.port,
                    user: hop.user,
                    auth: hop.auth,
                    password: None,
                })
                .collect(),
        },
    };
    request.validate()?;
    // Borrow the target's raw JSON until its metadata has been validated. Do not
    // use serde's normal String decoder: escaped plaintext would pass through a
    // non-zeroizing scratch allocation inside the JSON deserializer.
    request.export.route[1].password = password.map(|raw| SecretText(Zeroizing::new(raw.get().to_owned())));
    Ok(request)
}

/// The export is accepted only from a Linux anonymous stdin pipe. The plan is a
/// separate existing owner-only regular file; neither input may be a terminal,
/// named FIFO, socket, symlink, or guessed profile path.
pub fn read_request(plan_path: &Path, export_path: &Path) -> Result<ImportRequest, String> {
    let (plan, export) = read_inputs(plan_path, export_path)?;
    parse_request(&plan, &export)
}

/// Shared same-host boundary for selected imports and in-place route repairs.
pub(crate) fn read_inputs(
    plan_path: &Path,
    export_path: &Path,
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), String> {
    if export_path != Path::new("-") || !plan_path.is_absolute() {
        return Err(invalid());
    }
    validate_anonymous_stdin()?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(plan_path).map_err(|_| invalid())?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err("INSECURE_INPUT: Import plan must be owner-only and owned by the current user.".into());
        }
    }
    let mut plan = Zeroizing::new(Vec::with_capacity((MAX_PLAN_BYTES + 1) as usize));
    file.take(MAX_PLAN_BYTES + 1).read_to_end(&mut plan).map_err(|_| invalid())?;
    let mut export = Zeroizing::new(Vec::with_capacity((MAX_EXPORT_BYTES + 1) as usize));
    #[cfg(unix)]
    let input = {
        use std::os::fd::FromRawFd;
        let fd = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(invalid());
        }
        unsafe { std::fs::File::from_raw_fd(fd) }
    };
    #[cfg(not(unix))]
    let input = std::io::stdin(); // validate_anonymous_stdin already rejects this platform.
    input.take(MAX_EXPORT_BYTES + 1).read_to_end(&mut export).map_err(|_| invalid())?;
    Ok((plan, export))
}

fn validate_anonymous_stdin() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(libc::STDIN_FILENO, metadata.as_mut_ptr()) } != 0 {
            return Err(invalid());
        }
        let metadata = unsafe { metadata.assume_init() };
        let link = std::fs::read_link("/proc/self/fd/0").map_err(|_| invalid())?;
        if metadata.st_mode & libc::S_IFMT != libc::S_IFIFO
            || !link.as_os_str().as_encoded_bytes().starts_with(b"pipe:[")
        {
            return Err("INVALID_MEATSHELL_IMPORT: Export input must be a Linux anonymous stdin pipe.".into());
        }
        let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
            || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0
        {
            return Err(invalid());
        }
        std::panic::set_hook(Box::new(|_| eprintln!("selected import failed")));
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Err("INVALID_MEATSHELL_IMPORT: This same-host bridge requires Linux anonymous pipes.".into())
}

impl ImportRequest {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let plan = &self.plan;
        let expected = &plan.expected_export;
        let export = &self.export;
        if plan.format != "dbx-meatshell-import-plan"
            || plan.version != 1
            || !valid_id(&plan.source_connection_id)
            || !valid_id(&plan.new_connection_id)
            || plan.source_connection_id == plan.new_connection_id
            || !valid_label(&plan.new_connection_name, 256)
            || !valid_host(&plan.host)
            || plan.port == 0
            || !valid_label(&plan.database, 256)
            || !valid_label(&plan.username, 128)
            || !plan.is_production
            || plan.ssl
            || expected.schema_version != 1
            || export.schema_version != 1
            || expected.target_session_id != export.target_session_id
            || !valid_id(&export.target_session_id)
            || expected.route.len() != 2
            || export.route.len() != 2
        {
            return Err(invalid());
        }
        for (expected, actual) in expected.route.iter().zip(&export.route) {
            if expected.session_id != actual.session_id
                || expected.host != actual.host
                || expected.port != actual.port
                || expected.user != actual.user
                || expected.auth != actual.auth
                || !valid_id(&actual.session_id)
                || !valid_host(&actual.host)
                || actual.port == 0
                || !valid_label(&actual.user, 128)
            {
                return Err(invalid());
            }
        }
        let first = &export.route[0];
        let target = &export.route[1];
        if first.session_id == target.session_id
            || first.auth != "key"
            || target.auth != "password"
            || first.password.is_some()
            || target.session_id != export.target_session_id
            || (first.host == target.host && first.port == target.port && first.user == target.user)
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn target_password(&self) -> Result<Zeroizing<String>, String> {
        let value = self.export.route[1].password.as_ref().ok_or_else(secret_error)?;
        let decoded = decode_password_json(&value.0)?;
        validate_plaintext(&decoded, true)?;
        Ok(decoded)
    }

    pub(crate) fn validate_preview(&self) -> Result<(), String> {
        if self.export.route.iter().any(|hop| hop.password.is_some()) {
            return Err("INVALID_MEATSHELL_IMPORT: Preview accepts metadata only; omit target password.".into());
        }
        Ok(())
    }

    /// Prepare a credential-free native ConnectionConfig. Source JSON must be
    /// selected inside the same transaction that later resolves and rewraps the
    /// credentials. Do not hydrate or clone unrelated source secret fields.
    pub(crate) fn candidate(&self, source: &Value) -> Result<ConnectionConfig, String> {
        self.validate()?;
        let plan = &self.plan;
        if source.get("id").and_then(Value::as_str) != Some(&plan.source_connection_id)
            || source.get("db_type").and_then(Value::as_str) != Some("postgres")
            || source.get("host").and_then(Value::as_str) != Some(&plan.host)
            || source.get("port").and_then(Value::as_u64) != Some(u64::from(plan.port))
            || source.get("username").and_then(Value::as_str) != Some(&plan.username)
            || !optional_string(source, "password")?.is_empty()
            || !optional_bool(source, "save_password", true)?
        {
            return Err(source_mismatch());
        }
        let source_name = source.get("name").and_then(Value::as_str).ok_or_else(source_mismatch)?;
        if source_name.trim().to_lowercase() == plan.new_connection_name.trim().to_lowercase() {
            return Err(source_mismatch());
        }
        let first = source
            .get("transport_layers")
            .and_then(Value::as_array)
            .and_then(|layers| layers.first())
            .ok_or_else(source_mismatch)?;
        let expected = &plan.expected_export.route[0];
        let id = first.get("id").and_then(Value::as_str).ok_or_else(source_mismatch)?;
        let key_path = first.get("key_path").and_then(Value::as_str).ok_or_else(source_mismatch)?;
        if first.get("type").and_then(Value::as_str) != Some("ssh")
            || first.get("host").and_then(Value::as_str) != Some(&expected.host)
            || first.get("port").and_then(Value::as_u64) != Some(u64::from(expected.port))
            || first.get("user").and_then(Value::as_str) != Some(&expected.user)
            || first.get("auth_method").and_then(Value::as_str) != Some("key")
            || !valid_id(id)
            || id == self.export.target_session_id
            || !valid_label(key_path, 4096)
            || !optional_bool(first, "enabled", true)?
            || optional_bool(first, "expose_lan", false)?
            || optional_bool(first, "use_ssh_agent", false)?
            || optional_bool(first, "allow_exec_channel_proxy", false)?
            || !optional_string(first, "profile_id")?.is_empty()
            || !optional_string(first, "ssh_agent_sock_path")?.is_empty()
            || !optional_string(first, "password")?.is_empty()
            || !optional_string(first, "key_passphrase")?.is_empty()
        {
            return Err(source_mismatch());
        }
        let first_name = optional_string(first, "name")?;
        if !first_name.is_empty() && !valid_label(first_name, 256) {
            return Err(source_mismatch());
        }
        let timeout = match first.get("connect_timeout_secs") {
            None => 5,
            Some(value) => value.as_u64().filter(|seconds| *seconds > 0).ok_or_else(source_mismatch)?,
        };
        let read_only = optional_bool(source, "read_only", false)?;
        let target = &plan.expected_export.route[1];
        serde_json::from_value(json!({
            "id": plan.new_connection_id, "name": plan.new_connection_name, "db_type": "postgres",
            "host": plan.host, "port": plan.port, "database": plan.database, "username": plan.username,
            "password": "", "save_password": true, "read_only": read_only, "is_production": true, "ssl": false,
            "transport_layers": [{
                "type": "ssh", "id": id, "name": first_name, "enabled": true,
                "host": expected.host, "port": expected.port, "user": expected.user,
                "auth_method": "key", "key_path": key_path, "key_passphrase": "", "password": "",
                "connect_timeout_secs": timeout, "expose_lan": false, "use_ssh_agent": false,
                "allow_exec_channel_proxy": false, "profile_id": "", "ssh_agent_sock_path": ""
            }, {
                "type": "ssh", "id": target.session_id, "name": "Selected SSH hop", "enabled": true,
                "host": target.host, "port": target.port, "user": target.user,
                "auth_method": "password", "key_path": "", "key_passphrase": "", "password": "",
                "connect_timeout_secs": 5, "expose_lan": false, "use_ssh_agent": false,
                "allow_exec_channel_proxy": false, "profile_id": "", "ssh_agent_sock_path": ""
            }]
        }))
        .map_err(|_| invalid())
    }
}

pub(crate) fn validate_plaintext(value: &str, required: bool) -> Result<(), String> {
    if (required && value.is_empty())
        || value.len() > 65_536
        || value.starts_with("enc:")
        || value.starts_with("dbx-secret:")
    {
        Err(secret_error())
    } else {
        Ok(())
    }
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}
pub(crate) fn valid_label(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && value.trim() == value && !value.chars().any(char::is_control)
}
pub(crate) fn valid_host(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    value.parse::<IpAddr>().is_ok()
        || value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
fn optional_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    match value.get(key) {
        None => Ok(""),
        Some(value) => value.as_str().ok_or_else(source_mismatch),
    }
}
fn optional_bool(value: &Value, key: &str, default: bool) -> Result<bool, String> {
    match value.get(key) {
        None => Ok(default),
        Some(value) => value.as_bool().ok_or_else(source_mismatch),
    }
}

pub(crate) struct ScrubbedValue(pub Value);
impl Drop for ScrubbedValue {
    fn drop(&mut self) {
        fn scrub(value: &mut Value) {
            match value {
                Value::String(value) => value.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(scrub),
                Value::Object(values) => values.values_mut().for_each(scrub),
                _ => {}
            }
        }
        scrub(&mut self.0);
    }
}

pub(crate) fn decode_password_json(raw: &str) -> Result<Zeroizing<String>, String> {
    let bytes = raw.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return Err(secret_error());
    }
    let mut decoded = Zeroizing::new(String::with_capacity(bytes.len()));
    let end = bytes.len() - 1;
    let mut at = 1;
    while at < end {
        if bytes[at] != b'\\' {
            let start = at;
            while at < end && bytes[at] != b'\\' {
                if bytes[at] < 0x20 || bytes[at] == b'"' {
                    return Err(secret_error());
                }
                at += 1;
            }
            decoded.push_str(std::str::from_utf8(&bytes[start..at]).map_err(|_| secret_error())?);
            continue;
        }
        at += 1;
        let escape = *bytes.get(at).filter(|_| at < end).ok_or(secret_error())?;
        at += 1;
        match escape {
            b'"' => decoded.push('"'),
            b'\\' => decoded.push('\\'),
            b'/' => decoded.push('/'),
            b'b' => decoded.push('\u{8}'),
            b'f' => decoded.push('\u{c}'),
            b'n' => decoded.push('\n'),
            b'r' => decoded.push('\r'),
            b't' => decoded.push('\t'),
            b'u' => {
                let high = decode_hex_quad(bytes, &mut at, end)?;
                let scalar = if (0xd800..=0xdbff).contains(&high) {
                    if bytes.get(at..at + 2) != Some(b"\\u") {
                        return Err(secret_error());
                    }
                    at += 2;
                    let low = decode_hex_quad(bytes, &mut at, end)?;
                    if !(0xdc00..=0xdfff).contains(&low) {
                        return Err(secret_error());
                    }
                    0x10000 + ((high - 0xd800) << 10) + low - 0xdc00
                } else {
                    high
                };
                decoded.push(char::from_u32(scalar).ok_or(secret_error())?);
            }
            _ => return Err(secret_error()),
        }
    }
    Ok(decoded)
}
fn decode_hex_quad(bytes: &[u8], at: &mut usize, end: usize) -> Result<u32, String> {
    if *at + 4 > end {
        return Err(secret_error());
    }
    let mut value = 0;
    for byte in &bytes[*at..*at + 4] {
        value = (value << 4)
            | match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return Err(secret_error()),
            };
    }
    *at += 4;
    Ok(value)
}
