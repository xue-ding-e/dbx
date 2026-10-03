//! Restricted same-ID, two-hop SSH route repair. Plans contain metadata only;
//! the selected target credential arrives through the existing anonymous pipe.
//! An explicit TLS-only CAS may instead validate one encrypted PostgreSQL mode.
use super::meatshell_import::{decode_password_json, read_inputs, valid_host, valid_id, valid_label};
use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Value};
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) fn invalid() -> String {
    "INVALID_ROUTE_UPDATE: Invalid or unsupported route update.".into()
}
pub(crate) fn mismatch() -> String {
    "ROUTE_SOURCE_MISMATCH: The saved route no longer matches the approved plan.".into()
}
pub(crate) fn store_error() -> String {
    "ROUTE_STORE_ERROR: The route update could not be completed.".into()
}
pub(crate) fn secret_error() -> String {
    "ROUTE_SECRET_UNAVAILABLE: The selected target credential is unavailable or invalid.".into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdatePlan {
    format: String,
    version: u32,
    pub(crate) connection_id: String,
    pub(crate) expected: ExpectedConnection,
    pub(crate) changes: Value,
    pub(crate) expected_export: ExportMetadata,
    #[serde(default, deserialize_with = "present_sslmode_cas")]
    pub(crate) postgres_sslmode_cas: Option<PostgresSslmodeCas>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PostgresSslmodeCas {
    expected: String,
    replacement: String,
}

fn present_sslmode_cas<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PostgresSslmodeCas>, D::Error> {
    PostgresSslmodeCas::deserialize(deserializer).map(Some)
}

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedConnection {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) database: Option<String>,
    pub(crate) ssl: bool,
    pub(crate) username: String,
    pub(crate) transport_layers: Vec<ExpectedHop>,
}

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedHop {
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) auth_method: String,
}

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportMetadata {
    schema_version: u32,
    target_session_id: String,
    pub(crate) route: Vec<ExportHopMetadata>,
}

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportHopMetadata {
    session_id: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) user: String,
    pub(crate) auth: String,
}

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
    // RawValue distinguishes omitted from explicit null, unlike Option<String>.
    #[serde(default, borrow, deserialize_with = "present_password")]
    password: Option<&'a RawValue>,
}

fn present_password<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<&'de RawValue>, D::Error> {
    <&RawValue>::deserialize(deserializer).map(Some)
}

/// Deliberately no Debug/Serialize/Clone for credential-bearing requests.
pub struct RouteUpdateRequest {
    pub(crate) plan: UpdatePlan,
    password: Option<Zeroizing<String>>,
}

#[derive(Debug, Serialize)]
pub struct RouteUpdateReport {
    pub dry_run: bool,
    pub connection_id: String,
    pub updated: bool,
    pub target_password_changed: bool,
    /// Present only after the explicitly selected encrypted TLS mode was checked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postgres_sslmode_changed: Option<bool>,
    pub database_connection_attempted: bool,
}

pub fn read_request(plan: &Path, export: &Path) -> Result<RouteUpdateRequest, String> {
    let (plan, export) = read_inputs(plan, export).map_err(|_| invalid())?;
    parse_request(&plan, &export)
}

pub fn parse_request(plan: &[u8], export: &[u8]) -> Result<RouteUpdateRequest, String> {
    if plan.len() > 65_536 || export.len() > 1_048_576 {
        return Err(invalid());
    }
    let plan: UpdatePlan = serde_json::from_slice(plan).map_err(|_| invalid())?;
    let raw: RawExport<'_> = serde_json::from_slice(export).map_err(|_| invalid())?;
    if raw.route.len() != 2 || raw.route[0].password.is_some() {
        return Err(invalid());
    }
    let password = raw.route[1].password.map(|value| Zeroizing::new(value.get().to_owned()));
    let metadata = ExportMetadata {
        schema_version: raw.schema_version,
        target_session_id: raw.target_session_id,
        route: raw
            .route
            .into_iter()
            .map(|hop| ExportHopMetadata {
                session_id: hop.session_id,
                host: hop.host,
                port: hop.port,
                user: hop.user,
                auth: hop.auth,
            })
            .collect(),
    };
    if plan.expected_export != metadata {
        return Err(mismatch());
    }
    let request = RouteUpdateRequest { plan, password };
    request.validate()?;
    Ok(request)
}

impl RouteUpdateRequest {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let plan = &self.plan;
        let expected = &plan.expected;
        let export = &plan.expected_export;
        if plan.format != "dbx-route-update-plan"
            || plan.version != 1
            || !valid_id(&plan.connection_id)
            || !valid_host(&expected.host)
            || expected.port == 0
            || !valid_label(&expected.username, 128)
            || expected.transport_layers.len() != 2
            || export.schema_version != 1
            || export.route.len() != 2
            || !valid_id(&export.target_session_id)
        {
            return Err(invalid());
        }
        for hop in &expected.transport_layers {
            if !valid_id(&hop.id) || !valid_host(&hop.host) || hop.port == 0 || !valid_label(&hop.user, 128) {
                return Err(invalid());
            }
        }
        for hop in &export.route {
            if !valid_id(&hop.session_id) || !valid_host(&hop.host) || hop.port == 0 || !valid_label(&hop.user, 128) {
                return Err(invalid());
            }
        }
        let first = &expected.transport_layers[0];
        let second = &expected.transport_layers[1];
        let outer = &export.route[0];
        let target = &export.route[1];
        if first.id == second.id
            || first.auth_method != "key"
            || second.auth_method != "password"
            || outer.auth != "key"
            || target.auth != "password"
            || outer.session_id == target.session_id
            || target.session_id != export.target_session_id
            || first.host != outer.host
            || first.port != outer.port
            || first.user != outer.user
            || (outer.host == target.host && outer.port == target.port && outer.user == target.user)
        {
            return Err(invalid());
        }
        let changes = plan.changes.as_object().ok_or_else(invalid)?;
        for (key, value) in changes {
            let valid = match key.as_str() {
                "host" => value.as_str().is_some_and(valid_host),
                "port" => value.as_u64().is_some_and(|port| port > 0 && port <= u16::MAX as u64),
                "database" => {
                    value.is_null() || value.as_str().is_some_and(|name| name.is_empty() || valid_label(name, 256))
                }
                "ssl" => value.is_boolean(),
                "second_hop_name" => value.as_str().is_some_and(|name| name.is_empty() || valid_label(name, 256)),
                _ => false,
            };
            if !valid {
                return Err(invalid());
            }
        }
        if let Some(patch) = &plan.postgres_sslmode_cas {
            // This is a TLS-only correction for an already disabled JSON flag.
            // No credential-bearing payload or simultaneous route edit is allowed.
            if patch.expected != "verify-full"
                || patch.replacement != "disable"
                || expected.ssl
                || changes.len() != 1
                || changes.get("ssl") != Some(&Value::Bool(false))
                || self.password.is_some()
                || second.host != target.host
                || second.port != target.port
                || second.user != target.user
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    pub(crate) fn target_password(&self, dry_run: bool) -> Result<Option<Zeroizing<String>>, String> {
        if dry_run {
            return if self.password.is_none() { Ok(None) } else { Err(invalid()) };
        }
        let before = &self.plan.expected.transport_layers[1];
        let after = &self.plan.expected_export.route[1];
        if self.password.is_none()
            && (before.host != after.host || before.port != after.port || before.user != after.user)
        {
            return Err(secret_error());
        }
        self.password
            .as_ref()
            .map(|raw| {
                let decoded = decode_password_json(raw).map_err(|_| secret_error())?;
                super::meatshell_import::validate_plaintext(&decoded, false).map_err(|_| secret_error())?;
                Ok(decoded)
            })
            .transpose()
    }
}
