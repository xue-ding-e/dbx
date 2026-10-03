//! Narrow native storage bridge. No general connection loader is used here.
use super::*;
use crate::persistence::{
    connection_import::{plan_import, ImportBundle},
    meatshell_import::{self, ImportReport, ImportRequest, ScrubbedValue},
};
use zeroize::Zeroizing;

// Fixed, credential-free projection of only the chosen source and first hop.
// Empty/nonempty indicators reject legacy inline credentials without returning
// their values to Rust; discarded notes, SQL, plugin fields and old hops are absent.
const SELECT_SOURCE_METADATA: &str = r#"SELECT json_object('id',json_extract(config_json,'$.id'),
    'name',json_extract(config_json,'$.name'),
    'db_type',json_extract(config_json,'$.db_type'),
    'host',json_extract(config_json,'$.host'),
    'port',json(config_json -> '$.port'),
    'username',json_extract(config_json,'$.username'),
    'save_password',json(COALESCE(config_json -> '$.save_password','true')),
    'read_only',json(COALESCE(config_json -> '$.read_only','false')),
    'password',CASE WHEN json_type(config_json,'$.password') IS NULL OR (json_type(config_json,'$.password')='text' AND json_extract(config_json,'$.password')='') THEN '' ELSE '!nonempty-or-invalid!' END,
    'transport_layers',json_array(json_object('type',json_extract(config_json,'$.transport_layers[0].type'),
    'id',json_extract(config_json,'$.transport_layers[0].id'),
    'name',COALESCE(json_extract(config_json,'$.transport_layers[0].name'),''),
    'host',json_extract(config_json,'$.transport_layers[0].host'),
    'port',json(config_json -> '$.transport_layers[0].port'),
    'user',json_extract(config_json,'$.transport_layers[0].user'),
    'auth_method',json_extract(config_json,'$.transport_layers[0].auth_method'),
    'key_path',json_extract(config_json,'$.transport_layers[0].key_path'),
    'connect_timeout_secs',json(COALESCE(config_json -> '$.transport_layers[0].connect_timeout_secs','5')),
    'enabled',json(COALESCE(config_json -> '$.transport_layers[0].enabled','true')),
    'expose_lan',json(COALESCE(config_json -> '$.transport_layers[0].expose_lan','false')),
    'use_ssh_agent',json(COALESCE(config_json -> '$.transport_layers[0].use_ssh_agent','false')),
    'allow_exec_channel_proxy',json(COALESCE(config_json -> '$.transport_layers[0].allow_exec_channel_proxy','false')),
    'password',CASE WHEN json_type(config_json,'$.transport_layers[0].password') IS NULL OR (json_type(config_json,'$.transport_layers[0].password')='text' AND json_extract(config_json,'$.transport_layers[0].password')='') THEN '' ELSE '!nonempty-or-invalid!' END,
    'key_passphrase',CASE WHEN json_type(config_json,'$.transport_layers[0].key_passphrase') IS NULL OR (json_type(config_json,'$.transport_layers[0].key_passphrase')='text' AND json_extract(config_json,'$.transport_layers[0].key_passphrase')='') THEN '' ELSE '!nonempty-or-invalid!' END,
    'profile_id',CASE WHEN json_type(config_json,'$.transport_layers[0].profile_id') IS NULL OR (json_type(config_json,'$.transport_layers[0].profile_id')='text' AND json_extract(config_json,'$.transport_layers[0].profile_id')='') THEN '' ELSE '!nonempty-or-invalid!' END,
    'ssh_agent_sock_path',CASE WHEN json_type(config_json,'$.transport_layers[0].ssh_agent_sock_path') IS NULL OR (json_type(config_json,'$.transport_layers[0].ssh_agent_sock_path')='text' AND json_extract(config_json,'$.transport_layers[0].ssh_agent_sock_path')='') THEN '' ELSE '!nonempty-or-invalid!' END)))
FROM connections WHERE id=?1 AND json_type(config_json,'$.transport_layers')='array' AND json_type(config_json,'$.transport_layers[0]')='object'"#;

impl Storage {
    /// Open an existing explicit local profile without schema initialization,
    /// permission changes, data migration, credential hydration, or key creation.
    /// Unlike LocalBackend::open this never calls load_connections().
    pub async fn open_for_meatshell_import(path: &Path) -> Result<Self, String> {
        let metadata = path.symlink_metadata().map_err(|_| meatshell_import::store_error())?;
        if !path.is_absolute() || !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(meatshell_import::store_error());
        }
        // Refuse symlinked ancestors and insecure explicit profile ownership.
        // Native SQLite still opens the checked path; this is not a claim of a
        // descriptor-bound filesystem snapshot against a same-UID replacer.
        let mut ancestor = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir | std::path::Component::Normal(_) => ancestor.push(component),
                _ => return Err(meatshell_import::store_error()),
            }
            if ancestor.symlink_metadata().map_err(|_| meatshell_import::store_error())?.file_type().is_symlink() {
                return Err(meatshell_import::store_error());
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let parent = path
                .parent()
                .ok_or_else(meatshell_import::store_error)?
                .metadata()
                .map_err(|_| meatshell_import::store_error())?;
            if metadata.uid() != unsafe { libc::geteuid() }
                || parent.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o077 != 0
                || parent.mode() & 0o077 != 0
            {
                return Err(meatshell_import::store_error());
            }
        }
        let path_text = path.to_str().ok_or_else(meatshell_import::store_error)?;
        let db = crate::db::sqlite::connect_path(path_text).await.map_err(|_| meatshell_import::store_error())?;
        Ok(Self {
            db,
            path: path.to_path_buf(),
            secret_key_policy: SecretKeyPolicy::PlatformDefault,
            secret_key_creation_allowed: false,
            secret_codec_cache: Arc::new(Mutex::new(None)),
            migration_failure: Arc::new(Mutex::new(None)),
        })
    }

    /// Atomically add a new independent PostgreSQL connection. Preview resolves
    /// no source credentials. Apply reads exactly the selected DB password and
    /// first SSH key passphrase, re-encrypts under new native IDs, and never
    /// rewrites source rows or global policy. No database connection is made.
    pub async fn import_meatshell(&self, request: ImportRequest, dry_run: bool) -> Result<ImportReport, String> {
        request.validate()?;
        if dry_run {
            request.validate_preview()?;
        }
        let storage = self.clone();
        self.with_conn(move |conn| {
            let behavior = if dry_run { TransactionBehavior::Deferred } else { TransactionBehavior::Immediate };
            let tx = conn.transaction_with_behavior(behavior).map_err(|_| meatshell_import::store_error())?;
            let policy = load_mcp_global_policy_in_tx(&tx).map_err(|_| meatshell_import::store_error())?;
            if policy
                .allowed_tool_names
                .as_ref()
                .is_some_and(|names| !names.iter().any(|name| name == "dbx_import_connections"))
            {
                return Err("TOOL_OUT_OF_SCOPE: Import is not allowed by MCP policy.".into());
            }
            if policy.allowed_connection_ids.is_some() || !policy.allowed_group_ids.is_empty() {
                return Err("CONNECTION_OUT_OF_SCOPE: Import is disabled in scoped sessions.".into());
            }
            if !dry_run && policy.read_only {
                return Err("MCP_READ_ONLY: Global MCP read-only mode blocks connection imports.".into());
            }
            let plan = &request.plan;
            let candidate_exists: bool = tx
                .query_row("SELECT EXISTS(SELECT 1 FROM connections WHERE id=?1)", [&plan.new_connection_id], |row| {
                    row.get(0)
                })
                .map_err(|_| meatshell_import::store_error())?;
            if candidate_exists {
                return Err("CONNECTION_ALREADY_EXISTS: The candidate ID already exists.".into());
            }
            // Name uniqueness makes generic import identity deduplication
            // unnecessary. Select names only, never unrelated config or DSNs.
            {
                let mut statement = tx
                    .prepare("SELECT json_extract(config_json, '$.name') FROM connections")
                    .map_err(|_| meatshell_import::store_error())?;
                let rows = statement
                    .query_map([], |row| row.get::<_, String>(0))
                    .map_err(|_| meatshell_import::store_error())?;
                let desired = plan.new_connection_name.trim().to_lowercase();
                for name in rows {
                    if name.map_err(|_| meatshell_import::store_error())?.trim().to_lowercase() == desired {
                        return Err("CONNECTION_ALREADY_EXISTS: The candidate name already exists.".into());
                    }
                }
            }
            let source_json = Zeroizing::new(
                tx.query_row(SELECT_SOURCE_METADATA, [&plan.source_connection_id], |row| row.get::<_, String>(0))
                    .optional()
                    .map_err(|_| meatshell_import::store_error())?
                    .ok_or_else(meatshell_import::source_mismatch)?,
            );
            let source =
                ScrubbedValue(serde_json::from_str(&source_json).map_err(|_| meatshell_import::source_mismatch())?);
            let candidate = request.candidate(&source.0)?;
            let first = &candidate.transport_layers[0];
            let first_passphrase_key = transport_layer_ssh_key_passphrase_key(0, first);
            let first_legacy_passphrase_key = match first {
                TransportLayerConfig::Ssh(layer) if layer.id == "legacy" => "ssh_key_passphrase".to_string(),
                TransportLayerConfig::Ssh(layer) => ssh_tunnel_key_passphrase_key(0, layer),
                _ => return Err(meatshell_import::source_mismatch()),
            };
            let layout: Option<String> = tx
                .query_row("SELECT layout_json FROM sidebar_layout WHERE id=1", [], |row| row.get(0))
                .optional()
                .map_err(|_| meatshell_import::store_error())?;
            let layout = layout
                .map(|value| serde_json::from_str(&value).map_err(|_| meatshell_import::store_error()))
                .transpose()?;
            // Candidate is secret-free. Native planning can safely canonicalize
            // and allocate new IDs without making copies of plaintext values.
            let bundle = ImportBundle {
                connections: vec![candidate],
                profiles: Vec::new(),
                layout: None,
                timeout_inheritance: HashMap::new(),
            };
            let native = plan_import(bundle, &[], layout, dry_run).map_err(|_| meatshell_import::store_error())?;
            if native.connections.len() != 1 || native.report.imported_count != 1 {
                return Err(meatshell_import::store_error());
            }
            let mut report = ImportReport {
                dry_run,
                input_count: 1,
                planned_count: 1,
                imported_count: 0,
                source_connection_id: plan.source_connection_id.clone(),
                candidate_connection_id: plan.new_connection_id.clone(),
                connection_id: None,
                source_credentials_resolved: false,
                database_connection_attempted: false,
            };
            if dry_run {
                return Ok(report);
            }
            let target_password = request.target_password()?;
            // Never provision a key and never call get_secret(), whose legacy
            // plaintext path opportunistically migrates source secret rows.
            let codec = storage.secret_codec(false).map_err(|_| meatshell_import::secret_error())?;
            let database_password =
                read_selected_encrypted_secret(&tx, &codec, &plan.source_connection_id, "password")?
                    .ok_or_else(meatshell_import::secret_error)?;
            meatshell_import::validate_plaintext(&database_password, true)?;
            let passphrase =
                match read_selected_encrypted_secret(&tx, &codec, &plan.source_connection_id, &first_passphrase_key)? {
                    Some(value) => value,
                    None => read_selected_encrypted_secret(
                        &tx,
                        &codec,
                        &plan.source_connection_id,
                        &first_legacy_passphrase_key,
                    )?
                    .unwrap_or_else(|| Zeroizing::new(String::new())),
                };
            meatshell_import::validate_plaintext(&passphrase, false)?;
            let config = &native.connections[0];
            // Persist only the secret-free native config. The general native
            // persistence helper clones/canonicalizes it, so plaintext remains
            // solely in Zeroizing buffers until native secret-store encryption.
            persist_connection_in_tx(&tx, &codec, config).map_err(|_| meatshell_import::store_error())?;
            persist_secret_in_tx(&tx, &codec, &config.id, "password", &database_password)
                .map_err(|_| meatshell_import::store_error())?;
            persist_secret_in_tx(
                &tx,
                &codec,
                &config.id,
                &transport_layer_ssh_key_passphrase_key(0, &config.transport_layers[0]),
                &passphrase,
            )
            .map_err(|_| meatshell_import::store_error())?;
            persist_secret_in_tx(
                &tx,
                &codec,
                &config.id,
                &transport_layer_ssh_password_key(1, &config.transport_layers[1]),
                &target_password,
            )
            .map_err(|_| meatshell_import::store_error())?;
            let layout_json = serde_json::to_string(&native.layout).map_err(|_| meatshell_import::store_error())?;
            tx.execute("INSERT OR REPLACE INTO sidebar_layout (id,layout_json) VALUES (1,?1)", [layout_json])
                .map_err(|_| meatshell_import::store_error())?;
            tx.commit().map_err(|_| meatshell_import::store_error())?;
            report.imported_count = 1;
            report.connection_id = Some(config.id.clone());
            report.source_credentials_resolved = true;
            Ok(report)
        })
        .await
        .map_err(|error| match error.as_str() {
            message
                if message.starts_with("INVALID_MEATSHELL_IMPORT:")
                    || message.starts_with("MEATSHELL_")
                    || message.starts_with("TOOL_OUT_OF_SCOPE:")
                    || message.starts_with("CONNECTION_OUT_OF_SCOPE:")
                    || message.starts_with("MCP_READ_ONLY:")
                    || message.starts_with("CONNECTION_ALREADY_EXISTS:") =>
            {
                error
            }
            _ => meatshell_import::store_error(),
        })
    }
}

fn read_selected_encrypted_secret(
    tx: &Transaction<'_>,
    codec: &SecretCodec,
    connection_id: &str,
    key: &str,
) -> Result<Option<Zeroizing<String>>, String> {
    let row: Option<(String, Option<String>)> = tx
        .query_row(
            "SELECT secret, secret_enc FROM connection_secrets WHERE connection_id=?1 AND key=?2",
            params![connection_id, key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| meatshell_import::store_error())?;
    let Some((legacy, encrypted)) = row else {
        return Ok(None);
    };
    let legacy = Zeroizing::new(legacy);
    if !legacy.is_empty() {
        return Err(meatshell_import::secret_error());
    }
    let Some(encrypted) = encrypted.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let encrypted = Zeroizing::new(encrypted);
    codec
        .decrypt(connection_id, key, &encrypted)
        .map(|value| Some(Zeroizing::new(value)))
        .map_err(|_| meatshell_import::secret_error())
}

#[cfg(test)]
#[path = "meatshell_storage_tests.rs"]
mod tests;
