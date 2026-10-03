//! Native atomic route repair; never round-trip a hydrated/sanitized connection.
use super::*;
use crate::persistence::route_update::{self, ExpectedConnection, RouteUpdateReport, RouteUpdateRequest};

// Project metadata only. The key path and every inline credential are checked
// inside SQLite and never returned. Unknown fields stay in the original JSON.
// Preserve JSON port types so a stored boolean cannot compare equal to port 1.
const SELECT_ROUTE: &str = r#"SELECT json_object(
 'host',json_extract(config_json,'$.host'),'port',json(config_json -> '$.port'),
 'database',json_extract(config_json,'$.database'),'ssl',json(COALESCE(config_json -> '$.ssl','false')),
 'username',json_extract(config_json,'$.username'),
 'transport_layers',json_array(
   json_object('id',json_extract(config_json,'$.transport_layers[0].id'),
    'host',json_extract(config_json,'$.transport_layers[0].host'),'port',json(config_json -> '$.transport_layers[0].port'),
    'user',json_extract(config_json,'$.transport_layers[0].user'),'auth_method',json_extract(config_json,'$.transport_layers[0].auth_method')),
   json_object('id',json_extract(config_json,'$.transport_layers[1].id'),
    'host',json_extract(config_json,'$.transport_layers[1].host'),'port',json(config_json -> '$.transport_layers[1].port'),
    'user',json_extract(config_json,'$.transport_layers[1].user'),'auth_method',json_extract(config_json,'$.transport_layers[1].auth_method'))))
 FROM connections WHERE id=?1 AND json_extract(config_json,'$.id')=?1
 AND json_extract(config_json,'$.db_type')='postgres'
 AND json_array_length(config_json,'$.transport_layers')=2
 AND json_extract(config_json,'$.transport_layers[0].type')='ssh'
 AND json_extract(config_json,'$.transport_layers[1].type')='ssh'
 AND (json_type(config_json,'$.transport_layers[0].enabled') IS NULL OR json_type(config_json,'$.transport_layers[0].enabled')='true')
 AND (json_type(config_json,'$.transport_layers[1].enabled') IS NULL OR json_type(config_json,'$.transport_layers[1].enabled')='true')
 AND (json_type(config_json,'$.transport_layers[0].profile_id') IS NULL OR (json_type(config_json,'$.transport_layers[0].profile_id')='text' AND json_extract(config_json,'$.transport_layers[0].profile_id')=''))
 AND (json_type(config_json,'$.transport_layers[1].profile_id') IS NULL OR (json_type(config_json,'$.transport_layers[1].profile_id')='text' AND json_extract(config_json,'$.transport_layers[1].profile_id')=''))
 AND json_type(config_json,'$.transport_layers[0].key_path')='text' AND json_extract(config_json,'$.transport_layers[0].key_path')!=''
 AND (json_type(config_json,'$.password') IS NULL OR (json_type(config_json,'$.password')='text' AND json_extract(config_json,'$.password')=''))
 AND (json_type(config_json,'$.transport_layers[0].password') IS NULL OR (json_type(config_json,'$.transport_layers[0].password')='text' AND json_extract(config_json,'$.transport_layers[0].password')=''))
 AND (json_type(config_json,'$.transport_layers[0].key_passphrase') IS NULL OR (json_type(config_json,'$.transport_layers[0].key_passphrase')='text' AND json_extract(config_json,'$.transport_layers[0].key_passphrase')=''))
 AND (json_type(config_json,'$.transport_layers[1].password') IS NULL OR (json_type(config_json,'$.transport_layers[1].password')='text' AND json_extract(config_json,'$.transport_layers[1].password')=''))
 AND (json_type(config_json,'$.transport_layers[1].key_passphrase') IS NULL OR (json_type(config_json,'$.transport_layers[1].key_passphrase')='text' AND json_extract(config_json,'$.transport_layers[1].key_passphrase')=''))
"#;

impl Storage {
    /// Update only one existing ID and its second-hop password, preserving all
    /// other JSON fields, secret ciphertext, profiles, layout and global policy.
    /// Explicit TLS-only CAS changes just the selected encrypted URL parameters.
    /// Failed validation, encryption or persistence rolls back the transaction.
    pub async fn update_route(&self, request: RouteUpdateRequest, dry_run: bool) -> Result<RouteUpdateReport, String> {
        request.validate()?;
        if dry_run {
            request.target_password(true)?;
        }
        let storage = self.clone();
        self.with_conn(move |conn| {
            let behavior = if dry_run { TransactionBehavior::Deferred } else { TransactionBehavior::Immediate };
            let tx = conn.transaction_with_behavior(behavior).map_err(|_| route_update::store_error())?;
            let policy = load_mcp_global_policy_in_tx(&tx).map_err(|_| route_update::store_error())?;
            if policy
                .allowed_tool_names
                .as_ref()
                .is_some_and(|names| !names.iter().any(|name| name == "dbx_update_connection"))
            {
                return Err("TOOL_OUT_OF_SCOPE: Route updates are not allowed by MCP policy.".into());
            }
            // A persistent ID allowlist permits only this exact target. Group
            // scopes remain unsupported; the CLI rejects run-scoped sessions.
            if policy.allowed_connection_ids.as_ref().is_some_and(|ids| !ids.contains(&request.plan.connection_id))
                || !policy.allowed_group_ids.is_empty()
            {
                return Err("CONNECTION_OUT_OF_SCOPE: Route update target is outside the allowed scope.".into());
            }
            if !dry_run && policy.read_only {
                return Err("MCP_READ_ONLY: Global MCP read-only mode blocks route updates.".into());
            }
            let plan = &request.plan;
            let json: String = tx
                .query_row(SELECT_ROUTE, [&plan.connection_id], |row| row.get(0))
                .optional()
                .map_err(|_| route_update::store_error())?
                .ok_or_else(route_update::mismatch)?;
            let current: ExpectedConnection = serde_json::from_str(&json).map_err(|_| route_update::mismatch())?;
            if current != plan.expected {
                return Err(route_update::mismatch());
            }
            let mut report = RouteUpdateReport {
                dry_run,
                connection_id: plan.connection_id.clone(),
                updated: false,
                target_password_changed: false,
                postgres_sslmode_changed: None,
                database_connection_attempted: false,
            };
            if plan.postgres_sslmode_cas.is_some() {
                // Validate only the selected encrypted URL parameters. In this
                // explicit mode preview reads that secret, never SSH/DB passwords.
                let codec = storage.secret_codec(false).map_err(|_| route_update::secret_error())?;
                validate_postgres_sslmode(&tx, &codec, &plan.connection_id)?;
                report.postgres_sslmode_changed = Some(false);
                if !dry_run {
                    persist_secret_in_tx(&tx, &codec, &plan.connection_id, URL_PARAMS_SECRET_KEY, "sslmode=disable")
                        .map_err(|_| route_update::store_error())?;
                    tx.commit().map_err(|_| route_update::store_error())?;
                    report.updated = true;
                    report.postgres_sslmode_changed = Some(true);
                }
                // Do not execute even an idempotent config_json UPDATE: retain
                // its original bytes and every unrelated ciphertext unchanged.
                return Ok(report);
            }
            if dry_run {
                return Ok(report);
            }
            // Decode only after the stored source and policy have been checked.
            let password = request.target_password(false)?;
            // Authenticate this profile's selected existing credential before
            // encrypting a replacement. A valid but unrelated environment key
            // must never create a mixed-key profile. No other secret is read.
            let codec = if password.as_ref().is_some_and(|password| !password.is_empty()) {
                let codec = storage.secret_codec(false).map_err(|_| route_update::secret_error())?;
                authenticate_target_key(&tx, &codec, &plan.connection_id, &current.transport_layers[1].id)?;
                Some(codec)
            } else {
                None
            };
            let target = &plan.expected_export.route[1];
            let mut fields = vec![
                ("$.transport_layers[1].host", serde_json::json!(target.host)),
                ("$.transport_layers[1].port", serde_json::json!(target.port)),
                ("$.transport_layers[1].user", serde_json::json!(target.user)),
                ("$.transport_layers[1].auth_method", serde_json::json!("password")),
            ];
            for (key, value) in plan.changes.as_object().expect("validated changes") {
                let path = match key.as_str() {
                    "host" => "$.host",
                    "port" => "$.port",
                    "database" => "$.database",
                    "ssl" => "$.ssl",
                    "second_hop_name" => "$.transport_layers[1].name",
                    _ => return Err(route_update::invalid()),
                };
                fields.push((path, value.clone()));
            }
            let mut sql = "UPDATE connections SET config_json=json_set(config_json".to_string();
            let mut values = Vec::new();
            for (path, value) in fields {
                // Paths come only from the fixed whitelist above, never input.
                sql.push_str(&format!(",'{path}',json(?)"));
                values.push(value.to_string());
            }
            sql.push_str(") WHERE id=?");
            values.push(plan.connection_id.clone());
            if tx.execute(&sql, params_from_iter(values)).map_err(|_| route_update::store_error())? != 1 {
                return Err(route_update::mismatch());
            }
            if let Some(password) = password {
                // No key creation, general secret loader, source re-encryption,
                // or deletion of unrelated secret prefixes is permitted here.
                let id = &plan.expected.transport_layers[1].id;
                let key = format!("{TRANSPORT_LAYER_SECRET_PREFIX}{id}.ssh_password");
                if password.is_empty() {
                    // Deletion is idempotent and needs no encryption key.
                    tx.execute(
                        "DELETE FROM connection_secrets WHERE connection_id=?1 AND key=?2",
                        params![plan.connection_id, key],
                    )
                    .map_err(|_| route_update::store_error())?;
                    // Explicit clearing must also remove this hop's legacy
                    // fallback, or load_connections would resurrect it.
                    let legacy = if id == "legacy" {
                        "ssh_password".to_string()
                    } else {
                        format!("{SSH_TUNNEL_SECRET_PREFIX}{id}.password")
                    };
                    tx.execute(
                        "DELETE FROM connection_secrets WHERE connection_id=?1 AND key=?2",
                        params![plan.connection_id, legacy],
                    )
                    .map_err(|_| route_update::store_error())?;
                } else {
                    let codec = codec.as_ref().expect("authenticated replacement codec");
                    persist_secret_in_tx(&tx, codec, &plan.connection_id, &key, &password)
                        .map_err(|_| route_update::store_error())?;
                }
                report.target_password_changed = true;
            }
            tx.commit().map_err(|_| route_update::store_error())?;
            report.updated = true;
            Ok(report)
        })
        .await
        .map_err(|error| match error.as_str() {
            message
                if message.starts_with("ROUTE_")
                    || message.starts_with("INVALID_ROUTE_UPDATE:")
                    || message.starts_with("TOOL_OUT_OF_SCOPE:")
                    || message.starts_with("CONNECTION_OUT_OF_SCOPE:")
                    || message.starts_with("MCP_READ_ONLY:") =>
            {
                error
            }
            _ => route_update::store_error(),
        })
    }
}

fn validate_postgres_sslmode(tx: &Transaction<'_>, codec: &SecretCodec, connection_id: &str) -> Result<(), String> {
    let inline_absent: bool = tx
        .query_row(
            "SELECT json_type(config_json,'$.url_params') IS NULL
             OR json_type(config_json,'$.url_params')='null'
             OR (json_type(config_json,'$.url_params')='text' AND json_extract(config_json,'$.url_params')='')
             FROM connections WHERE id=?1",
            [connection_id],
            |row| row.get(0),
        )
        .map_err(|_| route_update::store_error())?;
    if !inline_absent {
        return Err(route_update::mismatch());
    }
    let row: Option<(bool, Option<String>)> = tx
        .query_row(
            "SELECT secret='',secret_enc FROM connection_secrets WHERE connection_id=?1 AND key=?2",
            params![connection_id, URL_PARAMS_SECRET_KEY],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| route_update::store_error())?;
    let ciphertext = row
        .filter(|(no_plaintext, _)| *no_plaintext)
        .and_then(|(_, ciphertext)| ciphertext)
        .filter(|ciphertext| !ciphertext.is_empty())
        .ok_or_else(route_update::secret_error)?;
    let current = zeroize::Zeroizing::new(
        codec.decrypt(connection_id, URL_PARAMS_SECRET_KEY, &ciphertext).map_err(|_| route_update::secret_error())?,
    );
    // Exact single-item syntax deliberately rejects aliases, duplicate/conflicting
    // modes, encodings and additional parameters rather than parse/rewrite them.
    if current.as_str() != "sslmode=verify-full" {
        return Err(route_update::mismatch());
    }
    Ok(())
}

fn authenticate_target_key(
    tx: &Transaction<'_>,
    codec: &SecretCodec,
    connection_id: &str,
    hop_id: &str,
) -> Result<(), String> {
    let canonical = format!("{TRANSPORT_LAYER_SECRET_PREFIX}{hop_id}.ssh_password");
    let legacy = if hop_id == "legacy" {
        "ssh_password".to_string()
    } else {
        format!("{SSH_TUNNEL_SECRET_PREFIX}{hop_id}.password")
    };
    for key in [canonical, legacy] {
        let row: Option<(bool, Option<String>)> = tx
            .query_row(
                "SELECT secret='',secret_enc FROM connection_secrets WHERE connection_id=?1 AND key=?2",
                params![connection_id, key],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| route_update::store_error())?;
        let Some((no_plaintext, ciphertext)) = row else { continue };
        if !no_plaintext {
            return Err(route_update::secret_error());
        }
        let Some(ciphertext) = ciphertext.filter(|value| !value.is_empty()) else { continue };
        let _authenticated = zeroize::Zeroizing::new(
            codec.decrypt(connection_id, &key, &ciphertext).map_err(|_| route_update::secret_error())?,
        );
        return Ok(());
    }
    // No selected encrypted secret means there is no bounded proof that this
    // key belongs to the profile. Do not inspect another saved credential.
    Err(route_update::secret_error())
}

#[cfg(test)]
#[path = "route_storage_tests.rs"]
mod tests;
