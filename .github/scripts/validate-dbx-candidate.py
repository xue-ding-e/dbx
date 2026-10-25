"""Manual validation overlay only; no publication or real connection access.

Resource/session guards adapted from AI440 c27fa175 admit()/run(), not its
product fixtures or RED classifier. Only configured GitHub-hosted Linux VMs.
The process guard signals the owned group and reaps its leader; runner teardown
is the outer boundary, not a proof of containment of malicious daemon escapes.
"""
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

PRODUCT_SHA = "fde384a73bb5f1d08e8d1986fd625b738d7890b4"

INTEGRATIONS = {'dbx-cli': ['connection_crud',
             'connection_import',
             'meatshell_import',
             'route_update'],
 'dbx-core': ['connection_crud',
              'connection_import',
              'meatshell_storage_cache'],
 'dbx-mcp': ['connection_crud', 'connection_import']}
CASES = {'crates/dbx-cli/tests/connection_crud.rs': ['native_cli_connection_crud_smoke'],
 'crates/dbx-cli/tests/connection_import.rs': ['cli_import_previews_by_default_and_requires_yes_to_persist',
                                               'cli_import_read_only_preview_is_allowed_but_apply_remains_blocked',
                                               'cli_import_rejects_invalid_encrypted_and_oversized_files',
                                               'cli_import_rejects_group_readable_input_before_preview_or_apply',
                                               'cli_import_cannot_run_in_web_mode_or_scoped_sessions',
                                               'cli_import_encrypted_bundle_uses_protected_passphrase_file',
                                               'explicit_initialization_creates_a_key_only_when_applying_to_an_empty_profile',
                                               'explicit_initialization_refuses_legacy_files_without_migrating_them',
                                               'cli_import_accepts_a_secure_passphrase_pipe_without_putting_it_in_argv'],
 'crates/dbx-cli/tests/meatshell_import.rs': ['bridge_honors_explicit_false_write_environment_before_opening_any_input',
                                              'bridge_rejects_remote_backend_and_scoped_sessions_without_opening_profile',
                                              'bridge_never_initializes_a_missing_profile_or_accepts_null_stdin'],
 'crates/dbx-cli/tests/route_update.rs': ['route_cli_rejects_remote_scope_and_run_write_prohibition_before_opening_profile',
                                          'route_cli_defaults_to_preview_then_updates_original_id_with_no_secret_output'],
 'crates/dbx-core/src/persistence/meatshell_storage_tests.rs': ['persistence::meatshell_storage::tests::bridge_preview_reads_no_source_secret_and_never_provisions_missing_key',
                                                                'persistence::meatshell_storage::tests::bridge_apply_rewraps_exact_selected_credentials_and_preserves_every_existing_row',
                                                                'persistence::meatshell_storage::tests::bridge_rejects_bad_source_credentials_without_changes',
                                                                'persistence::meatshell_storage::tests::bridge_rejects_selected_legacy_plaintext_instead_of_migrating_it',
                                                                'persistence::meatshell_storage::tests::bridge_rolls_back_after_config_and_secret_inserts_when_layout_fails',
                                                                'persistence::meatshell_storage::tests::bridge_enforces_native_policy_before_secrets_and_preserves_read_only_preview',
                                                                'persistence::meatshell_storage::tests::bridge_rejects_source_route_account_and_candidate_collisions',
                                                                'persistence::meatshell_storage::tests::bridge_strict_contract_rejects_secrets_in_plan_unknown_fields_and_route_changes',
                                                                'persistence::meatshell_storage::tests::bridge_rejects_boolean_ports_instead_of_coercing_them_to_one'],
 'crates/dbx-core/src/persistence/route_storage_tests.rs': ['persistence::route_storage::tests::route_preview_is_nonmutating_without_a_key_or_credential_reads',
                                                            'persistence::route_storage::tests::route_apply_preserves_original_id_unknown_fields_and_unselected_ciphertext',
                                                            'persistence::route_storage::tests::route_omitted_database_and_password_stay_untouched_but_explicit_empty_clears',
                                                            'persistence::route_storage::tests::route_wrong_existing_key_fails_without_creating_a_mixed_key_profile',
                                                            'persistence::route_storage::tests::route_failure_after_config_write_rolls_back_config_and_secrets_without_echo',
                                                            'persistence::route_storage::tests::route_rejects_null_or_missing_replacement_password_bad_metadata_and_shared_profiles',
                                                            'persistence::route_storage::tests::route_rejects_null_or_wrong_type_fields_in_the_saved_route',
                                                            'persistence::route_storage::tests::route_rejects_boolean_ports_instead_of_coercing_them_to_one',
                                                            'persistence::route_storage::tests::route_contract_rejects_unknown_fields_secret_plan_and_invalid_empty_values',
                                                            'persistence::route_storage::tests::route_global_id_allowlist_permits_listed_target_without_changing_policy',
                                                            'persistence::route_storage::tests::route_preview_and_apply_reject_excluded_ids_empty_allowlists_groups_and_forbidden_tools',
                                                            'persistence::route_storage::tests::route_apply_enforces_global_read_only_even_for_listed_target_without_mutation',
                                                            'persistence::route_storage::tests::route_tls_cas_preview_and_apply_preserve_json_policy_and_all_other_ciphertext',
                                                            'persistence::route_storage::tests::route_tls_cas_rejects_nonexact_duplicate_conflicting_aliased_and_malformed_params',
                                                            'persistence::route_storage::tests::route_tls_cas_rejects_unsupported_driver_and_inline_or_wrong_type_url_params',
                                                            'persistence::route_storage::tests::route_tls_cas_wrong_master_key_and_missing_or_plaintext_secret_fail_without_writes',
                                                            'persistence::route_storage::tests::route_tls_cas_contract_rejects_wrong_expectation_nulls_passwords_and_combined_changes',
                                                            'persistence::route_storage::tests::route_tls_cas_preserves_scope_tool_and_read_only_denials_without_mutation',
                                                            'persistence::route_storage::tests::route_tls_cas_persistence_failure_rolls_back_without_echo'],
 'crates/dbx-core/tests/connection_crud.rs': ['connection_crud_preserves_omitted_secrets_and_desktop_settings',
                                              'connection_crud_rejects_invalid_duplicate_missing_and_blocked_changes',
                                              'connection_crud_rejects_corrupt_stored_json_without_panicking',
                                              'connection_crud_concurrent_partial_updates_do_not_overwrite_each_other',
                                              'backend_errors_never_echo_submitted_credentials',
                                              'patch_validation_has_explicit_clear_semantics',
                                              'management_text_redacts_dsn_and_credential_assignment_variants',
                                              'details_do_not_expose_secrets_or_urls',
                                              'rejected_commit_admission_rolls_back_every_connection_mutation_and_its_secret_rows',
                                              'postcommit_hydration_failure_reports_persistence_without_claiming_rollback'],
 'crates/dbx-core/tests/connection_import.rs': ['preview_is_non_mutating_and_import_preserves_full_settings_and_existing_secrets',
                                                'duplicate_identity_never_replaces_saved_credentials_or_settings',
                                                'layout_and_tunnel_ids_are_remapped_without_overwriting_existing_data',
                                                'legacy_arrays_and_dbx_config_envelopes_are_supported',
                                                'invalid_bundles_fail_without_partial_import_or_secret_echo',
                                                'import_rechecks_global_policy_and_scopes_before_apply',
                                                'persistence_failure_rolls_back_connections_profiles_layout_and_secrets',
                                                'desktop_compatible_encrypted_fixture_decrypts_without_exposing_secrets',
                                                'equal_names_with_distinct_complete_identities_are_preserved_and_idempotent',
                                                'legacy_driver_canonicalization_does_not_break_duplicate_detection',
                                                'non_regular_import_input_is_rejected_without_blocking',
                                                'encrypted_import_refuses_readable_passphrase_and_shared_stdin',
                                                'timeout_inheritance_flags_follow_new_ids_and_preserve_existing_editor_settings',
                                                'invalid_timeout_inheritance_fails_without_partial_changes',
                                                'hostless_targets_remain_distinct_and_repeated_imports_skip_exact_dsns',
                                                'colliding_transport_ids_are_remapped_without_losing_independent_hop_credentials',
                                                'explicit_timeout_flags_require_completed_migration_in_existing_profiles',
                                                'empty_connection_strings_and_legacy_saved_targets_have_stable_identities'],
 'crates/dbx-core/tests/meatshell_storage_cache.rs': ['importer_repeated_key_failures_are_nonmutating_and_recover_after_key_restoration'],
 'crates/dbx-mcp/src/backend.rs': ['backend::tests::http_update_finishes_committed_cache_refresh_after_request_cancellation',
                                   'backend::tests::committed_copy_reload_failure_notifies_desktop_but_rejected_copy_does_not',
                                   'backend::tests::committed_reload_failure_evicts_old_runtime_state_but_precommit_failure_does_not',
                                   'backend::tests::overlapping_profile_updates_publish_cache_in_commit_order',
                                   'backend::tests::removed_profile_clears_all_owner_credentials_and_unlocks',
                                   'backend::tests::local_connection_mutations_notify_desktop_only_after_success',
                                   'backend::tests::local_connection_mutations_succeed_without_desktop',
                                   'backend::tests::local_connection_mutations_succeed_when_desktop_fails_or_stalls'],
 'crates/dbx-mcp/src/http.rs': ['http::tests::standalone_http_never_exposes_local_import_or_desktop_tools',
                                'http::tests::transport_session_management_verbs_are_not_accepted',
                                'http::tests::no_protocol_generation_receives_a_session_id',
                                'http::tests::http_serves_both_protocol_generations_without_sessions',
                                'http::tests::stateless_2026_requests_share_db_session_state',
                                'http::tests::http_service_shutdown_rolls_back_and_disconnects_inner_owner',
                                'http::tests::rejected_transport_verbs_do_not_starve_tools_or_discard_transactions',
                                'http::tests::oauth_http_principals_isolate_inner_sessions_and_cleanup',
                                'http::tests::oauth_http_discovery_authorization_isolation_limits_and_read_only',
                                'http::tests::policy_rotation_and_shutdown_cancel_stateless_handlers_and_preserve_rollback',
                                'http::tests::oauth_expiry_cancels_active_sql_and_disposes_its_uncertain_transaction',
                                'http::tests::both_stateless_protocol_generations_cancel_disconnected_handlers_and_release_permits',
                                'http::tests::independent_post_cancellation_notifications_match_upstream_stateless_semantics'],
 'crates/dbx-mcp/src/http_auth.rs': ['http_auth::tests::live_rotation_rejects_old_token_and_updates_hosts_and_origins',
                                     'http_auth::tests::host_validation_requires_exact_port_when_configured',
                                     'http_auth::tests::bare_ipv6_loopback_host_is_normalized_for_uri_authority_parsing',
                                     'http_auth::tests::post_response_and_control_budgets_are_independent_and_drop_releases_permits',
                                     'http_auth::tests::policy_generation_revokes_pending_dispatch_body_and_response_without_transport_sessions',
                                     'http_auth::tests::body_readers_are_bounded_and_released_on_disconnect_and_rotation',
                                     'http_auth::tests::stateless_headers_are_revalidated_and_malformed_transport_ids_fail_closed',
                                     'http_auth::tests::oauth_expiry_ends_only_its_post_response_and_releases_the_permit',
                                     'http_auth::tests::policy_generation_revocation_is_durable_before_waiters_subscribe'],
 'crates/dbx-mcp/src/http_mutations.rs': ['http_mutations::tests::non_http_mutations_keep_inline_cancellation_semantics',
                                          'http_mutations::tests::expired_rotated_disconnected_and_closed_requests_never_start_mutations',
                                          'http_mutations::tests::policy_rotation_or_dispatch_drop_before_first_poll_cannot_start_a_queued_write',
                                          'http_mutations::tests::committed_mutation_cleanup_finishes_after_expiry_rotation_and_response_drop',
                                          'http_mutations::tests::live_request_guard_rejects_revocation_at_the_storage_commit_boundary',
                                          'http_mutations::tests::panicking_completion_releases_capacity_and_does_not_block_shutdown',
                                          'http_mutations::tests::cancelled_responses_retain_all_request_capacity_and_shutdown_waits_for_completion'],
 'crates/dbx-mcp/src/http_principals.rs': ['http_principals::tests::empty_principal_keys_fail_closed_without_consuming_capacity',
                                           'http_principals::tests::same_principal_reuses_state_and_other_principals_are_isolated',
                                           'http_principals::tests::capacity_rejects_new_principals_without_evicting_existing_state',
                                           'http_principals::tests::active_lease_prevents_idle_eviction_and_drop_refreshes_idle_time',
                                           'http_principals::tests::shutdown_rejects_admission_and_waits_for_leases_before_draining_sessions',
                                           'http_principals::tests::retiring_cleanup_keeps_its_capacity_slot_until_backend_close_finishes',
                                           'http_principals::tests::shutdown_waits_for_cleanup_already_detached_by_reaping'],
 'crates/dbx-mcp/src/oauth.rs': ['oauth::tests::validates_signature_claims_scope_and_explicit_profile_owner',
                                 'oauth::tests::rejects_unsafe_configuration_and_private_keys',
                                 'oauth::tests::publishes_resource_metadata_without_profile_or_claims'],
 'crates/dbx-mcp/tests/connection_crud.rs': ['mcp_connection_crud_round_trip_preserves_credentials_and_rechecks_policy',
                                             'scoped_mcp_does_not_advertise_connection_update'],
 'crates/dbx-mcp/tests/connection_import.rs': ['mcp_import_preview_confirmation_and_idempotent_apply_are_secret_safe',
                                               'mcp_import_rechecks_policy_between_preview_and_confirmation',
                                               'mcp_import_rejects_malformed_or_encrypted_input_without_echoing_values',
                                               'mcp_import_rejects_group_readable_file',
                                               'mcp_import_is_unavailable_in_web_mode_or_scoped_sessions',
                                               'mcp_import_encrypted_bundle_uses_only_passphrase_file_paths']}
FRONTEND = ['apps/desktop/src/components/config/__tests__/ConfigUnencryptedExportDialog.spec.ts',
 'apps/desktop/src/components/connection/__tests__/ConnectionDialog.databasePicker.spec.ts',
 'apps/desktop/src/components/diff/__tests__/SchemaDiffDdlPanel.spec.ts',
 'apps/desktop/src/components/grid/__tests__/DataGridResultCellFilter.spec.ts',
 'apps/desktop/src/components/import/__tests__/TableImportDialog.batchSelection.spec.ts',
 'apps/desktop/src/composables/__tests__/useDialogSources.spec.ts',
 'apps/desktop/src/i18n/__tests__/forkFeatureLocaleParity.spec.ts',
 'apps/desktop/src/lib/__tests__/dataGrid/gridClientFilter.spec.ts',
 'apps/desktop/src/lib/__tests__/imports/redisDesktopManagerImport.spec.ts',
 'apps/desktop/src/lib/__tests__/mcp/mcpPolicySelection.spec.ts',
 'apps/desktop/src/lib/__tests__/schema/schemaDiffDdlNormalize.spec.ts',
 'apps/desktop/src/lib/__tests__/sql/sqlCompletion.performance.spec.ts',
 'apps/desktop/src/lib/connection/connectionConfigTransfer.spec.ts',
 'apps/desktop/src/stores/__tests__/connectionStore.timeout.spec.ts',
 'packages/app-tests/connectionImportRoundTrip.test.ts']

def admit(path):
    """Owned-process/visible-v2 observation, only on the configured hosted VM.

    Never reads PID 1 or another process's namespace. This is not a generic
    hostile-container capacity proof. Unsupported layouts and denied reads stop.
    """
    def require(condition, message):
        if not condition:
            raise RuntimeError("ADMISSION_UNKNOWN: " + message)

    def record_read(label, operation):
        print("MEMORY_READ " + label, flush=True)
        try:
            return operation()
        except OSError as error:
            print(json.dumps({"observation": "read_failed", "read_class": label,
                              "error_type": type(error).__name__, "errno": error.errno}), flush=True)
            raise

    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("RUNNER_OS") == "Linux", "requires the configured standard GitHub-hosted Linux VM")
    info = record_read("proc-meminfo", lambda: Path("/proc/meminfo").read_text())
    fields = {}
    for line in info.splitlines():
        key, _, value = line.partition(":")
        if key in ("MemTotal", "MemAvailable"):
            parts = value.split()
            require(len(parts) == 2 and parts[1] == "kB" and parts[0].isdigit(), "invalid memory units")
            fields[key] = int(parts[0]) * 1024
    require(set(fields) == {"MemTotal", "MemAvailable"}, "missing host memory metrics")
    require(0 <= fields["MemAvailable"] <= fields["MemTotal"], "invalid available memory")
    cgroup = record_read("proc-self-cgroup", lambda: Path("/proc/self/cgroup").read_text())
    mounts = record_read("proc-self-mountinfo", lambda: Path("/proc/self/mountinfo").read_text())
    namespace = record_read("proc-self-cgroup-namespace", lambda: os.readlink("/proc/self/ns/cgroup"))
    require(bool(re.fullmatch(r"cgroup:\[[0-9]+\]", namespace)), "unknown own namespace")
    entries = cgroup.splitlines()
    require(len(entries) == 1 and entries[0].startswith("0::"), "v1/mixed cgroups unsupported")
    relative = entries[0][3:]

    def safe_absolute(value):
        require(value.startswith("/") and "\\" not in value and "\0" not in value,
                "unsupported path encoding")
        require(value == "/" or all(part not in ("", ".", "..") for part in value[1:].split("/")), "unsafe cgroup path")
        return value

    safe_absolute(relative)
    found, points = [], []
    for line in mounts.splitlines():
        left, separator, right = line.partition(" - ")
        require(bool(separator), "invalid mountinfo")
        columns = left.split()
        require(len(columns) >= 6, "invalid mount columns")
        kind = right.split()[0]
        require(kind != "cgroup", "mixed/v1 hierarchy unsupported")
        points.append(safe_absolute(columns[4]))
        if kind == "cgroup2":
            require(columns[3] == "/", "hidden cgroup ancestors")
            found.append(safe_absolute(columns[4]))
    require(len(found) == 1, "ambiguous or missing v2 mount")
    mount = found[0]
    require(not any(point.startswith(mount + "/") for point in points), "nested mount hides ancestry")
    require(str(Path(mount).resolve(strict=True)) == mount, "cgroup mount alias")
    components = relative.strip("/").split("/") if relative != "/" else []
    require(len(components) <= 128, "cgroup hierarchy too deep")
    descriptor = record_read("cgroup-v2-root-directory", lambda: os.open(mount, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    records = []

    def control(fd, name, depth, maximum=128):
        label = f"cgroup-v2-depth-{depth}-{name}"
        def read():
            child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                require(stat.S_ISREG(os.fstat(child).st_mode), "nonregular control")
                data = os.read(child, maximum + 1)
                require(len(data) <= maximum, "oversized control")
                return data.decode("ascii").strip()
            finally:
                os.close(child)
        return record_read(label, read)

    try:
        for depth in range(len(components) + 1):
            before = os.fstat(descriptor)
            if depth == 0:
                require("memory" in control(descriptor, "cgroup.controllers", depth).split(), "memory controller unavailable")
                root_stat = control(descriptor, "memory.stat", depth, 65536)
                names = set()
                for line in root_stat.splitlines():
                    parts = line.split()
                    require(len(parts) == 2 and bool(re.fullmatch(r"[a-z][a-z0-9_]*", parts[0])) and parts[1].isdigit(), "invalid root memory.stat")
                    require(parts[0] not in names, "duplicate root memory.stat field")
                    names.add(parts[0])
                require({"anon", "file", "kernel_stack", "pagetables"} <= names, "incomplete root memory.stat")
                # On this ordinary VM, positive memory.stat plus BOTH scalar
                # controls absent identifies the real kernel root, not a hidden
                # namespaced child. An EACCES is never treated as absence.
                for name in ("memory.max", "memory.current"):
                    try:
                        control(descriptor, name, depth)
                    except FileNotFoundError:
                        pass
                    else:
                        raise RuntimeError("ADMISSION_UNKNOWN: root scalar controls imply incomplete ancestry")
                records.append({"depth": depth, "limit": None, "current": None,
                                "root": "positive memory.stat and exact ENOENT scalar controls"})
            else:
                maximum = control(descriptor, "memory.max", depth)
                current = control(descriptor, "memory.current", depth)
                require(maximum == "max" or maximum.isdigit(), "invalid memory.max")
                require(current.isdigit(), "invalid memory.current")
                records.append({"depth": depth, "limit": None if maximum == "max" else int(maximum), "current": int(current)})
            after = os.fstat(descriptor)
            require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "cgroup changed during observation")
            if depth < len(components):
                child = record_read(f"cgroup-v2-descend-{depth + 1}", lambda: os.open(components[depth], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor))
                os.close(descriptor)
                descriptor = child
    finally:
        os.close(descriptor)
    require(record_read("proc-self-cgroup-recheck", lambda: Path("/proc/self/cgroup").read_text()) == cgroup, "process migrated")
    require(record_read("proc-self-mountinfo-recheck", lambda: Path("/proc/self/mountinfo").read_text()) == mounts, "mounts changed")
    require(record_read("proc-self-namespace-recheck", lambda: os.readlink("/proc/self/ns/cgroup")) == namespace, "namespace changed")
    finite = [item for item in records if item["limit"] is not None]
    available = min([fields["MemAvailable"]] + [max(0, item["limit"] - item["current"]) for item in finite])
    capacity = min([fields["MemTotal"]] + [item["limit"] for item in finite])
    disk = shutil.disk_usage(path).free
    observation = {"host_available_bytes": fields["MemAvailable"], "effective_capacity_bytes": capacity,
                   "effective_available_bytes": available, "disk_free_bytes": disk,
                   "visible_ancestor_limits": records}
    print(json.dumps(observation), flush=True)
    require(capacity >= 12 * 1024**3, "less than 12 GiB effective capacity")
    require(available >= 10 * 1024**3, "less than 10 GiB effective available memory")
    require(disk >= 25 * 1024**3, "less than 25 GiB available disk")
    return observation

def run(args, cwd, name, timeout=120, env=None):
    remaining = int(deadline - time.monotonic())
    require(remaining > 5, "Validation's process budget reached the cleanup reserve")
    print(f"RUN {name}", flush=True)
    command_deadline = time.monotonic() + min(timeout, remaining) - 5
    path = output / f"{name}.log"
    child = None
    timed_out = False
    with path.open("w") as stream:
        try:
            # Defer the parent's cancellation exception until the child
            # object is owned; do not give children a blocked signal mask.
            cancellation["spawning"] = True
            try:
                child = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                         stdout=stream, stderr=subprocess.STDOUT,
                                         start_new_session=True)
            finally:
                cancellation["spawning"] = False
            if cancellation["pending"] is not None:
                raise InterruptedError("Validation interrupted during child creation")
            # WNOWAIT preserves the leader PID until group cleanup, avoiding
            # signaling a recycled numeric process group after a reap.
            while os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
                if time.monotonic() >= command_deadline or path.stat().st_size > 128 * 1024**2:
                    timed_out = True
                    break
                time.sleep(0.1)
            timed_out |= path.stat().st_size > 128 * 1024**2
        finally:
            if child is not None:
                # Standard runner teardown is the outer boundary. The owned
                # session additionally contains ordinary compiler/test
                # descendants, not deliberately escaping hostile daemons.
                previous_handlers = {sig: signal.signal(sig, signal.SIG_IGN)
                                     for sig in (signal.SIGINT, signal.SIGTERM)}
                record = {"label": name, "pid": child.pid, "timed_out_or_output_limit": timed_out,
                          "cleanup": "pending", "exit_code": None}
                try:
                    for sig, seconds in [(signal.SIGTERM, 1), (signal.SIGKILL, 1)]:
                        try:
                            os.killpg(child.pid, sig)
                        except ProcessLookupError:
                            pass
                        time.sleep(seconds)
                    code = child.wait(timeout=3)
                    record.update(cleanup="owned group TERM/KILL sent; leader reaped", exit_code=code)
                finally:
                    command_records.append(record)
                    (output / "command-records.json").write_text(json.dumps(command_records, indent=2) + "\n")
                    for sig, handler in previous_handlers.items():
                        signal.signal(sig, handler)
    if timed_out:
        raise RuntimeError(f"Process time/output budget exceeded: {name}; owned group terminated and leader reaped")
    content = path.read_text()
    print(f"RESULT {name}: {code}", flush=True)
    if code:
        print(content[-10000:], flush=True)
    return code, content

def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checked(args, name, timeout, env=None):
    code, content = run(args, root, name, timeout, env)
    require(code == 0, f"{name} failed; compile/setup failure is never test evidence")
    return content


def isolated_env(directory):
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    env = {key: os.environ[key] for key in ["PATH", "LANG", "LC_ALL", "TZ", "LD_LIBRARY_PATH"] if key in os.environ}
    env.update(HOME=str(directory), XDG_CONFIG_HOME=str(directory / "config"),
               XDG_DATA_HOME=str(directory / "data"), XDG_CACHE_HOME=str(directory / "cache"),
               TMPDIR=str(directory), DBX_DATA_DIR=str(directory / "dbx"),
               DBX_SECRET_KEY_FILE=str(directory / "synthetic-secret.key"),
               RUST_BACKTRACE="0", RUST_TEST_THREADS="1", CI="true",
               NODE_OPTIONS="--max-old-space-size=8192")
    return env


def network_fixture(args):
    # No sudo, host firewall edits, host service restarts, or fallback to a live
    # network. Unsupported user/net namespaces stop the validation.
    return ["unshare", "--user", "--map-current-user", "--keep-caps", "--net", "--", "sh", "-eu", "-c",
            'ip link set lo up; exec setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs -- "$@"', "synthetic-network", *args]


def discover_tests(content):
    return sorted(line[:-6] for line in content.splitlines() if line.endswith(": test"))


def validate_result(content, count):
    require(f"test result: ok. {count} passed; 0 failed; 0 ignored;" in content,
            "Missing exact non-skipped Rust test success count")


def main():
    global root, output, deadline, command_records, cancellation
    require(len(sys.argv) in (3, 4) and re.fullmatch(r"[a-f0-9]{40}", sys.argv[1]), "Exact validation SHA and output directory required")
    preflight_only = len(sys.argv) == 4
    require(not preflight_only or sys.argv[3] == "--preflight", "Unknown validation mode")
    root = Path(__file__).resolve().parents[2]
    output = Path(sys.argv[2]).resolve()
    require(not output.is_relative_to(root), "Logs/profiles/targets must be outside source checkout")
    output.mkdir(parents=True, exist_ok=False)
    deadline = time.monotonic() + 75 * 60
    command_records = []
    cancellation = {"spawning": False, "pending": None}

    def terminate(signum, _frame):
        if cancellation["spawning"]:
            cancellation["pending"] = signum
        else:
            raise InterruptedError(f"Validation interrupted by signal {signum}")
    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    require(checked(["git", "rev-parse", "HEAD"], "source-sha", 15).strip() == sys.argv[1], "Wrong validation checkout")
    require(not checked(["git", "status", "--porcelain"], "source-clean", 15).strip(), "Dirty validation source")
    changed = checked(["git", "diff", "--name-only", PRODUCT_SHA, "HEAD"], "overlay-scope", 15).splitlines()
    allowed = {".github/workflows/plugin-dev-host.yml", ".github/workflows/windows-service-smoke.yml",
               ".github/scripts/validate-dbx-candidate.py", ".github/scripts/test-validate-dbx-candidate.py"}
    require(set(changed) <= allowed, "Validation overlay changed product source")
    (output / "selector-manifest.json").write_text(json.dumps({"product_sha": PRODUCT_SHA, "validation_sha": sys.argv[1],
        "rust_cases": CASES, "rust_count": sum(map(len, CASES.values())), "frontend_files": FRONTEND,
        "features": {"core": ["duckdb-sidecar", "mq-admin", "sqlite-bundled", "test-support"],
                     "cli_and_mcp": "unchanged package defaults"},
        "not_covered": ["desktop default sqlcipher/dynamodb/system-fonts", "native os-keyring", "platform packages", "real database/SSH/Xen topology", "full upstream suite"]}, indent=2))
    admit(output)
    profile_base = output.parent / (output.name + "-synthetic-profiles")
    profile_base.mkdir(mode=0o700)
    # Probe the exact test isolation boundary before expensive compilation.
    probe = r"""
import os, pathlib, socket, sqlite3, sys, tempfile
if os.geteuid() != int(sys.argv[1]) or os.geteuid() == 0:
    raise RuntimeError("Fixture UID mapping changed")
if {name for _, name in socket.if_nameindex()} != {"lo"}:
    raise RuntimeError("Fixture network is not loopback-only")
status = pathlib.Path("/proc/self/status").read_text()
if "CapEff:\t0000000000000000" not in status or "NoNewPrivs:\t1" not in status:
    raise RuntimeError("Fixture privilege boundary is missing")
for family, address in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
    with socket.socket(family) as listener, socket.socket(family) as client:
        listener.settimeout(2)
        client.settimeout(2)
        listener.bind((address, 0))
        listener.listen(1)
        client.connect(listener.getsockname())
        peer, _ = listener.accept()
        with peer:
            peer.settimeout(2)
            client.sendall(b"synthetic-loopback")
            if peer.recv(64) != b"synthetic-loopback":
                raise RuntimeError("Fixture loopback transport failed")
with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
    with sqlite3.connect(str(pathlib.Path(directory) / "synthetic.sqlite")) as db:
        db.execute("create table synthetic(value integer)")
        db.execute("insert into synthetic values (1)")
        db.rollback()
        if db.execute("select count(*) from synthetic").fetchone() != (0,):
            raise RuntimeError("Fixture SQLite rollback failed")
"""
    checked(network_fixture(["python3", "-c", probe, str(os.geteuid())]),
            "network-isolation", 30, isolated_env(profile_base / "probe"))
    if preflight_only:
        (output / "preflight-only.json").write_text(json.dumps({"scope": "source/resource/isolated fixture qualification only; NOT test acceptance", "validation_sha": sys.argv[1]}))
        return
    build_env = os.environ.copy()
    build_env.update(CARGO_BUILD_JOBS="1", CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0",
                     CARGO_PROFILE_TEST_DEBUG="0", RUST_MIN_STACK="8388608",
                     CARGO_TARGET_DIR=str(output.parent / (output.name + "-target")),
                     TMPDIR=str(profile_base / "build-tmp"))
    Path(build_env["TMPDIR"]).mkdir()
    artifacts = {}
    compile_deadline = time.monotonic() + 45 * 60
    for crate in ["dbx-core", "dbx-mcp", "dbx-cli"]:
        admit(output)
        args = ["cargo", "test", "--locked", "--no-run", "--message-format=json", "-p", crate]
        if crate == "dbx-core":
            args += ["--no-default-features", "--features", "duckdb-sidecar,mq-admin,sqlite-bundled,test-support"]
        if crate != "dbx-cli":
            args += ["--lib"]
        for target in INTEGRATIONS[crate]:
            args += ["--test", target]
        remaining = int(compile_deadline - time.monotonic())
        require(remaining > 10, "Compile-stage budget exhausted")
        content = checked(args, "compile-" + crate, remaining, build_env)
        for line in content.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("reason") == "compiler-artifact" and item.get("executable") and item.get("profile", {}).get("test"):
                src = Path(item["target"]["src_path"]).resolve()
                if src.is_relative_to(root):
                    artifacts[str(src.relative_to(root))] = item["executable"]
    test_deadline = time.monotonic() + 8 * 60
    for index, (source, expected) in enumerate(CASES.items()):
        parts = source.split("/")
        artifact_key = source if parts[2] == "tests" else "/".join(parts[:2]) + "/src/lib.rs"
        require(artifact_key in artifacts, "Missing compiled test artifact: " + artifact_key)
        binary = artifacts[artifact_key]
        profile = profile_base / ("rust-" + str(index))
        env = isolated_env(profile)
        content = checked(network_fixture([binary, "--list", "--format", "terse"]), f"list-{index}", 30, env)
        discovered = discover_tests(content)
        require(set(expected) <= set(discovered), "Missing Rust test selector: " + source)
        if parts[2] == "tests":
            require(sorted(expected) == discovered, "Integration test inventory changed: " + source)
            groups = [(None, expected)]
        elif source.endswith("backend.rs"):
            groups = [(name, [name]) for name in expected]
        else:
            prefix = expected[0].rsplit("::", 1)[0] + "::"
            require(sorted(expected) == [name for name in discovered if name.startswith(prefix)], "Library module test inventory changed")
            groups = [(prefix, expected)]
        for ordinal, (selector, selected) in enumerate(groups):
            remaining = int(test_deadline - time.monotonic())
            require(remaining > 10, "Rust test-stage budget exhausted")
            args = [binary, "--test-threads=1"]
            if selector:
                args += [selector]
                if len(selected) == 1:
                    args += ["--exact"]
            result = checked(network_fixture(args), f"rust-{index}-{ordinal}", min(120, remaining), env)
            validate_result(result, len(selected))
    admit(output)
    frontend_deadline = time.monotonic() + 20 * 60
    def frontend_run(args, name, env=None, isolated=False):
        remaining = int(frontend_deadline - time.monotonic())
        require(remaining > 10, "Frontend-stage budget exhausted")
        return checked(network_fixture(args) if isolated else args, name, remaining, env)
    frontend_run(["pnpm", "--filter", "dbx...", "install", "--frozen-lockfile"], "frontend-install", build_env)
    env = isolated_env(profile_base / "frontend")
    frontend_run(["node", "scripts/sync-connection-types.mjs", "--check"], "generated-types", env, True)
    frontend_run(["node", "node_modules/vue-tsc/bin/vue-tsc.js", "--noEmit", "--project", "apps/desktop/tsconfig.json"], "frontend-typecheck", env, True)
    result_path = output / "vitest-results.json"
    frontend_run(["node", "node_modules/vitest/vitest.mjs", "run", *FRONTEND, "--maxWorkers=1", "--fileParallelism=false", "--reporter=json", "--outputFile=" + str(result_path)], "frontend-tests", env, True)
    results = json.loads(result_path.read_text())
    require(results["success"] and results["numFailedTests"] == 0 and results["numPendingTests"] == 0
            and results["numPassedTests"] > 0, "Frontend tests not all passed without skips")
    actual_files = {str(Path(item["name"]).resolve().relative_to(root)) for item in results["testResults"]}
    require(actual_files == set(FRONTEND), "Vitest file selection mismatch")
    require(not checked(["git", "status", "--porcelain"], "source-final-clean", 15).strip(), "Validation modified source")
    (output / "success.json").write_text(json.dumps({"product_sha": PRODUCT_SHA,
        "validation_sha": sys.argv[1], "rust_passed": sum(map(len, CASES.values())),
        "frontend_passed": results["numPassedTests"], "frontend_files": len(FRONTEND),
        "scope": "targeted Linux CLI/MCP closure and frontend; NOT a release gate"}, indent=2))


if __name__ == "__main__":
    main()
