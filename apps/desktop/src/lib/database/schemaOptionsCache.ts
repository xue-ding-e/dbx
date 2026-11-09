import { ref } from "vue";

/**
 * Schema names offered by the query editor's schema picker, keyed by
 * `connectionId:database:show-system|hide-system`.
 *
 * The list lives here instead of inside `useSchemaOptions()` so every picker shares
 * one cache and the app can drop it after the schemas change (#14582). A per-call
 * `ref` left the toolbar showing the list it loaded on mount even after the sidebar
 * had re-read the database.
 */
export const schemaOptionsByKey = ref<Record<string, string[]>>({});
export const loadingSchemaOptionsByKey = ref<Record<string, boolean>>({});
// Pending work has the same shared scope as its result and loading state.
export const schemaOptionsRequestsByKey = new Map<string, Promise<void>>();

/**
 * Drops the cached schema lists for a connection, or for a single database of it.
 * Keys are `<connectionId>:<database>:<system filter>`, so a database-scoped
 * invalidation matches both system-schema variants without touching other databases.
 */
export function invalidateSchemaOptionsCache(connectionId: string, database?: string): void {
  const prefix = database === undefined ? `${connectionId}:` : `${connectionId}:${database}:`;
  const keys = [...new Set([...Object.keys(schemaOptionsByKey.value), ...schemaOptionsRequestsByKey.keys(), ...Object.keys(loadingSchemaOptionsByKey.value)])].filter((key) => key.startsWith(prefix));

  // Revoke every old owner before reactive deletions can start replacement requests.
  for (const key of keys) schemaOptionsRequestsByKey.delete(key);
  for (const key of keys) {
    delete schemaOptionsByKey.value[key];
    if (!schemaOptionsRequestsByKey.has(key)) delete loadingSchemaOptionsByKey.value[key];
  }
}
