import { useConnectionStore } from "@/stores/connectionStore";
import { isSchemaAware as isSchemaAwareType, isSingleDatabase, usesTreeSchemaMode } from "@/lib/database/databaseCapabilities";
import { sortSidebarNames } from "@/lib/database/databaseTree";
import { filterSchemaNamesForConnection } from "@/lib/database/visibleDatabases";
import { loadingSchemaOptionsByKey, schemaOptionsByKey, schemaOptionsRequestsByKey } from "@/lib/database/schemaOptionsCache";
import type { ConnectionConfig } from "@/types/database";
import * as api from "@/lib/backend/api";

export function hasSchemaOptionsCacheEntry(options: Record<string, string[]>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(options, key);
}

export function schemaOptionsCacheKey(connectionId: string, database: string, showSystemSchemas: boolean): string {
  return `${connectionId}:${database}:${showSystemSchemas ? "show-system" : "hide-system"}`;
}

export function schemaOptionsForConnection(schemaNames: string[], connection: Pick<ConnectionConfig, "db_type" | "driver_profile" | "visible_databases" | "visible_schemas" | "show_system_schemas"> | undefined, database = ""): string[] {
  // Keep numeric schema suffixes in human order (SCHEMA2 before SCHEMA10), matching the database tree.
  return sortSidebarNames(filterSchemaNamesForConnection(schemaNames, connection, database));
}

export function useSchemaOptions() {
  const connectionStore = useConnectionStore();

  const schemaOptions = schemaOptionsByKey;
  const loadingSchemaOptions = loadingSchemaOptionsByKey;
  const schemaRequests = schemaOptionsRequestsByKey;

  function cacheKey(connectionId: string, database: string) {
    return schemaOptionsCacheKey(connectionId, database, connectionStore.getConfig(connectionId)?.show_system_schemas === true);
  }

  function isSchemaAware(connectionId: string): boolean {
    return isSchemaAwareType(connectionStore.getConfig(connectionId)?.db_type);
  }

  async function loadSchemaOptions(connectionId: string, database: string) {
    if (!isSchemaAware(connectionId)) return;
    const connection = connectionStore.getConfig(connectionId);
    const dbType = connection?.db_type;
    if (!database && !isSingleDatabase(dbType) && !usesTreeSchemaMode(dbType)) return;
    const key = cacheKey(connectionId, database);
    if (hasSchemaOptionsCacheEntry(schemaOptions.value, key)) return;
    const pending = schemaRequests.get(key);
    if (pending) return pending;

    // Claim the shared request before reactive loading updates can re-enter this function.
    const request = Promise.resolve().then(async () => {
      try {
        await connectionStore.ensureConnected(connectionId);
        const schemaNames = await api.listSchemas(connectionId, database);
        if (schemaRequests.get(key) === request) {
          schemaOptions.value[key] = schemaOptionsForConnection(schemaNames, connection, database);
        }
      } finally {
        // Invalidated requests still settle for their callers, but no longer own this key.
        if (schemaRequests.get(key) === request) {
          schemaRequests.delete(key);
          loadingSchemaOptions.value[key] = false;
        }
      }
    });
    schemaRequests.set(key, request);
    loadingSchemaOptions.value[key] = true;
    return request;
  }

  function getSchemaOptionsForDb(connectionId: string, database: string): string[] {
    return schemaOptions.value[cacheKey(connectionId, database)] ?? [];
  }

  function isLoadingSchemas(connectionId: string, database: string): boolean {
    return !!loadingSchemaOptions.value[cacheKey(connectionId, database)];
  }

  return {
    schemaOptions,
    loadingSchemaOptions,
    loadSchemaOptions,
    getSchemaOptionsForDb,
    isLoadingSchemas,
    isSchemaAware,
  };
}
