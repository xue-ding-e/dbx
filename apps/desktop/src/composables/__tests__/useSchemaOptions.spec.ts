import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { watch } from "vue";
import { schemaOptionsCacheKey, schemaOptionsForConnection, useSchemaOptions } from "@/composables/useSchemaOptions";
import { invalidateSchemaOptionsCache, loadingSchemaOptionsByKey, schemaOptionsByKey } from "@/lib/database/schemaOptionsCache";

const listSchemas = vi.hoisted(() => vi.fn());
const getConfig = vi.hoisted(() => vi.fn(() => ({ db_type: "postgres", show_system_schemas: false })));
const ensureConnected = vi.hoisted(() => vi.fn(async () => undefined));

vi.mock("@/stores/connectionStore", () => ({
  useConnectionStore: () => ({
    getConfig,
    ensureConnected,
  }),
}));

vi.mock("@/lib/backend/api", () => ({ listSchemas }));

describe("schemaOptionsForConnection", () => {
  it("sorts schema names with numeric suffixes naturally", () => {
    const schemaNames = ["WMWMSE16", "WMWMSE17", "WMWMSE18", "WMWMSE19", "WMWMSE2", "WMWMSE20", "WMWMSE1", "WMWMSE10"];

    expect(schemaOptionsForConnection(schemaNames, undefined)).toEqual(["WMWMSE1", "WMWMSE2", "WMWMSE10", "WMWMSE16", "WMWMSE17", "WMWMSE18", "WMWMSE19", "WMWMSE20"]);
    expect(schemaNames).toEqual(["WMWMSE16", "WMWMSE17", "WMWMSE18", "WMWMSE19", "WMWMSE2", "WMWMSE20", "WMWMSE1", "WMWMSE10"]);
  });

  it("sorts after applying the visible schema filter", () => {
    const connection = {
      db_type: "oracle" as const,
      visible_schemas: {
        ORCL: ["WMWMSE10", "WMWMSE2"],
      },
    };

    expect(schemaOptionsForConnection(["WMWMSE10", "SYSTEM", "WMWMSE2", "WMWMSE1"], connection, "ORCL")).toEqual(["WMWMSE2", "WMWMSE10"]);
  });

  it.each(["opengauss", "kingbase"] as const)("includes system schemas for %s when enabled", (dbType) => {
    expect(
      schemaOptionsForConnection(["information_schema", "pg_catalog", "public"], {
        db_type: dbType,
        show_system_schemas: true,
      }),
    ).toEqual(["information_schema", "pg_catalog", "public"]);
  });
});

describe("schemaOptionsCacheKey", () => {
  it("separates hidden and visible system-schema results", () => {
    expect(schemaOptionsCacheKey("connection-1", "postgres", false)).not.toBe(schemaOptionsCacheKey("connection-1", "postgres", true));
  });
});

describe("invalidateSchemaOptionsCache (#14582)", () => {
  beforeEach(() => {
    schemaOptionsByKey.value = {};
  });

  it("drops both system-schema variants of one database and keeps the neighbours", () => {
    const showSystem = schemaOptionsCacheKey("c1", "app", true);
    const hideSystem = schemaOptionsCacheKey("c1", "app", false);
    const otherDatabase = schemaOptionsCacheKey("c1", "archive", false);
    const otherConnection = schemaOptionsCacheKey("c2", "app", false);
    schemaOptionsByKey.value = { [showSystem]: ["public"], [hideSystem]: ["public"], [otherDatabase]: ["x"], [otherConnection]: ["y"] };

    invalidateSchemaOptionsCache("c1", "app");

    expect(schemaOptionsByKey.value[showSystem]).toBeUndefined();
    expect(schemaOptionsByKey.value[hideSystem]).toBeUndefined();
    expect(schemaOptionsByKey.value[otherDatabase]).toEqual(["x"]);
    expect(schemaOptionsByKey.value[otherConnection]).toEqual(["y"]);
  });

  it("drops every database of the connection when none is named", () => {
    schemaOptionsByKey.value = { [schemaOptionsCacheKey("c1", "app", false)]: ["a"], [schemaOptionsCacheKey("c1", "archive", false)]: ["b"], [schemaOptionsCacheKey("c2", "app", false)]: ["c"] };

    invalidateSchemaOptionsCache("c1");

    expect(Object.keys(schemaOptionsByKey.value)).toEqual([schemaOptionsCacheKey("c2", "app", false)]);
  });

  it("does not treat a longer connection id as the same connection", () => {
    const neighbour = schemaOptionsCacheKey("c10", "app", false);
    schemaOptionsByKey.value = { [schemaOptionsCacheKey("c1", "app", false)]: ["a"], [neighbour]: ["b"] };

    invalidateSchemaOptionsCache("c1");

    expect(schemaOptionsByKey.value[neighbour]).toEqual(["b"]);
  });
});

describe("useSchemaOptions sharing (#14582)", () => {
  beforeEach(() => {
    schemaOptionsByKey.value = {};
    listSchemas.mockReset();
  });

  it("shares one cache across pickers and re-reads it after invalidation", async () => {
    const toolbar = useSchemaOptions();
    const other = useSchemaOptions();

    listSchemas.mockResolvedValue(["public"]);
    await toolbar.loadSchemaOptions("c1", "app");
    expect(toolbar.getSchemaOptionsForDb("c1", "app")).toEqual(["public"]);

    // A second picker reuses the shared list instead of hitting the server again.
    await other.loadSchemaOptions("c1", "app");
    expect(listSchemas).toHaveBeenCalledTimes(1);
    expect(other.getSchemaOptionsForDb("c1", "app")).toEqual(["public"]);

    // After "the schemas changed", the next open re-reads and sees the new schema.
    listSchemas.mockResolvedValue(["public", "reporting"]);
    invalidateSchemaOptionsCache("c1", "app");
    await other.loadSchemaOptions("c1", "app");
    expect(listSchemas).toHaveBeenCalledTimes(2);
    expect(other.getSchemaOptionsForDb("c1", "app")).toEqual(["public", "reporting"]);
    expect(toolbar.getSchemaOptionsForDb("c1", "app")).toEqual(["public", "reporting"]);
  });
});

describe("useSchemaOptions shared request ownership", () => {
  const requests: { resolve: (value: string[]) => void }[] = [];
  const loads: Promise<void>[] = [];
  const stopWatches: (() => void)[] = [];

  function deferredSchemas() {
    let resolve!: (value: string[]) => void;
    let reject!: (reason: unknown) => void;
    const promise = new Promise<string[]>((resolvePromise, rejectPromise) => {
      resolve = resolvePromise;
      reject = rejectPromise;
    });
    const request = { promise, resolve, reject };
    requests.push(request);
    return request;
  }

  function load(picker: ReturnType<typeof useSchemaOptions>, connectionId = "c1", database = "app") {
    const promise = picker.loadSchemaOptions(connectionId, database);
    loads.push(promise);
    // Attach a handler immediately, including when an assertion fails before settlement.
    void promise.catch(() => undefined);
    return promise;
  }

  async function flushRequests() {
    await Promise.resolve();
    await Promise.resolve();
  }

  beforeEach(() => {
    invalidateSchemaOptionsCache("c1");
    invalidateSchemaOptionsCache("c2");
    schemaOptionsByKey.value = {};
    loadingSchemaOptionsByKey.value = {};
    listSchemas.mockReset();
    getConfig.mockReset().mockReturnValue({ db_type: "postgres", show_system_schemas: false });
    ensureConnected.mockReset().mockResolvedValue(undefined);
  });

  afterEach(async () => {
    for (const stop of stopWatches.splice(0)) stop();
    for (const request of requests.splice(0)) request.resolve([]);
    await Promise.allSettled(loads.splice(0));
    invalidateSchemaOptionsCache("c1");
    invalidateSchemaOptionsCache("c2");
  });

  it("deduplicates cold loads across pickers and repeated calls until settlement", async () => {
    const response = deferredSchemas();
    listSchemas.mockReturnValue(response.promise);
    const first = useSchemaOptions();
    const second = useSchemaOptions();
    const pending = [load(first), load(second), load(first)];

    expect(first.isLoadingSchemas("c1", "app")).toBe(true);
    expect(second.isLoadingSchemas("c1", "app")).toBe(true);
    await flushRequests();
    expect(ensureConnected).toHaveBeenCalledTimes(1);
    expect(listSchemas).toHaveBeenCalledTimes(1);

    response.resolve(["public"]);
    await Promise.all(pending);
    expect(first.getSchemaOptionsForDb("c1", "app")).toEqual(["public"]);
    expect(second.getSchemaOptionsForDb("c1", "app")).toEqual(["public"]);
    expect(first.isLoadingSchemas("c1", "app")).toBe(false);
    expect(second.isLoadingSchemas("c1", "app")).toBe(false);
  });

  it.each(["same", "another"] as const)("does not cache failure as an empty success and lets the %s picker retry", async (consumer) => {
    const response = deferredSchemas();
    const failure = new Error("schema lookup failed");
    listSchemas.mockReturnValueOnce(response.promise).mockResolvedValueOnce(["recovered"]);
    const first = useSchemaOptions();
    const second = useSchemaOptions();
    const initial = load(first);
    const joined = load(second);
    await flushRequests();
    response.reject(failure);

    await expect(initial).rejects.toBe(failure);
    await expect(joined).rejects.toBe(failure);
    expect(schemaOptionsByKey.value).not.toHaveProperty(schemaOptionsCacheKey("c1", "app", false));
    expect(second.isLoadingSchemas("c1", "app")).toBe(false);
    await load(consumer === "same" ? first : second);
    expect(second.getSchemaOptionsForDb("c1", "app")).toEqual(["recovered"]);
    expect(ensureConnected).toHaveBeenCalledTimes(2);
    expect(listSchemas).toHaveBeenCalledTimes(2);
  });

  it("retains a successful empty list as a shared cache entry", async () => {
    listSchemas.mockResolvedValue([]);
    await load(useSchemaOptions());
    await load(useSchemaOptions());

    expect(schemaOptionsByKey.value).toHaveProperty(schemaOptionsCacheKey("c1", "app", false), []);
    expect(listSchemas).toHaveBeenCalledTimes(1);
    expect(ensureConnected).toHaveBeenCalledTimes(1);
  });

  it("invalidates a pending database before a result exists without retrying its caller", async () => {
    const response = deferredSchemas();
    listSchemas.mockReturnValue(response.promise);
    const picker = useSchemaOptions();
    const initial = load(picker);
    await flushRequests();

    invalidateSchemaOptionsCache("c1", "app");
    expect(picker.isLoadingSchemas("c1", "app")).toBe(false);
    response.resolve(["stale"]);
    await expect(initial).resolves.toBeUndefined();
    expect(schemaOptionsByKey.value).not.toHaveProperty(schemaOptionsCacheKey("c1", "app", false));
    expect(ensureConnected).toHaveBeenCalledTimes(1);
    expect(listSchemas).toHaveBeenCalledTimes(1);
  });

  it.each(["resolve", "reject"] as const)("keeps a replacement pending when its superseded request %s", async (outcome) => {
    const stale = deferredSchemas();
    const fresh = deferredSchemas();
    const failure = new Error("old request failed");
    listSchemas.mockReturnValueOnce(stale.promise).mockReturnValueOnce(fresh.promise);
    const picker = useSchemaOptions();
    const other = useSchemaOptions();
    const initial = load(picker);
    await flushRequests();
    invalidateSchemaOptionsCache("c1", "app");
    const replacement = load(picker);
    await flushRequests();
    expect(listSchemas).toHaveBeenCalledTimes(2);

    if (outcome === "resolve") {
      stale.resolve(["stale"]);
      await expect(initial).resolves.toBeUndefined();
    } else {
      stale.reject(failure);
      await expect(initial).rejects.toBe(failure);
    }
    expect(schemaOptionsByKey.value).not.toHaveProperty(schemaOptionsCacheKey("c1", "app", false));
    expect(picker.isLoadingSchemas("c1", "app")).toBe(true);
    const joined = load(other);
    await flushRequests();
    expect(listSchemas).toHaveBeenCalledTimes(2);

    fresh.resolve(["fresh"]);
    await Promise.all([replacement, joined]);
    expect(picker.getSchemaOptionsForDb("c1", "app")).toEqual(["fresh"]);
    expect(other.isLoadingSchemas("c1", "app")).toBe(false);
    expect(ensureConnected).toHaveBeenCalledTimes(2);
  });

  it.each(["resolve", "reject"] as const)("preserves fresh success when an older request later %s", async (outcome) => {
    const stale = deferredSchemas();
    const fresh = deferredSchemas();
    const failure = new Error("late old failure");
    listSchemas.mockReturnValueOnce(stale.promise).mockReturnValueOnce(fresh.promise);
    const picker = useSchemaOptions();
    const initial = load(picker);
    await flushRequests();
    invalidateSchemaOptionsCache("c1", "app");
    const replacement = load(picker);
    await flushRequests();
    expect(listSchemas).toHaveBeenCalledTimes(2);
    fresh.resolve(["fresh"]);
    await replacement;

    if (outcome === "resolve") {
      stale.resolve(["stale"]);
      await expect(initial).resolves.toBeUndefined();
    } else {
      stale.reject(failure);
      await expect(initial).rejects.toBe(failure);
    }
    expect(picker.getSchemaOptionsForDb("c1", "app")).toEqual(["fresh"]);
    expect(picker.isLoadingSchemas("c1", "app")).toBe(false);
    expect(ensureConnected).toHaveBeenCalledTimes(2);
    expect(listSchemas).toHaveBeenCalledTimes(2);
  });

  it.each(["database", "connection"] as const)("invalidates pending system variants at %s scope and preserves neighbours", async (scope) => {
    const entries = [
      { connectionId: "c1", database: "app", showSystem: false },
      { connectionId: "c1", database: "app", showSystem: true },
      { connectionId: "c1", database: "archive", showSystem: false },
      { connectionId: "c2", database: "app", showSystem: false },
    ];
    const picker = useSchemaOptions();
    const pending = entries.map((entry) => {
      getConfig.mockReturnValue({ db_type: "postgres", show_system_schemas: entry.showSystem });
      const response = deferredSchemas();
      listSchemas.mockReturnValueOnce(response.promise);
      return { ...entry, response, load: load(picker, entry.connectionId, entry.database) };
    });
    await flushRequests();
    expect(listSchemas).toHaveBeenCalledTimes(4);

    invalidateSchemaOptionsCache("c1", scope === "database" ? "app" : undefined);
    for (const entry of pending) {
      const key = schemaOptionsCacheKey(entry.connectionId, entry.database, entry.showSystem);
      const invalidated = entry.connectionId === "c1" && (scope === "connection" || entry.database === "app");
      expect(!!loadingSchemaOptionsByKey.value[key]).toBe(!invalidated);
      entry.response.resolve(["public"]);
    }
    await Promise.all(pending.map((entry) => entry.load));
    for (const entry of pending) {
      const key = schemaOptionsCacheKey(entry.connectionId, entry.database, entry.showSystem);
      const invalidated = entry.connectionId === "c1" && (scope === "connection" || entry.database === "app");
      expect(schemaOptionsByKey.value[key]).toEqual(invalidated ? undefined : ["public"]);
      expect(!!loadingSchemaOptionsByKey.value[key]).toBe(false);
    }
    expect(ensureConnected).toHaveBeenCalledTimes(4);
    expect(listSchemas).toHaveBeenCalledTimes(4);
  });

  it("claims a request before a synchronous loading watcher asks another picker to load", async () => {
    const response = deferredSchemas();
    listSchemas.mockReturnValue(response.promise);
    const first = useSchemaOptions();
    const second = useSchemaOptions();
    let joined: Promise<void> | undefined;
    stopWatches.push(watch(() => first.isLoadingSchemas("c1", "app"), (loading) => {
      if (loading) joined = load(second);
    }, { flush: "sync" }));

    const initial = load(first);
    expect(joined).toBeDefined();
    await flushRequests();
    expect(listSchemas).toHaveBeenCalledTimes(1);
    response.resolve(["public"]);
    await Promise.all([initial, joined]);
    expect(second.getSchemaOptionsForDb("c1", "app")).toEqual(["public"]);
  });

  it("preserves a replacement started synchronously by cache invalidation", async () => {
    const response = deferredSchemas();
    listSchemas.mockResolvedValueOnce(["cached"]).mockReturnValueOnce(response.promise);
    const picker = useSchemaOptions();
    await load(picker);
    let replacement: Promise<void> | undefined;
    stopWatches.push(watch(() => picker.getSchemaOptionsForDb("c1", "app"), (schemas) => {
      if (schemas.length === 0) replacement = load(picker);
    }, { flush: "sync" }));

    invalidateSchemaOptionsCache("c1", "app");
    expect(replacement).toBeDefined();
    expect(picker.isLoadingSchemas("c1", "app")).toBe(true);
    await flushRequests();
    expect(listSchemas).toHaveBeenCalledTimes(2);
    response.resolve(["fresh"]);
    await replacement;
    expect(picker.getSchemaOptionsForDb("c1", "app")).toEqual(["fresh"]);
    expect(picker.isLoadingSchemas("c1", "app")).toBe(false);
  });

  it("keeps a replacement owned when a synchronous success watcher invalidates and reloads", async () => {
    const firstResponse = deferredSchemas();
    const nextResponse = deferredSchemas();
    listSchemas.mockReturnValueOnce(firstResponse.promise).mockReturnValueOnce(nextResponse.promise);
    const picker = useSchemaOptions();
    let replacement: Promise<void> | undefined;
    let invalidated = false;
    stopWatches.push(watch(() => picker.getSchemaOptionsForDb("c1", "app"), (schemas) => {
      if (schemas.length > 0 && !invalidated) {
        invalidated = true;
        invalidateSchemaOptionsCache("c1", "app");
        replacement = load(picker);
      }
    }, { flush: "sync" }));
    const initial = load(picker);
    await flushRequests();
    firstResponse.resolve(["initial"]);
    await expect(initial).resolves.toBeUndefined();
    await flushRequests();

    expect(replacement).toBeDefined();
    expect(listSchemas).toHaveBeenCalledTimes(2);
    expect(picker.isLoadingSchemas("c1", "app")).toBe(true);
    expect(picker.getSchemaOptionsForDb("c1", "app")).toEqual([]);
    nextResponse.resolve(["replacement"]);
    await replacement;
    expect(picker.getSchemaOptionsForDb("c1", "app")).toEqual(["replacement"]);
    expect(picker.isLoadingSchemas("c1", "app")).toBe(false);
  });

  it("revokes ownership when a synchronous loading watcher invalidates before the producer starts", async () => {
    const response = deferredSchemas();
    listSchemas.mockReturnValue(response.promise);
    const picker = useSchemaOptions();
    stopWatches.push(watch(() => picker.isLoadingSchemas("c1", "app"), (loading) => {
      if (loading) invalidateSchemaOptionsCache("c1", "app");
    }, { flush: "sync" }));

    const initial = load(picker);
    expect(picker.isLoadingSchemas("c1", "app")).toBe(false);
    await flushRequests();
    expect(listSchemas).toHaveBeenCalledTimes(1);
    response.resolve(["stale"]);
    await expect(initial).resolves.toBeUndefined();
    expect(schemaOptionsByKey.value).not.toHaveProperty(schemaOptionsCacheKey("c1", "app", false));
    expect(picker.isLoadingSchemas("c1", "app")).toBe(false);
    expect(ensureConnected).toHaveBeenCalledTimes(1);
  });

  it("revokes all connection owners before a synchronous watcher replaces another database request", async () => {
    const stale = deferredSchemas();
    const fresh = deferredSchemas();
    listSchemas.mockResolvedValueOnce(["cached"]).mockReturnValueOnce(stale.promise).mockReturnValueOnce(fresh.promise);
    const picker = useSchemaOptions();
    await load(picker);
    const initial = load(picker, "c1", "archive");
    await flushRequests();
    let replacement: Promise<void> | undefined;
    stopWatches.push(watch(() => picker.getSchemaOptionsForDb("c1", "app"), (schemas) => {
      if (schemas.length === 0) replacement = load(picker, "c1", "archive");
    }, { flush: "sync" }));

    invalidateSchemaOptionsCache("c1");
    expect(replacement).toBeDefined();
    await flushRequests();
    expect(listSchemas).toHaveBeenCalledTimes(3);
    stale.resolve(["stale"]);
    await initial;
    expect(picker.isLoadingSchemas("c1", "archive")).toBe(true);
    expect(picker.getSchemaOptionsForDb("c1", "archive")).toEqual([]);
    fresh.resolve(["fresh"]);
    await replacement;
    expect(picker.getSchemaOptionsForDb("c1", "archive")).toEqual(["fresh"]);
    expect(picker.isLoadingSchemas("c1", "archive")).toBe(false);
  });

  it("releases a failed owner before a synchronous loading watcher retries", async () => {
    const stale = deferredSchemas();
    const fresh = deferredSchemas();
    const failure = new Error("retryable failure");
    listSchemas.mockReturnValueOnce(stale.promise).mockReturnValueOnce(fresh.promise);
    const picker = useSchemaOptions();
    let replacement: Promise<void> | undefined;
    let retried = false;
    stopWatches.push(watch(() => picker.isLoadingSchemas("c1", "app"), (loading) => {
      if (!loading && !retried) {
        retried = true;
        replacement = load(picker);
      }
    }, { flush: "sync" }));
    const initial = load(picker);
    await flushRequests();
    stale.reject(failure);
    await expect(initial).rejects.toBe(failure);
    await flushRequests();

    expect(replacement).toBeDefined();
    expect(listSchemas).toHaveBeenCalledTimes(2);
    expect(picker.isLoadingSchemas("c1", "app")).toBe(true);
    fresh.resolve(["fresh"]);
    await replacement;
    expect(picker.getSchemaOptionsForDb("c1", "app")).toEqual(["fresh"]);
    expect(picker.isLoadingSchemas("c1", "app")).toBe(false);
  });

  it("releases a failed connection attempt without calling listSchemas or caching failure", async () => {
    const failure = new Error("connection unavailable");
    ensureConnected.mockRejectedValueOnce(failure);
    listSchemas.mockResolvedValue(["recovered"]);
    const first = useSchemaOptions();
    await expect(load(first)).rejects.toBe(failure);
    expect(listSchemas).not.toHaveBeenCalled();
    expect(schemaOptionsByKey.value).not.toHaveProperty(schemaOptionsCacheKey("c1", "app", false));
    expect(first.isLoadingSchemas("c1", "app")).toBe(false);

    await load(useSchemaOptions());
    expect(first.getSchemaOptionsForDb("c1", "app")).toEqual(["recovered"]);
    expect(ensureConnected).toHaveBeenCalledTimes(2);
    expect(listSchemas).toHaveBeenCalledTimes(1);
  });
});
