import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionConfig } from "@/types/database";

function installLocalStorage() {
  const data = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: vi.fn((key: string) => data.get(key) ?? null),
    setItem: vi.fn((key: string, value: string) => data.set(key, value)),
    removeItem: vi.fn((key: string) => data.delete(key)),
  });
}

function pgConnection(id: string): ConnectionConfig {
  return { id, name: id, db_type: "postgres", host: "127.0.0.1", port: 5432, username: "postgres", password: "", database: "app", read_only: false } as ConnectionConfig;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

async function setup() {
  const checkConnectionHealth = vi.fn().mockResolvedValue(undefined);
  const connectDb = vi.fn(async (config: ConnectionConfig) => config.id);
  const disconnectDb = vi.fn().mockResolvedValue(undefined);
  const loadConnections = vi.fn().mockResolvedValue([pgConnection("conn-a")]);

  vi.doMock("@/lib/backend/tauriRuntime", () => ({ isTauriRuntime: () => false }));
  vi.doMock("@/lib/backend/api", () => ({
    checkConnectionHealth,
    connectDb,
    disconnectDb,
    deleteSchemaCachePrefix: vi.fn().mockResolvedValue(undefined),
    deleteTableVGroupsForConnection: vi.fn().mockResolvedValue(undefined),
    loadConnections,
    loadEditorSettings: vi.fn().mockResolvedValue(null),
    loadSchemaCache: vi.fn().mockResolvedValue(null),
    loadSidebarLayout: vi.fn().mockResolvedValue(null),
    loadTableVGroups: vi.fn().mockResolvedValue({}),
    loadTunnelProfiles: vi.fn().mockResolvedValue([]),
    saveConnections: vi.fn().mockResolvedValue(undefined),
    saveEditorSettings: vi.fn().mockResolvedValue(undefined),
    saveSchemaCache: vi.fn().mockResolvedValue(undefined),
    saveSidebarLayout: vi.fn().mockResolvedValue(undefined),
  }));

  const { useConnectionStore, CONNECTION_CLOSED_BY_USER_MESSAGE } = await import("@/stores/connectionStore");
  const store = useConnectionStore();
  store.connections = [pgConnection("conn-a")];
  return { store, connectDb, disconnectDb, loadConnections, CONNECTION_CLOSED_BY_USER_MESSAGE };
}

describe("connectionStore: user-closed connections do not wake up from passive paths", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.unstubAllGlobals();
    vi.useRealTimers();
    installLocalStorage();
    setActivePinia(createPinia());
  });

  it("marks the connection on disconnect and blocks passive wake-ups", async () => {
    const { store, connectDb, CONNECTION_CLOSED_BY_USER_MESSAGE } = await setup();
    store.connectedIds.add("conn-a");
    await store.disconnect("conn-a");

    expect(store.connectedIds.has("conn-a")).toBe(false);
    expect(store.isConnectionClosedByUser("conn-a")).toBe(true);

    await expect(store.ensureConnected("conn-a", { skipIfClosedByUser: true })).rejects.toThrow(CONNECTION_CLOSED_BY_USER_MESSAGE);
    expect(connectDb).not.toHaveBeenCalled();
    expect(store.connectedIds.has("conn-a")).toBe(false);
  }, 20_000);

  it("lets an explicit reconnect through and clears the mark", async () => {
    const { store, connectDb } = await setup();
    store.connectedIds.add("conn-a");
    await store.disconnect("conn-a");

    // 用户主动入口（点侧栏连接节点 / 按 Run / 打开表数据）不带 skipIfClosedByUser。
    await store.ensureConnected("conn-a");
    expect(connectDb).toHaveBeenCalledTimes(1);
    expect(store.connectedIds.has("conn-a")).toBe(true);
    expect(store.isConnectionClosedByUser("conn-a")).toBe(false);

    // 标记清掉之后，页签界面的被动唤醒可以正常工作。
    await store.ensureConnected("conn-a", { skipIfClosedByUser: true });
    expect(store.connectedIds.has("conn-a")).toBe(true);
  }, 20_000);

  it("connect() clears the mark as well", async () => {
    const { store } = await setup();
    store.connectedIds.add("conn-a");
    await store.disconnect("conn-a");
    expect(store.isConnectionClosedByUser("conn-a")).toBe(true);

    await store.connect(pgConnection("conn-a"));
    expect(store.isConnectionClosedByUser("conn-a")).toBe(false);
  }, 20_000);

  it("system-side disconnects do not mark the connection", async () => {
    const { store, connectDb } = await setup();
    store.connectedIds.add("conn-a");
    // releasePluginConnectionsAfterClose / retirePasswordAfterChange 走这条。
    await store.disconnect("conn-a", { markClosedByUser: false });
    expect(store.isConnectionClosedByUser("conn-a")).toBe(false);

    await store.ensureConnected("conn-a", { skipIfClosedByUser: true });
    expect(connectDb).toHaveBeenCalledTimes(1);
    expect(store.connectedIds.has("conn-a")).toBe(true);
  }, 20_000);

  it.each([true, false])("respects a close during config loading (skipIfClosedByUser: %s)", async (skipIfClosedByUser) => {
    const { store, connectDb, loadConnections, CONNECTION_CLOSED_BY_USER_MESSAGE } = await setup();
    const loading = deferred<void>();
    const savedConnections = deferred<ConnectionConfig[]>();
    loadConnections.mockImplementationOnce(() => {
      loading.resolve();
      return savedConnections.promise;
    });
    store.connections = [];

    // Exercise the real initFromDisk path, delaying only its backend read.
    const pending = store.ensureConnected("conn-a", skipIfClosedByUser ? { skipIfClosedByUser: true } : {}).then(
      () => null,
      (error: unknown) => error,
    );
    try {
      await loading.promise;
      expect(store.connectingIds.has("conn-a")).toBe(false);
      expect(connectDb).not.toHaveBeenCalled();

      await store.disconnect("conn-a");
      expect(store.isConnectionClosedByUser("conn-a")).toBe(true);
      savedConnections.resolve([pgConnection("conn-a")]);

      if (skipIfClosedByUser) {
        expect(await pending).toEqual(new Error(CONNECTION_CLOSED_BY_USER_MESSAGE));
        expect(connectDb).not.toHaveBeenCalled();
        expect(store.connectedIds.has("conn-a")).toBe(false);
        expect(store.isConnectionClosedByUser("conn-a")).toBe(true);
      } else {
        expect(await pending).toBeNull();
        expect(connectDb).toHaveBeenCalledTimes(1);
        expect(store.connectedIds.has("conn-a")).toBe(true);
        expect(store.isConnectionClosedByUser("conn-a")).toBe(false);
      }
      expect(store.connectingIds.has("conn-a")).toBe(false);
    } finally {
      savedConnections.resolve([pgConnection("conn-a")]);
      await pending;
    }
  }, 20_000);

  it.each([true, false])("respects a close while waiting for an older full disconnect (skipIfClosedByUser: %s)", async (skipIfClosedByUser) => {
    const { store, connectDb, disconnectDb, CONNECTION_CLOSED_BY_USER_MESSAGE } = await setup();
    const disconnectStarted = deferred<void>();
    const olderDisconnect = deferred<void>();
    disconnectDb.mockImplementationOnce(() => {
      disconnectStarted.resolve();
      return olderDisconnect.promise;
    });
    store.connectedIds.add("conn-a");

    // No local connection attempt owns this restored pool, so its teardown blocks reconnect.
    const systemDisconnect = store.disconnect("conn-a", { markClosedByUser: false }).then(
      () => null,
      (error: unknown) => error,
    );
    let pending: Promise<unknown> = Promise.resolve(null);
    try {
      // Metadata retirement can delay the backend call; wait for that boundary explicitly.
      await disconnectStarted.promise;
      expect(disconnectDb).toHaveBeenCalledWith("conn-a", undefined);
      expect(store.isConnectionClosedByUser("conn-a")).toBe(false);
      pending = store.ensureConnected("conn-a", skipIfClosedByUser ? { skipIfClosedByUser: true } : {}).then(
        () => null,
        (error: unknown) => error,
      );
      expect(store.connectingIds.has("conn-a")).toBe(false);

      // A separate user close completes first while the caller still awaits the older request.
      await store.disconnect("conn-a");
      expect(disconnectDb).toHaveBeenCalledTimes(2);
      expect(store.isConnectionClosedByUser("conn-a")).toBe(true);
      expect(connectDb).not.toHaveBeenCalled();
      olderDisconnect.resolve();
      expect(await systemDisconnect).toBeNull();

      if (skipIfClosedByUser) {
        expect(await pending).toEqual(new Error(CONNECTION_CLOSED_BY_USER_MESSAGE));
        expect(connectDb).not.toHaveBeenCalled();
        expect(store.connectedIds.has("conn-a")).toBe(false);
        expect(store.isConnectionClosedByUser("conn-a")).toBe(true);
      } else {
        expect(await pending).toBeNull();
        expect(connectDb).toHaveBeenCalledTimes(1);
        expect(store.connectedIds.has("conn-a")).toBe(true);
        expect(store.isConnectionClosedByUser("conn-a")).toBe(false);
      }
      expect(store.connectingIds.has("conn-a")).toBe(false);
    } finally {
      olderDisconnect.resolve();
      await Promise.all([systemDisconnect, pending]);
    }
  }, 20_000);

  it("removing the connection clears a stale mark", async () => {
    const { store } = await setup();
    store.connectedIds.add("conn-a");
    await store.disconnect("conn-a");
    expect(store.isConnectionClosedByUser("conn-a")).toBe(true);

    await store.removeConnection("conn-a");
    expect(store.isConnectionClosedByUser("conn-a")).toBe(false);
  }, 20_000);
});
