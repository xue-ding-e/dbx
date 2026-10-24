// @vitest-environment happy-dom

import { createApp, h, nextTick, reactive, type App } from "vue";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import SchemaDiffDialog from "@/components/diff/SchemaDiffDialog.vue";
import SchemaDiffDeployStep from "@/components/diff/SchemaDiffDeployStep.vue";
import { startSchemaDiffSession, removeSchemaDiffSession } from "@/composables/useSchemaDiffSession";
import type { OracleRoutineKind, OracleRoutineOperation, OracleRoutinePlanInput, OracleRoutineSnapshot } from "@/types/schemaDiff";

const calls = vi.hoisted(() => ({ load: vi.fn(), compare: vi.fn(), prepare: vi.fn(), execute: vi.fn(), observe: vi.fn(), genericPlan: vi.fn(), confirm: vi.fn(), copy: vi.fn(), transaction: vi.fn(), databaseType: "oceanbase-oracle", sourceDatabaseType: "" }));
vi.mock("vue-i18n", () => ({ useI18n: () => ({ t: (key: string) => key }) }));
vi.mock("@/i18n", () => ({ default: { global: { t: (key: string) => key } } }));
vi.mock("@/composables/useToast", () => ({ useToast: () => ({ toast: vi.fn() }) }));
vi.mock("@/composables/useDialogSources", () => ({ openSchemaDiffSession: vi.fn() }));
vi.mock("@/composables/useExportTracker", () => ({ useExportTracker: () => ({ addSchemaDiffTask: vi.fn(), updateCompareTask: vi.fn() }) }));
vi.mock("@/stores/productionSafetyStore", () => ({ useProductionSafetyStore: () => ({ requestConfirmation: calls.confirm }) }));
vi.mock("@/stores/connectionStore", () => {
  const connections = () => ["source", "target"].map((id) => ({ id, name: id, db_type: id === "source" ? calls.sourceDatabaseType || calls.databaseType : calls.databaseType, is_production: id === "target", host: "localhost", port: 1 }));
  return {
    useConnectionStore: () => ({
      get connections() {
        return connections();
      },
      getConfig: (id: string) => connections().find((connection) => connection.id === id),
      ensureConnected: vi.fn().mockResolvedValue(undefined),
    }),
  };
});
vi.mock("@/stores/settingsStore", () => ({ useSettingsStore: () => ({ editorSettings: { theme: "default", fontSize: 12, fontFamily: "monospace" } }) }));
vi.mock("@/composables/useTheme", () => ({ useTheme: () => ({ isDark: { value: false } }) }));
vi.mock("@/lib/editor/editorThemes", () => ({ loadEditorTheme: async () => [], editorFontTheme: () => [] }));
vi.mock("@/lib/editor/codemirrorSqlDialect", () => ({ createDbxCodeMirrorSqlDialect: () => undefined }));
vi.mock("@/lib/common/clipboard", () => ({ copyToClipboard: calls.copy }));
vi.mock("@/lib/metadata/objectDdlCache", () => ({ invalidateObjectDdlCache: vi.fn().mockResolvedValue(undefined) }));
vi.mock("@/lib/table/objectBrowserRowsCache", () => ({ invalidateObjectBrowserRowsCache: vi.fn() }));
vi.mock("@/lib/backend/api", () => ({
  loadSchemaDiffRoutines: calls.load,
  prepareSchemaDiff: calls.compare,
  prepareOracleRoutinePlan: calls.prepare,
  updateOracleRoutineOperationReferences: vi.fn(async () => {}),
  executeOracleRoutineOperation: calls.execute,
  observeOracleRoutineOperation: calls.observe,
  generateSchemaSyncPlan: calls.genericPlan,
  executeQuery: vi.fn().mockResolvedValue({ rows: [] }),
  listFunctions: vi.fn().mockResolvedValue([]),
  executeScriptWith2pc: calls.transaction,
}));

// Substitute only CodeMirror's DOM boundary. The production dialog, session,
// deployment controller, buttons and production guard run unchanged.
vi.mock("@codemirror/state", () => ({
  EditorState: { readOnly: { of: () => [] }, create: (config: any) => ({ ...config, doc: { toString: () => config.doc, length: config.doc.length } }) },
  Compartment: class {
    of() {
      return [];
    }
    reconfigure() {
      return [];
    }
  },
}));
vi.mock("@codemirror/view", () => ({
  EditorView: class {
    static updateListener = { of: (callback: unknown) => callback };
    static scrollIntoView = () => ({});
    state: any;
    input: HTMLTextAreaElement;
    listener: any;
    constructor(config: any) {
      this.state = config.state;
      this.listener = config.state.extensions.find((extension: unknown) => typeof extension === "function");
      this.input = document.createElement("textarea");
      this.input.value = this.state.doc.toString();
      this.input.addEventListener("input", () => this.setText(this.input.value));
      config.parent.append(this.input);
    }
    setText(text: string) {
      this.state.doc = { toString: () => text, length: text.length };
      this.input.value = text;
      this.listener?.({ docChanged: true, state: this.state });
    }
    dispatch(change: any) {
      if (change.changes) this.setText(change.changes.insert);
    }
    focus() {
      this.input.focus();
    }
    destroy() {
      this.input.remove();
    }
  },
}));
vi.mock("@codemirror/lang-sql", () => ({ sql: () => [] }));
vi.mock("codemirror", () => ({ basicSetup: [] }));

const apps: App[] = [];
const sessions: string[] = [];
const records = new Map<string, OracleRoutineOperation>();
function snapshot(connectionId: string): OracleRoutineSnapshot {
  const owner = connectionId === "source" ? "Source" : "Target";
  const product = connectionId === "source" ? calls.sourceDatabaseType || calls.databaseType : calls.databaseType;
  return { endpoint: { connectionId, database: "tenant", schema: owner, databaseType: product === "oracle" ? "oracle" : "oceanbase-oracle", generation: 1 }, state: "complete", enumerationComplete: true, objects: [], issues: [] };
}
const sourceSql = 'CREATE OR REPLACE FUNCTION "F" RETURN NUMBER AS BEGIN RETURN 1; END';
const sourceFunction = { name: "F", function_type: "FUNCTION", definition: sourceSql, arguments: "", data_type: "NUMBER" };

beforeEach(() => {
  vi.clearAllMocks();
  records.clear();
  calls.databaseType = "oceanbase-oracle";
  calls.sourceDatabaseType = "";
  calls.load.mockImplementation(async (id: string) => snapshot(id));
  calls.compare.mockResolvedValue({ diffs: [], functionDiffs: [{ type: "added", name: "F", source: sourceFunction }], syncSql: "", renameCandidates: [] });
  calls.confirm.mockResolvedValue(true);
  calls.genericPlan.mockResolvedValue({ syncSql: "CREATE FUNCTION f() RETURNS int AS 'SELECT 1' LANGUAGE SQL;", rollbackCompleteness: "complete", missingRollbackObjects: [] });
  calls.transaction.mockResolvedValue({ status: "committed", executed_count: 1, statement_count: 1 });
  calls.prepare.mockImplementation(async (input: OracleRoutinePlanInput) => ({
    target: input.target.endpoint,
    ready: true,
    steps: input.drafts.map((draft) => {
      const operation: OracleRoutineOperation = { operationId: `approval-${calls.prepare.mock.calls.length}`, target: input.target.endpoint, identity: draft.identity, lifecycle: "prepared", dispatched: false, acknowledged: false, error: null, readback: null };
      records.set(operation.operationId, operation);
      return {
        identity: draft.identity,
        action: draft.action,
        sql: draft.sql ?? 'CREATE FUNCTION "Target"."F" RETURN NUMBER AS BEGIN RETURN 1; END;',
        sourceOriginal: sourceSql,
        targetOriginal: null,
        recoverySql: null,
        recoveryComplete: true,
        references: [],
        incomingCallers: [],
        issues: [],
        operation,
      };
    }),
  }));
  calls.observe.mockImplementation(async (id: string) => ({ operation: records.get(id), lifecycle: records.get(id)?.lifecycle, error: null }));
  calls.execute.mockImplementation(async (id: string) => {
    const operation: OracleRoutineOperation = {
      ...records.get(id)!,
      lifecycle: "terminal",
      dispatched: true,
      acknowledged: true,
      readback: { identity: records.get(id)!.identity, state: "invalid", exists: true, version: null, source: sourceSql, definitionMatches: true, issues: [], compilerMessages: [{ attribute: "ERROR", line: 1, position: 20, text: "invalid identifier" }] },
    };
    records.set(id, operation);
    return operation;
  });
});

async function flush() {
  for (let index = 0; index < 8; index++) {
    await nextTick();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}
function button(text: string) {
  const found = [...document.querySelectorAll<HTMLButtonElement>("button")].find((button) => button.textContent?.trim() === text);
  expect(found, text).toBeDefined();
  return found!;
}
async function mountComparison(databaseType: "oracle" | "oceanbase-oracle" | "postgres" | "mysql" | "sqlserver" = "oceanbase-oracle", sourceType = databaseType, kinds?: OracleRoutineKind[]) {
  calls.databaseType = databaseType;
  calls.sourceDatabaseType = sourceType;
  const session = startSchemaDiffSession(
    {
      sourceConnectionId: "source",
      sourceDatabase: "tenant",
      sourceSchema: "Source",
      sourceDbType: sourceType,
      targetConnectionId: "target",
      targetDatabase: "tenant",
      targetSchema: "Target",
      targetDbType: databaseType,
      options: { tables: false, views: false, functions: true, sequences: false, rules: false, owners: false, ...(kinds ? { routineObjectKinds: kinds } : {}) },
      ignoreComments: false,
      label: "test",
    },
    { tableListLoader: { load: vi.fn().mockResolvedValue([]) } },
  );
  sessions.push(session.id);
  await flush();
  expect(session.status).toBe("completed");
  const visible = reactive({ open: true });
  const host = document.createElement("div");
  document.body.append(host);
  const app = createApp({
    setup: () => () =>
      h(SchemaDiffDialog, {
        open: visible.open,
        sessionId: session.id,
        "onUpdate:open": (open: boolean) => {
          visible.open = open;
        },
      }),
  });
  apps.push(app);
  app.mount(host);
  await flush();
  return { session, visible };
}

afterEach(() => {
  apps.splice(0).forEach((app) => app.unmount());
  sessions.splice(0).forEach(removeSchemaDiffSession);
  document.body.innerHTML = "";
  localStorage.removeItem("dbx-schema-diff-size");
});

it("keeps external SQL and rollback previews separate from actual user edits, including clearing", async () => {
  const state = reactive({ sql: "original specification", mode: "forward" });
  const edits: string[] = [];
  const host = document.createElement("div");
  document.body.append(host);
  const app = createApp({
    setup: () => () =>
      h(SchemaDiffDeployStep, {
        deploySql: state.sql,
        deploySqlMode: state.mode as "forward" | "rollback",
        rollbackSql: "original recovery",
        selectedObjects: [],
        targetConnectionId: "target",
        targetDatabase: "tenant",
        targetSchema: "Target",
        executing: false,
        "onUpdate:deploySql": (sql: string) => edits.push(sql),
      }),
  });
  apps.push(app);
  app.mount(host);
  await flush();
  const input = host.querySelector<HTMLTextAreaElement>("textarea")!;
  state.sql = "";
  await flush();
  expect(input.value).toBe("");
  state.sql = "prepared target body";
  await flush();
  state.mode = "rollback";
  await flush();
  expect(input.value).toBe("original recovery");
  state.mode = "forward";
  await flush();
  expect(input.value).toBe("prepared target body");
  expect(edits).toEqual([]);
  input.value = "manual body";
  input.dispatchEvent(new Event("input"));
  input.value = "";
  input.dispatchEvent(new Event("input"));
  expect(edits).toEqual(["manual body", ""]);
});

it.each([
  [{ width: "0px", height: "0px" }, "1100px", "820px"],
  [{ width: "1120px", height: "840px" }, "1120px", "840px"],
])("opens readable results while preserving a positive saved dialog size: %j", async (saved, width, height) => {
  localStorage.setItem("dbx-schema-diff-size", JSON.stringify(saved));
  await mountComparison();
  const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
  expect(dialog.style.width).toBe(width);
  expect(dialog.style.height).toBe(height);
});

it("does not persist a hidden dialog's zero-sized resize observation", async () => {
  let resize: ResizeObserverCallback | undefined;
  vi.stubGlobal(
    "ResizeObserver",
    class {
      constructor(private callback: ResizeObserverCallback) {}
      observe(target: Element) {
        if (target.matches(".dbx-schema-diff-dialog")) resize = this.callback;
      }
      unobserve() {}
      disconnect() {}
    },
  );
  try {
    await mountComparison();
    await vi.waitFor(() => expect(resize).toBeDefined());
    resize!([{ contentRect: { width: 1120, height: 840 } } as ResizeObserverEntry], {} as ResizeObserver);
    await vi.waitFor(() => expect(JSON.parse(localStorage.getItem("dbx-schema-diff-size")!)).toEqual({ width: "1120px", height: "840px" }));
    resize!([{ contentRect: { width: 0, height: 0 } } as ResizeObserverEntry], {} as ResizeObserver);
    await new Promise((resolve) => setTimeout(resolve, 550));
    expect(JSON.parse(localStorage.getItem("dbx-schema-diff-size")!)).toEqual({ width: "1120px", height: "840px" });
  } finally {
    vi.unstubAllGlobals();
  }
});

it("opens the real Oracle comparison, retains draft on both confirmations' cancellation, then displays INVALID and corrects only that step", async () => {
  const { session } = await mountComparison();
  button("diff.nextStepDeployRoutines").click();
  await flush();
  expect(calls.genericPlan).not.toHaveBeenCalled();
  expect(session.routineDeployment?.plan?.ready).toBe(true);
  expect(button("diff.deployToServer").disabled).toBe(false);
  button("diff.deployToServer").click();
  await flush();
  const cancel = [...document.querySelectorAll<HTMLButtonElement>("button")].filter((button) => button.textContent?.trim() === "diff.cancel").at(-1)!;
  cancel.click();
  await flush();
  expect(calls.execute).not.toHaveBeenCalled();
  expect(session.routineDeployment?.drafts[0].sql).toContain('"Target"."F"');
  calls.confirm.mockResolvedValueOnce(false);
  button("diff.deployToServer").click();
  await flush();
  button("diff.confirmDeploy").click();
  await flush();
  expect(calls.confirm).toHaveBeenCalledTimes(1);
  expect(calls.execute).not.toHaveBeenCalled();
  button("diff.deployToServer").click();
  await flush();
  button("diff.confirmDeploy").click();
  await flush();
  expect(calls.execute).toHaveBeenCalledTimes(1);
  expect(document.body.textContent).toContain("ERROR 1:20 — invalid identifier");
  expect(button("diff.deployToServer").disabled).toBe(true);
  const editor = document.querySelector<HTMLTextAreaElement>(".deploy-sql-editor textarea")!;
  editor.value = 'CREATE FUNCTION "Target"."F" RETURN NUMBER AS BEGIN RETURN 77; END;';
  editor.dispatchEvent(new Event("input"));
  await flush();
  button("diff.routineValidate").click();
  await flush();
  expect(calls.prepare.mock.calls.at(-1)![0].drafts[0]).toMatchObject({ action: "replace", baselineOperationId: "approval-1", sql: editor.value });
  expect(button("diff.deployToServer").disabled).toBe(false);
  calls.execute.mockImplementationOnce(async (id: string) => ({
    ...records.get(id)!,
    lifecycle: "terminal",
    dispatched: true,
    acknowledged: true,
    readback: { identity: records.get(id)!.identity, state: "verified", exists: true, version: null, source: editor.value, definitionMatches: true, compilerMessages: [], issues: [] },
  }));
  button("diff.deployToServer").click();
  await flush();
  button("diff.confirmDeploy").click();
  await flush();
  expect(calls.execute.mock.calls.map((call) => call[0])).toEqual(["approval-1", "approval-2"]);
  expect(session.routineDeployment?.records).toHaveLength(2);
  expect(document.body.textContent).toContain("diff.routineReadOnlyCompleted");
});

it("keeps a newly included target body automatic until the user actually edits it", async () => {
  calls.load.mockImplementation(async (id: string) => {
    const result = snapshot(id);
    result.objects = (["PACKAGE", "PACKAGE_BODY"] as const).map((kind) => ({
      version: { identity: { owner: result.endpoint.schema!, name: "P", kind }, objectId: `${id}-${kind}`, status: "VALID", lastDdlTime: "1" },
      source: kind === "PACKAGE" ? 'CREATE PACKAGE "P" AS FUNCTION f RETURN NUMBER; END;' : 'CREATE PACKAGE BODY "P" AS FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END; END;',
      sourceComplete: true,
      dependencies: [],
      dependenciesComplete: true,
      issues: [],
    }));
    return result;
  });
  const spec = { ...sourceFunction, name: "P", function_type: "PACKAGE", definition: 'CREATE PACKAGE "P" AS g NUMBER; FUNCTION f RETURN NUMBER; END;' };
  calls.compare.mockResolvedValue({ diffs: [], functionDiffs: [{ type: "modified", name: "P", programKind: "PACKAGE", source: spec, target: { ...spec, definition: spec.definition.replace("g NUMBER; ", "") } }], syncSql: "", renameCandidates: [] });
  const ordinaryPrepare = calls.prepare.getMockImplementation()!;
  calls.prepare.mockImplementation(async (input: OracleRoutinePlanInput) => {
    const plan = await ordinaryPrepare(input);
    for (const step of plan.steps) step.sql = input.drafts.find((draft) => draft.identity.kind === step.identity.kind)?.sql ?? (step.identity.kind === "PACKAGE" ? spec.definition : 'CREATE PACKAGE BODY "Target"."P" AS FUNCTION f RETURN NUMBER IS BEGIN RETURN 1; END; END;');
    return plan;
  });
  const { session } = await mountComparison("oceanbase-oracle", "oceanbase-oracle", ["PACKAGE"]);
  button("diff.nextStepDeployRoutines").click();
  await flush();
  button("diff.packageRebuildTargetBody").click();
  await flush();
  const body = session.routineDeployment!.drafts.find((draft) => draft.identity.kind === "PACKAGE_BODY")!;
  expect(body.packageBodySource).toBe("target");
  expect(body.sql).toBeUndefined();
  button("diff.routineValidate").click();
  await flush();
  const request = calls.prepare.mock.calls.at(-1)![0] as OracleRoutinePlanInput;
  expect(request.drafts.find((draft) => draft.identity.kind === "PACKAGE_BODY")).toMatchObject({ packageBodySource: "target", sql: undefined });
  expect(body.sql).toContain('PACKAGE BODY "Target"."P"');
  const input = document.querySelector<HTMLTextAreaElement>(".deploy-sql-editor textarea")!;
  input.value = "";
  input.dispatchEvent(new Event("input"));
  await flush();
  expect(body.sql).toBe("");
  expect(session.routineDeployment!.plan).toBeNull();
});

it("restores the same draft and operation after closing and reopening the actual dialog", async () => {
  const { session, visible } = await mountComparison();
  button("diff.nextStepDeployRoutines").click();
  await flush();
  const editor = document.querySelector<HTMLTextAreaElement>(".deploy-sql-editor textarea")!;
  editor.value = "retained manual draft";
  editor.dispatchEvent(new Event("input"));
  await flush();
  visible.open = false;
  await flush();
  visible.open = true;
  await flush();
  expect(document.querySelector<HTMLTextAreaElement>(".deploy-sql-editor textarea")?.value).toBe("retained manual draft");
  expect(session.routineDeployment?.records[0].operationId).toBe("approval-1");
  expect(calls.execute).not.toHaveBeenCalled();
});

it("retains a late unknown result across close/reopen and only observes its original request", async () => {
  const { session, visible } = await mountComparison();
  button("diff.nextStepDeployRoutines").click();
  await flush();
  let reject!: (error: Error) => void;
  calls.execute.mockReturnValueOnce(
    new Promise((_resolve, fail) => {
      reject = fail;
    }),
  );
  button("diff.deployToServer").click();
  await flush();
  button("diff.confirmDeploy").click();
  await flush();
  expect(calls.execute).toHaveBeenCalledTimes(1);
  visible.open = false;
  await flush();
  const unknown = { ...records.get("approval-1")!, lifecycle: "unproven" as const, dispatched: true };
  records.set("approval-1", unknown);
  reject(new Error("client response lost"));
  await flush();
  visible.open = true;
  await flush();
  expect(session.routineDeployment?.drafts[0].operation?.operationId).toBe("approval-1");
  expect(button("diff.deployToServer").disabled).toBe(true);
  button("diff.routineObserve").click();
  await flush();
  expect(calls.observe).toHaveBeenLastCalledWith("approval-1", true);
  button("diff.routineValidate").click();
  await flush();
  expect(calls.prepare).toHaveBeenCalledTimes(1);
  expect(calls.execute).toHaveBeenCalledTimes(1);
  expect(document.body.textContent).toContain("termination is not proven");
});

it("retains all four comparison states and copies an equal object's exact raw source", async () => {
  const raw = sourceSql.replace("RETURN 1", "RETURN 'two  spaces'");
  calls.compare.mockResolvedValue({
    diffs: [],
    syncSql: "",
    functionDiffs: [
      { type: "added", name: "Added", source: { ...sourceFunction, name: "Added" } },
      { type: "modified", name: "Modified", source: { ...sourceFunction, name: "Modified" }, target: { ...sourceFunction, name: "Modified", definition: "old" } },
      { type: "removed", name: "Removed", target: { ...sourceFunction, name: "Removed" } },
      { type: "equal", name: "Equal", source: { ...sourceFunction, name: "Equal", definition: raw }, target: { ...sourceFunction, name: "Equal", definition: raw } },
    ],
  });
  await mountComparison();
  const rows = [...document.querySelectorAll<HTMLElement>('[role="button"]')].filter((row) => row.querySelector('input[type="checkbox"]'));
  expect(rows).toHaveLength(4);
  const equal = rows.find((row) => row.textContent?.includes("Equal"))!;
  expect(equal.textContent).toContain("diff.routineEqual");
  expect(equal.querySelector<HTMLInputElement>("input")?.disabled).toBe(true);
  equal.click();
  await flush();
  const copy = document.querySelector<HTMLButtonElement>('button[title="diff.copySourceDdl"]')!;
  expect(copy.disabled).toBe(false);
  copy.click();
  expect(calls.copy).toHaveBeenLastCalledWith(raw);
});

it.each(["mysql", "sqlserver"] as const)("keeps %s routine comparison copy-only", async (databaseType) => {
  await mountComparison(databaseType);
  expect(document.body.textContent).toContain("diff.routineSyncDeferredHint");
  expect(document.body.textContent).not.toContain("diff.nextStepDeployRoutines");
  expect(calls.prepare).not.toHaveBeenCalled();
  expect(calls.execute).not.toHaveBeenCalled();
});

it("keeps PostgreSQL's existing plan, confirmation and transactional execution path", async () => {
  await mountComparison("postgres");
  button("diff.nextStepDeployRoutines").click();
  await flush();
  expect(calls.genericPlan).toHaveBeenCalled();
  expect(calls.prepare).not.toHaveBeenCalled();
  button("diff.deployToServer").click();
  await flush();
  button("diff.confirmDeploy").click();
  await flush();
  expect(calls.transaction).toHaveBeenCalledWith("target", "tenant", ["CREATE FUNCTION f() RETURNS int AS 'SELECT 1' LANGUAGE SQL;"], "Target", false);
  expect(document.body.textContent).toContain("diff.deploySuccessMessage");
  expect(calls.execute).not.toHaveBeenCalled();
});

it("does not label two failed inventories as an equal empty comparison", async () => {
  calls.load.mockImplementation(async (id: string) => ({ ...snapshot(id), state: "permission-denied", enumerationComplete: false, issues: [{ stage: "inventory", code: "permission-denied", message: "Metadata visibility unavailable" }] }));
  calls.compare.mockResolvedValue({ diffs: [], functionDiffs: [], syncSql: "" });
  await mountComparison();
  expect(document.body.textContent).toContain("Metadata visibility unavailable");
  expect(document.body.textContent).toContain("diff.routineUnreadable");
  expect(document.body.textContent).not.toContain("diff.noDifferences");
  expect(button("diff.nextStepDeployRoutines").disabled).toBe(true);
});

it("opens a native Oracle target draft through the same controlled review", async () => {
  const { session } = await mountComparison("oracle");
  button("diff.nextStepDeployRoutines").click();
  await flush();
  expect(session.routineDeployment?.plan?.target.databaseType).toBe("oracle");
  expect(button("diff.deployToServer").disabled).toBe(false);
  expect(calls.genericPlan).not.toHaveBeenCalled();
});

it("keeps the old cross-product function selection outside the package deployment path", async () => {
  const session = startSchemaDiffSession(
    {
      sourceConnectionId: "source",
      sourceDatabase: "tenant",
      sourceSchema: "Source",
      sourceDbType: "oracle",
      targetConnectionId: "target",
      targetDatabase: "tenant",
      targetSchema: "Target",
      targetDbType: "oceanbase-oracle",
      options: { tables: false, views: false, functions: true, sequences: false, rules: false, owners: false, routineObjectKinds: ["FUNCTION"] },
      ignoreComments: false,
      label: "cross-product function",
    },
    { tableListLoader: { load: vi.fn() } },
  );
  sessions.push(session.id);
  await flush();
  expect(session.status).toBe("failed");
  expect(session.error).toContain("cross-product comparison supports explicit package kinds only");
  expect(calls.prepare).not.toHaveBeenCalled();
  expect(calls.execute).not.toHaveBeenCalled();
});

it("opens a cross-product package in the actual review and requires explicit target-draft review before approval", async () => {
  calls.compare.mockResolvedValue({ diffs: [], functionDiffs: [{ type: "added", name: "P", programKind: "PACKAGE", source: { ...sourceFunction, name: "P", function_type: "PACKAGE", definition: 'CREATE PACKAGE "P" AS n NUMBER; END;' } }], syncSql: "", renameCandidates: [] });
  const ordinaryPrepare = calls.prepare.getMockImplementation()!;
  calls.prepare.mockImplementation(async (input: OracleRoutinePlanInput) => {
    const plan = await ordinaryPrepare(input);
    plan.steps[0].sql = input.drafts[0].sql ?? 'CREATE PACKAGE "Target"."P" AS n NUMBER; END;';
    if (!input.drafts[0].sql) {
      plan.ready = false;
      plan.steps[0].operation = null;
      plan.steps[0].issues = [{ code: "review-required", message: "Review target draft", line: 1, column: 1 }];
    }
    return plan;
  });
  const { session } = await mountComparison("oceanbase-oracle", "oracle", ["PACKAGE"]);
  button("diff.nextStepDeployRoutines").click();
  await flush();
  expect(session.routineDeployment?.plan?.ready).toBe(false);
  expect(button("diff.deployToServer").disabled).toBe(true);
  button("diff.packageReviewTarget").click();
  await flush();
  button("diff.routineValidate").click();
  await flush();
  expect(calls.prepare.mock.calls.at(-1)![0].drafts[0].sql).toContain('PACKAGE "Target"."P"');
  expect(button("diff.deployToServer").disabled).toBe(false);
  expect(calls.execute).not.toHaveBeenCalled();
});
