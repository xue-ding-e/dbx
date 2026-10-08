import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parseDocument } from "yaml";

const source = readFileSync(resolve(process.cwd(), ".github/workflows/fork-current-full-desktop.yml"), "utf8");
const document = parseDocument(source, { uniqueKeys: true });
const workflow = document.toJS();

describe("current fork desktop build contract", () => {
  it("accepts only the candidate push or manual dispatch with read-only permissions", () => {
    expect(document.errors).toEqual([]);
    expect(workflow.on).toEqual({ push: { branches: ["integration/upstream-sync-20261008"] }, workflow_dispatch: null });
    expect(workflow.permissions).toEqual({ contents: "read" });
    expect(workflow.jobs.desktop.if).toBe("github.repository == 'xue-ding-e/dbx'");
    expect(source).not.toContain("secrets.");
  });

  it("builds the triggering commit with default desktop features and fails on build errors", () => {
    const steps = workflow.jobs.desktop.steps;
    const checkout = steps.find((step: { uses?: string }) => step.uses?.startsWith("actions/checkout@"));
    expect(checkout.with).toEqual({ ref: "${{ github.sha }}", "persist-credentials": false });
    const build = steps.find((step: { name?: string }) => step.name === "Build this exact commit with standard desktop feature defaults");
    expect(build.run).toBe("pnpm tauri build --no-bundle --ci -- --locked");
    expect(build["continue-on-error"]).toBeUndefined();
    expect(workflow.jobs.desktop["continue-on-error"]).toBeUndefined();
    expect(workflow.jobs.desktop.strategy["fail-fast"]).toBe(false);
  });

  it("publishes only review artifacts labelled with the verified source commit", () => {
    const steps = workflow.jobs.desktop.steps;
    const stage = steps.find((step: { name?: string }) => step.name === "Stage desktop and source identity");
    expect(stage.run).toContain('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"');
    expect(stage.run).toContain("git rev-parse HEAD > staging/desktop/SOURCE_COMMIT");
    const upload = steps.find((step: { uses?: string }) => step.uses?.startsWith("actions/upload-artifact@"));
    expect(upload.with.name).toContain("${{ github.sha }}");
    expect(upload.with["if-no-files-found"]).toBe("error");
    expect(steps.filter((step: { run?: string }) => /gh release|wrangler.*deploy|git push/.test(step.run ?? ""))).toEqual([]);
  });

  it("retains isolated Core, CLI and MCP regressions for the same source commit", () => {
    const focused = workflow.jobs["focused-rust"];
    expect(focused.if).toBe("github.repository == 'xue-ding-e/dbx'");
    const checkout = focused.steps.find((step: { uses?: string }) => step.uses?.startsWith("actions/checkout@"));
    expect(checkout.with).toEqual({ ref: "${{ github.sha }}", "persist-credentials": false });
    const commands = focused.steps.map((step: { run?: string }) => step.run ?? "");
    expect(commands).toContain("cargo fmt --check");
    expect(commands).toContain("cargo test --locked -p dbx-core --no-default-features --features sqlite-bundled,duckdb-sidecar,mq-admin --test connection_crud --test connection_import --test meatshell_storage_cache");
    expect(commands).toContain("cargo test --locked -p dbx-cli --bin dbx --test connection_crud --test connection_import --test meatshell_import --test route_update");
    expect(commands).toContain("cargo test --locked -p dbx-mcp --lib --test connection_crud --test connection_import --test protocol --test local --test version");
    expect(commands.join("\n")).not.toContain("--ignored");
    expect(focused.steps.every((step: Record<string, unknown>) => !step["continue-on-error"])).toBe(true);
  });
});
