import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_IDLE_DISCONNECT_SECS, DEFAULT_IDLE_TIMEOUT_SECS, MAX_IDLE_DISCONNECT_SECS, MAX_IDLE_TIMEOUT_SECS, normalizeConnectTimeoutSecs, normalizeIdleDisconnectSecs, normalizeIdleTimeoutSecs, supportsIdleTimeout } from "@/lib/connection/timeoutLimits";

const dialogSource = readFileSync(new URL("../../../components/connection/ConnectionDialog.vue", import.meta.url), "utf8");

describe("ConnectionDialog timeout controls", () => {
  it("restores the default when the connection timeout input is cleared", () => {
    expect(normalizeConnectTimeoutSecs("")).toBe(DEFAULT_CONNECT_TIMEOUT_SECS);
  });

  it("normalizes and bounds idle timeout values", () => {
    expect(normalizeIdleTimeoutSecs("")).toBe(DEFAULT_IDLE_TIMEOUT_SECS);
    expect(normalizeIdleTimeoutSecs(Number.NaN)).toBe(DEFAULT_IDLE_TIMEOUT_SECS);
    expect(normalizeIdleTimeoutSecs(-1)).toBe(DEFAULT_IDLE_TIMEOUT_SECS);
    expect(normalizeIdleTimeoutSecs(0)).toBe(0);
    expect(normalizeIdleTimeoutSecs(60)).toBe(60);
    expect(normalizeIdleTimeoutSecs(120.4)).toBe(120);
    expect(normalizeIdleTimeoutSecs(5000)).toBe(MAX_IDLE_TIMEOUT_SECS);
  });

  it("defaults auto-disconnect-when-idle to disabled and bounds its values", () => {
    // 0 是合法值（不启用），必须与非法输入区分：只有非数字/NaN/负数才回落默认 0。
    expect(normalizeIdleDisconnectSecs("")).toBe(DEFAULT_IDLE_DISCONNECT_SECS);
    expect(normalizeIdleDisconnectSecs(Number.NaN)).toBe(DEFAULT_IDLE_DISCONNECT_SECS);
    expect(normalizeIdleDisconnectSecs(-1)).toBe(DEFAULT_IDLE_DISCONNECT_SECS);
    expect(normalizeIdleDisconnectSecs(0)).toBe(0);
    expect(normalizeIdleDisconnectSecs(300)).toBe(300);
    expect(normalizeIdleDisconnectSecs(120.4)).toBe(120);
    expect(normalizeIdleDisconnectSecs(999999)).toBe(MAX_IDLE_DISCONNECT_SECS);
  });

  it("identifies database dialects that support idle connection timeouts", () => {
    expect(supportsIdleTimeout("mongodb")).toBe(true);
    expect(supportsIdleTimeout("mysql")).toBe(true);
    expect(supportsIdleTimeout("doris")).toBe(true);
    expect(supportsIdleTimeout("starrocks")).toBe(true);
    expect(supportsIdleTimeout("manticoresearch")).toBe(true);

    expect(supportsIdleTimeout("postgres")).toBe(false);
    expect(supportsIdleTimeout("sqlite")).toBe(false);
    expect(supportsIdleTimeout("redis")).toBe(false);
    expect(supportsIdleTimeout("sqlserver")).toBe(false);
    expect(supportsIdleTimeout("oracle")).toBe(false);
    expect(supportsIdleTimeout(undefined)).toBe(false);
  });

  it("binds idle timeout setting and hint in ConnectionDialog", () => {
    expect(dialogSource).toContain('v-show="supportsIdleTimeoutSetting"');
    expect(dialogSource).toContain("clampIdleTimeoutInput($event)");
    expect(dialogSource).toContain('t("connection.idleTimeoutHint")');
  });

  it("binds the auto-disconnect-when-idle input for every dialect", () => {
    // 该输入框不做方言门控：不挂在 supportsIdleTimeoutSetting 的 v-show 块内，也没用
    // supportsIdleTimeout 之类的判断。
    expect(dialogSource).toContain("clampIdleDisconnectInput($event)");
    expect(dialogSource).toContain('t("connection.idleDisconnect")');
    expect(dialogSource).toContain('v-model.number="form.idle_disconnect_secs"');
    // 开关+输入框与「保持连接间隔」一行保持一致；说明文案收进小问号 tooltip，
    // 避免和「空闲超时」的说明挤在一起。
    expect(dialogSource).toContain('v-model="idleDisconnectEnabled"');
    expect(dialogSource).toContain(':disabled="!idleDisconnectEnabled"');
    expect(dialogSource).toContain(":label=\"t('connection.idleDisconnectHint')\"");
  });

  it("warns when the idle auto-disconnect threshold can never beat keepalive", () => {
    // 软校验：阈值不大于「保持连接间隔」时给出提示，但不阻止保存。
    expect(dialogSource).toContain("idleDisconnectKeepaliveWarning");
    expect(dialogSource).toContain('t("connection.idleDisconnectKeepaliveWarning")');
    expect(dialogSource).toContain("const idleDisconnectKeepaliveWarning = computed");
  });
});
