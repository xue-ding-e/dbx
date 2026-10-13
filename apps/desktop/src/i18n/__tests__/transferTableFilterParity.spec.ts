import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const LOCALES = ["en", "es", "it", "ja", "ko", "pt-BR", "ru", "zh-CN", "zh-TW"] as const;
const KEYS = ["tableFilterSection", "tableFilterSectionHint", "tableFilterSet", "tableFilterEdit", "tableFilterClear", "tableFilterTitle", "tableFilterHint", "tableFilterPlaceholder", "tableFilterExamples", "tableFilterSave"] as const;

function declaredValue(source: string, key: string): string | undefined {
  return source.match(new RegExp(String.raw`^\s*${key}:\s*(["'])(.*?)\1,\s*$`, "m"))?.[2];
}

describe("per-table transfer filter locale declarations", () => {
  // Read source declarations: withEnglishFallback hides missing translations
  // at runtime, but the Ready-for-review autofill job requires these keys.
  it.each(LOCALES)("%s declares every filter label without losing SQL or placeholders", (locale) => {
    const source = readFileSync(new URL(`../locales/${locale}.ts`, import.meta.url), "utf8");
    const values = Object.fromEntries(KEYS.map((key) => [key, declaredValue(source, key)]));

    expect(
      KEYS.filter((key) => !values[key]?.trim()),
      `${locale}: missing source declarations`,
    ).toEqual([]);
    expect(values.tableFilterTitle?.match(/\{[^{}]+\}/g)).toEqual(["{table}"]);
    expect(values.tableFilterHint).toContain("WHERE");
    expect(values.tableFilterHint).toContain("SELECT");
    expect(values.tableFilterHint).toContain("MySQL / PostgreSQL");
    expect(values.tableFilterPlaceholder).toContain("id <= 90000");
    expect(values.tableFilterExamples).toContain("select *");
    for (const key of KEYS.filter((key) => key !== "tableFilterTitle")) {
      expect(values[key], `${locale}: ${key} must not introduce a placeholder`).not.toMatch(/\{[^{}]+\}/);
    }
  });
});
