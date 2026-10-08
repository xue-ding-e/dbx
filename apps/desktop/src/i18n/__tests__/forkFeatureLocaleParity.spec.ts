import { readFileSync } from "node:fs";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const LOCALES = ["en", "zh-CN", "zh-TW", "ja", "ko", "es", "it", "pt-BR", "ru", "az", "tr", "id"] as const;
const FEATURE_KEYS = {
  connection: ["databaseCategoryAll"],
  configExport: ["plaintextDefaultDescription", "includeCredentials", "plaintextCredentialsWarning", "exportWithCredentials", "exportWithoutCredentials"],
  settings: ["mcpToolImportConnections", "mcpToolGetConnection", "mcpToolUpdateConnection"],
};

function propertyName(node: ts.PropertyName): string | undefined {
  return ts.isIdentifier(node) || ts.isStringLiteral(node) ? node.text : undefined;
}

function sectionObject(source: ts.SourceFile, name: string): ts.ObjectLiteralExpression | undefined {
  let result: ts.ObjectLiteralExpression | undefined;
  function visit(node: ts.Node) {
    if (ts.isPropertyAssignment(node) && propertyName(node.name) === name && ts.isObjectLiteralExpression(node.initializer)) {
      result = node.initializer;
    }
    if (!result) ts.forEachChild(node, visit);
  }
  visit(source);
  return result;
}

describe("retained fork feature locale parity", () => {
  // Check declarations before withEnglishFallback merges them, so a missing
  // safety warning cannot be hidden by a successful English fallback.
  it.each(LOCALES)("%s declares every retained feature label", (locale) => {
    const source = ts.createSourceFile(locale, readFileSync(new URL(`../locales/${locale}.ts`, import.meta.url), "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    for (const [section, keys] of Object.entries(FEATURE_KEYS)) {
      const object = sectionObject(source, section);
      expect(object, `${locale}: missing ${section}`).toBeDefined();
      for (const key of keys) {
        const matches = object!.properties.filter((property) => ts.isPropertyAssignment(property) && propertyName(property.name) === key) as ts.PropertyAssignment[];
        expect(matches, `${locale}: ${section}.${key} must be declared once`).toHaveLength(1);
        const value = matches[0].initializer;
        expect(ts.isStringLiteral(value), `${locale}: ${section}.${key} must be translated text`).toBe(true);
        expect((value as ts.StringLiteral).text.trim()).not.toBe("");
      }
    }
  });
});
