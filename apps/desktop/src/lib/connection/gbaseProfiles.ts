import type { ConnectionConfig } from "@/types/database";

/**
 * GBase 8a / 8s / 8c share one picker entry and one version toggle, but they are
 * different engines: 8a and 8s are profiles of the `gbase` db type, while 8c is
 * PostgreSQL-shaped and keeps its own `gbase8c` db type (the same split as
 * OceanBase MySQL/Oracle mode). The toggle therefore switches `db_type` too.
 */
export const GBASE_PROFILES = ["gbase8a", "gbase8s", "gbase8c"] as const;

export type GbaseProfile = (typeof GBASE_PROFILES)[number];

export function isGbaseProfile(value: string | undefined | null): value is GbaseProfile {
  return GBASE_PROFILES.includes(value as GbaseProfile);
}

export function gbaseProfileFromConfig(config: Pick<ConnectionConfig, "db_type" | "driver_profile">): GbaseProfile {
  if (config.db_type === "gbase8c" || config.driver_profile === "gbase8c") return "gbase8c";
  return config.driver_profile === "gbase8s" ? "gbase8s" : "gbase8a";
}
