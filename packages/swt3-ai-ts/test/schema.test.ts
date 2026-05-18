import { describe, it, expect } from "vitest";
import { validateSchema } from "../src/schema.js";

describe("Schema Validator", () => {
  it("valid config passes", () => {
    const result = validateSchema({
      api_key: "axm_test",
      tenant_id: "TEST",
      clearing_level: 2,
      trust_mesh: { mode: "strict", min_trust_level: 2 },
      policy: { require_signing: true },
    });
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("unknown top-level key returns error", () => {
    const result = validateSchema({
      api_key: "axm_test",
      bogus_field: true,
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("bogus_field");
    expect(result.errors[0].message).toContain("unknown top-level key");
  });

  it("wrong type for clearing_level returns error", () => {
    const result = validateSchema({
      api_key: "axm_test",
      clearing_level: "high",
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("clearing_level");
  });

  it("invalid enum value returns error", () => {
    const result = validateSchema({
      api_key: "axm_test",
      trust_mesh: { mode: "aggressive" },
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("trust_mesh.mode");
  });

  it("wrong type in section returns error", () => {
    const result = validateSchema({
      api_key: "axm_test",
      policy: { require_signing: "yes" },
    });
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("policy.require_signing");
    expect(result.errors[0].message).toContain("expected boolean");
  });

  it("multiple errors accumulated correctly", () => {
    const result = validateSchema({
      bogus1: true,
      bogus2: true,
      clearing_level: 99,
      trust_mesh: { mode: "invalid", bad_key: true },
    });
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThanOrEqual(4);
  });
});
