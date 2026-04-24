/**
 * SWT3 AI Witness SDK — Core Witness class.
 *
 * Usage:
 *   import { Witness } from "@tenova/swt3-ai";
 *   import OpenAI from "openai";
 *
 *   const witness = new Witness({
 *     endpoint: "https://sovereign.tenova.io",
 *     apiKey: "axm_live_...",
 *     tenantId: "YOUR_TENANT_ID",
 *   });
 *
 *   const client = witness.wrap(new OpenAI()) as OpenAI;
 *   const response = await client.chat.completions.create({ ... });
 *
 *   // Graceful shutdown
 *   await witness.flush();
 *
 * Copyright (c) 2026 Tenable Nova LLC. Apache 2.0. Patent pending.
 */

import { randomUUID } from "node:crypto";
import { sha256Truncated } from "./fingerprint.js";
import { extractPayloads, extractGatekeeperPayload, extractRevocationPayload, REVOCATION_REASONS } from "./clearing.js";
import { WitnessBuffer } from "./buffer.js";
import { writeHandoffFiles } from "./handoff.js";
import { wrapOpenAI } from "./adapters/openai.js";
import { wrapAnthropic } from "./adapters/anthropic.js";
import { wrapBedrock } from "./adapters/bedrock.js";
import { createVercelOnFinish, type VercelOnFinishOptions } from "./adapters/vercel-ai.js";
import type { WitnessConfig, WitnessPayload, WitnessReceipt, InferenceRecord } from "./types.js";

export interface WitnessOptions {
  endpoint: string;
  apiKey: string;
  tenantId: string;
  clearingLevel?: 0 | 1 | 2 | 3;
  bufferSize?: number;
  flushInterval?: number;
  timeout?: number;
  maxRetries?: number;
  latencyThresholdMs?: number;
  guardrailsRequired?: number;
  guardrailNames?: string[];
  procedures?: string[];
  factorHandoff?: "file";
  factorHandoffPath?: string;
  agentId?: string;
  signingKey?: string;
  cycleId?: string;
  strict?: boolean;
  policyVersion?: string;
  jurisdiction?: string;
  legalBasis?: string;
  purposeClass?: string;
  onFlush?: (payloads: WitnessPayload[], receipts: WitnessReceipt[]) => void;
}

/**
 * Raised when strict (gatekeeper) mode blocks an inference due to
 * insufficient guardrails. The inference never reaches the AI model.
 */
export class GatekeeperError extends Error {
  readonly required: number;
  readonly active: number;
  readonly missingNames: string[];

  constructor(required: number, active: number, missingNames: string[] = []) {
    const msg = `Gatekeeper blocked: ${active} guardrails active, ${required} required` +
      (missingNames.length ? `. Missing: ${missingNames.join(", ")}` : "");
    super(msg);
    this.name = "GatekeeperError";
    this.required = required;
    this.active = active;
    this.missingNames = missingNames;
  }
}

export class Witness {
  private config: WitnessConfig;
  private buffer: WitnessBuffer;
  private handoffWarned = false;
  private _strict: boolean;

  constructor(options: WitnessOptions) {
    if (!options.endpoint) throw new Error("endpoint is required");
    if (!options.apiKey) throw new Error("apiKey is required");
    if (!options.apiKey.startsWith("axm_")) throw new Error("apiKey must start with 'axm_'");
    if (!options.tenantId) throw new Error("tenantId is required");
    if (options.factorHandoff && options.factorHandoff !== "file") {
      throw new Error("factorHandoff must be 'file' (other methods planned for v0.4.0)");
    }
    if (options.factorHandoff === "file" && !options.factorHandoffPath) {
      throw new Error("factorHandoffPath is required when factorHandoff is 'file'");
    }

    this.config = {
      endpoint: options.endpoint.replace(/\/+$/, ""),
      apiKey: options.apiKey,
      tenantId: options.tenantId,
      clearingLevel: options.clearingLevel ?? 1,
      bufferSize: options.bufferSize ?? 10,
      flushInterval: options.flushInterval ?? 5.0,
      timeout: options.timeout ?? 10000,
      maxRetries: options.maxRetries ?? 3,
      latencyThresholdMs: options.latencyThresholdMs ?? 30000,
      guardrailsRequired: options.guardrailsRequired ?? 0,
      guardrailNames: options.guardrailNames ?? [],
      procedures: options.procedures,
      factorHandoff: options.factorHandoff,
      factorHandoffPath: options.factorHandoffPath,
      agentId: options.agentId,
      signingKey: options.signingKey,
      cycleId: options.cycleId,
      policyVersion: options.policyVersion,
      jurisdiction: options.jurisdiction,
      legalBasis: options.legalBasis,
      purposeClass: options.purposeClass,
      onFlush: options.onFlush,
    };

    this._strict = options.strict ?? false;
    this.buffer = new WitnessBuffer(this.config);
  }

  /**
   * Wrap an AI client with transparent witnessing.
   *
   * Supported: OpenAI, Anthropic
   * Returns a proxy that behaves identically to the original client.
   *
   * Usage:
   *   const client = witness.wrap(new OpenAI()) as OpenAI;
   *   const client = witness.wrap(new Anthropic()) as Anthropic;
   */
  wrap(client: unknown): unknown {
    const proto = Object.getPrototypeOf(client);
    const name = proto?.constructor?.name ?? "";
    const obj = client as Record<string, unknown>;

    // OpenAI: has client.chat.completions
    if (name === "OpenAI" || obj?.chat) {
      return wrapOpenAI(client, this);
    }

    // Anthropic: has client.messages
    if (name === "Anthropic" || (obj?.messages && !obj?.chat)) {
      return wrapAnthropic(client, this);
    }

    // AWS Bedrock: has client.send and client.config
    if (name === "BedrockRuntimeClient" || (obj?.send && (obj as Record<string, unknown>)?.config)) {
      return wrapBedrock(client, this);
    }

    throw new TypeError(
      `Unsupported client: ${name || "unknown"}. Supported: OpenAI, Anthropic, BedrockRuntimeClient.`,
    );
  }

  /** Whether strict (gatekeeper) mode is enabled. Used by adapters. */
  get strict(): boolean {
    return this._strict;
  }

  /**
   * Pre-call guardrail gate (strict mode only).
   *
   * Evaluates whether configured guardrail requirements are met BEFORE
   * the inference call reaches the AI model. If requirements are not met,
   * throws `GatekeeperError` and mints an AI-GRD.3 anchor recording
   * the rejection. The rejection is evidence — it is enqueued for flush.
   *
   * This method is SYNCHRONOUS — evaluates local config only, no network.
   *
   * @throws {GatekeeperError} if guardrail requirements are not met
   */
  gateCheck(_messages?: unknown, _model?: string): string {
    const required = this.config.guardrailsRequired;
    const active = this.config.guardrailNames.length;
    const gatePassed = active >= required;

    // Mint AI-GRD.3 anchor regardless of outcome — rejection is evidence
    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    const payload = extractGatekeeperPayload(
      this.config.tenantId,
      required,
      active,
      gatePassed,
      this.config.clearingLevel,
      this.config.agentId,
      this.config.signingKey,
      this.config.cycleId,
      policyHash,
      this.config.jurisdiction,
      this.config.legalBasis,
      this.config.purposeClass,
    );
    this.buffer.enqueueMany([payload]);

    if (!gatePassed) {
      throw new GatekeeperError(required, active);
    }

    return payload.anchor_fingerprint;
  }

  /**
   * Wrap a function as a witnessed tool call (AI-TOOL.1).
   *
   * Usage:
   *   const search = witness.wrapTool(searchDatabase, "search_db");
   *   const result = await search("SELECT ...");
   *
   * Each call mints an AI-TOOL.1 anchor with:
   *   factor_a = 1 (tool was called)
   *   factor_b = latency_ms
   *   factor_c = 1 if succeeded, 0 if exception raised
   */
  wrapTool<T extends (...args: any[]) => any>(fn: T, toolName?: string): T {
    const name = toolName ?? fn.name ?? "anonymous";
    const self = this;

    const wrapper = function (this: any, ...args: any[]): any {
      const callId = randomUUID().replace(/-/g, "").slice(0, 12);
      const start = performance.now();
      let succeeded = true;
      let result: any;

      const finish = () => {
        const elapsedMs = Math.round(performance.now() - start);
        const inputHash = sha256Truncated(JSON.stringify(args));
        const outputHash = sha256Truncated(succeeded ? JSON.stringify(result) : "ERROR");

        const record: InferenceRecord = {
          modelId: name,
          modelHash: sha256Truncated(name),
          promptHash: inputHash,
          responseHash: outputHash,
          latencyMs: elapsedMs,
          guardrailsActive: 0,
          guardrailsRequired: 0,
          guardrailPassed: true,
          hasRefusal: !succeeded,
          provider: "tool",
          guardrailNames: [],
          toolName: name,
          toolCallId: callId,
        };

        self.record(record);
      };

      try {
        result = fn.apply(this, args);
      } catch (err) {
        succeeded = false;
        finish();
        throw err;
      }

      // Handle async functions (Promise detection)
      if (result && typeof result.then === "function") {
        return result.then(
          (v: any) => {
            result = v;
            finish();
            return v;
          },
          (err: any) => {
            succeeded = false;
            finish();
            throw err;
          },
        );
      }

      finish();
      return result;
    };

    return wrapper as unknown as T;
  }

  /**
   * Wrap a function as a witnessed access attempt (AI-ACC.1).
   *
   * Usage:
   *   const queryDb = witness.wrapAccess(dbQuery, "prod-database", "read-only analytics");
   *   const result = await queryDb("SELECT ...");
   *
   * Each call mints an AI-ACC.1 anchor with:
   *   factor_a = 1 (access attempt occurred)
   *   factor_b = 1 if within declared scope (or no scope set), 0 if out of scope
   *   factor_c = 1 if access granted, 0 if denied/failed
   */
  wrapAccess<T extends (...args: any[]) => any>(
    fn: T,
    resourceName?: string,
    scope?: string,
  ): T {
    const name = resourceName ?? fn.name ?? "unknown-resource";
    const self = this;

    const wrapper = function (this: any, ...args: any[]): any {
      const start = performance.now();
      let granted = true;
      let result: any;

      const finish = () => {
        const elapsedMs = Math.round(performance.now() - start);
        const inputHash = sha256Truncated(JSON.stringify(args));
        const outputHash = sha256Truncated(granted ? JSON.stringify(result) : "ACCESS_DENIED");

        const record: InferenceRecord = {
          modelId: name,
          modelHash: sha256Truncated(name),
          promptHash: inputHash,
          responseHash: outputHash,
          latencyMs: elapsedMs,
          guardrailsActive: 0,
          guardrailsRequired: 0,
          guardrailPassed: true,
          hasRefusal: !granted,
          provider: "access",
          guardrailNames: [],
          accessTarget: name,
          accessGranted: granted,
          accessScope: scope,
        };

        self.record(record);
      };

      try {
        result = fn.apply(this, args);
      } catch (err) {
        granted = false;
        finish();
        throw err;
      }

      // Handle async functions (Promise detection)
      if (result && typeof result.then === "function") {
        return result.then(
          (v: any) => {
            result = v;
            finish();
            return v;
          },
          (err: any) => {
            granted = false;
            finish();
            throw err;
          },
        );
      }

      finish();
      return result;
    };

    return wrapper as unknown as T;
  }

  /**
   * Revoke a previously-issued witness anchor (AI-REV.1).
   *
   * Mints an AI-REV.1 anchor that references the target anchor's
   * fingerprint, creating an immutable revocation receipt.
   *
   * @param fingerprint - The 12-character anchor fingerprint to revoke.
   * @param reason - Revocation reason: model_recall, policy_violation,
   *   data_contamination, consent_withdrawal, regulatory_order,
   *   error_correction, or unspecified.
   * @returns The fingerprint of the revocation anchor itself.
   */
  revoke(fingerprint: string, reason: string = "unspecified"): string {
    if (!fingerprint?.trim()) {
      throw new Error("fingerprint is required for revocation");
    }
    if (!(reason in REVOCATION_REASONS)) {
      throw new Error(
        `Unknown revocation reason: "${reason}". Valid: ${Object.keys(REVOCATION_REASONS).sort().join(", ")}`,
      );
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    const payload = extractRevocationPayload(
      this.config.tenantId,
      fingerprint.trim(),
      reason,
      this.config.clearingLevel,
      this.config.agentId,
      this.config.signingKey,
      this.config.cycleId,
      policyHash,
      this.config.jurisdiction,
      this.config.legalBasis,
      this.config.purposeClass,
    );
    this.buffer.enqueueMany([payload]);

    return payload.anchor_fingerprint;
  }

  /**
   * Record a witnessed inference. Extracts factors, applies clearing,
   * and enqueues payloads for background flush.
   *
   * If factorHandoff is configured, factors are written to the handoff
   * destination BEFORE clearing proceeds. If the handoff fails, the
   * payload is NOT transmitted.
   */
  record(inference: InferenceRecord, authorizationId?: string): void {
    // Merge guardrail config
    if (this.config.guardrailNames.length > 0 && inference.guardrailNames.length === 0) {
      inference.guardrailNames = this.config.guardrailNames;
      inference.guardrailsActive = this.config.guardrailNames.length;
      inference.guardrailsRequired = this.config.guardrailsRequired;
    }

    const policyHash = this.config.policyVersion
      ? sha256Truncated(this.config.policyVersion, 12)
      : undefined;
    const payloads = extractPayloads(
      inference,
      this.config.tenantId,
      this.config.clearingLevel,
      this.config.latencyThresholdMs,
      this.config.guardrailsRequired,
      this.config.procedures,
      this.config.agentId,
      this.config.signingKey,
      this.config.cycleId,
      policyHash,
      this.config.jurisdiction,
      this.config.legalBasis,
      this.config.purposeClass,
      authorizationId,
    );

    // Factor handoff: write full (uncleared) data to custody destination
    // BEFORE enqueuing the cleared payload for transmission.
    // If this fails, we do NOT proceed.
    if (this.config.factorHandoff === "file" && this.config.factorHandoffPath) {
      writeHandoffFiles(payloads, inference, this.config.tenantId, this.config.factorHandoffPath);
      if (!this.handoffWarned) {
        this.handoffWarned = true;
        console.info(
          `\n  [SWT3] ${payloads.length} anchors saved locally to ${this.config.factorHandoffPath}` +
          `\n  [SWT3] \u26a0 Local anchors won\u2019t survive a compliance audit.` +
          `\n  [SWT3] Connect to Axiom Engine \u2192 https://sovereign.tenova.io/signup?ref=sdk (free)\n`
        );
      }
    }

    this.buffer.enqueueMany(payloads);
  }

  /**
   * Create a Vercel AI SDK `onFinish` callback for streamText / generateText.
   *
   * Usage:
   *   const result = await streamText({
   *     model: openai("gpt-4o"),
   *     prompt: myPrompt,
   *     onFinish: witness.vercelOnFinish({ promptText: myPrompt }),
   *   });
   */
  vercelOnFinish(options?: VercelOnFinishOptions): (result: unknown) => void {
    return createVercelOnFinish(this, options) as (result: unknown) => void;
  }

  /** Force-flush all buffered payloads. */
  async flush(): Promise<WitnessReceipt[]> {
    return this.buffer.flush();
  }

  /** Stop the witness and flush remaining payloads. */
  async stop(): Promise<WitnessReceipt[]> {
    return this.buffer.stop();
  }

  /** Number of payloads waiting. */
  get pending(): number {
    return this.buffer.pending;
  }

  /** All receipts from completed flushes. */
  get receipts(): WitnessReceipt[] {
    return this.buffer.receipts;
  }
}
