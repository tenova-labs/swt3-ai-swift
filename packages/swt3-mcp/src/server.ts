/**
 * SWT3 MCP Server — Server assembly.
 *
 * Creates an MCP Server with tools and resources for the SWT3 AI Witness protocol.
 * Supports three modes: demo (zero config), API key only (auto-resolve tenant),
 * and full config (API key + tenant ID).
 */

import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { McpConfig } from "./config.js";
import { AxiomClient } from "./client.js";
import { handleWitness } from "./tools/witness.js";
import { handleVerify } from "./tools/verify.js";
import { handleProcedures } from "./tools/procedures.js";
import { handlePosture } from "./tools/posture.js";
import { handleSignup } from "./tools/signup.js";
import { readRegistry } from "./resources/registry.js";
import { readHealth } from "./resources/health.js";
import { REGISTRY_RESOURCE } from "./resources/registry.js";
import { HEALTH_RESOURCE } from "./resources/health.js";

export function createServer(config: McpConfig): McpServer {
  const client = new AxiomClient(config);

  const server = new McpServer({
    name: "swt3-mcp",
    version: "0.1.0",
  });

  // --- Tools ---

  server.registerTool("witness_inference", {
    description:
      "Mint a cryptographic SWT3 witness anchor for an AI inference. " +
      "Records model identity, prompt/response hashes, and latency as " +
      "compliance evidence. Raw text is hashed locally and never sent to the server." +
      (config.demo ? " Currently in DEMO mode — anchors are minted locally. Use the signup tool to persist them." : ""),
    inputSchema: {
      model_id: z.string().describe("AI model identifier (e.g., gpt-4o, claude-sonnet-4)"),
      prompt: z.string().optional().describe("Raw prompt text (hashed locally, never sent to server)"),
      prompt_hash: z.string().optional().describe("Pre-computed SHA-256 hash of prompt (16 hex chars)"),
      response: z.string().optional().describe("Raw response text (hashed locally, never sent to server)"),
      response_hash: z.string().optional().describe("Pre-computed SHA-256 hash of response (16 hex chars)"),
      latency_ms: z.number().optional().describe("Inference latency in milliseconds"),
      input_tokens: z.number().optional().describe("Number of input tokens"),
      output_tokens: z.number().optional().describe("Number of output tokens"),
      clearing_level: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3)]).optional()
        .describe("Data clearing level (0=analytics, 1=standard, 2=sensitive, 3=classified)"),
      procedure: z.string().optional().describe("UCT procedure ID (default: AI-INF.1)"),
      provider: z.string().optional().describe("AI provider name (openai, anthropic, bedrock, etc.)"),
      agent_id: z.string().optional().describe("Agent identity for this inference (AI-ID.1)"),
      cycle_id: z.string().optional().describe("Multi-agent chain link identifier"),
      jurisdiction: z.string().optional().describe("ISO 3166-1 jurisdiction code (e.g., 'DE', 'US-VA')"),
      legal_basis: z.string().optional().describe("GDPR legal basis (e.g., 'consent', 'legitimate_interest', 'contract')"),
      purpose_class: z.string().optional().describe("Processing purpose classification (e.g., 'clinical_decision_support')"),
    },
    annotations: { readOnlyHint: false },
  }, async (args) => {
    try {
      const text = await handleWitness(args, config, client);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("verify_anchor", {
    description:
      "Verify the cryptographic integrity of an SWT3 witness anchor. " +
      "Checks that the anchor's fingerprint matches the recomputed value " +
      "from the original factors, proving the evidence has not been tampered with.",
    inputSchema: {
      token: z.string().describe("SWT3 anchor token (e.g., SWT3-E-VULTR-AI-AIINF1-PASS-1700000000-96b7d56c0245)"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = await handleVerify(args, config, client);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("list_procedures", {
    description:
      "List available UCT (Universal Control Taxonomy) procedures from the SWT3 registry. " +
      "Each procedure maps to a specific compliance control (e.g., AI-INF.1 for inference provenance). " +
      "Optionally filter by namespace (AI, ACC, AUD, CFG, NET, etc.).",
    inputSchema: {
      namespace: z.string().optional().describe("Filter by UCT namespace prefix (e.g., 'AI' for AI procedures)"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = await handleProcedures(args, config, client);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("check_posture", {
    description:
      "Check the current AI witness compliance posture for your tenant. " +
      "Returns model activity summary, pass/fail counts, and overall compliance status." +
      (config.demo ? " Requires a live account — use the signup tool first." : ""),
    annotations: { readOnlyHint: true },
  }, async () => {
    if (config.demo) {
      return {
        content: [{ type: "text" as const, text: "Posture requires a live account. Use the signup tool to create a free account." }],
        isError: true,
      };
    }
    try {
      const text = await handlePosture({}, config, client);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  server.registerTool("signup", {
    description:
      "Get a signup link to create a free SWT3 account. " +
      "Opens in your browser — no credentials pass through the AI. " +
      "After signup, copy your API key into the MCP config to activate live mode.",
    inputSchema: {
      framework: z.string().optional().describe("Primary compliance framework (default: NIST-800-53). Options: NIST-800-53, CMMC-v2.0, AI-RMF, EU-AI-ACT, SR-11-7, NIST-800-171"),
    },
    annotations: { readOnlyHint: true },
  }, async (args) => {
    try {
      const text = await handleSignup(args, config);
      return { content: [{ type: "text" as const, text }] };
    } catch (err) {
      return {
        content: [{ type: "text" as const, text: `Error: ${(err as Error).message}` }],
        isError: true,
      };
    }
  });

  // --- Resources ---

  server.registerResource(
    REGISTRY_RESOURCE.name,
    REGISTRY_RESOURCE.uri,
    { mimeType: REGISTRY_RESOURCE.mimeType, description: REGISTRY_RESOURCE.description },
    async () => ({
      contents: [
        {
          uri: REGISTRY_RESOURCE.uri,
          mimeType: REGISTRY_RESOURCE.mimeType,
          text: await readRegistry(client),
        },
      ],
    }),
  );

  server.registerResource(
    HEALTH_RESOURCE.name,
    HEALTH_RESOURCE.uri,
    { mimeType: HEALTH_RESOURCE.mimeType, description: HEALTH_RESOURCE.description },
    async () => ({
      contents: [
        {
          uri: HEALTH_RESOURCE.uri,
          mimeType: HEALTH_RESOURCE.mimeType,
          text: await readHealth(client),
        },
      ],
    }),
  );

  return server;
}
