#!/usr/bin/env node
import "dotenv/config";
import express from "express";
import { createMcpHandler, type AuthInfo } from "@modelcontextprotocol/server";
import { toNodeHandler } from "@modelcontextprotocol/node";
import { createNotionClient } from "./notion-client.js";
import { createServer } from "./server.js";
import { isMainModule } from "./main-module.js";
import { timingSafeEqual } from "crypto";
import type { Kv } from "./auth/kv.js";

const PORT = parseInt(process.env.PORT ?? "3333", 10);
const NOTION_TOKEN = process.env.NOTION_TOKEN;
const NOTION_OAUTH_CLIENT_ID = process.env.NOTION_OAUTH_CLIENT_ID;
const NOTION_OAUTH_CLIENT_SECRET = process.env.NOTION_OAUTH_CLIENT_SECRET;

const oauthEnabled = !!(NOTION_OAUTH_CLIENT_ID && NOTION_OAUTH_CLIENT_SECRET);

const BEARER_MISSING_ERROR =
  "NOTION_MCP_BEARER is required to start easy-notion-mcp in static-token HTTP mode (since v0.3.0). " +
  "Generate a secret and set it in the server's environment, for example:\n" +
  "  export NOTION_MCP_BEARER=$(openssl rand -hex 32)\n" +
  "Then configure your MCP client to send `Authorization: Bearer <token>` on every /mcp request. " +
  "See the \"HTTP mode security posture\" section in README.md for the full setup.";

export interface CreateAppOptions {
  notionToken?: string;
  oauthClientId?: string;
  oauthClientSecret?: string;
  oauthRedirectUri?: string;
  rootPageId?: string;
  trustContent?: boolean;
  /**
   * Shared-secret bearer required on every /mcp request in static-token HTTP mode.
   * Required when neither oauthClientId nor oauthClientSecret is set.
   * Not used in OAuth mode (OAuth issues its own bearers).
   */
  bearer?: string;
  /** Public origin of this server: OAuth issuer and base of /callback. Defaults to http://localhost:$PORT. */
  publicUrl?: string;
  /** OAuth state store. Defaults to Redis from the environment, else memory. */
  kv?: Kv;
  /** Tool names hidden from clients, e.g. destructive tools for unattended agents. */
  disabledTools?: string[];
}

/**
 * Resolve the bind host for the HTTP server.
 * Default is `127.0.0.1` (loopback only); set `NOTION_MCP_BIND_HOST` to change it
 * (e.g. `0.0.0.0` for all interfaces, or a specific interface IP).
 */
export function getBindHost(env: NodeJS.ProcessEnv): string {
  return env.NOTION_MCP_BIND_HOST ?? "127.0.0.1";
}

function bearerAuthMiddleware(expectedBearer: string): express.RequestHandler {
  const expectedBuf = Buffer.from(expectedBearer, "utf8");
  const challenge = `Bearer realm="easy-notion-mcp"`;
  const reject = (
    res: express.Response,
    description: string,
  ) => {
    res.set(
      "WWW-Authenticate",
      `${challenge}, error="invalid_token", error_description="${description}"`,
    );
    res.status(401).json({ error: "invalid_token", error_description: description });
  };

  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      reject(res, "Missing Authorization header");
      return;
    }
    const parts = authHeader.split(" ");
    if (parts.length !== 2 || parts[0].toLowerCase() !== "bearer" || !parts[1]) {
      reject(res, "Invalid Authorization header format, expected 'Bearer <token>'");
      return;
    }
    const providedBuf = Buffer.from(parts[1], "utf8");
    if (providedBuf.length !== expectedBuf.length) {
      reject(res, "Invalid bearer token");
      return;
    }
    if (!timingSafeEqual(providedBuf, expectedBuf)) {
      reject(res, "Invalid bearer token");
      return;
    }
    next();
  };
}

/**
 * Create the Express app with MCP endpoints.
 * Exported so integration tests can use it without starting a real server.
 *
 * Stateless: every /mcp request builds its own server instance, so any
 * instance behind a load balancer can answer it. createMcpHandler serves the
 * 2026-07-28 protocol and falls back to stateless 2025-era serving.
 */
export async function createApp(options: CreateAppOptions = {}): Promise<express.Express> {
  const useOAuth = !!(options.oauthClientId && options.oauthClientSecret);

  if (!useOAuth && !options.bearer) {
    throw new Error(BEARER_MISSING_ERROR);
  }

  const app = express();
  app.use(express.json());

  const mcpHandler = (notionTokenFor: (auth?: AuthInfo) => string | undefined, allowWorkspaceParent: boolean) => {
    const handle = toNodeHandler(
      createMcpHandler(({ authInfo }) => {
        const notion = createNotionClient(notionTokenFor(authInfo)!);
        return createServer(() => notion, {
          rootPageId: options.rootPageId,
          trustContent: options.trustContent ?? false,
          allowWorkspaceParent,
          transport: "http",
          disabledTools: options.disabledTools,
        });
      }),
    );
    return async (req: express.Request, res: express.Response) => {
      if (!notionTokenFor(req.auth)) {
        res.status(401).json({ error: "No Notion token available" });
        return;
      }
      // express.json() already drained the stream, so the parsed body goes along.
      await handle(req, res, req.body);
    };
  };

  // Health check — helps verify the HTTP server is running and reachable
  app.get("/", (_req: express.Request, res: express.Response) => {
    res.json({
      status: "ok",
      server: "easy-notion-mcp",
      transport: "streamable-http",
      endpoint: "/mcp",
    });
  });

  if (useOAuth) {
    // Dynamic imports to avoid loading auth modules when not needed
    const { requireBearerAuth, getOAuthProtectedResourceMetadataUrl } = await import("@modelcontextprotocol/express");
    const { NotionOAuthProvider } = await import("./auth/oauth-provider.js");
    const { oauthRouter } = await import("./auth/router.js");
    const { redisKvFromEnv, sealedKv, encryptionKeyFromEnv, memoryKv } = await import("./auth/kv.js");

    const publicUrl = new URL(options.publicUrl ?? `http://localhost:${process.env.PORT ?? "3333"}`);
    const redis = options.kv ? undefined : redisKvFromEnv(process.env);
    const kv = sealedKv(options.kv ?? redis ?? memoryKv(), encryptionKeyFromEnv(process.env, !!redis));

    const oauthProvider = new NotionOAuthProvider(kv, {
      clientId: options.oauthClientId!,
      clientSecret: options.oauthClientSecret!,
      redirectUri: options.oauthRedirectUri ?? new URL("/callback", publicUrl).href,
    });

    app.use(oauthRouter(oauthProvider, publicUrl));

    const authMiddleware = requireBearerAuth({
      verifier: oauthProvider,
      resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL("/mcp", publicUrl)),
    });
    app.all("/mcp", authMiddleware, mcpHandler((auth) => auth?.extra?.notionToken as string | undefined, true));

    console.error("OAuth mode enabled");
  } else {
    // Static token mode
    const staticToken = options.notionToken;
    app.all("/mcp", bearerAuthMiddleware(options.bearer!), mcpHandler(() => staticToken, false));

    console.error("Static token mode (NOTION_TOKEN + NOTION_MCP_BEARER)");
  }

  return app;
}

/** The app as configured by the environment. Also the Vercel entry point. */
export function createAppFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<express.Express> {
  return createApp({
    notionToken: env.NOTION_TOKEN,
    oauthClientId: env.NOTION_OAUTH_CLIENT_ID,
    oauthClientSecret: env.NOTION_OAUTH_CLIENT_SECRET,
    oauthRedirectUri: env.OAUTH_REDIRECT_URI,
    publicUrl: env.PUBLIC_URL,
    rootPageId: env.NOTION_ROOT_PAGE_ID,
    trustContent: env.NOTION_TRUST_CONTENT === "true",
    bearer: env.NOTION_MCP_BEARER,
    disabledTools: env.NOTION_MCP_DISABLED_TOOLS?.split(",").map((name) => name.trim()).filter(Boolean),
  });
}

async function startServer() {
  if (!oauthEnabled && !NOTION_TOKEN) {
    console.error(
      "Either NOTION_TOKEN or (NOTION_OAUTH_CLIENT_ID + NOTION_OAUTH_CLIENT_SECRET) is required",
    );
    process.exit(1);
  }

  const bindHost = getBindHost(process.env);
  const app = await createAppFromEnv();

  app.listen(PORT, bindHost, () => {
    console.error(`easy-notion-mcp HTTP server listening on ${bindHost}:${PORT}`);
  });
}

// Only auto-start when run directly (not when imported by tests)
if (isMainModule(process.argv[1], import.meta.url)) {
  startServer().catch((error) => {
    console.error("Fatal:", error);
    process.exit(1);
  });
}
