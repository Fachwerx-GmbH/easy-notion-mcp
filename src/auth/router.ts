import express from "express";
import cors from "cors";
import { mcpAuthMetadataRouter } from "@modelcontextprotocol/express";
import {
  OAuthError,
  OAuthErrorCode,
  type OAuthClientInformationFull,
  type OAuthMetadata,
} from "@modelcontextprotocol/server";
import type { NotionOAuthProvider } from "./oauth-provider.js";

/**
 * The authorization server half of OAuth mode: discovery documents,
 * /register (DCR), /authorize, /token, /revoke and Notion's /callback.
 * SDK v2 ships only the resource-server half, so this replaces v1's mcpAuthRouter.
 */
export function oauthRouter(provider: NotionOAuthProvider, publicUrl: URL): express.Router {
  const issuer = publicUrl.href.replace(/\/$/, "");
  const metadata = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    revocation_endpoint: `${issuer}/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    revocation_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    client_id_metadata_document_supported: true,
  } as OAuthMetadata;
  const resource = new URL("/mcp", publicUrl);

  const router = express.Router();
  // Browser-based clients (MCP Inspector) call these cross-origin.
  router.use(["/.well-known", "/register", "/token", "/revoke"], cors());
  router.use(mcpAuthMetadataRouter({ oauthMetadata: metadata, resourceServerUrl: resource }));
  // Clients that probe the origin before the path-aware URL find the same document.
  router.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.json({ resource: resource.href, authorization_servers: [issuer] });
  });

  const sendOAuthError = (res: express.Response, error: unknown) => {
    if (!(error instanceof OAuthError)) {
      console.error("OAuth endpoint error:", error);
      res.status(500).json({ error: "server_error", error_description: "Internal server error" });
      return;
    }
    const status = error.code === OAuthErrorCode.InvalidClient ? 401 : 400;
    res.status(status).set("Cache-Control", "no-store").json(error.toResponseObject());
  };

  /** client_id and secret from client_secret_basic or the request body. */
  const readClientCredentials = (req: express.Request) => {
    const basic = /^Basic (.+)$/i.exec(req.headers.authorization ?? "");
    if (basic) {
      const [id, secret] = Buffer.from(basic[1], "base64").toString("utf8").split(":");
      return { clientId: decodeURIComponent(id), clientSecret: decodeURIComponent(secret ?? "") };
    }
    return { clientId: req.body?.client_id as string | undefined, clientSecret: req.body?.client_secret as string | undefined };
  };

  const authenticatedClient = async (req: express.Request): Promise<OAuthClientInformationFull> => {
    const { clientId, clientSecret } = readClientCredentials(req);
    const client = clientId ? await provider.getClient(clientId) : undefined;
    if (!client) throw new OAuthError(OAuthErrorCode.InvalidClient, "Unknown client");
    provider.authenticateClient(client, clientSecret);
    return client;
  };

  const form = [express.urlencoded({ extended: false }), express.json()];

  router.post("/register", express.json(), async (req, res) => {
    try {
      res.status(201).set("Cache-Control", "no-store").json(await provider.registerClient(req.body ?? {}));
    } catch (error) {
      sendOAuthError(res, error);
    }
  });

  router.all("/authorize", express.urlencoded({ extended: false }), async (req, res) => {
    const params = { ...req.query, ...(req.method === "POST" ? req.body : {}) } as Record<string, string | undefined>;

    // Until client and redirect_uri are trusted, errors are shown here, never redirected.
    let client: OAuthClientInformationFull | undefined;
    try {
      client = params.client_id ? await provider.getClient(params.client_id) : undefined;
    } catch (error) {
      sendOAuthError(res, error);
      return;
    }
    if (!client) {
      res.status(400).json({ error: "invalid_client", error_description: "Unknown client_id" });
      return;
    }
    const redirectUri = params.redirect_uri ?? (client.redirect_uris.length === 1 ? client.redirect_uris[0] : undefined);
    if (!redirectUri || !client.redirect_uris.includes(redirectUri)) {
      res.status(400).json({ error: "invalid_request", error_description: "Unregistered redirect_uri" });
      return;
    }

    const fail = (error: string, description: string) => {
      const target = new URL(redirectUri);
      target.searchParams.set("error", error);
      target.searchParams.set("error_description", description);
      if (params.state) target.searchParams.set("state", params.state);
      res.redirect(target.toString());
    };
    if (params.response_type !== "code") return fail("unsupported_response_type", "response_type must be code");
    if (!params.code_challenge || params.code_challenge_method !== "S256") {
      return fail("invalid_request", "PKCE with code_challenge_method S256 is required");
    }
    if (params.resource && params.resource.replace(/\/$/, "") !== resource.href) {
      return fail("invalid_target", `resource must be ${resource.href}`);
    }

    await provider.authorize(
      client,
      {
        state: params.state,
        codeChallenge: params.code_challenge,
        redirectUri,
        scopes: params.scope?.split(" ").filter(Boolean) ?? [],
        resource: params.resource,
      },
      res,
    );
  });

  router.post("/token", ...form, async (req, res) => {
    try {
      const client = await authenticatedClient(req);
      const body = req.body as Record<string, string | undefined>;
      let tokens;
      if (body.grant_type === "authorization_code") {
        if (!body.code || !body.code_verifier) {
          throw new OAuthError(OAuthErrorCode.InvalidRequest, "code and code_verifier are required");
        }
        tokens = await provider.exchangeAuthorizationCode(client, body.code, body.code_verifier, body.redirect_uri);
      } else if (body.grant_type === "refresh_token") {
        if (!body.refresh_token) throw new OAuthError(OAuthErrorCode.InvalidRequest, "refresh_token is required");
        tokens = await provider.exchangeRefreshToken(client, body.refresh_token);
      } else {
        throw new OAuthError(OAuthErrorCode.UnsupportedGrantType, "Unsupported grant_type");
      }
      res.set("Cache-Control", "no-store").json(tokens);
    } catch (error) {
      sendOAuthError(res, error);
    }
  });

  router.post("/revoke", ...form, async (req, res) => {
    try {
      await authenticatedClient(req);
      if (req.body?.token) await provider.revokeToken(req.body.token);
      res.status(200).json({});
    } catch (error) {
      sendOAuthError(res, error);
    }
  });

  router.get("/callback", (req, res) => provider.handleNotionCallback(req, res));

  return router;
}
