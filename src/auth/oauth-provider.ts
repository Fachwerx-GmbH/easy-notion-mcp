import { createHash, randomBytes, randomUUID, timingSafeEqual } from "crypto";
import { isIP } from "net";
import type { Request, Response } from "express";
import {
  OAuthError,
  OAuthErrorCode,
  type AuthInfo,
  type OAuthClientInformationFull,
  type OAuthClientMetadata,
  type OAuthTokens,
} from "@modelcontextprotocol/server";
import type { Kv } from "./kv.js";

const ACCESS_TOKEN_TTL_S = 60 * 60;
const REFRESH_TOKEN_TTL_S = 90 * 24 * 60 * 60;
// Sessions between /authorize and /callback, codes between /callback and /token.
const PENDING_TTL_S = 10 * 60;
const CLIENT_METADATA_DOCUMENT_TTL_S = 5 * 60;
const CLIENT_METADATA_DOCUMENT_MAX_BYTES = 64 * 1024;

export interface NotionOAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string; // Our callback URL, e.g. https://notion-mcp.example.com/callback
}

export interface AuthorizeParams {
  state?: string;
  codeChallenge: string;
  redirectUri: string;
  scopes: string[];
  resource?: string;
}

interface AuthSession extends AuthorizeParams {
  clientId: string;
}

interface PendingCode extends AuthSession {
  notionToken: string;
  notionRefreshToken?: string;
  workspaceId?: string;
}

export interface TokenRecord {
  // Only "access" tokens may be presented on the /mcp bearer path.
  kind: "access" | "refresh";
  notionToken: string;
  notionRefreshToken?: string;
  workspaceId?: string;
  clientId: string;
  scopes: string[];
  resource?: string;
  expiresAt?: number; // timestamp ms
}

const key = {
  client: (id: string) => `client:${id}`,
  clientMetadataDocument: (url: string) => `cimd:${url}`,
  session: (id: string) => `session:${id}`,
  code: (code: string) => `code:${code}`,
  token: (token: string) => `token:${token}`,
};

const newSecret = () => randomBytes(32).toString("base64url");

/**
 * A client_id that is an https URL with a path names a Client ID Metadata
 * Document (draft-ietf-oauth-client-id-metadata-document). Anything else is a
 * client_id this server issued through Dynamic Client Registration.
 */
export function isClientMetadataDocumentUrl(clientId: string): boolean {
  try {
    const url = new URL(clientId);
    return url.protocol === "https:" && url.pathname !== "/";
  } catch {
    return false;
  }
}

async function fetchClientMetadataDocument(clientId: string): Promise<OAuthClientInformationFull> {
  const url = new URL(clientId);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (url.username || url.password || url.hash || isIP(host) || host === "localhost" || host.endsWith(".localhost")) {
    throw new OAuthError(OAuthErrorCode.InvalidClient, "client_id is not an acceptable metadata document URL");
  }
  const response = await fetch(url, {
    redirect: "error",
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(5000),
  });
  const body = await response.text();
  if (!response.ok || body.length > CLIENT_METADATA_DOCUMENT_MAX_BYTES) {
    throw new OAuthError(OAuthErrorCode.InvalidClient, "client metadata document could not be fetched");
  }
  const doc = JSON.parse(body) as Partial<OAuthClientInformationFull>;
  if (doc.client_id !== clientId || !Array.isArray(doc.redirect_uris) || doc.redirect_uris.length === 0) {
    throw new OAuthError(OAuthErrorCode.InvalidClient, "client metadata document does not match its client_id");
  }
  // Metadata documents name public clients: no shared secret exists to check.
  return { ...doc, client_id: clientId, token_endpoint_auth_method: "none" } as OAuthClientInformationFull;
}

export function validateRedirectUris(uris: unknown): string[] {
  if (!Array.isArray(uris) || uris.length === 0) {
    throw new OAuthError(OAuthErrorCode.InvalidClientMetadata, "redirect_uris must be a non-empty array");
  }
  for (const uri of uris) {
    let url: URL;
    try {
      url = new URL(uri as string);
    } catch {
      throw new OAuthError(OAuthErrorCode.InvalidRedirectUri, `redirect_uri is not a URL: ${String(uri)}`);
    }
    if (url.hash || url.protocol === "javascript:" || url.protocol === "data:") {
      throw new OAuthError(OAuthErrorCode.InvalidRedirectUri, `redirect_uri is not allowed: ${uri}`);
    }
  }
  return uris as string[];
}

export class NotionOAuthProvider {
  constructor(
    private readonly kv: Kv,
    private readonly config: NotionOAuthConfig,
  ) {}

  async getClient(clientId: string): Promise<OAuthClientInformationFull | undefined> {
    if (!isClientMetadataDocumentUrl(clientId)) {
      return this.kv.get<OAuthClientInformationFull>(key.client(clientId));
    }
    const cached = await this.kv.get<OAuthClientInformationFull>(key.clientMetadataDocument(clientId));
    if (cached) return cached;
    const client = await fetchClientMetadataDocument(clientId);
    await this.kv.set(key.clientMetadataDocument(clientId), client, CLIENT_METADATA_DOCUMENT_TTL_S);
    return client;
  }

  async registerClient(metadata: OAuthClientMetadata): Promise<OAuthClientInformationFull> {
    validateRedirectUris(metadata.redirect_uris);
    const isPublic = metadata.token_endpoint_auth_method === "none";
    const client: OAuthClientInformationFull = {
      ...metadata,
      token_endpoint_auth_method: metadata.token_endpoint_auth_method ?? "client_secret_post",
      client_id: randomUUID(),
      client_id_issued_at: Math.floor(Date.now() / 1000),
      ...(isPublic ? {} : { client_secret: newSecret(), client_secret_expires_at: 0 }),
    };
    await this.kv.set(key.client(client.client_id), client);
    return client;
  }

  /** Checks the secret of a confidential client; public clients pass. */
  authenticateClient(client: OAuthClientInformationFull, presentedSecret: string | undefined): void {
    if (!client.client_secret) return;
    const expected = Buffer.from(client.client_secret);
    const presented = Buffer.from(presentedSecret ?? "");
    if (expected.length !== presented.length || !timingSafeEqual(expected, presented)) {
      throw new OAuthError(OAuthErrorCode.InvalidClient, "Invalid client credentials");
    }
  }

  /** Redirect the user to Notion's consent screen. */
  async authorize(client: OAuthClientInformationFull, params: AuthorizeParams, res: Response): Promise<void> {
    const sessionId = randomUUID();
    const session: AuthSession = { ...params, clientId: client.client_id };
    await this.kv.set(key.session(sessionId), session, PENDING_TTL_S);

    const notionAuthUrl = new URL("https://api.notion.com/v1/oauth/authorize");
    notionAuthUrl.searchParams.set("client_id", this.config.clientId);
    notionAuthUrl.searchParams.set("response_type", "code");
    notionAuthUrl.searchParams.set("owner", "user");
    notionAuthUrl.searchParams.set("redirect_uri", this.config.redirectUri);
    notionAuthUrl.searchParams.set("state", sessionId);
    res.redirect(notionAuthUrl.toString());
  }

  /** Notion's redirect back to /callback. */
  async handleNotionCallback(req: Request, res: Response): Promise<void> {
    const code = req.query.code as string | undefined;
    const sessionId = req.query.state as string | undefined;
    const error = req.query.error as string | undefined;

    if (!sessionId) {
      res.status(400).json({ error: "Missing state parameter" });
      return;
    }
    const session = await this.kv.take<AuthSession>(key.session(sessionId));
    if (!session) {
      res.status(400).json({ error: "Invalid or expired session" });
      return;
    }

    const redirectToClient = (params: Record<string, string>) => {
      const target = new URL(session.redirectUri);
      for (const [name, value] of Object.entries(params)) target.searchParams.set(name, value);
      if (session.state) target.searchParams.set("state", session.state);
      res.redirect(target.toString());
    };

    if (error || !code) {
      redirectToClient({
        error: error ?? "access_denied",
        error_description: (req.query.error_description as string) ?? "Notion authorization was denied",
      });
      return;
    }

    let tokenData: { access_token: string; refresh_token?: string; workspace_id?: string };
    try {
      const tokenResponse = await this.notionTokenRequest({
        grant_type: "authorization_code",
        code,
        redirect_uri: this.config.redirectUri,
      });
      if (!tokenResponse.ok) {
        console.error("Notion token exchange failed:", tokenResponse.status, await tokenResponse.text());
        redirectToClient({ error: "server_error", error_description: "Failed to exchange authorization code with Notion" });
        return;
      }
      tokenData = (await tokenResponse.json()) as typeof tokenData;
    } catch (err) {
      console.error("Notion token exchange error:", err);
      redirectToClient({ error: "server_error", error_description: "Notion token exchange failed" });
      return;
    }
    console.error(`Notion token exchange ok (refresh_token issued: ${tokenData.refresh_token ? "yes" : "no"})`);

    const ourCode = newSecret();
    const pending: PendingCode = {
      ...session,
      notionToken: tokenData.access_token,
      notionRefreshToken: tokenData.refresh_token,
      workspaceId: tokenData.workspace_id,
    };
    await this.kv.set(key.code(ourCode), pending, PENDING_TTL_S);
    redirectToClient({ code: ourCode });
  }

  /** Single use: the code is consumed before anything else is checked. */
  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    codeVerifier: string,
    redirectUri?: string,
  ): Promise<OAuthTokens> {
    const pending = await this.kv.take<PendingCode>(key.code(authorizationCode));
    if (!pending) {
      throw new OAuthError(OAuthErrorCode.InvalidGrant, "Invalid authorization code");
    }
    if (pending.clientId !== client.client_id) {
      throw new OAuthError(OAuthErrorCode.InvalidGrant, "Authorization code was not issued to this client");
    }
    if (redirectUri !== undefined && redirectUri !== pending.redirectUri) {
      throw new OAuthError(OAuthErrorCode.InvalidGrant, "redirect_uri does not match the authorization request");
    }
    const challenge = createHash("sha256").update(codeVerifier).digest("base64url");
    if (challenge !== pending.codeChallenge) {
      throw new OAuthError(OAuthErrorCode.InvalidGrant, "code_verifier does not match the code challenge");
    }

    const record: Omit<TokenRecord, "kind"> = {
      notionToken: pending.notionToken,
      notionRefreshToken: pending.notionRefreshToken,
      workspaceId: pending.workspaceId,
      clientId: client.client_id,
      scopes: pending.scopes,
      resource: pending.resource,
    };
    const refreshToken = newSecret();
    await this.kv.set(key.token(refreshToken), { ...record, kind: "refresh" }, REFRESH_TOKEN_TTL_S);
    return this.issueAccessToken(record, refreshToken);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens> {
    const record = await this.kv.get<TokenRecord>(key.token(refreshToken));
    if (!record || record.kind !== "refresh") {
      throw new OAuthError(OAuthErrorCode.InvalidGrant, "Invalid refresh token");
    }
    if (record.clientId !== client.client_id) {
      throw new OAuthError(OAuthErrorCode.InvalidGrant, "Refresh token was not issued to this client");
    }

    if (record.notionRefreshToken) {
      try {
        const tokenResponse = await this.notionTokenRequest({
          grant_type: "refresh_token",
          refresh_token: record.notionRefreshToken,
        });
        if (tokenResponse.ok) {
          const tokenData = (await tokenResponse.json()) as { access_token: string; refresh_token?: string };
          record.notionToken = tokenData.access_token;
          record.notionRefreshToken = tokenData.refresh_token ?? record.notionRefreshToken;
        }
        // A failed refresh keeps the current Notion token, which may still be valid.
      } catch (err) {
        console.error("Notion token refresh failed:", err);
      }
    }
    // Sliding window: each use keeps the refresh token alive for another 90 days.
    await this.kv.set(key.token(refreshToken), record, REFRESH_TOKEN_TTL_S);
    return this.issueAccessToken(record, refreshToken);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = await this.kv.get<TokenRecord>(key.token(token));
    if (!record || record.kind !== "access" || !record.expiresAt || record.expiresAt < Date.now()) {
      throw new OAuthError(OAuthErrorCode.InvalidToken, "Invalid or expired token");
    }
    return {
      token,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: Math.floor(record.expiresAt / 1000),
      resource: record.resource ? new URL(record.resource) : undefined,
      extra: { notionToken: record.notionToken, workspaceId: record.workspaceId },
    };
  }

  async revokeToken(token: string): Promise<void> {
    await this.kv.del(key.token(token));
  }

  private async issueAccessToken(record: Omit<TokenRecord, "kind">, refreshToken: string): Promise<OAuthTokens> {
    const accessToken = newSecret();
    const access: TokenRecord = { ...record, kind: "access", expiresAt: Date.now() + ACCESS_TOKEN_TTL_S * 1000 };
    await this.kv.set(key.token(accessToken), access, ACCESS_TOKEN_TTL_S);
    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL_S,
      refresh_token: refreshToken,
      scope: record.scopes.join(" "),
    };
  }

  private notionTokenRequest(body: Record<string, string>): Promise<globalThis.Response> {
    return fetch("https://api.notion.com/v1/oauth/token", {
      method: "POST",
      headers: {
        Authorization: "Basic " + Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString("base64"),
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });
  }
}
