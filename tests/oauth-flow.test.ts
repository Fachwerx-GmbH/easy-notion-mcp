import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createHash, randomBytes } from "crypto";
import request from "supertest";
import type express from "express";
import { createApp } from "../src/http.js";
import { memoryKv, sealedKv, type Kv } from "../src/auth/kv.js";

const REDIRECT = "http://localhost:9999/callback";
const verifier = "test-verifier-0123456789-0123456789-0123456789";
const challenge = createHash("sha256").update(verifier).digest("base64url");

const realFetch = globalThis.fetch;

function stubFetch(routes: Record<string, () => unknown>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = String(input);
      const route = routes[url];
      if (!route) return realFetch(input, init);
      return new Response(JSON.stringify(route()), { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
}

async function twoInstances(store: Kv) {
  const options = {
    oauthClientId: "notion-client-id",
    oauthClientSecret: "notion-client-secret",
    publicUrl: "https://mcp.example.com",
    kv: store,
  };
  return [await createApp(options), await createApp(options)] as const;
}

async function authorize(app: express.Express, clientId: string) {
  const res = await request(app).get("/authorize").query({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "client-state",
    resource: "https://mcp.example.com/mcp",
  });
  expect(res.status).toBe(302);
  return new URL(res.headers.location).searchParams.get("state")!;
}

async function callback(app: express.Express, sessionId: string) {
  const res = await request(app).get("/callback").query({ code: "notion-code", state: sessionId });
  expect(res.status).toBe(302);
  const location = new URL(res.headers.location);
  expect(location.searchParams.get("state")).toBe("client-state");
  return location.searchParams.get("code")!;
}

function tokenRequest(app: express.Express, form: Record<string, string>) {
  return request(app).post("/token").type("form").send(form);
}

describe("OAuth flow across stateless instances", () => {
  let store: Kv;
  let a: express.Express;
  let b: express.Express;

  beforeEach(async () => {
    process.env.TOKEN_ENC_KEY = randomBytes(32).toString("base64");
    stubFetch({
      "https://api.notion.com/v1/oauth/token": () => ({
        access_token: "ntn_fake",
        refresh_token: "ntn_refresh_fake",
        workspace_id: "ws1",
        token_type: "bearer",
      }),
    });
    store = memoryKv();
    [a, b] = await twoInstances(store);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.TOKEN_ENC_KEY;
  });

  async function register(app: express.Express, body: Record<string, unknown> = {}) {
    const res = await request(app)
      .post("/register")
      .send({ client_name: "test", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", ...body });
    expect(res.status).toBe(201);
    return res.body as { client_id: string; client_secret?: string };
  }

  it("runs register, authorize, callback, token, /mcp and refresh on alternating instances", async () => {
    const { client_id } = await register(a);
    const code = await callback(a, await authorize(b, client_id));

    const tokenRes = await tokenRequest(b, {
      grant_type: "authorization_code",
      code,
      code_verifier: verifier,
      client_id,
      redirect_uri: REDIRECT,
    });
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.headers["cache-control"]).toBe("no-store");
    const { access_token, refresh_token } = tokenRes.body;

    const list = await request(a)
      .post("/mcp")
      .set("Authorization", `Bearer ${access_token}`)
      .set("Accept", "application/json, text/event-stream")
      .send({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
    expect(list.status).toBe(200);

    const refreshed = await tokenRequest(a, { grant_type: "refresh_token", refresh_token, client_id });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.access_token).not.toBe(access_token);
  });

  it("consumes an authorization code once", async () => {
    const { client_id } = await register(a);
    const code = await callback(a, await authorize(a, client_id));
    const form = { grant_type: "authorization_code", code, code_verifier: verifier, client_id };
    expect((await tokenRequest(a, form)).status).toBe(200);
    const replay = await tokenRequest(b, form);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe("invalid_grant");
  });

  it("rejects a wrong PKCE verifier", async () => {
    const { client_id } = await register(a);
    const code = await callback(a, await authorize(a, client_id));
    const res = await tokenRequest(a, { grant_type: "authorization_code", code, code_verifier: "wrong", client_id });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
  });

  it("rejects a refresh token presented as a bearer on /mcp", async () => {
    const { client_id } = await register(a);
    const code = await callback(a, await authorize(a, client_id));
    const { refresh_token } = (
      await tokenRequest(a, { grant_type: "authorization_code", code, code_verifier: verifier, client_id })
    ).body;
    const res = await request(b)
      .post("/mcp")
      .set("Authorization", `Bearer ${refresh_token}`)
      .send({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} });
    expect(res.status).toBe(401);
  });

  it("requires the client secret of a confidential DCR client", async () => {
    const { client_id, client_secret } = await register(a, { token_endpoint_auth_method: "client_secret_post" });
    expect(client_secret).toBeTruthy();
    const code = await callback(a, await authorize(a, client_id));
    const form = { grant_type: "authorization_code", code, code_verifier: verifier, client_id };
    expect((await tokenRequest(a, { ...form, client_secret: "nope" })).status).toBe(401);
  });

  it("accepts a Client ID Metadata Document URL as client_id", async () => {
    const clientId = "https://client.example.com/oauth/metadata.json";
    stubFetch({
      [clientId]: () => ({ client_id: clientId, client_name: "cimd", redirect_uris: [REDIRECT] }),
      "https://api.notion.com/v1/oauth/token": () => ({ access_token: "ntn_fake", token_type: "bearer" }),
    });
    const code = await callback(a, await authorize(b, clientId));
    const res = await tokenRequest(a, { grant_type: "authorization_code", code, code_verifier: verifier, client_id: clientId });
    expect(res.status).toBe(200);
  });

  it("rejects a metadata document whose client_id differs from its URL", async () => {
    const clientId = "https://client.example.com/oauth/metadata.json";
    stubFetch({ [clientId]: () => ({ client_id: "https://evil.example.com/x", redirect_uris: [REDIRECT] }) });
    const res = await request(a).get("/authorize").query({
      response_type: "code",
      client_id: clientId,
      redirect_uri: REDIRECT,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    expect(res.status).toBe(401);
  });

  it("serves protected-resource metadata at the path-aware and the root URL", async () => {
    for (const path of ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"]) {
      const res = await request(a).get(path);
      expect(res.status).toBe(200);
      expect(res.body.resource).toBe("https://mcp.example.com/mcp");
    }
    const as = await request(a).get("/.well-known/oauth-authorization-server");
    expect(as.body.issuer).toBe("https://mcp.example.com");
    expect(as.body.client_id_metadata_document_supported).toBe(true);
  });
});

describe("sealedKv", () => {
  it("stores neither keys nor values in plain text", async () => {
    const inner = memoryKv();
    const raw: string[] = [];
    const spy: Kv = { ...inner, set: async (k, v, t) => { raw.push(k, String(v)); await inner.set(k, v, t); } };
    const kv = sealedKv(spy, randomBytes(32));
    await kv.set("token:secret-bearer", { notionToken: "ntn_secret" }, 60);
    expect(raw.join(" ")).not.toMatch(/secret-bearer|ntn_secret/);
    expect(await kv.get("token:secret-bearer")).toEqual({ notionToken: "ntn_secret" });
    expect(await kv.take("token:secret-bearer")).toEqual({ notionToken: "ntn_secret" });
    expect(await kv.get("token:secret-bearer")).toBeUndefined();
  });

  it("cannot open values sealed under another key", async () => {
    const inner = memoryKv();
    await sealedKv(inner, randomBytes(32)).set("k", { a: 1 });
    await expect(sealedKv(inner, randomBytes(32)).get("k")).rejects.toThrow();
  });
});
