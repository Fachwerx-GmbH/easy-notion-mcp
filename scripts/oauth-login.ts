/**
 * Runs the server's OAuth flow the way an MCP client does: DCR, PKCE,
 * consent in the browser, code exchange, one refresh. Writes the tokens to
 * the file named by TOKENS_OUT and prints none of them. Usage:
 *   TOKENS_OUT=/tmp/tokens.json tsx scripts/oauth-login.ts https://host
 */
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";

const base = (process.argv[2] ?? "http://localhost:3333").replace(/\/$/, "");
const out = process.env.TOKENS_OUT;
if (!out) throw new Error("TOKENS_OUT is required");
const redirectUri = "http://127.0.0.1:8976/callback";

const post = async (path: string, body: Record<string, string>, json = false) => {
  const res = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": json ? "application/json" : "application/x-www-form-urlencoded" },
    body: json ? JSON.stringify(body) : new URLSearchParams(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`${path} ${res.status} ${JSON.stringify(data)}`);
  return data;
};

const registration = await fetch(base + "/register", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ client_name: "easy-notion oauth-login", redirect_uris: [redirectUri], token_endpoint_auth_method: "none" }),
}).then((r) => r.json());
console.log(`registered client ${registration.client_id}`);

const verifier = randomBytes(32).toString("base64url");
const state = randomBytes(8).toString("hex");
const authorize = new URL(base + "/authorize");
authorize.search = new URLSearchParams({
  response_type: "code",
  client_id: registration.client_id,
  redirect_uri: redirectUri,
  code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  code_challenge_method: "S256",
  state,
  resource: base + "/mcp",
}).toString();

const code = await new Promise<string>((resolve, reject) => {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", redirectUri);
    if (url.pathname !== "/callback") return void res.writeHead(404).end();
    res.end("Done. You can close this tab.");
    server.close();
    const error = url.searchParams.get("error");
    if (error) return reject(new Error(`${error}: ${url.searchParams.get("error_description")}`));
    if (url.searchParams.get("state") !== state) return reject(new Error("state mismatch"));
    resolve(url.searchParams.get("code")!);
  }).listen(8976, "127.0.0.1", () => {
    console.log(`opening ${authorize.origin}/authorize in the browser`);
    execFile("open", [authorize.toString()]);
  });
});
console.log("callback received a code");

const tokens = await post("/token", {
  grant_type: "authorization_code",
  code,
  code_verifier: verifier,
  client_id: registration.client_id,
  redirect_uri: redirectUri,
});
console.log(`token: expires_in=${tokens.expires_in} refresh_token=${tokens.refresh_token ? "yes" : "no"}`);

const replay = await fetch(base + "/token", {
  method: "POST",
  body: new URLSearchParams({ grant_type: "authorization_code", code, code_verifier: verifier, client_id: registration.client_id }),
});
console.log(`code replay: ${replay.status} ${(await replay.json()).error}`);

const refreshed = await post("/token", { grant_type: "refresh_token", refresh_token: tokens.refresh_token, client_id: registration.client_id });
console.log(`refresh: new access token ${refreshed.access_token !== tokens.access_token ? "issued" : "NOT issued"}`);

await writeFile(out, JSON.stringify({ client_id: registration.client_id, ...refreshed }), { mode: 0o600 });
console.log(`tokens written to ${out}`);
