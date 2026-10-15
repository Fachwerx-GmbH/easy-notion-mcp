/**
 * Talks to a running HTTP server once per protocol era and prints what was
 * negotiated. Usage:
 *   MCP_TOKEN=<bearer> tsx scripts/smoke-remote.ts https://host/mcp
 * PAGE_ID and DATABASE_ID are optional; without them the first page and
 * database that `search` returns are used.
 */
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

const url = new URL(process.argv[2] ?? "http://localhost:3333/mcp");
const token = process.env.MCP_TOKEN;
if (!token) throw new Error("MCP_TOKEN is required");

const text = (result: unknown) =>
  ((result as { content?: Array<{ text?: string }> }).content ?? []).map((c) => c.text ?? "").join("");

async function run(mode: "legacy" | { pin: string }) {
  const client = new Client({ name: "easy-notion-smoke", version: "1.0.0" }, { versionNegotiation: { mode } });
  const transport = new StreamableHTTPClientTransport(url, {
    requestInit: { headers: { Authorization: `Bearer ${token}` } },
  });
  await client.connect(transport);
  const label = typeof mode === "string" ? mode : `pin ${mode.pin}`;
  console.log(`[${label}] era=${client.getProtocolEra()} version=${client.getNegotiatedProtocolVersion()}`);

  const { tools } = await client.listTools();
  console.log(`[${label}] tools/list: ${tools.length} tools`);

  let pageId = process.env.PAGE_ID;
  let databaseId = process.env.DATABASE_ID;
  if (!pageId || !databaseId) {
    const found = text(await client.callTool({ name: "search", arguments: { query: "" } }));
    const items = JSON.parse(found) as Array<{ id: string; type?: string; object?: string }>;
    const list = Array.isArray(items) ? items : ((items as { results?: typeof items }).results ?? []);
    pageId ??= list.find((i) => (i.type ?? i.object) === "page")?.id;
  }
  if (!databaseId) {
    const dbs = JSON.parse(text(await client.callTool({ name: "list_databases", arguments: {} })));
    databaseId = (Array.isArray(dbs) ? dbs : (dbs.results ?? dbs.databases ?? []))[0]?.id;
  }
  if (pageId) {
    const page = text(await client.callTool({ name: "read_page", arguments: { page_id: pageId, max_blocks: 3 } }));
    console.log(`[${label}] read_page ${pageId}: ${page.length} chars, title=${JSON.parse(page).title ?? "?"}`);
  }
  if (databaseId) {
    const rows = JSON.parse(text(await client.callTool({ name: "query_database", arguments: { database_id: databaseId } })));
    const count = Array.isArray(rows) ? rows.length : rows.results?.length;
    console.log(`[${label}] query_database ${databaseId}: ${count ?? JSON.stringify(rows).slice(0, 200)} rows`);
  }
  await client.close();
}

await run({ pin: "2026-07-28" });
await run("legacy");
